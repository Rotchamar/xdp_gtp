package xdpgtp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target "bpf" gtp ../ebpf-c/gtp.c -- -I../ebpf-c/common -Wall -Werror

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/j-keck/arping"
	"github.com/libp2p/go-netroute"
	probing "github.com/prometheus-community/pro-bing"
)

// Ethernet address length.
const ethAddrLen = 6

// Struct for storing usage statistics in BPF map.
type UsageStats struct {
	Packets uint64 // Number of packets sent since program was loaded
	Bytes   uint64 // Number of bytes sent since program was loaded
}

// Struct for storing UPF information in BPF map.
type upfInfo struct {
	localIP    uint32            // IP address of the host's UPF-facing interface (network byte order)
	ethNextHop [ethAddrLen]uint8 // Destination Ethernet address for packets sent towards UPF
	ethLocal   [ethAddrLen]uint8 // Source Ethernet address for packets sent towards UPF
	ifindex    uint32            // UPF-facing interface index
}

// Struct for storing client information in BPF map.
type clientInfo struct {
	teid       uint32            // GTP Tunnel Endpoint Identifier
	upfIP      uint32            // Client's UPF's IP address (network byte order)
	ethNextHop [ethAddrLen]uint8 // Destination Ethernet address for packets sent towards client
	ethLocal   [ethAddrLen]uint8 // Source Ethernet address for packets sent towards client
	ifindex    uint32            // Client-facing interface index
}

// Enum for defining the different states an interface can be regarding a loaded eBPF program.
type xdpgtpMode uint8

const (
	xdpgtpNone   xdpgtpMode = iota // No eBPF program attached
	xdpgtpClient                   // Client-facing XDPGTP eBPF program attached
	xdpgtpUpf                      // UPF-facing XDPGTP eBPF program attached
	xdpgtpCommon                   // Common XDPGTP eBPF program attached
)

// Struct for storing the state and link to eBPF program in an interface.
type ifaceStatus struct {
	mode    xdpgtpMode
	xdpLink link.Link
}

// XDPGTP holds the state of the running application.
type XDPGTP struct {
	objs          gtpObjects            // Compiled and generated objects from ../ebpf-c with cilium's bpf2go tool
	xdpFlags      link.XDPAttachFlags   // XDP hook location (generic, driver, or offload)
	ifaces        map[int]ifaceStatus   // Map for storing interfaces' status given their index
	upfInfoMap    map[uint32]upfInfo    // Map for storing UPF's information given their IP address in network byte order
	clientInfoMap map[uint32]clientInfo // Map for storing clients's information given their IP address in network byte order
}

// Convert IPv4 address from net.IP to uint32.
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

// Convert IPv4 address from uint32 to net.IP.
func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

// Convert uint32 from host to network byte order.
func htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

// NewXDPGTP loads compiled eBPF programs and maps into the kernel and returns a new XDPGTP.
//
// Users must call x.Close() to safely unload eBPF programs and maps from the kernel.
func NewXDPGTP(xdpFlags link.XDPAttachFlags) (*XDPGTP, error) {
	x := XDPGTP{}

	x.objs = gtpObjects{}
	if err := loadGtpObjects(&x.objs, nil); err != nil {
		return nil, fmt.Errorf("Could not load objects: %s", err)
	}

	x.xdpFlags = xdpFlags
	x.ifaces = make(map[int]ifaceStatus)
	x.upfInfoMap = make(map[uint32]upfInfo)
	x.clientInfoMap = make(map[uint32]clientInfo)

	return &x, nil
}

// Method for safely unloading the eBPF programs and maps from the kernel.
func (x XDPGTP) Close() error {
	return x.objs.Close()
}

// Method for attaching a generic eBPF program to an interface.
func (x XDPGTP) attachProgramToInterface(ifindex int, program *ebpf.Program, mode xdpgtpMode) error {
	ifaceStatus, ok := x.ifaces[ifindex]
	if ok && ifaceStatus.mode != xdpgtpNone {
		return fmt.Errorf("An XDP program is already attached to this interface")
	}

	var err error

	ifaceStatus.xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: ifindex,
		Flags:     x.xdpFlags,
	})
	if err != nil {
		return fmt.Errorf("Could not attach XDP program: %s", err)
	}

	ifaceStatus.mode = mode
	x.ifaces[ifindex] = ifaceStatus

	return nil
}

// Method for attaching the UPF-facing eBPF program to an interface given its index.
//
// Users must call x.DetachProgramFromInterface(ifindex) to safely detach the eBPF program.
func (x XDPGTP) AttachUpfFacingProgramToInterface(upfIfindex int) error {
	err := x.attachProgramToInterface(upfIfindex, x.objs.XdpGtpUpf, xdpgtpUpf)
	if err != nil {
		return err
	}

	return nil
}

// Method for attaching the client-facing eBPF program to an interface given its index.
//
// Users must call x.DetachProgramFromInterface(ifindex) to safely detach the eBPF program.
func (x XDPGTP) AttachClientFacingProgramToInterface(clientIfindex int) error {
	err := x.attachProgramToInterface(clientIfindex, x.objs.XdpGtpClient, xdpgtpClient)
	if err != nil {
		return err
	}

	return nil
}

// Method for attaching the common eBPF program to an interface given its index.
//
// Users must call x.DetachProgramFromInterface(ifindex) to safely detach the eBPF program.
func (x XDPGTP) AttachCommonProgramToInterface(commonIfindex int) error {
	err := x.attachProgramToInterface(commonIfindex, x.objs.XdpGtpCommon, xdpgtpCommon)
	if err != nil {
		return err
	}

	return nil
}

// Method for safely detaching an eBPF program from an interface.
func (x XDPGTP) DetachProgramFromInterface(ifindex int) error {
	ifaceStatus, ok := x.ifaces[ifindex]

	if !ok || ifaceStatus.mode == xdpgtpNone {
		return fmt.Errorf("Interface doesn't have any program attached")
	}

	ifaceStatus.xdpLink.Close()
	delete(x.ifaces, ifindex)

	return nil
}

// Method for adding a new UPF to the BPF map.
func (x XDPGTP) AddUpf(upfIP net.IP) error {
	upfInf := upfInfo{}

	routedIface, hwAddr, localIP, err := getEndpointAddrs(upfIP)
	if err != nil {
		return fmt.Errorf("Could not acquire UPF-related addresses: %s", err)
	}

	// Check whether the interface through which the UPF is routed has a UPF-facing or common XGPGTP eBPF program attached.
	upfProgramAttachedToRoutedIface := false
	for ifindex, status := range x.ifaces {
		if ifindex == routedIface.Index && (status.mode == xdpgtpUpf || status.mode == xdpgtpCommon) {
			upfProgramAttachedToRoutedIface = true
			break
		}
	}
	if !upfProgramAttachedToRoutedIface {
		return fmt.Errorf("UPF program not attached to routed interface")
	}

	upfInf.localIP = ip2int(localIP)
	upfInf.ethNextHop = [6]uint8(hwAddr)
	upfInf.ethLocal = [6]uint8(routedIface.HardwareAddr)
	upfInf.ifindex = uint32(routedIface.Index)

	x.upfInfoMap[ip2int(upfIP)] = upfInf

	err = x.objs.UpfMap.Update(ip2int(upfIP), upfInf, ebpf.UpdateNoExist)
	if err != nil {
		return fmt.Errorf("Could not load UPF: %s", err)
	}

	return nil
}

// Method for adding a new client to the BPF map.
func (x XDPGTP) AddClient(clientIP net.IP, teid uint32, upfIP net.IP) error {
	clientInf := clientInfo{}

	// Check whether the UPF indicated has been previously added to the BPF maps.
	if !x.UpfIsRegistered(upfIP) {
		return fmt.Errorf("Assigned UPF has not been previously registered")
	}

	routedIface, hwAddr, _, err := getEndpointAddrs(clientIP)
	if err != nil {
		return fmt.Errorf("Could not acquire client-related addresses: %s", err)
	}

	// Check whether the interface through which the client is routed has a client-facing or common XGPGTP eBPF program attached.
	clientProgramAttachedToRoutedIface := false
	for ifindex, status := range x.ifaces {
		if ifindex == routedIface.Index && (status.mode == xdpgtpClient || status.mode == xdpgtpCommon) {
			clientProgramAttachedToRoutedIface = true
			break
		}
	}
	if !clientProgramAttachedToRoutedIface {
		return fmt.Errorf("Client program not attached to routed interface")
	}

	clientInf.teid = teid
	clientInf.upfIP = ip2int(upfIP)
	clientInf.ethNextHop = [6]uint8(hwAddr)
	clientInf.ethLocal = [6]uint8(routedIface.HardwareAddr)
	clientInf.ifindex = uint32(routedIface.Index)

	x.clientInfoMap[ip2int(clientIP)] = clientInf

	err = x.objs.ClientMap.Update(ip2int(clientIP), clientInf, ebpf.UpdateNoExist)
	if err != nil {
		return fmt.Errorf("Could not load client: %s", err)
	}

	return nil
}

// UpfIsRegistered reports whether the indicated UPF is present in the corresponing BPF map.
func (x XDPGTP) UpfIsRegistered(upfIP net.IP) bool {
	_, isRegistered := x.upfInfoMap[ip2int(upfIP)]
	return isRegistered
}

// ClientIsRegistered reports whether the indicated client is present in the corresponding BPF map.
func (x XDPGTP) ClientIsRegistered(clientIP net.IP) bool {
	_, isRegistered := x.clientInfoMap[ip2int(clientIP)]
	return isRegistered
}

// GetClientsForUpf returns a net.IP slice containing all the clients' IPs which are attached to a certain UPF.
func (x XDPGTP) GetClientsForUpf(upfIP net.IP) []net.IP {
	blockingClients := make([]net.IP, 0)
	for clientIP, clientInf := range x.clientInfoMap {
		if clientInf.upfIP == ip2int(upfIP) {
			blockingClients = append(blockingClients, int2ip(clientIP))
		}
	}
	return blockingClients
}

// Method for removing an UPF from the BPF map.
//
// Will fail if there are any clients attached to this UPF. Users will need to remove all attached clients beforehand.
func (x XDPGTP) RemoveUpf(upfIP net.IP) error {
	blockingClients := x.GetClientsForUpf(upfIP)

	// Error message construction.
	if len(blockingClients) != 0 {
		blockingClientsStr := make([]string, len(blockingClients))
		for idx, blockingIP := range blockingClients {
			blockingClientsStr[idx] = blockingIP.String()
		}
		return fmt.Errorf("Could not delete UPF, %d clients depend on this UPF: %s",
			len(blockingClients), strings.Join(blockingClientsStr, ", "))
	}

	err := x.objs.UpfMap.Delete(ip2int(upfIP))
	if err != nil {
		return fmt.Errorf("Could not delete UPF: %s", err)
	}

	delete(x.upfInfoMap, ip2int(upfIP))

	return nil
}

// Method for removing a client from the BPF map.
func (x XDPGTP) RemoveClient(clientIP net.IP) error {
	err := x.objs.ClientMap.Delete(ip2int(clientIP))
	if err != nil {
		return fmt.Errorf("Could not delete client: %s", err)
	}

	delete(x.clientInfoMap, ip2int(clientIP))

	return nil
}

// Method for extracting the stats of transmitted packets in both directions
// (client->UPF and UPF->client).
//
// This function returns an array of UsageStats of length 2 ([0] for client->UPF
// and [1] for UPF->client).
func (x XDPGTP) GetUsageStats() ([2]UsageStats, error) {
	var val []UsageStats
	var totalStats [2]UsageStats

	for idx := range totalStats {
		err := x.objs.Txcnt.Lookup((uint32)(idx), &val)
		if err != nil {
			return totalStats, err
		}

		// Add up the information from all the CPU cores
		for _, stats := range val {
			totalStats[idx].Packets += stats.Packets
			totalStats[idx].Bytes += stats.Bytes
		}
	}

	return totalStats, nil
}

// This Function reports whether an IP address is reachable with an ICMP echo request.
func PingEndpoint(endpointIP string) (bool, error) {
	reachable := false

	pinger, err := probing.NewPinger(endpointIP)
	if err != nil {
		return reachable, err
	}
	pinger.Count = 1
	pinger.Timeout = 50000000 // 50 ms timeout
	err = pinger.Run()        // Blocks until finished
	if err != nil {
		return reachable, err
	}

	if pinger.PacketsRecv == 0 {
		return false, nil
	}

	return true, nil
}

// Function for obtaining the output routed interface, next hop's hardware address,
// and output routed interface's IP address for a given endpoint.
func getEndpointAddrs(endpointIP net.IP) (*net.Interface, net.HardwareAddr, net.IP, error) {
	router, err := netroute.New()
	if err != nil {
		return nil, nil, nil, err
	}

	// Check system's routing table.
	outputIface, gateway, localIP, err := router.Route(endpointIP)
	if err != nil {
		return nil, nil, nil, err
	}

	// If gateway is nil, that is, the UPF is found in the next hop, set the
	// gateway's address as the UPF's IP address.
	if gateway == nil {
		gateway = endpointIP
	}

	// Check the gateway's hardware address by means of an ARP ping.
	gwHwAddr, _, err := arping.Ping(gateway)
	if err != nil {
		return nil, nil, nil, err
	}

	return outputIface, gwHwAddr, localIP, nil
}
