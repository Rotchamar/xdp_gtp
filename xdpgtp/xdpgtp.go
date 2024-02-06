package xdpgtp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target "bpf" gtp ../ebpf-c/gtp.c -- -I../ebpf-c/common -Wall -Werror

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/j-keck/arping"
	"github.com/libp2p/go-netroute"
	probing "github.com/prometheus-community/pro-bing"
)

const ethAddrLen = 6

// Struct for storing usage statistics in BPF map.
type UsageStats struct {
	Packets uint64 // Number of packets sent since program was attached
	Bytes   uint64 // Number of bytes sent since program was attached
}

// Struct for storing UPF information in BPF map.
type UpfInfo struct {
	LocalIP    uint32            // IP address of the host's UPF-facing interface (network byte order)
	EthNextHop [ethAddrLen]uint8 // Destination Ethernet address for packets sent towards UPF
	EthLocal   [ethAddrLen]uint8 // Source Ethernet address for packets sent towards UPF
	Ifindex    uint32            // UPF-facing interface index
}

// Struct for storing client information in BPF map.
type ClientInfo struct {
	Teid       uint32            // GTP Tunnel Endpoint Identifier
	UpfIP      uint32            // Client's UPF's IP address (network byte order)
	EthNextHop [ethAddrLen]uint8 // Destination Ethernet address for packets sent towards client
	EthLocal   [ethAddrLen]uint8 // Source Ethernet address for packets sent towards client
	Ifindex    uint32            // Client-facing interface index
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

// Function for extracting the stats of transmitted packets in both directions
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

func pingEndpoint(endpointIP string) (bool, error) {
	reachable := false

	// Probe if endpoint is reachable.
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
	hwAddr, _, err := arping.Ping(gateway)
	if err != nil {
		return nil, nil, nil, err
	}

	return outputIface, hwAddr, localIP, nil
}

// Function for populating UpfInfo's elements given its IP address.
func getUpfInfoAddrs(upfIP net.IP, upfInf *UpfInfo, xdpIface *net.Interface) error {

	// Probe if UPF is reachable.
	reachable, err := pingEndpoint(upfIP.String())
	if err != nil {
		return err
	}
	if !reachable {
		log.Printf("Could not reach UPF with IP = %s", upfIP.String())
	}

	outputIface, hwAddr, localIP, err := getEndpointAddrs(upfIP)
	if err != nil {
		return err
	}

	if outputIface.Index != xdpIface.Index {
		return fmt.Errorf("Traffic to UPF is not routed through the designated interface (%s instead of %s)",
			outputIface.Name, xdpIface.Name)
	}

	upfInf.LocalIP = ip2int(localIP)
	upfInf.EthNextHop = [6]uint8(hwAddr)
	upfInf.EthLocal = [6]uint8(outputIface.HardwareAddr)
	upfInf.Ifindex = uint32(outputIface.Index)

	return nil
}

// Function for populating ClientInfo's routing-related elements given its IP address.
func getClientInfoAddrs(clientIP net.IP, clientInf *ClientInfo, xdpIface *net.Interface) error {

	// Probe if UPF is reachable.
	reachable, err := pingEndpoint(clientIP.String())
	if err != nil {
		return err
	}
	if !reachable {
		log.Printf("Could not reach client with IP = %s", clientIP.String())
	}

	outputIface, hwAddr, _, err := getEndpointAddrs(clientIP)
	if err != nil {
		return err
	}

	if outputIface.Index != xdpIface.Index {
		return fmt.Errorf("Traffic to client is not routed through the designated interface (%s instead of %s)",
			outputIface.Name, xdpIface.Name)
	}

	clientInf.EthNextHop = [6]uint8(hwAddr)
	clientInf.EthLocal = [6]uint8(outputIface.HardwareAddr)
	clientInf.Ifindex = uint32(outputIface.Index)

	return nil
}

type xdpgtpMode uint8

const (
	xdpgtpNone xdpgtpMode = iota
	xdpgtpClient
	xdpgtpUpf
	xdpgtpCommon
)

type ifaceStatus struct {
	mode    xdpgtpMode
	xdpLink link.Link
}

type XDPGTP struct {
	objs          gtpObjects
	xdpFlags      link.XDPAttachFlags
	ifaces        map[int]ifaceStatus
	upfInfoMap    map[uint32]UpfInfo
	clientInfoMap map[uint32]ClientInfo
}

func NewXDPGTP(xdpFlags link.XDPAttachFlags) (*XDPGTP, error) {
	x := XDPGTP{}

	x.objs = gtpObjects{}
	if err := loadGtpObjects(&x.objs, nil); err != nil {
		return nil, fmt.Errorf("Could not load objects: %s", err)
	}

	x.xdpFlags = xdpFlags
	x.ifaces = make(map[int]ifaceStatus)
	x.upfInfoMap = make(map[uint32]UpfInfo)
	x.clientInfoMap = make(map[uint32]ClientInfo)

	return &x, nil
}

// defer after creating new xdpgtp
func (x XDPGTP) Close() error {
	return x.objs.Close()
}

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

func (x XDPGTP) AttachClientFacingProgramToInterface(clientIfindex int) error {
	err := x.attachProgramToInterface(clientIfindex, x.objs.XdpGtpClient, xdpgtpClient)
	if err != nil {
		return err
	}

	return nil
}

func (x XDPGTP) AttachUpfFacingProgramToInterface(upfIfindex int) error {
	err := x.attachProgramToInterface(upfIfindex, x.objs.XdpGtpUpf, xdpgtpUpf)
	if err != nil {
		return err
	}

	return nil
}

func (x XDPGTP) AttachCommonProgramToInterface(commonIfindex int) error {
	err := x.attachProgramToInterface(commonIfindex, x.objs.XdpGtpCommon, xdpgtpCommon)
	if err != nil {
		return err
	}

	return nil
}

// Defer after attaching any program
func (x XDPGTP) DetachProgramFromInterface(ifindex int) error {

	ifaceStatus, ok := x.ifaces[ifindex]

	if !ok || ifaceStatus.mode == xdpgtpNone {
		return fmt.Errorf("Interface doesn't have any program attached")
	}

	ifaceStatus.xdpLink.Close()
	delete(x.ifaces, ifindex)

	return nil
}

func (x XDPGTP) UpfIsRegistered(upfIP net.IP) bool {
	_, isRegistered := x.upfInfoMap[ip2int(upfIP)]
	return isRegistered
}

func (xgtp XDPGTP) ClientIsRegistered(clientIP net.IP) bool {
	_, isRegistered := xgtp.clientInfoMap[ip2int(clientIP)]
	return isRegistered
}

func (x XDPGTP) AddUPF(upfIP net.IP) error {
	upfInf := UpfInfo{}

	routedIface, hwAddr, localIP, err := getEndpointAddrs(upfIP)
	if err != nil {
		return fmt.Errorf("Could not acquire UPF-related addresses: %s", err)
	}

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

	upfInf.LocalIP = ip2int(localIP)
	upfInf.EthNextHop = [6]uint8(hwAddr)
	upfInf.EthLocal = [6]uint8(routedIface.HardwareAddr)
	upfInf.Ifindex = uint32(routedIface.Index)

	x.upfInfoMap[ip2int(upfIP)] = upfInf

	err = x.objs.UpfMap.Update(ip2int(upfIP), upfInf, ebpf.UpdateNoExist)
	if err != nil {
		return fmt.Errorf("Could not load UPF: %s", err)
	}

	return nil
}

func (x XDPGTP) GetClientsForUPF(upfIP net.IP) []net.IP {

	blockingClients := make([]net.IP, 0)
	for clientIP, clientInf := range x.clientInfoMap {
		if clientInf.UpfIP == ip2int(upfIP) {
			blockingClients = append(blockingClients, int2ip(clientIP))
		}
	}
	return blockingClients
}

func (x XDPGTP) DeleteUPF(upfIP net.IP) error {

	blockingClients := x.GetClientsForUPF(upfIP)

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

func (x XDPGTP) AddClient(clientIP net.IP, teid uint32, upfIP net.IP) error {
	clientInf := ClientInfo{}

	if !x.UpfIsRegistered(upfIP) {
		return fmt.Errorf("Assigned client has not been previously registered")
	}

	routedIface, hwAddr, _, err := getEndpointAddrs(clientIP)
	if err != nil {
		return fmt.Errorf("Could not acquire client-related addresses: %s", err)
	}

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

	clientInf.Teid = teid
	clientInf.UpfIP = ip2int(upfIP)
	clientInf.EthNextHop = [6]uint8(hwAddr)
	clientInf.EthLocal = [6]uint8(routedIface.HardwareAddr)
	clientInf.Ifindex = uint32(routedIface.Index)

	x.clientInfoMap[ip2int(clientIP)] = clientInf

	err = x.objs.ClientMap.Update(ip2int(clientIP), clientInf, ebpf.UpdateNoExist)
	if err != nil {
		return fmt.Errorf("Could not load client: %s", err)
	}

	return nil
}

func (x XDPGTP) DeleteClient(clientIP net.IP) error {
	err := x.objs.ClientMap.Delete(ip2int(clientIP))
	if err != nil {
		return fmt.Errorf("Could not delete client: %s", err)
	}

	delete(x.clientInfoMap, ip2int(clientIP))

	return nil
}
