package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/j-keck/arping"
	"github.com/libp2p/go-netroute"
	probing "github.com/prometheus-community/pro-bing"
)

const ETH_ALEN = 6

// Custom flag type for inputting multiple flags of the same type at the same time.
type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Struct for storing usage statistics in BPF map.
type UsageStats struct {
	Packets uint64 // Number of packets sent since program was attached
	Bytes   uint64 // Number of bytes sent since program was attached
}

// Struct for storing UPF information in BPF map.
type UpfInfo struct {
	LocalIP    uint32          // IP address of the host's UPF-facing interface (network byte order)
	EthNextHop [ETH_ALEN]uint8 // Destination Ethernet address for packets sent towards UPF
	EthLocal   [ETH_ALEN]uint8 // Source Ethernet address for packets sent towards UPF
	Ifindex    uint32          // UPF-facing interface index
}

// Struct for storing client information in BPF map.
type ClientInfo struct {
	Teid       uint32          // GTP Tunnel Endpoint Identifier
	UpfIP      uint32          // Client's UPF's IP address (network byte order)
	EthNextHop [ETH_ALEN]uint8 // Destination Ethernet address for packets sent towards client
	EthLocal   [ETH_ALEN]uint8 // Source Ethernet address for packets sent towards client
	Ifindex    uint32          // Client-facing interface index
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
// (client->UPF and UPF->client) from a BPF per-CPU-array map.
//
// This function returns an array of UsageStats of length 2 ([0] for client->UPF
// and [1] for UPF->client).
func extractUsageStats(m *ebpf.Map) ([2]UsageStats, error) {
	var val []UsageStats
	var totalStats [2]UsageStats

	for idx := range totalStats {
		err := m.Lookup((uint32)(idx), &val)
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

// Function for populating UpfInfo's elements given its IP address.
func getUpfInfoAddrs(upfIP net.IP, upfInf *UpfInfo, xdpIface *net.Interface) error {

	// Probe if UPF is reachable.
	pinger, err := probing.NewPinger(upfIP.String())
	if err != nil {
		return err
	}
	pinger.Count = 1
	pinger.Timeout = 50000000 // 50 ms timeout
	err = pinger.Run()        // Blocks until finished
	if err != nil {
		return err
	}

	if pinger.PacketsRecv == 0 {
		log.Printf("Could not reach UPF with IP = %s", upfIP.String())
	}

	router, err := netroute.New()
	if err != nil {
		return err
	}

	// Check system's routing table.
	iface, gateway, localIP, err := router.Route(upfIP)
	if err != nil {
		return err
	}

	if iface.Index != xdpIface.Index {
		return fmt.Errorf("Traffic to UPF is not routed through the designated interface (%s instead of %s)", iface.Name, xdpIface.Name)
	}

	// If gateway is nil, that is, the UPF is found in the next hop, set the
	// gateway's address as the UPF's IP address.
	if gateway == nil {
		gateway = upfIP
	}

	// Check the gateway's hardware address by means of an ARP ping.
	hwAddr, _, err := arping.Ping(gateway)
	if err != nil {
		return err
	}

	upfInf.LocalIP = ip2int(localIP)
	upfInf.EthNextHop = [6]uint8(hwAddr)
	upfInf.EthLocal = [6]uint8(iface.HardwareAddr)
	upfInf.Ifindex = uint32(iface.Index)

	return nil
}

// Function for populating ClientInfo's routing-related elements given its IP address.
func getClientInfoAddrs(clientIP net.IP, clientInf *ClientInfo, xdpIface *net.Interface) error {

	// Probe if client is reachable
	pinger, err := probing.NewPinger(clientIP.String())
	if err != nil {
		return err
	}
	pinger.Count = 1
	pinger.Timeout = 50000000 // 50 ms timeout
	err = pinger.Run()        // Blocks until finished
	if err != nil {
		return err
	}

	if pinger.PacketsRecv == 0 {
		log.Printf("Could not reach client with IP = %s", clientIP.String())
	}

	router, err := netroute.New()
	if err != nil {
		return err
	}

	// Check system's routing table.
	iface, gateway, _, err := router.Route(clientIP)
	if err != nil {
		return err
	}

	if iface.Index != xdpIface.Index {
		return fmt.Errorf("Traffic to client is not routed through the designated interface (%s instead of %s)", iface.Name, xdpIface.Name)
	}

	// If gateway is nil, that is, the client is found in the next hop, set the
	// gateway's address as the client's IP address.
	if gateway == nil {
		gateway = clientIP
	}

	// Check the gateway's hardware address by means of an ARP ping.
	hwAddr, _, err := arping.Ping(gateway)
	if err != nil {
		return fmt.Errorf("Error ARPing next hop: %v", err)
	}

	clientInf.EthNextHop = [6]uint8(hwAddr)
	clientInf.EthLocal = [6]uint8(iface.HardwareAddr)
	clientInf.Ifindex = uint32(iface.Index)

	return nil
}

// Function for creating and populating ClientInfo and UpfInfo maps from an
// array of flags in the form "ClientIP,TEID,UpfIP", and the client-facing and
// UPF-facing interfaces.
//
// This function returns populated ClientInfo and  UpfInfo maps.
func populateClientUpfInfoMap(
	clients arrayFlags, clientIface, upfIface *net.Interface,
) (
	map[uint32]ClientInfo, map[uint32]UpfInfo, error,
) {
	clientInfoMap := make(map[uint32]ClientInfo)
	upfInfoMap := make(map[uint32]UpfInfo)

	for _, client := range clients {
		ipTeidIp := strings.Split(client, ",")

		if len(ipTeidIp) != 3 {
			return nil, nil, fmt.Errorf("Wrong number of client parameters")
		}

		parsedClientIP := net.ParseIP(ipTeidIp[0])
		if parsedClientIP == nil {
			return nil, nil, fmt.Errorf("Invalid IP address: %s", ipTeidIp[0])
		}

		// Parse the teid string to a base-10 32-bit uint
		teid, err := strconv.ParseUint(ipTeidIp[1], 10, 32)
		if err != nil {
			return nil, nil, err
		}

		parsedUpfIP := net.ParseIP(ipTeidIp[2])
		if parsedUpfIP == nil {
			return nil, nil, fmt.Errorf("Invalid IP address: %s", ipTeidIp[2])
		}

		// Check if UPF is already registered to avoid redundant code.
		if _, upfIsRegistered := upfInfoMap[ip2int(parsedUpfIP)]; !upfIsRegistered {
			var upfInfo UpfInfo

			err = getUpfInfoAddrs(parsedUpfIP, &upfInfo, upfIface)
			if err != nil {
				return nil, nil, err
			}

			upfInfoMap[ip2int(parsedUpfIP)] = upfInfo
		}

		if _, clientIsRegistered := clientInfoMap[ip2int(parsedClientIP)]; clientIsRegistered {
			return nil, nil, fmt.Errorf("Client with IP address %s is duplicated", ipTeidIp[0])
		}

		var clientInfo ClientInfo

		clientInfo.Teid = htonl(uint32(teid))
		clientInfo.UpfIP = ip2int(parsedUpfIP)

		err = getClientInfoAddrs(parsedClientIP, &clientInfo, clientIface)
		if err != nil {
			return nil, nil, err
		}

		clientInfoMap[ip2int(parsedClientIP)] = clientInfo
	}

	return clientInfoMap, upfInfoMap, nil
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target "bpf" gtp ../gtp.c -- -I../common -Wall -Werror

func main() {

	var clients arrayFlags

	flag.Var(&clients, "c", "A,B,C -> A: Client IP addr | B: TEID | C: UPF IP addr")
	ifaceNames := flag.String("i", "enp0s3", "A,B -> A: Interface where XDP client-facing program is to be attached "+
		"| B: Interface where XDP UPF-facing program is to be attached "+
		"(if not supplied, both will be attached to the same interface)")
	xdpMode := flag.String("m", "generic", "XDP attach mode (generic|driver|offload)")
	flag.Parse()

	ifaceNamesSlice := strings.Split(*ifaceNames, ",")

	var xdpFlags link.XDPAttachFlags

	switch *xdpMode {
	case "generic":
		xdpFlags = link.XDPGenericMode
	case "driver":
		xdpFlags = link.XDPDriverMode
	case "offload":
		xdpFlags = link.XDPOffloadMode
	default:
		log.Fatalf("Error: %s is not a valid XDP attach mode", *xdpMode)
	}

	// Load pre-compiled programs into the kernel.
	objs := gtpObjects{}
	if err := loadGtpObjects(&objs, nil); err != nil {
		log.Fatalf("Error: Loading objects: %s", err)
	}
	defer objs.Close()

	var clientIface, upfIface *net.Interface
	var err error

	if len(ifaceNamesSlice) == 1 ||
		(len(ifaceNamesSlice) == 2 && ifaceNamesSlice[0] == ifaceNamesSlice[1]) { // If client and UPF-facing interfaces are the same

		// Look up the network interface by name.
		iface, err := net.InterfaceByName(ifaceNamesSlice[0])
		if err != nil {
			log.Fatalf("Error: Lookup network iface %q: %s", ifaceNamesSlice[0], err)
		}

		// Attach the program.
		commonXDPLink, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGtpCommon,
			Interface: iface.Index,
			Flags:     xdpFlags,
		})
		if err != nil {
			log.Fatalf("Error: Could not attach XDP program: %s", err)
		}
		defer commonXDPLink.Close()

		log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

		clientIface = iface
		upfIface = iface

	} else if len(ifaceNamesSlice) == 2 { // If client and UPF-facing interfaces are different
		// Look up the client-facing interface by name.
		clientIface, err = net.InterfaceByName(ifaceNamesSlice[0])
		if err != nil {
			log.Fatalf("Error: Lookup client-facing network iface %q: %s", ifaceNamesSlice[0], err)
		}

		// Look up the UPF-facing interface by name.
		upfIface, err = net.InterfaceByName(ifaceNamesSlice[1])
		if err != nil {
			log.Fatalf("Error: Lookup UPF-facing network iface %q: %s", ifaceNamesSlice[0], err)
		}

		// Attach the client-facing program.
		clientXDPLink, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGtpClient,
			Interface: clientIface.Index,
			Flags:     xdpFlags,
		})
		if err != nil {
			log.Fatalf("Error: Could not attach XDP program: %s", err)
		}
		defer clientXDPLink.Close()

		log.Printf("Attached client-facing XDP program to iface %q (index %d)", clientIface.Name, clientIface.Index)

		// Attach the UPF-facing program.
		upfXDPLink, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGtpUpf,
			Interface: upfIface.Index,
			Flags:     xdpFlags,
		})
		if err != nil {
			log.Fatalf("Error: Could not attach XDP program: %s", err)
		}
		defer upfXDPLink.Close()

		log.Printf("Attached UPF-facing XDP program to iface %q (index %d)", upfIface.Name, upfIface.Index)
	} else {
		log.Fatalf("Error: Wrong number of argments for -i flag: %d", len(ifaceNamesSlice))
	}

	log.Printf("Press Ctrl-C to exit and remove the program")

	clientInfMap, upfInfMap, err := populateClientUpfInfoMap(clients, clientIface, upfIface)
	if err != nil {
		log.Fatalf("Error: Populating client and UPF maps: %s", err)
	}

	log.Printf("Client and UPF maps populated")

	// Load UPF map in the XDP program.
	for key, value := range upfInfMap {
		err = objs.UpfMap.Put(key, value)
		if err != nil {
			log.Fatalf("Error: Could not load UPF with IP %v: %s", int2ip(key), err)
		}
	}

	log.Printf("UPFs' map loaded")

	// Load client map in the XDP program.
	for key, value := range clientInfMap {
		err = objs.ClientMap.Put(key, value)
		if err != nil {
			log.Fatalf("Error: Could not load client with IP %v: %s", int2ip(key), err)
		}
	}

	log.Printf("Clients' map loaded")

	var oldStats [2]UsageStats
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Periodic function for map information extraction.
	for range ticker.C {

		newStats, err := extractUsageStats(objs.Txcnt)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		s := fmt.Sprintf("Client->UPF:\tTotal packets sent = %10d (%12.2f pps)\n\t\t"+
			"Total Bytes sent   = %10d (%12.2f bps)\n"+
			"UPF->Client:\tTotal packets sent = %10d (%12.2f pps)\n\t\t"+
			"Total Bytes sent   = %10d (%12.2f bps)\n",
			newStats[0].Packets,
			(float64)((newStats[0].Packets-oldStats[0].Packets)/1),
			newStats[0].Bytes,
			(float64)((newStats[0].Bytes-oldStats[0].Bytes)/1*8),
			newStats[1].Packets,
			(float64)((newStats[1].Packets-oldStats[1].Packets)/1),
			newStats[1].Bytes,
			(float64)((newStats[1].Bytes-oldStats[1].Bytes)/1*8))

		oldStats = newStats

		log.Printf("Map contents:\n%s\n", s)
	}
}
