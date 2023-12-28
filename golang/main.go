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

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../gtp.c -- -I../common

func main() {

	// var upfs arrayFlags
	var clients arrayFlags

	// flag.Var(&upfs, "u", "UPF IP address")
	flag.Var(&clients, "c", "A,B,C -> A: Client IP addr | B: TEID | C: UPF IP addr")
	ifaceNames := flag.String("i", "enp0s3", "A,B -> A: Interface where XDP client-facing program is to be attached "+
		"| B: Interface where XDP UPF-facing program is to be attached \n"+
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
		log.Fatalf("%s is not a valid XDP attach mode", *xdpMode)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %s", err)
	}
	defer objs.Close()

	var iface_client, iface_upf *net.Interface

	if len(ifaceNamesSlice) == 1 {
		// Look up the network interface by name.
		iface, err := net.InterfaceByName(ifaceNamesSlice[0])
		if err != nil {
			log.Fatalf("Lookup network iface %q: %s", ifaceNamesSlice[0], err)
		}

		// Attach the program.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGtpCommon,
			Interface: iface.Index,
			Flags:     xdpFlags,
		})
		if err != nil {
			log.Fatalf("Could not attach XDP program: %s", err)
		}
		defer l.Close()

		log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)

		iface_client = iface
		iface_upf = iface

	} else if len(ifaceNamesSlice) == 2 {
		var err error

		// Look up the client-facing interface by name.
		iface_client, err = net.InterfaceByName(ifaceNamesSlice[0])
		if err != nil {
			log.Fatalf("Lookup client-facing network iface %q: %s", ifaceNamesSlice[0], err)
		}

		// Look up the upf-facing interface by name.
		iface_upf, err = net.InterfaceByName(ifaceNamesSlice[1])
		if err != nil {
			log.Fatalf("Lookup UPF-facing network iface %q: %s", ifaceNamesSlice[0], err)
		}

		// Attach the client-facing program.
		l_client, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGtpClient,
			Interface: iface_client.Index,
			Flags:     xdpFlags,
		})
		if err != nil {
			log.Fatalf("Could not attach XDP program: %s", err)
		}
		defer l_client.Close()

		log.Printf("Attached client-facing XDP program to iface %q (index %d)", iface_client.Name, iface_client.Index)

		// Attach the UPF-facing program.
		l_upf, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpGtpUpf,
			Interface: iface_upf.Index,
			Flags:     xdpFlags,
		})
		if err != nil {
			log.Fatalf("Could not attach XDP program: %s", err)
		}
		defer l_upf.Close()

		log.Printf("Attached UPF-facing XDP program to iface %q (index %d)", iface_upf.Name, iface_upf.Index)
	} else {
		log.Fatalf("Wrong number of argments for -i flag: %d", len(ifaceNamesSlice))
	}

	log.Printf("Press Ctrl-C to exit and remove the program")

	client_inf_map, upf_inf_map, err := populate_client_upf_inf_map(clients, iface_client, iface_upf)
	if err != nil {
		log.Fatalf("Populating clients and UPFs maps: %s", err)
	}

	for key, value := range upf_inf_map {
		err = objs.UpfMap.Put(key, value)
		if err != nil {
			log.Fatalf("Could not load UPF with IP %v", int2ip(key))
		}
	}

	log.Printf("UPFs' map loaded")

	for key, value := range client_inf_map {
		err = objs.ClientMap.Put(key, value)
		if err != nil {
			log.Fatalf("Could not load client with IP %v", int2ip(key))
		}
	}

	log.Printf("Clients' map loaded")

	old_stats := make([]Usage_stats, 2)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {

		new_stats, err := extractUsageStats(objs.Rxcnt)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		s := fmt.Sprintf("Client->UPF:\tTotal packets sent = %10d (%12.2f pps)\n\t\t"+
			"Total Bytes sent   = %10d (%12.2f bps)\n"+
			"UPF->Client:\tTotal packets sent = %10d (%12.2f pps)\n\t\t"+
			"Total Bytes sent   = %10d (%12.2f bps)\n",
			new_stats[0].Packets,
			(float64)((new_stats[0].Packets-old_stats[0].Packets)/1),
			new_stats[0].Bytes,
			(float64)((new_stats[0].Bytes-old_stats[0].Bytes)/1*8),
			new_stats[1].Packets,
			(float64)((new_stats[1].Packets-old_stats[1].Packets)/1),
			new_stats[1].Bytes,
			(float64)((new_stats[1].Bytes-old_stats[1].Bytes)/1*8))

		old_stats = new_stats

		log.Printf("Map contents:\n%s\n", s)

		//countMap(objs.Rxcnttot)

	}

}

type Usage_stats struct {
	Packets uint64
	Bytes   uint64
}

// IP addrs in network byte order
type Client_info struct {
	teid         uint32
	upf_ip       uint32
	eth_next_hop [ETH_ALEN]uint8
	eth_local    [ETH_ALEN]uint8
	ifindex      uint32
}

// IP addrs in network byte order
type Upf_info struct {
	local_ip     uint32
	eth_next_hop [ETH_ALEN]uint8
	eth_local    [ETH_ALEN]uint8
	ifindex      uint32
}

func extractUsageStats(m *ebpf.Map) ([]Usage_stats, error) {
	var val []Usage_stats
	total_stats := make([]Usage_stats, 2)

	for idx := range total_stats {
		err := m.Lookup((uint32)(idx), &val)
		if err != nil {
			return nil, err
		}

		for _, stats := range val {
			total_stats[idx].Packets += stats.Packets
			total_stats[idx].Bytes += stats.Bytes
		}
	}

	return total_stats, nil
}

func countMap(m *ebpf.Map) {
	var (
		key    uint32
		val    []uint32
		totval uint32
	)
	key = 0

	err := m.Lookup(key, &val)
	if err != nil {
		fmt.Printf("\n%s\n\n", err)
		return
	}

	for _, v := range val {
		totval += v
	}

	fmt.Printf("\n%d\n\n", totval)

}

func populate_upf_inf_map(upfs arrayFlags, iface *net.Interface) (map[uint32]Upf_info, error) {
	upf_inf_map := make(map[uint32]Upf_info)

	for _, upf := range upfs {
		parsedUpfIP := net.ParseIP(upf)
		if parsedUpfIP == nil {
			return nil, fmt.Errorf("Invalid IP address: %s", upf)
		}

		var upf_inf Upf_info

		err := getUpfInfoAddrs(parsedUpfIP, &upf_inf, iface)
		if err != nil {
			return nil, err
		}

		upf_inf_map[ip2int(parsedUpfIP)] = upf_inf
	}

	return upf_inf_map, nil
}

func populate_client_upf_inf_map(clients arrayFlags, iface_client, iface_upf *net.Interface) (map[uint32]Client_info, map[uint32]Upf_info, error) {
	client_inf_map := make(map[uint32]Client_info)
	upf_inf_map := make(map[uint32]Upf_info)

	for _, client := range clients {
		ipteidip := strings.Split(client, ",")

		if len(ipteidip) != 3 {
			return nil, nil, fmt.Errorf("Wrong number of client parameters")
		}

		parsedClientIP := net.ParseIP(ipteidip[0])
		if parsedClientIP == nil {
			return nil, nil, fmt.Errorf("Invalid IP address: %s", ipteidip[0])
		}

		teid, err := strconv.ParseUint(ipteidip[1], 10, 32)
		if err != nil {
			return nil, nil, err
		}

		parsedUpfIP := net.ParseIP(ipteidip[2])
		if parsedUpfIP == nil {
			return nil, nil, fmt.Errorf("Invalid IP address: %s", ipteidip[0])
		}

		var upf_inf Upf_info

		err = getUpfInfoAddrs(parsedUpfIP, &upf_inf, iface_upf)
		if err != nil {
			return nil, nil, err
		}

		upf_inf_map[ip2int(parsedUpfIP)] = upf_inf

		var client_inf Client_info

		client_inf.teid = htonl(uint32(teid))
		client_inf.upf_ip = ip2int(parsedUpfIP)

		err = getClientInfoAddrs(parsedClientIP, &client_inf, iface_client)
		if err != nil {
			return nil, nil, err
		}

		client_inf_map[ip2int(parsedClientIP)] = client_inf
	}

	return client_inf_map, upf_inf_map, nil
}

func populate_client_inf_map(clients arrayFlags, upf_inf_map map[uint32]Upf_info, iface *net.Interface) (map[uint32]Client_info, error) {
	client_inf_map := make(map[uint32]Client_info)

	for _, client := range clients {
		ipteidip := strings.Split(client, ",")

		if len(ipteidip) != 3 {
			return nil, fmt.Errorf("Wrong number of client parameters")
		}

		parsedClientIP := net.ParseIP(ipteidip[0])
		if parsedClientIP == nil {
			return nil, fmt.Errorf("Invalid IP address: %s", ipteidip[0])
		}

		teid, err := strconv.ParseUint(ipteidip[1], 10, 32)
		if err != nil {
			return nil, err
		}

		parsedUpfIP := net.ParseIP(ipteidip[2])
		if parsedUpfIP == nil {
			return nil, fmt.Errorf("Invalid IP address: %s", ipteidip[0])
		}

		if _, ok := upf_inf_map[ip2int(parsedUpfIP)]; ok == false {
			return nil, fmt.Errorf("UPF with IP address = %v does not exist for client IP = %v", ipteidip[2], ipteidip[0])
		}

		var client_inf Client_info

		client_inf.teid = htonl(uint32(teid))
		client_inf.upf_ip = ip2int(parsedUpfIP)

		err = getClientInfoAddrs(parsedClientIP, &client_inf, iface)
		if err != nil {
			return nil, err
		}

		client_inf_map[ip2int(parsedClientIP)] = client_inf
	}

	return client_inf_map, nil
}

func getClientInfoAddrs(targetIP net.IP, client_inf *Client_info, xdp_iface *net.Interface) error {

	// Probe if host is reachable (only needed for UPF?)
	pinger, err := probing.NewPinger(targetIP.String())
	if err != nil {
		return err
	}
	pinger.Count = 1
	pinger.Timeout = 50000000 // 50 ms timeout
	err = pinger.Run()        // Blocks until finished.
	if err != nil {
		return err
	}

	if pinger.PacketsRecv == 0 {
		log.Printf("Could not reach host with IP = %s", targetIP.String())
	}

	// Check routing table
	r, err := netroute.New()
	if err != nil {
		return err
	}

	iface, gw, _, err := r.Route(targetIP)
	if err != nil {
		return err
	}

	if iface.Index != xdp_iface.Index {
		return fmt.Errorf("Traffic to client is not routed through the designated interface (%s instead of %s)", iface.Name, xdp_iface.Name)
	}

	if gw == nil {
		gw = targetIP
	}

	hwAddr, _, err := arping.Ping(gw)
	if err != nil {
		return fmt.Errorf("Error ARPing next hop: %v", err)
	}

	client_inf.eth_next_hop = [6]uint8(hwAddr)
	client_inf.eth_local = [6]uint8(iface.HardwareAddr)
	client_inf.ifindex = uint32(iface.Index)

	return nil
}

func getUpfInfoAddrs(targetIP net.IP, upf_inf *Upf_info, xdp_iface *net.Interface) error {

	// Probe if host is reachable (only needed for UPF?)
	pinger, err := probing.NewPinger(targetIP.String())
	if err != nil {
		return err
	}
	pinger.Count = 1
	pinger.Timeout = 50000000 // 50 ms timeout
	err = pinger.Run()        // Blocks until finished.
	if err != nil {
		return err
	}

	if pinger.PacketsRecv == 0 {
		log.Printf("Could not reach UPF with IP = %s", targetIP.String())
	}

	// Check routing table
	r, err := netroute.New()
	if err != nil {
		return err
	}

	iface, gw, local_ip, err := r.Route(targetIP)
	if err != nil {
		return err
	}

	if iface.Index != xdp_iface.Index {
		return fmt.Errorf("Traffic to UPF is not routed through the designated interface (%s instead of %s)", iface.Name, xdp_iface.Name)
	}

	if gw == nil {
		gw = targetIP
	}

	hwAddr, _, err := arping.Ping(gw)
	if err != nil {
		return err
	}

	upf_inf.local_ip = ip2int(local_ip)
	upf_inf.eth_next_hop = [6]uint8(hwAddr)
	upf_inf.eth_local = [6]uint8(iface.HardwareAddr)
	upf_inf.ifindex = uint32(iface.Index)

	return nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.LittleEndian.Uint32(ip[12:16])
	}
	return binary.LittleEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, nn)
	return ip
}

func htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}
