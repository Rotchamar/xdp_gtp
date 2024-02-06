package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Rotchamar/xdp_gtp/xdpgtp"

	"github.com/cilium/ebpf/link"
)

// Custom flag type for inputting multiple flags of the same type at the same time.
type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

// Function for creating and populating ClientInfo and UpfInfo maps from an
// array of flags in the form "ClientIP,TEID,UpfIP", and the client-facing and
// UPF-facing interfaces.
//
// This function returns populated ClientInfo and  UpfInfo maps.
func populateClientUpfInfoMap(xgtp *xdpgtp.XDPGTP, clients []string) error {

	fmt.Println(clients)

	for _, client := range clients {
		ipTeidIp := strings.Split(client, ",")

		if len(ipTeidIp) != 3 {
			return fmt.Errorf("Wrong number of client parameters")
		}

		parsedClientIP := net.ParseIP(ipTeidIp[0])
		if parsedClientIP == nil {
			return fmt.Errorf("Invalid IP address: %s", ipTeidIp[0])
		}

		// Parse the teid string to a base-10 32-bit uint
		teid, err := strconv.ParseUint(ipTeidIp[1], 10, 32)
		if err != nil {
			return err
		}

		parsedUpfIP := net.ParseIP(ipTeidIp[2])
		if parsedUpfIP == nil {
			return fmt.Errorf("Invalid IP address: %s", ipTeidIp[2])
		}

		if !xgtp.UPFIsRegistered(parsedUpfIP) {
			err = xgtp.AddUPF(parsedUpfIP)
			if err != nil {
				return err
			}
		}

		if xgtp.ClientIsRegistered(parsedClientIP) {
			return fmt.Errorf("Client with IP address %s is duplicated", ipTeidIp[0])
		}

		err = xgtp.AddClient(parsedClientIP, uint32(teid), parsedUpfIP)
		if err != nil {
			return err
		}

	}

	return nil
}

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

	xgtp, err := xdpgtp.NewXDPGTP(xdpFlags)
	if err != nil {
		log.Fatalf("TODO Error: Could not load objects: %s", err)
	}
	defer xgtp.Close()

	if len(ifaceNamesSlice) == 1 ||
		(len(ifaceNamesSlice) == 2 && ifaceNamesSlice[0] == ifaceNamesSlice[1]) { // If client and UPF-facing interfaces are the same

		// Look up the network interface by name.
		commonIface, err := net.InterfaceByName(ifaceNamesSlice[0])
		if err != nil {
			log.Fatalf("Error: Looking up network iface %q failed: %s", ifaceNamesSlice[0], err)
		}

		// Attach the program.
		err = xgtp.AttachCommonProgramToInterface(commonIface.Index)
		if err != nil {
			log.Fatalf("TODO Error: Could not attach XDP program: %s", err)
		}
		defer xgtp.DetachProgramFromInterface(commonIface.Index)

		log.Printf("Attached XDP program to iface %q (index %d)", commonIface.Name, commonIface.Index)

	} else if len(ifaceNamesSlice) == 2 { // If client and UPF-facing interfaces are different
		// Look up the client-facing interface by name.
		clientIface, err := net.InterfaceByName(ifaceNamesSlice[0])
		if err != nil {
			log.Fatalf("Error: Looking up client-facing network iface %q failed: %s", ifaceNamesSlice[0], err)
		}

		// Look up the UPF-facing interface by name.
		upfIface, err := net.InterfaceByName(ifaceNamesSlice[1])
		if err != nil {
			log.Fatalf("Error: Looking up UPF-facing network iface %q failed: %s", ifaceNamesSlice[0], err)
		}

		// Attach the client-facing program.
		err = xgtp.AttachClientFacingProgramToInterface(clientIface.Index)
		if err != nil {
			log.Fatalf("TODO Error: Could not attach XDP program: %s", err)
		}
		defer xgtp.DetachProgramFromInterface(clientIface.Index)

		log.Printf("Attached client-facing XDP program to iface %q (index %d)", clientIface.Name, clientIface.Index)

		// Attach the UPF-facing program.
		err = xgtp.AttachUpfFacingProgramToInterface(upfIface.Index)
		if err != nil {
			log.Fatalf("TODO Error: Could not attach XDP program: %s", err)
		}
		defer xgtp.DetachProgramFromInterface(upfIface.Index)

		log.Printf("Attached UPF-facing XDP program to iface %q (index %d)", upfIface.Name, upfIface.Index)
	} else {
		log.Fatalf("Error: Wrong number of argments for -i flag: %d", len(ifaceNamesSlice))
	}

	log.Printf("Press Ctrl-C to exit and remove the program")

	err = populateClientUpfInfoMap(xgtp, clients)
	if err != nil {
		log.Fatalf("Error: Could not populate client and UPF maps: %s", err)
	}

	log.Printf("Client and UPF maps populated")

	// // Load UPF map in the XDP program.
	// for key, value := range upfInfMap {
	// 	err = objs.UpfMap.Put(key, value)
	// 	if err != nil {
	// 		log.Fatalf("Error: Could not load UPF with IP %v: %s", int2ip(key), err)
	// 	}
	// }

	log.Printf("UPFs' map loaded")

	// // Load client map in the XDP program.
	// for key, value := range clientInfMap {
	// 	err = objs.ClientMap.Put(key, value)
	// 	if err != nil {
	// 		log.Fatalf("Error: Could not load client with IP %v: %s", int2ip(key), err)
	// 	}
	// }

	log.Printf("Clients' map loaded")

	var oldStats [2]xdpgtp.UsageStats
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Periodic function for map information extraction.
	for range ticker.C {

		newStats, err := xgtp.GetUsageStats()
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
