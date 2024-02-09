package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Rotchamar/xdp_gtp/xdpgtp"
	"github.com/cilium/ebpf/link"
)

func main() {

	clientIface, err := net.InterfaceByName("eth0")
	if err != nil {
		return
	}

	upfIface, err := net.InterfaceByName("eth1")
	if err != nil {
		return
	}

	xgtp, err := xdpgtp.NewXDPGTP(link.XDPGenericMode)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer xgtp.Close()

	err = xgtp.AttachClientFacingProgramToInterface(clientIface.Index)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer xgtp.DetachProgramFromInterface(clientIface.Index)

	err = xgtp.AttachUpfFacingProgramToInterface(upfIface.Index)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer xgtp.DetachProgramFromInterface(upfIface.Index)

	err = xgtp.AddUpf(net.ParseIP("10.0.100.20"))
	if err != nil {
		fmt.Println(err)
		return
	}

	err = xgtp.AddClient(net.ParseIP("10.0.1.10"), 1, net.ParseIP("10.0.100.20"))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Press Ctrl-C to exit")

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
