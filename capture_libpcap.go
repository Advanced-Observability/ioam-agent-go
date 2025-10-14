//go:build !pfring

package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func initializeCapture(interfaceName string) (*gopacket.PacketSource, error) {
	fmt.Println("[Ioam Agent] Initializing capture with libpcap")
	handle, err := pcap.OpenLive(interfaceName, 2048, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("couldn't open device %s: %v", interfaceName, err)
	}
	if err := handle.SetBPFFilter("ip6[6] == 0"); err != nil {
		return nil, fmt.Errorf("couldn't set BPF filter: %v", err)
	}
	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		return nil, fmt.Errorf("error setting handle direction: %v", err)
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}
