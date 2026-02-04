//go:build !pfring

package capture

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func InitializeCapture(interfaceName string) (*gopacket.PacketSource, error) {
	log.Println("[IOAM Agent] Initializing capture with libpcap")
	handle, err := pcap.OpenLive(interfaceName, 2048, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("Couldn't open device %s: %v", interfaceName, err)
	}
	if err := handle.SetBPFFilter("ip6[6] == 0"); err != nil {
		return nil, fmt.Errorf("Couldn't set BPF filter: %v", err)
	}
	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		return nil, fmt.Errorf("Error setting handle direction: %v", err)
	}
	return gopacket.NewPacketSource(handle, handle.LinkType()), nil
}
