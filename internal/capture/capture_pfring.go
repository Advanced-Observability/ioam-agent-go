//go:build pfring

package capture

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
)

func InitializeCapture(interfaceName string) (*gopacket.PacketSource, error) {
	log.Println("[IOAM Agent] Initializing capture with PF_RING")
	ring, err := pfring.NewRing(interfaceName, 2048, pfring.FlagPromisc)
	if err != nil {
		return nil, fmt.Errorf("Couldn't open device %s: %v", interfaceName, err)
	}
	if err := ring.SetBPFFilter("ip6[6] == 0"); err != nil {
		return nil, fmt.Errorf("Couldn't set BPF filter: %v", err)
	}
	if err := ring.SetDirection(pfring.ReceiveOnly); err != nil {
		return nil, fmt.Errorf("Error setting ring direction: %v", err)
	}
	if err := ring.Enable(); err != nil {
		return nil, fmt.Errorf("Error enabling ring: %v", err)
	}
	return gopacket.NewPacketSource(ring, layers.LinkTypeEthernet), nil
}
