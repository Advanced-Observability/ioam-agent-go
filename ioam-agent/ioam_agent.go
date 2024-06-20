package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	SPECIFIC_HEADER_TYPE = layers.IPProtocol(43) // Replace with your specific IPv6 header type
	IPV6_HOP_BY_HOP      = layers.IPProtocol(0)
)

func listDevices() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	fmt.Println("Available devices:")
	for _, device := range devices {
		fmt.Printf("%s", device.Name)
		if device.Description != "" {
			fmt.Printf(" (%s)", device.Description)
		}
		fmt.Println()
	}
}

func printIP6Address(addr net.IP) {
	fmt.Printf("Source IP Address: %s\n", addr)
}

func sendResponsePacket(handle *pcap.Handle, origIP *layers.IPv6) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Create a new IPv6 header
	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      origIP.DstIP,
		DstIP:      origIP.SrcIP,
		NextHeader: layers.IPProtocolNoNextHeader,
		HopLimit:   255,
	}

	// Serialize the IPv6 header
	if err := ipv6.SerializeTo(buffer, opts); err != nil {
		log.Fatalf("Error serializing IPv6 header: %v", err)
	}

	// Send the packet
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Printf("Error sending packet: %v", err)
	}
}

func packetHandler(handle *pcap.Handle, packet gopacket.Packet) {
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		printIP6Address(ipv6.SrcIP)

		// Check if the next header field matches the specific type or Hop-by-Hop Options header
		if ipv6.NextHeader == SPECIFIC_HEADER_TYPE || ipv6.NextHeader == IPV6_HOP_BY_HOP {
			fmt.Printf("Received a packet with the specific IPv6 header type %d or Hop-by-Hop Options header\n", SPECIFIC_HEADER_TYPE)

			if ipv6.NextHeader == IPV6_HOP_BY_HOP {
				hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
				if hbhLayer != nil {
					hbh, _ := hbhLayer.(*layers.IPv6HopByHop)
					fmt.Println("Hop-by-Hop Options:")
					for _, option := range hbh.Options {
						fmt.Printf("Option Type: %d\n", option.OptionType)
					}
				}
			}

			// Send a response packet back to the source
			sendResponsePacket(handle, ipv6)
		}
	}
}

func main() {
	dev := flag.String("i", "", "Specify the interface to capture packets on")
	list := flag.Bool("l", false, "List all available interfaces")
	flag.Parse()

	if *list {
		listDevices()
		os.Exit(0)
	}

	if *dev == "" {
		flag.Usage()
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*dev, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Couldn't open device %s: %v", *dev, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("ip6")
	if err != nil {
		log.Fatalf("Couldn't set BPF filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packetHandler(handle, packet)
	}
}
