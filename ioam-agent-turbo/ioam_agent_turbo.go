package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"google.golang.org/grpc"
	"golang.org/x/net/context"

	"ioam-agent-turbo/github.com/Advanced-Observability/ioam-api"
)

var DO_LOOPBACK bool

const (
	// For testing purposes
	FORCE_LOOPBACK      = true

	IPV6_TLV_IOAM       = 49
	IOAM_PREALLOC_TRACE = 0

	TRACE_TYPE_BIT0_MASK  = 1 << 23
	TRACE_TYPE_BIT1_MASK  = 1 << 22
	TRACE_TYPE_BIT2_MASK  = 1 << 21
	TRACE_TYPE_BIT3_MASK  = 1 << 20
	TRACE_TYPE_BIT4_MASK  = 1 << 19
	TRACE_TYPE_BIT5_MASK  = 1 << 18
	TRACE_TYPE_BIT6_MASK  = 1 << 17
	TRACE_TYPE_BIT7_MASK  = 1 << 16
	TRACE_TYPE_BIT8_MASK  = 1 << 15
	TRACE_TYPE_BIT9_MASK  = 1 << 14
	TRACE_TYPE_BIT10_MASK = 1 << 13
	TRACE_TYPE_BIT11_MASK = 1 << 12
	TRACE_TYPE_BIT22_MASK = 1 << 1
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

// TODO: Does not work
func sendBackPacket(handle *pcap.Handle, packet gopacket.Packet) {
	log.Println("Loopback enabled, sending back the packet")

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Get Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Println("Error: No Ethernet layer found in packet")
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	// Get IPv6 layer
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		log.Println("Error: No IPv6 layer found in packet")
		return
	}
	ipv6, _ := ipv6Layer.(*layers.IPv6)

	// Get Hop-by-Hop Options header
	hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
	if hbhLayer == nil {
		log.Println("Error: No Hop-by-Hop Options header found in packet")
		return
	}
	hbh, _ := hbhLayer.(*layers.IPv6HopByHop)

	// Swap Ethernet addresses
	ethSrc := eth.SrcMAC
	ethDst := eth.DstMAC
	eth.SrcMAC = ethDst
	eth.DstMAC = ethSrc

	// Swap IPv6 addresses
	ipv6Src := ipv6.SrcIP
	ipv6Dst := ipv6.DstIP
	ipv6.SrcIP = ipv6Dst
	ipv6.DstIP = ipv6Src

	// Set next header field to NoNextHeader
	hbh.NextHeader = layers.IPProtocolNoNextHeader

	// Serialize the layers
	gopacket.SerializeLayers(buffer, opts,
		eth,
		ipv6,
	)

	// Send the packet
	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Printf("Error sending packet: %v", err)
	} else {
		log.Printf("Sent packet to %s", ipv6Src)
	}
}

func parseNodeData(p []byte, ttype uint32) (ioam_api.IOAMNode, error) {
	node := ioam_api.IOAMNode{}
	i := 0

	if ttype&TRACE_TYPE_BIT0_MASK != 0 {
		node.HopLimit = uint32(p[i])
		node.Id = binary.BigEndian.Uint32(p[i:i+4]) & 0xFFFFFF
		i += 4
	}
	if ttype&TRACE_TYPE_BIT1_MASK != 0 {
		node.IngressId = uint32(binary.BigEndian.Uint16(p[i : i+2]))
		node.EgressId = uint32(binary.BigEndian.Uint16(p[i+2 : i+4]))
		i += 4
	}
	if ttype&TRACE_TYPE_BIT2_MASK != 0 {
		node.TimestampSecs = binary.BigEndian.Uint32(p[i : i+4])
		i += 4
	}
	if ttype&TRACE_TYPE_BIT3_MASK != 0 {
		node.TimestampFrac = binary.BigEndian.Uint32(p[i : i+4])
		i += 4
	}
	if ttype&TRACE_TYPE_BIT4_MASK != 0 {
		node.TransitDelay = binary.BigEndian.Uint32(p[i : i+4])
		i += 4
	}
	if ttype&TRACE_TYPE_BIT5_MASK != 0 {
		node.NamespaceData = p[i : i+4]
		i += 4
	}
	if ttype&TRACE_TYPE_BIT6_MASK != 0 {
		node.QueueDepth = binary.BigEndian.Uint32(p[i : i+4])
		i += 4
	}
	if ttype&TRACE_TYPE_BIT7_MASK != 0 {
		node.CsumComp = binary.BigEndian.Uint32(p[i : i+4])
		i += 4
	}
	if ttype&TRACE_TYPE_BIT8_MASK != 0 {
		node.HopLimit = uint32(p[i])
		node.IdWide = binary.BigEndian.Uint64(p[i:i+8]) & 0xFFFFFFFFFFFFFF
		i += 8
	}
	if ttype&TRACE_TYPE_BIT9_MASK != 0 {
		node.IngressIdWide = binary.BigEndian.Uint32(p[i : i+4])
		node.EgressIdWide = binary.BigEndian.Uint32(p[i+4 : i+8])
		i += 8
	}
	if ttype&TRACE_TYPE_BIT10_MASK != 0 {
		node.NamespaceDataWide = p[i : i+8]
		i += 8
	}
	if ttype&TRACE_TYPE_BIT11_MASK != 0 {
		node.BufferOccupancy = binary.BigEndian.Uint32(p[i : i+4])
		i += 4
	}

	return node, nil
}

func parseIOAMTrace(p []byte) (*ioam_api.IOAMTrace, bool, error) {
	var ns, nodelen, remlen, ttype uint32
	var loopback bool = ((p[2] & 0b00000010 ) >> 1) != 0

	ns = uint32(binary.BigEndian.Uint16(p[:2]))
	nodelen = uint32(p[2] >> 3)
	remlen = uint32(p[3] & 0x7F)
	ttype = binary.BigEndian.Uint32(p[4:8]) >> 8

	var nodes []*ioam_api.IOAMNode
	i := 8 + int(remlen)*4

	for i < len(p) {
		node, err := parseNodeData(p[i:], uint32(ttype))
		if err != nil {
			return nil, false, err
			}
			i += int(nodelen) * 4
			
			if ttype&TRACE_TYPE_BIT22_MASK != 0 {
				if len(p[i:]) < 4 {
					return nil, false, errors.New("invalid packet length")
				}
				opaqueLen := p[i]
				node.IdWide = binary.BigEndian.Uint64(p[i : i+4])
				if len(p[i:]) < 4+int(opaqueLen)*4 {
					return nil, false, errors.New("invalid packet length")
				}
				node.QueueDepth = binary.BigEndian.Uint32(p[i+4 : i+4+int(opaqueLen)*4])
				i += 4 + int(opaqueLen)*4
			}
						
		nodes = append(nodes, &node)
	}

	trace := &ioam_api.IOAMTrace{
		BitField:    uint32(ttype) << 8,
		NamespaceId: uint32(ns),
		Nodes:       nodes,
	}

	return trace, loopback, nil
}

func parseHopByHop(p []byte) ([]*ioam_api.IOAMTrace, bool, error) {
	if len(p) < 8 {
		return nil, false, errors.New("Hop-by-Hop header too short")
	}

	hbhLen := int(p[1] + 1) << 3
	i := 2
	var traces []*ioam_api.IOAMTrace
	var loopback bool

	for hbhLen > 0 {
		if len(p[i:]) < 4 {
			// Found padding or invalid trace data, return correctly parsed traces
			return traces, false, nil
		}
		var optType, optLen uint8 
		optType = p[i]
		optLen = p[i+1] + 2

		if optType == IPV6_TLV_IOAM && p[i+3] == IOAM_PREALLOC_TRACE {
			trace, iloopback, err := parseIOAMTrace(p[i+4 : i+int(optLen)])
			loopback = iloopback
			if err != nil {
				return nil, false, err
			}
			if trace != nil {
				traces = append(traces, trace)
			}
		}

		i += int(optLen)
		hbhLen -= int(optLen)
	}

	return traces, loopback, nil
}

func packetHandler(handle *pcap.Handle, packet gopacket.Packet, report func(trace *ioam_api.IOAMTrace)) {
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		
		// Check if the next header field is Hop-by-Hop Options header
		hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
		if hbhLayer != nil {
			hbh, _ := hbhLayer.(*layers.IPv6HopByHop)
			hbhHeader := hbh.LayerContents()
			traces, loopback, err := parseHopByHop(hbhHeader)
			if err != nil {
				log.Printf("Error parsing Hop-by-Hop header: %v", err)
				return
			}

			if FORCE_LOOPBACK || (DO_LOOPBACK && loopback) {
				sendBackPacket(handle, packet)
			}

			for _, trace := range traces {
				report(trace)
			}
		}
	}
}

func main() {
	dev := flag.String("i", "", "Specify the interface to capture packets on")
	list := flag.Bool("l", false, "List all available interfaces")
	flag.BoolVar(&DO_LOOPBACK, "loopback", false, "Enable packet loopback")
	output := flag.Bool("o", false, "Output traces to console")
	help := flag.Bool("h", false, "View help")
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *list {
		listDevices()
		os.Exit(0)
	}

	if *dev == "" {
		flag.Usage()
		os.Exit(1)
	}

	handle, err := pcap.OpenLive(*dev, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Couldn't open device %s: %v", *dev, err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("ip6")
	if err != nil {
		log.Fatalf("Couldn't set BPF filter: %v", err)
	}

	var reportFunc func(trace *ioam_api.IOAMTrace)
	if *output {
		reportFunc = func(trace *ioam_api.IOAMTrace) {
			fmt.Println(trace)
		}
		fmt.Println("[IOAM Agent] Printing IOAM traces...")
	} else {
		collector := os.Getenv("IOAM_COLLECTOR")
		if collector == "" {
			log.Fatalf("'IOAM_COLLECTOR' environment variable not defined")
		}

		conn, err := grpc.Dial(collector, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("Could not connect to collector: %v", err)
		}
		defer conn.Close()

		client := ioam_api.NewIOAMServiceClient(conn)
		reportFunc = func(trace *ioam_api.IOAMTrace) {
			// Call the gRPC service to report the trace
			_, err := client.Report(context.Background(), trace)
			if err != nil {
				log.Printf("Error reporting trace: %v", err)
			}
		}
		fmt.Println("[IOAM Agent] Reporting to IOAM collector...")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packetHandler(handle, packet, reportFunc)
	}
}
