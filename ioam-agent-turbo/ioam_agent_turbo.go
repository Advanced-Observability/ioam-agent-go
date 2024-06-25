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

const (
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
	} else {
		log.Printf("Sent DEX report to %s", origIP.SrcIP)
	}
}

func parseNodeData(p []byte, ttype uint32) (ioam_api.IOAMNode, error) {
	node := ioam_api.IOAMNode{}
	i := 0

	log.Println(ttype)
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

func parseIOAMTrace(p []byte) (*ioam_api.IOAMTrace, error) {
	var ns, nodelen, remlen, ttype uint32
	ns = uint32(binary.BigEndian.Uint16(p[:2]))
	nodelen = uint32(p[2] >> 3)
	remlen = uint32(p[3] & 0x7F)
	ttype = binary.BigEndian.Uint32(p[4:8]) >> 8

	var nodes []*ioam_api.IOAMNode
	i := 8 + int(remlen)*4

	for i < len(p) {
		node, err := parseNodeData(p[i:], uint32(ttype))
		if err != nil {
			return nil, err
			}
			i += int(nodelen) * 4
			
			if ttype&TRACE_TYPE_BIT22_MASK != 0 {
				if len(p[i:]) < 4 {
					return nil, errors.New("invalid packet length")
				}
				opaqueLen := p[i]
				node.IdWide = binary.BigEndian.Uint64(p[i : i+4])
				if len(p[i:]) < 4+int(opaqueLen)*4 {
					return nil, errors.New("invalid packet length")
				}
				node.QueueDepth = binary.BigEndian.Uint32(p[i+4 : i+4+int(opaqueLen)*4])
				i += 4 + int(opaqueLen)*4
			}
						
		log.Println(node.String())
		nodes = append(nodes, &node)
	}

	trace := &ioam_api.IOAMTrace{
		BitField:    uint32(ttype) << 8,
		NamespaceId: uint32(ns),
		Nodes:       nodes,
	}

	return trace, nil
}

func parseHopByHop(p []byte) ([]*ioam_api.IOAMTrace, error) {
	if len(p) < 8 {
		return nil, errors.New("Hop-by-Hop header too short")
	}

	hbhLen := int(p[1] + 1) << 3
	i := 2
	var traces []*ioam_api.IOAMTrace

	for hbhLen > 0 {
		if len(p[i:]) < 4 {
			// Found padding or invalid trace data, return correctly parsed traces
			return traces, nil
		}
		var optType, optLen uint8 
		optType = p[i]
		optLen = p[i+1] + 2

		if optType == IPV6_TLV_IOAM && p[i+3] == IOAM_PREALLOC_TRACE {
			trace, err := parseIOAMTrace(p[i+4 : i+int(optLen)])
			if err != nil {
				return nil, err
			}
			if trace != nil {
				traces = append(traces, trace)
			}
		}

		i += int(optLen)
		hbhLen -= int(optLen)
	}

	return traces, nil
}

func packetHandler(handle *pcap.Handle, packet gopacket.Packet, report func(trace *ioam_api.IOAMTrace), dex bool) {
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ipv6, _ := ipv6Layer.(*layers.IPv6)
		
		// Check if the next header field is Hop-by-Hop Options header
		hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
		if hbhLayer != nil {
			hbh, _ := hbhLayer.(*layers.IPv6HopByHop)
			hbhHeader := hbh.LayerContents()
			traces, err := parseHopByHop(hbhHeader)
			if err != nil {
				log.Printf("Error parsing Hop-by-Hop header: %v", err)
				return
			}

			for _, trace := range traces {
				report(trace)
			}

			if dex {
				sendResponsePacket(handle, ipv6)
			}
		}
	}
}

func main() {
	dev := flag.String("i", "", "Specify the interface to capture packets on")
	list := flag.Bool("l", false, "List all available interfaces")
	dex := flag.Bool("d", false, "Activate direct exporting")
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

	handle, err := pcap.OpenLive(*dev, 1600, true, pcap.BlockForever)
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
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		packetHandler(handle, packet, reportFunc, *dex)
	}
}
