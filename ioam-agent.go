package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"ioam-agent-go/github.com/Advanced-Observability/ioam-api"
)

const (
	// Configuration for testing/debugging
	StatsFile          = "AgentStats"
	ForceLoopback      = false
)
	
const (
	IPv6TLVIOAM        = 49
	IOAMPreallocTrace  = 0

	TraceTypeBit0Mask  = 1 << 23
	TraceTypeBit1Mask  = 1 << 22
	TraceTypeBit2Mask  = 1 << 21
	TraceTypeBit3Mask  = 1 << 20
	TraceTypeBit4Mask  = 1 << 19
	TraceTypeBit5Mask  = 1 << 18
	TraceTypeBit6Mask  = 1 << 17
	TraceTypeBit7Mask  = 1 << 16
	TraceTypeBit8Mask  = 1 << 15
	TraceTypeBit9Mask  = 1 << 14
	TraceTypeBit10Mask = 1 << 13
	TraceTypeBit11Mask = 1 << 12
	TraceTypeBit22Mask = 1 << 1
)

var doLoopback bool
var ipv6PacketsCount uint
var ioamPacketsCount uint

func sendBackPacket(handle *pcap.Handle, packet gopacket.Packet) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		log.Println("Error: No Ethernet layer found in packet")
		return
	}
	eth, _ := ethLayer.(*layers.Ethernet)

	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		log.Println("Error: No IPv6 layer found in packet")
		return
	}
	ipv6, _ := ipv6Layer.(*layers.IPv6)

	hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
	if hbhLayer == nil {
		log.Println("Error: No Hop-by-Hop Options header found in packet")
		return
	}
	hbh, _ := hbhLayer.(*layers.IPv6HopByHop)

	eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
	ipv6.SrcIP, ipv6.DstIP = ipv6.DstIP, ipv6.SrcIP
	hbh.NextHeader = layers.IPProtocolNoNextHeader

	if err := gopacket.SerializeLayers(buffer, opts, eth, ipv6); err != nil {
		log.Printf("Error serializing layers: %v", err)
		return
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Printf("Error sending packet: %v", err)
	}
}

func parseNodeData(data []byte, traceType uint32) (ioam_api.IOAMNode, error) {
	node := ioam_api.IOAMNode{}
	offset := 0

	if traceType&TraceTypeBit0Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.Id = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
		offset += 4
	}
	if traceType&TraceTypeBit1Mask != 0 {
		node.IngressId = uint32(binary.BigEndian.Uint16(data[offset:offset+2]))
		node.EgressId = uint32(binary.BigEndian.Uint16(data[offset+2:offset+4]))
		offset += 4
	}
	if traceType&TraceTypeBit2Mask != 0 {
		node.TimestampSecs = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TraceTypeBit3Mask != 0 {
		node.TimestampFrac = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TraceTypeBit4Mask != 0 {
		node.TransitDelay = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TraceTypeBit5Mask != 0 {
		node.NamespaceData = data[offset : offset+4]
		offset += 4
	}
	if traceType&TraceTypeBit6Mask != 0 {
		node.QueueDepth = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TraceTypeBit7Mask != 0 {
		node.CsumComp = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TraceTypeBit8Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.IdWide = binary.BigEndian.Uint64(data[offset:offset+8]) & 0xFFFFFFFFFFFFFF
		offset += 8
	}
	if traceType&TraceTypeBit9Mask != 0 {
		node.IngressIdWide = binary.BigEndian.Uint32(data[offset : offset+4])
		node.EgressIdWide = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8
	}
	if traceType&TraceTypeBit10Mask != 0 {
		node.NamespaceDataWide = data[offset : offset+8]
		offset += 8
	}
	if traceType&TraceTypeBit11Mask != 0 {
		node.BufferOccupancy = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	return node, nil
}

func parseIOAMTrace(data []byte) (*ioam_api.IOAMTrace, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("IOAM trace data too short")
	}

	ns := uint32(binary.BigEndian.Uint16(data[:2]))
	nodeLen := uint32(data[2] >> 3)
	remLen := uint32(data[3] & 0x7F)
	traceType := binary.BigEndian.Uint32(data[4:8]) >> 8
	loopback := (data[2] & 0b00000010) != 0

	var nodes []*ioam_api.IOAMNode
	offset := 8 + int(remLen)*4

	for offset < len(data) {
		node, err := parseNodeData(data[offset:], traceType)
		if err != nil {
			return nil, false, err
		}
		offset += int(nodeLen) * 4

		if traceType&TraceTypeBit22Mask != 0 {
			if len(data[offset:]) < 4 {
				return nil, false, errors.New("invalid packet length")
			}
			opaqueLen := data[offset]
			node.IdWide = binary.BigEndian.Uint64(data[offset : offset+4])
			if len(data[offset:]) < 4+int(opaqueLen)*4 {
				return nil, false, errors.New("invalid packet length")
			}
			node.QueueDepth = binary.BigEndian.Uint32(data[offset+4 : offset+4+int(opaqueLen)*4])
			offset += 4 + int(opaqueLen)*4
		}

		nodes = append(nodes, &node)
	}

	trace := &ioam_api.IOAMTrace{
		BitField:    traceType << 8,
		NamespaceId: ns,
		Nodes:       nodes,
	}

	return trace, loopback, nil
}

func parseHopByHop(data []byte) ([]*ioam_api.IOAMTrace, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("Hop-by-Hop header too short")
	}

	hbhLen := int(data[1]+1) << 3
	offset := 2
	var traces []*ioam_api.IOAMTrace
	var loopback bool

	for hbhLen > 0 {
		if len(data[offset:]) < 4 {
			return traces, false, nil
		}

		optType := data[offset]
		optLen := int(data[offset+1] + 2)

		if optType == IPv6TLVIOAM && data[offset+3] == IOAMPreallocTrace {
			ioamPacketsCount++

			trace, iloopback, err := parseIOAMTrace(data[offset+4 : offset+optLen])
			loopback = iloopback
			if err != nil {
				return nil, false, err
			}
			if trace != nil {
				traces = append(traces, trace)
			}
		}

		offset += optLen
		hbhLen -= optLen
	}

	return traces, loopback, nil
}

func packetHandler(handle *pcap.Handle, packet gopacket.Packet, report func(trace *ioam_api.IOAMTrace)) {
	ipv6PacketsCount++

	hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
	if hbhLayer == nil {
		return
	}

	hbh, _ := hbhLayer.(*layers.IPv6HopByHop)
	hbhHeader := hbh.LayerContents()
	traces, loopback, err := parseHopByHop(hbhHeader)
	if err != nil {
		log.Printf("Error parsing Hop-by-Hop header: %v", err)
		return
	}

	if ForceLoopback || (doLoopback && loopback) {
		sendBackPacket(handle, packet)
	}

	for _, trace := range traces {
		report(trace)
	}
}

func writeStats(fileName string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Error opening stats file: %v", err)
	}
	defer file.Close()

	for range ticker.C {
		_, err := file.Seek(0, 0)
		if err != nil {
			log.Fatalf("Error seeking stats file: %v", err)
		}

		_, err = fmt.Fprintf(file, "IPv6 Packets: %d\nIOAM Packets: %d\n", ipv6PacketsCount, ioamPacketsCount)
		if err != nil {
			log.Fatalf("Error writing to stats file: %v", err)
		}
	}
}

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

func main() {
	dev := flag.String("i", "", "Specify the interface to capture packets on")
	list := flag.Bool("l", false, "List all available interfaces")
	flag.BoolVar(&doLoopback, "loopback", false, "Enable IOAM packet loopback")
	output := flag.Bool("o", false, "Output IOAM traces to console")
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

	if doLoopback {
		fmt.Println("[IOAM Agent] Loopback enabled: IOAM packet headers will be forwarded back to sender")
	}

	handle, err := pcap.OpenLive(*dev, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Couldn't open device %s: %v", *dev, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ip6[6] == 0"); err != nil {
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
			if _, err := client.Report(context.Background(), trace); err != nil {
				log.Printf("Error reporting trace: %v", err)
			}
		}
		fmt.Println("[IOAM Agent] Reporting to IOAM collector...")
	}

	go writeStats(StatsFile)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetHandler(handle, packet, reportFunc)
	}
}
