package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	ioamAPI "ioam-agent-go/github.com/Advanced-Observability/ioam-api"
)

// Configuration constants
const (
	statsFileName     = "agentStats"
	forceLoopback     = false
)

const (
	ipv6TLVIOAM       = 49
	ioamPreallocTrace = 0

	traceTypeBit0Mask  = 1 << 23
	traceTypeBit1Mask  = 1 << 22
	traceTypeBit2Mask  = 1 << 21
	traceTypeBit3Mask  = 1 << 20
	traceTypeBit4Mask  = 1 << 19
	traceTypeBit5Mask  = 1 << 18
	traceTypeBit6Mask  = 1 << 17
	traceTypeBit7Mask  = 1 << 16
	traceTypeBit8Mask  = 1 << 15
	traceTypeBit9Mask  = 1 << 14
	traceTypeBit10Mask = 1 << 13
	traceTypeBit11Mask = 1 << 12
	traceTypeBit22Mask = 1 << 1
)

var (
	doLoopback       bool
	ipv6PacketCount  uint = 0
	ioamPacketCount  uint = 0
)

func worker(id uint, ring *pfring.Ring, packets <-chan gopacket.Packet, reportFunc func(trace *ioamAPI.IOAMTrace)) {
	for packet := range packets {
		handlePacket(ring, packet, reportFunc)
	}
}

func main() {
	interfaceName := flag.String("i", "", "Specify the interface to capture packets on")
	outputToConsole := flag.Bool("o", false, "Output IOAM traces to console")
	workerNmb := flag.Uint("g", 8, "Number of Goroutines for packet parsing")
	flag.BoolVar(&doLoopback, "loopback", false, "Enable IOAM packet loopback (send back packet copy)")
	showHelp := flag.Bool("h", false, "View help")
	flag.Parse()

	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}

	if *interfaceName == "" {
		flag.Usage()
		os.Exit(1)
	}
  
  if *workerNmb == 0 {
    fmt.Println("invalid value \"0\" for flag -g: cannot be 0")
    os.Exit(1)
  }

	if doLoopback {
		fmt.Println("[IOAM Agent] Loopback enabled: IOAM packet headers will be forwarded back to sender")
	}

	ring, err := initializeCapture(*interfaceName)
	if err != nil {
		log.Fatalf("Failed to initialize capture: %v", err)
	}
	defer ring.Close()

	var reportFunc func(trace *ioamAPI.IOAMTrace)

	var conn *grpc.ClientConn
	if *outputToConsole {
		reportFunc = consoleReport
		fmt.Println("[IOAM Agent] Printing IOAM traces...")
	} else {
		collector := os.Getenv("IOAM_COLLECTOR")
		if collector == "" {
			log.Fatalf("'IOAM_COLLECTOR' environment variable not defined")
		}

		// Create gRPC connection once
		conn, err = grpc.Dial(collector, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("Failed to connect to IOAM collector: %v", err)
		}
		defer conn.Close()

		client := ioamAPI.NewIOAMServiceClient(conn)
		
		// Create the stream once and reuse it
		stream, err := client.Report(context.Background())
		if err != nil {
			log.Fatalf("Failed to create gRPC stream: %v", err)
		}
		defer stream.CloseSend()

		reportFunc = func(trace *ioamAPI.IOAMTrace) {
			grpcReport(trace, stream)
		}
		fmt.Println("[IOAM Agent] Reporting to IOAM collector...")
	}

	go writeStats(statsFileName, *interfaceName)

	packets := make(chan gopacket.Packet, *workerNmb)
	for w := uint(1); w <= *workerNmb; w++ {
		go worker(w, ring, packets, reportFunc)
	}

	for {
		packet, _, err := ring.ReadPacketData()
		if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		gpacket := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.Default)
		packets <-gpacket
	}
}

func initializeCapture(interfaceName string) (*pfring.Ring, error) {
	ring, err := pfring.NewRing(interfaceName, 2048, pfring.FlagPromisc)
	if err != nil {
		return nil, fmt.Errorf("couldn't open device %s: %v", interfaceName, err)
	}

	if err := ring.SetBPFFilter("ip6[6] == 0"); err != nil {
		return nil, fmt.Errorf("couldn't set BPF filter: %v", err)
	}

	if err := ring.SetDirection(pfring.ReceiveOnly); err != nil {
		return nil, fmt.Errorf("error setting ring direction: %v", err)
	}

	if err := ring.Enable(); err != nil {
		return nil, fmt.Errorf("error enabling ring: %v", err)
	}

	return ring, nil
}

func handlePacket(ring *pfring.Ring, packet gopacket.Packet, report func(trace *ioamAPI.IOAMTrace)) {
	ipv6PacketCount++

	hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
	if hbhLayer == nil {
		return
	}

	hbh, _ := hbhLayer.(*layers.IPv6HopByHop)
	traces, loopback, err := parseHopByHop(hbh.LayerContents())
	if err != nil {
		log.Printf("Error parsing Hop-by-Hop header: %v", err)
		return
	}

	if forceLoopback || (doLoopback && loopback) {
		sendBackPacket(ring, packet)
	}

	for _, trace := range traces {
		report(trace)
	}
}

func sendBackPacket(ring *pfring.Ring, packet gopacket.Packet) {
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

	// Swap source and destination MAC and IP addresses
	eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
	ipv6.SrcIP, ipv6.DstIP = ipv6.DstIP, ipv6.SrcIP
	hbh.NextHeader = layers.IPProtocolNoNextHeader

	if err := gopacket.SerializeLayers(buffer, opts, eth, ipv6); err != nil {
		log.Printf("Error serializing layers: %v", err)
		return
	}

	if err := ring.WritePacketData(buffer.Bytes()); err != nil {
		log.Printf("Error sending packet: %v", err)
	}
}

func parseNodeData(data []byte, traceType uint32) (ioamAPI.IOAMNode, error) {
	node := ioamAPI.IOAMNode{}
	offset := 0

	if traceType&traceTypeBit0Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.Id = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
		offset += 4
	}
	if traceType&traceTypeBit1Mask != 0 {
		node.IngressId = uint32(binary.BigEndian.Uint16(data[offset:offset+2]))
		node.EgressId = uint32(binary.BigEndian.Uint16(data[offset+2:offset+4]))
		offset += 4
	}
	if traceType&traceTypeBit2Mask != 0 {
		node.TimestampSecs = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit3Mask != 0 {
		node.TimestampFrac = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit4Mask != 0 {
		node.TransitDelay = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit5Mask != 0 {
		node.NamespaceData = data[offset : offset+4]
		offset += 4
	}
	if traceType&traceTypeBit6Mask != 0 {
		node.QueueDepth = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit7Mask != 0 {
		node.CsumComp = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit8Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.IdWide = binary.BigEndian.Uint64(data[offset:offset+8]) & 0xFFFFFFFFFFFFFF
		offset += 8
	}
	if traceType&traceTypeBit9Mask != 0 {
		node.IngressIdWide = binary.BigEndian.Uint32(data[offset : offset+4])
		node.EgressIdWide = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8
	}
	if traceType&traceTypeBit10Mask != 0 {
		node.NamespaceDataWide = data[offset : offset+8]
		offset += 8
	}
	if traceType&traceTypeBit11Mask != 0 {
		node.BufferOccupancy = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	return node, nil
}

func parseIOAMTrace(data []byte) (*ioamAPI.IOAMTrace, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("IOAM trace data too short")
	}

	ns := uint32(binary.BigEndian.Uint16(data[:2]))
	nodeLen := uint32(data[2] >> 3)
	remLen := uint32(data[3] & 0x7F)
	traceType := binary.BigEndian.Uint32(data[4:8]) >> 8
	loopback := (data[2] & 0b00000010) != 0

	var nodes []*ioamAPI.IOAMNode
	offset := 8 + int(remLen)*4

	for offset < len(data) {
		node, err := parseNodeData(data[offset:], traceType)
		if err != nil {
			return nil, false, err
		}
		offset += int(nodeLen) * 4

		if traceType&traceTypeBit22Mask != 0 {
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

	trace := &ioamAPI.IOAMTrace{
		BitField:    traceType << 8,
		NamespaceId: ns,
		Nodes:       nodes,
	}

	return trace, loopback, nil
}

func parseHopByHop(data []byte) ([]*ioamAPI.IOAMTrace, bool, error) {
	if len(data) < 8 {
		return nil, false, errors.New("Hop-by-Hop header too short")
	}

	hbhLen := int(data[1]+1) << 3
	offset := 2
	var traces []*ioamAPI.IOAMTrace
	var loopback bool

	for hbhLen > 0 {
		if len(data[offset:]) < 4 {
			return traces, false, nil
		}

		optType := data[offset]
		optLen := int(data[offset+1] + 2)

		if optType == ipv6TLVIOAM && data[offset+3] == ioamPreallocTrace {
			ioamPacketCount++

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

// grpcReport streams an IOAM trace to the gRPC server
func grpcReport(trace *ioamAPI.IOAMTrace, stream ioamAPI.IOAMService_ReportClient) {
	if err := stream.Send(trace); err != nil {
		log.Printf("Error reporting trace: %v", err)
	}
}

func consoleReport(trace *ioamAPI.IOAMTrace) {
	fmt.Println(trace)
}

// Write various packet statistics to fileName every second
// Never returns, should be invoked as goroutine
func writeStats(fileName string, device string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Error opening stats file: %v", err)
	}
	defer file.Close()

	rxFilePath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", device)
	txFilePath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", device)

	rxFile, err := os.Open(rxFilePath)
	if err != nil {
		log.Fatalf("Error opening RX file: %v", err)
	}
	defer rxFile.Close()

	txFile, err := os.Open(txFilePath)
	if err != nil {
		log.Fatalf("Error opening TX file: %v", err)
	}
	defer txFile.Close()

	initialRX, err := readPacketCount(rxFile)
	if err != nil {
		log.Fatalf("Error reading initial RX packets: %v", err)
	}
	initialTX, err := readPacketCount(txFile)
	if err != nil {
		log.Fatalf("Error reading initial TX packets: %v", err)
	}

	for range ticker.C {
		currentRX, err := readPacketCount(rxFile)
		if err != nil {
			log.Fatalf("Error reading current RX packets: %v", err)
		}

		currentTX, err := readPacketCount(txFile)
		if err != nil {
			log.Fatalf("Error reading current TX packets: %v", err)
		}

		rxPacketCount := currentRX - initialRX
		txPacketCount := currentTX - initialTX

		// Update file statistics
		file.Seek(0, io.SeekStart)
		if _, err := fmt.Fprintf(file, "IPv6 packets parsed\t%d\nIOAM packets parsed\t%d\nPackets received\t%d\nPackets transmitted\t\t%d\n",
			ipv6PacketCount, ioamPacketCount, rxPacketCount, txPacketCount); err != nil {
			log.Fatalf("Error writing to stats file: %v", err)
		}
	}
}

func readPacketCount(file *os.File) (uint64, error) {
	_, err := file.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}

	var count uint64
	_, err = fmt.Fscanf(file, "%d\n", &count)
	if err != nil {
		return 0, err
	}

	return count, nil
}
