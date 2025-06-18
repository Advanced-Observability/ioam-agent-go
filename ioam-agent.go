//go:build !afpacket
// +build !afpacket

package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/grpc"

	ioamAPI "ioam-agent-go/github.com/Advanced-Observability/ioam-api"
)

const (
	statsFileName     = "agentStats"
)

var (
	ipv6PacketCount   uint64
	ioamPacketCount   uint64
)

func main() {
	cfg := parseFlags()
	source, err := initializeCapture(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to initialize capture: %v", err)
	}

	reportFunc := setupReporting(cfg)
	go writeStats(statsFileName, cfg.Interface)

	packets := make(chan gopacket.Packet, cfg.Workers)
	for w := uint(1); w <= cfg.Workers; w++ {
		go worker(w, packets, reportFunc)
	}

	for packet := range source.Packets() {
		packets <- packet
	}
}

type Config struct {
	Interface string
	Console   bool
	Workers   uint
	Loopback  bool
}

func parseFlags() *Config {
	iface := flag.String("i", "", "Interface to capture packets on")
	console := flag.Bool("o", false, "Output Ioam traces to console")
	workers := flag.Uint("g", 8, "Number of Goroutines for packet parsing")
	flag.Parse()

	if *iface == "" || *workers == 0 {
		flag.Usage()
		os.Exit(1)
	}

	return &Config{
		Interface: *iface,
		Console:   *console,
		Workers:   *workers,
	}
}

func setupReporting(cfg *Config) func(trace *ioamAPI.IOAMTrace) {
	if cfg.Console {
		fmt.Println("[Ioam Agent] Printing Ioam traces...")
		return func(trace *ioamAPI.IOAMTrace) { fmt.Println(trace) }
	}

	collector := os.Getenv("IOAM_COLLECTOR")
	if collector == "" {
		log.Fatal("'IOAM_COLLECTOR' environment variable not defined")
	}

	conn, err := grpc.Dial(collector, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to Ioam collector %s: %v", collector, err)
	}

	client := ioamAPI.NewIOAMServiceClient(conn)
	stream, err := client.Report(context.Background())
	if err != nil {
		log.Fatalf("Failed to create gRPC stream: %v", err)
	}

	fmt.Println("[Ioam Agent] Reporting Ioam traces to collector...")
	return func(trace *ioamAPI.IOAMTrace) {
		if err := stream.Send(trace); err != nil {
			log.Printf("Error reporting trace: %v", err)
		}
	}
}

func worker(id uint, packets <-chan gopacket.Packet, report func(*ioamAPI.IOAMTrace)) {
	for packet := range packets {
		handlePacket(packet, report)
	}
}

func handlePacket(packet gopacket.Packet, report func(*ioamAPI.IOAMTrace)) {
	atomic.AddUint64(&ipv6PacketCount, 1)
	hbhLayer := packet.Layer(layers.LayerTypeIPv6HopByHop)
	if hbhLayer == nil {
		return
	}
	hbh, _ := hbhLayer.(*layers.IPv6HopByHop)
	traces, _, err := parseHopByHop(hbh.LayerContents())
	if err != nil {
		log.Printf("Hop-by-Hop parse error: %v", err)
		return
	}
	for _, trace := range traces {
		report(trace)
	}
}

func writeStats(fileName, iface string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalf("Open stats file: %v", err)
	}
	defer file.Close()

	rxf := fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface)
	txf := fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", iface)
	for range ticker.C {
		rx := readInt(rxf)
		tx := readInt(txf)
		file.Seek(0, io.SeekStart)
		fmt.Fprintf(file, "IPv6 packets parsed\t%d\nIoam packets parsed\t%d\nPackets received\t%d\nPackets transmitted\t%d\n",
			atomic.LoadUint64(&ipv6PacketCount), atomic.LoadUint64(&ioamPacketCount), rx, tx)
	}
}

func readInt(path string) uint64 {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Open file %s: %v", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		var count uint64
		fmt.Sscanf(scanner.Text(), "%d", &count)
		return count
	}
	return 0
}
