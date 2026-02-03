//go:build !afpacket
// +build !afpacket

//go:generate protoc --go_out=. --go-grpc_out=. ioam_api.proto

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ioamAPI "ioam-agent-go/github.com/Advanced-Observability/ioam-api"
)

var (
	ipv6PacketCount uint64 = 0
	ioamPacketCount uint64 = 0
	nodeDumped      uint64 = 0
)

type Config struct {
	Interface string
	Collector string
	Dumpfile  string
	Statfile  string
	Console   bool
	Workers   uint
	Loopback  bool // unused
}

type Reporter func(trace *ioamAPI.IOAMTrace)

func main() {
	cfg := parseFlags()
	source, err := initializeCapture(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to initialize capture: %v", err)
	}

	reportFunc := setupReporting(cfg)
	go writeStats(cfg.Statfile, cfg.Interface)

	packets := make(chan gopacket.Packet, cfg.Workers)
	for w := uint(1); w <= cfg.Workers; w++ {
		go worker(w, packets, reportFunc)
	}

	for packet := range source.Packets() {
		packets <- packet
	}
}

func parseFlags() *Config {
	iface := flag.String("i", "", "Interface to capture packets on")
	collector := flag.String("c", "", "Reporter: Collector socket for gRPC trace streaming (fallback: 'IOAM_COLLECTOR' env variable)")
	dfile := flag.String("d", "", "Reporter: Dump received IOAM traces to file (csv format)")
	sfile := flag.String("s", "agent-stats_%Y-%m-%d.log", "Print statistics to file, %Y-%m-%d is replaced by the current date, updated live every second")
	console := flag.Bool("o", false, "Reporter: Print IOAM traces to console")
	workers := flag.Uint("g", 8, "Number of Goroutines for packet parsing")
	flag.Parse()

	if *iface == "" || *workers == 0 {
		flag.Usage()
		os.Exit(1)
	}

	return &Config{
		Interface: *iface,
		Collector: *collector,
		Dumpfile:  *dfile,
		Statfile:  expandFilename(*sfile, time.Now()),
		Console:   *console,
		Workers:   *workers,
	}
}

func expandFilename(pattern string, t time.Time) string {
	replacer := strings.NewReplacer(
		"%Y", "2006",
		"%m", "01",
		"%d", "02",
		"%H", "15",
		"%M", "04",
		"%S", "05",
	)
	return t.Format(replacer.Replace(pattern))
}

func setupReporting(cfg *Config) Reporter {
	var reporters []Reporter

	if cfg.Console {
		log.Println("[IOAM Agent] Printing IOAM traces...")
		reporters = append(reporters, func(trace *ioamAPI.IOAMTrace) {
			fmt.Println(trace)
		})
	}

	if cfg.Dumpfile != "" {
		log.Println("[IOAM Agent] Dumping IOAM traces to file...")
		f, err := os.OpenFile(cfg.Dumpfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("Error opening file: %v", err)
		} else {
			fmt.Fprintf(f, "index,namespace_id,tracetype,hop_limit,node_id,ingress_id,egress_id,timestamp_secs,timestamp_frac,transit_delay,queue_depth,csum_comp,buffer_occupancy,ingress_id_wide,egress_id_wide,id_wide,namespace_data,namespace_data_wide,oss_schema_id,oss_data\n")
			reporters = append(reporters, func(trace *ioamAPI.IOAMTrace) {
				dumpToFile(trace, f)
			})
		}
	}

	collector := os.Getenv("IOAM_COLLECTOR")
	if collector == "" {
		collector = cfg.Collector
	}
	if collector != "" {
		conn, err := grpc.NewClient(
			collector,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			log.Printf("Failed to connect to IOAM collector %s: %v", collector, err)
		} else {
			client := ioamAPI.NewIOAMServiceClient(conn)
			stream, err := client.Report(context.Background())
			if err != nil {
				log.Printf("Failed to create gRPC stream: %v", err)
			} else {
				log.Println("[IOAM Agent] Reporting IOAM traces to collector...")
				reporters = append(reporters, func(trace *ioamAPI.IOAMTrace) {
					if err := stream.Send(trace); err != nil {
						log.Printf("Error reporting trace: %v", err)
					}
				})
			}
		}
	}

	if len(reporters) == 0 {
		log.Fatal("No IOAM reporting method configured")
	}

	return func(trace *ioamAPI.IOAMTrace) {
		for _, r := range reporters {
			// Could modify implementation to have one worker pool per reporter
			r(trace)
		}
	}
}

func dumpToFile(trace *ioamAPI.IOAMTrace, f *os.File) {
	for _, node := range trace.GetNodes() {
		fmt.Fprintf(f, "%d,%d,%06x,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%04x,%08x,", nodeDumped, trace.GetNamespaceId(),
			trace.GetBitField(), node.GetHopLimit(), node.GetId(), node.GetIngressId(),
			node.GetEgressId(), node.GetTimestampSecs(), node.GetTimestampFrac(), node.GetTransitDelay(),
			node.GetQueueDepth(), node.GetCsumComp(), node.GetBufferOccupancy(), node.GetIngressIdWide(),
			node.GetEgressIdWide(), node.GetIdWide(), node.GetNamespaceData(), node.GetNamespaceDataWide())

		oss := node.GetOSS()
		if oss != nil {
			fmt.Fprintf(f, "%d,%x", oss.SchemaId, oss.Data)
		}
		fmt.Fprintf(f, "\n")
		nodeDumped++
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
