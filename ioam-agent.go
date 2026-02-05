//go:build !afpacket
// +build !afpacket

package main

import (
	"log"

	ioamAPI "github.com/Advanced-Observability/ioam-api"
	"github.com/google/gopacket"

	"github.com/Advanced-Observability/ioam-agent/internal/capture"
	"github.com/Advanced-Observability/ioam-agent/internal/config"
	"github.com/Advanced-Observability/ioam-agent/internal/parser"
	"github.com/Advanced-Observability/ioam-agent/internal/reporter"
	"github.com/Advanced-Observability/ioam-agent/internal/stats"
)

func main() {
	cfg := config.ParseFlags()
	source, err := capture.InitializeCapture(cfg.Interface)
	if err != nil {
		log.Fatalf("Failed to initialize capture: %v", err)
	}

	reportFunc := reporter.SetupReporting(cfg)
	go stats.WriteStats(cfg.Statfile, cfg.Interface)

	packets := make(chan gopacket.Packet, cfg.Workers)
	for w := uint(1); w <= cfg.Workers; w++ {
		go worker(w, packets, reportFunc)
	}

	for packet := range source.Packets() {
		packets <- packet
	}
}

func worker(id uint, packets <-chan gopacket.Packet, report func(*ioamAPI.IOAMTrace)) {
	for packet := range packets {
		parser.ParsePacket(packet, report)
	}
}
