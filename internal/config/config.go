package config

import (
	"flag"
	"os"
	"strings"
	"time"
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

func ParseFlags() *Config {
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
