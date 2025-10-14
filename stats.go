package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"time"
	"sync/atomic"
)

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