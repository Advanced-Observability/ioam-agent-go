package stats

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

var (
	Ipv6PacketCount uint64 = 0
	IoamPacketCount uint64 = 0
)

func WriteStats(fileName, iface string) {
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
		fmt.Fprintf(file, "%s ipv6-parsed-packets=%d ioam-parsed-packets=%d %s-rx=%d %s-tx=%d\n",
			time.Now().Format(time.RFC3339), Ipv6PacketCount, IoamPacketCount, iface, rx, iface, tx)
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
