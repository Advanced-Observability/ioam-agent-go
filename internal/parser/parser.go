package parser

import (
	"encoding/binary"
	"errors"
	"log"
	"sync/atomic"

	"github.com/Advanced-Observability/ioam-agent/internal/stats"
	ioamAPI "github.com/Advanced-Observability/ioam-api"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func parseNodeData(data []byte, traceType uint32) (ioamAPI.IOAMNode, error) {
	node := ioamAPI.IOAMNode{}
	offset := 0

	if traceType&traceTypeBit0Mask != 0 {
		node.HopLimit = uint32(data[offset])
		node.Id = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
		offset += 4
	}
	if traceType&traceTypeBit1Mask != 0 {
		node.IngressId = uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
		node.EgressId = uint32(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
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
		node, err := parseNodeData(data[offset:offset+int(nodeLen)*4], traceType)
		if err != nil {
			return nil, false, err
		}
		offset += int(nodeLen) * 4

		if traceType&traceTypeBit22Mask != 0 {
			if len(data[offset:]) < 4 {
				return nil, false, errors.New("invalid packet length")
			}
			opaqueLen := data[offset]
			if len(data[offset:]) < 4+int(opaqueLen)*4 {
				return nil, false, errors.New("invalid packet length")
			}
			if opaqueLen > 0 {
				node.OSS = &ioamAPI.Opaque{
					SchemaId: binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFF,
					Data:     data[offset+4 : offset+4+int(opaqueLen)*4],
				}
			}
			offset += 4 + int(opaqueLen)*4
		}

		nodes = append([]*ioamAPI.IOAMNode{&node}, nodes...)
	}

	trace := &ioamAPI.IOAMTrace{
		BitField:    traceType,
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
			atomic.AddUint64(&stats.IoamPacketCount, 1)

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

func ParsePacket(packet gopacket.Packet, report func(*ioamAPI.IOAMTrace)) {
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
