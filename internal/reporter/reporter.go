package reporter

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Advanced-Observability/ioam-agent/internal/config"
	ioamAPI "github.com/Advanced-Observability/ioam-api"
)

type Reporter func(trace *ioamAPI.IOAMTrace)

func SetupReporting(cfg *config.Config) Reporter {
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
			fmt.Fprintf(f, "timestamp,namespace_id,tracetype,hop_limit,node_id,ingress_id,egress_id,timestamp_secs,timestamp_frac,transit_delay,queue_depth,csum_comp,buffer_occupancy,ingress_id_wide,egress_id_wide,id_wide,namespace_data,namespace_data_wide,oss_schema_id,oss_data\n")
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
		toPrint := fmt.Sprintf("%s,%d,%06x,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%04x,%08x,",
			time.Now().Format(time.RFC3339), trace.GetNamespaceId(), trace.GetBitField(),
			node.GetHopLimit(), node.GetId(), node.GetIngressId(), node.GetEgressId(),
			node.GetTimestampSecs(), node.GetTimestampFrac(), node.GetTransitDelay(), node.GetQueueDepth(),
			node.GetCsumComp(), node.GetBufferOccupancy(), node.GetIngressIdWide(), node.GetEgressIdWide(),
			node.GetIdWide(), node.GetNamespaceData(), node.GetNamespaceDataWide())

		oss := node.GetOSS()
		if oss != nil {
			toPrint += fmt.Sprintf("%d,%x", oss.SchemaId, oss.Data)
		}
		toPrint += "\n"

		if _, err := f.WriteString(toPrint); err != nil {
			log.Printf("Error writing to file: %v", err)
		}
	}
}
