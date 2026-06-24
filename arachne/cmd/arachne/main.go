// cmd/arachne/main.go
// ArachneC2 — Entry point
// Simulates a decentralized P2P C2 implant for SIEM detection testing.
//
// Usage:
//   go run ./cmd/arachne [--config arachne.json] [--duration 5m]
//
// Output:
//   Writes JSONL events to LogFile (default: /tmp/arachne-events.jsonl)
//   The arachne_collector.py reads this file and sends events to SIEM.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Lollobar17/arachne-c2/internal/beacon"
	"github.com/Lollobar17/arachne-c2/internal/config"
	"github.com/Lollobar17/arachne-c2/internal/exfil"
	"github.com/Lollobar17/arachne-c2/internal/peer"
)

var (
	configPath = flag.String("config", "arachne.json", "Path to config file")
	duration   = flag.Duration("duration", 0, "Run duration (0 = run until Ctrl+C)")
	dryRun     = flag.Bool("dry-run", false, "Log events without making network requests")
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Open event log file
	logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", cfg.LogFile, err)
	}
	defer logFile.Close()

	logMu := sync.Mutex{}

	// Generic event logger — writes JSONL to file
	writeEvent := func(eventType string, data interface{}) {
		b, _ := json.Marshal(data)
		logMu.Lock()
		fmt.Fprintf(logFile, "%s\n", b)
		logMu.Unlock()
		if cfg.LogLevel == "debug" {
			log.Printf("[%s] %s", eventType, b)
		}
	}

	fmt.Printf("ArachneC2 Simulator starting\n")
	fmt.Printf("  Node ID:  %s\n", cfg.NodeID)
	fmt.Printf("  Role:     %s\n", cfg.NodeRole)
	fmt.Printf("  Log file: %s\n", cfg.LogFile)
	fmt.Printf("  Beacon:   %s (jitter %.0f%%)\n", cfg.BeaconInterval, cfg.BeaconJitter*100)
	if *dryRun {
		fmt.Println("  Mode:     DRY RUN (no network requests)")
	}
	fmt.Println()

	// Setup context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Duration limit
	if *duration > 0 {
		go func() {
			time.Sleep(*duration)
			fmt.Printf("\nDuration %s elapsed — shutting down\n", *duration)
			cancel()
		}()
	}

	// Signal handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived signal — shutting down")
		cancel()
	}()

	var wg sync.WaitGroup

	// Start beacon
	wg.Add(1)
	go func() {
		defer wg.Done()
		b := beacon.New(cfg, func(e beacon.BeaconEvent) {
			writeEvent("beacon", e)
			fmt.Printf("[beacon] → %s (success=%v, jitter=%dms)\n",
				e.TargetURL, e.Success, e.JitterMs)
		})
		b.Start(ctx)
	}()

	// Start peer manager
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm := peer.New(cfg, func(e peer.PeerEvent) {
			writeEvent("peer", e)
			fmt.Printf("[%s] → %s (success=%v)\n",
				e.EventType, e.PeerAddress, e.Success)
		})
		pm.Start(ctx)
	}()

	// Start exfiltration
	wg.Add(1)
	go func() {
		defer wg.Done()
		ex := exfil.New(cfg, func(e exfil.ExfilEvent) {
			writeEvent("exfil", e)
			fmt.Printf("[exfil] chunk %d/%d → %s (success=%v)\n",
				e.ChunkIndex, e.TotalChunks, e.TargetIP, e.Success)
		})
		ex.Start(ctx)
	}()

	wg.Wait()
	fmt.Println("ArachneC2 Simulator stopped.")
}
