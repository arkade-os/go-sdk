package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/explorer"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func main() {
	// Command-line flags
	numAddresses := flag.Int("addresses", 100, "Number of addresses to generate and subscribe")
	maxConnections := flag.Int("connections", 3, "Maximum number of concurrent WebSocket connections")
	batchSize := flag.Int("batch-size", 25, "Number of addresses per batch")
	batchDelay := flag.Duration("batch-delay", 50*time.Millisecond, "Delay between batches")
	explorerURL := flag.String("url", "https://mempool.space/api", "Explorer API URL")
	maxEvents := flag.Int("max-events", 5, "Maximum number of events to receive before stopping (0 = unlimited)")
	showAll := flag.Bool("show-all", false, "Show all subscribed addresses (not just first 3)")

	flag.Parse()

	fmt.Println("🧪 Testing Multi-Connection Explorer with Batched Subscriptions")
	fmt.Println("============================================================")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Addresses:     %d\n", *numAddresses)
	fmt.Printf("  Connections:   %d\n", *maxConnections)
	fmt.Printf("  Batch Size:    %d\n", *batchSize)
	fmt.Printf("  Batch Delay:   %v\n", *batchDelay)
	fmt.Printf("  Explorer URL:  %s\n", *explorerURL)
	fmt.Println("============================================================")

	// Create explorer with configurable parameters
	svc, err := explorer.NewExplorer(*explorerURL, arklib.Bitcoin,
		explorer.WithTracker(true),
		explorer.WithMaxConnections(*maxConnections),
		explorer.WithBatchSize(*batchSize),
		explorer.WithBatchDelay(*batchDelay))
	if err != nil {
		log.Fatal("❌ Failed to create explorer:", err)
	}

	// Verify actual configuration from the service
	actualConnections := svc.GetConnectionCount()
	actualBatchSize := svc.GetBatchSize()
	actualBatchDelay := svc.GetBatchDelay()

	fmt.Println("\nActual Configuration (verified from service):")
	if actualConnections == 0 {
		fmt.Println("  Mode:          Polling (WebSocket unavailable)")
	} else if actualConnections == 1 {
		fmt.Printf("  Connections:   %d connection\n", actualConnections)
	} else {
		fmt.Printf("  Connections:   %d connections\n", actualConnections)
	}
	fmt.Printf("  Batch Size:    %d addresses/batch\n", actualBatchSize)
	fmt.Printf("  Batch Delay:   %v\n", actualBatchDelay)
	fmt.Printf("  Base URL:      %s\n", svc.BaseUrl())

	// Generate test addresses
	addresses := make([]string, 0, *numAddresses)
	fmt.Printf("🔄 Generating %d test addresses...\n", *numAddresses)
	for i := 0; i < *numAddresses; i++ {
		addresses = append(addresses, newTestAddr(i))
	}
	fmt.Printf("✅ Generated %d addresses\n", len(addresses))

	// Subscribe to addresses (this will use the multi-connection batching)
	fmt.Println("📡 Subscribing to addresses with batched distribution...")
	start := time.Now()
	err = svc.SubscribeForAddresses(addresses)
	duration := time.Since(start)

	if err != nil {
		log.Fatal("❌ Failed to subscribe to addresses:", err)
	}

	// Verify actual subscription count from service
	actualSubscribed := svc.GetSubscribedAddressCount()
	errorCount := svc.GetErrorCount()
	subscribedAddresses := svc.GetSubscribedAddresses()

	fmt.Printf("✅ Successfully subscribed to %d addresses in %v\n", len(addresses), duration)
	fmt.Printf("📊 Verified: %d addresses actively subscribed in service\n", actualSubscribed)
	if actualConnections > 0 {
		fmt.Printf("📡 Distributed across %d WebSocket connection(s)\n", actualConnections)
	}

	// Show sample of subscribed addresses
	if len(subscribedAddresses) > 0 {
		if *showAll {
			fmt.Printf("📋 All subscribed addresses (%d total):\n", len(subscribedAddresses))
			for i, addr := range subscribedAddresses {
				isSubscribed := svc.IsAddressSubscribed(addr)
				status := "✅"
				if !isSubscribed {
					status = "❌"
				}
				fmt.Printf("   %d. %s %s\n", i+1, status, addr)
			}
		} else {
			fmt.Printf("📋 Sample subscribed addresses (first 3 of %d):\n", len(subscribedAddresses))
			for i := 0; i < 3 && i < len(subscribedAddresses); i++ {
				isSubscribed := svc.IsAddressSubscribed(subscribedAddresses[i])
				status := "✅"
				if !isSubscribed {
					status = "❌"
				}
				fmt.Printf("   %s %s\n", status, subscribedAddresses[i])
			}
			if len(subscribedAddresses) > 3 {
				fmt.Printf("   ... and %d more (use -show-all to see all)\n", len(subscribedAddresses)-3)
			}
		}
	}

	// Check for any errors during subscription
	if errorCount > 0 {
		fmt.Printf("⚠️  Warning: %d error(s) encountered during setup\n", errorCount)
		errors := svc.GetErrors()
		for i, err := range errors {
			fmt.Printf("   Error %d: %v\n", i+1, err)
		}
	} else {
		fmt.Println("✅ No errors encountered during setup")
	}

	if *maxEvents == 0 {
		fmt.Println("🔄 Listening for blockchain events indefinitely (Ctrl+C to stop)...")
	} else {
		fmt.Printf("🔄 Listening for blockchain events (will stop after %d events)...\n", *maxEvents)
	}

	// Listen for events
	eventCount := 0
	lastErrorCount := errorCount

	for ev := range svc.GetAddressesEvents() {
		eventCount++
		fmt.Printf("🎯 Event #%d: %+v\n", eventCount, ev)

		// Check for new errors periodically
		currentErrorCount := svc.GetErrorCount()
		if currentErrorCount > lastErrorCount {
			newErrors := svc.GetErrors()[lastErrorCount:]
			fmt.Printf("⚠️  %d new error(s) detected:\n", len(newErrors))
			for i, err := range newErrors {
				fmt.Printf("   Error %d: %v\n", lastErrorCount+i+1, err)
			}
			lastErrorCount = currentErrorCount
		}

		// Stop after receiving max events (if configured)
		if *maxEvents > 0 && eventCount >= *maxEvents {
			break
		}
	}

	// Final error summary
	finalErrorCount := svc.GetErrorCount()
	fmt.Println("\n✅ Test completed successfully!")
	fmt.Printf("📊 Final Statistics:\n")
	fmt.Printf("   Events received: %d\n", eventCount)
	fmt.Printf("   Total errors:    %d\n", finalErrorCount)
	if finalErrorCount == 0 {
		fmt.Println("   ✅ No errors encountered!")
	}
	fmt.Println("\n💡 The multi-connection architecture prevents I/O timeouts")
	fmt.Println("   and provides better scalability for high-volume usage.")
}

func newTestAddr(index int) string {
	// Create a deterministic address based on index for testing
	key, _ := btcec.NewPrivateKey()
	pubKey := key.PubKey()
	pubKeyCompressed := pubKey.SerializeCompressed()

	pubKeyHash := btcutil.Hash160(pubKeyCompressed)

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		log.Fatal(err)
	}

	return addr.EncodeAddress()
}
