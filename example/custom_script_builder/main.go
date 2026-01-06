package main

import (
	"context"
	"fmt"
	"log"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
)

// ExampleCustomScriptBuilder demonstrates how to create a custom VTXo script builder.
// This example creates scripts with custom conditions while maintaining ARK protocol compatibility.
type ExampleCustomScriptBuilder struct {
	// You can add configuration fields here
	enableExtendedTimelock bool
}

// NewExampleCustomScriptBuilder creates a new instance of the example custom script builder.
func NewExampleCustomScriptBuilder(enableExtendedTimelock bool) wallet.VtxoScriptBuilder {
	return &ExampleCustomScriptBuilder{
		enableExtendedTimelock: enableExtendedTimelock,
	}
}

// BuildOffchainScript generates a custom offchain VTXo script.
// In this example, we use the default script but could add custom logic here.
func (e *ExampleCustomScriptBuilder) BuildOffchainScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	// Example: Optionally extend the exit delay for additional security
	if e.enableExtendedTimelock {
		exitDelay.Value = exitDelay.Value * 2
		log.Printf("Extended offchain exit delay to %d", exitDelay.Value)
	}

	// For this example, we use the default script implementation
	// In a real custom builder, you would create your own script structure here
	vtxoScript := script.NewDefaultVtxoScript(userPubKey, signerPubKey, exitDelay)

	scripts, err := vtxoScript.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode custom offchain script: %w", err)
	}

	log.Printf("Generated custom offchain script with %d tapscripts", len(scripts))
	return scripts, nil
}

// BuildBoardingScript generates a custom boarding script.
func (e *ExampleCustomScriptBuilder) BuildBoardingScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	// Example: Boarding scripts typically have longer delays
	// This example shows you could apply different logic for boarding vs offchain

	if e.enableExtendedTimelock {
		// For boarding, we might want even more security
		exitDelay.Value = exitDelay.Value * 3
		log.Printf("Extended boarding exit delay to %d", exitDelay.Value)
	}

	vtxoScript := script.NewDefaultVtxoScript(userPubKey, signerPubKey, exitDelay)

	scripts, err := vtxoScript.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode custom boarding script: %w", err)
	}

	log.Printf("Generated custom boarding script with %d tapscripts", len(scripts))
	return scripts, nil
}

func main() {
	ctx := context.Background()

	// Create an in-memory store for this example
	storeSvc, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		log.Fatalf("Failed to setup store: %v", err)
	}

	// Create the ARK client
	client, err := arksdk.NewArkClient(storeSvc)
	if err != nil {
		log.Fatalf("Failed to create ARK client: %v", err)
	}

	// Create a custom script builder
	// Set enableExtendedTimelock to true to demonstrate custom behavior
	customBuilder := NewExampleCustomScriptBuilder(true)

	// Initialize the client with the custom script builder
	err = client.Init(ctx, arksdk.InitArgs{
		WalletType:    arksdk.SingleKeyWallet,
		ClientType:    arksdk.GrpcClient,
		ServerUrl:     "localhost:7070", // Replace with your ARK server URL
		Password:      "password",
		ScriptBuilder: customBuilder, // Use custom script builder
	})
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	log.Println("Successfully initialized ARK client with custom script builder!")

	// Unlock the wallet
	if err := client.Unlock(ctx, "password"); err != nil {
		log.Fatalf("Failed to unlock wallet: %v", err)
	}
	defer client.Lock(ctx)

	// Generate addresses - these will use the custom scripts
	_, offchainAddr, boardingAddr, err := client.Receive(ctx)
	if err != nil {
		log.Fatalf("Failed to generate addresses: %v", err)
	}

	log.Printf("Offchain address (with custom script): %s", offchainAddr)
	log.Printf("Boarding address (with custom script): %s", boardingAddr)

	// The custom script builder will be used for all VTXo operations:
	// - Receiving funds
	// - Sending offchain
	// - Boarding
	// - Collaborative exits
	// etc.

	log.Println("\nExample complete!")
	log.Println("\nKey points:")
	log.Println("1. Custom script builders implement the VtxoScriptBuilder interface")
	log.Println("2. Scripts must be compatible with the ARK protocol")
	log.Println("3. Both offchain and boarding scripts can have custom logic")
	log.Println("4. The script builder is used throughout the client lifecycle")
}

// Additional example: A script builder that logs all script generation
type LoggingScriptBuilder struct {
	underlying wallet.VtxoScriptBuilder
}

func NewLoggingScriptBuilder() wallet.VtxoScriptBuilder {
	return &LoggingScriptBuilder{
		underlying: wallet.NewDefaultScriptBuilder(),
	}
}

func (l *LoggingScriptBuilder) BuildOffchainScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	log.Printf("[LOGGING] Building offchain script - ExitDelay: %+v", exitDelay)
	scripts, err := l.underlying.BuildOffchainScript(userPubKey, signerPubKey, exitDelay)
	if err != nil {
		log.Printf("[LOGGING] Error building offchain script: %v", err)
		return nil, err
	}
	log.Printf("[LOGGING] Successfully built offchain script with %d tapscripts", len(scripts))
	return scripts, nil
}

func (l *LoggingScriptBuilder) BuildBoardingScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	log.Printf("[LOGGING] Building boarding script - ExitDelay: %+v", exitDelay)
	scripts, err := l.underlying.BuildBoardingScript(userPubKey, signerPubKey, exitDelay)
	if err != nil {
		log.Printf("[LOGGING] Error building boarding script: %v", err)
		return nil, err
	}
	log.Printf("[LOGGING] Successfully built boarding script with %d tapscripts", len(scripts))
	return scripts, nil
}
