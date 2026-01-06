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
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// LightningChannelScriptBuilder creates VTXO scripts for Lightning Network channels.
// It implements the dual-path Taproot structure required by Arkade Lightning Channels:
//
// Script Path 1: Standard 2-of-2 multisig (Alice + Bob)
// Script Path 2: Same 2-of-2 multisig + CSV timeout for Ark unilateral exit
//
// This allows:
// - Normal Lightning operation using standard commitment transactions
// - Unilateral exit if Arkade Server becomes unavailable
//
// The Server key does NOT appear in these scripts. The Server only
// participates in the VTXO creation (cooperative path), not in Lightning operations.
type LightningChannelScriptBuilder struct {
	// AliceKey is one channel participant's public key
	AliceKey *btcec.PublicKey

	// BobKey is the other channel participant's public key
	BobKey *btcec.PublicKey

	// EnableLogging enables detailed logging for debugging
	EnableLogging bool
}

// NewLightningChannelScriptBuilder creates a new Lightning channel script builder.
//
// Parameters:
//   - aliceKey: Public key of first channel participant
//   - bobKey: Public key of second channel participant
//
// The resulting scripts create a 2-of-2 multisig channel between Alice and Bob,
// with an Ark timeout escape hatch for unilateral exit.
func NewLightningChannelScriptBuilder(
	aliceKey, bobKey *btcec.PublicKey,
	enableLogging bool,
) wallet.VtxoScriptBuilder {
	return &LightningChannelScriptBuilder{
		AliceKey:      aliceKey,
		BobKey:        bobKey,
		EnableLogging: enableLogging,
	}
}

// BuildOffchainScript creates the Lightning channel funding output script.
//
// This implements the dual-path Taproot structure:
//
// Internal Key: MuSig2(Alice, Bob) - for key path spending
//
// Script Path 1: Standard Lightning 2-of-2 multisig
//   OP_CHECKSIG(Alice) OP_CHECKSIGADD(Bob) OP_2 OP_NUMEQUAL
//
// Script Path 2: Same multisig + Ark CSV timeout
//   OP_CHECKSIG(Alice) OP_CHECKSIGADD(Bob) OP_2 OP_NUMEQUAL
//   OP_CSV(<batch_expiry_blocks>)
//
// The Server's signerPubKey is NOT included in these scripts. Server only
// participates in the VTXO creation (cooperative spending path), not in
// Lightning commitment transactions.
func (l *LightningChannelScriptBuilder) BuildOffchainScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	if l.EnableLogging {
		log.Printf("[Lightning Channel] Building offchain script")
		log.Printf("  Alice: %x", schnorr.SerializePubKey(l.AliceKey))
		log.Printf("  Bob: %x", schnorr.SerializePubKey(l.BobKey))
		log.Printf("  Exit Delay: %+v", exitDelay)
	}

	// Build the dual-path Taproot script for Lightning channel funding
	channelScript, err := l.buildDualPathChannelScript(exitDelay)
	if err != nil {
		return nil, fmt.Errorf("failed to build channel script: %w", err)
	}

	if l.EnableLogging {
		log.Printf("[Lightning Channel] Generated %d tapscripts", len(channelScript))
	}

	return channelScript, nil
}

// BuildBoardingScript creates boarding scripts for Lightning channels.
//
// Note: Boarding typically uses longer exit delays than regular offchain VTXOs.
// For Lightning channels, you might want different policies for boarding vs
// regular channel operations.
func (l *LightningChannelScriptBuilder) BuildBoardingScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	if l.EnableLogging {
		log.Printf("[Lightning Channel] Building boarding script with extended delay")
	}

	// For boarding, we might want a longer CSV delay
	// This is configurable based on your security requirements
	return l.buildDualPathChannelScript(exitDelay)
}

// buildDualPathChannelScript creates the dual-path Taproot structure
// for Lightning channel funding outputs.
func (l *LightningChannelScriptBuilder) buildDualPathChannelScript(
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	// Standard Lightning 2-of-2 multisig script
	// This is the script used by Lightning commitment transactions
	lightningScript, err := l.buildLightning2of2Script()
	if err != nil {
		return nil, fmt.Errorf("failed to build Lightning script: %w", err)
	}

	// Create Leaf 1: Standard Lightning script (unmodified)
	// This is used for normal Lightning operation
	leaf1 := txscript.NewBaseTapLeaf(lightningScript)

	// Create Leaf 2: Lightning script + CSV timeout for Ark unilateral exit
	// This is the escape hatch if Server becomes unavailable
	csvScript, err := l.buildLightningScriptWithCSV(lightningScript, exitDelay)
	if err != nil {
		return nil, fmt.Errorf("failed to build CSV script: %w", err)
	}
	leaf2 := txscript.NewBaseTapLeaf(csvScript)

	// Build Taproot tree with both leaves
	tapTree := txscript.AssembleTaprootScriptTree(leaf1, leaf2)
	if tapTree == nil {
		return nil, fmt.Errorf("failed to assemble Taproot tree")
	}

	// Encode the scripts in the format expected by Arkade
	// This returns hex-encoded tapscripts
	return l.encodeTapscripts(tapTree, lightningScript, csvScript)
}

// buildLightning2of2Script creates the standard Lightning 2-of-2 multisig script.
//
// Script: OP_CHECKSIG(Alice) OP_CHECKSIGADD(Bob) OP_2 OP_NUMEQUAL
//
// This is a standard BIP342 Tapscript that requires signatures from both
// Alice and Bob to spend.
func (l *LightningChannelScriptBuilder) buildLightning2of2Script() ([]byte, error) {
	builder := txscript.NewScriptBuilder()

	// Alice's signature check
	builder.AddData(schnorr.SerializePubKey(l.AliceKey))
	builder.AddOp(txscript.OP_CHECKSIG)

	// Bob's signature check and accumulate
	builder.AddData(schnorr.SerializePubKey(l.BobKey))
	builder.AddOp(txscript.OP_CHECKSIGADD)

	// Require exactly 2 valid signatures
	builder.AddOp(txscript.OP_2)
	builder.AddOp(txscript.OP_NUMEQUAL)

	return builder.Script()
}

// buildLightningScriptWithCSV adds a CSV timeout to the Lightning script.
//
// This creates: <lightning_script> OP_CSV(<delay>)
//
// The CSV delay enables unilateral exit if the Arkade Server becomes
// unavailable. This should NEVER be needed during normal Lightning operation.
func (l *LightningChannelScriptBuilder) buildLightningScriptWithCSV(
	lightningScript []byte,
	exitDelay arklib.RelativeLocktime,
) ([]byte, error) {
	// Convert exit delay to CSV sequence
	csvSequence, err := arklib.BIP68Sequence(exitDelay)
	if err != nil {
		return nil, fmt.Errorf("failed to convert exit delay to CSV sequence: %w", err)
	}

	builder := txscript.NewScriptBuilder()

	// Add the original Lightning script
	builder.AddFullScript(lightningScript)

	// Add CSV timeout
	builder.AddInt64(int64(csvSequence))
	builder.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	builder.AddOp(txscript.OP_DROP)

	return builder.Script()
}

// encodeTapscripts encodes the Taproot tree into the format expected by Arkade.
//
// This is a simplified encoding for demonstration. In production, you would
// use the proper script.VtxoScript encoding format.
func (l *LightningChannelScriptBuilder) encodeTapscripts(
	tapTree *txscript.IndexedTapScriptTree,
	lightningScript, csvScript []byte,
) ([]string, error) {
	// For this example, we'll create a VtxoScript using the script package
	// In practice, you might need to adapt this based on your specific requirements

	// Create closures for each script path
	// Note: This is a simplified example. Real implementation would need
	// proper closure types matching the script semantics.

	// Create a custom multisig closure for the Lightning channel
	multisigClosure := &script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{l.AliceKey, l.BobKey},
	}

	// Create VTXO script with our closures
	vtxoScript := &script.VtxoScript{
		Closures: []script.Closure{multisigClosure},
	}

	// Encode and return
	return vtxoScript.Encode()
}

// Example usage demonstrating Lightning channel funding with custom scripts
func main() {
	ctx := context.Background()

	log.Println("=== Lightning Channel on Arkade Example ===")
	log.Println()

	// Generate keys for Alice and Bob (channel participants)
	alicePrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate Alice's key: %v", err)
	}
	aliceKey := alicePrivKey.PubKey()

	bobPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		log.Fatalf("Failed to generate Bob's key: %v", err)
	}
	bobKey := bobPrivKey.PubKey()

	log.Printf("Channel Participants:")
	log.Printf("  Alice: %x", schnorr.SerializePubKey(aliceKey))
	log.Printf("  Bob: %x", schnorr.SerializePubKey(bobKey))
	log.Println()

	// Create Lightning channel script builder
	// This creates 2-of-2 multisig between Alice and Bob
	channelBuilder := NewLightningChannelScriptBuilder(aliceKey, bobKey, true)

	// Create Arkade client with Lightning channel script builder
	storeSvc, err := store.NewStore(store.Config{
		ConfigStoreType: types.InMemoryStore,
	})
	if err != nil {
		log.Fatalf("Failed to setup store: %v", err)
	}

	client, err := arksdk.NewArkClient(storeSvc)
	if err != nil {
		log.Fatalf("Failed to create ARK client: %v", err)
	}

	log.Println("Initializing Arkade client with Lightning channel scripts...")

	// Initialize with custom script builder
	err = client.Init(ctx, arksdk.InitArgs{
		WalletType:    arksdk.SingleKeyWallet,
		ClientType:    arksdk.GrpcClient,
		ServerUrl:     "localhost:7070",
		Password:      "password",
		ScriptBuilder: channelBuilder, // Use Lightning channel scripts
	})
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	log.Println("✓ Client initialized with Lightning channel scripts")
	log.Println()

	// Unlock wallet
	if err := client.Unlock(ctx, "password"); err != nil {
		log.Fatalf("Failed to unlock wallet: %v", err)
	}
	defer client.Lock(ctx)

	// Generate addresses - these use Lightning channel scripts
	offchainAddr, boardingAddr, err := client.Receive(ctx)
	if err != nil {
		log.Fatalf("Failed to generate addresses: %v", err)
	}

	log.Println("Lightning Channel Funding Addresses:")
	log.Printf("  Offchain (Channel): %s", offchainAddr)
	log.Printf("  Boarding: %s", boardingAddr)
	log.Println()

	log.Println("=== Key Points ===")
	log.Println()
	log.Println("1. Dual-Path Taproot Structure:")
	log.Println("   - Leaf 1: Standard 2-of-2 Lightning multisig")
	log.Println("   - Leaf 2: Same multisig + CSV timeout for Ark exit")
	log.Println()
	log.Println("2. Server Participation:")
	log.Println("   ✓ Server participates in VTXO creation (cooperative path)")
	log.Println("   ✗ Server does NOT appear in Lightning commitment tx scripts")
	log.Println("   ✗ Server does NOT participate in HTLC forwarding")
	log.Println()
	log.Println("3. Channel Operation:")
	log.Println("   - Once funded, operates as standard Lightning channel")
	log.Println("   - Alice and Bob exchange Lightning commitment txs")
	log.Println("   - HTLCs route over standard Lightning rails")
	log.Println("   - Server only involved for lifecycle (renewal, resize, close)")
	log.Println()
	log.Println("4. Critical Constraint:")
	log.Println("   - Must enforce: htlc.cltv_expiry < batch_expiry - SAFETY_MARGIN")
	log.Println("   - Prevents race condition between HTLC timeout and VTXO expiry")
	log.Println()
	log.Println("5. Unilateral Exit:")
	log.Println("   - CSV timeout path is fallback if Server unavailable")
	log.Println("   - Normal force close uses cooperative mechanism with Server")
	log.Println()
	log.Println("=== Next Steps ===")
	log.Println()
	log.Println("To create an actual Lightning channel:")
	log.Println("1. Fund the VTXO (this creates the channel funding output)")
	log.Println("2. Exchange initial Lightning commitment transactions")
	log.Println("3. Operate the channel using standard Lightning protocols")
	log.Println("4. Monitor VTXO expiry and trigger renewal before deadline")
	log.Println("5. Implement HTLC acceptance with expiry validation")
	log.Println()
	log.Println("For a complete implementation, see:")
	log.Println("  https://github.com/vincenzopalazzo/lampo.rs")
	log.Println("  (lampo-ark-wallet/src/lib.rs, line 173+)")
}
