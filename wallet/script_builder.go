package wallet

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
)

// VtxoScriptBuilder defines the interface for building custom VTXo scripts.
// This allows users to provide custom script generation logic for both offchain
// and boarding addresses while maintaining compatibility with the ARK protocol.
//
// Implementations must ensure that:
//  1. Generated scripts are valid taproot scripts
//  2. Scripts respect the provided exit delays
//  3. Scripts include the necessary forfeit and exit closures
//  4. Encoded scripts can be decoded using script.ParseVtxoScript()
//
// Example usage:
//
//	type CustomBuilder struct{}
//
//	func (c *CustomBuilder) BuildOffchainScript(
//	    userPubKey, signerPubKey *btcec.PublicKey,
//	    exitDelay arklib.RelativeLocktime,
//	) ([]string, error) {
//	    // Custom script logic here
//	    return customScripts, nil
//	}
//
//	// Use in client initialization:
//	client.Init(ctx, arksdk.InitArgs{
//	    ScriptBuilder: &CustomBuilder{},
//	    // ... other fields
//	})
type VtxoScriptBuilder interface {
	// BuildOffchainScript creates a script for offchain VTXo addresses.
	// This script defines the spending conditions for VTXOs created in the
	// batch tree during normal ARK operations.
	//
	// Parameters:
	//   - userPubKey: The user's public key for signing transactions
	//   - signerPubKey: The ARK server's signer public key
	//   - exitDelay: The relative locktime for unilateral exit
	//
	// Returns:
	//   - []string: Array of hex-encoded tapscripts
	//   - error: Any error encountered during script generation
	BuildOffchainScript(
		userPubKey *btcec.PublicKey,
		signerPubKey *btcec.PublicKey,
		exitDelay arklib.RelativeLocktime,
	) ([]string, error)

	// BuildBoardingScript creates a script for boarding addresses.
	// Boarding addresses are used for onboarding funds into the ARK.
	// These scripts typically have different exit delay parameters.
	//
	// Parameters:
	//   - userPubKey: The user's public key for signing transactions
	//   - signerPubKey: The ARK server's signer public key
	//   - exitDelay: The relative locktime for boarding exit (often longer than offchain)
	//
	// Returns:
	//   - []string: Array of hex-encoded tapscripts
	//   - error: Any error encountered during script generation
	BuildBoardingScript(
		userPubKey *btcec.PublicKey,
		signerPubKey *btcec.PublicKey,
		exitDelay arklib.RelativeLocktime,
	) ([]string, error)
}
