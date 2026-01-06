package wallet

import (
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/btcsuite/btcd/btcec/v2"
)

// defaultScriptBuilder implements VtxoScriptBuilder using the standard ARK
// default script logic. This is the default implementation used when no
// custom script builder is provided.
//
// The default scripts include:
//   - Forfeit closure: Allows the server to claim funds in case of user misbehavior
//   - Exit closure: Allows unilateral exit after the specified delay
//
// This implementation uses script.NewDefaultVtxoScript internally, which creates
// standard ARK VTXo scripts compatible with all ARK servers.
type defaultScriptBuilder struct{}

// NewDefaultScriptBuilder creates a new instance of the default script builder.
// This builder generates standard ARK VTXo scripts that are compatible with
// all ARK protocol implementations.
//
// Returns:
//   - VtxoScriptBuilder: A new default script builder instance
func NewDefaultScriptBuilder() VtxoScriptBuilder {
	return &defaultScriptBuilder{}
}

// BuildOffchainScript generates the standard ARK offchain VTXo script.
// This script includes standard forfeit and exit closures with the specified
// exit delay for unilateral exits.
//
// Parameters:
//   - userPubKey: The user's public key (required, must not be nil)
//   - signerPubKey: The ARK server's signer public key (required, must not be nil)
//   - exitDelay: The relative locktime for unilateral exit
//
// Returns:
//   - []string: Array of hex-encoded tapscripts
//   - error: Returns error if script encoding fails
func (d *defaultScriptBuilder) BuildOffchainScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	vtxoScript := script.NewDefaultVtxoScript(userPubKey, signerPubKey, exitDelay)
	return vtxoScript.Encode()
}

// BuildBoardingScript generates the standard ARK boarding script.
// Boarding scripts are used for onboarding funds and typically have
// longer exit delays than offchain scripts.
//
// Parameters:
//   - userPubKey: The user's public key (required, must not be nil)
//   - signerPubKey: The ARK server's signer public key (required, must not be nil)
//   - exitDelay: The relative locktime for boarding exit (typically longer than offchain)
//
// Returns:
//   - []string: Array of hex-encoded tapscripts
//   - error: Returns error if script encoding fails
func (d *defaultScriptBuilder) BuildBoardingScript(
	userPubKey *btcec.PublicKey,
	signerPubKey *btcec.PublicKey,
	exitDelay arklib.RelativeLocktime,
) ([]string, error) {
	vtxoScript := script.NewDefaultVtxoScript(userPubKey, signerPubKey, exitDelay)
	return vtxoScript.Encode()
}
