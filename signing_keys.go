package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
)

func (a *arkClient) signingKeysByScript(ctx context.Context) (map[string]string, error) {
	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := a.ArkClient.GetAddresses(
		ctx,
	)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]string)

	for _, addr := range offchainAddrs {
		if err := addSigningKeyForOffchainAddress(keys, addr.Address, addr.KeyID); err != nil {
			return nil, err
		}
		if err := addSigningKeyForCheckpointScript(
			keys, addr.Tapscripts, addr.KeyID, cfg.CheckpointExitPath(),
		); err != nil {
			return nil, err
		}
	}

	for _, addr := range boardingAddrs {
		if err := addSigningKeyForOnchainAddress(
			keys,
			addr.Address,
			addr.KeyID,
			cfg.Network,
		); err != nil {
			return nil, err
		}
	}

	for _, addr := range redemptionAddrs {
		if err := addSigningKeyForOnchainAddress(
			keys,
			addr.Address,
			addr.KeyID,
			cfg.Network,
		); err != nil {
			return nil, err
		}
	}

	for i, addr := range onchainAddrs {
		keyID := ""
		if i < len(offchainAddrs) {
			keyID = offchainAddrs[i].KeyID
		}
		if keyID == "" && i < len(boardingAddrs) {
			keyID = boardingAddrs[i].KeyID
		}
		if keyID == "" && i < len(redemptionAddrs) {
			keyID = redemptionAddrs[i].KeyID
		}

		if err := addSigningKeyForOnchainAddress(keys, addr, keyID, cfg.Network); err != nil {
			return nil, err
		}
	}

	return keys, nil
}

func addSigningKeyForOffchainAddress(keys map[string]string, address, keyID string) error {
	if keyID == "" {
		return nil
	}

	decoded, err := arklib.DecodeAddressV0(address)
	if err != nil {
		return err
	}

	script, err := decoded.GetPkScript()
	if err != nil {
		return err
	}

	keys[hex.EncodeToString(script)] = keyID
	return nil
}

func addSigningKeyForCheckpointScript(
	keys map[string]string,
	tapscripts []string,
	keyID string,
	checkpointExitPath []byte,
) error {
	if keyID == "" || len(tapscripts) == 0 || len(checkpointExitPath) == 0 {
		return nil
	}

	signerUnrollClosure := &arkscript.CSVMultisigClosure{}
	valid, err := signerUnrollClosure.Decode(checkpointExitPath)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("invalid checkpoint exit path")
	}

	vtxoScript, err := arkscript.ParseVtxoScript(tapscripts)
	if err != nil {
		return err
	}

	forfeitClosures := vtxoScript.ForfeitClosures()
	if len(forfeitClosures) == 0 {
		return nil
	}

	// Offchain sends spend a synthetic checkpoint VTXO whose tree is composed
	// from the server unroll path and the owner's collaborative forfeit path.
	checkpointScript := arkscript.TapscriptsVtxoScript{
		Closures: []arkscript.Closure{signerUnrollClosure, forfeitClosures[0]},
	}
	taprootKey, _, err := checkpointScript.TapTree()
	if err != nil {
		return err
	}

	script, err := arkscript.P2TRScript(taprootKey)
	if err != nil {
		return err
	}

	keys[hex.EncodeToString(script)] = keyID
	return nil
}

func addSigningKeyForOnchainAddress(
	keys map[string]string,
	address, keyID string,
	network arklib.Network,
) error {
	if keyID == "" {
		return nil
	}

	script, err := toOutputScript(address, network)
	if err != nil {
		return err
	}

	keys[hex.EncodeToString(script)] = keyID
	return nil
}
