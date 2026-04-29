package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkscript "github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/wallet/hdwallet"
	"github.com/btcsuite/btcd/btcec/v2"
)

// discoverHDWalletKeys walks the BIP32 child range, batched by gapLimit,
// querying the indexer for each batch's offchain VTXO scripts. Discovery
// stops as soon as `gapLimit` consecutive unused indices have been seen.
// All keys up to and including the highest used index are then allocated
// via NewKey so the wallet's tracked-keys view matches discovery.
//
// Returns true if at least one key was discovered.
// TODO: Drop this file in https://github.com/arkade-os/go-sdk/pull/145
func (a *arkClient) discoverHDWalletKeys(ctx context.Context) (bool, error) {
	w := a.Wallet()
	if w == nil {
		return false, nil
	}

	gapLimit := a.hdGapLimit
	if gapLimit == 0 {
		gapLimit = hdwallet.DefaultGapLimit
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return false, err
	}

	var (
		nextIdx           uint32
		lastUsedIdx       int64 = -1
		consecutiveUnused uint32
	)

	for consecutiveUnused < gapLimit {
		scripts, err := a.deriveOffchainScriptsBatch(ctx, w, cfg, nextIdx, gapLimit)
		if err != nil {
			return false, err
		}

		used, err := a.queryUsedScripts(ctx, scripts)
		if err != nil {
			return false, err
		}

		for i, scriptHex := range scripts {
			idx := nextIdx + uint32(i)
			if _, isUsed := used[scriptHex]; isUsed {
				lastUsedIdx = int64(idx)
				consecutiveUnused = 0
				continue
			}
			consecutiveUnused++
			if consecutiveUnused >= gapLimit {
				break
			}
		}

		nextIdx += gapLimit
	}

	if lastUsedIdx < 0 {
		return false, nil
	}

	for i := uint32(0); i < uint32(lastUsedIdx)+1; i++ {
		if _, err := w.NewKey(ctx); err != nil {
			return false, err
		}
	}
	return true, nil
}

// deriveOffchainScriptsBatch derives `count` consecutive keys starting at
// `start` and returns the hex-encoded offchain VTXO pkScript for each, in
// order.
func (a *arkClient) deriveOffchainScriptsBatch(
	ctx context.Context, w wallet.WalletService, cfg *clientTypes.Config, start, count uint32,
) ([]string, error) {
	scripts := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		keyID := fmt.Sprintf("m/0/%d", start+i)
		keyRef, err := w.GetKey(ctx, keyID)
		if err != nil {
			return nil, err
		}
		scriptHex, err := offchainPkScriptHex(keyRef.PubKey, cfg)
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, scriptHex)
	}
	return scripts, nil
}

// queryUsedScripts queries the indexer for any VTXO activity on the given
// scripts and returns the set of scripts that have at least one VTXO.
func (a *arkClient) queryUsedScripts(
	ctx context.Context, scripts []string,
) (map[string]struct{}, error) {
	if len(scripts) == 0 {
		return nil, nil
	}
	res, err := a.Indexer().GetVtxos(ctx, indexer.WithScripts(scripts))
	if err != nil {
		return nil, err
	}
	used := make(map[string]struct{}, len(res.Vtxos))
	for _, v := range res.Vtxos {
		used[v.Script] = struct{}{}
	}
	return used, nil
}

// offchainPkScriptHex computes the default offchain VTXO pkScript for the
// given owner pubkey, using the server signer pubkey and unilateral exit
// delay from the SDK config, and returns it hex-encoded.
func offchainPkScriptHex(pubKey *btcec.PublicKey, cfg *clientTypes.Config) (string, error) {
	vtxoScript := arkscript.NewDefaultVtxoScript(pubKey, cfg.SignerPubKey, cfg.UnilateralExitDelay)
	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return "", err
	}
	addr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
		VtxoTapKey: vtxoTapKey,
	}
	pkScript, err := addr.GetPkScript()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pkScript), nil
}
