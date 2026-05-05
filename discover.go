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
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
)

// discoverHDWalletKeys walks the BIP32 child range, batched by gapLimit,
// querying both the indexer (offchain VTXOs) and the explorer (boarding
// address tx history) for each batch. Discovery stops as soon as `gapLimit`
// consecutive unused indices have been seen across both sources.
// All keys up to and including the highest used index are then allocated
// via NewKey so the wallet's tracked-keys view matches discovery.
//
// Returns true if at least one key was discovered.
func (a *arkClient) discoverHDWalletKeys(ctx context.Context) (bool, error) {
	w := a.Wallet()
	if w == nil {
		return false, nil
	}

	// Discovery only applies to HD wallets. Single-key wallets have a fixed
	// key set and their GetKey ignores the keyID, which would cause the gap-
	// limit loop to run forever (every index returns the same used key).
	if w.GetType() != hdwallet.Type {
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

		boardingAddrs, err := a.deriveBoardingAddressBatch(ctx, w, cfg, nextIdx, gapLimit)
		if err != nil {
			return false, err
		}

		offchainUsed, err := a.queryUsedScripts(ctx, scripts)
		if err != nil {
			return false, err
		}

		boardingUsed, err := a.queryUsedBoardingAddresses(boardingAddrs)
		if err != nil {
			return false, err
		}

		for i, scriptHex := range scripts {
			idx := nextIdx + uint32(i)
			_, inOffchain := offchainUsed[scriptHex]
			_, inBoarding := boardingUsed[boardingAddrs[i]]
			if inOffchain || inBoarding {
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

// deriveBoardingAddressBatch derives `count` consecutive boarding taproot
// addresses starting at `start`, using the boarding VtxoScript
// (BoardingExitDelay), returning each address string in order.
func (a *arkClient) deriveBoardingAddressBatch(
	ctx context.Context, w wallet.WalletService, cfg *clientTypes.Config, start, count uint32,
) ([]string, error) {
	netParams := toBitcoinNetwork(cfg.Network)
	addrs := make([]string, 0, count)
	for i := uint32(0); i < count; i++ {
		keyID := fmt.Sprintf("m/0/%d", start+i)
		keyRef, err := w.GetKey(ctx, keyID)
		if err != nil {
			return nil, err
		}
		boardingScript := arkscript.NewDefaultVtxoScript(
			keyRef.PubKey, cfg.SignerPubKey, cfg.BoardingExitDelay,
		)
		tapKey, _, err := boardingScript.TapTree()
		if err != nil {
			return nil, err
		}
		addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &netParams)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr.EncodeAddress())
	}
	return addrs, nil
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

// queryUsedBoardingAddresses checks the explorer for any transaction history
// on each of the given boarding addresses and returns the subset that have at
// least one transaction. Returns an empty set (not an error) when no explorer
// is configured.
func (a *arkClient) queryUsedBoardingAddresses(addrs []string) (map[string]struct{}, error) {
	used := make(map[string]struct{})
	exp := a.Explorer()
	if exp == nil {
		return used, nil
	}
	for _, addr := range addrs {
		txs, err := exp.GetTxs(addr)
		if err != nil {
			return nil, err
		}
		if len(txs) > 0 {
			used[addr] = struct{}{}
		}
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
