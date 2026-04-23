package contract

import (
	"context"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// DefaultHandler derives the standard Ark VTXO contracts for a wallet key:
// one offchain (Arkade address, IsOnchain=false), one boarding (P2TR with
// boarding delay, IsOnchain=true), and one onchain (bare key P2TR, IsOnchain=true).
type DefaultHandler struct{}

// DeriveContracts derives all three address-type contracts for the given key.
// Each contract is self-contained: all params (tapscripts, delay, signer key)
// live in Params so no external config is needed to interpret the contract later.
func (h *DefaultHandler) DeriveContracts(
	_ context.Context,
	key wallet.KeyRef,
	cfg *clientTypes.Config,
) ([]*Contract, error) {
	netParams, err := toBitcoinNetwork(cfg.Network)
	if err != nil {
		return nil, err
	}

	signerKeyHex := hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerPubKey))

	// --- offchain VTXO contract (IsOnchain=false) ---
	offchainScript := script.NewDefaultVtxoScript(
		key.PubKey, cfg.SignerPubKey, cfg.UnilateralExitDelay,
	)
	vtxoTapKey, _, err := offchainScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("offchain tap tree: %w", err)
	}
	arkAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
		VtxoTapKey: vtxoTapKey,
	}
	encodedArkAddr, err := arkAddr.EncodeV0()
	if err != nil {
		return nil, fmt.Errorf("encode ark address: %w", err)
	}
	tapscripts, err := offchainScript.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode offchain tapscripts: %w", err)
	}
	pkScript, err := txscript.PayToTaprootScript(vtxoTapKey)
	if err != nil {
		return nil, fmt.Errorf("offchain pkScript: %w", err)
	}
	offchain := &Contract{
		Type: TypeDefault,
		Params: map[string]string{
			ParamKeyID:      key.Id,
			ParamSignerKey:  signerKeyHex,
			ParamTapscripts: serializeTapscripts(tapscripts),
			ParamExitDelay:  serializeDelay(cfg.UnilateralExitDelay),
		},
		Script:    hex.EncodeToString(pkScript),
		Address:   encodedArkAddr,
		IsOnchain: false,
		State:     StateActive,
	}

	// --- boarding contract (IsOnchain=true, has tapscripts and boarding delay) ---
	boardingScript := script.NewDefaultVtxoScript(
		key.PubKey, cfg.SignerPubKey, cfg.BoardingExitDelay,
	)
	boardingTapKey, _, err := boardingScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("boarding tap tree: %w", err)
	}
	boardingAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey), &netParams,
	)
	if err != nil {
		return nil, fmt.Errorf("boarding address: %w", err)
	}
	boardingTapscripts, err := boardingScript.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode boarding tapscripts: %w", err)
	}
	boardingPkScript, err := txscript.PayToTaprootScript(boardingTapKey)
	if err != nil {
		return nil, fmt.Errorf("boarding pkScript: %w", err)
	}
	boarding := &Contract{
		Type: TypeDefaultBoarding,
		Params: map[string]string{
			ParamKeyID:      key.Id,
			ParamSignerKey:  signerKeyHex,
			ParamTapscripts: serializeTapscripts(boardingTapscripts),
			ParamExitDelay:  serializeDelay(cfg.BoardingExitDelay),
		},
		Script:    hex.EncodeToString(boardingPkScript),
		Address:   boardingAddr.EncodeAddress(),
		IsOnchain: true,
		State:     StateActive,
	}

	// --- onchain contract (IsOnchain=true, bare key-path P2TR, no tapscripts or delay) ---
	onchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	onchainAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(onchainTapKey), &netParams,
	)
	if err != nil {
		return nil, fmt.Errorf("onchain address: %w", err)
	}
	onchainPkScript, err := txscript.PayToTaprootScript(onchainTapKey)
	if err != nil {
		return nil, fmt.Errorf("onchain pkScript: %w", err)
	}
	onchain := &Contract{
		Type: TypeDefaultOnchain,
		Params: map[string]string{
			ParamKeyID:     key.Id,
			ParamSignerKey: signerKeyHex,
		},
		Script:    hex.EncodeToString(onchainPkScript),
		Address:   onchainAddr.EncodeAddress(),
		IsOnchain: true,
		State:     StateActive,
	}

	return []*Contract{offchain, boarding, onchain}, nil
}

// SelectPath returns the appropriate tapscript leaf for the given spend context.
// Default tapscript order: [0]=exit (CSV), [1]=forfeit (multisig).
func (h *DefaultHandler) SelectPath(
	_ context.Context, c *Contract, pctx PathContext,
) (*PathSelection, error) {
	tapscripts := c.GetTapscripts()
	if len(tapscripts) < 2 {
		return nil, fmt.Errorf(
			"default contract requires at least 2 tapscripts, got %d",
			len(tapscripts),
		)
	}
	if pctx.Collaborative {
		return tapLeafSelection(tapscripts[1], nil, nil)
	}
	delay, err := c.GetDelay()
	if err != nil {
		return nil, fmt.Errorf("exit delay: %w", err)
	}
	seq, err := arklib.BIP68Sequence(delay)
	if err != nil {
		return nil, fmt.Errorf("BIP68 sequence: %w", err)
	}
	s := uint32(seq)
	return tapLeafSelection(tapscripts[0], &s, nil)
}

// GetSpendablePaths returns all leaves that can be used given the current context.
func (h *DefaultHandler) GetSpendablePaths(
	_ context.Context, c *Contract, pctx PathContext,
) ([]PathSelection, error) {
	tapscripts := c.GetTapscripts()
	if len(tapscripts) < 2 {
		return nil, fmt.Errorf(
			"default contract requires at least 2 tapscripts, got %d",
			len(tapscripts),
		)
	}
	delay, err := c.GetDelay()
	if err != nil {
		return nil, fmt.Errorf("exit delay: %w", err)
	}
	seq, err := arklib.BIP68Sequence(delay)
	if err != nil {
		return nil, fmt.Errorf("BIP68 sequence: %w", err)
	}
	s := uint32(seq)

	exit, err := tapLeafSelection(tapscripts[0], &s, nil)
	if err != nil {
		return nil, err
	}
	paths := []PathSelection{*exit}

	if pctx.Collaborative {
		forfeit, err := tapLeafSelection(tapscripts[1], nil, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *forfeit)
	}
	return paths, nil
}

// tapLeafSelection decodes a hex-encoded tapscript and builds a PathSelection.
func tapLeafSelection(
	hexScript string,
	sequence, locktime *uint32,
) (*PathSelection, error) {
	scriptBytes, err := hex.DecodeString(hexScript)
	if err != nil {
		return nil, fmt.Errorf("decode tapscript hex: %w", err)
	}
	return &PathSelection{
		Leaf:     txscript.NewBaseTapLeaf(scriptBytes),
		Sequence: sequence,
		Locktime: locktime,
	}, nil
}

func toBitcoinNetwork(net arklib.Network) (chaincfg.Params, error) {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams, nil
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params, nil
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams, nil
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams, nil
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams, nil
	default:
		return chaincfg.Params{}, fmt.Errorf("unknown network %q", net.Name)
	}
}
