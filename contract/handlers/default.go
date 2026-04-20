package handlers

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

const TypeDefault = "default"

// DefaultHandler derives the standard Ark VTXO contract:
// offchain (Arkade address) + boarding (P2TR, BoardingExitDelay) + onchain (bare key P2TR).
type DefaultHandler struct{}

func (h *DefaultHandler) Type() string { return TypeDefault }

func (h *DefaultHandler) DeriveContract(
	_ context.Context,
	key wallet.KeyRef,
	cfg *clientTypes.Config,
	_ map[string]string, // unused for the default handler
) (*contract.Contract, error) {
	netParams := toBitcoinNetwork(cfg.Network)

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
		return nil, fmt.Errorf("pkScript: %w", err)
	}

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

	onchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	onchainAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(onchainTapKey), &netParams,
	)
	if err != nil {
		return nil, fmt.Errorf("onchain address: %w", err)
	}

	return &contract.Contract{
		Type:               TypeDefault,
		Params:             map[string]string{"keyId": key.Id},
		Script:             hex.EncodeToString(pkScript),
		Address:            encodedArkAddr,
		Boarding:           boardingAddr.EncodeAddress(),
		Onchain:            onchainAddr.EncodeAddress(),
		State:              contract.StateActive,
		CreatedAt:          time.Now(),
		Tapscripts:         tapscripts,
		BoardingTapscripts: boardingTapscripts,
		Delay:              cfg.UnilateralExitDelay,
		BoardingDelay:      cfg.BoardingExitDelay,
	}, nil
}

// SelectPath returns the appropriate tapscript leaf for the given spend context.
// Default tapscript order: [0]=exit (CSV), [1]=forfeit (multisig).
func (h *DefaultHandler) SelectPath(
	_ context.Context, c *contract.Contract, pctx contract.PathContext,
) (*contract.PathSelection, error) {
	if len(c.Tapscripts) < 2 {
		return nil, fmt.Errorf("default contract requires at least 2 tapscripts, got %d", len(c.Tapscripts))
	}
	if pctx.Collaborative {
		return tapLeafSelection(c.Tapscripts[1], nil, nil)
	}
	seq, err := arklib.BIP68Sequence(c.Delay)
	if err != nil {
		return nil, fmt.Errorf("BIP68 sequence: %w", err)
	}
	s := uint32(seq)
	return tapLeafSelection(c.Tapscripts[0], &s, nil)
}

// GetSpendablePaths returns all leaves that can be used given the current context.
func (h *DefaultHandler) GetSpendablePaths(
	_ context.Context, c *contract.Contract, pctx contract.PathContext,
) ([]contract.PathSelection, error) {
	if len(c.Tapscripts) < 2 {
		return nil, fmt.Errorf("default contract requires at least 2 tapscripts, got %d", len(c.Tapscripts))
	}
	seq, err := arklib.BIP68Sequence(c.Delay)
	if err != nil {
		return nil, fmt.Errorf("BIP68 sequence: %w", err)
	}
	s := uint32(seq)

	exit, err := tapLeafSelection(c.Tapscripts[0], &s, nil)
	if err != nil {
		return nil, err
	}
	paths := []contract.PathSelection{*exit}

	if pctx.Collaborative {
		forfeit, err := tapLeafSelection(c.Tapscripts[1], nil, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *forfeit)
	}
	return paths, nil
}

func (h *DefaultHandler) SerializeParams(_ any) (map[string]string, error) {
	return nil, nil
}

func (h *DefaultHandler) DeserializeParams(_ map[string]string) (any, error) {
	return nil, nil
}

// tapLeafSelection decodes a hex-encoded tapscript and builds a PathSelection.
func tapLeafSelection(hexScript string, sequence, locktime *uint32) (*contract.PathSelection, error) {
	scriptBytes, err := hex.DecodeString(hexScript)
	if err != nil {
		return nil, fmt.Errorf("decode tapscript hex: %w", err)
	}
	return &contract.PathSelection{
		Leaf:     txscript.NewBaseTapLeaf(scriptBytes),
		Sequence: sequence,
		Locktime: locktime,
	}, nil
}

func toBitcoinNetwork(net arklib.Network) chaincfg.Params {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}
