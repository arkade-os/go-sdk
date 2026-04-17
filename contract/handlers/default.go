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
	_ context.Context, key wallet.KeyRef, cfg *clientTypes.Config,
) (*contract.Contract, error) {
	netParams := toBitcoinNetwork(cfg.Network)

	// Offchain script uses UnilateralExitDelay.
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

	// Boarding script uses BoardingExitDelay.
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

	// Onchain address: bare key-path P2TR (no script tree).
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

func (h *DefaultHandler) SerializeParams(params any) (map[string]string, error) {
	p, ok := params.(map[string]string)
	if !ok {
		return nil, fmt.Errorf("DefaultHandler: params must be map[string]string")
	}
	return p, nil
}

func (h *DefaultHandler) DeserializeParams(params map[string]string) (any, error) {
	return params, nil
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
