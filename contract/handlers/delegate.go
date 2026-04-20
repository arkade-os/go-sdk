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
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const TypeDelegate = "delegate"

// DelegateHandler derives an offchain Ark contract that adds a 3-of-3 delegate
// spending path alongside the standard forfeit and unilateral-exit paths.
//
// Tapscript leaf order:
//
//	[0] exit:     CSVMultisigClosure{[owner], UnilateralExitDelay}
//	[1] forfeit:  MultisigClosure{[owner, server]}
//	[2] delegate: MultisigClosure{[owner, delegate, server]}
type DelegateHandler struct{}

func (h *DelegateHandler) Type() string { return TypeDelegate }

func (h *DelegateHandler) DeriveContract(
	_ context.Context,
	key wallet.KeyRef,
	cfg *clientTypes.Config,
	rawParams map[string]string,
) (*contract.Contract, error) {
	delegatePubKey, err := parseDelegatePubKey(rawParams)
	if err != nil {
		return nil, err
	}

	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{key.PubKey},
				},
				Locktime: cfg.UnilateralExitDelay,
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, cfg.SignerPubKey},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, delegatePubKey, cfg.SignerPubKey},
			},
		},
	}

	vtxoTapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("delegate tap tree: %w", err)
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

	tapscripts, err := vtxoScript.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode tapscripts: %w", err)
	}

	pkScript, err := txscript.PayToTaprootScript(vtxoTapKey)
	if err != nil {
		return nil, fmt.Errorf("pkScript: %w", err)
	}

	return &contract.Contract{
		Type: TypeDelegate,
		Params: map[string]string{
			"keyId":          key.Id,
			"delegatePubKey": hex.EncodeToString(schnorr.SerializePubKey(delegatePubKey)),
		},
		Script:     hex.EncodeToString(pkScript),
		Address:    encodedArkAddr,
		State:      contract.StateActive,
		CreatedAt:  time.Now(),
		Tapscripts: tapscripts,
		Delay:      cfg.UnilateralExitDelay,
	}, nil
}

// SelectPath returns the forfeit leaf when collaborative, the exit leaf otherwise.
// Delegate leaf ordering: [0]=exit, [1]=forfeit, [2]=delegate.
func (h *DelegateHandler) SelectPath(
	_ context.Context, c *contract.Contract, pctx contract.PathContext,
) (*contract.PathSelection, error) {
	if len(c.Tapscripts) < 3 {
		return nil, fmt.Errorf("delegate contract requires 3 tapscripts, got %d", len(c.Tapscripts))
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

// GetSpendablePaths returns exit always; forfeit + delegate when collaborative.
func (h *DelegateHandler) GetSpendablePaths(
	_ context.Context, c *contract.Contract, pctx contract.PathContext,
) ([]contract.PathSelection, error) {
	if len(c.Tapscripts) < 3 {
		return nil, fmt.Errorf("delegate contract requires 3 tapscripts, got %d", len(c.Tapscripts))
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
		delegate, err := tapLeafSelection(c.Tapscripts[2], nil, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *forfeit, *delegate)
	}
	return paths, nil
}

func (h *DelegateHandler) SerializeParams(params any) (map[string]string, error) {
	p, ok := params.(map[string]string)
	if !ok {
		return nil, fmt.Errorf("DelegateHandler: params must be map[string]string")
	}
	return p, nil
}

func (h *DelegateHandler) DeserializeParams(params map[string]string) (any, error) {
	return params, nil
}

func parseDelegatePubKey(rawParams map[string]string) (*btcec.PublicKey, error) {
	hexKey, ok := rawParams["delegatePubKey"]
	if !ok || hexKey == "" {
		return nil, fmt.Errorf("delegate handler: missing required param \"delegatePubKey\"")
	}
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("delegate handler: invalid delegatePubKey hex: %w", err)
	}
	pub, err := schnorr.ParsePubKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("delegate handler: invalid delegatePubKey: %w", err)
	}
	return pub, nil
}
