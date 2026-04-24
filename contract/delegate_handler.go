package contract

import (
	"context"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// DelegateHandler derives an offchain Ark VTXO contract that adds a 3-of-3 delegate
// spending path alongside the standard forfeit and unilateral-exit paths.
//
// Tapscript leaf order:
//
//	[0] exit:     CSVMultisigClosure{[owner], UnilateralExitDelay}
//	[1] forfeit:  MultisigClosure{[owner, server]}
//	[2] delegate: MultisigClosure{[owner, delegate, server]}
type DelegateHandler struct{}

// DeriveContract derives the delegate VTXO contract. Only an offchain contract is
// produced; no boarding or onchain facets are derived for delegate contracts.
//
// Closure ordering is load-bearing: the arkd client-lib uses forfeitClosures[0]
// to build forfeit transactions, and ForfeitClosures() matches all *MultisigClosure
// values regardless of key count. The 2-of-2 forfeit MUST remain at index [1] so
// it is picked ahead of the 3-of-3 delegate at index [2]. Do not reorder.
func (h *DelegateHandler) DeriveContract(
	_ context.Context,
	key wallet.KeyRef,
	cfg *clientTypes.Config,
	delegateKey *btcec.PublicKey,
) (*Contract, error) {
	if delegateKey == nil {
		return nil, fmt.Errorf("delegate key must not be nil")
	}
	if delegateKey.IsEqual(key.PubKey) {
		return nil, fmt.Errorf("delegate key must differ from owner key")
	}
	if delegateKey.IsEqual(cfg.SignerPubKey) {
		return nil, fmt.Errorf("delegate key must differ from signer key")
	}

	signerKeyHex := hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerPubKey))

	vtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			// [0] exit: owner unilateral after CSV timelock
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{key.PubKey},
				},
				Locktime: cfg.UnilateralExitDelay,
			},
			// [1] forfeit: owner + server cooperative, no delay
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, cfg.SignerPubKey},
			},
			// [2] delegate: owner + delegate + server 3-of-3, no delay
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{key.PubKey, delegateKey, cfg.SignerPubKey},
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

	return &Contract{
		Type: TypeDelegate,
		Params: map[string]string{
			ParamKeyID:       key.Id,
			ParamSignerKey:   signerKeyHex,
			ParamDelegateKey: hex.EncodeToString(delegateKey.SerializeCompressed()),
			ParamTapscripts:  serializeTapscripts(tapscripts),
			ParamExitDelay:   serializeDelay(cfg.UnilateralExitDelay),
		},
		Script:    hex.EncodeToString(pkScript),
		Address:   encodedArkAddr,
		IsOnchain: false,
		State:     StateActive,
	}, nil
}

// SelectPath returns the forfeit leaf (2-of-2) for a standard collaborative spend,
// the delegate leaf (3-of-3) when pctx.UseDelegatePath is set, or the exit leaf
// for a unilateral spend.
func (h *DelegateHandler) SelectPath(
	_ context.Context, c *Contract, pctx PathContext,
) (*PathSelection, error) {
	tapscripts := c.GetTapscripts()
	if len(tapscripts) < 3 {
		return nil, fmt.Errorf("delegate contract requires 3 tapscripts, got %d", len(tapscripts))
	}
	if pctx.Collaborative {
		if pctx.UseDelegatePath {
			return tapLeafSelection(tapscripts[2], nil, nil)
		}
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

// GetSpendablePaths returns exit always; forfeit and delegate when collaborative.
func (h *DelegateHandler) GetSpendablePaths(
	_ context.Context, c *Contract, pctx PathContext,
) ([]PathSelection, error) {
	tapscripts := c.GetTapscripts()
	if len(tapscripts) < 3 {
		return nil, fmt.Errorf("delegate contract requires 3 tapscripts, got %d", len(tapscripts))
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
		delegate, err := tapLeafSelection(tapscripts[2], nil, nil)
		if err != nil {
			return nil, err
		}
		paths = append(paths, *forfeit, *delegate)
	}
	return paths, nil
}
