package swap

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	arkidentity "github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract"
	vhtlcHandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

func (h *SwapHandler) newLocalVHTLCKey(ctx context.Context) (*arkidentity.KeyRef, error) {
	keyRef, err := h.arkClient.Identity().NewKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("derive local VHTLC key: %w", err)
	}
	if keyRef == nil || keyRef.PubKey == nil || keyRef.Id == "" {
		return nil, fmt.Errorf("derive local VHTLC key: invalid key ref")
	}
	return keyRef, nil
}

func (h *SwapHandler) ensureLocalVHTLCContract(
	ctx context.Context, opts vhtlc.Opts,
) (*arkidentity.KeyRef, error) {
	scriptHex, err := vhtlcScriptHex(opts)
	if err != nil {
		return nil, err
	}

	contracts, err := h.arkClient.ContractManager().GetContracts(
		ctx, contract.WithScripts([]string{scriptHex}),
	)
	if err != nil {
		return nil, fmt.Errorf("lookup VHTLC contract: %w", err)
	}
	for _, c := range contracts {
		if c.Type != types.ContractTypeVHTLC {
			continue
		}
		handler, err := h.arkClient.ContractManager().GetHandler(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("get VHTLC handler: %w", err)
		}
		return handler.GetKeyRef(c)
	}

	keyRef, err := h.findLocalVHTLCKey(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("missing local VHTLC contract for script %s: %w", scriptHex, err)
	}
	if err := h.storeLocalVHTLCContract(ctx, *keyRef, opts, scriptHex); err != nil {
		return nil, err
	}
	return keyRef, nil
}

func (h *SwapHandler) storeLocalVHTLCContract(
	ctx context.Context,
	keyRef arkidentity.KeyRef,
	opts vhtlc.Opts,
	expectedScript string,
) error {
	if expectedScript == "" {
		var err error
		expectedScript, err = vhtlcScriptHex(opts)
		if err != nil {
			return err
		}
	}

	handler := vhtlcHandler.NewHandler(h.arkClient.Client(), h.config.Network)
	built, err := handler.NewContract(ctx, keyRef, &opts)
	if err != nil {
		return fmt.Errorf("build local VHTLC contract: %w", err)
	}
	if built.Script != expectedScript {
		return fmt.Errorf(
			"local VHTLC contract script mismatch: expected %s, got %s",
			expectedScript,
			built.Script,
		)
	}
	keyIndex, err := h.arkClient.Identity().GetKeyIndex(ctx, keyRef.Id)
	if err != nil {
		return fmt.Errorf("get VHTLC key index: %w", err)
	}
	if err := h.arkClient.Store().ContractStore().AddContract(ctx, *built, keyIndex); err != nil {
		return fmt.Errorf("store local VHTLC contract: %w", err)
	}
	return nil
}

func (h *SwapHandler) findLocalVHTLCKey(
	ctx context.Context, opts vhtlc.Opts,
) (*arkidentity.KeyRef, error) {
	keys, err := h.arkClient.Identity().ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list wallet keys: %w", err)
	}

	for _, key := range keys {
		if key.PubKey == nil {
			continue
		}
		if samePubKey(key.PubKey, opts.Sender) || samePubKey(key.PubKey, opts.Receiver) {
			k := key
			return &k, nil
		}
	}
	return nil, fmt.Errorf("wallet does not own sender or receiver key")
}

func (h *SwapHandler) localVHTLCKeyForAddress(
	ctx context.Context, address string,
) (*arkidentity.KeyRef, error) {
	contracts, err := h.arkClient.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeVHTLC),
	)
	if err != nil {
		return nil, fmt.Errorf("lookup VHTLC contracts: %w", err)
	}
	for _, c := range contracts {
		if c.Address != address {
			continue
		}
		handler, err := h.arkClient.ContractManager().GetHandler(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("get VHTLC handler: %w", err)
		}
		return handler.GetKeyRef(c)
	}
	return nil, fmt.Errorf("no local VHTLC contract for address %s", address)
}

func vhtlcScriptHex(opts vhtlc.Opts) (string, error) {
	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return "", fmt.Errorf("build VHTLC script: %w", err)
	}
	tapKey, _, err := vhtlcScript.TapTree()
	if err != nil {
		return "", fmt.Errorf("compute VHTLC tap tree: %w", err)
	}
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	if err != nil {
		return "", fmt.Errorf("compute VHTLC pkScript: %w", err)
	}
	return hex.EncodeToString(pkScript), nil
}

func samePubKey(a, b *btcec.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}
