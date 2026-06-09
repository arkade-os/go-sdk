package swap

import (
	"context"
	"fmt"

	arkidentity "github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract"
	htlcHandler "github.com/arkade-os/go-sdk/contract/handlers/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/types"
)

func (h *SwapHandler) newLocalHTLCKey(ctx context.Context) (*arkidentity.KeyRef, error) {
	keyRef, err := h.arkClient.Identity().NewKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("create local HTLC key: %w", err)
	}
	return keyRef, nil
}

func (h *SwapHandler) ensureLocalHTLCContract(
	ctx context.Context,
	expectedAddress string,
	serverPubKeyHex string,
	swapTree boltz.SwapTree,
) (*arkidentity.KeyRef, error) {
	if expectedAddress == "" {
		return nil, fmt.Errorf("missing HTLC address")
	}

	opts, err := newHTLCOpts(serverPubKeyHex, swapTree)
	if err != nil {
		return nil, err
	}

	keyRef, err := h.localHTLCContractKeyRef(ctx, expectedAddress)
	if err != nil {
		return nil, err
	}
	if keyRef != nil {
		return keyRef, nil
	}

	keys, err := h.arkClient.Identity().ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list wallet keys: %w", err)
	}
	for _, key := range keys {
		built, err := h.buildLocalHTLCContract(ctx, key, *opts)
		if err != nil || built.Address != expectedAddress {
			continue
		}
		if err := h.storeBuiltLocalHTLCContract(ctx, *built, key); err != nil {
			return nil, err
		}
		k := key
		return &k, nil
	}

	return nil, fmt.Errorf(
		"missing local HTLC contract for %s: wallet does not own a matching key",
		expectedAddress,
	)
}

func (h *SwapHandler) localHTLCContractKeyRef(
	ctx context.Context,
	expectedAddress string,
) (*arkidentity.KeyRef, error) {
	contracts, err := h.arkClient.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeHTLC),
	)
	if err != nil {
		return nil, fmt.Errorf("lookup HTLC contracts: %w", err)
	}
	for _, c := range contracts {
		if c.Address != expectedAddress {
			continue
		}
		handler, err := h.arkClient.ContractManager().GetHandler(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("get HTLC handler: %w", err)
		}
		keyRef, err := handler.GetKeyRef(c)
		if err != nil {
			return nil, fmt.Errorf("get HTLC key ref: %w", err)
		}
		return keyRef, nil
	}
	return nil, nil
}

func (h *SwapHandler) storeLocalHTLCContract(
	ctx context.Context,
	keyRef arkidentity.KeyRef,
	opts htlcHandler.Opts,
	expectedAddress string,
) error {
	built, err := h.buildLocalHTLCContract(ctx, keyRef, opts)
	if err != nil {
		return err
	}
	if built.Address != expectedAddress {
		return fmt.Errorf(
			"local HTLC contract address mismatch: expected %s, got %s",
			expectedAddress,
			built.Address,
		)
	}
	return h.storeBuiltLocalHTLCContract(ctx, *built, keyRef)
}

func (h *SwapHandler) buildLocalHTLCContract(
	ctx context.Context,
	keyRef arkidentity.KeyRef,
	opts htlcHandler.Opts,
) (*types.Contract, error) {
	handler := htlcHandler.NewHandler(h.config.Network)
	built, err := handler.NewContract(ctx, keyRef, &opts)
	if err != nil {
		return nil, fmt.Errorf("build local HTLC contract: %w", err)
	}
	return built, nil
}

func (h *SwapHandler) storeBuiltLocalHTLCContract(
	ctx context.Context,
	built types.Contract,
	keyRef arkidentity.KeyRef,
) error {
	existing, err := h.arkClient.Store().ContractStore().GetContractsByScripts(
		ctx, []string{built.Script},
	)
	if err != nil {
		return fmt.Errorf("lookup local HTLC contract: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	keyIndex, err := h.arkClient.Identity().GetKeyIndex(ctx, keyRef.Id)
	if err != nil {
		return fmt.Errorf("get HTLC key index: %w", err)
	}
	if err := h.arkClient.Store().ContractStore().AddContract(ctx, built, keyIndex); err != nil {
		return fmt.Errorf("store local HTLC contract: %w", err)
	}
	return nil
}

func newHTLCOpts(
	serverPubKeyHex string,
	swapTree boltz.SwapTree,
) (*htlcHandler.Opts, error) {
	if err := validateSwapTree(swapTree); err != nil {
		return nil, fmt.Errorf("invalid HTLC swap tree: %w", err)
	}

	serverPubKey, err := parsePubkey(serverPubKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid HTLC server pubkey: %w", err)
	}

	return &htlcHandler.Opts{
		Server: serverPubKey,
		ClaimLeaf: htlcHandler.Leaf{
			Output: swapTree.ClaimLeaf.Output,
		},
		RefundLeaf: htlcHandler.Leaf{
			Output: swapTree.RefundLeaf.Output,
		},
	}, nil
}
