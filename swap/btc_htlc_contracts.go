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

	keyRef, err := h.localHTLCKeyRefForAddress(ctx, expectedAddress)
	if err != nil {
		return nil, err
	}
	if keyRef != nil {
		return keyRef, nil
	}

	keys, err := h.arkWallet.Identity().ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("list wallet keys: %w", err)
	}
	network := networkNameToParams(h.config.Network.Name)
	for _, key := range keys {
		if key.PubKey == nil {
			continue
		}
		if err := validateBtcLockupAddress(
			network, expectedAddress, serverPubKeyHex, key.PubKey, swapTree,
		); err != nil {
			continue
		}
		if err := h.storeLocalHTLCContract(ctx, key, *opts); err != nil {
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

func (h *SwapHandler) localHTLCKeyRefForAddress(
	ctx context.Context,
	expectedAddress string,
) (*arkidentity.KeyRef, error) {
	contracts, err := h.arkWallet.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeHTLC),
	)
	if err != nil {
		return nil, fmt.Errorf("lookup HTLC contracts: %w", err)
	}
	for _, c := range contracts {
		if c.Address != expectedAddress {
			continue
		}
		handler, err := h.arkWallet.ContractManager().GetHandler(ctx, c)
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
) error {
	if _, err := h.arkWallet.ContractManager().NewContract(
		ctx,
		types.ContractTypeHTLC,
		contract.WithKeyRef(keyRef),
		contract.WithParams(&opts),
	); err != nil {
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
