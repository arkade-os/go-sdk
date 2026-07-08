package swap

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func (h *SwapHandler) ensureLocalHTLCKey(
	ctx context.Context,
	expectedAddress string,
	serverPubKeyHex string,
	swapTree boltz.SwapTree,
) (*btcec.PrivateKey, error) {
	if expectedAddress == "" {
		return nil, fmt.Errorf("missing HTLC address")
	}

	if _, err := newHTLCOpts(serverPubKeyHex, swapTree); err != nil {
		return nil, err
	}

	key, err := h.localHTLCKeyForAddress(ctx, expectedAddress)
	if err != nil {
		return nil, err
	}
	if key != nil {
		if err := validateBtcLockupAddress(
			networkNameToParams(h.config.Network.Name),
			expectedAddress,
			serverPubKeyHex,
			key.PubKey(),
			swapTree,
		); err != nil {
			return nil, fmt.Errorf("local HTLC key does not match lockup address: %w", err)
		}
		return key, nil
	}

	return nil, fmt.Errorf(
		"missing local HTLC key for %s: ephemeral key is not available",
		expectedAddress,
	)
}

func (h *SwapHandler) localHTLCKeyForAddress(
	ctx context.Context,
	expectedAddress string,
) (*btcec.PrivateKey, error) {
	h.htlcMu.RLock()
	key, ok := h.htlcKeysByAddress[expectedAddress]
	if !ok {
		h.htlcMu.RUnlock()
		return h.persistedHTLCKeyForAddress(ctx, expectedAddress)
	}
	h.htlcMu.RUnlock()

	return key, nil
}

func (h *SwapHandler) persistedHTLCKeyForAddress(
	ctx context.Context,
	expectedAddress string,
) (*btcec.PrivateKey, error) {
	store := h.htlcKeyStore()
	if store == nil {
		return nil, nil
	}

	record, err := store.Get(ctx, expectedAddress)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("load HTLC key for %s: %w", expectedAddress, err)
	}

	keyBytes, err := hex.DecodeString(record.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode persisted HTLC key for %s: %w", expectedAddress, err)
	}
	key, _ := btcec.PrivKeyFromBytes(keyBytes)

	h.htlcMu.Lock()
	h.htlcKeysByAddress[expectedAddress] = key
	h.htlcMu.Unlock()

	return key, nil
}

func (h *SwapHandler) storeLocalHTLCKey(
	ctx context.Context,
	address string,
	key *btcec.PrivateKey,
) error {
	if address == "" {
		return fmt.Errorf("missing HTLC address")
	}
	if key == nil {
		return fmt.Errorf("missing HTLC key")
	}
	if store := h.htlcKeyStore(); store != nil {
		if err := store.Add(ctx, HTLCKeyRecord{
			Address:       address,
			PrivateKeyHex: hex.EncodeToString(key.Serialize()),
			CreatedAt:     time.Now().Unix(),
		}); err != nil {
			return fmt.Errorf("persist HTLC key for %s: %w", address, err)
		}
	}

	h.htlcMu.Lock()
	defer h.htlcMu.Unlock()

	h.htlcKeysByAddress[address] = key
	return nil
}

func (h *SwapHandler) htlcKeyStore() HTLCKeyRepository {
	if h == nil || h.store == nil {
		return nil
	}
	return h.store.HTLCKeys()
}

func newHTLCOpts(
	serverPubKeyHex string,
	swapTree boltz.SwapTree,
) (*htlc.Opts, error) {
	if err := validateSwapTree(swapTree); err != nil {
		return nil, fmt.Errorf("invalid HTLC swap tree: %w", err)
	}

	if _, err := parsePubkey(serverPubKeyHex); err != nil {
		return nil, fmt.Errorf("invalid HTLC server pubkey: %w", err)
	}

	claimComponents, err := validateClaimLeafScript(swapTree.ClaimLeaf.Output)
	if err != nil {
		return nil, fmt.Errorf("invalid HTLC claim leaf: %w", err)
	}
	claimKey, err := schnorr.ParsePubKey(claimComponents.ClaimPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("invalid HTLC claim pubkey: %w", err)
	}

	refundComponents, err := ValidateRefundLeafScript(swapTree.RefundLeaf.Output)
	if err != nil {
		return nil, fmt.Errorf("invalid HTLC refund leaf: %w", err)
	}
	refundKey, err := schnorr.ParsePubKey(refundComponents.RefundPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("invalid HTLC refund pubkey: %w", err)
	}

	opts := &htlc.Opts{
		ClaimKey:       claimKey,
		RefundKey:      refundKey,
		PreimageHash:   append([]byte(nil), claimComponents.PreimageHash[:]...),
		RefundLocktime: arklib.AbsoluteLocktime(refundComponents.Timeout),
	}
	if err := validateHTLCOptsMatchSwapTree(*opts, swapTree); err != nil {
		return nil, err
	}

	return opts, nil
}

func validateHTLCOptsMatchSwapTree(opts htlc.Opts, swapTree boltz.SwapTree) error {
	claimScript, refundScript, err := htlc.NewHTLCLeafScriptsFromOpts(opts)
	if err != nil {
		return fmt.Errorf("rebuild HTLC leaves from opts: %w", err)
	}
	if got := hex.EncodeToString(claimScript); !strings.EqualFold(got, swapTree.ClaimLeaf.Output) {
		return fmt.Errorf("rebuilt HTLC claim leaf mismatch")
	}
	if got := hex.EncodeToString(
		refundScript,
	); !strings.EqualFold(
		got,
		swapTree.RefundLeaf.Output,
	) {
		return fmt.Errorf("rebuilt HTLC refund leaf mismatch")
	}

	return nil
}
