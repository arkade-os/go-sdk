package swap

import (
	"encoding/hex"
	"fmt"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func (h *SwapHandler) ensureLocalHTLCKey(
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

	if key := h.localHTLCKeyForAddress(expectedAddress); key != nil {
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
	expectedAddress string,
) *btcec.PrivateKey {
	h.htlcMu.RLock()
	defer h.htlcMu.RUnlock()

	key, ok := h.htlcKeysByAddress[expectedAddress]
	if !ok {
		return nil
	}
	return key
}

func (h *SwapHandler) storeLocalHTLCKey(
	address string,
	key *btcec.PrivateKey,
) {
	h.htlcMu.Lock()
	defer h.htlcMu.Unlock()

	h.htlcKeysByAddress[address] = key
}

func newHTLCPrivateKey() (*btcec.PrivateKey, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate HTLC key: %w", err)
	}
	return privateKey, nil
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
