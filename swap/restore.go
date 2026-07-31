package swap

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/lightningnetwork/lnd/input"

	log "github.com/sirupsen/logrus"
)

// restoreGapLimit is the number of consecutive unused keys Boltz scans when restoring swaps
// from our xpub, mirroring its own default.
const restoreGapLimit = 50

// restoreSwaps rebuilds the swaps known to Boltz when the local store is empty, ie. after a
// wallet restore. It asks Boltz for all the swaps associated with our keys, re-imports their
// vhtlc contracts and persists them with the right data and status, so that recoverPendingSwaps
// can then claim or refund whatever is left in flight.
func (h *SwapManager) restoreSwaps(ctx context.Context) {
	existing, err := h.store.Swaps().List(ctx)
	if err != nil {
		log.WithError(err).Error("swap restore: failed to list swaps")
		return
	}
	// Restore only makes sense on an empty store: any local data means we never lost it.
	// This also makes a double import impossible: the first restored record makes the store
	// non-empty, so a later startup can never re-import on top of restored data.
	if len(existing) > 0 {
		return
	}

	// An empty swap store alone doesn't mean a wallet restore: it's also the very first
	// startup of a brand new wallet. The wallet is unlocked (and so has already restored its
	// own contracts) by the time the manager is created, so an empty contract store confirms
	// the first startup, where there's nothing to restore and no reason to disclose our xpub
	// to Boltz.
	contracts, err := h.wallet.Store().ContractStore().ListContracts(ctx)
	if err != nil {
		log.WithError(err).Error("swap restore: failed to list wallet contracts")
		return
	}
	if len(contracts) <= 0 {
		return
	}

	request, err := h.restoreRequest(ctx)
	if err != nil {
		log.WithError(err).Error("swap restore: failed to build restore request")
		return
	}

	restorable, err := h.boltzSvc.RestoreSwaps(*request)
	if err != nil {
		log.WithError(err).Error("swap restore: failed to fetch swaps from boltz")
		return
	}

	for _, restored := range restorable {
		if err := h.restoreSwap(ctx, restored); err != nil {
			log.WithError(err).Warnf("swap restore: failed to restore swap %s", restored.Id)
			continue
		}
		log.Debugf("swap restore: restored %s swap %s", restored.Type, restored.Id)
	}
}

// restoreRequest identifies our keys to Boltz: the account xpub for HD identities, so that
// Boltz can derive our per-swap keys itself and report their derivation index, or the single
// public key otherwise.
func (h *SwapManager) restoreRequest(ctx context.Context) (*boltz.RestoreSwapsRequest, error) {
	keyProvider := h.wallet.Identity()

	if keyProvider.GetType() == identity.SingleKeyIdentity {
		keyId, err := keyProvider.NextKeyId(ctx, "")
		if err != nil {
			return nil, err
		}
		keyRef, err := keyProvider.GetKey(ctx, keyId)
		if err != nil {
			return nil, err
		}
		return &boltz.RestoreSwapsRequest{
			PublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		}, nil
	}

	xpub, err := keyProvider.GetXpub(ctx)
	if err != nil {
		return nil, err
	}
	// The xpub is the external chain node (account/0), our keys are its direct children: the
	// derivation path relative to it is empty.
	return &boltz.RestoreSwapsRequest{
		Xpub:           xpub,
		DerivationPath: "m",
		GapLimit:       restoreGapLimit,
	}, nil
}

// restoreSwap re-imports the vhtlc contract of the given restored swap and persists the swap.
// Swaps already terminated on Boltz are persisted as successful, everything else is left
// pending for the recovery to drive to its terminal state.
func (h *SwapManager) restoreSwap(ctx context.Context, restored boltz.Swap) error {
	var details *boltz.SwapDetails
	weAreSender := true
	switch restored.Type {
	case SwapTypeSubmarine:
		details = restored.RefundDetails
	case SwapTypeReverse:
		details = restored.ClaimDetails
		weAreSender = false
	case SwapTypeChain:
		// Only Arkade -> BTC chain swaps are supported: we funded the vhtlc and can refund it.
		// The BTC side is claimed with an ephemeral key that can't be restored from the seed.
		if restored.From != boltz.CurrencyArk {
			return fmt.Errorf(
				"unsupported chain swap direction: %s -> %s", restored.From, restored.To,
			)
		}
		details = restored.RefundDetails
	default:
		return fmt.Errorf("unknown swap type %s", restored.Type)
	}

	if details == nil {
		return fmt.Errorf("missing swap details")
	}
	if details.TimeoutBlockHeight == 0 {
		return fmt.Errorf("missing vhtlc timeouts in swap details")
	}

	contractScript, err := h.restoreVhtlcContract(ctx, restored, details, weAreSender)
	if err != nil {
		return err
	}

	status := SwapStatusPending
	switch boltz.ParseEvent(restored.Status) {
	case boltz.TransactionClaimed, boltz.InvoiceSettled:
		status = SwapStatusSuccess
	case boltz.SwapExpired, boltz.TransactionFailed, boltz.InvoiceFailedToPay,
		boltz.TransactionLockupFailed:
		// The swap failed: if we funded the vhtlc it must be refunded, not claimed. Persisting it
		// as failed routes it to the refund path in recoverPendingSwaps instead of leaving it
		// pending, where recovery would depend on Boltz still reporting an actionable status.
		status = SwapStatusFailed
	}

	preimageHash, err := restoredPreimageHash(restored, details)
	if err != nil {
		return err
	}

	swap := swaptypes.Swap{
		Id:          restored.Id,
		From:        restored.From,
		To:          restored.To,
		CreatedAt:   time.Unix(int64(restored.CreatedAt), 0),
		Status:      int(status),
		VHTLCScript: contractScript,
		Amount:      details.Amount,
	}
	if restored.Type == SwapTypeChain {
		// The BTC-side data of the restored chain swap, if any. The ephemeral claim key and
		// the destination address are lost, so the swap can only be refunded, never claimed.
		swap.ChainSwap = &swaptypes.ChainSwapInfo{}
		if restored.ClaimDetails != nil {
			swap.ChainSwap.Address = restored.ClaimDetails.LockupAddress
			swap.ChainSwap.ServerPublicKey = restored.ClaimDetails.ServerPublicKey
			swap.ChainSwap.RefundLocktime = restored.ClaimDetails.TimeoutBlockHeight
		}
	} else {
		swap.LNSwap = &swaptypes.LNSwapInfo{
			Invoice:      restored.Invoice,
			PreimageHash: preimageHash,
		}
	}

	return h.persistSwap(ctx, swap)
}

// restoreVhtlcContract rebuilds the vhtlc contract of a restored swap from its details and our
// key at the reported derivation index, and imports it into the contract manager. The rebuilt
// address must match the lockup address Boltz reports.
func (h *SwapManager) restoreVhtlcContract(
	ctx context.Context, restored boltz.Swap, details *boltz.SwapDetails, weAreSender bool,
) (string, error) {
	keyProvider := h.wallet.Identity()
	contractManager := h.wallet.ContractManager()
	handler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	if err != nil {
		return "", err
	}

	keyId := fmt.Sprintf("m/0/%d", details.KeyIndex)
	if keyProvider.GetType() == identity.SingleKeyIdentity {
		if keyId, err = keyProvider.NextKeyId(ctx, ""); err != nil {
			return "", err
		}
	}
	keyRef, err := keyProvider.GetKey(ctx, keyId)
	if err != nil {
		return "", fmt.Errorf("failed to get key %s: %w", keyId, err)
	}

	serverPubkey, err := parsePubkey(details.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid server pubkey: %w", err)
	}

	preimageHash, err := restoredPreimageHash(restored, details)
	if err != nil {
		return "", err
	}

	vhtlcScript, err := vhtlc.NewVhtlcScript(
		hex.EncodeToString(preimageHash), details.Tree.ClaimLeaf.Output,
		details.Tree.RefundLeaf.Output, details.Tree.RefundLeafWithoutReceiver.Output,
		details.Tree.UnilateralClaimLeaf.Output, details.Tree.UnilateralRefundLeaf.Output,
		details.Tree.UnilateralRefundWithoutReceiver.Output,
	)
	if err != nil {
		return "", err
	}
	vhtlcOpts := vhtlcScript.Opts()

	contractArgs := vhtlchandler.ContractArgs{
		Signer:                               vhtlcOpts.Server,
		PreimageHash:                         preimageHash,
		RefundLocktime:                       vhtlcOpts.RefundLocktime,
		UnilateralClaimDelay:                 vhtlcOpts.UnilateralClaimDelay,
		UnilateralRefundDelay:                vhtlcOpts.UnilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: vhtlcOpts.UnilateralRefundWithoutReceiverDelay,
	}
	if weAreSender {
		contractArgs.SenderKeyId = keyRef.Id
		contractArgs.Sender = keyRef.PubKey
		contractArgs.Receiver = serverPubkey
	} else {
		contractArgs.ReceiverKeyId = keyRef.Id
		contractArgs.Receiver = keyRef.PubKey
		contractArgs.Sender = serverPubkey
	}

	vhtlcContract, err := handler.NewContract(ctx, contractArgs)
	if err != nil {
		return "", fmt.Errorf("failed to rebuild vhtlc contract: %w", err)
	}
	if vhtlcContract.Address != details.LockupAddress {
		return "", fmt.Errorf(
			"vhtlc address mismatch: rebuilt %s, got %s from boltz",
			vhtlcContract.Address, details.LockupAddress,
		)
	}

	// The contract may be tracked already, eg. when a previous restore run failed halfway.
	tracked, err := contractManager.GetContracts(
		ctx, contract.WithScripts([]string{vhtlcContract.Script}),
	)
	if err != nil {
		return "", err
	}
	if len(tracked) > 0 {
		return vhtlcContract.Script, nil
	}

	if err := contractManager.ImportContract(ctx, *vhtlcContract); err != nil {
		return "", err
	}
	return vhtlcContract.Script, nil
}

// restoredPreimageHash returns the HASH160 the vhtlc locks on, computed from the SHA256
// preimage hash Boltz reports.
func restoredPreimageHash(restored boltz.Swap, details *boltz.SwapDetails) ([]byte, error) {
	preimageHashHex := details.PreimageHash
	if preimageHashHex == "" {
		preimageHashHex = restored.PreimageHash
	}
	if preimageHashHex == "" {
		return nil, fmt.Errorf("missing preimage hash")
	}

	sha256Hash, err := hex.DecodeString(preimageHashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid preimage hash: %w", err)
	}
	return input.Ripemd160H(sha256Hash), nil
}
