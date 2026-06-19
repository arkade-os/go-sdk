package swap

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	arkidentity "github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

func (h *SwapHandler) storeLocalVHTLCContract(
	ctx context.Context,
	keyRef arkidentity.KeyRef,
	opts vhtlc.Opts,
) error {
	contractOpts, err := optsForLocalVHTLCOwner(opts, keyRef.PubKey)
	if err != nil {
		return err
	}

	if _, err := h.arkWallet.ContractManager().NewContract(
		ctx,
		types.ContractTypeVHTLC,
		contract.WithKeyRef(keyRef),
		contract.WithParams(&contractOpts),
	); err != nil {
		return fmt.Errorf("store local VHTLC contract: %w", err)
	}
	return nil
}

func (h *SwapHandler) ensureLocalVHTLCContractForSigning(
	ctx context.Context,
	opts vhtlc.Opts,
) error {
	scriptHex, err := vhtlcScriptHex(opts)
	if err != nil {
		return err
	}

	contracts, err := h.arkWallet.ContractManager().GetContracts(
		ctx,
		contract.WithScripts([]string{scriptHex}),
	)
	if err != nil {
		return fmt.Errorf("lookup VHTLC contract: %w", err)
	}
	for _, c := range contracts {
		if c.Type == types.ContractTypeVHTLC {
			return nil
		}
	}

	keyRef, err := h.localVHTLCKeyRefFromOpts(ctx, opts)
	if err != nil {
		return fmt.Errorf("missing local VHTLC contract for script %s: %w", scriptHex, err)
	}
	return h.storeLocalVHTLCContract(ctx, *keyRef, opts)
}

func optsForLocalVHTLCOwner(
	opts vhtlc.Opts,
	owner *btcec.PublicKey,
) (vhtlc.Opts, error) {
	if owner == nil {
		return vhtlc.Opts{}, fmt.Errorf("missing local VHTLC owner key")
	}
	if samePubKey(owner, opts.Sender) {
		opts.Sender = nil
		return opts, nil
	}
	if samePubKey(owner, opts.Receiver) {
		opts.Receiver = nil
		return opts, nil
	}
	return vhtlc.Opts{}, fmt.Errorf("wallet does not own sender or receiver key")
}

func (h *SwapHandler) localVHTLCKeyRefFromOpts(
	ctx context.Context,
	opts vhtlc.Opts,
) (*arkidentity.KeyRef, error) {
	keys, err := h.arkWallet.Identity().ListKeys(ctx)
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
	contracts, err := h.arkWallet.ContractManager().GetContracts(
		ctx, contract.WithType(types.ContractTypeVHTLC),
	)
	if err != nil {
		return nil, fmt.Errorf("lookup VHTLC contracts: %w", err)
	}
	for _, c := range contracts {
		if c.Address != address {
			continue
		}
		handler, err := h.arkWallet.ContractManager().GetHandler(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("get VHTLC handler: %w", err)
		}
		return handler.GetKeyRef(c)
	}
	return nil, fmt.Errorf("no local VHTLC contract for address %s", address)
}

func samePubKey(a, b *btcec.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	return bytes.Equal(schnorr.SerializePubKey(a), schnorr.SerializePubKey(b))
}

func (h *SwapHandler) buildLocalSenderVHTLC(
	counterpartyReceiverPubkey *btcec.PublicKey,
	preimageHash []byte,
	refundLocktime arklib.AbsoluteLocktime,
	unilateralClaimDelay, unilateralRefundDelay,
	unilateralRefundWithoutReceiverDelay arklib.RelativeLocktime,
	localSenderPubkey *btcec.PublicKey,
) (string, *vhtlc.VHTLCScript, *vhtlc.Opts, error) {
	if localSenderPubkey == nil {
		return "", nil, nil, fmt.Errorf("missing local VHTLC sender pubkey")
	}
	if counterpartyReceiverPubkey == nil {
		return "", nil, nil, fmt.Errorf("missing counterparty VHTLC receiver pubkey")
	}
	return h.buildVHTLC(
		localSenderPubkey,
		counterpartyReceiverPubkey,
		preimageHash,
		refundLocktime,
		unilateralClaimDelay,
		unilateralRefundDelay,
		unilateralRefundWithoutReceiverDelay,
	)
}

func (h *SwapHandler) buildLocalReceiverVHTLC(
	counterpartySenderPubkey *btcec.PublicKey,
	preimageHash []byte,
	refundLocktime arklib.AbsoluteLocktime,
	unilateralClaimDelay, unilateralRefundDelay,
	unilateralRefundWithoutReceiverDelay arklib.RelativeLocktime,
	localReceiverPubkey *btcec.PublicKey,
) (string, *vhtlc.VHTLCScript, *vhtlc.Opts, error) {
	if counterpartySenderPubkey == nil {
		return "", nil, nil, fmt.Errorf("missing counterparty VHTLC sender pubkey")
	}
	if localReceiverPubkey == nil {
		return "", nil, nil, fmt.Errorf("missing local VHTLC receiver pubkey")
	}
	return h.buildVHTLC(
		counterpartySenderPubkey,
		localReceiverPubkey,
		preimageHash,
		refundLocktime,
		unilateralClaimDelay,
		unilateralRefundDelay,
		unilateralRefundWithoutReceiverDelay,
	)
}

func (h *SwapHandler) buildVHTLC(
	senderPubkey, receiverPubkey *btcec.PublicKey,
	preimageHash []byte,
	refundLocktime arklib.AbsoluteLocktime,
	unilateralClaimDelay, unilateralRefundDelay,
	unilateralRefundWithoutReceiverDelay arklib.RelativeLocktime,
) (string, *vhtlc.VHTLCScript, *vhtlc.Opts, error) {
	if senderPubkey == nil {
		return "", nil, nil, fmt.Errorf("missing VHTLC sender pubkey")
	}
	if receiverPubkey == nil {
		return "", nil, nil, fmt.Errorf("missing VHTLC receiver pubkey")
	}

	opts := vhtlc.Opts{
		Sender:                               senderPubkey,
		Receiver:                             receiverPubkey,
		Server:                               h.config.SignerPubKey,
		PreimageHash:                         preimageHash,
		RefundLocktime:                       refundLocktime,
		UnilateralClaimDelay:                 unilateralClaimDelay,
		UnilateralRefundDelay:                unilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: unilateralRefundWithoutReceiverDelay,
	}

	vHTLC, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	if err != nil {
		return "", nil, nil, err
	}

	encodedAddr, err := vHTLC.Address(h.config.Network.Addr)
	if err != nil {
		return "", nil, nil, err
	}

	return encodedAddr, vHTLC, &opts, nil
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
