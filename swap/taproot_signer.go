package swap

import (
	"context"
	"fmt"

	sdkidentity "github.com/arkade-os/go-sdk/identity"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func (h *SwapHandler) requireKeyedTaprootSigner() (sdkidentity.KeyedTaprootSigner, error) {
	signer, ok := h.arkWallet.Identity().(sdkidentity.KeyedTaprootSigner)
	if !ok {
		return nil, fmt.Errorf("wallet identity does not support keyed taproot signing")
	}
	return signer, nil
}

func (h *SwapHandler) newMuSig2Session(
	ctx context.Context,
	keyID string,
	counterpartyPubKey *btcec.PublicKey,
) (sdkidentity.MuSig2Session, error) {
	signer, err := h.requireKeyedTaprootSigner()
	if err != nil {
		return nil, err
	}
	return signer.NewMuSig2Session(ctx, keyID, counterpartyPubKey)
}

func (h *SwapHandler) signSchnorr(
	ctx context.Context,
	keyID string,
	msg [32]byte,
) (*schnorr.Signature, error) {
	signer, err := h.requireKeyedTaprootSigner()
	if err != nil {
		return nil, err
	}
	return signer.SignSchnorr(ctx, keyID, msg)
}
