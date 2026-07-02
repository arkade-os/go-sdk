package swap

import (
	"fmt"

	sdkidentity "github.com/arkade-os/go-sdk/identity"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

func (h *SwapHandler) requirePreimageSigner() (sdkidentity.KeyedPreimageSigner, error) {
	signer, ok := h.arkWallet.Identity().(sdkidentity.KeyedPreimageSigner)
	if !ok {
		return nil, fmt.Errorf("wallet identity does not support deterministic preimage signing")
	}
	return signer, nil
}

func signLocalSchnorr(
	key *btcec.PrivateKey,
	msg [32]byte,
) (*schnorr.Signature, error) {
	if key == nil {
		return nil, fmt.Errorf("missing local HTLC private key")
	}
	return schnorr.Sign(key, msg[:])
}

func newLocalMuSig2Session(
	key *btcec.PrivateKey,
	counterpartyPubKey *btcec.PublicKey,
) (*localMuSig2Session, error) {
	if key == nil {
		return nil, fmt.Errorf("missing local HTLC private key")
	}
	if counterpartyPubKey == nil {
		return nil, fmt.Errorf("counterparty public key is required")
	}
	return &localMuSig2Session{
		key:                key,
		counterpartyPubKey: counterpartyPubKey,
	}, nil
}

type localMuSig2Session struct {
	key                *btcec.PrivateKey
	counterpartyPubKey *btcec.PublicKey
	ourNonces          *musig2.Nonces
}

func (s *localMuSig2Session) Keys() []*btcec.PublicKey {
	return []*btcec.PublicKey{s.counterpartyPubKey, s.key.PubKey()}
}

func (s *localMuSig2Session) GenerateNonce() ([66]byte, error) {
	nonces, err := musig2.GenNonces(musig2.WithPublicKey(s.key.PubKey()))
	if err != nil {
		return [66]byte{}, fmt.Errorf("musig2.GenNonces: %w", err)
	}
	s.ourNonces = nonces
	return nonces.PubNonce, nil
}

func (s *localMuSig2Session) AggregateNonces(
	counterpartyNonce [66]byte,
) ([66]byte, error) {
	if s.ourNonces == nil {
		return [66]byte{}, fmt.Errorf("nonce not generated")
	}
	combined, err := musig2.AggregateNonces([][66]byte{
		s.ourNonces.PubNonce,
		counterpartyNonce,
	})
	if err != nil {
		return [66]byte{}, fmt.Errorf("musig2.AggregateNonces: %w", err)
	}
	return combined, nil
}

func (s *localMuSig2Session) PartialSign(
	combinedNonce [66]byte,
	msg [32]byte,
	merkleRoot []byte,
) (*musig2.PartialSignature, error) {
	if s.ourNonces == nil {
		return nil, fmt.Errorf("nonce not generated")
	}
	if len(merkleRoot) != 32 {
		return nil, fmt.Errorf("invalid merkle root length: got %d want 32", len(merkleRoot))
	}
	partialSig, err := musig2.Sign(
		s.ourNonces.SecNonce,
		s.key,
		combinedNonce,
		s.Keys(),
		msg,
		musig2.WithTaprootSignTweak(merkleRoot),
		musig2.WithFastSign(),
	)
	if err != nil {
		return nil, fmt.Errorf("musig2.Sign: %w", err)
	}
	return partialSig, nil
}
