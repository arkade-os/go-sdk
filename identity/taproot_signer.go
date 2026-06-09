package identity

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

// KeyedTaprootSigner signs taproot messages with a specific wallet key.
type KeyedTaprootSigner interface {
	SignSchnorr(ctx context.Context, keyID string, msg [32]byte) (*schnorr.Signature, error)
	NewMuSig2Session(
		ctx context.Context,
		keyID string,
		counterpartyPubKey *btcec.PublicKey,
	) (MuSig2Session, error)
}

type MuSig2Session interface {
	Keys() []*btcec.PublicKey
	GenerateNonce() ([66]byte, error)
	AggregateNonces(counterpartyNonce [66]byte) ([66]byte, error)
	PartialSign(
		ctx context.Context,
		combinedNonce [66]byte,
		msg [32]byte,
		merkleRoot []byte,
	) (*musig2.PartialSignature, error)
}

func (s *service) SignSchnorr(
	_ context.Context,
	keyID string,
	msg [32]byte,
) (*schnorr.Signature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.safeCheck(); err != nil {
		return nil, err
	}
	if keyID == "" {
		return nil, fmt.Errorf("key id is required")
	}

	privKey, err := s.keyProvider.DeriveKeyAt(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key %q: %w", keyID, err)
	}
	return schnorr.Sign(privKey, msg[:])
}

func (s *service) NewMuSig2Session(
	_ context.Context,
	keyID string,
	counterpartyPubKey *btcec.PublicKey,
) (MuSig2Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.safeCheck(); err != nil {
		return nil, err
	}
	if keyID == "" {
		return nil, fmt.Errorf("key id is required")
	}
	if counterpartyPubKey == nil {
		return nil, fmt.Errorf("counterparty public key is required")
	}

	privKey, err := s.keyProvider.DeriveKeyAt(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key %q: %w", keyID, err)
	}
	return &keyedMuSig2Session{
		key:                privKey,
		counterpartyPubKey: counterpartyPubKey,
	}, nil
}

type keyedMuSig2Session struct {
	key                *btcec.PrivateKey
	counterpartyPubKey *btcec.PublicKey
	ourNonces          *musig2.Nonces
}

func (s *keyedMuSig2Session) Keys() []*btcec.PublicKey {
	return []*btcec.PublicKey{s.counterpartyPubKey, s.key.PubKey()}
}

func (s *keyedMuSig2Session) GenerateNonce() ([66]byte, error) {
	nonces, err := musig2.GenNonces(musig2.WithPublicKey(s.key.PubKey()))
	if err != nil {
		return [66]byte{}, fmt.Errorf("musig2.GenNonces: %w", err)
	}
	s.ourNonces = nonces
	return nonces.PubNonce, nil
}

func (s *keyedMuSig2Session) AggregateNonces(
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

func (s *keyedMuSig2Session) PartialSign(
	_ context.Context,
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
