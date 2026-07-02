package identity

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// KeyedPreimageSigner signs deterministic swap-preimage derivation messages.
type KeyedPreimageSigner interface {
	SignSchnorrBIP340(ctx context.Context, keyID string, msg [32]byte) (*schnorr.Signature, error)
}

func (s *service) SignSchnorrBIP340(
	_ context.Context,
	keyID string,
	msg [32]byte,
) (*schnorr.Signature, error) {
	var auxRand [32]byte
	return s.signSchnorr(keyID, msg, schnorr.CustomNonce(auxRand))
}

func (s *service) signSchnorr(
	keyID string,
	msg [32]byte,
	opts ...schnorr.SignOption,
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
	return schnorr.Sign(privKey, msg[:], opts...)
}
