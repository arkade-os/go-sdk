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
	var auxRand [32]byte
	return schnorr.Sign(privKey, msg[:], schnorr.CustomNonce(auxRand))
}
