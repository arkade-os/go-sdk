package identity

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// SignSchnorrBIP340 signs msg with the key identified by keyID, producing the exact BIP340
// signature (aux_rand = 32 zero bytes). Determinism here is a hard requirement, not a nicety:
// swap preimages are derived by hashing this signature, so the same key and message must yield
// the identical signature on every run, restore and BIP340-compliant implementation. The other
// schnorr.Sign call sites of this package use btcec's default RFC6979 nonce instead — also
// deterministic, but an implementation detail of btcec — because nothing is derived from
// their output; only this method carries the cross-implementation determinism contract.
func (s *service) SignSchnorrBIP340(
	_ context.Context, keyID string, msg [32]byte,
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
