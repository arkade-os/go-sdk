package swap

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

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
	// Hedge the nonce randomness with the secret key and the aggregate key as BIP327
	// recommends: a weak RNG alone then can't yield a nonce that is predictable or reusable
	// against a different key set. The message can't be bound too: it isn't known yet at
	// this point of the protocol (the sighash depends on the counterparty's nonce).
	combined, _, _, err := musig2.AggregateKeys(s.Keys(), false)
	if err != nil {
		return [66]byte{}, fmt.Errorf("musig2.AggregateKeys: %w", err)
	}
	nonces, err := musig2.GenNonces(
		musig2.WithPublicKey(s.key.PubKey()),
		musig2.WithNonceSecretKeyAux(s.key),
		musig2.WithNonceCombinedKeyAux(combined.FinalKey),
	)
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
	// Signing a second message with the same secret nonce leaks the private key: zero it and
	// drop the session nonce whatever the outcome, so another PartialSign on this session
	// fails with "nonce not generated" instead of reusing it.
	s.ourNonces.SecNonce = [musig2.SecNonceSize]byte{}
	s.ourNonces = nil
	if err != nil {
		return nil, fmt.Errorf("musig2.Sign: %w", err)
	}
	return partialSig, nil
}
