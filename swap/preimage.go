package swap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const preimageTagV1 = "Arkade-Boltz-Preimage-v1"

// PreimageSigner signs deterministic swap-preimage derivation messages.
type PreimageSigner interface {
	SignSchnorrBIP340(ctx context.Context, keyID string, msg [32]byte) (*schnorr.Signature, error)
}

// DerivePreimage generates a deterministic preimage for Boltz swaps by crafting and signing a
// message with a well defined format (check BuildPreimageMessage) and signing its SHA256 hash.
// The SHA256 hash of the signature is returned as the preimage.
//
//	message_hash	= SHA256(message)
//	sig				= BIP340_SchnorrSign(local_key, message, aux_rand=0)
//	preimage 		= SHA256(sig)
func DerivePreimage(
	ctx context.Context, signer PreimageSigner, keyRef identity.KeyRef,
) (vhtlc.Preimage, error) {
	if signer == nil {
		return nil, fmt.Errorf("missing preimage signer")
	}
	if keyRef.Id == "" {
		return nil, fmt.Errorf("missing preimage key id")
	}

	// Index is always 0 for now.
	msg, err := BuildPreimageMessage(keyRef.PubKey, 0)
	if err != nil {
		return nil, err
	}
	msgHash := sha256.Sum256(msg)

	sig, err := signer.SignSchnorrBIP340(ctx, keyRef.Id, msgHash)
	if err != nil {
		return nil, fmt.Errorf("sign preimage message: %w", err)
	}

	preimage := sha256.Sum256(sig.Serialize())
	return preimage[:], nil
}

// BuildPreimageMessage creates a deterministic message that can be signed to generate a
// deterministic preimage.
//
// message = "Arkade-Boltz-Preimage-v1" || xonly_pubkey(32B) || uint32_le(index)
func BuildPreimageMessage(pubkey *btcec.PublicKey, index uint32) ([]byte, error) {
	if pubkey == nil {
		return nil, fmt.Errorf("missing preimage pubkey")
	}

	payload := make([]byte, 0, len(preimageTagV1)+32+4)
	payload = append(payload, []byte(preimageTagV1)...)
	payload = append(payload, schnorr.SerializePubKey(pubkey)...)

	var indexBytes [4]byte
	binary.LittleEndian.PutUint32(indexBytes[:], index)
	payload = append(payload, indexBytes[:]...)

	return payload, nil
}
