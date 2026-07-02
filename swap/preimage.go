package swap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	arkidentity "github.com/arkade-os/arkd/pkg/client-lib/identity"
	sdkidentity "github.com/arkade-os/go-sdk/identity"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/input"
)

// Deterministic swap preimage format:
//
//	payload  = "Arkade-Boltz-Preimage-v1" || xonly_pubkey(32B) || uint32_le(index)
//	message  = SHA256(payload)
//	sig      = BIP340_SchnorrSign(local_key, message, aux_rand=0)
//	preimage = SHA256(sig)
//
// Boltz receives SHA256(preimage). VHTLC/HTLC scripts use RIPEMD160(SHA256(preimage)).
const preimageTagV1 = "Arkade-Boltz-Preimage-v1"

func buildPreimageMessagePayload(pubKey *btcec.PublicKey, index uint32) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("missing preimage pubkey")
	}

	payload := make([]byte, 0, len(preimageTagV1)+32+4)
	payload = append(payload, []byte(preimageTagV1)...)
	payload = append(payload, schnorr.SerializePubKey(pubKey)...)

	var indexBytes [4]byte
	binary.LittleEndian.PutUint32(indexBytes[:], index)
	payload = append(payload, indexBytes[:]...)

	return payload, nil
}

func buildPreimageMessage(pubKey *btcec.PublicKey, index uint32) ([32]byte, error) {
	payload, err := buildPreimageMessagePayload(pubKey, index)
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(payload), nil
}

func genPreimage(
	ctx context.Context,
	signer sdkidentity.KeyedPreimageSigner,
	keyRef arkidentity.KeyRef,
	index uint32,
) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("missing preimage signer")
	}
	if keyRef.Id == "" {
		return nil, fmt.Errorf("missing preimage key id")
	}

	msg, err := buildPreimageMessage(keyRef.PubKey, index)
	if err != nil {
		return nil, err
	}

	sig, err := signer.SignSchnorrBIP340(ctx, keyRef.Id, msg)
	if err != nil {
		return nil, fmt.Errorf("sign preimage message: %w", err)
	}

	preimage := sha256.Sum256(sig.Serialize())
	return preimage[:], nil
}

func genPreimageInfo(
	ctx context.Context,
	signer sdkidentity.KeyedPreimageSigner,
	keyRef arkidentity.KeyRef,
) (preimage []byte, preimageHashSHA256, preimageHashHASH160 []byte, err error) {
	preimage, err = genPreimage(ctx, signer, keyRef, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	preimageHashSHA256, preimageHashHASH160 = preimageHashes(preimage)
	return preimage, preimageHashSHA256, preimageHashHASH160, nil
}

func preimageHashes(preimage []byte) ([]byte, []byte) {
	sha := sha256.Sum256(preimage)
	shaBytes := sha[:]
	return shaBytes, input.Ripemd160H(shaBytes)
}
