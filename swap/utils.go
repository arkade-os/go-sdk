package swap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	decodepay "github.com/nbd-wtf/ln-decodepay"
)

func parseLocktime(locktime uint32) arklib.RelativeLocktime {
	if locktime >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: locktime}
	}

	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: locktime}
}

// stripTxSignatures returns a copy of the given tx without any tapscript signature.
func stripTxSignatures(tx *psbt.Packet) (*psbt.Packet, string, error) {
	unsignedTx := &psbt.Packet{}
	*unsignedTx = *tx

	// Clone the inputs so that dropping the signatures doesn't mutate the given tx.
	unsignedTx.Inputs = make([]psbt.PInput, len(tx.Inputs))
	copy(unsignedTx.Inputs, tx.Inputs)

	for i := range unsignedTx.Inputs {
		unsignedTx.Inputs[i].TaprootScriptSpendSig = nil
	}

	base64, err := unsignedTx.B64Encode()
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode psbt: %w", err)
	}
	return unsignedTx, base64, nil
}

// combineTxSignatures returns the fully signed tx combining the signatures of the given tx copies.
func combineTxSignatures(txs ...*psbt.Packet) (*psbt.Packet, string, error) {
	if len(txs) < 2 {
		return nil, "", fmt.Errorf("missing signed tx to combine")
	}

	fullySignedTx := &psbt.Packet{}
	*fullySignedTx = *txs[0]

	// Clone the inputs so that adding the signatures doesn't mutate the given tx.
	fullySignedTx.Inputs = make([]psbt.PInput, len(txs[0].Inputs))
	copy(fullySignedTx.Inputs, txs[0].Inputs)

	txid := fullySignedTx.UnsignedTx.TxID()
	for _, tx := range txs[1:] {
		if tx.UnsignedTx.TxID() != txid {
			return nil, "", fmt.Errorf(
				"cannot combine signature for txs with different txids: expected %s, got %s",
				txid, tx.UnsignedTx.TxID(),
			)
		}
	}

	for i, in := range fullySignedTx.Inputs {
		sigsMap := make(map[string]*psbt.TaprootScriptSpendSig)
		for _, sig := range in.TaprootScriptSpendSig {
			pubkey := hex.EncodeToString(sig.XOnlyPubKey)
			sigsMap[pubkey] = sig
		}
		for _, tx := range txs[1:] {
			in := tx.Inputs[i]
			for _, sig := range in.TaprootScriptSpendSig {
				pubkey := hex.EncodeToString(sig.XOnlyPubKey)
				if _, ok := sigsMap[pubkey]; !ok {
					sigsMap[pubkey] = sig
				}
			}
		}
		sigs := make([]*psbt.TaprootScriptSpendSig, 0, len(sigsMap))
		for _, sig := range sigsMap {
			sigs = append(sigs, sig)
		}
		fullySignedTx.Inputs[i].TaprootScriptSpendSig = sigs
	}

	base64, err := fullySignedTx.B64Encode()
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode combined tx: %w", err)
	}
	return fullySignedTx, base64, nil
}

func verifyTxSignatures(
	tx *psbt.Packet, pubkeys []*btcec.PublicKey, expectedTapLeaves map[int]txscript.TapLeaf,
) error {
	for _, signer := range pubkeys {
		if err := verifyTxInputSignatures(tx, signer, expectedTapLeaves); err != nil {
			return err
		}
	}
	return nil
}

// verifyTxInputSignatures checks that all inputs have a signature for the given pubkey
// and the signature is correct for the given tapscript leaf
func verifyTxInputSignatures(
	tx *psbt.Packet, pubkey *btcec.PublicKey, tapLeaves map[int]txscript.TapLeaf,
) error {
	xOnlyPubkey := schnorr.SerializePubKey(pubkey)

	prevouts := make(map[wire.OutPoint]*wire.TxOut)
	sigsToVerify := make(map[int]*psbt.TaprootScriptSpendSig)

	for inputIndex, input := range tx.Inputs {
		// collect previous outputs
		if input.WitnessUtxo == nil {
			return fmt.Errorf("input %d has no witness utxo, cannot verify signature", inputIndex)
		}

		outpoint := tx.UnsignedTx.TxIn[inputIndex].PreviousOutPoint
		prevouts[outpoint] = input.WitnessUtxo

		tapLeaf, ok := tapLeaves[inputIndex]
		if !ok {
			return fmt.Errorf(
				"input %d has no tapscript leaf, cannot verify signature", inputIndex,
			)
		}

		tapLeafHash := tapLeaf.TapHash()

		// check if pubkey has a tapscript sig
		hasSig := false
		for _, sig := range input.TaprootScriptSpendSig {
			if bytes.Equal(sig.XOnlyPubKey, xOnlyPubkey) &&
				bytes.Equal(sig.LeafHash, tapLeafHash[:]) {
				hasSig = true
				sigsToVerify[inputIndex] = sig
				break
			}
		}

		if !hasSig {
			return fmt.Errorf("input %d has no signature for pubkey %x", inputIndex, xOnlyPubkey)
		}
	}

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(prevouts)
	txSigHashes := txscript.NewTxSigHashes(tx.UnsignedTx, prevoutFetcher)

	for inputIndex, sig := range sigsToVerify {
		msgHash, err := txscript.CalcTapscriptSignaturehash(
			txSigHashes,
			sig.SigHash,
			tx.UnsignedTx,
			inputIndex,
			prevoutFetcher,
			tapLeaves[inputIndex],
		)
		if err != nil {
			return fmt.Errorf("failed to calculate tapscript signature hash: %w", err)
		}

		signature, err := schnorr.ParseSignature(sig.Signature)
		if err != nil {
			return fmt.Errorf("failed to parse signature: %w", err)
		}

		if !signature.Verify(msgHash, pubkey) {
			return fmt.Errorf("input %d: invalid signature", inputIndex)
		}
	}

	return nil
}

// GetInputTapLeaves returns a map of input index to tapscript leaf
// if the input has no tapscript leaf, it is not included in the map
func getInputTapLeaves(tx *psbt.Packet) map[int]txscript.TapLeaf {
	tapLeaves := make(map[int]txscript.TapLeaf)
	for inputIndex, input := range tx.Inputs {
		if len(input.TaprootLeafScript) <= 0 {
			continue
		}
		tapLeaves[inputIndex] = txscript.NewBaseTapLeaf(input.TaprootLeafScript[0].Script)
	}
	return tapLeaves
}

func decodeInvoice(invoice string) (uint64, []byte, int, error) {
	bolt11, err := decodepay.Decodepay(invoice)
	if err != nil {
		return 0, nil, -1, err
	}

	amount := uint64(bolt11.MSatoshi / 1000)
	preimageHash, err := hex.DecodeString(bolt11.PaymentHash)
	if err != nil {
		return 0, nil, -1, err
	}

	return amount, input.Ripemd160H(preimageHash), bolt11.Expiry, nil
}

func parsePubkey(pubkey string) (*btcec.PublicKey, error) {
	if len(pubkey) <= 0 {
		return nil, errors.New("empty public key")
	}

	dec, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey: %s", err)
	}

	if len(dec) == schnorr.PubKeyBytesLen {
		pk, err := schnorr.ParsePubKey(dec)
		if err != nil {
			return nil, fmt.Errorf("invalid x-only pubkey: %s", err)
		}

		return pk, nil
	}

	pk, err := btcec.ParsePubKey(dec)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey: %s", err)
	}

	return pk, nil
}

// retry runs fn at the given interval until it reports done, then returns its error, if any.
// An error with done=false is transient: fn is retried, and the last transient error is
// returned if the context expires before fn is done.
func retry(
	ctx context.Context, interval time.Duration, fn func(ctx context.Context) (bool, error),
) error {
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("timed out, last error: %w", lastErr)
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("timed out")
			}
			return ctx.Err()
		default:
			done, err := fn(ctx)
			if done {
				return err
			}
			if err != nil {
				lastErr = err
			}
			<-time.After(interval)
		}
	}
}
