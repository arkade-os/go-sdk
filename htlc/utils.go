package htlc

import (
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

// parseClaimLeafScript parses a Bitcoin HTLC claim leaf with the shape:
//
//	OP_SIZE 32 OP_EQUALVERIFY
//	OP_HASH160 <preimageHash> OP_EQUALVERIFY
//	<claimPubKey> OP_CHECKSIG
//
// and returns the claim pubkey and the preimage hash.
func parseClaimLeafScript(leafScript []byte) (*btcec.PublicKey, []byte, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, leafScript)

	if err := expectOpcode(&tokenizer, txscript.OP_SIZE, "OP_SIZE"); err != nil {
		return nil, nil, err
	}

	preimageSize, err := expectData(&tokenizer, 1, "preimage size")
	if err != nil {
		return nil, nil, err
	}
	const preimageLen = 32
	if preimageSize[0] != preimageLen {
		return nil, nil, fmt.Errorf(
			"expected preimage size 0x%x (%d bytes), got 0x%x",
			preimageLen, preimageLen, preimageSize[0],
		)
	}

	if err := expectOpcode(&tokenizer, txscript.OP_EQUALVERIFY, "OP_EQUALVERIFY"); err != nil {
		return nil, nil, err
	}
	if err := expectOpcode(&tokenizer, txscript.OP_HASH160, "OP_HASH160"); err != nil {
		return nil, nil, err
	}

	preimageHash, err := expectData(&tokenizer, hash160Len, "preimage hash")
	if err != nil {
		return nil, nil, err
	}

	if err := expectOpcode(
		&tokenizer,
		txscript.OP_EQUALVERIFY,
		"second OP_EQUALVERIFY",
	); err != nil {
		return nil, nil, err
	}

	claimPubKeyBytes, err := expectData(&tokenizer, schnorr.PubKeyBytesLen, "claim pubkey")
	if err != nil {
		return nil, nil, err
	}

	if err := expectOpcode(&tokenizer, txscript.OP_CHECKSIG, "OP_CHECKSIG"); err != nil {
		return nil, nil, err
	}
	if err := expectDone(&tokenizer); err != nil {
		return nil, nil, err
	}

	claimKey, err := schnorr.ParsePubKey(claimPubKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid claim pubkey: %w", err)
	}

	return claimKey, preimageHash, nil
}

// parseRefundLeafScript parses a Bitcoin HTLC refund leaf with the shape:
//
//	<refundPubKey> OP_CHECKSIGVERIFY
//	<absoluteLocktime> OP_CHECKLOCKTIMEVERIFY
//
// and returns the refund pubkey and the absolute locktime.
func parseRefundLeafScript(leafScript []byte) (*btcec.PublicKey, uint32, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, leafScript)

	refundPubKeyBytes, err := expectData(&tokenizer, schnorr.PubKeyBytesLen, "refund pubkey")
	if err != nil {
		return nil, 0, err
	}

	if err := expectOpcode(
		&tokenizer, txscript.OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY",
	); err != nil {
		return nil, 0, err
	}

	locktime, err := expectUint32(&tokenizer, "timeout")
	if err != nil {
		return nil, 0, err
	}

	if err := expectOpcode(
		&tokenizer, txscript.OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY",
	); err != nil {
		return nil, 0, err
	}
	if err := expectDone(&tokenizer); err != nil {
		return nil, 0, err
	}

	refundKey, err := schnorr.ParsePubKey(refundPubKeyBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid refund pubkey: %w", err)
	}

	return refundKey, locktime, nil
}

func expectOpcode(
	tokenizer *txscript.ScriptTokenizer, expected byte, name string,
) error {
	opcode, data, err := nextToken(tokenizer, name)
	if err != nil {
		return err
	}
	if opcode != expected {
		return fmt.Errorf("expected %s (0x%x), got 0x%x", name, expected, opcode)
	}
	if len(data) != 0 {
		return fmt.Errorf("expected %s without data, got %d bytes", name, len(data))
	}
	return nil
}

func expectData(
	tokenizer *txscript.ScriptTokenizer, expectedLen int, name string,
) ([]byte, error) {
	opcode, data, err := nextToken(tokenizer, name)
	if err != nil {
		return nil, err
	}
	if opcode > txscript.OP_PUSHDATA4 {
		return nil, fmt.Errorf("expected data push for %s, got opcode 0x%x", name, opcode)
	}
	if len(data) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes for %s, got %d", expectedLen, name, len(data))
	}
	return data, nil
}

func expectUint32(tokenizer *txscript.ScriptTokenizer, name string) (uint32, error) {
	opcode, data, err := nextToken(tokenizer, name)
	if err != nil {
		return 0, err
	}

	switch {
	case opcode == txscript.OP_0:
		return 0, nil
	case opcode >= txscript.OP_1 && opcode <= txscript.OP_16:
		return uint32(txscript.AsSmallInt(opcode)), nil
	case opcode <= txscript.OP_PUSHDATA4:
		return decodePositiveScriptNum(data, name)
	default:
		return 0, fmt.Errorf("expected numeric push for %s, got opcode 0x%x", name, opcode)
	}
}

func decodePositiveScriptNum(data []byte, name string) (uint32, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("missing %s bytes", name)
	}
	if len(data) > 5 {
		return 0, fmt.Errorf("expected %s to be at most 5 bytes, got %d", name, len(data))
	}

	last := data[len(data)-1]
	if last&0x80 != 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}

	var value uint64
	for i, b := range data {
		value |= uint64(b) << (8 * i)
	}
	if value > math.MaxUint32 {
		return 0, fmt.Errorf("%s exceeds uint32: %d", name, value)
	}
	return uint32(value), nil
}

func nextToken(tokenizer *txscript.ScriptTokenizer, name string) (byte, []byte, error) {
	if !tokenizer.Next() {
		if err := tokenizer.Err(); err != nil {
			return 0, nil, fmt.Errorf("failed to read %s: %w", name, err)
		}
		return 0, nil, fmt.Errorf("missing %s", name)
	}
	return tokenizer.Opcode(), tokenizer.Data(), nil
}

func expectDone(tokenizer *txscript.ScriptTokenizer) error {
	if tokenizer.Next() {
		return fmt.Errorf(
			"unexpected extra bytes at end of script: opcode 0x%x at byte %d",
			tokenizer.Opcode(),
			tokenizer.ByteIndex(),
		)
	}
	if err := tokenizer.Err(); err != nil {
		return fmt.Errorf("failed to parse script: %w", err)
	}
	return nil
}
