package htlc

import (
	"encoding/hex"
	"fmt"
	"math"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
)

const (
	Hash160Len = 20
)

// Opts are the raw parameters needed to build Bitcoin HTLC leaf scripts.
//
// ClaimKey and RefundKey are the script-path keys.
type Opts struct {
	ClaimKey       *btcec.PublicKey
	RefundKey      *btcec.PublicKey
	PreimageHash   []byte
	RefundLocktime arklib.AbsoluteLocktime
}

func (o Opts) validate() error {
	if o.ClaimKey == nil && o.RefundKey == nil {
		return fmt.Errorf("missing claim or refund key")
	}
	if len(o.PreimageHash) != Hash160Len {
		return fmt.Errorf(
			"preimage hash must be %d bytes, got %d", Hash160Len, len(o.PreimageHash),
		)
	}
	if o.RefundLocktime == 0 {
		return fmt.Errorf("refund locktime must be greater than 0")
	}
	return nil
}

// NewHTLCLeafScriptsFromOpts builds the claim and refund leaves from complete
// HTLC opts without applying wallet ownership semantics.
func NewHTLCLeafScriptsFromOpts(opts Opts) ([]byte, []byte, error) {
	if err := opts.validate(); err != nil {
		return nil, nil, err
	}
	if opts.ClaimKey == nil {
		return nil, nil, fmt.Errorf("missing claim key")
	}
	if opts.RefundKey == nil {
		return nil, nil, fmt.Errorf("missing refund key")
	}

	claimScript, err := claimLeafScript(opts.PreimageHash, opts.ClaimKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create claim leaf script: %w", err)
	}
	refundScript, err := refundLeafScript(opts.RefundKey, opts.RefundLocktime)
	if err != nil {
		return nil, nil, fmt.Errorf("create refund leaf script: %w", err)
	}

	return claimScript, refundScript, nil
}

func claimLeafScript(preimageHash []byte, claimKey *btcec.PublicKey) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(claimKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
}

func refundLeafScript(
	refundKey *btcec.PublicKey,
	refundLocktime arklib.AbsoluteLocktime,
) ([]byte, error) {
	return txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(refundKey)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddInt64(int64(refundLocktime)).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
}


// ClaimLeafComponents contains the parsed components from a Bitcoin HTLC claim
// leaf script.
type ClaimLeafComponents struct {
	PreimageHash [Hash160Len]byte
	ClaimPubKey  [schnorr.PubKeyBytesLen]byte
}

// RefundLeafComponents contains the parsed components from a Bitcoin HTLC
// refund leaf script.
type RefundLeafComponents struct {
	RefundPubKey [schnorr.PubKeyBytesLen]byte
	Timeout      uint32
}

// ParseClaimLeafScriptHex parses a hex-encoded Bitcoin HTLC claim leaf.
func ParseClaimLeafScriptHex(outputHex string) (*ClaimLeafComponents, error) {
	scriptBytes, err := hex.DecodeString(outputHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claim leaf output hex: %w", err)
	}
	return ParseClaimLeafScript(scriptBytes)
}

// ParseClaimLeafScript parses a Bitcoin HTLC claim leaf with the shape:
//
//	OP_SIZE 32 OP_EQUALVERIFY
//	OP_HASH160 <preimageHash> OP_EQUALVERIFY
//	<claimPubKey> OP_CHECKSIG
func ParseClaimLeafScript(leafScript []byte) (*ClaimLeafComponents, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, leafScript)

	if err := expectOpcode(&tokenizer, txscript.OP_SIZE, "OP_SIZE"); err != nil {
		return nil, err
	}

	preimageSize, err := expectData(&tokenizer, 1, "preimage size")
	if err != nil {
		return nil, err
	}
	const preimageLen = 32
	if preimageSize[0] != preimageLen {
		return nil, fmt.Errorf(
			"expected preimage size 0x%x (%d bytes), got 0x%x",
			preimageLen, preimageLen, preimageSize[0],
		)
	}

	if err := expectOpcode(&tokenizer, txscript.OP_EQUALVERIFY, "OP_EQUALVERIFY"); err != nil {
		return nil, err
	}
	if err := expectOpcode(&tokenizer, txscript.OP_HASH160, "OP_HASH160"); err != nil {
		return nil, err
	}

	preimageHashBytes, err := expectData(&tokenizer, Hash160Len, "preimage hash")
	if err != nil {
		return nil, err
	}

	if err := expectOpcode(
		&tokenizer,
		txscript.OP_EQUALVERIFY,
		"second OP_EQUALVERIFY",
	); err != nil {
		return nil, err
	}

	claimPubKeyBytes, err := expectData(&tokenizer, schnorr.PubKeyBytesLen, "claim pubkey")
	if err != nil {
		return nil, err
	}

	if err := expectOpcode(&tokenizer, txscript.OP_CHECKSIG, "OP_CHECKSIG"); err != nil {
		return nil, err
	}
	if err := expectDone(&tokenizer); err != nil {
		return nil, err
	}

	var components ClaimLeafComponents
	copy(components.PreimageHash[:], preimageHashBytes)
	copy(components.ClaimPubKey[:], claimPubKeyBytes)
	return &components, nil
}

// ParseRefundLeafScriptHex parses a hex-encoded Bitcoin HTLC refund leaf.
func ParseRefundLeafScriptHex(outputHex string) (*RefundLeafComponents, error) {
	scriptBytes, err := hex.DecodeString(outputHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund leaf output hex: %w", err)
	}
	return ParseRefundLeafScript(scriptBytes)
}

// ParseRefundLeafScript parses a Bitcoin HTLC refund leaf with the shape:
//
//	<refundPubKey> OP_CHECKSIGVERIFY
//	<absoluteLocktime> OP_CHECKLOCKTIMEVERIFY
func ParseRefundLeafScript(leafScript []byte) (*RefundLeafComponents, error) {
	tokenizer := txscript.MakeScriptTokenizer(0, leafScript)

	refundPubKeyBytes, err := expectData(&tokenizer, schnorr.PubKeyBytesLen, "refund pubkey")
	if err != nil {
		return nil, err
	}

	if err := expectOpcode(
		&tokenizer, txscript.OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY",
	); err != nil {
		return nil, err
	}

	locktime, err := expectUint32(&tokenizer, "timeout")
	if err != nil {
		return nil, err
	}

	if err := expectOpcode(
		&tokenizer, txscript.OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY",
	); err != nil {
		return nil, err
	}
	if err := expectDone(&tokenizer); err != nil {
		return nil, err
	}

	var components RefundLeafComponents
	copy(components.RefundPubKey[:], refundPubKeyBytes)
	components.Timeout = locktime
	return &components, nil
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
