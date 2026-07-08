package handler

import (
	"encoding/hex"
	"fmt"
	"strconv"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func parsePubkey(key, label string) (*btcec.PublicKey, error) {
	if len(key) <= 0 {
		return nil, fmt.Errorf("empty %s key", label)
	}
	buf, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid %s key format", label)
	}
	pubkey, err := schnorr.ParsePubKey(buf)
	if err != nil {
		return nil, fmt.Errorf("invalid %s key: %w", label, err)
	}
	return pubkey, nil
}

func parsePreimageHash(str string) ([]byte, error) {
	if len(str) <= 0 {
		return nil, fmt.Errorf("empty preimage hash")
	}
	buf, err := hex.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("invalid preimage hash format")
	}
	if l := len(buf); l != hash160Len {
		return nil, fmt.Errorf("invalid preimage hash len: got %d, expected %d", l, hash160Len)
	}
	return buf, nil
}

func parseAbsoluteLocktime(value string) (arklib.AbsoluteLocktime, error) {
	if len(value) <= 0 {
		return 0, fmt.Errorf("empty absolute locktime")
	}
	val, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid absolute locktime format")
	}
	if val == 0 {
		return 0, fmt.Errorf("zero absolute locktime")
	}
	return arklib.AbsoluteLocktime(val), nil
}

func parseRelativeLocktime(value string) (*arklib.RelativeLocktime, error) {
	if len(value) <= 0 {
		return nil, fmt.Errorf("empty relative locktime")
	}
	val, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid relative locktime format")
	}
	if val == 0 {
		return nil, fmt.Errorf("zero relative locktime")
	}
	if val < 512 {
		return &arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: uint32(val),
		}, nil
	}
	return &arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeSecond,
		Value: uint32(val),
	}, nil
}

func parseReceiverScript(str string) ([]byte, error) {
	if len(str) <= 0 {
		return nil, fmt.Errorf("empty non interactive receiver script")
	}
	buf, err := hex.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf("invalid non interactive receiver script format")
	}
	return buf, nil
}
