package utils

import (
	"fmt"
	"strconv"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/btcsuite/btcd/chaincfg"
)

func ToBitcoinNetwork(net arklib.Network) chaincfg.Params {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}

func NextKeyID(keyID string) (string, error) {
	if keyID == "" {
		return "m/0/0", nil
	}

	index, err := ParseDerivationIndex(keyID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("m/0/%d", index+1), nil
}

func ParseDerivationIndex(keyID string) (uint32, error) {
	if keyID == "" {
		return 0, fmt.Errorf("key id is required")
	}
	if strings.Contains(keyID, "'") {
		return 0, fmt.Errorf("derivation path %s contains forbidden hardened index", keyID)
	}

	if idx, err := strconv.ParseUint(keyID, 10, 32); err == nil {
		return uint32(idx), nil
	}

	path := strings.TrimPrefix(keyID, "m/")
	parts := strings.Split(path, "/")

	idx, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse derivation index for path %s: %w", keyID, err)
	}

	return uint32(idx), nil
}

func ParseDelay(s string) (*arklib.RelativeLocktime, error) {
	delay, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("exit delay %s has invalid format", s)
	}
	if delay < 512 {
		return &arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: uint32(delay),
		}, nil
	}
	return &arklib.RelativeLocktime{
		Type:  arklib.LocktimeTypeSecond,
		Value: uint32(delay),
	}, nil
}
