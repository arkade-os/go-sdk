package utils

import (
	"fmt"
	"strconv"

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
