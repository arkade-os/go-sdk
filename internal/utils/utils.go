package utils

import (
	"fmt"
	"reflect"
	"strconv"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
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

// ValidateHandler rejects both an interface that is nil and an interface holding a typed-nil
// concrete value (e.g. var h *MyHandler; validateHandler(h, ...)).
func ValidateHandler(h handlers.Handler, t types.ContractType) error {
	if h == nil {
		return fmt.Errorf("nil handler for contract type %q", t)
	}
	v := reflect.ValueOf(h)
	if !v.IsValid() {
		return fmt.Errorf("nil handler for contract type %q", t)
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Map,
		reflect.Func, reflect.Chan, reflect.Interface:
		if v.IsNil() {
			return fmt.Errorf("nil concrete handler for contract type %q", t)
		}
	}
	return nil
}
