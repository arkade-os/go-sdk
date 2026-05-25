package utils

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
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
	if err := handlerSanityCheck(h, t); err != nil {
		return err
	}
	return nil
}

func handlerSanityCheck(h handlers.Handler, t types.ContractType) error {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return err
	}

	randomId := hex.EncodeToString(buf)
	randomKey, err := btcec.NewPrivateKey()
	if err != nil {
		return err
	}

	fakeId := identity.KeyRef{
		Id:     randomId,
		PubKey: randomKey.PubKey(),
	}
	c, err := h.NewContract(context.Background(), fakeId)
	if err != nil {
		return fmt.Errorf("custom handler NewContract fails: %w", err)
	}
	if c == nil {
		return fmt.Errorf("custom handler NewContract returns nil contract")
	}
	if c.Type != t {
		return fmt.Errorf(
			"custom handler creates contracts with wrong type: expected %s, got %s", t, c.Type,
		)
	}
	if len(c.Script) <= 0 {
		return fmt.Errorf("custom handler creates contracts with empty script")
	}
	if _, err := h.GetKeyRefs(*c); err != nil {
		return fmt.Errorf("custom handler GetKeyRefs fails: %w", err)
	}
	if _, err := h.GetKeyRef(*c); err != nil {
		return fmt.Errorf("custom handler GetKeyRef fails: %w", err)
	}
	if _, err := h.GetSignerKey(*c); err != nil {
		return fmt.Errorf("custom handler GetSignerKey fails: %w", err)
	}
	if _, err := h.GetExitDelay(*c); err != nil {
		return fmt.Errorf("custom handler GetExitDelay fails: %w", err)
	}
	if _, err := h.GetTapscripts(*c); err != nil {
		return fmt.Errorf("custom handler GetTapscripts fails: %w", err)
	}

	return nil
}
