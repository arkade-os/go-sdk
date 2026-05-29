package utils_test

import (
	"context"
	"fmt"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestToBitcoinNetwork(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			name     string
			network  arklib.Network
			expected chaincfg.Params
		}{
			{
				name:     "mainnet",
				network:  arklib.Bitcoin,
				expected: chaincfg.MainNetParams,
			},
			{
				name:     "testnet",
				network:  arklib.BitcoinTestNet,
				expected: chaincfg.TestNet3Params,
			},
			{
				name:     "signet",
				network:  arklib.BitcoinSigNet,
				expected: chaincfg.SigNetParams,
			},
			{
				name:     "mutinynet",
				network:  arklib.BitcoinMutinyNet,
				expected: arklib.MutinyNetSigNetParams,
			},
			{
				name:     "regtest",
				network:  arklib.BitcoinRegTest,
				expected: chaincfg.RegressionNetParams,
			},
			{
				name:     "unknown defaults to mainnet",
				network:  arklib.Network{Name: "totally-unknown"},
				expected: chaincfg.MainNetParams,
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got := utils.ToBitcoinNetwork(c.network)
				require.Equal(t, c.expected.Name, got.Name)
			})
		}
	})
}

func TestParseDelay(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			name     string
			input    string
			expected arklib.RelativeLocktime
		}{
			{
				name:  "zero is block-based",
				input: "0",
				expected: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeBlock,
					Value: 0,
				},
			},
			{
				name:  "small value is block-based",
				input: "144",
				expected: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeBlock,
					Value: 144,
				},
			},
			{
				name:  "just under threshold is block-based",
				input: "511",
				expected: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeBlock,
					Value: 511,
				},
			},
			{
				name:  "threshold is second-based",
				input: "512",
				expected: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeSecond,
					Value: 512,
				},
			},
			{
				name:  "large value is second-based",
				input: "1024",
				expected: arklib.RelativeLocktime{
					Type:  arklib.LocktimeTypeSecond,
					Value: 1024,
				},
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := utils.ParseDelay(c.input)
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, c.expected, *got)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		cases := []struct {
			name          string
			input         string
			expectedError string
		}{
			{
				name:          "empty",
				input:         "",
				expectedError: "invalid format",
			},
			{
				name:          "non-numeric",
				input:         "notanumber",
				expectedError: "invalid format",
			},
			{
				name:          "negative",
				input:         "-1",
				expectedError: "invalid format",
			},
			{
				name:          "decimal",
				input:         "3.14",
				expectedError: "invalid format",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := utils.ParseDelay(c.input)
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Nil(t, got)
			})
		}
	})
}

func TestValidateHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h := &mockedHandler{}
		mockHandler(h, "test")
		require.NoError(t, utils.ValidateHandler(h, "test"))
	})

	t.Run("invalid", func(t *testing.T) {
		var nilHandler *mockedHandler
		handlerErr := fmt.Errorf("boom")
		fixtures := []struct {
			name            string
			handler         func() handlers.Handler
			contractType    types.ContractType
			wantErrContains string
		}{
			{
				name:            "nil handler",
				handler:         func() handlers.Handler { return nil },
				contractType:    "test",
				wantErrContains: "nil handler",
			},
			{
				name:            "typed-nil handler",
				handler:         func() handlers.Handler { return nilHandler },
				contractType:    "test",
				wantErrContains: "nil concrete handler",
			},
			{
				name: "NewContract returns error",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					// First match wins, so register the failure before defaults.
					h.On("NewContract", mock.Anything, mock.Anything).
						Return((*types.Contract)(nil), handlerErr)
					mockHandler(h, "test")
					return h
				},
				contractType:    "test",
				wantErrContains: "NewContract fails",
			},
			{
				name: "contract created with wrong type",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					mockHandler(h, "other")
					return h
				},
				contractType:    "test",
				wantErrContains: "wrong type",
			},
			{
				name: "GetKeyRefs returns error",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					h.On("GetKeyRefs", mock.Anything).
						Return(map[string]string(nil), handlerErr)
					mockHandler(h, "test")
					return h
				},
				contractType:    "test",
				wantErrContains: "GetKeyRefs fails",
			},
			{
				name: "GetKeyRef returns error",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					h.On("GetKeyRef", mock.Anything).
						Return((*identity.KeyRef)(nil), handlerErr)
					mockHandler(h, "test")
					return h
				},
				contractType:    "test",
				wantErrContains: "GetKeyRef fails",
			},
			{
				name: "GetSignerKey returns error",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					h.On("GetSignerKey", mock.Anything).
						Return((*btcec.PublicKey)(nil), handlerErr)
					mockHandler(h, "test")
					return h
				},
				contractType:    "test",
				wantErrContains: "GetSignerKey fails",
			},
			{
				name: "GetExitDelay returns error",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					h.On("GetExitDelay", mock.Anything).
						Return((*arklib.RelativeLocktime)(nil), handlerErr)
					mockHandler(h, "test")
					return h
				},
				contractType:    "test",
				wantErrContains: "GetExitDelay fails",
			},
			{
				name: "GetTapscripts returns error",
				handler: func() handlers.Handler {
					h := &mockedHandler{}
					h.On("GetTapscripts", mock.Anything).
						Return([]string(nil), handlerErr)
					mockHandler(h, "test")
					return h
				},
				contractType:    "test",
				wantErrContains: "GetTapscripts fails",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := utils.ValidateHandler(f.handler(), f.contractType)
				require.Error(t, err)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

// mockedHandler is a testify-mock-based handlers.Handler. Behavior is configured per test via
// .On(...) / .Return(...) chains; the test helper mockHandler wires every method to a zero-value
// success response.
type mockedHandler struct {
	mock.Mock
}

func (h *mockedHandler) Derivable() bool { return true }

func (h *mockedHandler) NewContract(
	ctx context.Context, k identity.KeyRef, params any,
) (*types.Contract, error) {
	a := h.Called(ctx, k)
	c, _ := a.Get(0).(*types.Contract)
	return c, a.Error(1)
}

func (h *mockedHandler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	a := h.Called(c)
	m, _ := a.Get(0).(map[string]string)
	return m, a.Error(1)
}

func (h *mockedHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	a := h.Called(c)
	r, _ := a.Get(0).(*identity.KeyRef)
	return r, a.Error(1)
}

func (h *mockedHandler) GetSignerKey(c types.Contract) (*btcec.PublicKey, error) {
	a := h.Called(c)
	p, _ := a.Get(0).(*btcec.PublicKey)
	return p, a.Error(1)
}

func (h *mockedHandler) GetExitDelay(c types.Contract) (*arklib.RelativeLocktime, error) {
	a := h.Called(c)
	d, _ := a.Get(0).(*arklib.RelativeLocktime)
	return d, a.Error(1)
}

func (h *mockedHandler) GetTapscripts(c types.Contract) ([]string, error) {
	a := h.Called(c)
	s, _ := a.Get(0).([]string)
	return s, a.Error(1)
}

// mockHandler wires every method on h to a zero-value successful response, with NewContract
// returning a contract of type ct.
// Fixtures that want to force a specific failure register their failing call first
// (first match wins) and then call mockHandler for the rest.
func mockHandler(h *mockedHandler, ct types.ContractType) {
	h.On("NewContract", mock.Anything, mock.Anything).Return(
		&types.Contract{
			Type:   ct,
			Script: "dummy",
			State:  types.ContractStateActive,
		}, nil,
	)
	h.On("GetKeyRefs", mock.Anything).Return(map[string]string(nil), nil)
	h.On("GetKeyRef", mock.Anything).Return((*identity.KeyRef)(nil), nil)
	h.On("GetSignerKey", mock.Anything).Return((*btcec.PublicKey)(nil), nil)
	h.On("GetExitDelay", mock.Anything).Return((*arklib.RelativeLocktime)(nil), nil)
	h.On("GetTapscripts", mock.Anything).Return([]string(nil), nil)
}
