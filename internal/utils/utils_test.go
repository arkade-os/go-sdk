package utils_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
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
		err := utils.ValidateHandler(&mockHandler{}, "test")
		require.NoError(t, err)
	})

	t.Run("invalid", func(t *testing.T) {
		var nilHandler *mockHandler
		fixtures := []struct {
			name            string
			handler         handlers.Handler
			wantErrContains string
		}{
			{
				name:            "nil handler",
				handler:         nil,
				wantErrContains: "nil handler",
			},
			{
				name:            "typed-nil handler",
				handler:         nilHandler,
				wantErrContains: "nil concrete handler",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				err := utils.ValidateHandler(f.handler, "test")
				require.Error(t, err)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

// mockHandler is a minimal handlers.Handler used only by the
// WithContractHandler tests. It implements the full interface with
// zero-value stubs since these tests never invoke the methods.
type mockHandler struct{ typ types.ContractType }

func (h *mockHandler) NewContract(
	_ context.Context, k identity.KeyRef,
) (*types.Contract, error) {
	s := sha256.Sum256([]byte(string(h.typ) + ":" + k.Id))
	return &types.Contract{
		Type:   h.typ,
		Script: hex.EncodeToString(s[:]),
		State:  types.ContractStateActive,
	}, nil
}
func (h *mockHandler) GetKeyRefs(types.Contract) (map[string]string, error) {
	return nil, nil
}
func (h *mockHandler) GetKeyRef(types.Contract) (*identity.KeyRef, error) {
	return nil, errors.New("not implemented")
}
func (h *mockHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *mockHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (h *mockHandler) GetTapscripts(types.Contract) ([]string, error) {
	return nil, nil
}
