package utils_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/internal/utils"
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
