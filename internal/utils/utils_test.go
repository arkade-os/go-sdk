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

func TestNextKeyID(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "empty seeds first id",
				input:    "",
				expected: "m/0/0",
			},
			{
				name:     "increments path",
				input:    "m/0/0",
				expected: "m/0/1",
			},
			{
				name:     "increments deep path",
				input:    "m/0/41",
				expected: "m/0/42",
			},
			{
				name:     "plain index increments into path form",
				input:    "5",
				expected: "m/0/6",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := utils.NextKeyID(c.input)
				require.NoError(t, err)
				require.Equal(t, c.expected, got)
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
				name:          "hardened path",
				input:         "m/0/0'",
				expectedError: "forbidden hardened index",
			},
			{
				name:          "non-numeric tail",
				input:         "m/0/notanumber",
				expectedError: "failed to parse derivation index",
			},
			{
				name:          "non-numeric plain",
				input:         "abc",
				expectedError: "failed to parse derivation index",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := utils.NextKeyID(c.input)
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Empty(t, got)
			})
		}
	})
}

func TestParseDerivationIndex(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			name     string
			input    string
			expected uint32
		}{
			{
				name:     "plain zero",
				input:    "0",
				expected: 0,
			},
			{
				name:     "plain index",
				input:    "42",
				expected: 42,
			},
			{
				name:     "path with single segment",
				input:    "m/12",
				expected: 12,
			},
			{
				name:     "standard path",
				input:    "m/0/0",
				expected: 0,
			},
			{
				name:     "max uint32",
				input:    "4294967295",
				expected: 4294967295,
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := utils.ParseDerivationIndex(c.input)
				require.NoError(t, err)
				require.Equal(t, c.expected, got)
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
				expectedError: "key id is required",
			},
			{
				name:          "hardened tail",
				input:         "m/0/0'",
				expectedError: "forbidden hardened index",
			},
			{
				name:          "hardened root",
				input:         "m/0'/0",
				expectedError: "forbidden hardened index",
			},
			{
				name:          "non-numeric tail",
				input:         "m/0/notanumber",
				expectedError: "failed to parse derivation index",
			},
			{
				name:          "non-numeric plain",
				input:         "abc",
				expectedError: "failed to parse derivation index",
			},
			{
				name:          "uint32 overflow",
				input:         "4294967296",
				expectedError: "failed to parse derivation index",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				got, err := utils.ParseDerivationIndex(c.input)
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Zero(t, got)
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
