package arksdk_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// seedConfigStore seeds the config store of a freshly created client so that
// LoadArkClient can subsequently load it without a live server.
func seedConfigStore(t *testing.T, datadir string) {
	t.Helper()

	c, err := arksdk.NewArkClient(datadir, false)
	require.NoError(t, err)

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	cfg := clientTypes.Config{
		ServerUrl:     "localhost:7070",
		SignerPubKey:  privKey.PubKey(),
		ForfeitPubKey: privKey.PubKey(),
		WalletType:    "singlekey",
		Network:       arklib.BitcoinRegTest,
		ExplorerURL:   "http://127.0.0.1:3000",
	}
	require.NoError(t, c.GetConfigStore().AddData(t.Context(), cfg))
}

func TestNewArkClient(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name    string
			datadir string
			verbose bool
		}{
			{
				name:    "empty datadir uses in-memory stores",
				datadir: "",
			},
			{
				name:    "non-empty datadir uses file and SQL stores",
				datadir: t.TempDir(),
			},
			{
				name:    "verbose flag is accepted",
				datadir: "",
				verbose: true,
			},
			{
				// whitespace is trimmed, so this behaves identically to empty datadir
				name:    "whitespace-only datadir uses in-memory stores",
				datadir: "   ",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.NewArkClient(f.datadir, f.verbose)
				require.NoError(t, err)
				require.NotNil(t, client)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			datadir         string
			wantErrContains string
		}{
			{
				// /dev/null is a character device, not a directory, so
				// creating a subdirectory inside it fails.
				name:            "non-creatable datadir",
				datadir:         "/dev/null/subdir",
				wantErrContains: "failed to open store",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.NewArkClient(f.datadir, false)
				require.Error(t, err)
				require.ErrorContains(t, err, f.wantErrContains)
				require.Nil(t, client)
			})
		}
	})
}

func TestLoadNewArkClient(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name    string
			datadir string
			verbose bool
		}{
			{
				name:    "seeded datadir loads client successfully",
				datadir: func() string { d := t.TempDir(); seedConfigStore(t, d); return d }(),
			},
			{
				name:    "seeded datadir with verbose flag",
				datadir: func() string { d := t.TempDir(); seedConfigStore(t, d); return d }(),
				verbose: true,
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				c, err := arksdk.LoadArkClient(f.datadir, f.verbose)
				require.NoError(t, err)
				require.NotNil(t, c)

				// Unlock fails because no wallet keys were created (only config was seeded),
				// but it must return an error — not panic.
				// Regression: before the fix, Unlock would start goroutines that called
				// explorer.GetAddressesEvents() on a nil listeners field and panic.
				err = c.Unlock(t.Context(), "password")
				require.Error(t, err)

				// Stop must not panic on a locked/uninitialized wallet.
				// Regression: old code called a.Explorer().Stop() via the safeCheck wrapper
				// which returned nil for a locked wallet, causing a nil-deref panic.
				require.NotPanics(t, func() { c.Stop() })
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			datadir         string
			wantErrContains string
		}{
			{
				name:            "empty datadir with no existing config",
				datadir:         "",
				wantErrContains: "not initialized",
			},
			{
				// whitespace is trimmed to "", so this behaves identically to empty datadir
				name:            "whitespace-only datadir with no existing config",
				datadir:         "   ",
				wantErrContains: "not initialized",
			},
			{
				name:            "fresh datadir with no existing config",
				datadir:         t.TempDir(),
				wantErrContains: "not initialized",
			},
			{
				name:            "non-creatable datadir",
				datadir:         "/dev/null/subdir",
				wantErrContains: "failed to open store",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.LoadArkClient(f.datadir, false)
				require.Error(t, err)
				if f.wantErrContains != "" {
					require.ErrorContains(t, err, f.wantErrContains)
				}
				require.Nil(t, client)
			})
		}
	})
}
