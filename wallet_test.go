package arksdk_test

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientstore "github.com/arkade-os/arkd/pkg/client-lib/store"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

func TestNewWallet(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fixtures := []struct {
			name    string
			datadir string
		}{
			{
				name:    "non-empty datadir uses file and SQL stores",
				datadir: t.TempDir(),
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				client, err := arksdk.NewWallet(f.datadir)
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
				name:            "empty datadir",
				datadir:         "",
				wantErrContains: "datadir must be specified",
			},
			{
				name:            "whitespace-only datadir",
				datadir:         "   ",
				wantErrContains: "datadir must be specified",
			},
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
				client, err := arksdk.NewWallet(f.datadir)
				require.Error(t, err)
				require.ErrorContains(t, err, f.wantErrContains)
				require.Nil(t, client)
			})
		}
	})
}

func TestLoadWallet(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("default", func(t *testing.T) {
			datadir := t.TempDir()
			seedIdentity(t, datadir)

			wallet, err := arksdk.LoadWallet(datadir)
			require.NoError(t, err)
			require.NotNil(t, wallet)
			require.True(t, wallet.IsLocked(t.Context()))

			err = wallet.Unlock(t.Context(), "password")
			require.NoError(t, err)
			require.False(t, wallet.IsLocked(t.Context()))
		})
		t.Run("with custom scheduler", func(t *testing.T) {
			datadir := t.TempDir()
			seedIdentity(t, datadir)

			nextSettlement := time.Now().Add(time.Hour)
			c, err := arksdk.LoadWallet(datadir, arksdk.WithScheduler(&testScheduler{
				scheduledAt: nextSettlement,
			}))
			require.NoError(t, err)

			require.Equal(t, nextSettlement, c.WhenNextSettlement())
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			datadir         string
			wantErrContains string
		}{
			{
				name:            "empty datadir",
				datadir:         "",
				wantErrContains: "datadir must be specified",
			},
			{
				name:            "whitespace-only datadir",
				datadir:         "   ",
				wantErrContains: "datadir must be specified",
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
				client, err := arksdk.LoadWallet(f.datadir)
				require.Error(t, err)
				if f.wantErrContains != "" {
					require.ErrorContains(t, err, f.wantErrContains)
				}
				require.Nil(t, client)
			})
		}
	})
}

func TestWhenNextSettlement(t *testing.T) {
	t.Run("returns injected scheduler time", func(t *testing.T) {
		nextSettlement := time.Now().Add(time.Hour)
		c, err := arksdk.NewWallet(t.TempDir(), arksdk.WithScheduler(&testScheduler{
			scheduledAt: nextSettlement,
		}))
		require.NoError(t, err)

		require.Equal(t, nextSettlement, c.WhenNextSettlement())
	})

	t.Run("returns zero when auto settle is disabled", func(t *testing.T) {
		c, err := arksdk.NewWallet(t.TempDir(), arksdk.WithoutAutoSettle())
		require.NoError(t, err)

		require.True(t, c.WhenNextSettlement().IsZero())
	})
}

type testScheduler struct {
	scheduledAt time.Time
}

func (s *testScheduler) Start() {}

func (s *testScheduler) Stop() {}

func (s *testScheduler) ScheduleTask(_ func(), at time.Time) error {
	s.scheduledAt = at
	return nil
}

func (s *testScheduler) CancelScheduledTask() {
	s.scheduledAt = time.Time{}
}

func (s *testScheduler) GetTaskScheduledAt() time.Time {
	return s.scheduledAt
}

// seedIdentity seeds the identity of a freshly created wallet so that
// LoadWallet can subsequently load it without a live server.
func seedIdentity(t *testing.T, datadir string) {
	t.Helper()

	c, err := arksdk.NewWallet(datadir)
	require.NoError(t, err)

	mnemonic, err := c.Identity().Create(t.Context(), chaincfg.RegressionNetParams, "password", "")
	require.NoError(t, err)
	require.NotEmpty(t, mnemonic)

	clientStore, err := clientstore.NewStore(clientstore.Config{
		ConfigStoreType: clienttypes.FileStore,
		BaseDir:         datadir,
	})
	require.NoError(t, err)
	require.NotNil(t, clientStore)

	randomKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	require.NotNil(t, randomKey)

	err = clientStore.ConfigStore().AddData(t.Context(), clienttypes.Config{
		ServerUrl:     "localhost:7070",
		SignerPubKey:  randomKey.PubKey(),
		ForfeitPubKey: randomKey.PubKey(),
		Network:       arklib.BitcoinRegTest,
		ExplorerURL:   "http://127.0.0.1:3000",
	})
	require.NoError(t, err)
}
