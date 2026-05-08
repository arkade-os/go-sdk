package filewalletstore_test

import (
	"os"
	"path/filepath"
	"testing"

	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
	filewalletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store/file"
	"github.com/stretchr/testify/require"
)

func TestFileStore(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		t.Run("NewStore", func(t *testing.T) {
			t.Run("missing datadir", func(t *testing.T) {
				_, err := filewalletstore.NewStore("")
				require.ErrorContains(t, err, "missing datadir")
			})
		})

		t.Run("data corruption", func(t *testing.T) {
			t.Run("on save", func(t *testing.T) {
				datadir := t.TempDir()
				require.NoError(t, os.WriteFile(
					filepath.Join(datadir, "wallet.json"), []byte("not json"), 0600,
				))
				storeSvc, err := filewalletstore.NewStore(datadir)
				require.NoError(t, err)
				err = storeSvc.Save(t.Context(), walletstore.State{NextIndex: 1})
				require.ErrorContains(t, err, "failed to unmarshal hd wallet state")
			})

			t.Run("on load", func(t *testing.T) {
				datadir := t.TempDir()
				require.NoError(t, os.WriteFile(
					filepath.Join(datadir, "wallet.json"), []byte("not json"), 0600,
				))
				storeSvc, err := filewalletstore.NewStore(datadir)
				require.NoError(t, err)
				_, err = storeSvc.Load(t.Context())
				require.ErrorContains(t, err, "failed to unmarshal hd wallet state")
			})
		})
	})
}
