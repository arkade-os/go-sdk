package identityfilestore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/go-sdk/identity/store"
	"github.com/arkade-os/go-sdk/identity/store/file"
	"github.com/stretchr/testify/require"
)

func TestFileStore(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		t.Run("NewStore", func(t *testing.T) {
			t.Run("missing datadir", func(t *testing.T) {
				_, err := identityfilestore.NewStore("")
				require.ErrorContains(t, err, "missing datadir")
			})
		})

		t.Run("data corruption", func(t *testing.T) {
			t.Run("on save", func(t *testing.T) {
				datadir := t.TempDir()
				require.NoError(t, os.WriteFile(
					filepath.Join(datadir, "identity.json"), []byte("not json"), 0600,
				))
				storeSvc, err := identityfilestore.NewStore(datadir)
				require.NoError(t, err)
				err = storeSvc.Save(t.Context(), identitystore.IdentityData{NextIndex: 1})
				require.ErrorContains(t, err, "failed to unmarshal identity data")
			})

			t.Run("on load", func(t *testing.T) {
				datadir := t.TempDir()
				require.NoError(t, os.WriteFile(
					filepath.Join(datadir, "identity.json"), []byte("not json"), 0600,
				))
				storeSvc, err := identityfilestore.NewStore(datadir)
				require.NoError(t, err)
				_, err = storeSvc.Load(t.Context())
				require.ErrorContains(t, err, "failed to unmarshal identity data")
			})
		})
	})
}
