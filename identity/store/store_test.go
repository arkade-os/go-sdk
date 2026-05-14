package identitystore_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/identity"
	identitystore "github.com/arkade-os/go-sdk/identity/store"
	identityfilestore "github.com/arkade-os/go-sdk/identity/store/file"
	identityinmemorystore "github.com/arkade-os/go-sdk/identity/store/inmemory"
	"github.com/stretchr/testify/require"
)

var (
	storeImpls = []string{types.InMemoryStore, types.FileStore}

	testData = identitystore.IdentityData{
		Type:                 identity.Type,
		EncryptedMnemonic:    "encryptedMnemonic",
		EncryptedExtendedKey: "encryptedXPriv",
		NextIndex:            15,
	}
)

func TestSave(t *testing.T) {
	for _, impl := range storeImpls {
		t.Run(impl, func(t *testing.T) {
			t.Run("valid", func(t *testing.T) {
				t.Run("first write", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), testData))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, testData, *loaded)
				})

				t.Run("update next index only", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), testData))

					require.NoError(
						t,
						s.Save(t.Context(), identitystore.IdentityData{NextIndex: 16}),
					)

					expected := testData
					expected.NextIndex = 16
					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, expected, *loaded)
				})

				t.Run("save after clear", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), testData))
					require.NoError(t, s.Clear(t.Context()))

					reseed := testData
					reseed.NextIndex = 99
					require.NoError(t, s.Save(t.Context(), reseed))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, reseed, *loaded)
				})
			})

			t.Run("invalid", func(t *testing.T) {
				fixtures := []struct {
					name            string
					data            identitystore.IdentityData
					wantErrContains string
				}{
					{
						name: "missing identity type",
						data: identitystore.IdentityData{
							EncryptedExtendedKey: "encryptedXPriv",
							EncryptedMnemonic:    "encryptedMnemonic",
						},
						wantErrContains: "missing identity type",
					},
					{
						name: "missing encrypted extended key",
						data: identitystore.IdentityData{
							Type:              identity.Type,
							EncryptedMnemonic: "encryptedMnemonic",
						},
						wantErrContains: "missing encrypted extended key",
					},
					{
						name: "missing encrypted mnemonic",
						data: identitystore.IdentityData{
							Type:                 identity.Type,
							EncryptedExtendedKey: "encryptedXPriv",
						},
						wantErrContains: "missing encrypted mnemonic",
					},
				}

				for _, f := range fixtures {
					t.Run(f.name, func(t *testing.T) {
						s := newStore(t, impl)
						err := s.Save(t.Context(), f.data)
						require.ErrorContains(t, err, f.wantErrContains)
					})
				}
			})
		})
	}
}

func TestLoad(t *testing.T) {
	for _, impl := range storeImpls {
		t.Run(impl, func(t *testing.T) {
			t.Run("valid", func(t *testing.T) {
				t.Run("empty", func(t *testing.T) {
					s := newStore(t, impl)

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Nil(t, loaded)
				})

				t.Run("populated", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), testData))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, testData, *loaded)
				})
			})
		})
	}
}

func TestClear(t *testing.T) {
	for _, impl := range storeImpls {
		t.Run(impl, func(t *testing.T) {
			t.Run("valid", func(t *testing.T) {
				t.Run("empty", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Clear(t.Context()))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Nil(t, loaded)
				})

				t.Run("populated", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), testData))
					require.NoError(t, s.Clear(t.Context()))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Nil(t, loaded)
				})
			})
		})
	}
}

func newStore(t *testing.T, impl string) identitystore.IdentityStore {
	t.Helper()
	switch impl {
	case types.InMemoryStore:
		return identityinmemorystore.NewStore()
	case types.FileStore:
		s, err := identityfilestore.NewStore(t.TempDir())
		require.NoError(t, err)
		return s
	}
	t.Fatalf("unknown store impl: %s", impl)
	return nil
}
