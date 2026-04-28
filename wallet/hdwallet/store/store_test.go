package walletstore_test

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/wallet/hdwallet"
	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
	filewalletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store/file"
	inmemorywalletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store/inmemory"
	"github.com/stretchr/testify/require"
)

var (
	storeImpls = []string{types.InMemoryStore, types.FileStore}

	validState = walletstore.State{
		WalletType:         hdwallet.Type,
		EncryptedMnemonic:  "encryptedMnemonic",
		EncryptedMasterKey: "encryptedMasterKey",
		NextIndex:          15,
	}
)

func TestSave(t *testing.T) {
	for _, impl := range storeImpls {
		t.Run(impl, func(t *testing.T) {
			t.Run("valid", func(t *testing.T) {
				t.Run("first write", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), validState))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, validState, *loaded)
				})

				t.Run("update next index only", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), validState))

					require.NoError(t, s.Save(t.Context(), walletstore.State{NextIndex: 16}))

					expected := validState
					expected.NextIndex = 16
					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, expected, *loaded)
				})

				t.Run("save after clear", func(t *testing.T) {
					s := newStore(t, impl)
					require.NoError(t, s.Save(t.Context(), validState))
					require.NoError(t, s.Clear(t.Context()))

					reseed := validState
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
					state           walletstore.State
					wantErrContains string
				}{
					{
						name: "missing wallet type",
						state: walletstore.State{
							EncryptedMasterKey: "encryptedMasterKey",
							EncryptedMnemonic:  "encryptedMnemonic",
						},
						wantErrContains: "missing wallet type",
					},
					{
						name: "missing encrypted master key",
						state: walletstore.State{
							WalletType:        hdwallet.Type,
							EncryptedMnemonic: "encryptedMnemonic",
						},
						wantErrContains: "missing encrypted master key",
					},
					{
						name: "missing encrypted mnemonic",
						state: walletstore.State{
							WalletType:         hdwallet.Type,
							EncryptedMasterKey: "encryptedMasterKey",
						},
						wantErrContains: "missing encrypted mnemonic",
					},
				}

				for _, f := range fixtures {
					t.Run(f.name, func(t *testing.T) {
						s := newStore(t, impl)
						err := s.Save(t.Context(), f.state)
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
					require.NoError(t, s.Save(t.Context(), validState))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Equal(t, validState, *loaded)
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
					require.NoError(t, s.Save(t.Context(), validState))
					require.NoError(t, s.Clear(t.Context()))

					loaded, err := s.Load(t.Context())
					require.NoError(t, err)
					require.Nil(t, loaded)
				})
			})
		})
	}
}

func newStore(t *testing.T, impl string) walletstore.Store {
	t.Helper()
	switch impl {
	case types.InMemoryStore:
		return inmemorywalletstore.NewStore()
	case types.FileStore:
		s, err := filewalletstore.NewStore(t.TempDir())
		require.NoError(t, err)
		return s
	}
	t.Fatalf("unknown store impl: %s", impl)
	return nil
}
