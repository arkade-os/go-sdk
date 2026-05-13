package identity

import (
	"encoding/hex"
	"sync"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/identity/store"
	"github.com/arkade-os/go-sdk/identity/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

var network = chaincfg.RegressionNetParams

const (
	testPassword = "testpassword"
	testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
)

func TestCreate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("without mnemonic", func(t *testing.T) {
			svc := newIdentity(t, identityinmemorystore.NewStore())
			seed, err := svc.Create(t.Context(), network, testPassword, "")
			require.NoError(t, err)
			require.NotEmpty(t, seed)
			require.True(t, bip39.IsMnemonicValid(seed))
			require.True(t, svc.IsLocked())
		})

		t.Run("with mnemonic", func(t *testing.T) {
			svc := newIdentity(t, identityinmemorystore.NewStore())
			seed, err := svc.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)
			require.Equal(t, testMnemonic, seed)
			require.True(t, svc.IsLocked())
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			setup           func(t *testing.T) identity.Identity
			seed            string
			wantErrContains string
		}{
			{
				setup: func(t *testing.T) identity.Identity {
					return newIdentity(t, identityinmemorystore.NewStore())
				},
				seed:            "not a valid mnemonic",
				wantErrContains: "invalid mnemonic",
			},
			{
				setup:           newInitializedIdentity,
				seed:            "",
				wantErrContains: ErrAlreadyInitialized.Error(),
			},
		}

		for _, f := range fixtures {
			svc := f.setup(t)
			_, err := svc.Create(t.Context(), network, testPassword, f.seed)
			require.ErrorContains(t, err, f.wantErrContains)
		}
	})
}

func TestUnlock(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("after create", func(t *testing.T) {
			svc := newInitializedIdentity(t)
			require.True(t, svc.IsLocked())

			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())

			// Idempotent on an already-unlocked identity.
			restored, err = svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())
		})

		t.Run("cold start", func(t *testing.T) {
			store := identityinmemorystore.NewStore()
			seeder := newIdentity(t, store)
			_, err := seeder.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)

			svc := newIdentity(t, store)
			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())
		})

		t.Run("restored", func(t *testing.T) {
			store := identityinmemorystore.NewStore()
			seeder := newIdentity(t, store)
			_, err := seeder.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)
			_, err = seeder.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			_, err = seeder.NewKey(t.Context())
			require.NoError(t, err)
			_, err = seeder.NewKey(t.Context())
			require.NoError(t, err)

			svc := newIdentity(t, store)
			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.True(t, restored)
		})

		t.Run("locked identity", func(t *testing.T) {
			svc := newInitializedIdentity(t)
			require.True(t, svc.IsLocked())

			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())

			err = svc.Lock(t.Context())
			require.NoError(t, err)
			require.True(t, svc.IsLocked())

			restored, err = svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())

			err = svc.Lock(t.Context())
			require.NoError(t, err)
			require.True(t, svc.IsLocked())

			restored, err = svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			password        string
			wantErrContains string
		}{
			{
				name:            "invalid password",
				setup:           newInitializedIdentity,
				password:        "wrong",
				wantErrContains: "invalid password",
			},
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					svc := newIdentity(t, identityinmemorystore.NewStore())
					return svc
				},
				password:        testPassword,
				wantErrContains: ErrNotInitialized.Error(),
			},
			{
				name: "wrong identity type",
				setup: func(t *testing.T) identity.Identity {
					store := identityinmemorystore.NewStore()
					require.NoError(t, store.Save(t.Context(), identitystore.IdentityData{
						Type:                 "lnd",
						EncryptedExtendedKey: "deadbeef",
						EncryptedMnemonic:    "deadbeef",
					}))
					return newIdentity(t, store)
				},
				password:        testPassword,
				wantErrContains: "persisted data is not for this identity",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc := f.setup(t)
				_, err := svc.Unlock(t.Context(), f.password)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestLock(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		require.NoError(t, svc.Lock(t.Context()))
		require.True(t, svc.IsLocked())

		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)
		require.False(t, svc.IsLocked())

		require.NoError(t, svc.Lock(t.Context()))
		require.True(t, svc.IsLocked())

		require.NoError(t, svc.Lock(t.Context()))
		require.True(t, svc.IsLocked())

		// Post-Lock the identity must still be unlockable from the persisted store.
		_, err = svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)
		require.False(t, svc.IsLocked())
	})

	t.Run("zeroes in-memory mnemonic", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		concrete := svc.(*service)
		// Capture an alias to the underlying mnemonic storage so we can verify
		// the backing memory is wiped after Lock.
		captured := concrete.mnemonic
		require.NotEmpty(t, captured)

		require.NoError(t, svc.Lock(t.Context()))

		for i, b := range captured {
			require.Zerof(t, b, "captured mnemonic byte %d not zeroed", i)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			wantErrContains string
		}{
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					svc := newIdentity(t, identityinmemorystore.NewStore())
					return svc
				},
				wantErrContains: ErrNotInitialized.Error(),
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc := f.setup(t)
				err := svc.Lock(t.Context())
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestDump(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("after unlock", func(t *testing.T) {
			svc := newInitializedIdentity(t)
			_, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			dumped, err := svc.Dump(t.Context())
			require.NoError(t, err)
			require.Equal(t, testMnemonic, dumped)
		})

		t.Run("after cold start", func(t *testing.T) {
			store := identityinmemorystore.NewStore()
			seeder := newIdentity(t, store)
			_, err := seeder.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)

			svc := newIdentity(t, store)
			_, err = svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			dumped, err := svc.Dump(t.Context())
			require.NoError(t, err)
			require.Equal(t, testMnemonic, dumped)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			wantErrContains string
		}{
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					return newIdentity(t, identityinmemorystore.NewStore())
				},
				wantErrContains: ErrNotInitialized.Error(),
			},
			{
				name: "identity is locked",
				setup: func(t *testing.T) identity.Identity {
					return newInitializedIdentity(t)
				},
				wantErrContains: ErrIsLocked.Error(),
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc := f.setup(t)
				_, err := svc.Dump(t.Context())
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestNewKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		store := identityinmemorystore.NewStore()
		svc := newIdentity(t, store)
		_, err := svc.Create(t.Context(), network, testPassword, testMnemonic)
		require.NoError(t, err)
		_, err = svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		first, err := svc.NewKey(t.Context())
		require.NoError(t, err)
		require.Equal(t, "m/0/0", first.Id)

		second, err := svc.NewKey(t.Context())
		require.NoError(t, err)
		require.Equal(t, "m/0/1", second.Id)

		require.NotEqual(
			t, first.PubKey.SerializeCompressed(), second.PubKey.SerializeCompressed(),
		)

		data, err := store.Load(t.Context())
		require.NoError(t, err)
		require.EqualValues(t, 2, data.NextIndex)
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			wantErrContains string
		}{
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					return newIdentity(t, identityinmemorystore.NewStore())
				},
				wantErrContains: ErrNotInitialized.Error(),
			},
			{
				name: "identity is locked",
				setup: func(t *testing.T) identity.Identity {
					return newInitializedIdentity(t)
				},
				wantErrContains: ErrIsLocked.Error(),
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc := f.setup(t)
				_, err := svc.NewKey(t.Context())
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestGetKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		allocated, err := svc.NewKey(t.Context())
		require.NoError(t, err)

		t.Run("by key id", func(t *testing.T) {
			resolved, err := svc.GetKey(t.Context(), allocated.Id)
			require.NoError(t, err)
			require.Equal(t, allocated.Id, resolved.Id)
			require.Equal(
				t,
				allocated.PubKey.SerializeCompressed(),
				resolved.PubKey.SerializeCompressed(),
			)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			id              string
			wantErrContains string
		}{
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					return newIdentity(t, identityinmemorystore.NewStore())
				},
				id:              "m/0/0",
				wantErrContains: ErrNotInitialized.Error(),
			},
			{
				name: "identity is locked",
				setup: func(t *testing.T) identity.Identity {
					return newInitializedIdentity(t)
				},
				id:              "m/0/0",
				wantErrContains: ErrIsLocked.Error(),
			},
			{
				name: "missing key id",
				setup: func(t *testing.T) identity.Identity {
					svc := newInitializedIdentity(t)
					_, err := svc.Unlock(t.Context(), testPassword)
					require.NoError(t, err)
					return svc
				},
				id:              "",
				wantErrContains: "key id is required",
			},
			{
				name: "hardened key id",
				setup: func(t *testing.T) identity.Identity {
					svc := newInitializedIdentity(t)
					_, err := svc.Unlock(t.Context(), testPassword)
					require.NoError(t, err)
					return svc
				},
				id:              "m/0'/0",
				wantErrContains: "forbidden hardened index",
			},
			{
				name: "malformed key id",
				setup: func(t *testing.T) identity.Identity {
					svc := newInitializedIdentity(t)
					_, err := svc.Unlock(t.Context(), testPassword)
					require.NoError(t, err)
					return svc
				},
				id:              "m/0/abd",
				wantErrContains: "failed to parse derivation index",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc := f.setup(t)
				_, err := svc.GetKey(t.Context(), f.id)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestNextKeyId(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		// Empty input is the documented "official" way for callers (e.g. the
		// contract manager on a fresh wallet) to obtain the very first key id
		// without knowing the derivation format. It must NOT error.
		t.Run("empty id returns first key id", func(t *testing.T) {
			next, err := svc.NextKeyId(t.Context(), "")
			require.NoError(t, err)
			require.Equal(t, "m/0/0", next)
		})

		t.Run("advances trailing index by one", func(t *testing.T) {
			fixtures := []struct {
				in   string
				want string
			}{
				{in: "m/0/0", want: "m/0/1"},
				{in: "m/0/5", want: "m/0/6"},
				{in: "m/0/41", want: "m/0/42"},
			}
			for _, f := range fixtures {
				next, err := svc.NextKeyId(t.Context(), f.in)
				require.NoError(t, err)
				require.Equal(t, f.want, next)
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		fixtures := []struct {
			name            string
			id              string
			wantErrContains string
		}{
			{
				name:            "hardened key id",
				id:              "m/0'/0",
				wantErrContains: "forbidden hardened index",
			},
			{
				name:            "malformed key id",
				id:              "m/0/notanumber",
				wantErrContains: "failed to parse derivation index",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				_, err := svc.NextKeyId(t.Context(), f.id)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestGetKeyIndex(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		// Empty input pairs with NextKeyId's empty-input behavior so the
		// contract manager can compute startIdx without special-casing the
		// "no contracts yet" branch.
		t.Run("empty id returns zero", func(t *testing.T) {
			idx, err := svc.GetKeyIndex(t.Context(), "")
			require.NoError(t, err)
			require.Equal(t, uint32(0), idx)
		})

		t.Run("returns trailing path index", func(t *testing.T) {
			fixtures := []struct {
				in   string
				want uint32
			}{
				{in: "m/0/0", want: 0},
				{in: "m/0/1", want: 1},
				{in: "m/0/42", want: 42},
			}
			for _, f := range fixtures {
				got, err := svc.GetKeyIndex(t.Context(), f.in)
				require.NoError(t, err)
				require.Equal(t, f.want, got)
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		svc := newInitializedIdentity(t)
		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		fixtures := []struct {
			name            string
			id              string
			wantErrContains string
		}{
			{
				name:            "hardened key id",
				id:              "m/0'/0",
				wantErrContains: "forbidden hardened index",
			},
			{
				name:            "malformed key id",
				id:              "m/0/notanumber",
				wantErrContains: "failed to parse derivation index",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				_, err := svc.GetKeyIndex(t.Context(), f.id)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestListKeys(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("no allocations", func(t *testing.T) {
			svc := newInitializedIdentity(t)
			_, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			keys, err := svc.ListKeys(t.Context())
			require.NoError(t, err)
			require.Empty(t, keys)
		})

		t.Run("after allocations sorted", func(t *testing.T) {
			svc := newInitializedIdentity(t)
			_, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			first, err := svc.NewKey(t.Context())
			require.NoError(t, err)
			second, err := svc.NewKey(t.Context())
			require.NoError(t, err)
			third, err := svc.NewKey(t.Context())
			require.NoError(t, err)

			keys, err := svc.ListKeys(t.Context())
			require.NoError(t, err)
			require.Len(t, keys, 3)
			require.Equal(t, first.Id, keys[0].Id)
			require.Equal(t, second.Id, keys[1].Id)
			require.Equal(t, third.Id, keys[2].Id)
			require.True(t, keys[0].Id < keys[1].Id)
			require.True(t, keys[1].Id < keys[2].Id)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			wantErrContains string
		}{
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					return newIdentity(t, identityinmemorystore.NewStore())
				},
				wantErrContains: ErrNotInitialized.Error(),
			},
			{
				name:            "identity is locked",
				setup:           newInitializedIdentity,
				wantErrContains: ErrIsLocked.Error(),
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				svc := f.setup(t)
				_, err := svc.ListKeys(t.Context())
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestSignMessage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		svc := newInitializedIdentity(t)

		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)

		msg := make([]byte, 32)
		copy(msg, []byte("hello"))

		sig1, err := svc.SignMessage(t.Context(), msg)
		require.NoError(t, err)
		sig2, err := svc.SignMessage(t.Context(), msg)
		require.NoError(t, err)
		require.Equal(t, sig1, sig2)

		// Different message → different signature.
		other := make([]byte, 32)
		copy(other, []byte("world"))
		sigOther, err := svc.SignMessage(t.Context(), other)
		require.NoError(t, err)
		require.NotEqual(t, sig1, sigOther)

		// Verify the signature was produced by the documented fixed key m/0/0.
		signingKey, err := svc.GetKey(t.Context(), "m/0/0")
		require.NoError(t, err)

		sigBytes, err := hex.DecodeString(sig1)
		require.NoError(t, err)
		parsedSig, err := schnorr.ParseSignature(sigBytes)
		require.NoError(t, err)
		require.True(t, parsedSig.Verify(msg, signingKey.PubKey))
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) identity.Identity
			msg             []byte
			wantErrContains string
		}{
			{
				name: "identity not initialized",
				setup: func(t *testing.T) identity.Identity {
					return newIdentity(t, identityinmemorystore.NewStore())
				},
				msg:             make([]byte, 32),
				wantErrContains: ErrNotInitialized.Error(),
			},
			{
				name:            "identity is locked",
				setup:           newInitializedIdentity,
				msg:             make([]byte, 32),
				wantErrContains: ErrIsLocked.Error(),
			},
		}

		for _, f := range fixtures {
			svc := f.setup(t)
			_, err := svc.SignMessage(t.Context(), f.msg)
			require.ErrorContains(t, err, f.wantErrContains)
		}
	})
}

func TestGetType(t *testing.T) {
	svc := newIdentity(t, identityinmemorystore.NewStore())
	require.Equal(t, Type, svc.GetType())
}

func TestIsLocked(t *testing.T) {
	svc := newInitializedIdentity(t)
	require.True(t, svc.IsLocked())

	_, err := svc.Unlock(t.Context(), testPassword)
	require.NoError(t, err)
	require.False(t, svc.IsLocked())

	require.NoError(t, svc.Lock(t.Context()))
	require.True(t, svc.IsLocked())
}

func TestNewVtxoTreeSigner(t *testing.T) {
	svc := newIdentity(t, identityinmemorystore.NewStore())

	first, err := svc.NewVtxoTreeSigner(t.Context())
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := svc.NewVtxoTreeSigner(t.Context())
	require.NoError(t, err)
	require.NotNil(t, second)

	require.NotSame(t, first, second)
}

// TestServiceConcurrentAccess exercises the *service wrapper under
// concurrent NewKey/GetKey/SignMessage/ListKeys calls. The keyService has
// its own concurrency test, but the service wrapper has its own RWMutex
// and runs additional logic (persistState, safeCheck) that must also be
// race-safe.
func TestServiceConcurrentAccess(t *testing.T) {
	svc := newInitializedIdentity(t)
	_, err := svc.Unlock(t.Context(), testPassword)
	require.NoError(t, err)

	const allocs = 50
	const reads = 100
	msg := make([]byte, 32)
	copy(msg, []byte("concurrent"))

	var wg sync.WaitGroup
	wg.Add(allocs + reads*3)

	for i := 0; i < allocs; i++ {
		go func() {
			defer wg.Done()
			_, err := svc.NewKey(t.Context())
			require.NoError(t, err)
		}()
	}
	for i := 0; i < reads; i++ {
		go func() {
			defer wg.Done()
			_, err := svc.ListKeys(t.Context())
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			_, err := svc.SignMessage(t.Context(), msg)
			require.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			require.False(t, svc.IsLocked())
		}()
	}

	wg.Wait()

	keys, err := svc.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, allocs)
}

func newMasterKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	seed := bip39.NewSeed(testMnemonic, "")
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	return masterKey
}

func newIdentity(t *testing.T, store identitystore.IdentityStore) identity.Identity {
	t.Helper()
	svc, err := NewIdentity(store)
	require.NoError(t, err)
	return svc
}

func newInitializedIdentity(t *testing.T) identity.Identity {
	t.Helper()
	svc := newIdentity(t, identityinmemorystore.NewStore())
	_, err := svc.Create(t.Context(), network, testPassword, testMnemonic)
	require.NoError(t, err)
	return svc
}
