package hdwallet

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	walletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store"
	inmemorywalletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store/inmemory"
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
			svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())
			seed, err := svc.Create(t.Context(), network, testPassword, "")
			require.NoError(t, err)
			require.NotEmpty(t, seed)
			require.True(t, bip39.IsMnemonicValid(seed))
			require.True(t, svc.IsLocked())
		})

		t.Run("with mnemonic", func(t *testing.T) {
			svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())
			seed, err := svc.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)
			require.Equal(t, testMnemonic, seed)
			require.True(t, svc.IsLocked())
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			setup           func(t *testing.T) wallet.WalletService
			seed            string
			wantErrContains string
		}{
			{
				setup: func(t *testing.T) wallet.WalletService {
					return newTestHDWalletService(t, inmemorywalletstore.NewStore())
				},
				seed:            "not a valid mnemonic",
				wantErrContains: "invalid mnemonic",
			},
			{
				setup:           newTestCreatedWallet,
				seed:            "",
				wantErrContains: "wallet already initialized",
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
			svc := newTestCreatedWallet(t)
			require.True(t, svc.IsLocked())

			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())

			// Idempotent on an already-unlocked wallet.
			restored, err = svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())
		})

		t.Run("cold start", func(t *testing.T) {
			store := inmemorywalletstore.NewStore()
			seeder := newTestHDWalletService(t, store)
			_, err := seeder.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)

			svc := newTestHDWalletService(t, store)
			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.False(t, restored)
			require.False(t, svc.IsLocked())
		})

		t.Run("restored", func(t *testing.T) {
			store := inmemorywalletstore.NewStore()
			seeder := newTestHDWalletService(t, store)
			_, err := seeder.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)
			_, err = seeder.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			_, err = seeder.NewKey(t.Context())
			require.NoError(t, err)
			_, err = seeder.NewKey(t.Context())
			require.NoError(t, err)

			svc := newTestHDWalletService(t, store)
			restored, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)
			require.True(t, restored)
		})

		t.Run("locked wallet", func(t *testing.T) {
			svc := newTestCreatedWallet(t)
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
			setup           func(t *testing.T) wallet.WalletService
			password        string
			wantErrContains string
		}{
			{
				name:            "invalid password",
				setup:           newTestCreatedWallet,
				password:        "wrong",
				wantErrContains: "invalid password",
			},
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())
					return svc
				},
				password:        testPassword,
				wantErrContains: "wallet not initialized",
			},
			{
				name: "wrong wallet type",
				setup: func(t *testing.T) wallet.WalletService {
					store := inmemorywalletstore.NewStore()
					require.NoError(t, store.Save(t.Context(), walletstore.State{
						WalletType:         "lnd",
						EncryptedMasterKey: "deadbeef",
						EncryptedMnemonic:  "deadbeef",
						PasswordHash:       "deadbeef",
					}))
					return newTestHDWalletService(t, store)
				},
				password:        testPassword,
				wantErrContains: "store is not for HD wallet type",
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
		svc := newTestCreatedWallet(t)
		require.NoError(t, svc.Lock(t.Context()))
		require.True(t, svc.IsLocked())

		_, err := svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)
		require.False(t, svc.IsLocked())

		require.NoError(t, svc.Lock(t.Context()))
		require.True(t, svc.IsLocked())

		require.NoError(t, svc.Lock(t.Context()))
		require.True(t, svc.IsLocked())

		// Post-Lock the wallet must still be unlockable from the persisted store.
		_, err = svc.Unlock(t.Context(), testPassword)
		require.NoError(t, err)
		require.False(t, svc.IsLocked())
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) wallet.WalletService
			wantErrContains string
		}{
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())
					return svc
				},
				wantErrContains: "wallet not initialized",
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
			svc := newTestCreatedWallet(t)
			_, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			dumped, err := svc.Dump(t.Context())
			require.NoError(t, err)
			require.Equal(t, testMnemonic, dumped)
		})

		t.Run("after cold start", func(t *testing.T) {
			store := inmemorywalletstore.NewStore()
			seeder := newTestHDWalletService(t, store)
			_, err := seeder.Create(t.Context(), network, testPassword, testMnemonic)
			require.NoError(t, err)

			svc := newTestHDWalletService(t, store)
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
			setup           func(t *testing.T) wallet.WalletService
			wantErrContains string
		}{
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestHDWalletService(t, inmemorywalletstore.NewStore())
				},
				wantErrContains: "wallet not initialized",
			},
			{
				name: "wallet is locked",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestCreatedWallet(t)
				},
				wantErrContains: "wallet is locked",
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
		store := inmemorywalletstore.NewStore()
		svc := newTestHDWalletService(t, store)
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

		state, err := store.Load(t.Context())
		require.NoError(t, err)
		require.EqualValues(t, 2, state.NextIndex)
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) wallet.WalletService
			wantErrContains string
		}{
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestHDWalletService(t, inmemorywalletstore.NewStore())
				},
				wantErrContains: "wallet not initalized",
			},
			{
				name: "wallet is locked",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestCreatedWallet(t)
				},
				wantErrContains: "wallet is locked",
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
		svc := newTestCreatedWallet(t)
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
			setup           func(t *testing.T) wallet.WalletService
			id              string
			wantErrContains string
		}{
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestHDWalletService(t, inmemorywalletstore.NewStore())
				},
				id:              "m/0/0",
				wantErrContains: "wallet not initalized",
			},
			{
				name: "wallet is locked",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestCreatedWallet(t)
				},
				id:              "m/0/0",
				wantErrContains: "wallet is locked",
			},
			{
				name: "missing key id",
				setup: func(t *testing.T) wallet.WalletService {
					svc := newTestCreatedWallet(t)
					_, err := svc.Unlock(t.Context(), testPassword)
					require.NoError(t, err)
					return svc
				},
				id:              "",
				wantErrContains: "key id is required",
			},
			{
				name: "hardened key id",
				setup: func(t *testing.T) wallet.WalletService {
					svc := newTestCreatedWallet(t)
					_, err := svc.Unlock(t.Context(), testPassword)
					require.NoError(t, err)
					return svc
				},
				id:              "m/0'/0",
				wantErrContains: "forbidden hardened index",
			},
			{
				name: "malformed key id",
				setup: func(t *testing.T) wallet.WalletService {
					svc := newTestCreatedWallet(t)
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

func TestListKeys(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("no allocations", func(t *testing.T) {
			svc := newTestCreatedWallet(t)
			_, err := svc.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			keys, err := svc.ListKeys(t.Context())
			require.NoError(t, err)
			require.Empty(t, keys)
		})

		t.Run("after allocations sorted", func(t *testing.T) {
			svc := newTestCreatedWallet(t)
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
			setup           func(t *testing.T) wallet.WalletService
			wantErrContains string
		}{
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestHDWalletService(t, inmemorywalletstore.NewStore())
				},
				wantErrContains: "wallet not initalized",
			},
			{
				name:            "wallet is locked",
				setup:           newTestCreatedWallet,
				wantErrContains: "wallet is locked",
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
		svc := newTestCreatedWallet(t)

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
		signingKey, err := svc.(*service).keyProvider.DeriveKeyAt("m/0/0")
		require.NoError(t, err)

		sigBytes, err := hex.DecodeString(sig1)
		require.NoError(t, err)
		parsedSig, err := schnorr.ParseSignature(sigBytes)
		require.NoError(t, err)
		require.True(t, parsedSig.Verify(msg, signingKey.PubKey()))
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			setup           func(t *testing.T) wallet.WalletService
			msg             []byte
			wantErrContains string
		}{
			{
				name: "wallet not initialized",
				setup: func(t *testing.T) wallet.WalletService {
					return newTestHDWalletService(t, inmemorywalletstore.NewStore())
				},
				msg:             make([]byte, 32),
				wantErrContains: "wallet not initalized",
			},
			{
				name:            "wallet is locked",
				setup:           newTestCreatedWallet,
				msg:             make([]byte, 32),
				wantErrContains: "wallet is locked",
			},
		}

		for _, f := range fixtures {
			svc := f.setup(t)
			_, err := svc.SignMessage(t.Context(), f.msg)
			require.ErrorContains(t, err, f.wantErrContains)
		}
	})
}

func TestEncryption(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		plaintext := []byte("test secret data")
		password := []byte("mypassword")

		encrypted, err := encryptAES256(plaintext, password)
		require.NoError(t, err)

		decrypted, err := decryptAES256(encrypted, password)
		require.NoError(t, err)
		require.Equal(t, plaintext, decrypted)

		// Same plaintext+password must produce a different ciphertext (random salt).
		encryptedAgain, err := encryptAES256(plaintext, password)
		require.NoError(t, err)
		require.NotEqual(t, encrypted, encryptedAgain)
	})

	t.Run("invalid", func(t *testing.T) {
		rightCiphertext, err := encryptAES256([]byte("plaintext"), []byte("mypassword"))
		require.NoError(t, err)

		fixtures := []struct {
			name            string
			ciphertext      []byte
			password        []byte
			wantErrContains string
		}{
			{
				name:            "missing data",
				ciphertext:      nil,
				password:        []byte("mypassword"),
				wantErrContains: "missing encrypted data",
			},
			{
				name:            "missing password",
				ciphertext:      []byte("nonempty"),
				password:        nil,
				wantErrContains: "missing password",
			},
			{
				name:            "wrong data lenght",
				ciphertext:      []byte("short"),
				password:        []byte("mypassword"),
				wantErrContains: "encrypted data too short",
			},
			{
				name:            "wrong password",
				ciphertext:      rightCiphertext,
				password:        []byte("nottherightpassword"),
				wantErrContains: "invalid password",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				_, err := decryptAES256(f.ciphertext, f.password)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestGetType(t *testing.T) {
	svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())
	require.Equal(t, Type, svc.GetType())
}

func TestIsLocked(t *testing.T) {
	svc := newTestCreatedWallet(t)
	require.True(t, svc.IsLocked())

	_, err := svc.Unlock(t.Context(), testPassword)
	require.NoError(t, err)
	require.False(t, svc.IsLocked())

	require.NoError(t, svc.Lock(t.Context()))
	require.True(t, svc.IsLocked())
}

func TestNewVtxoTreeSigner(t *testing.T) {
	svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())

	first, err := svc.NewVtxoTreeSigner(t.Context())
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := svc.NewVtxoTreeSigner(t.Context())
	require.NoError(t, err)
	require.NotNil(t, second)

	require.NotSame(t, first, second)
}

func createTestMasterKey(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	seed := bip39.NewSeed(testMnemonic, "")
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	return masterKey
}

func newTestHDWalletService(t *testing.T, store walletstore.Store) wallet.WalletService {
	t.Helper()
	svc, err := NewService(store)
	require.NoError(t, err)
	return svc
}

func newTestCreatedWallet(t *testing.T) wallet.WalletService {
	t.Helper()
	svc := newTestHDWalletService(t, inmemorywalletstore.NewStore())
	_, err := svc.Create(t.Context(), network, testPassword, testMnemonic)
	require.NoError(t, err)
	return svc
}
