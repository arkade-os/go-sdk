package identity

import (
	"encoding/hex"
	"sync"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	identitystore "github.com/arkade-os/go-sdk/identity/store"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/stretchr/testify/require"
)

func TestKeyServiceGetXpub(t *testing.T) {
	t.Run("is the neutered account key", func(t *testing.T) {
		master := newMasterKey(t)
		provider := newHDKeyService(master)

		xpub, err := provider.GetXpub()
		require.NoError(t, err)
		require.NotEmpty(t, xpub)

		extKey, err := hdkeychain.NewKeyFromString(xpub)
		require.NoError(t, err)
		// The xpub must be public-only: deriving a child of a private extended key keeps it
		// private, so serializing it would leak the account xprv.
		require.False(t, extKey.IsPrivate())

		// It must equal the neutered account node (master/defaultAccount).
		account, err := master.Derive(defaultAccount)
		require.NoError(t, err)
		neutered, err := account.Neuter()
		require.NoError(t, err)
		require.Equal(t, neutered.String(), xpub)
	})

	t.Run("children match the derived keys", func(t *testing.T) {
		provider := newHDKeyService(newMasterKey(t))

		xpub, err := provider.GetXpub()
		require.NoError(t, err)
		extKey, err := hdkeychain.NewKeyFromString(xpub)
		require.NoError(t, err)

		// A third party (eg. Boltz swap restore) must be able to derive our keys from the xpub
		// alone: xpub/i has to equal the private key derived at m/0/i.
		for _, index := range []uint32{0, 1, 7, 42} {
			child, err := extKey.Derive(index)
			require.NoError(t, err)
			childPubKey, err := child.ECPubKey()
			require.NoError(t, err)

			priv, err := provider.DeriveKeyAt(toDerivationPath(index))
			require.NoError(t, err)
			require.Equal(t,
				hex.EncodeToString(priv.PubKey().SerializeCompressed()),
				hex.EncodeToString(childPubKey.SerializeCompressed()),
			)
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		provider := newHDKeyService(newMasterKey(t))

		first, err := provider.GetXpub()
		require.NoError(t, err)
		second, err := provider.GetXpub()
		require.NoError(t, err)
		require.Equal(t, first, second)
	})
}

func TestDeriveKeyAt(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("deterministic", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))

			priv1, err := provider.DeriveKeyAt("m/0/0")
			require.NoError(t, err)
			require.NotNil(t, priv1)

			priv2, err := provider.DeriveKeyAt("m/0/0")
			require.NoError(t, err)
			require.Equal(t,
				hex.EncodeToString(priv1.Serialize()),
				hex.EncodeToString(priv2.Serialize()),
			)
		})

		t.Run("different indices", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))

			priv0, err := provider.DeriveKeyAt("m/0/0")
			require.NoError(t, err)
			priv5, err := provider.DeriveKeyAt("m/0/5")
			require.NoError(t, err)
			require.NotEqual(t,
				hex.EncodeToString(priv0.Serialize()),
				hex.EncodeToString(priv5.Serialize()),
			)
		})

		t.Run("ids idempotency", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))

			ids := []string{"5", "0/5", "m/5", "m/0/5"}
			derivedKeys := make(map[string]struct{})
			for _, id := range ids {
				key, err := provider.DeriveKeyAt(id)
				require.NoError(t, err)
				require.NotNil(t, key)
				derivedKeys[hex.EncodeToString(key.Serialize())] = struct{}{}
			}
			require.Len(t, derivedKeys, 1)
		})

		t.Run("ignores custom chain in derivation path", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))

			ids := []string{"m/0/5", "m/1/5", "m/2/5"}
			derivedKeys := make(map[string]struct{})
			for _, id := range ids {
				key, err := provider.DeriveKeyAt(id)
				require.NoError(t, err)
				require.NotNil(t, key)
				derivedKeys[hex.EncodeToString(key.Serialize())] = struct{}{}
			}
			require.Len(t, derivedKeys, 1)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			keyId           string
			wantErrContains string
		}{
			{
				name:            "empty id",
				keyId:           "",
				wantErrContains: "key id is required",
			},
			{
				name:            "hardened path",
				keyId:           "m/0'/0",
				wantErrContains: "forbidden hardened index",
			},
			{
				name:            "malformed path",
				keyId:           "m/0/abc",
				wantErrContains: "failed to parse derivation index",
			},
		}

		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				provider := newHDKeyService(newMasterKey(t))
				_, err := provider.DeriveKeyAt(f.keyId)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestGetNextKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		provider := newHDKeyService(newMasterKey(t))

		priv0, _, keyId0, err := provider.GetNextKey()
		require.NoError(t, err)
		require.Equal(t, "m/0/0", keyId0)
		require.EqualValues(t, 1, provider.GetNextKeyIndex())

		priv1, _, keyId1, err := provider.GetNextKey()
		require.NoError(t, err)
		require.Equal(t, "m/0/1", keyId1)
		require.EqualValues(t, 2, provider.GetNextKeyIndex())

		// The key at index N matches DeriveKeyAt("m/0/N").
		derivedAt0, err := provider.DeriveKeyAt("m/0/0")
		require.NoError(t, err)
		require.Equal(t,
			hex.EncodeToString(priv0.Serialize()),
			hex.EncodeToString(derivedAt0.Serialize()),
		)
		derivedAt1, err := provider.DeriveKeyAt("m/0/1")
		require.NoError(t, err)
		require.Equal(t,
			hex.EncodeToString(priv1.Serialize()),
			hex.EncodeToString(derivedAt1.Serialize()),
		)

		// Allocated keys appear in GetAllKeyRefs.
		require.ElementsMatch(t,
			[]string{"m/0/0", "m/0/1"},
			keyRefIds(provider.GetAllKeyRefs()),
		)
	})
}

func TestGetNextKeyIndex(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("initial", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			require.EqualValues(t, 0, provider.GetNextKeyIndex())
		})

		t.Run("after allocations", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			for i := 0; i < 3; i++ {
				_, _, _, err := provider.GetNextKey()
				require.NoError(t, err)
			}
			require.EqualValues(t, 3, provider.GetNextKeyIndex())
		})

		t.Run("after load data", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			require.NoError(t, provider.LoadState(identitystore.IdentityData{NextIndex: 7}))
			require.EqualValues(t, 7, provider.GetNextKeyIndex())
		})
	})
}

func TestGetAllKeyRefs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("empty", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			require.Empty(t, provider.GetAllKeyRefs())
		})

		t.Run("after get next key", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			_, _, _, err := provider.GetNextKey()
			require.NoError(t, err)
			_, _, _, err = provider.GetNextKey()
			require.NoError(t, err)

			require.ElementsMatch(t,
				[]string{"m/0/0", "m/0/1"},
				keyRefIds(provider.GetAllKeyRefs()),
			)
		})

		t.Run("after derive key at", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			_, err := provider.DeriveKeyAt("m/0/3")
			require.NoError(t, err)

			refs := provider.GetAllKeyRefs()
			require.Empty(t, refs)
		})
	})
}

func TestLoadData(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("sets next index", func(t *testing.T) {
			provider := newHDKeyService(newMasterKey(t))
			require.NoError(t, provider.LoadState(identitystore.IdentityData{NextIndex: 12}))
			require.EqualValues(t, 12, provider.GetNextKeyIndex())
		})
	})
}

func TestConcurrentKeyGeneration(t *testing.T) {
	provider := newHDKeyService(newMasterKey(t))

	var wg sync.WaitGroup
	count := 100
	wg.Add(count)

	for i := 0; i < count; i++ {
		go func() {
			defer wg.Done()
			if _, _, _, err := provider.GetNextKey(); err != nil {
				t.Errorf("concurrent key generation failed: %v", err)
			}
		}()
	}
	wg.Wait()

	require.EqualValues(t, count, provider.GetNextKeyIndex())
}

func keyRefIds(refs []identity.KeyRef) []string {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.Id)
	}
	return ids
}
