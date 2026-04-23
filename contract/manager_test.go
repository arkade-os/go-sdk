package contract_test

import (
	"context"
	"fmt"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// mockKeystore is a fake Keystore backed by a fixed private key.
type mockKeystore struct {
	key *wallet.KeyRef
}

func newMockKeystore(t *testing.T) *mockKeystore {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return &mockKeystore{
		key: &wallet.KeyRef{Id: "test-key-id", PubKey: priv.PubKey()},
	}
}

func (m *mockKeystore) NewKey(_ context.Context, _ ...wallet.KeyOption) (*wallet.KeyRef, error) {
	return m.key, nil
}

func (m *mockKeystore) GetKey(_ context.Context, _ ...wallet.KeyOption) (*wallet.KeyRef, error) {
	return m.key, nil
}

func (m *mockKeystore) ListKeys(_ context.Context) ([]wallet.KeyRef, error) {
	return []wallet.KeyRef{*m.key}, nil
}

func testConfig(t *testing.T) *clientTypes.Config {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return &clientTypes.Config{
		SignerPubKey: priv.PubKey(),
		Network:      arklib.BitcoinRegTest,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 144,
		},
		BoardingExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 1008,
		},
	}
}

func TestManager_Bootstrap(t *testing.T) {
	t.Parallel()

	t.Run("Load populates contracts for existing keys", func(t *testing.T) {
		t.Parallel()
		ks := newMockKeystore(t)
		mgr := contract.NewManager(ks, testConfig(t), nil)
		require.NoError(t, mgr.Load(context.Background()))

		contracts, err := mgr.GetContracts(context.Background(), contract.Filter{})
		require.NoError(t, err)
		// One key → three contracts: offchain, boarding, onchain.
		require.Len(t, contracts, 3)
		types := make(map[string]bool, 3)
		for _, c := range contracts {
			types[c.Type] = true
		}
		require.True(t, types[contract.TypeDefault])
		require.True(t, types[contract.TypeDefaultBoarding])
		require.True(t, types[contract.TypeDefaultOnchain])
	})

	t.Run("Load with no keys is a no-op", func(t *testing.T) {
		t.Parallel()
		mgr := contract.NewManager(&emptyKeystore{}, testConfig(t), nil)
		require.NoError(t, mgr.Load(context.Background()))

		contracts, err := mgr.GetContracts(context.Background(), contract.Filter{})
		require.NoError(t, err)
		require.Empty(t, contracts)
	})
}

func TestManager_NewDefault(t *testing.T) {
	t.Parallel()

	t.Run("NewDefault creates contract and persists it", func(t *testing.T) {
		t.Parallel()
		ks := newMockKeystore(t)
		mgr := contract.NewManager(ks, testConfig(t), nil)

		c, err := mgr.NewDefault(context.Background())
		require.NoError(t, err)
		require.Equal(t, contract.TypeDefault, c.Type)
		require.Equal(t, contract.StateActive, c.State)

		all, err := mgr.GetContracts(context.Background(), contract.Filter{})
		require.NoError(t, err)
		require.Len(t, all, 3)
		scripts := make(map[string]bool, 3)
		for _, a := range all {
			scripts[a.Script] = true
		}
		require.True(t, scripts[c.Script])
	})

	t.Run("NewDefault reuses existing active contract", func(t *testing.T) {
		t.Parallel()
		ks := newMockKeystore(t)
		mgr := contract.NewManager(ks, testConfig(t), nil)

		c1, err := mgr.NewDefault(context.Background())
		require.NoError(t, err)
		c2, err := mgr.NewDefault(context.Background())
		require.NoError(t, err)
		require.Equal(t, c1.Script, c2.Script)
	})
}

func TestManager_GetContracts_Filter(t *testing.T) {
	t.Parallel()

	ks := newMockKeystore(t)
	mgr := contract.NewManager(ks, testConfig(t), nil)

	c, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)

	t.Run("filter by type matches", func(t *testing.T) {
		typ := contract.TypeDefault
		got, err := mgr.GetContracts(context.Background(), contract.Filter{Type: &typ})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, c.Script, got[0].Script)
	})

	t.Run("filter by type misses", func(t *testing.T) {
		typ := "other"
		got, err := mgr.GetContracts(context.Background(), contract.Filter{Type: &typ})
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("filter by script matches", func(t *testing.T) {
		got, err := mgr.GetContracts(context.Background(), contract.Filter{Script: &c.Script})
		require.NoError(t, err)
		require.Len(t, got, 1)
	})
}

func TestManager_OnContractEvent(t *testing.T) {
	t.Parallel()

	mgr := contract.NewManager(newMockKeystore(t), testConfig(t), nil)

	var received []contract.Event
	unsub := mgr.OnContractEvent(func(e contract.Event) {
		received = append(received, e)
	})

	_, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)
	require.Len(t, received, 3)
	for _, e := range received {
		require.Equal(t, "contract_created", e.Type)
	}

	// Unsubscribe stops delivery. Close clears the cache so the next NewDefault
	// must create a new contract and would emit if still subscribed.
	unsub()
	require.NoError(t, mgr.Close())
	_, err = mgr.NewDefault(context.Background())
	require.NoError(t, err)
	require.Len(t, received, 3) // still 3, events would fire but callback was removed
}

func TestManager_Close(t *testing.T) {
	t.Parallel()

	mgr := contract.NewManager(newMockKeystore(t), testConfig(t), nil)
	_, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)

	require.NoError(t, mgr.Close())

	all, err := mgr.GetContracts(context.Background(), contract.Filter{})
	require.NoError(t, err)
	require.Empty(t, all)
}

func TestManager_GetContracts_StateFilter(t *testing.T) {
	t.Parallel()

	ks := newMockKeystore(t)
	mgr := contract.NewManager(ks, testConfig(t), nil)

	_, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)

	t.Run("active state filter matches", func(t *testing.T) {
		t.Parallel()
		active := string(contract.StateActive)
		got, err := mgr.GetContracts(context.Background(), contract.Filter{State: &active})
		require.NoError(t, err)
		require.Len(t, got, 3)
	})

	t.Run("inactive state filter misses active contracts", func(t *testing.T) {
		t.Parallel()
		inactive := string(contract.StateInactive)
		got, err := mgr.GetContracts(context.Background(), contract.Filter{State: &inactive})
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestManager_GetContractsForVtxos(t *testing.T) {
	t.Parallel()

	ks := newMockKeystore(t)
	mgr := contract.NewManager(ks, testConfig(t), nil)

	c, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)

	t.Run("returns matching contract", func(t *testing.T) {
		t.Parallel()
		got, err := mgr.GetContractsForVtxos(context.Background(), []string{c.Script})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, c.Script, got[0].Script)
	})

	t.Run("empty scripts returns nothing", func(t *testing.T) {
		t.Parallel()
		got, err := mgr.GetContractsForVtxos(context.Background(), nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("unknown script is silently omitted", func(t *testing.T) {
		t.Parallel()
		got, err := mgr.GetContractsForVtxos(context.Background(), []string{"deadbeef"})
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("mix of known and unknown scripts", func(t *testing.T) {
		t.Parallel()
		got, err := mgr.GetContractsForVtxos(context.Background(), []string{c.Script, "deadbeef"})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, c.Script, got[0].Script)
	})
}

func TestManager_NewDefault_KeystoreError(t *testing.T) {
	t.Parallel()

	t.Run("NewKey error is propagated", func(t *testing.T) {
		t.Parallel()
		mgr := contract.NewManager(&errKeystore{}, testConfig(t), nil)
		_, err := mgr.NewDefault(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "keystore unavailable")
	})

	t.Run("nil key from NewKey returns error", func(t *testing.T) {
		t.Parallel()
		mgr := contract.NewManager(&emptyKeystore{}, testConfig(t), nil)
		_, err := mgr.NewDefault(context.Background())
		require.Error(t, err)
		require.Contains(t, err.Error(), "keystore returned nil key")
	})
}

// emptyKeystore returns no keys.
type emptyKeystore struct{}

func (e *emptyKeystore) NewKey(_ context.Context, _ ...wallet.KeyOption) (*wallet.KeyRef, error) {
	return nil, nil
}
func (e *emptyKeystore) GetKey(_ context.Context, _ ...wallet.KeyOption) (*wallet.KeyRef, error) {
	return nil, nil
}
func (e *emptyKeystore) ListKeys(_ context.Context) ([]wallet.KeyRef, error) {
	return nil, nil
}

// errKeystore returns an error from NewKey.
type errKeystore struct{}

func (e *errKeystore) NewKey(_ context.Context, _ ...wallet.KeyOption) (*wallet.KeyRef, error) {
	return nil, fmt.Errorf("keystore unavailable")
}
func (e *errKeystore) GetKey(_ context.Context, _ ...wallet.KeyOption) (*wallet.KeyRef, error) {
	return nil, nil
}
func (e *errKeystore) ListKeys(_ context.Context) ([]wallet.KeyRef, error) {
	return nil, nil
}
