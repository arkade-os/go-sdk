package contract_test

import (
	"context"
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

// fixedHandler records calls and returns a canned contract.
type fixedHandler struct {
	calls int
}

func (f *fixedHandler) Type() string { return "default" }

func (f *fixedHandler) DeriveContract(
	_ context.Context, key wallet.KeyRef, _ *clientTypes.Config,
) (*contract.Contract, error) {
	f.calls++
	return &contract.Contract{
		Type:    "default",
		Script:  "deadbeef" + key.Id,
		Address: "ark1" + key.Id,
		State:   contract.StateActive,
	}, nil
}

func (f *fixedHandler) SerializeParams(_ any) (map[string]string, error)    { return nil, nil }
func (f *fixedHandler) DeserializeParams(_ map[string]string) (any, error)  { return nil, nil }

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

	t.Run("Bootstrap populates contracts for existing keys", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		h := &fixedHandler{}
		require.NoError(t, reg.Register(h))

		ks := newMockKeystore(t)
		mgr := contract.NewManager(ks, testConfig(t), reg)
		require.NoError(t, mgr.Bootstrap(context.Background()))

		contracts, err := mgr.GetContracts(context.Background(), contract.Filter{})
		require.NoError(t, err)
		require.Len(t, contracts, 1)
		require.Equal(t, "default", contracts[0].Type)
		require.Equal(t, 1, h.calls)
	})

	t.Run("Bootstrap with no default handler is a no-op", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		ks := newMockKeystore(t)
		mgr := contract.NewManager(ks, testConfig(t), reg)
		require.NoError(t, mgr.Bootstrap(context.Background()))

		contracts, err := mgr.GetContracts(context.Background(), contract.Filter{})
		require.NoError(t, err)
		require.Empty(t, contracts)
	})
}

func TestManager_NewDefault(t *testing.T) {
	t.Parallel()

	t.Run("NewDefault creates contract and persists it", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		require.NoError(t, reg.Register(&fixedHandler{}))

		ks := newMockKeystore(t)
		mgr := contract.NewManager(ks, testConfig(t), reg)

		c, err := mgr.NewDefault(context.Background())
		require.NoError(t, err)
		require.Equal(t, "default", c.Type)
		require.Equal(t, contract.StateActive, c.State)

		all, err := mgr.GetContracts(context.Background(), contract.Filter{})
		require.NoError(t, err)
		require.Len(t, all, 1)
		require.Equal(t, c.Script, all[0].Script)
	})

	t.Run("NewDefault returns error when no default handler registered", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		mgr := contract.NewManager(newMockKeystore(t), testConfig(t), reg)
		_, err := mgr.NewDefault(context.Background())
		require.Error(t, err)
	})
}

func TestManager_GetContracts_Filter(t *testing.T) {
	t.Parallel()

	reg := contract.NewRegistry()
	require.NoError(t, reg.Register(&fixedHandler{}))

	ks := newMockKeystore(t)
	mgr := contract.NewManager(ks, testConfig(t), reg)

	c, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)

	t.Run("filter by type matches", func(t *testing.T) {
		typ := "default"
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

	reg := contract.NewRegistry()
	require.NoError(t, reg.Register(&fixedHandler{}))

	mgr := contract.NewManager(newMockKeystore(t), testConfig(t), reg)

	var received []contract.Event
	unsub := mgr.OnContractEvent(func(e contract.Event) {
		received = append(received, e)
	})

	_, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)
	require.Len(t, received, 1)
	require.Equal(t, "contract_created", received[0].Type)

	// Unsubscribe stops delivery.
	unsub()
	_, err = mgr.NewDefault(context.Background())
	require.NoError(t, err)
	require.Len(t, received, 1) // still 1
}

func TestManager_Close(t *testing.T) {
	t.Parallel()

	reg := contract.NewRegistry()
	require.NoError(t, reg.Register(&fixedHandler{}))

	mgr := contract.NewManager(newMockKeystore(t), testConfig(t), reg)
	_, err := mgr.NewDefault(context.Background())
	require.NoError(t, err)

	require.NoError(t, mgr.Close())

	all, err := mgr.GetContracts(context.Background(), contract.Filter{})
	require.NoError(t, err)
	require.Empty(t, all)
}
