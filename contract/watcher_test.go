package contract_test

import (
	"context"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/stretchr/testify/require"
)

// --- mock explorer ---

type mockExplorer struct {
	mu         sync.Mutex
	subscribed []string
	eventCh    chan clientTypes.OnchainAddressEvent
	subErr     error // returned by SubscribeForAddresses when non-nil
}

func newMockExplorer() *mockExplorer {
	return &mockExplorer{
		eventCh: make(chan clientTypes.OnchainAddressEvent, 16),
	}
}

func (m *mockExplorer) SubscribeForAddresses(addrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.subErr != nil {
		return m.subErr
	}
	m.subscribed = append(m.subscribed, addrs...)
	return nil
}

func (m *mockExplorer) UnsubscribeForAddresses(addrs []string) error { return nil }

func (m *mockExplorer) GetAddressesEvents() <-chan clientTypes.OnchainAddressEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventCh
}

func (m *mockExplorer) getSubscribed() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.subscribed))
	copy(out, m.subscribed)
	return out
}

// satisfy the full explorer.Explorer interface with no-ops for methods not needed.
func (m *mockExplorer) GetTxHex(_ string) (string, error)      { return "", nil }
func (m *mockExplorer) GetTxs(_ string) ([]explorer.Tx, error) { return nil, nil }
func (m *mockExplorer) GetTxOutspends(_ string) ([]explorer.SpentStatus, error) {
	return nil, nil
}
func (m *mockExplorer) GetUtxos(_ string) ([]explorer.Utxo, error) { return nil, nil }

func (m *mockExplorer) GetRedeemedVtxosBalance(
	_ string,
	_ arklib.RelativeLocktime,
) (uint64, map[int64]uint64, error) {
	return 0, nil, nil
}
func (m *mockExplorer) GetTxBlockTime(_ string) (bool, int64, error) { return false, 0, nil }
func (m *mockExplorer) Broadcast(_ ...string) (string, error)        { return "", nil }
func (m *mockExplorer) GetFeeRate() (float64, error)                 { return 0, nil }
func (m *mockExplorer) BaseUrl() string                              { return "" }
func (m *mockExplorer) GetConnectionCount() int                      { return 0 }
func (m *mockExplorer) GetSubscribedAddresses() []string             { return nil }
func (m *mockExplorer) IsAddressSubscribed(_ string) bool            { return false }
func (m *mockExplorer) Start()                                       {}
func (m *mockExplorer) Stop()                                        {}

// --- mock manager ---

type watcherMockManager struct {
	mu        sync.Mutex
	contracts []contract.Contract
	cbs       []func(contract.Event)
}

func (m *watcherMockManager) Load(_ context.Context) error { return nil }
func (m *watcherMockManager) NewDefault(_ context.Context) (*contract.Contract, error) {
	return nil, nil
}

func (m *watcherMockManager) GetContracts(
	_ context.Context,
	_ contract.Filter,
) ([]contract.Contract, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.contracts, nil
}

func (m *watcherMockManager) GetContractsForVtxos(
	_ context.Context,
	_ []string,
) ([]contract.Contract, error) {
	return nil, nil
}
func (m *watcherMockManager) OnContractEvent(cb func(contract.Event)) func() {
	m.mu.Lock()
	m.cbs = append(m.cbs, cb)
	m.mu.Unlock()
	return func() {}
}
func (m *watcherMockManager) Close() error { return nil }

func (m *watcherMockManager) emit(e contract.Event) {
	m.mu.Lock()
	cbs := make([]func(contract.Event), len(m.cbs))
	copy(cbs, m.cbs)
	m.mu.Unlock()
	for _, cb := range cbs {
		cb(e)
	}
}

// --- helpers ---

func regtest() arklib.Network { return arklib.BitcoinRegTest }

// makeWatcherContract builds a minimal contract with plausible-looking addresses
// for regtest. We use the addresses from the default_handler_test fixture.
func makeWatcherContract(boarding, onchain string) contract.Contract {
	return contract.Contract{
		Script:             "aabbcc",
		Type:               contract.TypeDefault,
		State:              contract.StateActive,
		Boarding:           boarding,
		Onchain:            onchain,
		BoardingTapscripts: []string{"leaf0"},
		BoardingDelay:      arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
	}
}

// --- tests ---

func TestWatcher_InitialSubscription(t *testing.T) {
	t.Parallel()

	boarding := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	onchain := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"

	exp := newMockExplorer()
	mgr := &watcherMockManager{
		contracts: []contract.Contract{makeWatcherContract(boarding, onchain)},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Give the goroutine time to subscribe.
	require.Eventually(t, func() bool {
		subs := exp.getSubscribed()
		return len(subs) >= 2
	}, time.Second, 10*time.Millisecond)

	subs := exp.getSubscribed()
	require.Contains(t, subs, boarding)
	require.Contains(t, subs, onchain)
}

func TestWatcher_DynamicContractSubscription(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Wait for the OnContractEvent callback to be registered.
	require.Eventually(t, func() bool {
		mgr.mu.Lock()
		defer mgr.mu.Unlock()
		return len(mgr.cbs) > 0
	}, time.Second, 10*time.Millisecond)

	newBoarding := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	c := makeWatcherContract(newBoarding, "")
	mgr.emit(contract.Event{Type: "contract_created", Contract: c})

	require.Eventually(t, func() bool {
		subs := exp.getSubscribed()
		for _, s := range subs {
			if s == newBoarding {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

func TestWatcher_EventsForwardedToChannel(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Send an event on the explorer channel.
	evt := clientTypes.OnchainAddressEvent{
		NewUtxos: []clientTypes.OnchainOutput{{Outpoint: clientTypes.Outpoint{Txid: "deadbeef"}}},
	}
	exp.eventCh <- evt

	select {
	case got := <-w.Events():
		require.Equal(t, "deadbeef", got.NewUtxos[0].Txid)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestWatcher_ReconnectOnChannelClose(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Close the current event channel to simulate a disconnect.
	exp.mu.Lock()
	close(exp.eventCh)
	exp.eventCh = make(chan clientTypes.OnchainAddressEvent, 16)
	exp.mu.Unlock()

	// Watcher should resubscribe; send an event on the new channel and
	// verify it is forwarded.
	evt := clientTypes.OnchainAddressEvent{
		NewUtxos: []clientTypes.OnchainOutput{{Outpoint: clientTypes.Outpoint{Txid: "cafebabe"}}},
	}

	require.Eventually(t, func() bool {
		select {
		case exp.eventCh <- evt:
			return true
		default:
			return false
		}
	}, 2*time.Second, 50*time.Millisecond)

	select {
	case got := <-w.Events():
		require.Equal(t, "cafebabe", got.NewUtxos[0].Txid)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconnect event")
	}
}
