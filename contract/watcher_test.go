package contract_test

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// --- mock explorer ---

type mockExplorer struct {
	mu           sync.Mutex
	subscribed   []string
	unsubscribed []string
	eventCh      chan clientTypes.OnchainAddressEvent
	subErr       error // returned by SubscribeForAddresses when non-nil
	subErrN      int   // if > 0, auto-clears subErr after N failures; 0 means always fail
	subCallCount int   // incremented on every SubscribeForAddresses call
}

func newMockExplorer() *mockExplorer {
	return &mockExplorer{
		eventCh: make(chan clientTypes.OnchainAddressEvent, 16),
	}
}

func (m *mockExplorer) SubscribeForAddresses(addrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subCallCount++
	if m.subErr != nil {
		err := m.subErr
		if m.subErrN > 0 {
			m.subErrN--
			if m.subErrN == 0 {
				m.subErr = nil
			}
		}
		return err
	}
	m.subscribed = append(m.subscribed, addrs...)
	return nil
}

func (m *mockExplorer) UnsubscribeForAddresses(addrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsubscribed = append(m.unsubscribed, addrs...)
	return nil
}

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

func (m *mockExplorer) getUnsubscribed() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.unsubscribed))
	copy(out, m.unsubscribed)
	return out
}

func (m *mockExplorer) trySend(evt clientTypes.OnchainAddressEvent) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case m.eventCh <- evt:
		return true
	default:
		return false
	}
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
	mu              sync.Mutex
	contracts       []contract.Contract
	cbs             []func(contract.Event)
	getContractsErr error // if non-nil, returned by GetContracts
}

func (m *watcherMockManager) Load(_ context.Context) error { return nil }
func (m *watcherMockManager) NewDefault(_ context.Context) (*contract.Contract, error) {
	return nil, nil
}

func (m *watcherMockManager) GetContracts(
	_ context.Context,
	_ ...contract.FilterOption,
) ([]contract.Contract, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getContractsErr != nil {
		return nil, m.getContractsErr
	}
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
func (m *watcherMockManager) NewDelegate(
	_ context.Context, _ *btcec.PublicKey,
) (*contract.Contract, error) {
	return nil, nil
}
func (m *watcherMockManager) SelectPath(
	_ context.Context, _ *contract.Contract, _ contract.PathContext,
) (*contract.PathSelection, error) {
	return nil, nil
}
func (m *watcherMockManager) GetSpendablePaths(
	_ context.Context, _ *contract.Contract, _ contract.PathContext,
) ([]contract.PathSelection, error) {
	return nil, nil
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

func (m *watcherMockManager) cbCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cbs)
}

// --- helpers ---

func regtest() arklib.Network { return arklib.BitcoinRegTest }

func makeBoardingContract(addr string) contract.Contract {
	return contract.Contract{
		Script:    "aabbcc",
		Type:      contract.TypeDefaultBoarding,
		State:     contract.StateActive,
		IsOnchain: true,
		Address:   addr,
		Params: map[string]string{
			contract.ParamExitDelay:  "block:144",
			contract.ParamTapscripts: `["leaf0"]`,
		},
	}
}

func makeOnchainContract(addr string) contract.Contract {
	return contract.Contract{
		Script:    "ddeeff",
		Type:      contract.TypeDefaultOnchain,
		State:     contract.StateActive,
		IsOnchain: true,
		Address:   addr,
		Params:    map[string]string{},
	}
}

// makeOffchainContract builds a TypeDefault (IsOnchain=false) contract with a
// valid ark V0 address and returns it alongside the expected Bitcoin P2TR
// address that the watcher should subscribe to after ark-to-onchain conversion.
func makeOffchainContract(t *testing.T) (contract.Contract, string) {
	t.Helper()

	userPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	signerPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	vtxoTapKey := userPriv.PubKey()
	signerPubKey := signerPriv.PubKey()

	arkAddr := &arklib.Address{
		HRP:        arklib.BitcoinRegTest.Addr,
		Signer:     signerPubKey,
		VtxoTapKey: vtxoTapKey,
	}
	encoded, err := arkAddr.EncodeV0()
	require.NoError(t, err)

	// watcherArkToOnchain extracts VtxoTapKey and builds a P2TR from it.
	onchainAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	c := contract.Contract{
		Script:    "ffaabb",
		Type:      contract.TypeDefault,
		State:     contract.StateActive,
		IsOnchain: false,
		Address:   encoded,
		Params: map[string]string{
			contract.ParamExitDelay:  "block:144",
			contract.ParamTapscripts: `["leaf0","leaf1"]`,
		},
	}
	return c, onchainAddr.EncodeAddress()
}

// scriptHexFor returns the P2TR output script hex for a Bitcoin address string.
func scriptHexFor(t *testing.T, addr string) string {
	t.Helper()
	decoded, err := btcutil.DecodeAddress(addr, &chaincfg.RegressionNetParams)
	require.NoError(t, err)
	sc, err := txscript.PayToAddrScript(decoded)
	require.NoError(t, err)
	return hex.EncodeToString(sc)
}

// --- tests ---

func TestWatcher_InitialSubscription(t *testing.T) {
	t.Parallel()

	boarding := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	onchain := "bcrt1ph9qqde3z0xkk8gzny2tz3uxfd30799w8dkgpj7ktlu9cxcankljqmxer0v"

	exp := newMockExplorer()
	mgr := &watcherMockManager{
		contracts: []contract.Contract{
			makeBoardingContract(boarding),
			makeOnchainContract(onchain),
		},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return len(exp.getSubscribed()) >= 2
	}, time.Second, 10*time.Millisecond)

	subs := exp.getSubscribed()
	require.Contains(t, subs, boarding)
	require.Contains(t, subs, onchain)
}

func TestWatcher_OffchainContract(t *testing.T) {
	t.Parallel()

	c, expectedOnchain := makeOffchainContract(t)

	exp := newMockExplorer()
	mgr := &watcherMockManager{contracts: []contract.Contract{c}}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Watcher converts the ark address to P2TR and subscribes to that.
	require.Eventually(t, func() bool {
		subs := exp.getSubscribed()
		for _, s := range subs {
			if s == expectedOnchain {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)

	info, ok := w.LookupAddress(scriptHexFor(t, expectedOnchain))
	require.True(t, ok)
	require.Equal(t, []string{"leaf0", "leaf1"}, info.Tapscripts)
	delay, err := c.GetDelay()
	require.NoError(t, err)
	require.Equal(t, delay, info.Delay)
}

func TestWatcher_StartError(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{
		getContractsErr: errors.New("database unavailable"),
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	err := w.Start(context.Background())
	require.ErrorContains(t, err, "database unavailable")
}

func TestWatcher_BackoffRetry(t *testing.T) {
	t.Parallel()

	addr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	exp := newMockExplorer()
	exp.subErr = errors.New("connection refused")
	exp.subErrN = 1 // fail once, then auto-clear and succeed on retry

	mgr := &watcherMockManager{
		contracts: []contract.Contract{makeBoardingContract(addr)},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// After 1 failure + 1s backoff + successful retry, the address should appear.
	require.Eventually(t, func() bool {
		subs := exp.getSubscribed()
		for _, s := range subs {
			if s == addr {
				return true
			}
		}
		return false
	}, 4*time.Second, 100*time.Millisecond)
}

func TestWatcher_BackoffContextCancel(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	exp.subErr = errors.New("connection refused")
	// subErrN = 0: always fail (never auto-clears)

	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Wait for the first failed subscribe attempt, confirming the goroutine
	// has entered subscribeWithBackoff and is now sleeping through the backoff.
	require.Eventually(t, func() bool {
		exp.mu.Lock()
		defer exp.mu.Unlock()
		return exp.subCallCount > 0
	}, time.Second, 10*time.Millisecond)

	// Cancel mid-backoff; the goroutine should exit promptly.
	cancel()

	select {
	case _, ok := <-w.Events():
		require.False(t, ok, "Events() should be closed after context cancel during backoff")
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine did not exit when context was cancelled during backoff")
	}
}

func TestWatcher_DynamicContractSubscription(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0
	}, time.Second, 10*time.Millisecond)

	newBoarding := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	mgr.emit(contract.Event{Type: "contract_created", Contract: makeBoardingContract(newBoarding)})

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

func TestWatcher_EventTypeFilter(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0
	}, time.Second, 10*time.Millisecond)

	newAddr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	// vtxo_received is not "contract_created" so the watcher must ignore it.
	mgr.emit(contract.Event{Type: "vtxo_received", Contract: makeBoardingContract(newAddr)})

	require.Never(t, func() bool {
		for _, s := range exp.getSubscribed() {
			if s == newAddr {
				return true
			}
		}
		return false
	}, 300*time.Millisecond, 10*time.Millisecond)
}

func TestWatcher_AddressDeduplication(t *testing.T) {
	t.Parallel()

	addr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	c := makeBoardingContract(addr)

	exp := newMockExplorer()
	mgr := &watcherMockManager{contracts: []contract.Contract{c}}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Wait for initial subscription and callback registration.
	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0 && len(exp.getSubscribed()) >= 1
	}, time.Second, 10*time.Millisecond)

	initialCallCount := func() int {
		exp.mu.Lock()
		defer exp.mu.Unlock()
		return exp.subCallCount
	}()

	// Emit contract_created for the same address; addContractAddresses should
	// detect the duplicate and not call SubscribeForAddresses again.
	mgr.emit(contract.Event{Type: "contract_created", Contract: c})

	require.Never(t, func() bool {
		exp.mu.Lock()
		defer exp.mu.Unlock()
		return exp.subCallCount > initialCallCount
	}, 300*time.Millisecond, 10*time.Millisecond)
}

func TestWatcher_EventsForwardedToChannel(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

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

	// Watcher should resubscribe; send an event on the new channel.
	evt := clientTypes.OnchainAddressEvent{
		NewUtxos: []clientTypes.OnchainOutput{{Outpoint: clientTypes.Outpoint{Txid: "cafebabe"}}},
	}

	require.Eventually(t, func() bool {
		return exp.trySend(evt)
	}, 2*time.Second, 50*time.Millisecond)

	select {
	case got := <-w.Events():
		require.Equal(t, "cafebabe", got.NewUtxos[0].Txid)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reconnect event")
	}
}

func TestWatcher_LookupAddress(t *testing.T) {
	t.Parallel()

	addr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	exp := newMockExplorer()
	mgr := &watcherMockManager{
		contracts: []contract.Contract{makeBoardingContract(addr)},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return len(exp.getSubscribed()) > 0
	}, time.Second, 10*time.Millisecond)

	info, ok := w.LookupAddress(scriptHexFor(t, addr))
	require.True(t, ok)
	require.Equal(t, []string{"leaf0"}, info.Tapscripts)
}

func TestWatcher_ZeroDelayFallback(t *testing.T) {
	t.Parallel()

	// TypeDefaultOnchain contracts have no exitDelay param; the watcher falls
	// back to a zero RelativeLocktime rather than skipping the contract.
	addr := "bcrt1ph9qqde3z0xkk8gzny2tz3uxfd30799w8dkgpj7ktlu9cxcankljqmxer0v"
	exp := newMockExplorer()
	mgr := &watcherMockManager{
		contracts: []contract.Contract{makeOnchainContract(addr)},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return len(exp.getSubscribed()) > 0
	}, time.Second, 10*time.Millisecond)

	info, ok := w.LookupAddress(scriptHexFor(t, addr))
	require.True(t, ok)
	require.Equal(t, arklib.RelativeLocktime{}, info.Delay)
}

func TestWatcher_MalformedAddressSkipped(t *testing.T) {
	t.Parallel()

	good := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	bad := contract.Contract{
		Script:    "112233",
		Type:      contract.TypeDefault,
		State:     contract.StateActive,
		IsOnchain: false,
		Address:   "not-a-valid-ark-address",
		Params:    map[string]string{contract.ParamExitDelay: "block:144"},
	}

	exp := newMockExplorer()
	mgr := &watcherMockManager{
		contracts: []contract.Contract{makeBoardingContract(good), bad},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// The good contract is subscribed; the bad one is silently skipped.
	require.Eventually(t, func() bool {
		return len(exp.getSubscribed()) >= 1
	}, time.Second, 10*time.Millisecond)

	subs := exp.getSubscribed()
	require.Len(t, subs, 1)
	require.Contains(t, subs, good)
}

func TestWatcher_UnsubscribeOnStop(t *testing.T) {
	t.Parallel()

	addr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	exp := newMockExplorer()
	mgr := &watcherMockManager{
		contracts: []contract.Contract{makeBoardingContract(addr)},
	}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return len(exp.getSubscribed()) > 0
	}, time.Second, 10*time.Millisecond)

	w.Stop()

	// UnsubscribeForAddresses is called before the channel closes, so waiting
	// for the channel to close guarantees the unsubscribe already happened.
	select {
	case _, ok := <-w.Events():
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Stop to complete")
	}

	require.Contains(t, exp.getUnsubscribed(), addr)
}

func TestWatcher_StopClosesEvents(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// OnContractEvent is registered before subscribeWithBackoff, so its presence
	// confirms the goroutine has started and the listen loop is reachable.
	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0
	}, time.Second, 10*time.Millisecond)

	w.Stop()

	select {
	case _, ok := <-w.Events():
		require.False(t, ok, "Events() channel should be closed after Stop")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Events() to close after Stop")
	}
}

func TestWatcher_ConcurrentStop(t *testing.T) {
	t.Parallel()

	exp := newMockExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0
	}, time.Second, 10*time.Millisecond)

	// Concurrent Stop calls must not panic (cancel is idempotent; close is
	// guarded by sync.Once).
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.Stop()
		}()
	}
	wg.Wait()

	select {
	case _, ok := <-w.Events():
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Events() to close")
	}
}
