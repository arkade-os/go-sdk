package contract_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// --- mock explorer (renamed to avoid clash with utils_test.go's mockExplorer) ---

type mockWatcherExplorer struct {
	mu           sync.Mutex
	subscribed   []string
	unsubscribed []string
	eventCh      chan clientTypes.OnchainAddressEvent
	subErr       error // returned by SubscribeForAddresses when non-nil
	subErrN      int   // if > 0, auto-clears subErr after N failures; 0 means always fail
	subCallCount int   // incremented on every SubscribeForAddresses call
}

func newMockWatcherExplorer() *mockWatcherExplorer {
	return &mockWatcherExplorer{
		eventCh: make(chan clientTypes.OnchainAddressEvent, 16),
	}
}

func (m *mockWatcherExplorer) SubscribeForAddresses(addrs []string) error {
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

func (m *mockWatcherExplorer) UnsubscribeForAddresses(addrs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsubscribed = append(m.unsubscribed, addrs...)
	return nil
}

func (m *mockWatcherExplorer) GetAddressesEvents() <-chan clientTypes.OnchainAddressEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventCh
}

func (m *mockWatcherExplorer) getSubscribed() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.subscribed))
	copy(out, m.subscribed)
	return out
}

func (m *mockWatcherExplorer) getUnsubscribed() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.unsubscribed))
	copy(out, m.unsubscribed)
	return out
}

func (m *mockWatcherExplorer) trySend(evt clientTypes.OnchainAddressEvent) bool {
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
func (m *mockWatcherExplorer) GetTxHex(_ string) (string, error)      { return "", nil }
func (m *mockWatcherExplorer) GetTxs(_ string) ([]explorer.Tx, error) { return nil, nil }
func (m *mockWatcherExplorer) GetTxOutspends(_ string) ([]explorer.SpentStatus, error) {
	return nil, nil
}
func (m *mockWatcherExplorer) GetUtxos(_ []string) ([]explorer.Utxo, error) { return nil, nil }

func (m *mockWatcherExplorer) GetRedeemedVtxosBalance(
	_ string,
	_ arklib.RelativeLocktime,
) (uint64, map[int64]uint64, error) {
	return 0, nil, nil
}
func (m *mockWatcherExplorer) GetTxBlockTime(_ string) (bool, int64, error) { return false, 0, nil }
func (m *mockWatcherExplorer) Broadcast(_ ...string) (string, error)        { return "", nil }
func (m *mockWatcherExplorer) GetFeeRate() (float64, error)                 { return 0, nil }
func (m *mockWatcherExplorer) BaseUrl() string                              { return "" }
func (m *mockWatcherExplorer) GetConnectionCount() int                      { return 0 }
func (m *mockWatcherExplorer) GetSubscribedAddresses() []string             { return nil }
func (m *mockWatcherExplorer) IsAddressSubscribed(_ string) bool            { return false }
func (m *mockWatcherExplorer) Start()                                       {}
func (m *mockWatcherExplorer) Stop()                                        {}

// --- mock contract handler ---

// mockContractHandler serves tapscripts from c.Params["tapscripts"] (JSON array)
// and exit delay from c.Params["exitDelay"] (integer string, same logic as
// the real default handler: value < 512 → block, else → second).
type mockContractHandler struct{}

func (h *mockContractHandler) NewContract(
	_ context.Context,
	_ identity.KeyRef,
) (*types.Contract, error) {
	return nil, nil
}
func (h *mockContractHandler) GetKeyRefs(_ types.Contract) (map[string]string, error) {
	return nil, nil
}

func (h *mockContractHandler) GetKeyRef(
	_ types.Contract,
) (*identity.KeyRef, error) {
	return nil, nil
}
func (h *mockContractHandler) GetSignerKey(_ types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (h *mockContractHandler) GetExitDelay(c types.Contract) (*arklib.RelativeLocktime, error) {
	s, ok := c.Params["exitDelay"]
	if !ok {
		return nil, fmt.Errorf("contract %s has no exitDelay param", c.Script)
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("contract %s invalid exitDelay %q: %w", c.Script, s, err)
	}
	lt := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: uint32(n)}
	if n < 512 {
		lt.Type = arklib.LocktimeTypeBlock
	}
	return &lt, nil
}
func (h *mockContractHandler) GetTapscripts(c types.Contract) ([]string, error) {
	s, ok := c.Params["tapscripts"]
	if !ok {
		return nil, nil
	}
	var ts []string
	if err := json.Unmarshal([]byte(s), &ts); err != nil {
		return nil, err
	}
	return ts, nil
}

// Ensure mockContractHandler satisfies handlers.Handler at compile time.
var _ handlers.Handler = (*mockContractHandler)(nil)

// --- mock manager ---

type watcherMockManager struct {
	mu              sync.Mutex
	contracts       []types.Contract
	cbs             []func(types.Contract)
	getContractsErr error
}

func (m *watcherMockManager) GetSupportedContractTypes(_ context.Context) []types.ContractType {
	return nil
}
func (m *watcherMockManager) ScanContracts(_ context.Context, _ uint32) error { return nil }
func (m *watcherMockManager) NewContract(
	_ context.Context, _ types.ContractType, _ ...contract.ContractOption,
) (*types.Contract, error) {
	return nil, nil
}
func (m *watcherMockManager) GetContracts(
	_ context.Context,
	_ ...contract.FilterOption,
) ([]types.Contract, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getContractsErr != nil {
		return nil, m.getContractsErr
	}
	return m.contracts, nil
}
func (m *watcherMockManager) GetHandler(
	_ context.Context, _ types.Contract,
) (handlers.Handler, error) {
	return &mockContractHandler{}, nil
}
func (m *watcherMockManager) NewDelegate(
	_ context.Context, _ *btcec.PublicKey,
) (*types.Contract, error) {
	return nil, nil
}
func (m *watcherMockManager) Clean(_ context.Context) error { return nil }
func (m *watcherMockManager) Close()                        {}
func (m *watcherMockManager) OnContractEvent(cb func(types.Contract)) func() {
	m.mu.Lock()
	m.cbs = append(m.cbs, cb)
	m.mu.Unlock()
	return func() {}
}

func (m *watcherMockManager) emit(c types.Contract) {
	m.mu.Lock()
	cbs := make([]func(types.Contract), len(m.cbs))
	copy(cbs, m.cbs)
	m.mu.Unlock()
	for _, cb := range cbs {
		cb(c)
	}
}

func (m *watcherMockManager) cbCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cbs)
}

// --- helpers ---

func regtest() arklib.Network { return arklib.BitcoinRegTest }

// makeBoardingContract builds a ContractTypeBoarding contract with the given P2TR address.
func makeBoardingContract(addr string) types.Contract {
	return types.Contract{
		Script:  "aabbcc",
		Type:    types.ContractTypeBoarding,
		State:   types.ContractStateActive,
		Address: addr,
		Params: map[string]string{
			"exitDelay":  "144",
			"tapscripts": `["leaf0"]`,
		},
	}
}

// makeSecondBoardingContract builds a second ContractTypeBoarding contract (used
// in tests that need two distinct boarding addresses to subscribe).
func makeSecondBoardingContract(addr string) types.Contract {
	return types.Contract{
		Script:  "ddeeff",
		Type:    types.ContractTypeBoarding,
		State:   types.ContractStateActive,
		Address: addr,
		Params: map[string]string{
			"exitDelay": "144",
		},
	}
}

// makeOffchainContract builds a ContractTypeDefault contract with a valid Ark V0
// address and returns it together with the expected Bitcoin P2TR address that the
// watcher should subscribe to after ark-to-onchain conversion.
func makeOffchainContract(t *testing.T) (types.Contract, string) {
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

	onchainAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	c := types.Contract{
		Script:  "ffaabb",
		Type:    types.ContractTypeDefault,
		State:   types.ContractStateActive,
		Address: encoded,
		Params: map[string]string{
			"exitDelay":  "144",
			"tapscripts": `["leaf0","leaf1"]`,
		},
	}
	return c, onchainAddr.EncodeAddress()
}

// makeOffchainContractNoDelay is like makeOffchainContract but omits the
// exitDelay param. Used to verify the watcher skips contracts whose handler
// cannot resolve the exit delay rather than silently substituting zero.
func makeOffchainContractNoDelay(t *testing.T) (types.Contract, string) {
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

	onchainAddr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(vtxoTapKey),
		&chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	c := types.Contract{
		Script:  "ffaacc",
		Type:    types.ContractTypeDefault,
		State:   types.ContractStateActive,
		Address: encoded,
		Params:  map[string]string{}, // no exitDelay so GetExitDelay errors
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

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{
		contracts: []types.Contract{
			makeBoardingContract(boarding),
			makeSecondBoardingContract(onchain),
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

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{contracts: []types.Contract{c}}

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
	// exitDelay "144" < 512 → LocktimeTypeBlock with value 144
	require.Equal(
		t,
		arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144},
		info.Delay,
	)
}

func TestWatcher_StartError(t *testing.T) {
	t.Parallel()

	exp := newMockWatcherExplorer()
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
	exp := newMockWatcherExplorer()
	exp.subErr = errors.New("connection refused")
	exp.subErrN = 1 // fail once, then auto-clear and succeed on retry

	mgr := &watcherMockManager{
		contracts: []types.Contract{makeBoardingContract(addr)},
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

	addr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	exp := newMockWatcherExplorer()
	exp.subErr = errors.New("connection refused")
	// subErrN = 0: always fail (never auto-clears)

	mgr := &watcherMockManager{
		contracts: []types.Contract{makeBoardingContract(addr)},
	}

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

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0
	}, time.Second, 10*time.Millisecond)

	newBoarding := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	mgr.emit(makeBoardingContract(newBoarding))

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

// TestWatcher_InvalidBoardingDelaySkipped verifies that a boarding contract
// whose handler fails GetExitDelay is silently skipped (not subscribed).
// This replaces the old EventTypeFilter test which relied on the removed
// contract.Event type.
func TestWatcher_InvalidBoardingDelaySkipped(t *testing.T) {
	t.Parallel()

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	require.Eventually(t, func() bool {
		return mgr.cbCount() > 0
	}, time.Second, 10*time.Millisecond)

	// Boarding contract with no exitDelay param → GetExitDelay returns error →
	// watcher skips boarding contracts whose delay cannot be resolved.
	badBoarding := types.Contract{
		Script:  "bad001",
		Type:    types.ContractTypeBoarding,
		State:   types.ContractStateActive,
		Address: "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6",
		Params:  map[string]string{}, // no exitDelay
	}
	mgr.emit(badBoarding)

	require.Never(t, func() bool {
		return len(exp.getSubscribed()) > 0
	}, 300*time.Millisecond, 10*time.Millisecond)
}

func TestWatcher_AddressDeduplication(t *testing.T) {
	t.Parallel()

	addr := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	c := makeBoardingContract(addr)

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{contracts: []types.Contract{c}}

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

	// Emit the same contract again; addContractAddresses should detect the
	// duplicate script and not call SubscribeForAddresses again.
	mgr.emit(c)

	require.Never(t, func() bool {
		exp.mu.Lock()
		defer exp.mu.Unlock()
		return exp.subCallCount > initialCallCount
	}, 300*time.Millisecond, 10*time.Millisecond)
}

func TestWatcher_EventsForwardedToChannel(t *testing.T) {
	t.Parallel()

	exp := newMockWatcherExplorer()
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

	exp := newMockWatcherExplorer()
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
	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{
		contracts: []types.Contract{makeBoardingContract(addr)},
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

func TestWatcher_InvalidExitDelaySkipped(t *testing.T) {
	t.Parallel()

	// A contract whose handler cannot resolve the exit delay must be skipped:
	// returning zero would mark resulting UTXOs immediately spendable in the
	// wallet, which is a security-relevant footgun.
	c, expectedOnchain := makeOffchainContractNoDelay(t)

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{contracts: []types.Contract{c}}

	w := contract.NewWatcher(exp, mgr, regtest())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Give the watcher a moment to (not) subscribe.
	time.Sleep(100 * time.Millisecond)

	require.Empty(t, exp.getSubscribed())
	_, ok := w.LookupAddress(scriptHexFor(t, expectedOnchain))
	require.False(t, ok)
}

func TestWatcher_MalformedAddressSkipped(t *testing.T) {
	t.Parallel()

	good := "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6"
	bad := types.Contract{
		Script:  "112233",
		Type:    types.ContractTypeDefault,
		State:   types.ContractStateActive,
		Address: "not-a-valid-ark-address",
		Params:  map[string]string{"exitDelay": "144"},
	}

	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{
		contracts: []types.Contract{makeBoardingContract(good), bad},
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
	exp := newMockWatcherExplorer()
	mgr := &watcherMockManager{
		contracts: []types.Contract{makeBoardingContract(addr)},
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

	exp := newMockWatcherExplorer()
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

	exp := newMockWatcherExplorer()
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
