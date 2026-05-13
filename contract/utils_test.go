package contract_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	hdidentity "github.com/arkade-os/go-sdk/identity"
	identityinmemorystore "github.com/arkade-os/go-sdk/identity/store/inmemory"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

const (
	testUnilateralExitDelay int64 = 144
	testBoardingExitDelay   int64 = 1024
	testCheckpointTapscript       = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"
	testPassword                  = "testpassword"
)

var testNetwork = arklib.BitcoinRegTest

// newTestManager wires a contract manager with a fresh in-memory KV store
// and a brand-new mocked env. Tests that don't need to drive the mocks call
// this; tests that do should reach for newTestManagerWithEnv instead.
func newTestManager(t *testing.T) (contract.Manager, types.ContractStore) {
	t.Helper()
	_, mgr, store := newTestManagerWithEnv(t)
	return mgr, store
}

// newTestManagerWithEnv builds the same manager + store as newTestManager
// and additionally returns the mocked env it sits on top of. Use this when
// the test needs to stage indexer responses or pre-derive scripts.
func newTestManagerWithEnv(
	t *testing.T,
) (*mockedEnv, contract.Manager, types.ContractStore) {
	t.Helper()

	env := newMockedEnv(t)

	svc, err := store.NewStore(store.Config{StoreType: types.KVStore})
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	mgr, err := contract.NewManager(contract.Args{
		Store:       svc.ContractStore(),
		KeyProvider: env.identity,
		Client:      env.transport,
		Indexer:     env.indexer,
		Explorer:    env.explorer,
		Network:     testNetwork,
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)

	return env, mgr, svc.ContractStore()
}

func newTestPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}

// mockTransportClient is a minimal stub for client.TransportClient. The default
// handler only invokes GetInfo (and Close on shutdown), so every other method
// returns zero values — they should never run during these tests.
type mockTransportClient struct {
	info    *client.Info
	infoErr error
}

func (m *mockTransportClient) GetInfo(_ context.Context) (*client.Info, error) {
	return m.info, m.infoErr
}

func (m *mockTransportClient) RegisterIntent(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (m *mockTransportClient) DeleteIntent(_ context.Context, _, _ string) error { return nil }

func (m *mockTransportClient) EstimateIntentFee(
	_ context.Context, _, _ string,
) (int64, error) {
	return 0, nil
}

func (m *mockTransportClient) ConfirmRegistration(_ context.Context, _ string) error { return nil }

func (m *mockTransportClient) SubmitTreeNonces(
	_ context.Context, _, _ string, _ tree.TreeNonces,
) error {
	return nil
}

func (m *mockTransportClient) SubmitTreeSignatures(
	_ context.Context, _, _ string, _ tree.TreePartialSigs,
) error {
	return nil
}

func (m *mockTransportClient) SubmitSignedForfeitTxs(
	_ context.Context, _ []string, _ string,
) error {
	return nil
}

func (m *mockTransportClient) GetEventStream(
	_ context.Context, _ []string,
) (<-chan client.BatchEventChannel, func(), error) {
	return nil, func() {}, nil
}

func (m *mockTransportClient) SubmitTx(
	_ context.Context, _ string, _ []string,
) (string, string, []string, error) {
	return "", "", nil, nil
}

func (m *mockTransportClient) FinalizeTx(_ context.Context, _ string, _ []string) error {
	return nil
}

func (m *mockTransportClient) GetPendingTx(
	_ context.Context, _, _ string,
) ([]client.AcceptedOffchainTx, error) {
	return nil, nil
}

func (m *mockTransportClient) GetTransactionsStream(
	_ context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	return nil, func() {}, nil
}

func (m *mockTransportClient) ModifyStreamTopics(
	_ context.Context, _, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (m *mockTransportClient) OverwriteStreamTopics(
	_ context.Context, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (m *mockTransportClient) Close() {}

// mockIndexer satisfies contract.offchainDataProvider. Tests that don't
// exercise ScanContracts leave usedScripts nil and the mock returns an empty
// response. Scan tests populate usedScripts (or set err) before scanning.
//
// The mock returns every configured script unconditionally — the manager only
// matches against contracts in the current batch, so extra entries in the
// response are ignored.
type mockIndexer struct {
	usedScripts map[string]struct{}
	err         error
}

func (m *mockIndexer) GetVtxos(
	_ context.Context, _ ...indexer.GetVtxosOption,
) (*indexer.VtxosResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.usedScripts) == 0 {
		return &indexer.VtxosResponse{}, nil
	}
	vtxos := make([]clienttypes.Vtxo, 0, len(m.usedScripts))
	for s := range m.usedScripts {
		vtxos = append(vtxos, clienttypes.Vtxo{Script: s})
	}
	return &indexer.VtxosResponse{Vtxos: vtxos}, nil
}

// mockExplorer satisfies contract.onchainDataProvider. Tests that don't
// exercise the boarding scan leave usedAddresses nil and the mock returns
// an empty response. Boarding scan tests populate usedAddresses (or set
// err) before scanning.
//
// The boarding scan queries one address per contract and treats a
// non-empty txs slice as "used", so any sentinel struct works as the
// payload.
type mockExplorer struct {
	usedAddresses map[string]struct{}
	err           error
}

func (m *mockExplorer) GetTxs(addr string) ([]explorer.Tx, error) {
	if m.err != nil {
		return nil, m.err
	}
	if _, ok := m.usedAddresses[addr]; ok {
		return []explorer.Tx{{}}, nil
	}
	return nil, nil
}

// mockedEnv bundles the mocked dependencies the contract manager is built
// on top of, so tests can stage indexer responses or pre-derive the same
// contracts the manager would auto-derive at given key indices, without
// reaching into manager internals. The manager itself is intentionally
// not part of the env — see newTestManagerWithEnv for the wiring.
type mockedEnv struct {
	indexer        *mockIndexer
	explorer       *mockExplorer
	transport      *mockTransportClient
	identity       identity.Identity
	derive         func(keyId string) types.Contract
	deriveBoarding func(keyId string) types.Contract
}

func newMockedEnv(t *testing.T) *mockedEnv {
	t.Helper()

	signer := newTestPubKey(t)
	transport := &mockTransportClient{
		info: &client.Info{
			SignerPubKey:        hex.EncodeToString(signer.SerializeCompressed()),
			UnilateralExitDelay: testUnilateralExitDelay,
			BoardingExitDelay:   testBoardingExitDelay,
			CheckpointTapscript: testCheckpointTapscript,
		},
	}

	wsvc, err := hdidentity.NewIdentity(identityinmemorystore.NewStore())
	require.NoError(t, err)
	_, err = wsvc.Create(t.Context(), chaincfg.RegressionNetParams, testPassword, "")
	require.NoError(t, err)
	_, err = wsvc.Unlock(t.Context(), testPassword)
	require.NoError(t, err)

	// Mirror the manager's derivation across both contract types: same
	// identity, same handlers, same key chain. derive(keyId) yields the
	// offchain contract the scan loop would produce; deriveBoarding(keyId)
	// the boarding (onchain) one. The boarding handler is the same impl
	// parameterized with isOnchain=true — see contract/handlers/default.
	offchainHandler := defaultHandler.NewHandler(transport, testNetwork, false)
	boardingHandler := defaultHandler.NewHandler(transport, testNetwork, true)
	derive := func(keyId string) types.Contract {
		t.Helper()
		keyRef, err := wsvc.GetKey(t.Context(), keyId)
		require.NoError(t, err)
		c, err := offchainHandler.NewContract(t.Context(), *keyRef)
		require.NoError(t, err)
		return *c
	}
	deriveBoarding := func(keyId string) types.Contract {
		t.Helper()
		keyRef, err := wsvc.GetKey(t.Context(), keyId)
		require.NoError(t, err)
		c, err := boardingHandler.NewContract(t.Context(), *keyRef)
		require.NoError(t, err)
		return *c
	}

	return &mockedEnv{
		indexer:        &mockIndexer{},
		explorer:       &mockExplorer{},
		transport:      transport,
		identity:       wsvc,
		derive:         derive,
		deriveBoarding: deriveBoarding,
	}
}

// markUsed configures the mock indexer to report the given key ids as
// used (offchain scan path). Each key id is resolved via derive() to the
// script the scan would generate.
func (e *mockedEnv) markUsed(t *testing.T, keyIds ...string) {
	t.Helper()
	if e.indexer.usedScripts == nil {
		e.indexer.usedScripts = make(map[string]struct{}, len(keyIds))
	}
	for _, k := range keyIds {
		e.indexer.usedScripts[e.derive(k).Script] = struct{}{}
	}
}

// markBoardingUsed configures the mock explorer to report the given key
// ids as used (boarding scan path). Each key id is resolved via
// deriveBoarding() to the onchain (taproot) address the scan would
// generate — the boarding scan keys lookup by Address, not Script.
func (e *mockedEnv) markBoardingUsed(t *testing.T, keyIds ...string) {
	t.Helper()
	if e.explorer.usedAddresses == nil {
		e.explorer.usedAddresses = make(map[string]struct{}, len(keyIds))
	}
	for _, k := range keyIds {
		e.explorer.usedAddresses[e.deriveBoarding(k).Address] = struct{}{}
	}
}
