package contract_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	managerOwnerKeyIDParam = "keyID"
	managerIsOnchainParam  = "isOnchain"

	testUnilateralExitDelay int64 = 144
	testBoardingExitDelay   int64 = 1024
	testCheckpointTapscript       = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"
)

var testNetwork = arklib.BitcoinRegTest

// newTestManager wires the contract manager with a real in-memory KV store
// and a real default handler backed by a stubbed transport client. It returns
// the manager and the underlying contract store so tests can seed fixtures or
// assert side effects directly.
func newTestManager(t *testing.T) (contract.Manager, types.ContractStore) {
	t.Helper()

	svc, err := store.NewStore(store.Config{AppDataStoreType: types.KVStore})
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	signer := newTestPubKey(t)
	transport := &mockTransportClient{
		info: &client.Info{
			SignerPubKey:        hex.EncodeToString(signer.SerializeCompressed()),
			UnilateralExitDelay: testUnilateralExitDelay,
			BoardingExitDelay:   testBoardingExitDelay,
			CheckpointTapscript: testCheckpointTapscript,
		},
	}

	mgr, err := contract.NewManager(svc.ContractStore(), testNetwork, transport)
	require.NoError(t, err)
	t.Cleanup(mgr.Close)

	return mgr, svc.ContractStore()
}

func newTestKeyRef(t *testing.T) wallet.KeyRef {
	t.Helper()
	return wallet.KeyRef{Id: "m/0/0", PubKey: newTestPubKey(t)}
}

func newTestKeyRefAt(t *testing.T, id string) wallet.KeyRef {
	t.Helper()
	return wallet.KeyRef{Id: id, PubKey: newTestPubKey(t)}
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
