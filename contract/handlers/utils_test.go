package handlers_test

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
)

// mockTransportClient is a minimal stub for client.TransportClient. The default
// handler only invokes GetInfo (and Close on shutdown), so every other method
// returns zero values — they should never run during these tests.
type mockTransportClient struct {
	info    *client.Info
	infoErr error
}

func (f *mockTransportClient) GetInfo(_ context.Context) (*client.Info, error) {
	return f.info, f.infoErr
}

func (f *mockTransportClient) RegisterIntent(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (f *mockTransportClient) DeleteIntent(_ context.Context, _, _ string) error { return nil }

func (f *mockTransportClient) EstimateIntentFee(
	_ context.Context, _, _ string,
) (int64, error) {
	return 0, nil
}

func (f *mockTransportClient) ConfirmRegistration(_ context.Context, _ string) error { return nil }

func (f *mockTransportClient) SubmitTreeNonces(
	_ context.Context, _, _ string, _ tree.TreeNonces,
) error {
	return nil
}

func (f *mockTransportClient) SubmitTreeSignatures(
	_ context.Context, _, _ string, _ tree.TreePartialSigs,
) error {
	return nil
}

func (f *mockTransportClient) SubmitSignedForfeitTxs(
	_ context.Context, _ []string, _ string,
) error {
	return nil
}

func (f *mockTransportClient) GetEventStream(
	_ context.Context, _ []string,
) (<-chan client.BatchEventChannel, func(), error) {
	return nil, func() {}, nil
}

func (f *mockTransportClient) SubmitTx(
	_ context.Context, _ string, _ []string,
) (string, string, []string, error) {
	return "", "", nil, nil
}

func (f *mockTransportClient) FinalizeTx(_ context.Context, _ string, _ []string) error {
	return nil
}

func (f *mockTransportClient) GetPendingTx(
	_ context.Context, _, _ string,
) ([]client.AcceptedOffchainTx, error) {
	return nil, nil
}

func (f *mockTransportClient) GetTransactionsStream(
	_ context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	return nil, func() {}, nil
}

func (f *mockTransportClient) ModifyStreamTopics(
	_ context.Context, _, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (f *mockTransportClient) OverwriteStreamTopics(
	_ context.Context, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (f *mockTransportClient) Close() {}
