package handlers_test

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
)

// mockClient is a minimal stub for client.Client. The default handler only invokes GetInfo
// (and Close on shutdown), so every other method returns zero values — they should never run
// during these tests.
type mockClient struct {
	info    *client.Info
	infoErr error
}

func (f *mockClient) GetInfo(_ context.Context) (*client.Info, error) {
	return f.info, f.infoErr
}

func (f *mockClient) RegisterIntent(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (f *mockClient) DeleteIntent(_ context.Context, _, _ string) error { return nil }

func (f *mockClient) EstimateIntentFee(
	_ context.Context, _, _ string,
) (int64, error) {
	return 0, nil
}

func (f *mockClient) ConfirmRegistration(_ context.Context, _ string) error { return nil }

func (f *mockClient) SubmitTreeNonces(
	_ context.Context, _, _ string, _ tree.TreeNonces,
) error {
	return nil
}

func (f *mockClient) SubmitTreeSignatures(
	_ context.Context, _, _ string, _ tree.TreePartialSigs,
) error {
	return nil
}

func (f *mockClient) SubmitSignedForfeitTxs(
	_ context.Context, _ []string, _ string,
) error {
	return nil
}

func (f *mockClient) GetEventStream(
	_ context.Context, _ []string,
) (<-chan client.BatchEventChannel, func(), error) {
	return nil, func() {}, nil
}

func (f *mockClient) SubmitTx(
	_ context.Context, _ string, _ []string,
) (string, string, []string, error) {
	return "", "", nil, nil
}

func (f *mockClient) FinalizeTx(_ context.Context, _ string, _ []string) error {
	return nil
}

func (f *mockClient) GetPendingTx(
	_ context.Context, _, _ string,
) ([]client.AcceptedOffchainTx, error) {
	return nil, nil
}

func (f *mockClient) GetTransactionsStream(
	_ context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	return nil, func() {}, nil
}

func (f *mockClient) ModifyStreamTopics(
	_ context.Context, _, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (f *mockClient) OverwriteStreamTopics(
	_ context.Context, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (f *mockClient) Close() {}
