package arksdk_test

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/chaincfg"
)

type mockWallet struct{}

var _ wallet.WalletService = (*mockWallet)(nil)

func (m *mockWallet) GetType() string {
	return "mock"
}
func (m *mockWallet) Create(_ context.Context, _ chaincfg.Params, _, _ string) (string, error) {
	return "", nil
}
func (m *mockWallet) Lock(_ context.Context) error {
	return nil
}
func (m *mockWallet) Unlock(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (m *mockWallet) IsLocked() bool {
	return false
}
func (m *mockWallet) NextIndex(_ context.Context) (uint32, error) {
	return 0, nil
}
func (m *mockWallet) NewKey(_ context.Context) (*wallet.KeyRef, error) {
	return nil, nil
}
func (m *mockWallet) GetKey(_ context.Context, _ string) (*wallet.KeyRef, error) {
	return nil, nil
}
func (m *mockWallet) ListKeys(_ context.Context) ([]wallet.KeyRef, error) {
	return nil, nil
}
func (m *mockWallet) SignTransaction(
	_ context.Context, _ string, _ map[string]string,
) (string, error) {
	return "", nil
}
func (m *mockWallet) SignMessage(_ context.Context, _ []byte) (string, error) {
	return "", nil
}
func (m *mockWallet) Dump(_ context.Context) (string, error) {
	return "", nil
}
func (m *mockWallet) NewVtxoTreeSigner(_ context.Context) (tree.SignerSession, error) {
	return nil, nil
}
