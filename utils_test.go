package arksdk_test

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

type mockWallet struct{}

var _ wallet.WalletService = (*mockWallet)(nil)

func (m *mockWallet) GetType() string {
	return "mock"
}
func (m *mockWallet) Create(_ context.Context, _, _ string) (string, error) {
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
func (m *mockWallet) GetAddresses(_ context.Context) (
	[]string, []clienttypes.Address, []clienttypes.Address, []clienttypes.Address, error,
) {
	return nil, nil, nil, nil, nil
}
func (m *mockWallet) NewAddress(_ context.Context, _ bool) (
	string, *clienttypes.Address, *clienttypes.Address, error,
) {
	return "", nil, nil, nil
}
func (m *mockWallet) NewAddresses(_ context.Context, _ bool, _ int) (
	[]string, []clienttypes.Address, []clienttypes.Address, error,
) {
	return nil, nil, nil, nil
}
func (m *mockWallet) SignTransaction(
	_ context.Context, _ explorer.Explorer, _ string,
) (string, error) {
	return "", nil
}
func (m *mockWallet) SignMessage(_ context.Context, _ []byte) (string, error) {
	return "", nil
}
func (m *mockWallet) Dump(_ context.Context) (string, error) {
	return "", nil
}
func (m *mockWallet) NewVtxoTreeSigner(_ context.Context, _ string) (tree.SignerSession, error) {
	return nil, nil
}
