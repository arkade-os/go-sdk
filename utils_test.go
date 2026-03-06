package arksdk_test

import (
	"context"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
)

type mockWallet struct{}

var _ wallet.WalletService = (*mockWallet)(nil)

func (m *mockWallet) GetType() string                                       { return "mock" }
func (m *mockWallet) Create(_ context.Context, _, _ string) (string, error) { return "", nil }
func (m *mockWallet) Lock(_ context.Context) error                          { return nil }
func (m *mockWallet) Unlock(_ context.Context, _ string) (bool, error)      { return false, nil }
func (m *mockWallet) IsLocked() bool                                        { return false }
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
func (m *mockWallet) SignMessage(_ context.Context, _ []byte) (string, error) { return "", nil }
func (m *mockWallet) Dump(_ context.Context) (string, error)                  { return "", nil }
func (m *mockWallet) NewVtxoTreeSigner(_ context.Context, _ string) (tree.SignerSession, error) {
	return nil, nil
}

type mockExplorer struct{}

var _ explorer.Explorer = (*mockExplorer)(nil)

func (m *mockExplorer) Start()                                 {}
func (m *mockExplorer) Stop()                                  {}
func (m *mockExplorer) GetTxHex(_ string) (string, error)      { return "", nil }
func (m *mockExplorer) Broadcast(_ ...string) (string, error)  { return "", nil }
func (m *mockExplorer) GetTxs(_ string) ([]explorer.Tx, error) { return nil, nil }
func (m *mockExplorer) GetTxOutspends(_ string) ([]explorer.SpentStatus, error) {
	return nil, nil
}
func (m *mockExplorer) GetUtxos(_ string) ([]explorer.Utxo, error) { return nil, nil }
func (m *mockExplorer) GetRedeemedVtxosBalance(
	_ string, _ arklib.RelativeLocktime,
) (uint64, map[int64]uint64, error) {
	return 0, nil, nil
}
func (m *mockExplorer) GetTxBlockTime(_ string) (bool, int64, error)               { return false, 0, nil }
func (m *mockExplorer) BaseUrl() string                                            { return "" }
func (m *mockExplorer) GetFeeRate() (float64, error)                               { return 0, nil }
func (m *mockExplorer) GetConnectionCount() int                                    { return 0 }
func (m *mockExplorer) GetSubscribedAddresses() []string                           { return nil }
func (m *mockExplorer) IsAddressSubscribed(_ string) bool                          { return false }
func (m *mockExplorer) GetAddressesEvents() <-chan clienttypes.OnchainAddressEvent { return nil }
func (m *mockExplorer) SubscribeForAddresses(_ []string) error                     { return nil }
func (m *mockExplorer) UnsubscribeForAddresses(_ []string) error                   { return nil }
