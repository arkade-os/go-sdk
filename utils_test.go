package arksdk_test

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
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

func TestValidateAddress(t *testing.T) {
	// Generate keys once for constructing addresses programmatically.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pubKey := privKey.PubKey()
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	// Onchain addresses across different networks and script types.
	p2pkhMainnet, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	require.NoError(t, err)
	p2wpkhMainnet, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	require.NoError(t, err)
	p2trMainnet, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(pubKey), &chaincfg.MainNetParams)
	require.NoError(t, err)
	p2pkhTestnet, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.TestNet3Params)
	require.NoError(t, err)
	p2trRegtest, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(pubKey), &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	// Offchain Ark address (tark = Bitcoin testnet HRP).
	signerKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	arkAddr := arklib.Address{
		Version:    0,
		HRP:        arklib.BitcoinTestNet.Addr,
		VtxoTapKey: pubKey,
		Signer:     signerKey.PubKey(),
	}
	offchainAddr, err := arkAddr.EncodeV0()
	require.NoError(t, err)

	t.Run("valid onchain", func(t *testing.T) {
		fixtures := []struct {
			name    string
			address string
		}{
			{"mainnet P2PKH", p2pkhMainnet.String()},
			{"mainnet P2WPKH", p2wpkhMainnet.String()},
			{"mainnet P2TR", p2trMainnet.String()},
			{"testnet P2PKH", p2pkhTestnet.String()},
			{"regtest P2TR", p2trRegtest.String()},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				isOnchain, isOffchain, err := arksdk.ValidateAddress(f.address)
				require.NoError(t, err)
				require.True(t, isOnchain)
				require.False(t, isOffchain)
			})
		}
	})

	t.Run("valid offchain", func(t *testing.T) {
		isOnchain, isOffchain, err := arksdk.ValidateAddress(offchainAddr)
		require.NoError(t, err)
		require.False(t, isOnchain)
		require.True(t, isOffchain)
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name    string
			address string
		}{
			{"empty string", ""},
			{"random garbage", "not-an-address"},
			{"unknown bech32 prefix", "wrongprefix1qt9tfh7c09hlsstzq5y9tzuwyaesrwr8gpy8cn29cxv0flp64958s0n0yd0"},
			{"truncated bech32", "bc1q"},
			{"truncated ark address", offchainAddr[:len(offchainAddr)/2]},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				isOnchain, isOffchain, err := arksdk.ValidateAddress(f.address)
				require.Error(t, err)
				require.False(t, isOnchain)
				require.False(t, isOffchain)
			})
		}
	})
}
