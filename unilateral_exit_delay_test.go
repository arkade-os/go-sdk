package arksdk

import (
	"context"
	"encoding/hex"
	"net"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestEffectiveUnilateralExitDelay(t *testing.T) {
	t.Run("mainnet is hardcoded to seven days", func(t *testing.T) {
		current := arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 86528,
		}

		got := effectiveUnilateralExitDelay(arklib.Bitcoin, current)

		require.Equal(t, mainnetUnilateralExitDelay, got)
	})

	t.Run("non-mainnet networks keep server value", func(t *testing.T) {
		current := arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 86528,
		}

		for _, network := range []arklib.Network{
			arklib.BitcoinRegTest,
			arklib.BitcoinTestNet,
			arklib.BitcoinSigNet,
			arklib.BitcoinMutinyNet,
		} {
			t.Run(network.Name, func(t *testing.T) {
				got := effectiveUnilateralExitDelay(network, current)
				require.Equal(t, current, got)
			})
		}
	})
}

func TestNormalizePersistedUnilateralExitDelay(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	client, err := NewArkClient(t.TempDir())
	require.NoError(t, err)

	cfg := clientTypes.Config{
		ServerUrl:     "localhost:7070",
		SignerPubKey:  privKey.PubKey(),
		ForfeitPubKey: privKey.PubKey(),
		WalletType:    "singlekey",
		Network:       arklib.Bitcoin,
		ExplorerURL:   "https://mempool.space/api",
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 86528,
		},
	}
	require.NoError(t, client.GetConfigStore().AddData(t.Context(), cfg))

	normalizedCfg, changed, err := normalizePersistedUnilateralExitDelay(
		t.Context(),
		client.GetConfigStore(),
	)
	require.NoError(t, err)
	require.True(t, changed)
	require.NotNil(t, normalizedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, normalizedCfg.UnilateralExitDelay)

	storedCfg, err := client.GetConfigStore().GetData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, storedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, storedCfg.UnilateralExitDelay)
}

func TestLoadArkClientUsesStoredUnilateralExitDelay(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	datadir := t.TempDir()
	client, err := NewArkClient(datadir)
	require.NoError(t, err)

	cfg := clientTypes.Config{
		ServerUrl:     "localhost:7070",
		SignerPubKey:  privKey.PubKey(),
		ForfeitPubKey: privKey.PubKey(),
		WalletType:    "singlekey",
		Network:       arklib.Bitcoin,
		ExplorerURL:   "https://mempool.space/api",
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: mainnetUnilateralExitDelaySeconds,
		},
	}
	require.NoError(t, client.GetConfigStore().AddData(t.Context(), cfg))

	loaded, err := LoadArkClient(datadir)
	require.NoError(t, err)

	loadedCfg, err := loaded.GetConfigData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, loadedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, loadedCfg.UnilateralExitDelay)
}

func TestLoadArkClientNormalizesMainnetUnilateralExitDelay(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	datadir := t.TempDir()
	client, err := NewArkClient(datadir)
	require.NoError(t, err)

	cfg := clientTypes.Config{
		ServerUrl:     "localhost:7070",
		SignerPubKey:  privKey.PubKey(),
		ForfeitPubKey: privKey.PubKey(),
		WalletType:    "singlekey",
		Network:       arklib.Bitcoin,
		ExplorerURL:   "https://mempool.space/api",
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 86528,
		},
	}
	require.NoError(t, client.GetConfigStore().AddData(t.Context(), cfg))

	loaded, err := LoadArkClient(datadir)
	require.NoError(t, err)

	loadedCfg, err := loaded.GetConfigData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, loadedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, loadedCfg.UnilateralExitDelay)

	storedCfg, err := loaded.GetConfigStore().GetData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, storedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, storedCfg.UnilateralExitDelay)
}

func TestInitNormalizesMainnetUnilateralExitDelay(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	serverURL := startTestArkInfoServer(t, &arkv1.GetInfoResponse{
		SignerPubkey:        hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		ForfeitPubkey:       hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		Network:             arklib.Bitcoin.Name,
		SessionDuration:     15,
		UnilateralExitDelay: 86528,
		BoardingExitDelay:   2048,
		Dust:                450,
	})

	client, err := NewArkClient(t.TempDir())
	require.NoError(t, err)

	err = client.Init(
		t.Context(),
		serverURL,
		"",
		"password",
		WithExplorerURL("http://127.0.0.1:3000"),
	)
	require.NoError(t, err)

	cfg, err := client.GetConfigData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, mainnetUnilateralExitDelay, cfg.UnilateralExitDelay)

	storedCfg, err := client.GetConfigStore().GetData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, storedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, storedCfg.UnilateralExitDelay)
}

func TestInitWithWalletNormalizesMainnetUnilateralExitDelay(t *testing.T) {
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	serverURL := startTestArkInfoServer(t, &arkv1.GetInfoResponse{
		SignerPubkey:        hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		ForfeitPubkey:       hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
		Network:             arklib.Bitcoin.Name,
		SessionDuration:     15,
		UnilateralExitDelay: 86528,
		BoardingExitDelay:   2048,
		Dust:                450,
	})

	client, err := NewArkClient(t.TempDir())
	require.NoError(t, err)

	err = client.Init(
		t.Context(),
		serverURL,
		"",
		"password",
		WithExplorerURL("http://127.0.0.1:3000"),
		WithWallet(&testWalletService{}),
	)
	require.NoError(t, err)

	cfg, err := client.GetConfigData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, mainnetUnilateralExitDelay, cfg.UnilateralExitDelay)

	storedCfg, err := client.GetConfigStore().GetData(t.Context())
	require.NoError(t, err)
	require.NotNil(t, storedCfg)
	require.Equal(t, mainnetUnilateralExitDelay, storedCfg.UnilateralExitDelay)
}


type testArkServiceServer struct {
	arkv1.UnimplementedArkServiceServer
	info *arkv1.GetInfoResponse
}

type testWalletService struct{}

func (w *testWalletService) GetType() string { return "test-wallet" }
func (w *testWalletService) Create(context.Context, string, string) (string, error) {
	return "", nil
}
func (w *testWalletService) Lock(context.Context) error                   { return nil }
func (w *testWalletService) Unlock(context.Context, string) (bool, error) { return false, nil }
func (w *testWalletService) IsLocked() bool                               { return false }
func (w *testWalletService) Dump(context.Context) (string, error)         { return "", nil }
func (w *testWalletService) GetAddresses(context.Context) ([]string, []clientTypes.Address, []clientTypes.Address, []clientTypes.Address, error) {
	return nil, nil, nil, nil, nil
}
func (w *testWalletService) NewAddress(context.Context, bool) (string, *clientTypes.Address, *clientTypes.Address, error) {
	return "", nil, nil, nil
}
func (w *testWalletService) NewAddresses(context.Context, bool, int) ([]string, []clientTypes.Address, []clientTypes.Address, error) {
	return nil, nil, nil, nil
}
func (w *testWalletService) SignTransaction(context.Context, explorer.Explorer, string) (string, error) {
	return "", nil
}
func (w *testWalletService) SignMessage(context.Context, []byte) (string, error) {
	return "", nil
}
func (w *testWalletService) NewVtxoTreeSigner(context.Context, string) (tree.SignerSession, error) {
	return nil, nil
}

var _ wallet.WalletService = (*testWalletService)(nil)

func (s *testArkServiceServer) GetInfo(
	context.Context,
	*arkv1.GetInfoRequest,
) (*arkv1.GetInfoResponse, error) {
	return s.info, nil
}

func startTestArkInfoServer(
	t *testing.T,
	info *arkv1.GetInfoResponse,
) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	arkv1.RegisterArkServiceServer(server, &testArkServiceServer{info: info})

	go func() {
		_ = server.Serve(lis)
	}()

	t.Cleanup(func() {
		server.Stop()
		_ = lis.Close()
	})

	return lis.Addr().String()
}