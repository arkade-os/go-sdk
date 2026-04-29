package e2e

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	transport "github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store/inmemory"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	password    = "secret"
	serverUrl   = "127.0.0.1:7070"
	explorerUrl = "http://127.0.0.1:3000"
)

type testStoreBackend struct {
	name string
}

func (b testStoreBackend) datadir(t *testing.T) string {
	t.Helper()

	if b.name == "sql" {
		return t.TempDir()
	}

	return ""
}

func (b testStoreBackend) setupClient(t *testing.T) sdk.ArkClient {
	t.Helper()

	return setupClientWithDatadir(t, b.datadir(t))
}

// setupClientWithOptions creates a client backed by this store with the given
// extra ClientOptions applied (in addition to the default test setup).
func (b testStoreBackend) setupClientWithOptions(
	t *testing.T, opts ...sdk.ClientOption,
) sdk.ArkClient {
	t.Helper()

	return setupClientWithDatadir(t, b.datadir(t), opts...)
}

func (b testStoreBackend) setupClientWithWallet(
	t *testing.T, prvkey string,
) (sdk.ArkClient, wallet.WalletService, transport.TransportClient) {
	t.Helper()

	return setupClientWithWalletAndDatadir(t, b.datadir(t), prvkey)
}

func runForEachStoreBackend(t *testing.T, fn func(t *testing.T, backend testStoreBackend)) {
	t.Helper()

	backends := []testStoreBackend{
		{name: "kv"},
		{name: "sql"},
	}

	for _, backend := range backends {
		t.Run(backend.name, func(t *testing.T) {
			fn(t, backend)
		})
	}
}

func setupClientWithDatadir(
	t *testing.T, datadir string, opts ...sdk.ClientOption,
) sdk.ArkClient {
	t.Helper()

	arkClient, err := sdk.NewArkClient(datadir, opts...)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	err = arkClient.Init(t.Context(), serverUrl, privkeyHex, password)
	require.NoError(t, err)

	err = arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.True(t, synced.Synced)
	require.Nil(t, synced.Err)

	t.Cleanup(arkClient.Stop)

	return arkClient
}

func setupClientWithWalletAndDatadir(
	t *testing.T, datadir, prvkey string,
) (sdk.ArkClient, wallet.WalletService, transport.TransportClient) {
	t.Helper()

	arkClient, err := sdk.NewArkClient(datadir)
	require.NoError(t, err)
	require.NotNil(t, arkClient)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)
	require.NotNil(t, walletStore)

	configStore := arkClient.GetConfigStore()
	require.NotNil(t, configStore)

	wallet, err := singlekeywallet.NewBitcoinWallet(configStore, walletStore)
	require.NoError(t, err)

	if len(prvkey) <= 0 {
		key, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		prvkey = hex.EncodeToString(key.Serialize())
	}

	err = arkClient.Init(t.Context(), serverUrl, prvkey, password, sdk.WithWallet(wallet))
	require.NoError(t, err)

	err = arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.True(t, synced.Synced)
	require.Nil(t, synced.Err)

	t.Cleanup(arkClient.Stop)

	grpcClient, err := grpcclient.NewClient(serverUrl)
	require.NoError(t, err)

	return arkClient, wallet, grpcClient
}

func faucetOnchain(t *testing.T, address string, amount float64) {
	_, err := runCommand("nigiri", "faucet", address, fmt.Sprintf("%.8f", amount))
	require.NoError(t, err)
}

func faucetOffchain(t *testing.T, client sdk.ArkClient, amount float64) clientTypes.Vtxo {
	ctx := t.Context()
	offchainAddr, err := client.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, offchainAddr)

	note := generateNote(t, uint64(amount*1e8))

	aliceVtxoCh := client.GetVtxoEventChannel(ctx)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var vtxo clientTypes.Vtxo
	go func() {
		defer wg.Done()
		for event := range aliceVtxoCh {
			if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
				continue
			}
			vtxo = event.Vtxos[0]
			break
		}
	}()

	txid, err := client.RedeemNotes(ctx, []string{note})
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	wg.Wait()

	return vtxo
}

func generateNote(t *testing.T, amount uint64) string {
	adminHttpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	reqBody := bytes.NewReader([]byte(fmt.Sprintf(`{"amount": "%d"}`, amount)))
	req, err := http.NewRequest("POST", "http://127.0.0.1:7071/v1/admin/note", reqBody)
	if err != nil {
		t.Fatalf("failed to prepare note request: %s", err)
	}
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	req.Header.Set("Content-Type", "application/json")

	resp, err := adminHttpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to create note: %s", err)
	}

	var noteResp struct {
		Notes []string `json:"notes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&noteResp); err != nil {
		t.Fatalf("failed to parse response: %s", err)
	}

	return noteResp.Notes[0]
}

func runCommand(name string, arg ...string) (string, error) {
	errb := new(strings.Builder)
	cmd := newCommand(name, arg...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}

	if err := cmd.Start(); err != nil {
		return "", err
	}
	output := new(strings.Builder)
	errorb := new(strings.Builder)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(output, stdout); err != nil {
			fmt.Fprintf(errb, "error reading stdout: %s", err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(errorb, stderr); err != nil {
			fmt.Fprintf(errb, "error reading stderr: %s", err)
		}
	}()

	wg.Wait()
	if err := cmd.Wait(); err != nil {
		if errMsg := errorb.String(); len(errMsg) > 0 {
			return "", fmt.Errorf("%s", errMsg)
		}

		if outMsg := output.String(); len(outMsg) > 0 {
			return "", fmt.Errorf("%s", outMsg)
		}

		return "", err
	}

	if errMsg := errb.String(); len(errMsg) > 0 {
		return "", fmt.Errorf("%s", errMsg)
	}

	return strings.Trim(output.String(), "\n"), nil
}

func newCommand(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}

func generateBlocks(n int) error {
	_, err := runCommand("nigiri", "rpc", "--generate", fmt.Sprintf("%d", n))
	return err
}
