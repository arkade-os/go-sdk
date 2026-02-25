package e2e

import (
	"bytes"
	"context"
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

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/client"
	grpcclient "github.com/arkade-os/go-sdk/client/grpc"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet"
	singlekeywallet "github.com/arkade-os/go-sdk/wallet/singlekey"
	inmemorystore "github.com/arkade-os/go-sdk/wallet/singlekey/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	password  = "secret"
	serverUrl = "127.0.0.1:7070"
)

func setupClient(t *testing.T) arksdk.ArkClient {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	client, err := arksdk.NewArkClient(appDataStore)
	require.NoError(t, err)

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	privkeyHex := hex.EncodeToString(privkey.Serialize())

	err = client.Init(t.Context(), arksdk.InitArgs{
		WalletType:           arksdk.SingleKeyWallet,
		ClientType:           arksdk.GrpcClient,
		ServerUrl:            serverUrl,
		Password:             password,
		Seed:                 privkeyHex,
		WithTransactionFeed:  true,
		ExplorerPollInterval: time.Second,
	})
	require.NoError(t, err)

	err = client.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-client.IsSynced(t.Context())
	require.True(t, synced.Synced)
	require.Nil(t, synced.Err)

	return client
}

func setupClientWithWallet(
	t *testing.T, withoutFinalizePendingTxs bool, prvkey string,
) (arksdk.ArkClient, wallet.WalletService, client.TransportClient) {
	appDataStore, err := store.NewStore(store.Config{
		ConfigStoreType:  types.InMemoryStore,
		AppDataStoreType: types.KVStore,
	})
	require.NoError(t, err)

	var opts []arksdk.ClientOption
	if withoutFinalizePendingTxs {
		opts = append(opts, arksdk.WithoutFinalizePendingTxs())
	}
	client, err := arksdk.NewArkClient(appDataStore, opts...)
	require.NoError(t, err)

	walletStore, err := inmemorystore.NewWalletStore()
	require.NoError(t, err)
	require.NotNil(t, walletStore)

	wallet, err := singlekeywallet.NewBitcoinWallet(appDataStore.ConfigStore(), walletStore)
	require.NoError(t, err)

	if len(prvkey) <= 0 {
		key, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		prvkey = hex.EncodeToString(key.Serialize())
	}

	err = client.InitWithWallet(context.Background(), arksdk.InitWithWalletArgs{
		Wallet:               wallet,
		ClientType:           arksdk.GrpcClient,
		ServerUrl:            serverUrl,
		Password:             password,
		Seed:                 prvkey,
		WithTransactionFeed:  true,
		ExplorerPollInterval: 2 * time.Second,
	})
	require.NoError(t, err)

	err = client.Unlock(context.Background(), password)
	require.NoError(t, err)

	synced := <-client.IsSynced(t.Context())
	require.True(t, synced.Synced)
	require.Nil(t, synced.Err)

	grpcClient, err := grpcclient.NewClient(serverUrl)
	require.NoError(t, err)

	return client, wallet, grpcClient
}

func faucetOnchain(t *testing.T, address string, amount float64) {
	_, err := runCommand("nigiri", "faucet", address, fmt.Sprintf("%.8f", amount))
	require.NoError(t, err)
}

func faucetOffchain(t *testing.T, client arksdk.ArkClient, amount float64) types.Vtxo {
	ctx := t.Context()
	_, offchainAddr, _, err := client.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, offchainAddr)

	note := generateNote(t, uint64(amount*1e8))

	aliceVtxoCh := client.GetVtxoEventChannel(ctx)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var vtxo types.Vtxo
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
