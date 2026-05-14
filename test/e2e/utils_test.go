package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const (
	password  = "secret"
	serverUrl = "127.0.0.1:7070"
)

var explorerUrl = func() string {
	if u := os.Getenv("ARK_ELECTRUM_URL"); u != "" {
		return u
	}
	return "tcp://127.0.0.1:50001"
}()

var esploraUrl = os.Getenv("ARK_ESPLORA_URL")

func setupClient(t *testing.T, seed string, opts ...sdk.WalletOption) sdk.Wallet {
	t.Helper()

	arkClient, err := sdk.NewWallet(t.TempDir(), opts...)
	require.NoError(t, err)

	initOpts := []sdk.InitOption{sdk.WithElectrumExplorer(explorerUrl)}
	if esploraUrl != "" {
		initOpts = append(initOpts, sdk.WithElectrumPackageBroadcastURL(esploraUrl))
	}
	err = arkClient.Init(
		t.Context(),
		serverUrl,
		seed,
		password,
		initOpts...,
	)
	require.NoError(t, err)

	err = arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.Nil(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(arkClient.Stop)

	return arkClient
}

func faucetOnchain(t *testing.T, address string, amount float64) {
	_, err := runCommand("nigiri", "faucet", address, fmt.Sprintf("%.8f", amount))
	require.NoError(t, err)
}

func faucetOffchain(
	t *testing.T, client sdk.Wallet, amount float64,
) clientTypes.Vtxo {
	ctx := t.Context()

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

func generateBlocks(t *testing.T, n int) {
	_, err := runCommand("nigiri", "rpc", "--generate", fmt.Sprintf("%d", n))
	require.NoError(t, err)
}

func recvUtxoEvent(t *testing.T, ch <-chan types.UtxoEvent) types.UtxoEvent {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for utxo event")
		return types.UtxoEvent{}
	}
}

func recvVtxoEvent(t *testing.T, ch <-chan types.VtxoEvent) types.VtxoEvent {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for vtxo event")
		return types.VtxoEvent{}
	}
}

func recvTxEvent(t *testing.T, ch <-chan types.TransactionEvent) types.TransactionEvent {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(60 * time.Second):
		t.Fatal("timed out waiting for tx event")
		return types.TransactionEvent{}
	}
}
