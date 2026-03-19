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

func setupClient(t *testing.T) (sdk.ArkClient, *btcec.PrivateKey) {
	t.Helper()

	arkClient, err := sdk.NewArkClient("", false)
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

	return arkClient, privkey
}

func setupClientWithWallet(
	t *testing.T, prvkey string,
) (sdk.ArkClient, wallet.WalletService, transport.TransportClient) {
	t.Helper()

	arkClient, err := sdk.NewArkClient("", false)
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

// --- mock-boltz admin API helpers ---

const mockBoltzAdminURL = "http://127.0.0.1:9101"

// setMockBoltzConfig updates the mock-boltz runtime configuration via POST /admin/config.
// Accepted fields: claimMode, refundMode, arkRefundLocktimeSeconds, btcLockupTimeoutBlocks, etc.
func setMockBoltzConfig(t *testing.T, cfg map[string]any) {
	t.Helper()
	body, err := json.Marshal(cfg)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", mockBoltzAdminURL+"/admin/config", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"setMockBoltzConfig failed: %s", string(respBody))
}

// resetMockBoltz resets all swaps and runtime config to defaults via POST /admin/reset.
func resetMockBoltz(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest("POST", mockBoltzAdminURL+"/admin/reset", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// injectMockBoltzSwapEvent sends a swap status event via POST /admin/swaps/:id/event.
// This allows tests to force specific swap state transitions (e.g., swap.expired, transaction.lockupFailed).
func injectMockBoltzSwapEvent(t *testing.T, swapID, status string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"status": status})
	require.NoError(t, err)

	url := fmt.Sprintf("%s/admin/swaps/%s/event", mockBoltzAdminURL, swapID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"injectMockBoltzSwapEvent(%s, %s) failed: %s", swapID, status, string(respBody))
}

// getMockBoltzSwap retrieves a swap's state from mock-boltz via GET /admin/swaps/:id.
func getMockBoltzSwap(t *testing.T, swapID string) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/admin/swaps/%s", mockBoltzAdminURL, swapID)
	resp, err := http.Get(url) //nolint:gosec
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var result map[string]any
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)
	return result
}

// waitForMockBoltzHealth polls the mock-boltz /health endpoint until it returns 200 or the timeout expires.
func waitForMockBoltzHealth(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(mockBoltzAdminURL + "/health") //nolint:gosec
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("mock-boltz did not become healthy within timeout")
}

// --- LND helpers (for Lightning swap tests with real Boltz) ---

// lndAddInvoice creates a Lightning invoice on nigiri's LND node.
// Returns the payment_request string.
func lndAddInvoice(sats int) (string, error) {
	out, err := runCommand(
		"docker", "exec", "lnd",
		"lncli", "--network=regtest",
		"addinvoice", "--amt", fmt.Sprintf("%d", sats),
	)
	if err != nil {
		return "", fmt.Errorf("lnd addinvoice: %w", err)
	}

	var resp struct {
		PaymentRequest string `json:"payment_request"`
		RHash          string `json:"r_hash"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("parse lnd addinvoice response: %w (raw: %s)", err, out)
	}
	return resp.PaymentRequest, nil
}

// lndPayInvoice pays a Lightning invoice from nigiri's LND node.
func lndPayInvoice(invoice string) error {
	_, err := runCommand(
		"docker", "exec", "lnd",
		"lncli", "--network=regtest",
		"payinvoice", "--force", invoice,
	)
	return err
}

// --- Regtest BTC helpers ---

// getBlockHeight returns the current regtest block height via nigiri RPC.
func getBlockHeight(t *testing.T) int {
	t.Helper()
	out, err := runCommand("nigiri", "rpc", "getblockcount")
	require.NoError(t, err)

	var height int
	_, err = fmt.Sscanf(strings.TrimSpace(out), "%d", &height)
	require.NoError(t, err)
	return height
}

// mineBlocks generates n regtest blocks.
func mineBlocks(t *testing.T, n int) {
	t.Helper()
	if n <= 0 {
		return
	}
	addr, err := runCommand("nigiri", "rpc", "getnewaddress")
	require.NoError(t, err)
	_, err = runCommand("nigiri", "rpc", "generatetoaddress", fmt.Sprintf("%d", n), strings.TrimSpace(addr))
	require.NoError(t, err)
}

// mineBlocksToHeight mines blocks until the chain height reaches at least target.
func mineBlocksToHeight(t *testing.T, target int) {
	t.Helper()
	current := getBlockHeight(t)
	if current >= target {
		return
	}
	mineBlocks(t, target-current)
}

// sendToAddress sends the given BTC amount (as a string like "0.00003000")
// to the address and returns the txid.
func sendToAddress(t *testing.T, address, amountBtc string) string {
	t.Helper()
	out, err := runCommand("nigiri", "rpc", "sendtoaddress", address, amountBtc)
	require.NoError(t, err)
	txid := strings.TrimSpace(out)
	require.NotEmpty(t, txid)
	return txid
}

// getRawTransaction returns the raw hex of a transaction by txid.
func getRawTransaction(t *testing.T, txid string) string {
	t.Helper()
	out, err := runCommand("nigiri", "rpc", "getrawtransaction", txid)
	require.NoError(t, err)
	txhex := strings.TrimSpace(out)
	require.NotEmpty(t, txhex)
	return txhex
}

// fundAddressAndGetConfirmedTx sends sats to address, mines blocks to confirm,
// and returns the txid and raw tx hex.
func fundAddressAndGetConfirmedTx(t *testing.T, address string, sats uint64) (string, string) {
	t.Helper()
	amountBtc := fmt.Sprintf("%d.%08d", sats/100000000, sats%100000000)
	txid := sendToAddress(t, address, amountBtc)
	mineBlocks(t, 10)
	txhex := getRawTransaction(t, txid)
	return txid, txhex
}

// injectMockBoltzSwapEventWithTx sends a swap event via admin API with
// optional transaction ID and hex, used for events like transaction.server.mempool.
func injectMockBoltzSwapEventWithTx(t *testing.T, swapID, status, txid, txhex string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"status": status,
		"txid":   txid,
		"txhex":  txhex,
	})
	require.NoError(t, err)

	url := fmt.Sprintf("%s/admin/swaps/%s/event", mockBoltzAdminURL, swapID)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	require.Equalf(t, http.StatusOK, resp.StatusCode,
		"injectMockBoltzSwapEventWithTx(%s, %s) failed: %s", swapID, status, string(respBody))
}

// getMockBoltzSwapTyped retrieves a swap's state from mock-boltz as a typed struct.
type mockSwapState struct {
	ID               string `json:"id"`
	LastStatus       string `json:"lastStatus"`
	ServerLockAmount uint64 `json:"serverLockAmount"`
	BTCLockupAddress string `json:"btcLockupAddress"`
	ClaimRequests    int    `json:"claimRequests"`
	RefundRequests   int    `json:"refundRequests"`
}

func getMockBoltzSwapTyped(t *testing.T, swapID string) mockSwapState {
	t.Helper()
	url := fmt.Sprintf("%s/admin/swaps/%s", mockBoltzAdminURL, swapID)
	resp, err := http.Get(url) //nolint:gosec
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var state mockSwapState
	err = json.NewDecoder(resp.Body).Decode(&state)
	require.NoError(t, err)
	return state
}

// --- Thread-safe error collection for concurrent tests ---

type concurrentErrors struct {
	mu   sync.Mutex
	errs []error
}

func (e *concurrentErrors) add(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errs = append(e.errs, err)
}
