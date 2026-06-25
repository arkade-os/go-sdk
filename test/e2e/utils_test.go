package e2e_test

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

	singlekeywallet "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	inmemorystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	password          = "secret"
	serverUrl         = "127.0.0.1:7070"
	explorerUrl       = "http://127.0.0.1:3000"
	mockBoltzAdminURL = "http://127.0.0.1:9101"
	settleTimeout     = 90 * time.Second
)

func setupClient(t *testing.T, seed string, opts ...sdk.WalletOption) sdk.Wallet {
	t.Helper()

	arkClient, err := sdk.NewWallet(t.TempDir(), opts...)
	require.NoError(t, err)

	err = arkClient.Init(t.Context(), serverUrl, seed, password)
	require.NoError(t, err)

	err = arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.Nil(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(arkClient.Stop)

	return arkClient
}

// setupSwapClient creates a wallet with a single-key identity for swap/vhtlc
// tests that need direct access to the private key for manual PSBT signing.
func setupSwapClient(t *testing.T) (sdk.Wallet, *btcec.PrivateKey) {
	t.Helper()

	privkey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	store, err := inmemorystore.NewStore()
	require.NoError(t, err)
	singleKey, err := singlekeywallet.NewIdentity(store)
	require.NoError(t, err)

	seed := hex.EncodeToString(privkey.Serialize())
	w := setupClient(t, seed,
		sdk.WithIdentity(singleKey),
	)

	return w, privkey
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

	clientVtxoCh := client.GetVtxoEventChannel(ctx)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	var vtxo clientTypes.Vtxo
	go func() {
		defer wg.Done()
		for event := range clientVtxoCh {
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

// --- LND helpers (for Lightning swap tests) ---

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
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("parse lnd addinvoice response: %w (raw: %s)", err, out)
	}
	return resp.PaymentRequest, nil
}

func lndAddInvoiceWithHash(sats int) (string, string, error) {
	out, err := runCommand(
		"docker", "exec", "lnd",
		"lncli", "--network=regtest",
		"addinvoice", "--amt", fmt.Sprintf("%d", sats),
	)
	if err != nil {
		return "", "", fmt.Errorf("lnd addinvoice: %w", err)
	}

	var resp struct {
		PaymentRequest string `json:"payment_request"`
		RHash          string `json:"r_hash"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", "", fmt.Errorf("parse lnd addinvoice response: %w (raw: %s)", err, out)
	}
	return resp.PaymentRequest, resp.RHash, nil
}

func lndPayInvoice(invoice string) error {
	_, err := runCommand(
		"docker", "exec", "lnd",
		"lncli", "--network=regtest",
		"payinvoice", "--force", invoice,
	)
	return err
}

// --- Regtest BTC helpers ---

func getBlockHeight(t *testing.T) int {
	t.Helper()
	out, err := runCommand("nigiri", "rpc", "getblockcount")
	require.NoError(t, err)

	var height int
	_, err = fmt.Sscanf(strings.TrimSpace(out), "%d", &height)
	require.NoError(t, err)
	return height
}

func mineBlocks(t *testing.T, n int) {
	t.Helper()
	if n <= 0 {
		return
	}
	addr, err := runCommand("nigiri", "rpc", "getnewaddress")
	require.NoError(t, err)
	_, err = runCommand(
		"nigiri", "rpc", "generatetoaddress",
		fmt.Sprintf("%d", n), strings.TrimSpace(addr),
	)
	require.NoError(t, err)
}

func mineBlocksToHeight(t *testing.T, target int) {
	t.Helper()
	current := getBlockHeight(t)
	if current >= target {
		return
	}
	mineBlocks(t, target-current)
}

func sendToAddress(t *testing.T, address, amountBtc string) string {
	t.Helper()
	out, err := runCommand("nigiri", "rpc", "sendtoaddress", address, amountBtc)
	require.NoError(t, err)
	txid := strings.TrimSpace(out)
	require.NotEmpty(t, txid)
	return txid
}

func getRawTransaction(t *testing.T, txid string) string {
	t.Helper()
	out, err := runCommand("nigiri", "rpc", "getrawtransaction", txid)
	require.NoError(t, err)
	txhex := strings.TrimSpace(out)
	require.NotEmpty(t, txhex)
	return txhex
}

func fundAddressAndGetConfirmedTx(t *testing.T, address string, sats uint64) (string, string) {
	t.Helper()
	amountBtc := fmt.Sprintf("%d.%08d", sats/100000000, sats%100000000)
	txid := sendToAddress(t, address, amountBtc)
	mineBlocks(t, 10)
	txhex := getRawTransaction(t, txid)
	return txid, txhex
}

// --- Mock Boltz helpers ---

func injectMockBoltzSwapEvent(t *testing.T, swapID, status string) {
	t.Helper()
	injectMockBoltzSwapEventWithTx(t, swapID, status, "", "")
}

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

func resetMockBoltz(t *testing.T) {
	t.Helper()
	req, err := http.NewRequest("POST", mockBoltzAdminURL+"/admin/reset", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func setMockBoltzConfig(t *testing.T, config map[string]any) {
	t.Helper()
	body, err := json.Marshal(config)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", mockBoltzAdminURL+"/admin/config", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

type mockSwapState struct {
	ID               string `json:"id"`
	LastStatus       string `json:"lastStatus"`
	ServerLockAmount uint64 `json:"serverLockAmount"`
	BTCLockupAddress string `json:"btcLockupAddress"`
	ClaimRequests    int    `json:"claimRequests"`
	RefundRequests   int    `json:"refundRequests"`
}

func getMockBoltzSwap(t *testing.T, swapID string) map[string]any {
	t.Helper()
	url := fmt.Sprintf("%s/admin/swaps/%s", mockBoltzAdminURL, swapID)
	resp, err := http.Get(url) //nolint:gosec
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	var state map[string]any
	err = json.NewDecoder(resp.Body).Decode(&state)
	require.NoError(t, err)
	return state
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

// --- Thread-safe error collection ---

type concurrentErrors struct {
	mu   sync.Mutex
	errs []error
}

func (e *concurrentErrors) add(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errs = append(e.errs, err)
}
