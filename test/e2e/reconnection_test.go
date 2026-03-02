package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const adminServerURL = "http://127.0.0.1:7071"

type walletStatusResponse struct {
	Initialized bool `json:"initialized"`
	Unlocked    bool `json:"unlocked"`
	Synced      bool `json:"synced"`
}

func TestReconnectionAfterArkdRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	alice := setupClient(t)
	t.Cleanup(func() { alice.Stop() })

	aliceTxCh := alice.GetTransactionEventChannel(ctx)
	aliceVtxoCh := alice.GetVtxoEventChannel(ctx)
	require.NotNil(t, aliceTxCh)
	require.NotNil(t, aliceVtxoCh)

	restartArkdAndWaitReady(t, 90*time.Second)

	drainVtxoEvents(aliceVtxoCh)
	drainTxEvents(aliceTxCh)

	_, aliceOffchainAddr, _, err := alice.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceOffchainAddr)

	note := generateNote(t, 21_000)
	_, err = alice.RedeemNotes(ctx, []string{note})
	require.NoError(t, err)

	require.NoError(t, waitForVtxoAddedEvent(aliceVtxoCh, 45*time.Second))

	bob := setupClient(t)
	t.Cleanup(func() { bob.Stop() })

	_, bobOffchainAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobOffchainAddr)

	arkTxid, err := alice.SendOffChain(ctx, []types.Receiver{{
		To:     bobOffchainAddr,
		Amount: 1_000,
	}})
	require.NoError(t, err)
	require.NotEmpty(t, arkTxid)

	require.NoError(t, waitForArkTxEvent(aliceTxCh, arkTxid, 45*time.Second))
}

func restartArkdAndWaitReady(t *testing.T, timeout time.Duration) {
	t.Helper()

	_, err := runCommand("docker", "stop", "arkd")
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		running, err := isContainerRunning("arkd")
		return err == nil && !running
	}, 20*time.Second, 500*time.Millisecond)

	_, err = runCommand("docker", "start", "arkd")
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		running, err := isContainerRunning("arkd")
		return err == nil && running
	}, 20*time.Second, 500*time.Millisecond)

	require.Eventually(t, func() bool {
		status, err := getArkdWalletStatus()
		if err != nil {
			return false
		}
		if !status.Initialized {
			return false
		}
		if !status.Unlocked {
			_ = unlockArkdWallet()
			return false
		}
		return status.Synced
	}, timeout, time.Second, "arkd wallet did not become initialized/unlocked/synced")
}

func isContainerRunning(name string) (bool, error) {
	out, err := runCommand("docker", "inspect", "-f", "{{.State.Running}}", name)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
}

func getArkdWalletStatus() (*walletStatusResponse, error) {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, adminServerURL+"/v1/admin/wallet/status", nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var status walletStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	return &status, nil
}

func unlockArkdWallet() error {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	body := []byte(fmt.Sprintf(`{"password":"%s"}`, password))
	req, err := http.NewRequest(
		http.MethodPost,
		adminServerURL+"/v1/admin/wallet/unlock",
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= http.StatusBadRequest {
		payload, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unlock endpoint returned %d: %s", resp.StatusCode, string(payload))
	}
	return nil
}

func drainVtxoEvents(ch <-chan types.VtxoEvent) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func drainTxEvents(ch <-chan types.TransactionEvent) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func waitForVtxoAddedEvent(ch <-chan types.VtxoEvent, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return fmt.Errorf("vtxo channel closed")
			}
			if event.Type == types.VtxosAdded && len(event.Vtxos) > 0 {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for VTXOS_ADDED event")
		}
	}
}

func waitForArkTxEvent(
	ch <-chan types.TransactionEvent,
	arkTxid string,
	timeout time.Duration,
) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return fmt.Errorf("transaction channel closed")
			}
			for _, tx := range event.Txs {
				if tx.ArkTxid == arkTxid {
					return nil
				}
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for ark tx event %s", arkTxid)
		}
	}
}
