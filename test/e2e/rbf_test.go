package e2e

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSettleAfterRBFBumpFee verifies that boarding UTXOs funded via
// RBF-replaced transactions (bumpfee) can be settled correctly.
//
// Bitcoin Core's bumpfee can reorder transaction outputs. This test
// ensures the SDK correctly tracks the boarding output even when its
// vout index changes in the replacement transaction.
func TestSettleAfterRBFBumpFee(t *testing.T) {
	ctx := t.Context()
	client := setupClient(t, "")

	// Get the boarding address.
	_, _, boardingAddrs, _, err := client.GetAddresses(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, boardingAddrs)
	boardingAddr := boardingAddrs[0].Address
	t.Logf("boarding address: %s", boardingAddr)

	// Create a dedicated Bitcoin Core wallet for RBF testing with low fee rate.
	walletName := fmt.Sprintf("rbftest_%d", time.Now().UnixNano())
	_, err = runCommand("nigiri", "rpc", "createwallet", walletName)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = runCommand("nigiri", "rpc", "unloadwallet", walletName)
	})

	rpc := func(args ...string) (string, error) {
		fullArgs := append([]string{"rpc", fmt.Sprintf("-rpcwallet=%s", walletName)}, args...)
		return runCommand("nigiri", fullArgs...)
	}

	// Fund the test wallet.
	fundAddr, err := rpc("getnewaddress", "", "bech32m")
	require.NoError(t, err)
	fundAddr = strings.TrimSpace(fundAddr)

	faucetOnchain(t, fundAddr, 1)
	require.NoError(t, generateBlocks(1))

	// Set a low fee rate so bumpfee has room to increase.
	_, err = rpc("settxfee", "0.00001000")
	require.NoError(t, err)

	// Send 5 boarding transactions, each RBF-bumped before mining.
	const numBoardingTxs = 5
	for i := range numBoardingTxs {
		txidOut, err := rpc("-named", "sendtoaddress",
			fmt.Sprintf("address=%s", boardingAddr),
			"amount=0.001",
			"replaceable=true",
		)
		require.NoError(t, err)
		origTxid := strings.TrimSpace(txidOut)
		t.Logf("boarding tx %d original: %s", i+1, origTxid)

		// Bump the fee — this creates a replacement tx that may reorder outputs.
		bumpOut, err := rpc("bumpfee", origTxid)
		require.NoError(t, err)

		var bumpResp struct {
			Txid string `json:"txid"`
		}
		require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(bumpOut)), &bumpResp))
		t.Logf("boarding tx %d bumped:   %s", i+1, bumpResp.Txid)
	}

	// Mine all replacement transactions.
	require.NoError(t, generateBlocks(1))

	// Wait for the SDK to detect the confirmed UTXOs, then settle.
	require.Eventually(t, func() bool {
		_, err := client.Settle(ctx)
		if err != nil {
			t.Logf("settle attempt: %v", err)
		}
		return err == nil
	}, 60*time.Second, 2*time.Second, "settle should succeed after RBF bumpfee")

	t.Log("settle succeeded after RBF bumpfee")

	// Verify balance reflects the settled funds.
	balance, err := client.Balance(ctx)
	require.NoError(t, err)
	require.Greater(t, int(balance.OffchainBalance.Total), 0,
		"balance should be positive after settling bumped boarding UTXOs")
	t.Logf("offchain balance after settle: %d sats", balance.OffchainBalance.Total)
}
