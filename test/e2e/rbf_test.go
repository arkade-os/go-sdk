package e2e_test

import (
	"encoding/json"
	"fmt"
	"regexp"
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
	boardingAddr, err := client.NewBoardingAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, boardingAddr)

	balance, err := client.Balance(ctx)
	require.NoError(t, err)
	require.Zero(t, int(balance.OffchainBalance.Total))

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

	// Send 5 boarding transactions, each RBF-bumped and mined individually.
	// Mining after each bump ensures the wallet has a confirmed UTXO for the
	// next send (otherwise sendtoaddress fails due to insufficient funds).
	ansiRe := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	const numBoardingTxs = 5
	for range numBoardingTxs {
		txidOut, err := rpc("-named", "sendtoaddress",
			fmt.Sprintf("address=%s", boardingAddr), "amount=0.001", "replaceable=true",
		)
		require.NoError(t, err)
		origTxid := strings.TrimSpace(txidOut)

		// Bump the fee — this creates a replacement tx that may reorder outputs.
		bumpOut, err := rpc("bumpfee", origTxid)
		require.NoError(t, err)

		var bumpResp struct {
			Txid string `json:"txid"`
		}
		// Strip ANSI escape codes that nigiri injects via terminal coloring.
		cleanBump := ansiRe.ReplaceAllString(strings.TrimSpace(bumpOut), "")
		require.NoError(t, json.Unmarshal([]byte(cleanBump), &bumpResp))

		// Mine so the wallet's change is confirmed for the next iteration.
		require.NoError(t, generateBlocks(1))
	}

	// Wait for the SDK to detect the confirmed UTXOs, then settle.
	require.Eventually(t, func() bool {
		_, err := client.Settle(ctx)
		return err == nil
	}, 60*time.Second, 2*time.Second, "settle should succeed after RBF bumpfee")

	// Verify balance reflects the settled funds.
	balance, err = client.Balance(ctx)
	require.NoError(t, err)
	require.Greater(t, int(balance.OffchainBalance.Total), 0)
}
