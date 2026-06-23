//go:build smoke

package e2e_test

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestSignerRotationRestartSmoke(t *testing.T) {
	datadir := t.TempDir()
	alice := setupClientWithDir(t, datadir, "")
	preSats, oldSigner, _ := fundSignerRotationWallet(t, alice)

	t.Logf("funded wallet under signer %s", oldSigner)
	currentSigner := waitForSignerRotation(
		t,
		alice,
		oldSigner,
		"Rotate arkd now: make a new signer current, keep the old signer deprecated before cutoff",
	)

	alice.Stop()
	restarted := loadClientWithDir(t, datadir)

	requireMigratedToCurrentSigner(t, restarted, currentSigner, preSats)
	requireInactiveContracts(t, restarted)
	requireSpendableMigratedFunds(t, restarted, preSats)
}

func TestSignerRotationRuntimeSmoke(t *testing.T) {
	ctx := t.Context()

	alice := setupClient(t, "", arksdk.WithRefreshDbInterval(30*time.Second))
	preSats, oldSigner, _ := fundSignerRotationWallet(t, alice)

	t.Logf("funded live wallet under signer %s", oldSigner)
	currentSigner := waitForSignerRotation(
		t,
		alice,
		oldSigner,
		"Rotate arkd now without restarting Alice: make a new signer current, keep the old signer deprecated before cutoff",
	)

	require.Eventually(t, func() bool {
		vtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
		if err != nil || len(vtxos) == 0 || totalVtxoAmount(vtxos) != preSats {
			return false
		}
		for _, v := range vtxos {
			if vtxoSignerKey(t, alice, v) != currentSigner {
				return false
			}
		}
		return true
	}, 3*time.Minute, 2*time.Second,
		"live wallet should migrate after the next periodic refresh")

	requireMigratedToCurrentSigner(t, alice, currentSigner, preSats)
	requireInactiveContracts(t, alice)
	requireSpendableMigratedFunds(t, alice, preSats)
}

func fundSignerRotationWallet(t *testing.T, alice arksdk.Wallet) (uint64, string, string) {
	t.Helper()
	ctx := t.Context()

	const fundBtc = 0.001
	const fundSats = uint64(fundBtc * 1e8)
	faucetOffchain(t, alice, fundBtc)

	preVtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, preVtxos, "alice must hold spendable vtxos before rotation")
	preSats := totalVtxoAmount(preVtxos)
	require.Equal(t, fundSats, preSats)

	oldSigner := vtxoSignerKey(t, alice, preVtxos[0])
	require.NotEmpty(t, oldSigner)

	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	return preSats, oldSigner, seed
}

func requireMigratedToCurrentSigner(
	t *testing.T, w arksdk.Wallet, currentSigner string, preSats uint64,
) {
	t.Helper()
	ctx := t.Context()
	// All surviving spendable vtxos must now commit to KEY B.
	postVtxos, _, err := w.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, postVtxos, "wallet must hold the migrated funds")
	for _, v := range postVtxos {
		require.Equal(t, currentSigner, vtxoSignerKey(t, w, v),
			"every migrated vtxo must commit to the current signer KEY B (#822)")
	}

	require.Equal(t, preSats, totalVtxoAmount(postVtxos),
		"offchain migration must preserve the sats balance")

	bal, err := w.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats, bal.OffchainBalance.Total,
		"offchain sats balance preserved across the migration")
}

func requireInactiveContracts(t *testing.T, w arksdk.Wallet) {
	t.Helper()

	inactive, err := w.ContractManager().GetContracts(
		t.Context(), contract.WithState(types.ContractStateInactive),
	)
	require.NoError(t, err)
	require.NotEmpty(t, inactive,
		"the migrated deprecated-signer contract must be marked inactive")
	for _, c := range inactive {
		require.Equal(t, types.ContractStateInactive, c.State)
	}
}

func requireSpendableMigratedFunds(t *testing.T, sender arksdk.Wallet, preSats uint64) {
	t.Helper()
	ctx := t.Context()

	bob := setupClient(t, "")
	bobAddr, err := bob.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddr)

	const sendBtc = uint64(20_000) // a small BTC portion of the consolidated vtxo
	require.Less(t, sendBtc, preSats, "the BTC spend must be a portion of the balance")

	_, err = sender.SendOffChain(ctx, []clientTypes.Receiver{
		{
			To: bobAddr, Amount: sendBtc,
		},
	})
	require.NoError(t, err, "spending from the migrated vtxo must succeed")

	bobBal, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, sendBtc, bobBal.OffchainBalance.Total,
		"recipient must hold exactly the sent BTC portion")

	senderBal, err := sender.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats-sendBtc, senderBal.OffchainBalance.Total,
		"sender must retain the remaining BTC (offchain send charges no fee)")
}

// totalVtxoAmount sums the amounts of the given vtxos.
func totalVtxoAmount(vtxos []clientTypes.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

// vtxoSignerKey returns the stored contract signer's x-only hex.
func vtxoSignerKey(t *testing.T, w arksdk.Wallet, vtxo clientTypes.Vtxo) string {
	t.Helper()
	mgr := w.ContractManager()
	require.NotNil(t, mgr)

	contracts, err := mgr.GetContracts(t.Context(), contract.WithScripts([]string{vtxo.Script}))
	require.NoError(t, err)
	require.Len(t, contracts, 1, "expected exactly one contract for vtxo script %s", vtxo.Script)

	handler, err := mgr.GetHandler(t.Context(), contracts[0])
	require.NoError(t, err)
	signerKey, err := handler.GetSignerKey(contracts[0])
	require.NoError(t, err)
	return hex.EncodeToString(schnorr.SerializePubKey(signerKey))
}

func waitForSignerRotation(
	t *testing.T, w arksdk.Wallet, oldSigner, msg string,
) string {
	t.Helper()
	t.Log(msg)
	fmt.Fprintln(os.Stderr, msg)
	t.Log("polling arkd GetInfo every second until active signer changes")

	var (
		currentSigner string
		lastErr       error
	)
	require.Eventually(t, func() bool {
		currentSigner, lastErr = arkdCurrentSigner(t, w)
		return lastErr == nil && currentSigner != oldSigner
	}, 5*time.Minute, time.Second,
		"rotation must change the active signer (A -> B); last current signer=%s lastErr=%v",
		currentSigner, lastErr)

	return currentSigner
}

// arkdCurrentSigner returns arkd's current signer as x-only hex.
func arkdCurrentSigner(t *testing.T, w arksdk.Wallet) (string, error) {
	t.Helper()
	info, err := w.Client().GetInfo(t.Context())
	if err != nil {
		return "", err
	}
	buf, err := hex.DecodeString(info.SignerPubKey)
	if err != nil {
		return "", err
	}
	// btcec.ParsePubKey accepts both compressed and x-only inputs.
	key, err := btcec.ParsePubKey(buf)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(schnorr.SerializePubKey(key)), nil
}

func setupClientWithDir(t *testing.T, dir, seed string, opts ...arksdk.WalletOption) arksdk.Wallet {
	t.Helper()

	arkClient, err := arksdk.NewWallet(dir, opts...)
	require.NoError(t, err)

	err = arkClient.Init(t.Context(), serverUrl, seed, password)
	require.NoError(t, err)

	unlockClient(t, arkClient)
	return arkClient
}

func loadClientWithDir(t *testing.T, dir string, opts ...arksdk.WalletOption) arksdk.Wallet {
	t.Helper()

	arkClient, err := arksdk.LoadWallet(dir, opts...)
	require.NoError(t, err)

	unlockClient(t, arkClient)
	return arkClient
}

func unlockClient(t *testing.T, arkClient arksdk.Wallet) {
	t.Helper()

	err := arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.Nil(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(arkClient.Stop)
}
