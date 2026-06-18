//go:build smoke

package e2e_test

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestSignerRotationRestoreSmoke(t *testing.T) {
	ctx := t.Context()

	alice := setupClient(t, "")
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

	t.Logf("funded wallet under signer %s", oldSigner)
	waitForEnter(
		t,
		"Rotate arkd now: make a new signer current, keep the old signer deprecated before cutoff, then press Enter",
	)

	restored := setupClient(t, seed)

	currentSigner := arkdCurrentSigner(t, restored)
	require.NotEqual(t, oldSigner, currentSigner,
		"rotation must have changed the active signer (A -> B)")

	// All surviving spendable vtxos must now commit to KEY B.
	postVtxos, _, err := restored.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, postVtxos, "restored wallet must hold the migrated funds")
	for _, v := range postVtxos {
		require.Equal(t, currentSigner, vtxoSignerKey(t, restored, v),
			"every migrated vtxo must commit to the current signer KEY B (#822)")
	}

	require.Equal(t, preSats, totalVtxoAmount(postVtxos),
		"offchain migration must preserve the sats balance")

	bal, err := restored.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, preSats, bal.OffchainBalance.Total,
		"offchain sats balance preserved across the migration")

	inactive, err := restored.ContractManager().GetContracts(
		ctx, contract.WithState(types.ContractStateInactive),
	)
	require.NoError(t, err)
	require.NotEmpty(t, inactive,
		"the migrated deprecated-signer contract must be marked inactive")
	for _, c := range inactive {
		require.Equal(t, types.ContractStateInactive, c.State)
	}

	bob := setupClient(t, "")
	bobAddr, err := bob.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddr)

	const sendBtc = uint64(20_000) // a small BTC portion of the consolidated vtxo
	require.Less(t, sendBtc, preSats, "the BTC spend must be a portion of the balance")

	_, err = restored.SendOffChain(ctx, []clientTypes.Receiver{
		{
			To: bobAddr, Amount: sendBtc,
		},
	})
	require.NoError(t, err, "spending from the migrated vtxo must succeed")

	bobBal, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, sendBtc, bobBal.OffchainBalance.Total,
		"recipient must hold exactly the sent BTC portion")

	senderBal, err := restored.Balance(ctx)
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

// arkdCurrentSigner returns arkd's current signer as x-only hex.
func arkdCurrentSigner(t *testing.T, w arksdk.Wallet) string {
	t.Helper()
	info, err := w.Client().GetInfo(t.Context())
	require.NoError(t, err)
	buf, err := hex.DecodeString(info.SignerPubKey)
	require.NoError(t, err)
	// btcec.ParsePubKey accepts both compressed and x-only inputs.
	key, err := btcec.ParsePubKey(buf)
	require.NoError(t, err)
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

func waitForEnter(t *testing.T, msg string) {
	t.Helper()
	t.Log(msg)
	fmt.Fprintln(os.Stderr, msg)

	tty, err := os.Open("/dev/tty")
	require.NoError(t, err)
	defer tty.Close()

	_, err = bufio.NewReader(tty).ReadString('\n')
	require.NoError(t, err)
}
