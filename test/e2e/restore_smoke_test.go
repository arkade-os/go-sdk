//go:build smoke

package e2e_test

import (
	"encoding/hex"
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// TestRestoreAfterSignerRotation is the end-to-end proof of the deprecated-
// signer (key rotation) support:
//
//	Item A — a wallet restored from seed AFTER a server signer rotation
//	         rediscovers its pre-rotation (deprecated-signer) vtxos, which a
//	         signer-unaware discovery would render invisible.
//	Item B — those vtxos are migrated onto outputs committing to the CURRENT
//	         signer before the deprecated key's cutoff.
//
// It REQUIRES an arkd built with deprecated-signer support (feat/deprecated-keys,
// arkd#822), which is not yet merged: there is no server build that advertises a
// deprecated signer set or that co-signs spends of deprecated-signer outputs. So
// the test is written as complete, compiling logic but skipped until that server
// support lands — unskip the line below when arkd#822 is merged.
func TestRestoreAfterSignerRotation(t *testing.T) {
	t.Skip(
		"requires arkd with deprecated-signer support " +
			"(feat/deprecated-keys, arkd#822) — unskip when merged",
	)

	ctx := t.Context()

	// 1. Fund alice under the OLD (soon-to-be-deprecated) signer.
	alice := setupClient(t, "")
	const fundBtc = 0.001
	const fundSats = uint64(fundBtc * 1e8)
	faucetOffchain(t, alice, fundBtc)

	preVtxos, _, err := alice.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.Equal(t, fundSats, vtxoTotalAmount(preVtxos), "pre-rotation funding must be visible")

	// Record the signer the funded vtxo committed to — this is the OLD signer.
	oldSigner := contractSignerKey(t, alice, preVtxos[0])
	require.NotEmpty(t, oldSigner)

	// Export the seed so we can restore a fresh-DB wallet after the rotation.
	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	// 2. Trigger a server signer rotation on arkd. With arkd#822 this is done
	// via the admin API / operator config: the server begins advertising a new
	// active signer plus the old one as a deprecated signer (with a cutoff far
	// enough out that migration is still collaborative). Until that endpoint
	// exists this is a placeholder for the rotation step.
	rotateServerSigner(t)

	// 3. Restore alice from seed into a brand-new (empty) DB. Discovery (Item A)
	// runs inside ScanContracts at unlock, BEFORE refreshDb, so the pre-rotation
	// deprecated-signer vtxos must be found even though every freshly-allocated
	// contract now commits to the new signer.
	restored := setupClient(t, seed)

	// 4. Item A assertion: pre-rotation vtxos are rediscovered. Their total
	// value (before any migration spends them) must equal what alice funded.
	currentSigner := serverCurrentSigner(t, restored)
	require.NotEqual(t, oldSigner, currentSigner, "rotation must have changed the active signer")

	// 5. Item B assertion: after restore, reconcileDeprecatedSigners has run in
	// the unlock goroutine and migrated the deprecated-signer vtxos onto
	// current-signer outputs (arkd#822: every settle output commits to the
	// current signer). All surviving spendable vtxos must therefore commit to
	// the CURRENT signer, and the total value is preserved.
	postVtxos, _, err := restored.ListVtxos(ctx, arksdk.WithSpendableOnly())
	require.NoError(t, err)
	require.NotEmpty(t, postVtxos, "restored wallet must hold the recovered funds")
	// The migration is a real subset settle, which deducts settlement fees, so
	// the post-migration total is at most the funded amount and at least
	// fundSats minus a generous fee allowance. An exact equality would break the
	// moment the test is unskipped against a live arkd that charges any fee.
	const maxMigrationFeeSats = uint64(5_000)
	postTotal := vtxoTotalAmount(postVtxos)
	require.LessOrEqual(
		t, postTotal, fundSats,
		"migration cannot create value above the funded amount",
	)
	require.GreaterOrEqual(
		t, postTotal, fundSats-maxMigrationFeeSats,
		"migration must preserve the recovered value net of settlement fees",
	)
	for _, v := range postVtxos {
		require.Equal(
			t, currentSigner, contractSignerKey(t, restored, v),
			"every migrated vtxo must commit to the current signer (#822)",
		)
	}
}

// vtxoTotalAmount sums the amounts of the given vtxos.
func vtxoTotalAmount(vtxos []clientTypes.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

// contractSignerKey returns the x-only hex of the signer the contract backing
// the given vtxo commits to, read from the stored contract via its handler.
func contractSignerKey(t *testing.T, w arksdk.Wallet, vtxo clientTypes.Vtxo) string {
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

// serverCurrentSigner returns the x-only hex of the server's CURRENT active
// signer as advertised over the wire.
func serverCurrentSigner(t *testing.T, w arksdk.Wallet) string {
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

// rotateServerSigner triggers a signer rotation on the running arkd. Implemented
// against the admin API once arkd#822 lands; today it is a no-op placeholder
// reached only when the t.Skip above is removed.
func rotateServerSigner(t *testing.T) {
	t.Helper()
	t.Fatal(
		"rotateServerSigner: server-side signer rotation (arkd#822) is not yet " +
			"available — remove the t.Skip only once arkd exposes the rotation control",
	)
}
