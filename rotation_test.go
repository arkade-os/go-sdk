package arksdk

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}

func compressedHex(key *btcec.PublicKey) string {
	return hex.EncodeToString(key.SerializeCompressed())
}

func xonlyHexOf(key *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

// TestClassifySigner covers every counted signer state plus the unknown
// sentinel and the cutoff thresholds (cutoff==0 and past-cutoff, plus multiple
// deprecated signers). There is no safety margin: any future (or zero) cutoff
// classifies as signerToMigrate, and any past cutoff as signerExpired.
func TestClassifySigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	current := testKey(t)
	farFuture := testKey(t)
	nearFuture := testKey(t)
	expired := testKey(t)
	noCutoff := testKey(t)
	unknown := testKey(t)

	currentHex := xonlyHexOf(current)
	deprecated := map[string]client.DeprecatedSigner{
		xonlyHexOf(farFuture): {
			PubKey: xonlyHexOf(farFuture), CutoffDate: now.Add(72 * time.Hour).Unix(),
		},
		xonlyHexOf(nearFuture): {
			PubKey: xonlyHexOf(nearFuture), CutoffDate: now.Add(2 * time.Hour).Unix(),
		},
		xonlyHexOf(expired): {
			PubKey: xonlyHexOf(expired), CutoffDate: now.Add(-time.Hour).Unix(),
		},
		xonlyHexOf(noCutoff): {
			PubKey: xonlyHexOf(noCutoff), CutoffDate: 0,
		},
	}

	cases := []struct {
		name string
		key  string
		want signerState
	}{
		{"current", currentHex, signerActive},
		{"toMigrate (cutoff far out)", xonlyHexOf(farFuture), signerToMigrate},
		{"toMigrate (cutoff near)", xonlyHexOf(nearFuture), signerToMigrate},
		{"expired (past cutoff)", xonlyHexOf(expired), signerExpired},
		{"no cutoff is always toMigrate", xonlyHexOf(noCutoff), signerToMigrate},
		{"unknown signer", xonlyHexOf(unknown), signerUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := classifySigner(c.key, currentHex, deprecated, now)
			require.Equal(t, c.want, got)
		})
	}
}

// TestCollectToMigrateVtxos verifies the subset passed to WithSettleVtxos
// contains exactly the signerToMigrate vtxos — Active
// (current-signer) and Expired (past-cutoff, exit-only) vtxos are excluded, and
// vtxos with no signer mapping are skipped. This is the input that
// reconcileDeprecatedSigners feeds to the unexported settle(ctx,
// WithSettleVtxos(...)) (the safeCheck-free path used during the synchronous
// unlock-time migration).
func TestCollectToMigrateVtxos(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	current := testKey(t)
	toMigrateA := testKey(t)
	toMigrateB := testKey(t)
	expired := testKey(t)

	currentHex := xonlyHexOf(current)
	deprecated := map[string]client.DeprecatedSigner{
		xonlyHexOf(toMigrateA): {
			PubKey: xonlyHexOf(toMigrateA), CutoffDate: now.Add(72 * time.Hour).Unix(),
		},
		xonlyHexOf(toMigrateB): {
			PubKey: xonlyHexOf(toMigrateB), CutoffDate: 0, // no cutoff → toMigrate
		},
		xonlyHexOf(expired): {
			PubKey: xonlyHexOf(expired), CutoffDate: now.Add(-time.Hour).Unix(),
		},
	}

	// 3 Active vtxos, 2 ToMigrate vtxos, 1 Expired vtxo. Scripts are arbitrary
	// unique tags used only as map keys here.
	spendable := []clienttypes.Vtxo{
		{Script: "active-1", Amount: 100},
		{Script: "active-2", Amount: 200},
		{Script: "active-3", Amount: 300},
		{Script: "tomigrate-1", Amount: 1000},
		{Script: "tomigrate-2", Amount: 2000},
		{Script: "expired-1", Amount: 9000},
		{Script: "orphan-1", Amount: 5}, // no signer mapping → skipped
	}
	signerByScript := map[string]string{
		"active-1":    currentHex,
		"active-2":    currentHex,
		"active-3":    currentHex,
		"tomigrate-1": xonlyHexOf(toMigrateA),
		"tomigrate-2": xonlyHexOf(toMigrateB),
		"expired-1":   xonlyHexOf(expired),
		// "orphan-1" intentionally absent.
	}

	got := collectToMigrateVtxos(spendable, signerByScript, currentHex, deprecated, now)

	require.Len(t, got, 2, "only the two ToMigrate vtxos are collected")
	gotScripts := map[string]bool{}
	for _, v := range got {
		gotScripts[v.Script] = true
	}
	require.True(t, gotScripts["tomigrate-1"])
	require.True(t, gotScripts["tomigrate-2"])
	require.False(t, gotScripts["active-1"], "current-signer vtxo must be excluded")
	require.False(t, gotScripts["active-2"], "current-signer vtxo must be excluded")
	require.False(t, gotScripts["active-3"], "current-signer vtxo must be excluded")
	require.False(t, gotScripts["expired-1"], "expired vtxo must be excluded (exit-only)")
	require.False(t, gotScripts["orphan-1"], "unmapped vtxo must be skipped")
}

// TestDeprecatedSignerSet verifies normalization, dedup of an entry equal to the
// current signer, and that malformed entries are skipped.
func TestDeprecatedSignerSet(t *testing.T) {
	current := testKey(t)
	dep := testKey(t)

	info := &client.Info{
		// current advertised compressed; helper must normalize to x-only.
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			// compressed deprecated key
			{PubKey: compressedHex(dep), CutoffDate: 123},
			// duplicate of current → must be dropped
			{PubKey: compressedHex(current), CutoffDate: 999},
			// malformed → must be skipped, not fatal
			{PubKey: "not-hex", CutoffDate: 1},
			{PubKey: "00", CutoffDate: 1},
		},
	}

	currentHex, set := deprecatedSignerSet(info)
	require.Equal(t, xonlyHexOf(current), currentHex)
	require.Len(t, set, 1, "only the one real deprecated key survives")

	d, ok := set[xonlyHexOf(dep)]
	require.True(t, ok)
	require.Equal(t, int64(123), d.CutoffDate)
	require.Equal(t, xonlyHexOf(dep), d.PubKey, "stored as x-only")

	// The current key must not appear as a deprecated entry.
	_, present := set[xonlyHexOf(current)]
	require.False(t, present)
}

// TestSignerSetDigestStability verifies the digest is stable under reordering
// and changes when the signer set changes (drives live-rotation detection).
func TestSignerSetDigestStability(t *testing.T) {
	current := testKey(t)
	a := testKey(t)
	b := testKey(t)

	info1 := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(a)}, {PubKey: compressedHex(b)},
		},
	}
	// Same set, deprecated entries reordered → same digest.
	info2 := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(b)}, {PubKey: compressedHex(a)},
		},
	}
	require.Equal(t, signerSetDigest(info1), signerSetDigest(info2))

	// A rotation: current changes → digest changes.
	rotated := &client.Info{
		SignerPubKey: compressedHex(a),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(current)}, {PubKey: compressedHex(b)},
		},
	}
	require.NotEqual(t, signerSetDigest(info1), signerSetDigest(rotated))

	// Adding a deprecated key → digest changes.
	added := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(a)},
			{PubKey: compressedHex(b)},
			{PubKey: compressedHex(testKey(t))},
		},
	}
	require.NotEqual(t, signerSetDigest(info1), signerSetDigest(added))
}

// TestReconcileNoContractManager verifies the no-op guard: with no contract
// manager (wallet not yet unlocked) reconcile returns a zero status and no
// error, so it can never break the Unlock path.
func TestReconcileNoContractManager(t *testing.T) {
	w := &wallet{}
	status, err := w.reconcileDeprecatedSigners(t.Context())
	require.NoError(t, err)
	require.Equal(t, DeprecatedSignerStatus{}, status)

	summary, err := w.DeprecatedSignerSummary(t.Context())
	require.NoError(t, err)
	require.Equal(t, DeprecatedSignerStatus{}, summary)
}

// TestUpdateNearestCutoff verifies the nearest (earliest) non-zero cutoff wins
// and that a zero cutoff never overrides a real one.
func TestUpdateNearestCutoff(t *testing.T) {
	var status DeprecatedSignerStatus

	updateNearestCutoff(&status, 0)
	require.True(t, status.NearestCutoff.IsZero(), "zero cutoff must not set a nearest")

	later := time.Now().Add(48 * time.Hour).Unix()
	sooner := time.Now().Add(2 * time.Hour).Unix()
	updateNearestCutoff(&status, later)
	require.Equal(t, time.Unix(later, 0), status.NearestCutoff)
	updateNearestCutoff(&status, sooner)
	require.Equal(t, time.Unix(sooner, 0), status.NearestCutoff, "earlier cutoff wins")
	updateNearestCutoff(&status, later)
	require.Equal(t, time.Unix(sooner, 0), status.NearestCutoff, "later cutoff must not override")
}

// TestSkipMigrationSettleGuard verifies the empty-toMigrate guard
// (skipMigrationSettle): an empty/nil ToMigrate subset must be skipped so it
// never reaches Settle, where WithSettleVtxos(nil) would fall back to a FULL
// settle of every spendable vtxo. A non-empty subset must proceed.
func TestSkipMigrationSettleGuard(t *testing.T) {
	require.True(t, skipMigrationSettle(nil), "nil subset must be skipped")
	require.True(t, skipMigrationSettle([]clienttypes.Vtxo{}),
		"empty subset must be skipped")
	require.False(t, skipMigrationSettle([]clienttypes.Vtxo{{Script: "a"}}),
		"non-empty subset must proceed to settle")

	// End-to-end of the guard's premise: when no spendable vtxo classifies as
	// ToMigrate, collectToMigrateVtxos returns empty — exactly the case where the
	// guard must engage rather than passing nil to Settle. Here every vtxo is
	// either current-signer (Active) or past-cutoff (Expired); none is ToMigrate.
	now := time.Unix(1_700_000_000, 0)
	current := testKey(t)
	expired := testKey(t)
	currentHex := xonlyHexOf(current)
	deprecated := map[string]client.DeprecatedSigner{
		xonlyHexOf(expired): {
			PubKey: xonlyHexOf(expired), CutoffDate: now.Add(-time.Hour).Unix(),
		},
	}
	spendable := []clienttypes.Vtxo{
		{Script: "active-1", Amount: 100},
		{Script: "expired-1", Amount: 200},
	}
	signerByScript := map[string]string{
		"active-1":  currentHex,
		"expired-1": xonlyHexOf(expired),
	}
	toMigrate := collectToMigrateVtxos(spendable, signerByScript, currentHex, deprecated, now)
	require.Empty(t, toMigrate, "no vtxo should classify as ToMigrate in this setup")
	require.True(t, skipMigrationSettle(toMigrate),
		"guard must skip settle when no vtxo is actually migratable, "+
			"preventing an accidental full-settle of the Active/Expired vtxos")
}
