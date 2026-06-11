package arksdk

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
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

// TestClassifySigner covers every signer state and the cutoff thresholds
// (EC-5 cutoff==0/past-cutoff, EC-15 dueNow margin, EC-16 multiple deprecated).
func TestClassifySigner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	margin := 24 * time.Hour

	current := testKey(t)
	migratable := testKey(t)
	dueNow := testKey(t)
	expired := testKey(t)
	noCutoff := testKey(t)
	unknown := testKey(t)

	currentHex := xonlyHexOf(current)
	deprecated := map[string]client.DeprecatedSigner{
		xonlyHexOf(migratable): {
			PubKey: xonlyHexOf(migratable), CutoffDate: now.Add(72 * time.Hour).Unix(),
		},
		xonlyHexOf(dueNow): {
			PubKey: xonlyHexOf(dueNow), CutoffDate: now.Add(2 * time.Hour).Unix(),
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
		{"current", currentHex, signerCurrent},
		{"migratable (cutoff far out)", xonlyHexOf(migratable), signerMigratable},
		{"dueNow (cutoff within margin)", xonlyHexOf(dueNow), signerDueNow},
		{"expired (past cutoff)", xonlyHexOf(expired), signerExpired},
		{"no cutoff is always migratable", xonlyHexOf(noCutoff), signerMigratable},
		{"unknown signer", xonlyHexOf(unknown), signerUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := classifySigner(c.key, currentHex, deprecated, now, margin)
			require.Equal(t, c.want, got)
		})
	}

	t.Run("cutoff exactly at margin boundary is dueNow", func(t *testing.T) {
		boundary := testKey(t)
		set := map[string]client.DeprecatedSigner{
			xonlyHexOf(boundary): {
				PubKey: xonlyHexOf(boundary), CutoffDate: now.Add(margin).Unix(),
			},
		}
		got, _ := classifySigner(xonlyHexOf(boundary), currentHex, set, now, margin)
		require.Equal(t, signerDueNow, got)
	})
}

// TestDeprecatedSignerSet verifies normalization, dedup of an entry equal to the
// current signer, and that malformed entries are skipped (EC-4, EC-10).
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
