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

// TestBuildSignerMap covers every counted signer state and the cutoff
// thresholds (cutoff==0 and past-cutoff, plus multiple deprecated signers), and
// asserts that a signer in neither the current nor the deprecated set is ABSENT
// from the map (a map miss the caller treats as a logged skip — there is no
// signerUnknown enum value anymore). There is no safety margin: any future (or
// zero) cutoff classifies as signerToMigrate, and any past cutoff as
// signerExpired.
func TestBuildSignerMap(t *testing.T) {
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

	m := buildSignerMap(currentHex, deprecated, now)

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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			si, ok := m[c.key]
			require.True(t, ok, "known signer must be present in the map")
			require.Equal(t, c.want, si.state)
		})
	}

	t.Run("unknown signer is absent (map miss)", func(t *testing.T) {
		_, ok := m[xonlyHexOf(unknown)]
		require.False(t, ok,
			"a signer in neither current nor deprecated must be absent from the map")
	})

	t.Run("empty current signer is not added", func(t *testing.T) {
		m2 := buildSignerMap("", deprecated, now)
		require.Len(t, m2, len(deprecated),
			"an empty current signer hex must not create an entry")
	})
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

func TestDeprecatedSignersForConfig(t *testing.T) {
	current := testKey(t)
	compressedDep := testKey(t)
	xOnlyDep := testKey(t)

	info := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(compressedDep), CutoffDate: 123},
			{PubKey: xonlyHexOf(xOnlyDep), CutoffDate: 0},
			{PubKey: compressedHex(current), CutoffDate: 999},
			{PubKey: "not-hex", CutoffDate: 1},
		},
	}

	signers := deprecatedSignersForConfig(info, current)
	require.Len(t, signers, 2)
	require.Equal(t, xonlyHexOf(compressedDep), xonlyHexOf(signers[0].PubKey))
	require.Equal(t, time.Unix(123, 0), signers[0].CutoffDate)
	require.Equal(t, xonlyHexOf(xOnlyDep), xonlyHexOf(signers[1].PubKey))
	require.True(t, signers[1].CutoffDate.IsZero())
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
// manager (wallet not yet unlocked) reconcile returns no error, so it can never
// break the Unlock path.
func TestReconcileNoContractManager(t *testing.T) {
	w := &wallet{}
	err := w.reconcileDeprecatedSigners(t.Context())
	require.NoError(t, err)
}
