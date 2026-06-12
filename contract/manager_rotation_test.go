package contract_test

import (
	"encoding/hex"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

// currentSignerKey parses the env's current server signer pubkey.
func currentSignerKey(t *testing.T, env *mockedEnv) *btcec.PublicKey {
	t.Helper()
	buf, err := hex.DecodeString(env.transport.info.SignerPubKey)
	require.NoError(t, err)
	key, err := btcec.ParsePubKey(buf)
	require.NoError(t, err)
	return key
}

// deprecatedSignerEntry builds a deprecated-signer wire entry (no cutoff) for
// an already-known pubkey.
func deprecatedSignerEntry(key *btcec.PublicKey) client.DeprecatedSigner {
	return client.DeprecatedSigner{
		PubKey: hex.EncodeToString(key.SerializeCompressed()),
	}
}

// signerKeyParam mirrors the param name the default handler stores the signer
// pubkey under. Asserted on stored contracts to prove each candidate carries
// the correct (x-only) signer.
const signerKeyParam = "signerKey"

func xOnlyHex(t *testing.T, key *btcec.PublicKey) string {
	t.Helper()
	return hex.EncodeToString(schnorr.SerializePubKey(key))
}

// contractsBySigner groups stored contracts by their signerKey param.
func contractsBySigner(cs []types.Contract) map[string][]types.Contract {
	out := make(map[string][]types.Contract)
	for _, c := range cs {
		out[c.Params[signerKeyParam]] = append(out[c.Params[signerKeyParam]], c)
	}
	return out
}

// TestScanContractsMultiSigner verifies that a single rotation (current + one
// deprecated signer) discovers and persists vtxos under BOTH signers, and that
// the whole batch is probed in a single indexer call rather than one call per
// signer.
func TestScanContractsMultiSigner(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)
	deprecated := env.addDeprecatedSigner(t)
	current := currentSignerKey(t, env)

	// m/0/0 used under the current signer; m/0/1 used under the deprecated one.
	env.markUsedForSigner(t, current, "m/0/0")
	env.markUsedForSigner(t, deprecated, "m/0/1")

	require.NoError(t, mgr.ScanContracts(t.Context(), 5))

	got, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)

	bySigner := contractsBySigner(got)
	curHex := xOnlyHex(t, current)
	depHex := xOnlyHex(t, deprecated)

	// Current signer: indices 0..0 (lastUsed=0) → m/0/0 only.
	require.ElementsMatch(t, []string{"m/0/0"}, ownerKeyIds(bySigner[curHex]))
	// Deprecated signer scans from 0, lastUsed=1 → m/0/0, m/0/1.
	require.ElementsMatch(t, []string{"m/0/0", "m/0/1"}, ownerKeyIds(bySigner[depHex]))

	// One batched probe per index-batch, NOT one per signer. With gapLimit=5
	// the scan completes within a couple of batches; the key invariant is that
	// the call count is far below (signers × batches) — exactly one call per
	// batch. Assert it is no more than the number of index-batches walked.
	require.GreaterOrEqual(t, env.indexer.callCount, 1)
	require.LessOrEqual(
		t, env.indexer.callCount, 2,
		"expected one batched probe per index-batch, got %d", env.indexer.callCount,
	)
}

// TestScanContractsUnionGapAcrossSigners verifies the SINGLE union gap counter
// (the post-fix termination rule): a hit by ANY accepted signer at an index
// resets the shared counter, so a deprecated-signer hit keeps discovery alive
// past the point where the current signer alone would have stopped. The
// protective behavior the old per-signer design provided (a current-signer stop
// must not hide a later deprecated-signer hit) is preserved by the union
// counter — but now the SAME counter also protects the current signer's own
// late hits (see TestScanContractsHighCurrentSignerStartIdx).
func TestScanContractsUnionGapAcrossSigners(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)
	deprecated := env.addDeprecatedSigner(t)
	current := currentSignerKey(t, env)

	// Current signer: single hit at m/0/0, then a run of misses. Deprecated
	// signer: hit at m/0/4. With the union counter and gapLimit=5 the shared
	// counter resets at index 0 (current+deprecated hit) and again at index 4
	// (deprecated hit), so the scan never fires its gap inside 0..4 and both
	// signers' contracts in that range are discovered.
	env.markUsedForSigner(t, current, "m/0/0")
	env.markUsedForSigner(t, deprecated, "m/0/4")

	require.NoError(t, mgr.ScanContracts(t.Context(), 5))

	got, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)

	bySigner := contractsBySigner(got)
	curHex := xOnlyHex(t, current)
	depHex := xOnlyHex(t, deprecated)

	// Current signer persists up to its last hit (m/0/0).
	require.ElementsMatch(t, []string{"m/0/0"}, ownerKeyIds(bySigner[curHex]))
	// Deprecated signer, scanning from 0, persists 0..4 — its hit at m/0/4 is
	// discovered because the union counter never reached gapLimit before it.
	require.ElementsMatch(
		t, []string{"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4"},
		ownerKeyIds(bySigner[depHex]),
		"deprecated-signer hit within the shared gap window must be discovered",
	)
}

// TestScanContractsHighCurrentSignerStartIdx is THE P0 regression test for the
// union gap counter. It reproduces the index-1000 fund-loss scenario (scaled
// down): after a rotation, the current signer's FIRST hit sits beyond gapLimit
// from index 0, while the deprecated signer has hits at the low indices. On a
// fresh-DB restore the current signer (signers[0]) resumes at index 0, so a
// per-signer gap counter would exhaust the current signer's window long before
// its first hit and that post-rotation balance would be lost forever.
//
// The union counter fixes this: the deprecated signer's contiguous low-index
// hits keep the shared counter alive across the gap, so the scan walks far
// enough to reach the current signer's late hit and discovers BOTH signers'
// funds.
//
// This test would FAIL against the pre-fix per-signer counter logic: the
// current signer's gap would fire at index gapLimit (no current-signer hit
// in 0..gapLimit-1), marking it done before its hit at m/0/8 is ever probed.
func TestScanContractsHighCurrentSignerStartIdx(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)
	deprecated := env.addDeprecatedSigner(t)
	current := currentSignerKey(t, env)

	// Deprecated signer (pre-rotation funds) has contiguous hits at the low
	// indices 0..5. The current signer's only hit is at m/0/8 — strictly beyond
	// gapLimit=5 from index 0, i.e. a per-signer counter for the current signer
	// would have fired at index 5 (no current hit in 0..4). m/0/8 is reachable
	// because the deprecated hits at 0..5 keep the shared counter at 0 through
	// index 5; from index 5 the union counter then has indices 6,7 unused (2 < 5)
	// before the current-signer hit at 8 resets it again.
	env.markUsedForSigner(t, deprecated, "m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4", "m/0/5")
	env.markUsedForSigner(t, current, "m/0/8")

	require.NoError(t, mgr.ScanContracts(t.Context(), 5))

	got, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)

	bySigner := contractsBySigner(got)
	curHex := xOnlyHex(t, current)
	depHex := xOnlyHex(t, deprecated)

	// The whole point: the current signer's high-index hit IS discovered.
	require.Contains(
		t, ownerKeyIds(bySigner[curHex]), "m/0/8",
		"current-signer hit beyond gapLimit must be discovered via the union counter",
	)
	// Deprecated signer's low-index funds are discovered too (range 0..5).
	require.ElementsMatch(
		t, []string{"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4", "m/0/5"},
		ownerKeyIds(bySigner[depHex]),
		"deprecated-signer low-index funds must be discovered",
	)
}

// TestScanContractsDeprecatedFromIndex0 verifies that even when current-signer
// contracts already exist at high indices (so the current scan resumes after
// them), the deprecated-signer scan starts from index 0 and finds a low-index
// pre-rotation vtxo.
func TestScanContractsDeprecatedFromIndex0(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)

	// Seed current-signer contracts at indices 0..2 via the public API (no
	// deprecated signer registered yet).
	for i := 0; i < 3; i++ {
		_, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
		require.NoError(t, err)
	}

	// Now a rotation happens: register the deprecated signer and mark an
	// old-signer vtxo at the very first index.
	deprecated := env.addDeprecatedSigner(t)
	env.markUsedForSigner(t, deprecated, "m/0/0")

	require.NoError(t, mgr.ScanContracts(t.Context(), 3))

	got, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)

	depHex := xOnlyHex(t, deprecated)
	bySigner := contractsBySigner(got)
	require.Contains(
		t, ownerKeyIds(bySigner[depHex]), "m/0/0",
		"deprecated-signer index-0 contract must be discovered despite high current-signer indices",
	)
}

// TestScanContractsIdempotent verifies a second scan over an already-scanned DB
// returns no error and does not duplicate rows (INSERT OR IGNORE).
func TestScanContractsIdempotent(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)
	deprecated := env.addDeprecatedSigner(t)
	current := currentSignerKey(t, env)
	env.markUsedForSigner(t, current, "m/0/0")
	env.markUsedForSigner(t, deprecated, "m/0/0")

	require.NoError(t, mgr.ScanContracts(t.Context(), 3))
	first, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)

	// Second scan: must be a no-op, no error, same row set.
	require.NoError(t, mgr.ScanContracts(t.Context(), 3))
	second, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)

	require.ElementsMatch(t, scriptsOf(first...), scriptsOf(second...))
}

// TestScanContractsDedupSameScript verifies that when two signers (degenerate
// case: a deprecated entry equal to the current key) would produce the same
// candidate scripts, acceptedSigners collapses them so only one signer is
// scanned and the probe receives a deduplicated list.
func TestScanContractsDedupEqualToCurrent(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)

	// Register the CURRENT signer key as a "deprecated" entry — a no-op the
	// dedup must absorb.
	current := currentSignerKey(t, env)
	env.transport.info.DeprecatedSignerPubKeys = append(
		env.transport.info.DeprecatedSignerPubKeys,
		deprecatedSignerEntry(current),
	)
	env.markUsedForSigner(t, current, "m/0/0")

	require.NoError(t, mgr.ScanContracts(t.Context(), 3))

	got, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeDefault))
	require.NoError(t, err)
	// Exactly one row for m/0/0 — not two from a duplicated signer.
	require.ElementsMatch(t, []string{"m/0/0"}, ownerKeyIds(got))

	// The most recent probe must contain no duplicate scripts.
	seen := make(map[string]struct{}, len(env.indexer.lastScripts))
	for _, s := range env.indexer.lastScripts {
		_, dup := seen[s]
		require.False(t, dup, "probe contained a duplicate script %s", s)
		seen[s] = struct{}{}
	}
}

// TestScanContractsBoardingDeprecated verifies boarding (onchain) discovery
// covers deprecated signers too.
func TestScanContractsBoardingDeprecated(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)
	deprecated := env.addDeprecatedSigner(t)

	env.markBoardingUsedForSigner(t, deprecated, "m/0/1")

	require.NoError(t, mgr.ScanContracts(t.Context(), 5))

	got, err := mgr.GetContracts(t.Context(), contract.WithType(types.ContractTypeBoarding))
	require.NoError(t, err)

	depHex := xOnlyHex(t, deprecated)
	bySigner := contractsBySigner(got)
	require.ElementsMatch(
		t, []string{"m/0/0", "m/0/1"}, ownerKeyIds(bySigner[depHex]),
		"deprecated-signer boarding contracts must be discovered",
	)
}
