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
// signer (EC-11).
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

// TestScanContractsPerSignerGapIndependence verifies that the current and
// deprecated signers walk independent gap counters (EC-1): the current signer
// hitting only its first index (and then exhausting its gap) must not stop the
// deprecated signer from discovering a hit at a higher index that lies within
// the deprecated signer's OWN gap window.
func TestScanContractsPerSignerGapIndependence(t *testing.T) {
	env, mgr, _ := newTestManagerWithEnv(t)
	deprecated := env.addDeprecatedSigner(t)
	current := currentSignerKey(t, env)

	// Current signer: single hit at m/0/0, then a run of misses that exhausts
	// its gap. Deprecated signer: hit at m/0/4, reachable within gapLimit=5
	// from index 0 even though the current signer has long since stopped.
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
	// Deprecated signer, scanning from 0 with its own gap counter, persists
	// 0..4 — its hit at m/0/4 is found independently of the current signer's
	// earlier stop.
	require.ElementsMatch(
		t, []string{"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4"},
		ownerKeyIds(bySigner[depHex]),
		"deprecated-signer hit within its own gap must be discovered independently",
	)
}

// TestScanContractsDeprecatedFromIndex0 verifies that even when current-signer
// contracts already exist at high indices (so the current scan resumes after
// them), the deprecated-signer scan starts from index 0 and finds a low-index
// pre-rotation vtxo (EC-2, spec 3.3.5).
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
// returns no error and does not duplicate rows (INSERT OR IGNORE, EC-12).
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
// covers deprecated signers too (EC-7).
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
