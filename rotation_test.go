package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
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

// --- Test doubles -----------------------------------------------------------

// fakeContractStore records every UpdateContractState call and can be told to
// fail for specific scripts, so tests can assert WHICH scripts were flipped
// inactive (and that a failing flip does not abort the pass). Only
// UpdateContractState is exercised; the rest of the ContractStore interface is
// satisfied with no-op stubs to keep the double minimal.
type fakeContractStore struct {
	updated  map[string]types.ContractState
	failOn   map[string]bool
	failErr  error
	allCalls []string
}

func newFakeContractStore() *fakeContractStore {
	return &fakeContractStore{
		updated: map[string]types.ContractState{},
		failOn:  map[string]bool{},
		failErr: fmt.Errorf("update failed"),
	}
}

func (f *fakeContractStore) UpdateContractState(
	_ context.Context, script string, state types.ContractState,
) error {
	f.allCalls = append(f.allCalls, script)
	if f.failOn[script] {
		return f.failErr
	}
	f.updated[script] = state
	return nil
}

func (f *fakeContractStore) AddContract(context.Context, types.Contract, uint32) error {
	return nil
}
func (f *fakeContractStore) ListContracts(context.Context) ([]types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) GetContractsByScripts(
	context.Context, []string,
) ([]types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) GetContractsByState(
	context.Context, types.ContractState,
) ([]types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) GetContractsByType(
	context.Context, types.ContractType,
) ([]types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) GetLatestContract(
	context.Context, types.ContractType,
) (*types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) Clean(context.Context) error { return nil }

// fakeStore is a minimal types.Store that returns the embedded fake
// ContractStore. Only ContractStore() is used by inactivateContracts; the rest
// return nil and are never called in these tests.
type fakeStore struct {
	contractStore types.ContractStore
}

func (s *fakeStore) ContractStore() types.ContractStore       { return s.contractStore }
func (s *fakeStore) TransactionStore() types.TransactionStore { return nil }
func (s *fakeStore) UtxoStore() types.UtxoStore               { return nil }
func (s *fakeStore) VtxoStore() types.VtxoStore               { return nil }
func (s *fakeStore) AssetStore() types.AssetStore             { return nil }
func (s *fakeStore) Clean(context.Context)                    {}
func (s *fakeStore) Close()                                   {}

// --- Single-pass classification --------------------------------------------

// TestClassifyVtxosSinglePass verifies the unified single-pass classification
// (classifyVtxos): the ToMigrate bucket collects exactly the migratable vtxos,
// the expired bucket collects exactly the past-cutoff scripts, and a vtxo under
// an unknown signer (a signerMap miss) — as well as one with no contract mapping
// — is skipped.
func TestClassifyVtxosSinglePass(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	current := testKey(t)
	toMigrateA := testKey(t)
	toMigrateB := testKey(t)
	expired := testKey(t)
	unknown := testKey(t)

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

	// 1 Active, 2 ToMigrate, 1 Expired, 1 under an unknown signer, 1 orphan
	// (no signer mapping). Scripts are arbitrary unique tags used as map keys.
	spendable := []clienttypes.Vtxo{
		{Script: "active-1", Amount: 100},
		{Script: "tomigrate-1", Amount: 1000},
		{Script: "tomigrate-2", Amount: 2000},
		{Script: "expired-1", Amount: 9000},
		{Script: "unknown-1", Amount: 7}, // signer present but not in current∪deprecated
		{Script: "orphan-1", Amount: 5},  // no signer mapping → skipped
	}
	signerByScript := map[string]string{
		"active-1":    currentHex,
		"tomigrate-1": xonlyHexOf(toMigrateA),
		"tomigrate-2": xonlyHexOf(toMigrateB),
		"expired-1":   xonlyHexOf(expired),
		"unknown-1":   xonlyHexOf(unknown),
		// "orphan-1" intentionally absent.
	}

	signerMap := buildSignerMap(currentHex, deprecated, now)
	toMigrate, expiredScripts := classifyVtxos(spendable, signerByScript, signerMap)

	// ToMigrate bucket holds exactly the two migratable vtxos.
	require.Len(t, toMigrate, 2)
	migrate := map[string]bool{}
	for _, v := range toMigrate {
		migrate[v.Script] = true
	}
	require.True(t, migrate["tomigrate-1"])
	require.True(t, migrate["tomigrate-2"])
	require.False(t, migrate["active-1"], "current-signer vtxo must be excluded")
	require.False(t, migrate["expired-1"], "expired vtxo must be excluded (exit-only)")
	require.False(t, migrate["unknown-1"], "unknown-signer vtxo must be excluded")
	require.False(t, migrate["orphan-1"], "unmapped vtxo must be excluded")

	// Expired bucket holds exactly the past-cutoff script.
	require.Equal(t, []string{"expired-1"}, expiredScripts)
}

// TestClassifyVtxosExpiredOnly verifies that when there are zero ToMigrate
// vtxos, the Expired scripts are still collected — the migration block is
// skipped but the Expired-inactivation block must still run.
func TestClassifyVtxosExpiredOnly(t *testing.T) {
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
		{Script: "expired-2", Amount: 300},
	}
	signerByScript := map[string]string{
		"active-1":  currentHex,
		"expired-1": xonlyHexOf(expired),
		"expired-2": xonlyHexOf(expired),
	}

	toMigrate, expiredScripts := classifyVtxos(
		spendable, signerByScript, buildSignerMap(currentHex, deprecated, now),
	)

	require.Empty(t, toMigrate, "ToMigrate bucket must be empty")
	require.ElementsMatch(t, []string{"expired-1", "expired-2"}, expiredScripts,
		"both expired scripts must be collected even with zero ToMigrate vtxos")
}

// --- sendOffchain bypass (no safeCheck) ------------------------------------

// TestSendOffchainBypassNoSafeCheck proves the internal sendOffchain is NOT
// safeCheck-gated: on a bare, un-synced wallet (the state during the synchronous
// unlock-time migration) the public SendOffChain returns ErrNotInitialized via
// safeCheck, but the internal sendOffchain reaches its own body and returns the
// empty-slice no-op ("", nil) WITHOUT ever consulting safeCheck. This mirrors
// TestPublicSettleStillSafeChecked for the SendOffChain split and confirms the
// migration path can run before the wallet is marked synced.
func TestSendOffchainBypassNoSafeCheck(t *testing.T) {
	w := &wallet{}

	// Public entry is safeCheck-gated: a bare wallet fails before any work.
	_, err := w.SendOffChain(context.Background(), nil)
	require.ErrorIs(t, err, ErrNotInitialized,
		"public SendOffChain must remain safeCheck-gated")

	// Internal bypass is NOT gated: with an empty migration set it returns the
	// no-op result without touching safeCheck (which would have errored above).
	txid, err := w.sendOffchain(context.Background(), nil)
	require.NoError(t, err,
		"internal sendOffchain must bypass safeCheck (no ErrNotInitialized)")
	require.Empty(t, txid, "empty migration set is a no-op returning an empty txid")

	txid, err = w.sendOffchain(context.Background(), []clienttypes.VtxoWithTapTree{})
	require.NoError(t, err, "empty (non-nil) migration set is also a no-op")
	require.Empty(t, txid)
}

// --- inactivation after migration ------------------------------------------

// TestInactivateAfterMigrationSuccess verifies the inactivateContracts helper —
// the post-migration flip step — calls UpdateContractState(ContractStateInactive)
// for every provided script, and that a failing flip for one script does NOT
// abort the others (errors are logged and skipped). This covers the
// "inactivate after migration success" requirement and the resilience boundary.
func TestInactivateAfterMigrationSuccess(t *testing.T) {
	fcs := newFakeContractStore()
	fcs.failOn["migrate-2"] = true // one flip fails mid-pass
	w := &wallet{store: &fakeStore{contractStore: fcs}}

	w.inactivateContracts(context.Background(), []string{"migrate-1", "migrate-2", "migrate-3"})

	// All three were attempted (the failure did not abort the loop).
	require.ElementsMatch(t,
		[]string{"migrate-1", "migrate-2", "migrate-3"}, fcs.allCalls,
		"every script must be attempted even if one flip fails")

	// The two that succeeded are recorded inactive; the failing one is not.
	require.Equal(t, types.ContractStateInactive, fcs.updated["migrate-1"])
	require.Equal(t, types.ContractStateInactive, fcs.updated["migrate-3"])
	_, ok := fcs.updated["migrate-2"]
	require.False(t, ok, "a failed flip must not be recorded as inactive")
}

// TestInactivateEmptyNoOp verifies that flipping an empty script set is a no-op:
// when there is nothing to migrate (and nothing expired), no UpdateContractState
// call is made. This pins the migration-failure boundary: the reconcile caller
// never builds a migratedScripts set when sendOffchain returns early, so
// inactivateContracts is invoked with an empty slice.
func TestInactivateEmptyNoOp(t *testing.T) {
	fcs := newFakeContractStore()
	w := &wallet{store: &fakeStore{contractStore: fcs}}

	w.inactivateContracts(context.Background(), nil)
	w.inactivateContracts(context.Background(), []string{})

	require.Empty(t, fcs.allCalls, "no UpdateContractState call on an empty script set")
}
