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

// TestBuildSignerMap covers current, migratable, expired, no-cutoff, and unknown.
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

// TestDeprecatedSignerSet covers normalization, dedup, and malformed entries.
func TestDeprecatedSignerSet(t *testing.T) {
	current := testKey(t)
	dep := testKey(t)

	info := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(dep), CutoffDate: 123},
			{PubKey: compressedHex(current), CutoffDate: 999},
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

// TestSignerSetDigestStability covers live-rotation digest behavior.
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
	info2 := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(b)}, {PubKey: compressedHex(a)},
		},
	}
	require.Equal(t, signerSet(info1), signerSet(info2))

	rotated := &client.Info{
		SignerPubKey: compressedHex(a),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(current)}, {PubKey: compressedHex(b)},
		},
	}
	require.NotEqual(t, signerSet(info1), signerSet(rotated))

	added := &client.Info{
		SignerPubKey: compressedHex(current),
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{
			{PubKey: compressedHex(a)},
			{PubKey: compressedHex(b)},
			{PubKey: compressedHex(testKey(t))},
		},
	}
	require.NotEqual(t, signerSet(info1), signerSet(added))
}

// --- Test doubles -----------------------------------------------------------

// fakeContractStore records UpdateContractState calls.
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
func (f *fakeContractStore) GetActiveContractsByType(
	context.Context, types.ContractType,
) ([]types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) GetLatestActiveContract(
	context.Context, types.ContractType,
) (*types.Contract, error) {
	return nil, nil
}
func (f *fakeContractStore) Clean(context.Context) error { return nil }

// fakeStore only exposes ContractStore for inactivation tests.
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

// TestClassifyVtxosSinglePass covers migratable, expired, unknown, and orphaned.
func TestClassifyVtxosSinglePass(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	current := testKey(t)
	toMigrateA := testKey(t)
	toMigrateB := testKey(t)
	cutoffExpired := testKey(t)
	unknown := testKey(t)

	currentHex := xonlyHexOf(current)
	deprecated := map[string]client.DeprecatedSigner{
		xonlyHexOf(toMigrateA): {
			PubKey: xonlyHexOf(toMigrateA), CutoffDate: now.Add(72 * time.Hour).Unix(),
		},
		xonlyHexOf(toMigrateB): {
			PubKey: xonlyHexOf(toMigrateB), CutoffDate: 0, // no cutoff → toMigrate
		},
		xonlyHexOf(cutoffExpired): {
			PubKey: xonlyHexOf(cutoffExpired), CutoffDate: now.Add(-time.Hour).Unix(),
		},
	}

	spendable := []clienttypes.Vtxo{
		{Script: "active-1", Amount: 100},
		{Script: "tomigrate-1", Amount: 1000},
		{Script: "tomigrate-2", Amount: 2000},
		{Script: "cutoff-expired-1", Amount: 9000},
		{Script: "unknown-1", Amount: 7}, // signer present but not in current∪deprecated
		{Script: "orphan-1", Amount: 5},  // no signer mapping → skipped
	}
	signerByScript := map[string]string{
		"active-1":         currentHex,
		"tomigrate-1":      xonlyHexOf(toMigrateA),
		"tomigrate-2":      xonlyHexOf(toMigrateB),
		"cutoff-expired-1": xonlyHexOf(cutoffExpired),
		"unknown-1":        xonlyHexOf(unknown),
		// "orphan-1" intentionally absent.
	}

	signerMap := buildSignerMap(currentHex, deprecated, now)
	toMigrate := classifyVtxos(spendable, signerByScript, signerMap, 330)

	require.Len(t, toMigrate, 2)
	migrate := map[string]bool{}
	for _, v := range toMigrate {
		migrate[v.Script] = true
	}
	require.True(t, migrate["tomigrate-1"])
	require.True(t, migrate["tomigrate-2"])
	require.False(t, migrate["active-1"], "current-signer vtxo must be excluded")
	require.False(t, migrate["cutoff-expired-1"],
		"cutoff-expired signer vtxo must be excluded")
	require.False(t, migrate["unknown-1"], "unknown-signer vtxo must be excluded")
	require.False(t, migrate["orphan-1"], "unmapped vtxo must be excluded")
}

func TestClassifyVtxosSkipsCutoffExpiredSignerFunds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	current := testKey(t)
	cutoffExpired := testKey(t)
	currentHex := xonlyHexOf(current)
	cutoffExpiredHex := xonlyHexOf(cutoffExpired)
	deprecated := map[string]client.DeprecatedSigner{
		cutoffExpiredHex: {
			PubKey: cutoffExpiredHex, CutoffDate: now.Add(-time.Hour).Unix(),
		},
	}
	spendable := []clienttypes.Vtxo{
		{Script: "active-1", Amount: 100},
		{Script: "cutoff-expired-1", Amount: 200},
		{Script: "cutoff-expired-2", Amount: 300},
	}
	signerByScript := map[string]string{
		"active-1":         currentHex,
		"cutoff-expired-1": cutoffExpiredHex,
		"cutoff-expired-2": cutoffExpiredHex,
	}

	toMigrate := classifyVtxos(
		spendable, signerByScript, buildSignerMap(currentHex, deprecated, now), 330,
	)

	require.Empty(t, toMigrate, "cutoff-expired signer funds must not self-send")
}

func TestClassifyVtxosSkipsRecoverableAndSubdustFunds(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	current := testKey(t)
	deprecatedKey := testKey(t)
	currentHex := xonlyHexOf(current)
	deprecatedHex := xonlyHexOf(deprecatedKey)
	deprecated := map[string]client.DeprecatedSigner{
		deprecatedHex: {
			PubKey: deprecatedHex, CutoffDate: now.Add(72 * time.Hour).Unix(),
		},
	}

	spendable := []clienttypes.Vtxo{
		{Script: "normal", Amount: 1000},
		{Script: "subdust", Amount: 100},
		{Script: "swept", Amount: 1000, Swept: true},
		{Script: "recoverable-vtxo", Amount: 1000, ExpiresAt: time.Now().Add(-time.Hour)},
	}
	signerByScript := map[string]string{
		"normal":           deprecatedHex,
		"subdust":          deprecatedHex,
		"swept":            deprecatedHex,
		"recoverable-vtxo": deprecatedHex,
	}

	toMigrate := classifyVtxos(
		spendable, signerByScript, buildSignerMap(currentHex, deprecated, now), 330,
	)

	require.Len(t, toMigrate, 1)
	require.Equal(t, "normal", toMigrate[0].Script)
}

// --- inactivation after migration ------------------------------------------

// TestInactivateAfterMigrationSuccess covers best-effort inactive updates.
func TestInactivateAfterMigrationSuccess(t *testing.T) {
	fcs := newFakeContractStore()
	fcs.failOn["migrate-2"] = true // one flip fails mid-pass
	w := &wallet{store: &fakeStore{contractStore: fcs}}

	w.deactivateContracts(context.Background(), []string{"migrate-1", "migrate-2", "migrate-3"})

	require.ElementsMatch(t,
		[]string{"migrate-1", "migrate-2", "migrate-3"}, fcs.allCalls,
		"every script must be attempted even if one flip fails")

	require.Equal(t, types.ContractStateInactive, fcs.updated["migrate-1"])
	require.Equal(t, types.ContractStateInactive, fcs.updated["migrate-3"])
	_, ok := fcs.updated["migrate-2"]
	require.False(t, ok, "a failed flip must not be recorded as inactive")
}

// TestInactivateEmptyNoOp verifies an empty script set is a no-op.
func TestInactivateEmptyNoOp(t *testing.T) {
	fcs := newFakeContractStore()
	w := &wallet{store: &fakeStore{contractStore: fcs}}

	w.deactivateContracts(context.Background(), nil)
	w.deactivateContracts(context.Background(), []string{})

	require.Empty(t, fcs.allCalls, "no UpdateContractState call on an empty script set")
}
