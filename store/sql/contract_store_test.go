package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/contract"
	sqlstore "github.com/arkade-os/go-sdk/store/sql"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const createContractTable = `
CREATE TABLE IF NOT EXISTS contract (
    script               TEXT PRIMARY KEY,
    type                 TEXT NOT NULL,
    label                TEXT NOT NULL DEFAULT '',
    params               TEXT NOT NULL DEFAULT '{}',
    address              TEXT NOT NULL DEFAULT '',
    boarding             TEXT NOT NULL DEFAULT '',
    onchain              TEXT NOT NULL DEFAULT '',
    state                TEXT NOT NULL DEFAULT 'active',
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER,
    metadata             TEXT NOT NULL DEFAULT '{}',
    tapscripts           TEXT NOT NULL DEFAULT '[]',
    boarding_tapscripts  TEXT NOT NULL DEFAULT '[]',
    delay_type           INTEGER NOT NULL DEFAULT 0,
    delay_value          INTEGER NOT NULL DEFAULT 0,
    boarding_delay_type  INTEGER NOT NULL DEFAULT 0,
    boarding_delay_value INTEGER NOT NULL DEFAULT 0
)`

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(createContractTable)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func newTestContract(script string) contract.Contract {
	now := time.Now().Truncate(time.Second)
	return contract.Contract{
		Script:             script,
		Type:               contract.TypeDefault,
		Label:              "test-label",
		Params:             map[string]string{"keyId": "key-" + script},
		Address:            "ark1testaddr",
		Boarding:           "tb1qboardingaddr",
		Onchain:            "tb1qonchainaddr",
		State:              contract.StateActive,
		CreatedAt:          now,
		Metadata:           map[string]any{},
		Tapscripts:         []string{"deadbeef", "cafebabe"},
		BoardingTapscripts: []string{"aabbccdd"},
		Delay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 144,
		},
		BoardingDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 1008,
		},
	}
}

func TestContractStore_UpsertAndGet(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()
	c := newTestContract("aabbccddeeff")

	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.NotNil(t, got)

	require.Equal(t, c.Script, got.Script)
	require.Equal(t, c.Type, got.Type)
	require.Equal(t, c.Label, got.Label)
	require.Equal(t, c.Params, got.Params)
	require.Equal(t, c.Address, got.Address)
	require.Equal(t, c.Boarding, got.Boarding)
	require.Equal(t, c.Onchain, got.Onchain)
	require.Equal(t, c.State, got.State)
	require.Equal(t, c.CreatedAt.Unix(), got.CreatedAt.Unix())
	require.Equal(t, c.Tapscripts, got.Tapscripts)
	require.Equal(t, c.BoardingTapscripts, got.BoardingTapscripts)
	require.Equal(t, c.Delay, got.Delay)
	require.Equal(t, c.BoardingDelay, got.BoardingDelay)
	require.Nil(t, got.ExpiresAt)
}

func TestContractStore_GetNotFound(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))

	got, err := store.GetContractByScript(context.Background(), "nonexistent")
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestContractStore_UpsertUpdatesLabelAndState(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()
	c := newTestContract("script001")
	require.NoError(t, store.UpsertContract(ctx, c))

	updated := c
	updated.Label = "new-label"
	updated.State = contract.StateInactive
	require.NoError(t, store.UpsertContract(ctx, updated))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, "new-label", got.Label)
	require.Equal(t, contract.StateInactive, got.State)
	// Immutable fields should not change on conflict update.
	require.Equal(t, c.Type, got.Type)
	require.Equal(t, c.Address, got.Address)
}

func TestContractStore_ExpiresAt(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	expiry := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	c := newTestContract("expiry_script")
	c.ExpiresAt = &expiry
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.NotNil(t, got.ExpiresAt)
	require.Equal(t, expiry.Unix(), got.ExpiresAt.Unix())
}

func TestContractStore_ListContracts_NoFilter(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	for _, script := range []string{"s1", "s2", "s3"} {
		require.NoError(t, store.UpsertContract(ctx, newTestContract(script)))
	}

	contracts, err := store.ListContracts(ctx, contract.Filter{})
	require.NoError(t, err)
	require.Len(t, contracts, 3)
}

func TestContractStore_ListContracts_FilterByType(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c1 := newTestContract("s1")
	c2 := newTestContract("s2")
	c2.Type = "other"
	require.NoError(t, store.UpsertContract(ctx, c1))
	require.NoError(t, store.UpsertContract(ctx, c2))

	typ := contract.TypeDefault
	got, err := store.ListContracts(ctx, contract.Filter{Type: &typ})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "s1", got[0].Script)
}

func TestContractStore_ListContracts_FilterByState(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	active := newTestContract("active_s")
	inactive := newTestContract("inactive_s")
	inactive.State = contract.StateInactive
	require.NoError(t, store.UpsertContract(ctx, active))
	require.NoError(t, store.UpsertContract(ctx, inactive))

	stateStr := string(contract.StateActive)
	got, err := store.ListContracts(ctx, contract.Filter{State: &stateStr})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "active_s", got[0].Script)
}

func TestContractStore_ListContracts_FilterByScript(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	for _, s := range []string{"match", "other1", "other2"} {
		require.NoError(t, store.UpsertContract(ctx, newTestContract(s)))
	}

	script := "match"
	got, err := store.ListContracts(ctx, contract.Filter{Script: &script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "match", got[0].Script)
}

func TestContractStore_ListContracts_Empty(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))

	contracts, err := store.ListContracts(context.Background(), contract.Filter{})
	require.NoError(t, err)
	require.Empty(t, contracts)
}

func TestContractStore_UpdateContractState(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("state_script")
	require.NoError(t, store.UpsertContract(ctx, c))

	require.NoError(t, store.UpdateContractState(ctx, c.Script, contract.StateInactive))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, contract.StateInactive, got.State)
}

func TestContractStore_Clean(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	for _, s := range []string{"s1", "s2"} {
		require.NoError(t, store.UpsertContract(ctx, newTestContract(s)))
	}

	require.NoError(t, store.Clean(ctx))

	contracts, err := store.ListContracts(ctx, contract.Filter{})
	require.NoError(t, err)
	require.Empty(t, contracts)
}

func TestContractStore_JSONRoundTrip_Params(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("params_script")
	c.Params = map[string]string{"keyId": "abc123", "extra": "value"}
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, c.Params, got.Params)
}

func TestContractStore_JSONRoundTrip_Tapscripts(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("tap_script")
	c.Tapscripts = []string{"deadbeef", "cafebabe", "f00d"}
	c.BoardingTapscripts = []string{"11223344", "55667788"}
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, c.Tapscripts, got.Tapscripts)
	require.Equal(t, c.BoardingTapscripts, got.BoardingTapscripts)
}

func TestContractStore_JSONRoundTrip_Metadata(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("meta_script")
	// JSON round-trip decodes numbers as float64 for interface{} values.
	c.Metadata = map[string]any{"version": float64(1), "tag": "test"}
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, c.Metadata, got.Metadata)
}

func TestContractStore_DelayRoundTrip(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("delay_script")
	c.Delay = arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 512}
	c.BoardingDelay = arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 2016}
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, c.Delay, got.Delay)
	require.Equal(t, c.BoardingDelay, got.BoardingDelay)
}
