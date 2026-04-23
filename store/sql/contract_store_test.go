package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/contract"
	sqlstore "github.com/arkade-os/go-sdk/store/sql"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const createContractTable = `
CREATE TABLE IF NOT EXISTS contract (
    script      TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    params      TEXT NOT NULL DEFAULT '{}',
    address     TEXT NOT NULL DEFAULT '',
    is_onchain  INTEGER NOT NULL DEFAULT 0,
    state       TEXT NOT NULL DEFAULT 'active',
    created_at  INTEGER NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}'
)`

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	_, err = db.Exec(createContractTable)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func newTestContract(script string) contract.Contract {
	now := time.Now().Truncate(time.Second)
	return contract.Contract{
		Script: script,
		Type:   contract.TypeDefault,
		Label:  "test-label",
		Params: map[string]string{
			contract.ParamKeyID:      "key-" + script,
			contract.ParamTapscripts: `["deadbeef","cafebabe"]`,
			contract.ParamExitDelay:  "block:144",
		},
		Address:   "ark1testaddr",
		IsOnchain: false,
		State:     contract.StateActive,
		CreatedAt: now,
		Metadata:  map[string]any{},
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
	require.Equal(t, c.IsOnchain, got.IsOnchain)
	require.Equal(t, c.State, got.State)
	require.Equal(t, c.CreatedAt.Unix(), got.CreatedAt.Unix())
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
	c.Params[contract.ParamTapscripts] = `["deadbeef","cafebabe","f00d"]`
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, c.Params[contract.ParamTapscripts], got.Params[contract.ParamTapscripts])
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
	c.Params[contract.ParamExitDelay] = "block:512"
	require.NoError(t, store.UpsertContract(ctx, c))

	got, err := store.GetContractByScript(ctx, c.Script)
	require.NoError(t, err)
	require.Equal(t, "block:512", got.Params[contract.ParamExitDelay])
}
