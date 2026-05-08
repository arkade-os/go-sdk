package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	sqlstore "github.com/arkade-os/go-sdk/store/sql"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const createContractTable = `
CREATE TABLE IF NOT EXISTS contract (
    script      TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    label       TEXT,
    params      TEXT NOT NULL DEFAULT '{}',
    address     TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'active',
    created_at  INTEGER NOT NULL,
    key_index   INTEGER NOT NULL DEFAULT 0,
    metadata    TEXT
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

func newTestContract(script string) types.Contract {
	now := time.Now().Truncate(time.Second)
	return types.Contract{
		Script: script,
		Type:   types.ContractTypeDefault,
		Label:  "test-label",
		Params: map[string]string{
			"ownerKeyId": "key-" + script,
			"tapscripts": `["deadbeef","cafebabe"]`,
			"exitDelay":  "144",
		},
		Address:   "ark1testaddr",
		State:     types.ContractStateActive,
		CreatedAt: now,
		Metadata:  map[string]string{},
	}
}

func TestContractStore_AddAndGet(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()
	c := newTestContract("aabbccddeeff")

	require.NoError(t, store.AddContract(ctx, c, 0))

	got, err := store.GetContractsByScripts(ctx, []string{c.Script})
	require.NoError(t, err)
	require.Len(t, got, 1)

	require.Equal(t, c.Script, got[0].Script)
	require.Equal(t, c.Type, got[0].Type)
	require.Equal(t, c.Label, got[0].Label)
	require.Equal(t, c.Params, got[0].Params)
	require.Equal(t, c.Address, got[0].Address)
	require.Equal(t, c.State, got[0].State)
	require.Equal(t, c.CreatedAt.Unix(), got[0].CreatedAt.Unix())
}

func TestContractStore_GetNotFound(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))

	got, err := store.GetContractsByScripts(context.Background(), []string{"nonexistent"})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestContractStore_DuplicateAddReturnsError(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()
	c := newTestContract("script001")
	require.NoError(t, store.AddContract(ctx, c, 0))

	err := store.AddContract(ctx, c, 0)
	require.Error(t, err, "adding a contract with a duplicate script must return an error")
}

func TestContractStore_ListContracts(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	for i, script := range []string{"s1", "s2", "s3"} {
		require.NoError(t, store.AddContract(ctx, newTestContract(script), uint32(i)))
	}

	contracts, err := store.ListContracts(ctx)
	require.NoError(t, err)
	require.Len(t, contracts, 3)
}

func TestContractStore_GetContractsByType(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c1 := newTestContract("s1") // ContractTypeDefault
	c2 := newTestContract("s2")
	c2.Type = types.ContractTypeBoarding
	require.NoError(t, store.AddContract(ctx, c1, 0))
	require.NoError(t, store.AddContract(ctx, c2, 1))

	got, err := store.GetContractsByType(ctx, types.ContractTypeDefault)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "s1", got[0].Script)
}

func TestContractStore_GetContractsByState(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	active := newTestContract("active_s")
	inactive := newTestContract("inactive_s")
	inactive.State = types.ContractStateInactive
	require.NoError(t, store.AddContract(ctx, active, 0))
	require.NoError(t, store.AddContract(ctx, inactive, 1))

	got, err := store.GetContractsByState(ctx, types.ContractStateActive)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "active_s", got[0].Script)
}

func TestContractStore_GetContractsByScripts(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	for i, s := range []string{"match", "other1", "other2"} {
		require.NoError(t, store.AddContract(ctx, newTestContract(s), uint32(i)))
	}

	got, err := store.GetContractsByScripts(ctx, []string{"match"})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "match", got[0].Script)
}

func TestContractStore_ListContracts_Empty(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))

	contracts, err := store.ListContracts(context.Background())
	require.NoError(t, err)
	require.Empty(t, contracts)
}

func TestContractStore_UpdateContractState(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("state_script")
	require.NoError(t, store.AddContract(ctx, c, 0))

	require.NoError(t, store.UpdateContractState(ctx, c.Script, types.ContractStateInactive))

	got, err := store.GetContractsByScripts(ctx, []string{c.Script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, types.ContractStateInactive, got[0].State)
}

func TestContractStore_Clean(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	for i, s := range []string{"s1", "s2"} {
		require.NoError(t, store.AddContract(ctx, newTestContract(s), uint32(i)))
	}

	require.NoError(t, store.Clean(ctx))

	contracts, err := store.ListContracts(ctx)
	require.NoError(t, err)
	require.Empty(t, contracts)
}

func TestContractStore_JSONRoundTrip_Params(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("params_script")
	c.Params = map[string]string{"ownerKeyId": "abc123", "extra": "value"}
	require.NoError(t, store.AddContract(ctx, c, 0))

	got, err := store.GetContractsByScripts(ctx, []string{c.Script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, c.Params, got[0].Params)
}

func TestContractStore_JSONRoundTrip_Tapscripts(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("tap_script")
	c.Params["tapscripts"] = `["deadbeef","cafebabe","f00d"]`
	require.NoError(t, store.AddContract(ctx, c, 0))

	got, err := store.GetContractsByScripts(ctx, []string{c.Script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, c.Params["tapscripts"], got[0].Params["tapscripts"])
}

func TestContractStore_JSONRoundTrip_Metadata(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("meta_script")
	c.Metadata = map[string]string{"version": "1", "tag": "test"}
	require.NoError(t, store.AddContract(ctx, c, 0))

	got, err := store.GetContractsByScripts(ctx, []string{c.Script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, c.Metadata, got[0].Metadata)
}

func TestContractStore_ExitDelayRoundTrip(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	c := newTestContract("delay_script")
	c.Params["exitDelay"] = "512"
	require.NoError(t, store.AddContract(ctx, c, 0))

	got, err := store.GetContractsByScripts(ctx, []string{c.Script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "512", got[0].Params["exitDelay"])
}

func TestContractStore_GetLatestContract(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))
	ctx := context.Background()

	// Insert two contracts of the same type; the latest by created_at is returned.
	c1 := newTestContract("first")
	c1.CreatedAt = time.Now().Add(-time.Hour).Truncate(time.Second)
	c2 := newTestContract("second")
	c2.CreatedAt = time.Now().Truncate(time.Second)

	require.NoError(t, store.AddContract(ctx, c1, 0))
	require.NoError(t, store.AddContract(ctx, c2, 1))

	got, err := store.GetLatestContract(ctx, types.ContractTypeDefault)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "second", got.Script)
}

func TestContractStore_GetLatestContractNotFound(t *testing.T) {
	t.Parallel()

	store := sqlstore.NewContractStore(newTestDB(t))

	got, err := store.GetLatestContract(context.Background(), types.ContractTypeDefault)
	require.NoError(t, err)
	require.Nil(t, got)
}
