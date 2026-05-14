package store_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const (
	ownerKeyParam           = "ownerKey"
	ownerKeyIdParam         = "ownerKeyId"
	signerKeyParam          = "signerKey"
	exitDelayParam          = "exitDelay"
	checkpointExitPathParam = "checkpointExitPath"
)

var (
	testContractCreatedAt = time.Unix(1746143068, 0)

	// Active, offchain (default type), key index 0.
	testContractA = types.Contract{
		Type:      types.ContractTypeDefault,
		Label:     "first",
		Script:    "0000000000000000000000000000000000000000000000000000000000000001",
		Address:   "ark1qfirst",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			ownerKeyIdParam: "m/0/0",
			ownerKeyParam:   "0102030405",
			signerKeyParam:  "06070809",
			exitDelayParam:  "144",
		},
	}

	// Active, offchain (default type), key index 1.
	testContractB = types.Contract{
		Type:      types.ContractTypeDefault,
		Label:     "second",
		Script:    "0000000000000000000000000000000000000000000000000000000000000002",
		Address:   "ark1qsecond",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			ownerKeyIdParam: "m/0/1",
			ownerKeyParam:   "0a0b0c0d0e",
			signerKeyParam:  "0f101112",
			exitDelayParam:  "288",
		},
	}

	// Inactive, boarding (onchain) type, key index 2.
	testContractC = types.Contract{
		Type:      types.ContractTypeBoarding,
		Label:     "third",
		Script:    "0000000000000000000000000000000000000000000000000000000000000003",
		Address:   "ark1qthird",
		State:     types.ContractStateInactive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			ownerKeyIdParam: "m/0/2",
			ownerKeyParam:   "131415",
			signerKeyParam:  "161718",
			exitDelayParam:  "144",
		},
	}

	// Fully populated fixture (extra params + metadata) for round-trip checks.
	testContractFull = types.Contract{
		Type:      types.ContractTypeDefault,
		Label:     "full",
		Script:    "0000000000000000000000000000000000000000000000000000000000000004",
		Address:   "ark1qfull",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			ownerKeyIdParam: "m/0/4",
			ownerKeyParam:   "deadbeef",
			signerKeyParam:  "cafebabe",
			exitDelayParam:  "144",
			"extra1":        "value1",
			"extra2":        "value2",
		},
		// JSON-decoded numbers land as float64 — use it directly so SQL/JSON
		// round-trip works correctly.
		Metadata: map[string]string{
			"version": "1",
			"tag":     "test",
		},
	}
)

func TestContractStoreAddContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()

			t.Run("multiple", func(t *testing.T) {
				require.NoError(t, s.AddContract(ctx, testContractA, 0))
				require.NoError(t, s.AddContract(ctx, testContractB, 1))

				got, err := s.ListContracts(ctx)
				require.NoError(t, err)
				require.Len(t, got, 2)
			})

			t.Run("round trip", func(t *testing.T) {
				require.NoError(t, s.AddContract(ctx, testContractFull, 4))

				got, err := s.GetContractsByScripts(ctx, []string{testContractFull.Script})
				require.NoError(t, err)
				require.Len(t, got, 1)

				fetched := got[0]
				require.Equal(t, testContractFull.Type, fetched.Type)
				require.Equal(t, testContractFull.Label, fetched.Label)
				require.Equal(t, testContractFull.Script, fetched.Script)
				require.Equal(t, testContractFull.Address, fetched.Address)
				require.Equal(t, testContractFull.State, fetched.State)
				require.Equal(
					t, testContractFull.CreatedAt.Unix(), fetched.CreatedAt.Unix(),
				)
				require.Equal(t, testContractFull.Params, fetched.Params)
				require.Equal(t, testContractFull.Metadata, fetched.Metadata)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			t.Run("duplicated contract", func(t *testing.T) {
				ctx := t.Context()
				require.NoError(t, s.AddContract(ctx, testContractA, 0))

				err := s.AddContract(ctx, testContractA, 0)
				require.Error(t, err)
				require.ErrorContains(t, err, "already exists")
			})
		})
	})
}

func TestContractStoreListContracts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {

		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()

			empty, err := s.ListContracts(ctx)
			require.NoError(t, err)
			require.Empty(t, empty)

			// Mix of default and boarding contracts to verify the no-arg
			// listing returns every persisted contract regardless of type.
			seedContracts(t, s, testContractA, testContractB, testContractC)

			got, err := s.ListContracts(ctx)
			require.NoError(t, err)
			require.Len(t, got, 3)
		})
	})
}

func TestContractStoreGetContractsByScripts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("non empty", func(t *testing.T) {
				requested := []string{testContractA.Script, testContractC.Script}
				got, err := s.GetContractsByScripts(ctx, requested)
				require.NoError(t, err)
				require.Len(t, got, len(requested))

				gotScripts := make([]string, len(got))
				for i, c := range got {
					gotScripts[i] = c.Script
				}
				require.ElementsMatch(t, requested, gotScripts)
			})

			t.Run("empty", func(t *testing.T) {
				cases := []struct {
					scripts []string
				}{
					{[]string{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}},
					{nil},
					{[]string{}},
				}

				for _, c := range cases {
					got, err := s.GetContractsByScripts(ctx, c.scripts)
					require.NoError(t, err)
					require.Empty(t, got)
				}
			})
		})
	})
}

func TestContractStoreGetContractsByState(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("non empty", func(t *testing.T) {
				active, err := s.GetContractsByState(ctx, types.ContractStateActive)
				require.NoError(t, err)
				require.Len(t, active, 2)

				inactive, err := s.GetContractsByState(ctx, types.ContractStateInactive)
				require.NoError(t, err)
				require.Len(t, inactive, 1)
				require.Equal(t, testContractC.Script, inactive[0].Script)
			})

			t.Run("empty", func(t *testing.T) {
				cases := []struct {
					state types.ContractState
				}{
					{""},
					{"unknown"},
				}

				for _, c := range cases {
					got, err := s.GetContractsByState(ctx, c.state)
					require.NoError(t, err)
					require.Empty(t, got)
				}
			})
		})
	})
}

func TestContractStoreGetContractsByType(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("default returns offchain contracts", func(t *testing.T) {
				got, err := s.GetContractsByType(ctx, types.ContractTypeDefault)
				require.NoError(t, err)
				require.Len(t, got, 2)
			})

			t.Run("boarding returns onchain contracts", func(t *testing.T) {
				got, err := s.GetContractsByType(ctx, types.ContractTypeBoarding)
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, testContractC.Script, got[0].Script)
			})

			t.Run("empty", func(t *testing.T) {
				cases := []struct {
					contractType types.ContractType
				}{
					{""},
					{"unknown"},
				}

				for _, c := range cases {
					got, err := s.GetContractsByType(ctx, c.contractType)
					require.NoError(t, err)
					require.Empty(t, got)
				}
			})
		})
	})
}

func TestContractStoreGetLatestContract(t *testing.T) {
	t.Run("empty store returns nil", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			got, err := s.GetLatestContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			require.Nil(t, got)
		})
	})

	t.Run("returns nil for a type with no contracts", func(t *testing.T) {
		// Even with contracts of a *different* type present, the requested
		// type having no rows is not an error — the manager relies on
		// (nil, nil) here to detect a fresh wallet.
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB)

			got, err := s.GetLatestContract(ctx, types.ContractTypeBoarding)
			require.NoError(t, err)
			require.Nil(t, got)
		})
	})

	t.Run("returns the only contract", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA)

			got, err := s.GetLatestContract(ctx, types.ContractTypeDefault)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, testContractA.Script, got.Script)
		})
	})

	t.Run("returns highest key index even when inserted out of order", func(t *testing.T) {
		// Insertion order is A (idx=0), Full (idx=4), B (idx=1). Latest by
		// key_index is Full. The order is intentionally scrambled so a
		// backend that returns by insertion order / rowid (i.e. ignores
		// the key_index column) surfaces as a test failure here rather
		// than going unnoticed because the manager happens to always
		// create contracts in ascending key-index order.
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractFull, testContractB)

			got, err := s.GetLatestContract(ctx, types.ContractTypeDefault)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, testContractFull.Script, got.Script)
		})
	})

	t.Run("filters by contract type", func(t *testing.T) {
		// Default and boarding contracts share the same key-index space
		// in the underlying wallet, but each pool's "latest" is computed
		// independently. Boarding's idx=2 must NOT promote it to "latest
		// default" just because its index is higher.
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			latestDefault, err := s.GetLatestContract(ctx, types.ContractTypeDefault)
			require.NoError(t, err)
			require.NotNil(t, latestDefault)
			require.Equal(t, testContractB.Script, latestDefault.Script)

			latestBoarding, err := s.GetLatestContract(ctx, types.ContractTypeBoarding)
			require.NoError(t, err)
			require.NotNil(t, latestBoarding)
			require.Equal(t, testContractC.Script, latestBoarding.Script)
		})
	})
}

func TestContractStoreUpdateContractState(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA)

			// No errors if the status changes but still set to active
			require.NoError(t, s.UpdateContractState(
				ctx, testContractA.Script, types.ContractStateActive,
			))

			got, err := s.GetContractsByScripts(ctx, []string{testContractA.Script})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, types.ContractStateActive, got[0].State)

			// No errors if the status changes to inactive
			require.NoError(t, s.UpdateContractState(
				ctx, testContractA.Script, types.ContractStateInactive,
			))

			got, err = s.GetContractsByScripts(ctx, []string{testContractA.Script})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, types.ContractStateInactive, got[0].State)

			// No errors if the status changes but still set inactive
			require.NoError(t, s.UpdateContractState(
				ctx, testContractA.Script, types.ContractStateInactive,
			))

			got, err = s.GetContractsByScripts(ctx, []string{testContractA.Script})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, types.ContractStateInactive, got[0].State)

			// No errors if the status changes back to active
			require.NoError(t, s.UpdateContractState(
				ctx, testContractA.Script, types.ContractStateActive,
			))

			got, err = s.GetContractsByScripts(ctx, []string{testContractA.Script})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, types.ContractStateActive, got[0].State)

			// No errors if the status changes back to inactive
			require.NoError(t, s.UpdateContractState(
				ctx, testContractA.Script, types.ContractStateInactive,
			))

			got, err = s.GetContractsByScripts(ctx, []string{testContractA.Script})
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, types.ContractStateInactive, got[0].State)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()

			t.Run("not found", func(t *testing.T) {
				err := s.UpdateContractState(
					ctx,
					"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
					types.ContractStateInactive,
				)
				require.Error(t, err)
				require.ErrorContains(t, err, "not found")
			})

			t.Run("after clean", func(t *testing.T) {
				seedContracts(t, s, testContractA)
				require.NoError(t, s.Clean(ctx))

				err := s.UpdateContractState(
					ctx, testContractA.Script, types.ContractStateInactive,
				)
				require.Error(t, err)
				require.ErrorContains(t, err, "not found")
			})
		})
	})
}

func TestContractStoreClean(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()

			t.Run("empty store", func(t *testing.T) {
				require.NoError(t, s.Clean(ctx))
			})

			t.Run("non empty store", func(t *testing.T) {
				seedContracts(t, s, testContractA, testContractB)
				got, err := s.ListContracts(ctx)
				require.NoError(t, err)
				require.NotEmpty(t, got)

				require.NoError(t, s.Clean(ctx))

				got, err = s.ListContracts(ctx)
				require.NoError(t, err)
				require.Empty(t, got)

				// No errors if cleaning an already cleaned store
				require.NoError(t, s.Clean(ctx))

				got, err = s.ListContracts(ctx)
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("clean and reseed", func(t *testing.T) {
				seedContracts(t, s, testContractA, testContractB)
				require.NoError(t, s.Clean(ctx))

				// Re-seeding the same scripts must not collide with leftover state.
				seedContracts(t, s, testContractA, testContractC)

				offchain, err := s.GetContractsByType(ctx, types.ContractTypeDefault)
				require.NoError(t, err)
				require.Len(t, offchain, 1)
				require.Equal(t, testContractA.Script, offchain[0].Script)

				boarding, err := s.GetContractsByType(ctx, types.ContractTypeBoarding)
				require.NoError(t, err)
				require.Len(t, boarding, 1)
				require.Equal(t, testContractC.Script, boarding[0].Script)
			})
		})
	})
}

func forEachContractBackend(t *testing.T, fn func(t *testing.T, s types.ContractStore)) {
	t.Helper()

	backends := []struct {
		name   string
		config store.Config
	}{
		{name: "sql", config: store.Config{StoreType: types.SQLStore, Args: t.TempDir()}},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			svc, err := store.NewStore(b.config)
			require.NoError(t, err)
			t.Cleanup(svc.Close)

			cs := svc.ContractStore()
			require.NotNil(t, cs)

			fn(t, cs)
		})
	}
}

func seedContracts(t *testing.T, s types.ContractStore, contracts ...types.Contract) {
	t.Helper()
	getIndex := func(str string) uint32 {
		ss := strings.Split(str, "/")
		s := ss[len(ss)-1]
		i, _ := strconv.ParseUint(s, 10, 32)
		return uint32(i)
	}
	for _, c := range contracts {
		index := getIndex(c.Params[ownerKeyIdParam])
		require.NoError(t, s.AddContract(t.Context(), c, index))
	}
}
