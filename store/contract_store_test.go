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

	// Active vhtlc, key index 5.
	testContractVHTLC = types.Contract{
		Type:      types.ContractTypeVHTLC,
		Label:     "vhtlc",
		Script:    "0000000000000000000000000000000000000000000000000000000000000005",
		Address:   "ark1qvhtlc",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			ownerKeyIdParam: "m/0/5",
			ownerKeyParam:   "191a1b",
			signerKeyParam:  "1c1d1e",
		},
	}

	// Active non-interactive vhtlc, key index 6: stored under the vhtlc type, the
	// non-interactive param is what resolves its exact type back on read.
	testContractNonInteractiveVHTLC = types.Contract{
		Type:      types.ContractTypeNonInteractiveVHTLC,
		Label:     "noninteractive",
		Script:    "0000000000000000000000000000000000000000000000000000000000000006",
		Address:   "ark1qnivhtlc",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			ownerKeyIdParam:          "m/0/6",
			ownerKeyParam:            "1f2021",
			signerKeyParam:           "222324",
			"nonInteractiveReceiver": "51201f2021",
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

func TestContractStoreGetActiveContractsByType(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("default returns offchain contracts", func(t *testing.T) {
				got, err := s.GetActiveContractsByType(ctx, types.ContractTypeDefault)
				require.NoError(t, err)
				require.Len(t, got, 2)
			})

			t.Run("boarding returns onchain contracts", func(t *testing.T) {
				got, err := s.GetActiveContractsByType(ctx, types.ContractTypeBoarding)
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("empty", func(t *testing.T) {
				cases := []struct {
					contractType types.ContractType
				}{
					{""},
					{"unknown"},
				}

				for _, c := range cases {
					got, err := s.GetActiveContractsByType(ctx, c.contractType)
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

	t.Run("ignores the contract state", func(t *testing.T) {
		// The latest contract must be returned no matter its state: it drives the
		// key-index counter, and skipping a disabled contract would rewind the
		// counter and reuse its key (and the preimage derived from it).
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractFull)
			require.NoError(t, s.DisableContracts(ctx, []string{testContractFull.Script}))

			got, err := s.GetLatestContract(ctx, types.ContractTypeDefault)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, testContractFull.Script, got.Script)
		})
	})

	t.Run("computed across the vhtlc flavors", func(t *testing.T) {
		// Normal and non-interactive vhtlcs derive their keys from the same keyspace,
		// so they are stored under the same type: asking for either flavor returns the
		// same contract, the one holding the latest key, preventing the next key index
		// from colliding with the other flavor's.
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractVHTLC, testContractNonInteractiveVHTLC)

			for _, contractType := range []types.ContractType{
				types.ContractTypeVHTLC, types.ContractTypeNonInteractiveVHTLC,
			} {
				got, err := s.GetLatestContract(ctx, contractType)
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, testContractNonInteractiveVHTLC.Script, got.Script)
				require.Equal(t, types.ContractTypeNonInteractiveVHTLC, got.Type)
			}
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

func TestContractStoreEnableDisableContracts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			// A and B are seeded active, C inactive.
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("disable a single contract", func(t *testing.T) {
				require.NoError(t, s.DisableContracts(ctx, []string{testContractA.Script}))
				require.Equal(
					t, types.ContractStateInactive, contractState(t, s, testContractA.Script),
				)
				// Contracts not in the list are untouched.
				require.Equal(
					t, types.ContractStateActive, contractState(t, s, testContractB.Script),
				)
			})

			t.Run("enable a single contract", func(t *testing.T) {
				require.NoError(t, s.EnableContracts(ctx, []string{testContractC.Script}))
				require.Equal(
					t, types.ContractStateActive, contractState(t, s, testContractC.Script),
				)
			})

			t.Run("disable multiple contracts", func(t *testing.T) {
				require.NoError(t, s.DisableContracts(
					ctx, []string{testContractA.Script, testContractB.Script},
				))
				require.Equal(
					t, types.ContractStateInactive, contractState(t, s, testContractA.Script),
				)
				require.Equal(
					t, types.ContractStateInactive, contractState(t, s, testContractB.Script),
				)
			})

			t.Run("enable multiple contracts", func(t *testing.T) {
				require.NoError(t, s.EnableContracts(
					ctx, []string{testContractA.Script, testContractB.Script},
				))
				require.Equal(
					t, types.ContractStateActive, contractState(t, s, testContractA.Script),
				)
				require.Equal(
					t, types.ContractStateActive, contractState(t, s, testContractB.Script),
				)
			})
			t.Run("empty scripts is a no-op", func(t *testing.T) {
				ctx := t.Context()
				require.NoError(t, s.EnableContracts(ctx, nil))
				require.NoError(t, s.DisableContracts(ctx, []string{}))
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		const missingScript = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

		t.Run("single unknown script", func(t *testing.T) {
			forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
				err := s.DisableContracts(t.Context(), []string{missingScript})
				require.ErrorContains(t, err, "not found")
			})
		})

		// The whole point of running a multi-script update in a transaction: if any script is
		// missing the entire batch rolls back, so a valid script listed before a missing one must
		// keep its original state rather than being left half-applied.
		t.Run("multi-script batch rolls back when one script is missing", func(t *testing.T) {
			forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
				ctx := t.Context()
				seedContracts(t, s, testContractA)
				require.Equal(
					t, types.ContractStateActive, contractState(t, s, testContractA.Script),
				)

				err := s.DisableContracts(ctx, []string{testContractA.Script, missingScript})
				require.ErrorContains(t, err, "not found")
				require.Equal(
					t, types.ContractStateActive, contractState(t, s, testContractA.Script),
					"the batch must roll back, leaving the valid contract untouched",
				)
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

				offchain, err := s.GetActiveContractsByType(ctx, types.ContractTypeDefault)
				require.NoError(t, err)
				require.Len(t, offchain, 1)
				require.Equal(t, testContractA.Script, offchain[0].Script)

				boarding, err := s.GetActiveContractsByType(ctx, types.ContractTypeBoarding)
				require.NoError(t, err)
				require.Empty(t, boarding)
			})
		})
	})
}

func forEachContractBackend(t *testing.T, fn func(t *testing.T, s types.ContractStore)) {
	t.Helper()

	backends := []struct {
		name   string
		config types.StoreConfig
	}{
		{name: "sql", config: types.StoreConfig{StoreType: types.SQLStore, Args: t.TempDir()}},
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

func contractState(t *testing.T, s types.ContractStore, script string) types.ContractState {
	t.Helper()
	got, err := s.GetContractsByScripts(t.Context(), []string{script})
	require.NoError(t, err)
	require.Len(t, got, 1)
	return got[0].State
}
