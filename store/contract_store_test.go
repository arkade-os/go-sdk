package store_test

import (
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

var (
	testContractCreatedAt = time.Unix(1746143068, 0)

	// Active, offchain, key index 0.
	testContractA = types.Contract{
		Type:      types.ContractTypeDefault,
		Label:     "first",
		Script:    "0000000000000000000000000000000000000000000000000000000000000001",
		Address:   "ark1qfirst",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			types.ContractParamOwnerKeyId: "m/0/0",
			types.ContractParamOwnerKey:   "0102030405",
			types.ContractParamSignerKey:  "06070809",
			types.ContractParamExitDelay:  "144",
			types.ContractParamIsOnchain:  "false",
		},
	}

	// Active, offchain, key index 1.
	testContractB = types.Contract{
		Type:      types.ContractTypeDefault,
		Label:     "second",
		Script:    "0000000000000000000000000000000000000000000000000000000000000002",
		Address:   "ark1qsecond",
		State:     types.ContractStateActive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			types.ContractParamOwnerKeyId: "m/0/1",
			types.ContractParamOwnerKey:   "0a0b0c0d0e",
			types.ContractParamSignerKey:  "0f101112",
			types.ContractParamExitDelay:  "288",
			types.ContractParamIsOnchain:  "false",
		},
	}

	// Inactive, onchain, key index 2.
	testContractC = types.Contract{
		Type:      types.ContractTypeDefault,
		Label:     "third",
		Script:    "0000000000000000000000000000000000000000000000000000000000000003",
		Address:   "ark1qthird",
		State:     types.ContractStateInactive,
		CreatedAt: testContractCreatedAt,
		Params: map[string]string{
			types.ContractParamOwnerKeyId: "m/0/2",
			types.ContractParamOwnerKey:   "131415",
			types.ContractParamSignerKey:  "161718",
			types.ContractParamExitDelay:  "144",
			types.ContractParamIsOnchain:  "true",
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
			types.ContractParamOwnerKeyId: "m/0/4",
			types.ContractParamOwnerKey:   "deadbeef",
			types.ContractParamSignerKey:  "cafebabe",
			types.ContractParamExitDelay:  "144",
			types.ContractParamIsOnchain:  "false",
			"extra1":                      "value1",
			"extra2":                      "value2",
		},
		// JSON-decoded numbers land as float64 — use it directly so SQL/JSON
		// round-trip matches the in-memory KV path.
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
				require.NoError(t, s.AddContract(ctx, testContractA))
				require.NoError(t, s.AddContract(ctx, testContractB))

				got, err := s.ListContracts(ctx, false)
				require.NoError(t, err)
				require.Len(t, got, 2)
			})

			t.Run("round trip", func(t *testing.T) {
				require.NoError(t, s.AddContract(ctx, testContractFull))

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
			cases := []struct {
				name          string
				params        map[string]string
				expectedError string
			}{
				{
					name: "missing ownerKey",
					params: map[string]string{
						types.ContractParamOwnerKeyId: "m/0/0",
						types.ContractParamSignerKey:  "06070809",
						types.ContractParamExitDelay:  "144",
						types.ContractParamIsOnchain:  "false",
					},
					expectedError: "missing ownerKey param",
				},
				{
					name: "missing keyID",
					params: map[string]string{
						types.ContractParamOwnerKey:  "0102030405",
						types.ContractParamSignerKey: "06070809",
						types.ContractParamExitDelay: "144",
						types.ContractParamIsOnchain: "false",
					},
					expectedError: "missing ownerKeyId param",
				},
				{
					name: "missing signerKey",
					params: map[string]string{
						types.ContractParamOwnerKey:   "0102030405",
						types.ContractParamOwnerKeyId: "m/0/0",
						types.ContractParamExitDelay:  "144",
						types.ContractParamIsOnchain:  "false",
					},
					expectedError: "missing signerKey param",
				},
				{
					name: "missing exitDelay",
					params: map[string]string{
						types.ContractParamOwnerKey:   "0102030405",
						types.ContractParamOwnerKeyId: "m/0/0",
						types.ContractParamSignerKey:  "06070809",
						types.ContractParamIsOnchain:  "false",
					},
					expectedError: "missing exitDelay param",
				},
				{
					name: "invalid keyID",
					params: map[string]string{
						types.ContractParamOwnerKey:   "0102030405",
						types.ContractParamOwnerKeyId: "m/0/notanumber",
						types.ContractParamSignerKey:  "06070809",
						types.ContractParamExitDelay:  "144",
						types.ContractParamIsOnchain:  "false",
					},
					expectedError: "invalid ownerKeyId param",
				},
				{
					name: "invalid exitDelay",
					params: map[string]string{
						types.ContractParamOwnerKey:   "0102030405",
						types.ContractParamOwnerKeyId: "m/0/0",
						types.ContractParamSignerKey:  "06070809",
						types.ContractParamExitDelay:  "notanumber",
						types.ContractParamIsOnchain:  "false",
					},
					expectedError: "invalid exitDelay param",
				},
				{
					name: "invalid isOnchain",
					params: map[string]string{
						types.ContractParamOwnerKey:   "0102030405",
						types.ContractParamOwnerKeyId: "m/0/0",
						types.ContractParamSignerKey:  "06070809",
						types.ContractParamExitDelay:  "144",
						types.ContractParamIsOnchain:  "notabool",
					},
					expectedError: "invalid isOnchain param",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					broken := cloneContract(testContractA)
					broken.Script = "broken-" + c.name
					broken.Params = c.params

					err := s.AddContract(t.Context(), broken)
					require.Error(t, err)
					require.ErrorContains(t, err, c.expectedError)
				})
			}

			t.Run("duplicated contract", func(t *testing.T) {
				ctx := t.Context()
				require.NoError(t, s.AddContract(ctx, testContractA))

				err := s.AddContract(ctx, testContractA)
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

			empty, err := s.ListContracts(ctx, false)
			require.NoError(t, err)
			require.Empty(t, empty)

			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("offchain", func(t *testing.T) {
				got, err := s.ListContracts(ctx, false)
				require.NoError(t, err)
				require.Len(t, got, 2)
			})
			t.Run("onchain", func(t *testing.T) {
				got, err := s.ListContracts(ctx, true)
				require.NoError(t, err)
				require.Len(t, got, 1)
			})
		})
	})
}

func TestContractStoreGetLatestContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("offchain", func(t *testing.T) {
				got, err := s.GetLatestContract(ctx, types.ContractTypeDefault, false)
				require.NoError(t, err)
				require.NotNil(t, got)
				// Highest owner_key_index (m/0/1) -> testContractB.
				require.Equal(t, testContractB.Script, got.Script)
			})

			t.Run("onchain", func(t *testing.T) {
				got, err := s.GetLatestContract(ctx, types.ContractTypeDefault, true)
				require.NoError(t, err)
				require.NotNil(t, got)
				// Highest owner_key_index (m/0/2) -> testContractC.
				require.Equal(t, testContractC.Script, got.Script)
			})

			t.Run("empty", func(t *testing.T) {
				cases := []struct {
					contractType types.ContractType
				}{
					{""},
					{"unknown"},
				}

				for _, c := range cases {
					got, err := s.GetLatestContract(ctx, c.contractType, false)
					require.NoError(t, err)
					require.Nil(t, got)

					got, err = s.GetLatestContract(ctx, c.contractType, true)
					require.NoError(t, err)
					require.Nil(t, got)
				}
			})

			t.Run("filters by type", func(t *testing.T) {
				// Add a contract of a different type with a higher key index than
				// any existing one — must NOT be returned when filtering by the
				// default type.
				altType := types.ContractType("alt")
				other := cloneContract(testContractC)
				other.Script = "0000000000000000000000000000000000000000000000000000000000000099"
				other.Type = altType
				other.Params[types.ContractParamOwnerKeyId] = "m/0/9"
				other.Params[types.ContractParamIsOnchain] = "true"
				require.NoError(t, s.AddContract(ctx, other))

				got, err := s.GetLatestContract(ctx, types.ContractTypeDefault, true)
				require.NoError(t, err)
				require.NotNil(t, got)
				require.Equal(t, types.ContractTypeDefault, got.Type)
				require.Equal(t, testContractC.Script, got.Script)

				gotAlt, err := s.GetLatestContract(ctx, altType, true)
				require.NoError(t, err)
				require.NotNil(t, gotAlt)
				require.Equal(t, altType, gotAlt.Type)
				require.Equal(t, other.Script, gotAlt.Script)
			})
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

			t.Run("non empty", func(t *testing.T) {
				got, err := s.GetContractsByType(ctx, types.ContractTypeDefault)
				require.NoError(t, err)
				require.Len(t, got, 3)
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

func TestContractStoreGetOnchainContracts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractB, testContractC)

			t.Run("non empty", func(t *testing.T) {
				got, err := s.GetOnchainContracts(ctx)
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, testContractC.Script, got[0].Script)
			})

			t.Run("empty", func(t *testing.T) {
				err := s.Clean(ctx)
				require.NoError(t, err)

				seedContracts(t, s, testContractA, testContractB)

				got, err := s.GetOnchainContracts(ctx)
				require.NoError(t, err)
				require.Empty(t, got)
			})
		})
	})
}

func TestContractStoreGetContractsByKeyIDs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()
			seedContracts(t, s, testContractA, testContractC)

			t.Run("non empty", func(t *testing.T) {
				got, err := s.GetContractsByKeyIDs(ctx, []string{"m/0/0", "m/0/2"})
				require.NoError(t, err)
				require.Len(t, got, 2)
			})

			t.Run("empty", func(t *testing.T) {
				got, err := s.GetContractsByKeyIDs(ctx, []string{"m/0/1"})
				require.NoError(t, err)
				require.Empty(t, got)
			})
		})
	})

	t.Run("invalid", func(t *testing.T) {
		forEachContractBackend(t, func(t *testing.T, s types.ContractStore) {
			ctx := t.Context()

			t.Run("invalid key id", func(t *testing.T) {
				cases := []struct {
					keyIDs []string
				}{
					{[]string{"m/0/notanumber"}},
					{[]string{"m/0/0'"}},
					{[]string{""}},
					{[]string{"m/0/0", "m/0/notanumber"}},
				}

				for _, c := range cases {
					got, err := s.GetContractsByKeyIDs(ctx, c.keyIDs)
					require.Error(t, err)
					require.ErrorContains(t, err, "invalid key ID")
					require.Nil(t, got)
				}
			})
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
				got, err := s.ListContracts(ctx, false)
				require.NoError(t, err)
				require.NotEmpty(t, got)

				require.NoError(t, s.Clean(ctx))

				got, err = s.ListContracts(ctx, false)
				require.NoError(t, err)
				require.Empty(t, got)

				// No errors if cleaning an already cleaned store
				require.NoError(t, s.Clean(ctx))

				got, err = s.ListContracts(ctx, false)
				require.NoError(t, err)
				require.Empty(t, got)
			})

			t.Run("clean and reseed", func(t *testing.T) {
				seedContracts(t, s, testContractA, testContractB)
				require.NoError(t, s.Clean(ctx))

				// Re-seeding the same scripts must not collide with leftover state.
				seedContracts(t, s, testContractA, testContractC)

				offchain, err := s.ListContracts(ctx, false)
				require.NoError(t, err)
				require.Len(t, offchain, 1)
				require.Equal(t, testContractA.Script, offchain[0].Script)

				onchain, err := s.ListContracts(ctx, true)
				require.NoError(t, err)
				require.Len(t, onchain, 1)
				require.Equal(t, testContractC.Script, onchain[0].Script)
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
		{name: "kv", config: store.Config{AppDataStoreType: types.KVStore}},
		{name: "sql", config: store.Config{AppDataStoreType: types.SQLStore}},
	}

	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) {
			cfg := b.config
			if b.name == "sql" {
				cfg.BaseDir = t.TempDir()
			}

			svc, err := store.NewStore(cfg)
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
	for _, c := range contracts {
		require.NoError(t, s.AddContract(t.Context(), c))
	}
}

// cloneContract returns a deep-enough copy of c so callers can mutate
// Params/Metadata without polluting the shared fixtures.
func cloneContract(c types.Contract) types.Contract {
	out := c
	out.Params = make(map[string]string, len(c.Params))
	for k, v := range c.Params {
		out.Params[k] = v
	}
	if c.Metadata != nil {
		out.Metadata = make(map[string]string, len(c.Metadata))
		for k, v := range c.Metadata {
			out.Metadata[k] = v
		}
	}
	return out
}
