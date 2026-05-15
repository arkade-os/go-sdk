package contract_test

import (
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const (
	ownerKeyIdParam = "ownerKeyId"
)

func TestManagerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("offchain persisted", func(t *testing.T) {
			mgr, store := newTestManager(t)

			c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			require.NotNil(t, c)
			require.Equal(t, types.ContractTypeDefault, c.Type)
			require.Equal(t, types.ContractStateActive, c.State)
			require.NotEmpty(t, c.Script)
			require.NotEmpty(t, c.Address)
			// Auto-derived from a fresh wallet, the first key is m/0/0.
			require.Equal(t, "m/0/0", c.Params[ownerKeyIdParam])

			// Persisted exactly once.
			persisted, err := store.GetContractsByScripts(t.Context(), []string{c.Script})
			require.NoError(t, err)
			require.Len(t, persisted, 1)
			require.Equal(t, c.Script, persisted[0].Script)
		})

		t.Run("boarding persisted", func(t *testing.T) {
			mgr, store := newTestManager(t)

			c, err := mgr.NewContract(t.Context(), types.ContractTypeBoarding)
			require.NoError(t, err)
			require.Equal(t, types.ContractTypeBoarding, c.Type)
			require.Contains(t, c.Address, "bcrt1p")

			persisted, err := store.GetContractsByType(
				t.Context(), types.ContractTypeBoarding,
			)
			require.NoError(t, err)
			require.Len(t, persisted, 1)
			require.Equal(t, c.Script, persisted[0].Script)
		})

		t.Run("with label persisted", func(t *testing.T) {
			mgr, store := newTestManager(t)

			c, err := mgr.NewContract(
				t.Context(), types.ContractTypeDefault, contract.WithLabel("my-label"),
			)
			require.NoError(t, err)
			require.Equal(t, "my-label", c.Label)

			persisted, err := store.GetContractsByScripts(t.Context(), []string{c.Script})
			require.NoError(t, err)
			require.Len(t, persisted, 1)
			require.Equal(t, "my-label", persisted[0].Label)
		})

		t.Run("sequential offchain calls advance the key index", func(t *testing.T) {
			mgr, _ := newTestManager(t)

			c0, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			c1, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			c2, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)

			require.Equal(t, "m/0/0", c0.Params[ownerKeyIdParam])
			require.Equal(t, "m/0/1", c1.Params[ownerKeyIdParam])
			require.Equal(t, "m/0/2", c2.Params[ownerKeyIdParam])
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			contractType    types.ContractType
			opts            []contract.ContractOption
			wantErrContains string
		}{
			{
				name:            "missing contract type",
				contractType:    "",
				wantErrContains: "missing contract type",
			},
			{
				name:            "unsupported contract type",
				contractType:    types.ContractType("vhtlc"),
				wantErrContains: "unsupported contract type",
			},
			{
				name:         "conflicting label option",
				contractType: types.ContractTypeDefault,
				opts: []contract.ContractOption{
					contract.WithLabel("a"), contract.WithLabel("b"),
				},
				wantErrContains: "label option is already set",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				mgr, _ := newTestManager(t)
				_, err := mgr.NewContract(t.Context(), f.contractType, f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestManagerGetSupportedContractTypes(t *testing.T) {
	mgr, _ := newTestManager(t)
	supported := mgr.GetSupportedContractTypes(t.Context())
	require.ElementsMatch(
		t,
		[]types.ContractType{types.ContractTypeDefault, types.ContractTypeBoarding},
		supported,
	)
}

func TestManagerGetContracts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// Each subtest gets its own manager and seeds a known set of contracts
		// so the per-filter assertions are independent.
		t.Run("no filter returns all contracts of every type", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			off1 := newOffchainContract(t, mgr)
			off2 := newOffchainContract(t, mgr)
			board := newOnchainContract(t, mgr)

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, scriptsOf(off1, off2, board), scriptsOf(got...))
		})

		t.Run("by type returns boarding contracts only", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			_ = newOffchainContract(t, mgr)
			on := newOnchainContract(t, mgr)

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeBoarding),
			)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, on.Script, got[0].Script)
		})

		t.Run("by type", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			c := newOffchainContract(t, mgr)

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeDefault),
			)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, c.Script, got[0].Script)
		})

		t.Run("by scripts", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			a := newOffchainContract(t, mgr)
			b := newOffchainContract(t, mgr)
			_ = newOffchainContract(t, mgr)

			got, err := mgr.GetContracts(
				t.Context(), contract.WithScripts([]string{a.Script, b.Script}),
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{a.Script, b.Script}, scriptsOf(got...))
		})

		t.Run("by state", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			_ = newOffchainContract(t, mgr)
			_ = newOffchainContract(t, mgr)

			got, err := mgr.GetContracts(
				t.Context(), contract.WithState(types.ContractStateActive),
			)
			require.NoError(t, err)
			require.Len(t, got, 2)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			opts            []contract.FilterOption
			wantErrContains string
		}{
			{
				name: "type and state combined",
				opts: []contract.FilterOption{
					contract.WithType(types.ContractTypeDefault),
					contract.WithState(types.ContractStateActive),
				},
				wantErrContains: "a filter is already set",
			},
			{
				name: "scripts and type combined",
				opts: []contract.FilterOption{
					contract.WithScripts([]string{"abcd"}),
					contract.WithType(types.ContractTypeBoarding),
				},
				wantErrContains: "a filter is already set",
			},
			{
				name: "type filter set twice",
				opts: []contract.FilterOption{
					contract.WithType(types.ContractTypeDefault),
					contract.WithType(types.ContractTypeDefault),
				},
				wantErrContains: "contract type filter already set",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				mgr, _ := newTestManager(t)
				_, err := mgr.GetContracts(t.Context(), f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestManagerGetHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
		require.NoError(t, err)

		handler, err := mgr.GetHandler(t.Context(), *c)
		require.NoError(t, err)
		require.NotNil(t, handler)

		// Smoke-check that the returned handler operates on the contract
		// the manager just created — i.e. dispatch went to the right place.
		refs, err := handler.GetKeyRefs(*c)
		require.NoError(t, err)
		values := slices.Collect(maps.Values(refs))
		require.Contains(t, values, c.Params[ownerKeyIdParam])
	})

	t.Run("invalid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		handler, err := mgr.GetHandler(t.Context(), types.Contract{Type: "vhtlc"})
		require.ErrorContains(t, err, "unsupported contract type")
		require.Nil(t, handler)
	})
}

func TestManagerScanContracts(t *testing.T) {
	t.Run("offchain", func(t *testing.T) {
		t.Run("fresh wallet with no usage stores nothing", func(t *testing.T) {
			mgr, _ := newTestManager(t)

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.Empty(t, got)
		})

		t.Run("usage at the very first key persists m/0/0", func(t *testing.T) {
			// Pins the m/0/0-skip class of bug we hit during the manager
			// rewrite: the inner loop's first NextKeyId("") must produce
			// m/0/0 and that contract must end up in the store when the
			// indexer flags it.
			env, mgr, _ := newTestManagerWithEnv(t)
			env.markUsed(t, "m/0/0")

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"m/0/0"}, ownerKeyIds(got))
		})

		t.Run("sparse hit inside one batch persists up to last used", func(t *testing.T) {
			// gapLimit=5, only m/0/2 used. Verifies the persist loop pulls
			// in the intermediate unused indices (0, 1) so the next
			// NewContract starts from m/0/3 — i.e. lastUsedIdx anchors
			// persistence, not the individual usage hits.
			env, mgr, _ := newTestManagerWithEnv(t)
			env.markUsed(t, "m/0/2")

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(
				t, []string{"m/0/0", "m/0/1", "m/0/2"}, ownerKeyIds(got),
			)
		})

		t.Run("hits across multiple batches advance currentKeyId correctly", func(t *testing.T) {
			// gapLimit=3, hits at 2, 4, 7 — each batch keeps consecutiveUnused
			// below the threshold, so the scan walks past three batch
			// boundaries before giving up. A bug where currentKeyId fails to
			// chain across batches would either short-stop at batch 1 or
			// re-derive the same indices.
			env, mgr, _ := newTestManagerWithEnv(t)
			env.markUsed(t, "m/0/2", "m/0/4", "m/0/7")

			require.NoError(t, mgr.ScanContracts(t.Context(), 3))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []string{
				"m/0/0", "m/0/1", "m/0/2",
				"m/0/3", "m/0/4", "m/0/5",
				"m/0/6", "m/0/7",
			}, ownerKeyIds(got))
		})

		t.Run("re-scan with no new usage is a no-op", func(t *testing.T) {
			// init.go calls ScanContracts on every wallet unlock. With
			// contracts already in the store (created via the public
			// NewContract API), a second scan must not duplicate or drop
			// anything when the indexer reports nothing new.
			_, mgr, _ := newTestManagerWithEnv(t)
			for i := 0; i < 5; i++ {
				_, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
				require.NoError(t, err)
			}

			require.NoError(t, mgr.ScanContracts(t.Context(), 3))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []string{
				"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4",
			}, ownerKeyIds(got))
		})

		t.Run("re-scan picks up new usage past the latest stored", func(t *testing.T) {
			// Manager creates m/0/0..m/0/4 via NewContract; externally
			// m/0/7 has been used since. The scan must resume strictly
			// after m/0/4 (no re-deriving of existing rows) and persist
			// m/0/5..m/0/7.
			env, mgr, _ := newTestManagerWithEnv(t)
			for i := 0; i < 5; i++ {
				_, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
				require.NoError(t, err)
			}
			env.markUsed(t, "m/0/7")

			require.NoError(t, mgr.ScanContracts(t.Context(), 3))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, []string{
				"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4",
				"m/0/5", "m/0/6", "m/0/7",
			}, ownerKeyIds(got))
		})

		t.Run("indexer error is propagated", func(t *testing.T) {
			env, mgr, _ := newTestManagerWithEnv(t)
			env.indexer.err = errors.New("indexer down")

			err := mgr.ScanContracts(t.Context(), 5)
			require.ErrorContains(t, err, "indexer down")
		})
	})

	// Boarding mirrors offchain but exercises the explorer-backed scan path:
	// findUsedBoardingContracts queries the explorer per-address rather than
	// the indexer in batch. The same gap-limit / persist-up-to-lastUsedIdx /
	// chain-currentKeyId-across-batches invariants must hold; only the data
	// source differs.
	t.Run("boarding", func(t *testing.T) {
		t.Run("fresh wallet with no usage stores nothing", func(t *testing.T) {
			mgr, _ := newTestManager(t)

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.Empty(t, got)
		})

		t.Run("usage at the very first key persists m/0/0", func(t *testing.T) {
			env, mgr, _ := newTestManagerWithEnv(t)
			env.markBoardingUsed(t, "m/0/0")

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeBoarding),
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"m/0/0"}, ownerKeyIds(got))
		})

		t.Run("sparse hit inside one batch persists up to last used", func(t *testing.T) {
			env, mgr, _ := newTestManagerWithEnv(t)
			env.markBoardingUsed(t, "m/0/2")

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeBoarding),
			)
			require.NoError(t, err)
			require.ElementsMatch(
				t, []string{"m/0/0", "m/0/1", "m/0/2"}, ownerKeyIds(got),
			)
		})

		t.Run("hits across multiple batches advance currentKeyId correctly", func(t *testing.T) {
			env, mgr, _ := newTestManagerWithEnv(t)
			env.markBoardingUsed(t, "m/0/2", "m/0/4", "m/0/7")

			require.NoError(t, mgr.ScanContracts(t.Context(), 3))

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeBoarding),
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{
				"m/0/0", "m/0/1", "m/0/2",
				"m/0/3", "m/0/4", "m/0/5",
				"m/0/6", "m/0/7",
			}, ownerKeyIds(got))
		})

		t.Run("re-scan with no new usage is a no-op", func(t *testing.T) {
			_, mgr, _ := newTestManagerWithEnv(t)
			for i := 0; i < 5; i++ {
				_, err := mgr.NewContract(t.Context(), types.ContractTypeBoarding)
				require.NoError(t, err)
			}

			require.NoError(t, mgr.ScanContracts(t.Context(), 3))

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeBoarding),
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{
				"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4",
			}, ownerKeyIds(got))
		})

		t.Run("re-scan picks up new usage past the latest stored", func(t *testing.T) {
			env, mgr, _ := newTestManagerWithEnv(t)
			for i := 0; i < 5; i++ {
				_, err := mgr.NewContract(t.Context(), types.ContractTypeBoarding)
				require.NoError(t, err)
			}
			env.markBoardingUsed(t, "m/0/7")

			require.NoError(t, mgr.ScanContracts(t.Context(), 3))

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeBoarding),
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{
				"m/0/0", "m/0/1", "m/0/2", "m/0/3", "m/0/4",
				"m/0/5", "m/0/6", "m/0/7",
			}, ownerKeyIds(got))
		})

		t.Run("explorer error is propagated", func(t *testing.T) {
			env, mgr, _ := newTestManagerWithEnv(t)
			env.explorer.err = errors.New("explorer down")

			err := mgr.ScanContracts(t.Context(), 5)
			require.ErrorContains(t, err, "explorer down")
		})
	})
}

func TestManagerClean(t *testing.T) {
	t.Run("empty store", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		require.NoError(t, mgr.Clean(t.Context()))
	})

	t.Run("seeded store ends empty and is idempotent", func(t *testing.T) {
		mgr, store := newTestManager(t)
		_ = newOffchainContract(t, mgr)
		_ = newOnchainContract(t, mgr)

		require.NoError(t, mgr.Clean(t.Context()))

		all, err := store.ListContracts(t.Context())
		require.NoError(t, err)
		require.Empty(t, all)

		// Cleaning an already-clean store must be a no-op.
		require.NoError(t, mgr.Clean(t.Context()))
	})
}

func TestManagerRegisterHandler(t *testing.T) {
	const customType = types.ContractType("custom")

	t.Run("valid", func(t *testing.T) {
		t.Run("runtime registration is visible end-to-end", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			require.NoError(
				t, mgr.RegisterHandler(t.Context(), customType, newFakeHandler(customType)),
			)

			supported := mgr.GetSupportedContractTypes(t.Context())
			require.ElementsMatch(t, []types.ContractType{
				types.ContractTypeDefault, types.ContractTypeBoarding, customType,
			}, supported)

			c, err := mgr.NewContract(t.Context(), customType)
			require.NoError(t, err)
			require.Equal(t, customType, c.Type)
			require.NotEmpty(t, c.Script)

			h, err := mgr.GetHandler(t.Context(), *c)
			require.NoError(t, err)
			require.NotNil(t, h)
		})

		t.Run("Args.ExtraHandlers wires built-ins and custom together", func(t *testing.T) {
			_, mgr, _ := newTestManagerWithExtraHandlers(
				t, map[types.ContractType]handlers.Handler{
					customType: newFakeHandler(customType),
				},
			)

			supported := mgr.GetSupportedContractTypes(t.Context())
			require.ElementsMatch(t, []types.ContractType{
				types.ContractTypeDefault, types.ContractTypeBoarding, customType,
			}, supported)

			// Custom registered at construction.
			cc, err := mgr.NewContract(t.Context(), customType)
			require.NoError(t, err)
			require.Equal(t, customType, cc.Type)

			// Built-in still works alongside.
			cd, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			require.Equal(t, types.ContractTypeDefault, cd.Type)
		})

		t.Run("multiple custom handlers dispatch independently", func(t *testing.T) {
			// Two distinct custom types registered side by side. Each must
			// route to its own handler and produce its own script — a bug
			// where dispatch falls back to a single handler (or where
			// scripts collide across types) would surface here.
			const typA = types.ContractType("custom-a")
			const typB = types.ContractType("custom-b")

			_, mgr, _ := newTestManagerWithExtraHandlers(
				t, map[types.ContractType]handlers.Handler{
					typA: newFakeHandler(typA),
					typB: newFakeHandler(typB),
				},
			)

			supported := mgr.GetSupportedContractTypes(t.Context())
			require.ElementsMatch(t, []types.ContractType{
				types.ContractTypeDefault, types.ContractTypeBoarding, typA, typB,
			}, supported)

			ca, err := mgr.NewContract(t.Context(), typA)
			require.NoError(t, err)
			require.Equal(t, typA, ca.Type)

			cb, err := mgr.NewContract(t.Context(), typB)
			require.NoError(t, err)
			require.Equal(t, typB, cb.Type)

			// fakeScript mixes the type into the digest, so the same key
			// id under two types must produce different scripts.
			require.NotEqual(t, ca.Script, cb.Script)

			// GetContracts filtered by each type sees only its own rows.
			gotA, err := mgr.GetContracts(t.Context(), contract.WithType(typA))
			require.NoError(t, err)
			require.Len(t, gotA, 1)
			require.Equal(t, ca.Script, gotA[0].Script)

			gotB, err := mgr.GetContracts(t.Context(), contract.WithType(typB))
			require.NoError(t, err)
			require.Len(t, gotB, 1)
			require.Equal(t, cb.Script, gotB[0].Script)
		})

		t.Run("ScanContracts iterates the registered handler", func(t *testing.T) {
			// Custom-type contracts use the same indexer-backed findUsed path
			// as offchain default contracts. Staging a script in the indexer
			// at m/0/2 must persist m/0/0..m/0/2 just like the default case.
			env, mgr, _ := newTestManagerWithEnv(t)
			require.NoError(
				t, mgr.RegisterHandler(t.Context(), customType, newFakeHandler(customType)),
			)
			env.indexer.usedScripts = map[string]struct{}{
				fakeScript(customType, "m/0/2"): {},
			}

			require.NoError(t, mgr.ScanContracts(t.Context(), 5))

			got, err := mgr.GetContracts(t.Context(), contract.WithType(customType))
			require.NoError(t, err)
			require.ElementsMatch(
				t, []string{"m/0/0", "m/0/1", "m/0/2"}, ownerKeyIds(got),
			)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			typ             types.ContractType
			handler         handlers.Handler
			wantErrContains string
		}{
			{
				name:            "empty type",
				typ:             "",
				handler:         newFakeHandler(customType),
				wantErrContains: "missing contract type",
			},
			{
				name:            "nil handler",
				typ:             customType,
				handler:         nil,
				wantErrContains: "nil handler",
			},
			{
				name:            "reserved default",
				typ:             types.ContractTypeDefault,
				handler:         newFakeHandler(types.ContractTypeDefault),
				wantErrContains: "already registered",
			},
			{
				name:            "reserved boarding",
				typ:             types.ContractTypeBoarding,
				handler:         newFakeHandler(types.ContractTypeBoarding),
				wantErrContains: "already registered",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				mgr, _ := newTestManager(t)
				err := mgr.RegisterHandler(t.Context(), f.typ, f.handler)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}

		t.Run("duplicate runtime registration", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			require.NoError(
				t, mgr.RegisterHandler(t.Context(), customType, newFakeHandler(customType)),
			)
			err := mgr.RegisterHandler(t.Context(), customType, newFakeHandler(customType))
			require.ErrorContains(t, err, "already registered")
		})
	})
}

func TestManagerArgsExtraHandlers(t *testing.T) {
	const customType = types.ContractType("custom")

	fixtures := []struct {
		name            string
		extras          map[types.ContractType]handlers.Handler
		wantErrContains string
	}{
		{
			name: "empty type",
			extras: map[types.ContractType]handlers.Handler{
				"": newFakeHandler(customType),
			},
			wantErrContains: "missing contract type",
		},
		{
			name: "nil handler",
			extras: map[types.ContractType]handlers.Handler{
				customType: nil,
			},
			wantErrContains: "nil handler",
		},
		{
			name: "collides with default",
			extras: map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault: newFakeHandler(types.ContractTypeDefault),
			},
			wantErrContains: "already registered",
		},
		{
			name: "collides with boarding",
			extras: map[types.ContractType]handlers.Handler{
				types.ContractTypeBoarding: newFakeHandler(types.ContractTypeBoarding),
			},
			wantErrContains: "already registered",
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			env := newMockedEnv(t)
			svc, err := store.NewStore(store.Config{
				StoreType: types.SQLStore,
				Args:      t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(svc.Close)

			_, err = contract.NewManager(contract.Args{
				Store:         svc.ContractStore(),
				KeyProvider:   env.identity,
				Client:        env.transport,
				Indexer:       env.indexer,
				Explorer:      env.explorer,
				Network:       testNetwork,
				ExtraHandlers: f.extras,
			})
			require.ErrorContains(t, err, f.wantErrContains)
		})
	}
}

func newOffchainContract(t *testing.T, mgr contract.Manager) types.Contract {
	t.Helper()
	c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault)
	require.NoError(t, err)
	// Distinct creation timestamps so SortBy clauses in store queries are
	// deterministic across the test run.
	time.Sleep(time.Millisecond)
	return *c
}

func newOnchainContract(t *testing.T, mgr contract.Manager) types.Contract {
	t.Helper()
	c, err := mgr.NewContract(t.Context(), types.ContractTypeBoarding)
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	return *c
}

func scriptsOf(cs ...types.Contract) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Script
	}
	return out
}

func ownerKeyIds(cs []types.Contract) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Params[ownerKeyIdParam]
	}
	return out
}
