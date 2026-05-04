package contract_test

import (
	"maps"
	"slices"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestManagerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("offchain persisted", func(t *testing.T) {
			mgr, store := newTestManager(t)
			keyRef := newTestKeyRef(t)

			c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault, keyRef)
			require.NoError(t, err)
			require.NotNil(t, c)
			require.Equal(t, types.ContractTypeDefault, c.Type)
			require.Equal(t, types.ContractStateActive, c.State)
			require.NotEmpty(t, c.Script)
			require.NotEmpty(t, c.Address)
			require.Equal(t, "false", c.Params[managerIsOnchainParam])
			require.Equal(t, keyRef.Id, c.Params[managerOwnerKeyIDParam])

			// Persisted exactly once.
			persisted, err := store.GetContractsByScripts(t.Context(), []string{c.Script})
			require.NoError(t, err)
			require.Len(t, persisted, 1)
			require.Equal(t, c.Script, persisted[0].Script)
		})

		t.Run("onchain persisted", func(t *testing.T) {
			mgr, store := newTestManager(t)
			keyRef := newTestKeyRef(t)

			c, err := mgr.NewContract(
				t.Context(), types.ContractTypeDefault, keyRef, contract.WithIsOnchain(),
			)
			require.NoError(t, err)
			require.Equal(t, "true", c.Params[managerIsOnchainParam])
			require.Contains(t, c.Address, "bcrt1p")

			persisted, err := store.GetOnchainContracts(t.Context())
			require.NoError(t, err)
			require.Len(t, persisted, 1)
			require.Equal(t, c.Script, persisted[0].Script)
		})

		t.Run("with label persisted", func(t *testing.T) {
			mgr, store := newTestManager(t)
			keyRef := newTestKeyRef(t)

			c, err := mgr.NewContract(
				t.Context(), types.ContractTypeDefault, keyRef, contract.WithLabel("my-label"),
			)
			require.NoError(t, err)
			require.Equal(t, "my-label", c.Label)

			persisted, err := store.GetContractsByScripts(t.Context(), []string{c.Script})
			require.NoError(t, err)
			require.Len(t, persisted, 1)
			require.Equal(t, "my-label", persisted[0].Label)
		})

		t.Run("dry run skips persistence", func(t *testing.T) {
			mgr, store := newTestManager(t)
			keyRef := newTestKeyRef(t)

			c, err := mgr.NewContract(
				t.Context(), types.ContractTypeDefault, keyRef, contract.WithDryRun(),
			)
			require.NoError(t, err)
			require.NotNil(t, c)
			require.NotEmpty(t, c.Script)

			persisted, err := store.GetContractsByScripts(t.Context(), []string{c.Script})
			require.NoError(t, err)
			require.Empty(t, persisted)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		fixtures := []struct {
			name            string
			contractType    types.ContractType
			keyRef          func(t *testing.T) wallet.KeyRef
			opts            []contract.ContractOption
			wantErrContains string
		}{
			{
				name:            "missing contract type",
				contractType:    "",
				keyRef:          newTestKeyRef,
				wantErrContains: "missing contract type",
			},
			{
				name:         "missing key id",
				contractType: types.ContractTypeDefault,
				keyRef: func(t *testing.T) wallet.KeyRef {
					return wallet.KeyRef{PubKey: newTestPubKey(t)}
				},
				wantErrContains: "missing public key id",
			},
			{
				name:         "missing public key",
				contractType: types.ContractTypeDefault,
				keyRef: func(_ *testing.T) wallet.KeyRef {
					return wallet.KeyRef{Id: "m/0/0"}
				},
				wantErrContains: "missing public key",
			},
			{
				name:            "unsupported contract type",
				contractType:    types.ContractType("vhtlc"),
				keyRef:          newTestKeyRef,
				wantErrContains: "unsupported contract type",
			},
			{
				name:         "conflicting label option",
				contractType: types.ContractTypeDefault,
				keyRef:       newTestKeyRef,
				opts: []contract.ContractOption{
					contract.WithLabel("a"), contract.WithLabel("b"),
				},
				wantErrContains: "label option is already set",
			},
			{
				name:         "conflicting isOnchain option",
				contractType: types.ContractTypeDefault,
				keyRef:       newTestKeyRef,
				opts: []contract.ContractOption{
					contract.WithIsOnchain(), contract.WithIsOnchain(),
				},
				wantErrContains: "isOnchain option is already set",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				mgr, _ := newTestManager(t)
				_, err := mgr.NewContract(t.Context(), f.contractType, f.keyRef(t), f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestManagerGetSupportedContractTypes(t *testing.T) {
	mgr, _ := newTestManager(t)
	supported := mgr.GetSupportedContractTypes(t.Context())
	require.ElementsMatch(t, []types.ContractType{types.ContractTypeDefault}, supported)
}

func TestManagerGetContracts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// Each subtest gets its own manager and seeds a known set of contracts
		// so the per-filter assertions are independent.
		t.Run("no filter returns all offchain", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			off1 := newOffchainContract(t, mgr, "m/0/0")
			off2 := newOffchainContract(t, mgr, "m/0/1")
			// Boarding contracts are explicitly excluded from the no-filter listing.
			_ = newOnchainContract(t, mgr, "m/0/2")

			got, err := mgr.GetContracts(t.Context())
			require.NoError(t, err)
			require.ElementsMatch(t, scriptsOf(off1, off2), scriptsOf(got...))
		})

		t.Run("by isOnchain", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			_ = newOffchainContract(t, mgr, "m/0/0")
			on := newOnchainContract(t, mgr, "m/0/1")

			got, err := mgr.GetContracts(t.Context(), contract.WithIsOnchain())
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, on.Script, got[0].Script)
		})

		t.Run("by type", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			c := newOffchainContract(t, mgr, "m/0/0")

			got, err := mgr.GetContracts(
				t.Context(), contract.WithType(types.ContractTypeDefault),
			)
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, c.Script, got[0].Script)
		})

		t.Run("by scripts", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			a := newOffchainContract(t, mgr, "m/0/0")
			b := newOffchainContract(t, mgr, "m/0/1")
			_ = newOffchainContract(t, mgr, "m/0/2")

			got, err := mgr.GetContracts(
				t.Context(), contract.WithScripts([]string{a.Script, b.Script}),
			)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{a.Script, b.Script}, scriptsOf(got...))
		})

		t.Run("by key IDs", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			a := newOffchainContract(t, mgr, "m/0/0")
			_ = newOffchainContract(t, mgr, "m/0/1")

			got, err := mgr.GetContracts(t.Context(), contract.WithKeyIDs([]string{"m/0/0"}))
			require.NoError(t, err)
			require.Len(t, got, 1)
			require.Equal(t, a.Script, got[0].Script)
		})

		t.Run("by state", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			_ = newOffchainContract(t, mgr, "m/0/0")
			_ = newOffchainContract(t, mgr, "m/0/1")

			got, err := mgr.GetContracts(
				t.Context(), contract.WithState(types.ContractStateActive),
			)
			require.NoError(t, err)
			require.Len(t, got, 2)
		})

		t.Run("returns empty on no match", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			got, err := mgr.GetContracts(
				t.Context(), contract.WithKeyIDs([]string{"m/9/9"}),
			)
			require.NoError(t, err)
			require.Empty(t, got)
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
				name: "scripts and isOnchain combined",
				opts: []contract.FilterOption{
					contract.WithScripts([]string{"abcd"}),
					contract.WithIsOnchain(),
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

func TestManagerGetKeyIDUsedForLatestContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("offchain returns latest", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			_ = newOffchainContract(t, mgr, "m/0/0")
			_ = newOffchainContract(t, mgr, "m/0/2")
			_ = newOffchainContract(t, mgr, "m/0/1")

			id, err := mgr.GetKeyIDUsedForLatestContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			require.Equal(t, "m/0/2", id)
		})

		t.Run("onchain returns latest", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			// Mix of onchain and offchain — the WithIsOnchain flag must scope
			// the lookup to onchain contracts only.
			_ = newOffchainContract(t, mgr, "m/0/3")
			_ = newOnchainContract(t, mgr, "m/0/0")
			_ = newOnchainContract(t, mgr, "m/0/2")

			id, err := mgr.GetKeyIDUsedForLatestContract(
				t.Context(), types.ContractTypeDefault, contract.WithIsOnchain(),
			)
			require.NoError(t, err)
			require.Equal(t, "m/0/2", id)
		})

		t.Run("no contracts returns empty", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			id, err := mgr.GetKeyIDUsedForLatestContract(t.Context(), types.ContractTypeDefault)
			require.NoError(t, err)
			require.Empty(t, id)
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
				name:         "conflicting option",
				contractType: types.ContractTypeDefault,
				opts: []contract.ContractOption{
					contract.WithIsOnchain(), contract.WithIsOnchain(),
				},
				wantErrContains: "isOnchain option is already set",
			},
		}
		for _, f := range fixtures {
			t.Run(f.name, func(t *testing.T) {
				mgr, _ := newTestManager(t)
				_, err := mgr.GetKeyIDUsedForLatestContract(t.Context(), f.contractType, f.opts...)
				require.ErrorContains(t, err, f.wantErrContains)
			})
		}
	})
}

func TestManagerGetKeyRefs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		keyRef := newTestKeyRef(t)
		c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault, keyRef)
		require.NoError(t, err)

		refs, err := mgr.GetKeyRefs(t.Context(), *c)
		require.NoError(t, err)
		require.NotEmpty(t, refs)
		values := slices.Collect(maps.Values(refs))
		require.Contains(t, values, keyRef.Id)
	})

	t.Run("invalid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		refs, err := mgr.GetKeyRefs(t.Context(), types.Contract{Type: "vhtlc"})
		require.ErrorContains(t, err, "unsupported contract type")
		require.Nil(t, refs)
	})
}

func TestManagerGetSignerKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault, newTestKeyRef(t))
		require.NoError(t, err)

		signer, err := mgr.GetSignerKey(t.Context(), *c)
		require.NoError(t, err)
		require.NotNil(t, signer)
	})

	t.Run("invalid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		_, err := mgr.GetSignerKey(t.Context(), types.Contract{Type: "vhtlc"})
		require.ErrorContains(t, err, "unsupported contract type")
	})
}

func TestManagerGetExitDelay(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("offchain", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault, newTestKeyRef(t))
			require.NoError(t, err)

			delay, err := mgr.GetExitDelay(t.Context(), *c)
			require.NoError(t, err)
			require.NotNil(t, delay)
			require.Equal(t, arklib.LocktimeTypeBlock, delay.Type)
			require.Equal(t, uint32(testUnilateralExitDelay), delay.Value)
		})

		t.Run("onchain", func(t *testing.T) {
			mgr, _ := newTestManager(t)
			c, err := mgr.NewContract(
				t.Context(), types.ContractTypeDefault, newTestKeyRef(t),
				contract.WithIsOnchain(),
			)
			require.NoError(t, err)

			delay, err := mgr.GetExitDelay(t.Context(), *c)
			require.NoError(t, err)
			require.Equal(t, arklib.LocktimeTypeSecond, delay.Type)
			require.Equal(t, uint32(testBoardingExitDelay), delay.Value)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		_, err := mgr.GetExitDelay(t.Context(), types.Contract{Type: "vhtlc"})
		require.ErrorContains(t, err, "unsupported contract type")
	})
}

func TestManagerGetTapscripts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		c, err := mgr.NewContract(t.Context(), types.ContractTypeDefault, newTestKeyRef(t))
		require.NoError(t, err)

		scripts, err := mgr.GetTapscripts(t.Context(), *c)
		require.NoError(t, err)
		require.NotEmpty(t, scripts)
		for _, s := range scripts {
			require.NotEmpty(t, s)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		_, err := mgr.GetTapscripts(t.Context(), types.Contract{Type: "vhtlc"})
		require.ErrorContains(t, err, "unsupported contract type")
	})
}

func TestManagerClean(t *testing.T) {
	t.Run("empty store", func(t *testing.T) {
		mgr, _ := newTestManager(t)
		require.NoError(t, mgr.Clean(t.Context()))
	})

	t.Run("seeded store ends empty and is idempotent", func(t *testing.T) {
		mgr, store := newTestManager(t)
		_ = newOffchainContract(t, mgr, "m/0/0")
		_ = newOnchainContract(t, mgr, "m/0/1")

		require.NoError(t, mgr.Clean(t.Context()))

		offchain, err := store.ListContracts(t.Context(), false)
		require.NoError(t, err)
		require.Empty(t, offchain)
		onchain, err := store.ListContracts(t.Context(), true)
		require.NoError(t, err)
		require.Empty(t, onchain)

		// Cleaning an already-clean store must be a no-op.
		require.NoError(t, mgr.Clean(t.Context()))
	})
}

func newOffchainContract(t *testing.T, mgr contract.Manager, keyID string) types.Contract {
	t.Helper()
	c, err := mgr.NewContract(
		t.Context(), types.ContractTypeDefault, newTestKeyRefAt(t, keyID),
	)
	require.NoError(t, err)
	// Distinct creation timestamps so SortBy clauses in store queries are
	// deterministic across the test run.
	time.Sleep(time.Millisecond)
	return *c
}

func newOnchainContract(t *testing.T, mgr contract.Manager, keyID string) types.Contract {
	t.Helper()
	c, err := mgr.NewContract(
		t.Context(), types.ContractTypeDefault, newTestKeyRefAt(t, keyID),
		contract.WithIsOnchain(),
	)
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
