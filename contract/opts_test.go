package contract

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWithHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		opts, err := applyManagerOptions(
			WithHandler("custom", newMockHandler("custom")),
		)
		require.NoError(t, err)
		require.Len(t, opts.customHandlers, 1)
		require.NotNil(t, opts.customHandlers["custom"])
	})

	t.Run("multiple distinct types", func(t *testing.T) {
		opts, err := applyManagerOptions(
			WithHandler("custom-1", newMockHandler("custom-1")),
			WithHandler("custom-2", newMockHandler("custom-2")),
		)
		require.NoError(t, err)
		require.Len(t, opts.customHandlers, 2)
	})

	t.Run("empty type errors", func(t *testing.T) {
		mgr, err := applyManagerOptions(
			WithHandler("", newMockHandler("x")),
		)
		require.ErrorContains(t, err, "missing contract type")
		require.Nil(t, mgr)
	})

	t.Run("nil handler errors", func(t *testing.T) {
		mgr, err := applyManagerOptions(WithHandler("custom", nil))
		require.ErrorContains(t, err, `nil handler for contract type "custom"`)
		require.Nil(t, mgr)
	})

	t.Run("typed-nil handler errors", func(t *testing.T) {
		var h *mockHandler
		mgr, err := applyManagerOptions(WithHandler("custom", h))
		require.ErrorContains(t, err, `nil concrete handler for contract type "custom"`)
		require.Nil(t, mgr)
	})

	t.Run("duplicate in same options errors", func(t *testing.T) {
		mgr, err := applyManagerOptions(
			WithHandler("custom", newMockHandler("custom")),
			WithHandler("custom", newMockHandler("custom")),
		)
		require.ErrorContains(t, err, `duplicate handler for contract type "custom"`)
		require.Nil(t, mgr)
	})
}

func TestWithTypeFilter(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f, err := applyFilterOptions(WithType(types.ContractTypeDefault))
		require.NoError(t, err)
		require.Equal(t, types.ContractTypeDefault, f.contractType)
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []FilterOption
			expectError string
		}{
			{
				name: "already set",
				opts: []FilterOption{
					WithType(types.ContractTypeDefault),
					WithType(types.ContractTypeDefault),
				},
				expectError: "contract type filter already set",
			},
			{
				name: "conflicts with state",
				opts: []FilterOption{
					WithState(types.ContractStateActive),
					WithType(types.ContractTypeDefault),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with scripts",
				opts: []FilterOption{
					WithScripts([]string{"abcd"}),
					WithType(types.ContractTypeDefault),
				},
				expectError: "a filter is already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := applyFilterOptions(tc.opts...)
				require.ErrorContains(t, err, tc.expectError)
			})
		}
	})
}

func TestWithStateFilter(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f, err := applyFilterOptions(WithState(types.ContractStateActive))
		require.NoError(t, err)
		require.Equal(t, types.ContractStateActive, f.state)
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []FilterOption
			expectError string
		}{
			{
				name: "already set",
				opts: []FilterOption{
					WithState(types.ContractStateActive),
					WithState(types.ContractStateActive),
				},
				expectError: "contract state filter already set",
			},
			{
				name: "conflicts with type",
				opts: []FilterOption{
					WithType(types.ContractTypeDefault),
					WithState(types.ContractStateActive),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with scripts",
				opts: []FilterOption{
					WithScripts([]string{"abcd"}),
					WithState(types.ContractStateActive),
				},
				expectError: "a filter is already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := applyFilterOptions(tc.opts...)
				require.ErrorContains(t, err, tc.expectError)
			})
		}
	})
}

func TestWithScriptsFilter(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		scripts := []string{"abcd", "ef01"}
		f, err := applyFilterOptions(WithScripts(scripts))
		require.NoError(t, err)
		require.Equal(t, scripts, f.scripts)

		// mutating the input must not mutate the stored slice
		scripts[0] = "mutated"
		require.NotEqual(t, "mutated", f.scripts[0])
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []FilterOption
			expectError string
		}{
			{
				name: "missing scripts",
				opts: []FilterOption{
					WithScripts([]string{}),
				},
				expectError: "missing scripts",
			},
			{
				name: "already set",
				opts: []FilterOption{
					WithScripts([]string{"a"}),
					WithScripts([]string{"b"}),
				},
				expectError: "contract scripts filter already set",
			},
			{
				name: "conflicts with type",
				opts: []FilterOption{
					WithType(types.ContractTypeDefault),
					WithScripts([]string{"a"}),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with state",
				opts: []FilterOption{
					WithState(types.ContractStateActive),
					WithScripts([]string{"a"}),
				},
				expectError: "a filter is already set",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := applyFilterOptions(tc.opts...)
				require.ErrorContains(t, err, tc.expectError)
			})
		}
	})
}

func TestWithLabel(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		o, err := applyContractOptions(WithLabel("my-label"))
		require.NoError(t, err)
		require.Equal(t, "my-label", o.label)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := applyContractOptions(WithLabel("a"), WithLabel("b"))
		require.ErrorContains(t, err, "label option is already set")
	})
}

func TestWithKeyRef(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	keyRef := identity.KeyRef{Id: "m/0/7", PubKey: key.PubKey()}

	t.Run("valid", func(t *testing.T) {
		o, err := applyContractOptions(WithKeyRef(keyRef))
		require.NoError(t, err)
		require.NotNil(t, o.keyRef)
		require.Equal(t, keyRef.Id, o.keyRef.Id)
		require.Equal(t, keyRef.PubKey.SerializeCompressed(), o.keyRef.PubKey.SerializeCompressed())
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := applyContractOptions(WithKeyRef(identity.KeyRef{}))
		require.ErrorContains(t, err, "key ref ID is required")

		_, err = applyContractOptions(WithKeyRef(identity.KeyRef{Id: "m/0/0"}))
		require.ErrorContains(t, err, "key ref pubkey is required")

		_, err = applyContractOptions(WithKeyRef(keyRef), WithKeyRef(keyRef))
		require.ErrorContains(t, err, "key ref option is already set")
	})
}

func TestWithServerParams(t *testing.T) {
	info := &client.Info{SignerPubKey: "abcd"}

	t.Run("valid", func(t *testing.T) {
		o, err := applyContractOptions(WithServerParams(info))
		require.NoError(t, err)
		require.Equal(t, info, o.serverParams)
	})

	t.Run("nil errors", func(t *testing.T) {
		_, err := applyContractOptions(WithServerParams(nil))
		require.ErrorContains(t, err, "server params cannot be nil")
	})

	t.Run("duplicate errors", func(t *testing.T) {
		_, err := applyContractOptions(WithServerParams(info), WithServerParams(info))
		require.ErrorContains(t, err, "server params option is already set")
	})
}

func applyManagerOptions(opts ...ManagerOption) (*managerOptions, error) {
	o := newDefaultManagerOption()
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func applyFilterOptions(opts ...FilterOption) (*filterOptions, error) {
	f := newDefaultFilter()
	for _, opt := range opts {
		if err := opt.applyFilter(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func applyContractOptions(opts ...ContractOption) (*contractOptions, error) {
	o := newDefaultContractOption()
	for _, opt := range opts {
		if err := opt.applyContract(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// mockHandler is a minimal handlers.Handler used by the option tests.
// NewContract returns a fully populated contract whose params reference the
// derived key id so getKeyRef can resolve it back; the other getters return
// stable mocked data so handlerSanityCheck (run by WithHandler) sees a
// consistent handler.
type mockHandler struct {
	ctType string
}

func newMockHandler(ctType string) handlers.Handler {
	return &mockHandler{ctType}
}

const mockOwnerKeyIdParam = "ownerKeyId"

func (m *mockHandler) Derivable() bool { return true }
func (m *mockHandler) NewContract(
	_ context.Context, k identity.KeyRef, _ any,
) (*types.Contract, error) {
	return &types.Contract{
		Type:    types.ContractType(m.ctType),
		State:   types.ContractStateActive,
		Script:  m.ctType + "-test-script",
		Address: m.ctType + "-test-address",
		Params:  map[string]string{mockOwnerKeyIdParam: k.Id},
	}, nil
}
func (m *mockHandler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	return map[string]string{mockOwnerKeyIdParam: c.Params[mockOwnerKeyIdParam]}, nil
}
func (m *mockHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	return &identity.KeyRef{Id: c.Params[mockOwnerKeyIdParam]}, nil
}
func (m *mockHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (m *mockHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return &arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 144}, nil
}
func (m *mockHandler) GetTapscripts(types.Contract) ([]string, error) {
	return []string{m.ctType + "-tapscript"}, nil
}
