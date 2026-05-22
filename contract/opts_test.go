package contract

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestWithHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		opts, err := applyManagerOptions(
			WithHandler("vhtlc", newMockHandler("vhtlc")),
		)
		require.NoError(t, err)
		require.Len(t, opts.customHandlers, 1)
		require.NotNil(t, opts.customHandlers["vhtlc"])
	})

	t.Run("multiple distinct types", func(t *testing.T) {
		opts, err := applyManagerOptions(
			WithHandler("vhtlc", newMockHandler("vhtlc")),
			WithHandler("delegate", newMockHandler("delegate")),
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
		mgr, err := applyManagerOptions(WithHandler("vhtlc", nil))
		require.ErrorContains(t, err, `nil handler for contract type "vhtlc"`)
		require.Nil(t, mgr)
	})

	t.Run("typed-nil handler errors", func(t *testing.T) {
		var h *mockHandler
		mgr, err := applyManagerOptions(WithHandler("vhtlc", h))
		require.ErrorContains(t, err, `nil concrete handler for contract type "vhtlc"`)
		require.Nil(t, mgr)
	})

	t.Run("duplicate in same options errors", func(t *testing.T) {
		mgr, err := applyManagerOptions(
			WithHandler("vhtlc", newMockHandler("vhtlc")),
			WithHandler("vhtlc", newMockHandler("vhtlc")),
		)
		require.ErrorContains(t, err, `duplicate handler for contract type "vhtlc"`)
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

type mockHandler struct {
	ctType string
}

func newMockHandler(ctType string) handlers.Handler {
	return &mockHandler{ctType}
}

func (m *mockHandler) NewContract(_ context.Context, _ identity.KeyRef) (*types.Contract, error) {
	return &types.Contract{Type: types.ContractType(m.ctType)}, nil
}
func (m *mockHandler) GetKeyRefs(contract types.Contract) (map[string]string, error) {
	return nil, nil
}
func (m *mockHandler) GetKeyRef(contract types.Contract) (*identity.KeyRef, error) {
	return nil, nil
}
func (m *mockHandler) GetSignerKey(contract types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}
func (m *mockHandler) GetExitDelay(contract types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}
func (m *mockHandler) GetTapscripts(contract types.Contract) ([]string, error) {
	return nil, nil
}
