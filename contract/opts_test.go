package contract

import (
	"testing"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

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

func applyFilterOptions(opts ...FilterOption) (*filter, error) {
	f := newDefaultFilter()
	for _, opt := range opts {
		if err := opt.applyFilter(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func applyContractOptions(opts ...ContractOption) (*contractOption, error) {
	o := newDefaultContractOption()
	for _, opt := range opts {
		if err := opt.applyContract(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}
