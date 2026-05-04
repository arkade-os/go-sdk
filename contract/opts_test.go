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
				name: "conflicts with isOnchain",
				opts: []FilterOption{
					WithIsOnchain(),
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
			{
				name: "conflicts with key IDs",
				opts: []FilterOption{
					WithKeyIDs([]string{"k"}),
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
				name: "conflicts with isOnchain",
				opts: []FilterOption{
					WithIsOnchain(),
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
			{
				name: "conflicts with key IDs",
				opts: []FilterOption{
					WithKeyIDs([]string{"k"}),
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
			{
				name: "conflicts with isOnchain",
				opts: []FilterOption{
					WithIsOnchain(),
					WithScripts([]string{"a"}),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with key IDs",
				opts: []FilterOption{
					WithKeyIDs([]string{"k"}),
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

func TestWithKeyIDFilter(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		keyIDs := []string{"k1", "k2"}
		f, err := applyFilterOptions(WithKeyIDs(keyIDs))
		require.NoError(t, err)
		require.Equal(t, keyIDs, f.keyIDs)

		// mutating the input must not mutate the stored slice
		keyIDs[0] = "mutated"
		require.NotEqual(t, "mutated", f.keyIDs[0])
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
					WithKeyIDs([]string{"k1"}),
					WithKeyIDs([]string{"k2"}),
				},
				expectError: "key ID filter already set",
			},
			{
				name: "conflicts with type",
				opts: []FilterOption{
					WithType(types.ContractTypeDefault),
					WithKeyIDs([]string{"k"}),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with state",
				opts: []FilterOption{
					WithState(types.ContractStateActive),
					WithKeyIDs([]string{"k"}),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with scripts",
				opts: []FilterOption{
					WithScripts([]string{"a"}),
					WithKeyIDs([]string{"k"}),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with isOnchain",
				opts: []FilterOption{
					WithIsOnchain(),
					WithKeyIDs([]string{"k"}),
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

func TestWithIsOnchainAsFilter(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		f, err := applyFilterOptions(WithIsOnchain())
		require.NoError(t, err)
		require.True(t, f.isOnchain)
	})

	t.Run("invalid", func(t *testing.T) {
		testCases := []struct {
			name        string
			opts        []FilterOption
			expectError string
		}{
			{
				name:        "already set",
				opts:        []FilterOption{WithIsOnchain(), WithIsOnchain()},
				expectError: "isOnchain filter is already set",
			},
			{
				name: "conflicts with type",
				opts: []FilterOption{
					WithType(types.ContractTypeDefault),
					WithIsOnchain(),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with state",
				opts: []FilterOption{
					WithState(types.ContractStateActive),
					WithIsOnchain(),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with scripts",
				opts: []FilterOption{
					WithScripts([]string{"a"}),
					WithIsOnchain(),
				},
				expectError: "a filter is already set",
			},
			{
				name: "conflicts with key IDs",
				opts: []FilterOption{
					WithKeyIDs([]string{"k"}),
					WithIsOnchain(),
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

func TestWithDryRun(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		o, err := applyContractOptions(WithDryRun())
		require.NoError(t, err)
		require.True(t, o.dryRun)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := applyContractOptions(WithDryRun(), WithDryRun())
		require.ErrorContains(t, err, "dry run option is already set")
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

func TestWithIsOnchainAsContractOption(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		o, err := applyContractOptions(WithIsOnchain())
		require.NoError(t, err)
		require.True(t, o.isOnchain)
	})

	t.Run("composes with other contract options", func(t *testing.T) {
		o, err := applyContractOptions(WithIsOnchain(), WithLabel("x"), WithDryRun())
		require.NoError(t, err)
		require.True(t, o.isOnchain)
		require.True(t, o.dryRun)
		require.Equal(t, "x", o.label)
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := applyContractOptions(WithIsOnchain(), WithIsOnchain())
		require.ErrorContains(t, err, "isOnchain option is already set")
	})
}

// TestWithIsOnchainSatisfiesBothFamilies guarantees the shared option type can
// be passed to both FilterOption and ContractOption variadic parameters at
// compile time.
func TestWithIsOnchainSatisfiesBothFamilies(t *testing.T) {
	opt := WithIsOnchain()
	var _ FilterOption = opt
	var _ ContractOption = opt

	f, err := applyFilterOptions(opt)
	require.NoError(t, err)
	require.True(t, f.isOnchain)

	o, err := applyContractOptions(WithIsOnchain())
	require.NoError(t, err)
	require.True(t, o.isOnchain)
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
