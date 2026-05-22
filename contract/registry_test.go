package contract_test

import (
	"testing"

	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry_RejectsBuiltinCollision(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		t.Run("empty contract type", func(t *testing.T) {
			reg, err := contract.NewRegistry(nil, map[types.ContractType]handlers.Handler{
				types.ContractType(""): newMockHandler(t, "x"),
			})
			require.ErrorContains(t, err, "missing contract type")
			require.Nil(t, reg)
		})

		t.Run("nil handler", func(t *testing.T) {
			reg, err := contract.NewRegistry(nil, map[types.ContractType]handlers.Handler{
				types.ContractType("vhtlc"): nil,
			})
			require.ErrorContains(t, err, "nil handler")
			require.Nil(t, reg)
		})
		t.Run("reserved contract type", func(t *testing.T) {
			builtins := map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault: newMockHandler(t, types.ContractTypeDefault),
			}
			customs := map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault: newMockHandler(t, types.ContractTypeDefault),
			}
			reg, err := contract.NewRegistry(builtins, customs)
			require.ErrorContains(t, err, "reserved by a built-in handler")
			require.Nil(t, reg)
		})
	})
}

func TestRegistry_SupportedTypes(t *testing.T) {
	builtins := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault:  newMockHandler(t, types.ContractTypeDefault),
		types.ContractTypeBoarding: newMockHandler(t, types.ContractTypeBoarding),
	}
	customs := map[types.ContractType]handlers.Handler{
		types.ContractType("vhtlc"):    newMockHandler(t, "vhtlc"),
		types.ContractType("delegate"): newMockHandler(t, "delegate"),
	}
	reg, err := contract.NewRegistry(builtins, customs)
	require.NoError(t, err)

	got := reg.SupportedTypes()
	want := []types.ContractType{
		types.ContractTypeBoarding,
		types.ContractTypeDefault,
		types.ContractType("delegate"),
		types.ContractType("vhtlc"),
	}
	require.Equal(t, want, got, "must be sorted alphabetically and include all types")
}

func TestRegistry_GetHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h := newMockHandler(t, "vhtlc")
		customs := map[types.ContractType]handlers.Handler{
			types.ContractType("vhtlc"): h,
		}
		reg, err := contract.NewRegistry(nil, customs)
		require.NoError(t, err)

		got, err := reg.GetHandler(types.ContractType("vhtlc"))
		require.NoError(t, err)
		require.Same(t, h, got)
	})

	t.Run("invalid", func(t *testing.T) {
		reg, err := contract.NewRegistry(nil, nil)
		require.NoError(t, err)

		_, err = reg.GetHandler(types.ContractType("vhtlc"))
		require.ErrorContains(t, err, `no handler registered for contract type "vhtlc"`)
	})
}
