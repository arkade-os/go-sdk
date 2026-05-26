package contract_test

import (
	"testing"

	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("builtins only", func(t *testing.T) {
			hDefault := &mockedHandler{}
			mockHandler(hDefault, types.ContractTypeDefault)
			hBoarding := &mockedHandler{}
			mockHandler(hBoarding, types.ContractTypeBoarding)
			builtins := map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault:  hDefault,
				types.ContractTypeBoarding: hBoarding,
			}

			reg, err := contract.NewRegistry(builtins, nil)
			require.NoError(t, err)
			require.NotNil(t, reg)
			require.ElementsMatch(
				t,
				[]types.ContractType{types.ContractTypeBoarding, types.ContractTypeDefault},
				reg.SupportedTypes(),
			)

			got, err := reg.GetHandler(types.ContractTypeDefault)
			require.NoError(t, err)
			require.Same(t, hDefault, got)
		})

		t.Run("customs only", func(t *testing.T) {
			hCustom := &mockedHandler{}
			mockHandler(hCustom, "custom")
			customs := map[types.ContractType]handlers.Handler{
				types.ContractType("custom"): hCustom,
			}

			reg, err := contract.NewRegistry(nil, customs)
			require.NoError(t, err)
			require.NotNil(t, reg)
			require.Equal(
				t,
				[]types.ContractType{types.ContractType("custom")},
				reg.SupportedTypes(),
			)

			got, err := reg.GetHandler(types.ContractType("custom"))
			require.NoError(t, err)
			require.Same(t, hCustom, got)
		})

		t.Run("builtins and customs merged", func(t *testing.T) {
			hBuiltin := &mockedHandler{}
			mockHandler(hBuiltin, types.ContractTypeDefault)
			hCustom := &mockedHandler{}
			mockHandler(hCustom, "custom")
			builtins := map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault: hBuiltin,
			}
			customs := map[types.ContractType]handlers.Handler{
				types.ContractType("custom"): hCustom,
			}

			reg, err := contract.NewRegistry(builtins, customs)
			require.NoError(t, err)
			require.NotNil(t, reg)
			require.ElementsMatch(
				t,
				[]types.ContractType{types.ContractTypeDefault, types.ContractType("custom")},
				reg.SupportedTypes(),
			)

			gotBuiltin, err := reg.GetHandler(types.ContractTypeDefault)
			require.NoError(t, err)
			require.Same(t, hBuiltin, gotBuiltin)

			gotCustom, err := reg.GetHandler(types.ContractType("custom"))
			require.NoError(t, err)
			require.Same(t, hCustom, gotCustom)
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("empty contract type", func(t *testing.T) {
			h := &mockedHandler{}
			mockHandler(h, "x")
			reg, err := contract.NewRegistry(nil, map[types.ContractType]handlers.Handler{
				types.ContractType(""): h,
			})
			require.ErrorContains(t, err, "missing contract type")
			require.Nil(t, reg)
		})

		t.Run("nil handler", func(t *testing.T) {
			reg, err := contract.NewRegistry(nil, map[types.ContractType]handlers.Handler{
				types.ContractType("custom"): nil,
			})
			require.ErrorContains(t, err, "nil handler")
			require.Nil(t, reg)
		})
		t.Run("reserved contract type", func(t *testing.T) {
			hBuiltin := &mockedHandler{}
			mockHandler(hBuiltin, types.ContractTypeDefault)
			hCustom := &mockedHandler{}
			mockHandler(hCustom, types.ContractTypeDefault)
			builtins := map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault: hBuiltin,
			}
			customs := map[types.ContractType]handlers.Handler{
				types.ContractTypeDefault: hCustom,
			}
			reg, err := contract.NewRegistry(builtins, customs)
			require.ErrorContains(t, err, "reserved by a built-in handler")
			require.Nil(t, reg)
		})
	})
}

func TestRegistry_SupportedTypes(t *testing.T) {
	hDefault := &mockedHandler{}
	mockHandler(hDefault, types.ContractTypeDefault)
	hBoarding := &mockedHandler{}
	mockHandler(hBoarding, types.ContractTypeBoarding)
	hCustom1 := &mockedHandler{}
	mockHandler(hCustom1, "custom-1")
	hCustom2 := &mockedHandler{}
	mockHandler(hCustom2, "custom-2")
	builtins := map[types.ContractType]handlers.Handler{
		types.ContractTypeDefault:  hDefault,
		types.ContractTypeBoarding: hBoarding,
	}
	customs := map[types.ContractType]handlers.Handler{
		types.ContractType("custom-1"): hCustom1,
		types.ContractType("custom-2"): hCustom2,
	}
	reg, err := contract.NewRegistry(builtins, customs)
	require.NoError(t, err)

	got := reg.SupportedTypes()
	want := []types.ContractType{
		types.ContractTypeBoarding,
		types.ContractType("custom-1"),
		types.ContractType("custom-2"),
		types.ContractTypeDefault,
	}
	require.Equal(t, want, got, "must be sorted alphabetically and include all types")
}

func TestRegistry_GetHandler(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h := &mockedHandler{}
		mockHandler(h, "custom")
		customs := map[types.ContractType]handlers.Handler{
			types.ContractType("custom"): h,
		}
		reg, err := contract.NewRegistry(nil, customs)
		require.NoError(t, err)

		got, err := reg.GetHandler(types.ContractType("custom"))
		require.NoError(t, err)
		require.Same(t, h, got)
	})

	t.Run("invalid", func(t *testing.T) {
		reg, err := contract.NewRegistry(nil, nil)
		require.NoError(t, err)

		_, err = reg.GetHandler(types.ContractType("custom"))
		require.ErrorContains(t, err, `no handler registered for contract type "custom"`)
	})
}
