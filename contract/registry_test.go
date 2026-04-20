package contract_test

import (
	"context"
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/stretchr/testify/require"
)

// registryStub is a no-op Handler used only for Registry tests.
type registryStub struct{ name string }

func (s *registryStub) Type() string { return s.name }

func (s *registryStub) DeriveContract(
	_ context.Context, _ wallet.KeyRef, _ *clientTypes.Config, _ map[string]string,
) (*contract.Contract, error) {
	return nil, nil
}

func (s *registryStub) SelectPath(
	_ context.Context, _ *contract.Contract, _ contract.PathContext,
) (*contract.PathSelection, error) {
	return nil, nil
}

func (s *registryStub) GetSpendablePaths(
	_ context.Context, _ *contract.Contract, _ contract.PathContext,
) ([]contract.PathSelection, error) {
	return nil, nil
}

func (s *registryStub) SerializeParams(_ any) (map[string]string, error) { return nil, nil }

func (s *registryStub) DeserializeParams(_ map[string]string) (any, error) { return nil, nil }

func TestRegistry(t *testing.T) {
	t.Parallel()

	t.Run("Get returns false for unknown type", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		_, ok := reg.Get("unknown")
		require.False(t, ok)
	})

	t.Run("Register and Get round-trip", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		h := &registryStub{name: "foo"}
		require.NoError(t, reg.Register(h))
		got, ok := reg.Get("foo")
		require.True(t, ok)
		require.Equal(t, "foo", got.Type())
	})

	t.Run("Register duplicate returns error", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		require.NoError(t, reg.Register(&registryStub{name: "dup"}))
		err := reg.Register(&registryStub{name: "dup"})
		require.Error(t, err)
		require.ErrorContains(t, err, "already registered")
	})

	t.Run("MustGet panics for unknown type", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		require.Panics(t, func() { reg.MustGet("nope") })
	})

	t.Run("MustGet returns handler for known type", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		require.NoError(t, reg.Register(&registryStub{name: "bar"}))
		got := reg.MustGet("bar")
		require.Equal(t, "bar", got.Type())
	})

	t.Run("multiple handlers coexist", func(t *testing.T) {
		t.Parallel()
		reg := contract.NewRegistry()
		require.NoError(t, reg.Register(&registryStub{name: "a"}))
		require.NoError(t, reg.Register(&registryStub{name: "b"}))
		_, okA := reg.Get("a")
		_, okB := reg.Get("b")
		require.True(t, okA)
		require.True(t, okB)
	})
}
