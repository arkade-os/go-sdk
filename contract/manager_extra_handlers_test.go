package contract_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const customContractType types.ContractType = "custom"

// fakeHandler is a minimal handlers.Handler implementation used to verify
// that the contract manager honours user-supplied handler registrations.
type fakeHandler struct {
	signer  *btcec.PublicKey
	network arklib.Network
}

func (f *fakeHandler) NewContract(
	_ context.Context, keyRef identity.KeyRef,
) (*types.Contract, error) {
	pub := hex.EncodeToString(keyRef.PubKey.SerializeCompressed())
	return &types.Contract{
		Type:    customContractType,
		Script:  "custom-script:" + pub,
		Address: "custom-addr:" + pub,
		Params:  map[string]string{ownerKeyIdParam: keyRef.Id},
		State:   types.ContractStateActive,
	}, nil
}

func (f *fakeHandler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	keyId, ok := c.Params[ownerKeyIdParam]
	if !ok {
		return nil, fmt.Errorf("missing %s param", ownerKeyIdParam)
	}
	return map[string]string{c.Script: keyId}, nil
}

func (f *fakeHandler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	keyId, ok := c.Params[ownerKeyIdParam]
	if !ok {
		return nil, fmt.Errorf("missing %s param", ownerKeyIdParam)
	}
	return &identity.KeyRef{Id: keyId}, nil
}

func (f *fakeHandler) GetSignerKey(types.Contract) (*btcec.PublicKey, error) {
	return f.signer, nil
}

func (f *fakeHandler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return &arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1024}, nil
}

func (f *fakeHandler) GetTapscripts(types.Contract) ([]string, error) {
	return nil, nil
}

// newTestManagerWithExtras builds a manager whose handler map carries the
// given extras in addition to the built-in default/boarding handlers, sharing
// the rest of the mocked env with newTestManager.
func newTestManagerWithExtras(
	t *testing.T, extras map[types.ContractType]handlers.Handler,
) (*mockedEnv, contract.Manager, types.ContractStore) {
	t.Helper()

	env := newMockedEnv(t)
	svc, err := store.NewStore(store.Config{
		StoreType: types.SQLStore,
		Args:      t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	mgr, err := contract.NewManager(contract.Args{
		Store:         svc.ContractStore(),
		KeyProvider:   env.identity,
		Client:        env.transport,
		Indexer:       env.indexer,
		Explorer:      env.explorer,
		Network:       testNetwork,
		ExtraHandlers: extras,
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)

	return env, mgr, svc.ContractStore()
}

func TestManagerExtraHandlers(t *testing.T) {
	t.Run("custom type is supported", func(t *testing.T) {
		extras := map[types.ContractType]handlers.Handler{
			customContractType: &fakeHandler{signer: newTestPubKey(t), network: testNetwork},
		}
		_, mgr, _ := newTestManagerWithExtras(t, extras)

		supported := mgr.GetSupportedContractTypes(t.Context())
		require.Contains(t, supported, customContractType)
		require.Contains(t, supported, types.ContractTypeDefault)
		require.Contains(t, supported, types.ContractTypeBoarding)
	})

	t.Run("new contract uses registered handler", func(t *testing.T) {
		extras := map[types.ContractType]handlers.Handler{
			customContractType: &fakeHandler{signer: newTestPubKey(t), network: testNetwork},
		}
		_, mgr, store := newTestManagerWithExtras(t, extras)

		c, err := mgr.NewContract(t.Context(), customContractType)
		require.NoError(t, err)
		require.Equal(t, customContractType, c.Type)
		require.True(t, slices.IndexFunc([]byte(c.Script), func(b byte) bool {
			return b == ':'
		}) > 0, "fake handler produced an unexpected script %q", c.Script)

		persisted, err := store.GetContractsByScripts(t.Context(), []string{c.Script})
		require.NoError(t, err)
		require.Len(t, persisted, 1)
		require.Equal(t, c.Script, persisted[0].Script)
	})

	t.Run("get handler returns registered handler", func(t *testing.T) {
		fake := &fakeHandler{signer: newTestPubKey(t), network: testNetwork}
		extras := map[types.ContractType]handlers.Handler{customContractType: fake}
		_, mgr, _ := newTestManagerWithExtras(t, extras)

		c, err := mgr.NewContract(t.Context(), customContractType)
		require.NoError(t, err)
		got, err := mgr.GetHandler(t.Context(), *c)
		require.NoError(t, err)
		require.Same(t, fake, got)
	})

	t.Run("nil handler rejected", func(t *testing.T) {
		env := newMockedEnv(t)
		svc, err := store.NewStore(store.Config{
			StoreType: types.SQLStore,
			Args:      t.TempDir(),
		})
		require.NoError(t, err)
		t.Cleanup(svc.Close)

		_, err = contract.NewManager(contract.Args{
			Store:       svc.ContractStore(),
			KeyProvider: env.identity,
			Client:      env.transport,
			Indexer:     env.indexer,
			Explorer:    env.explorer,
			Network:     testNetwork,
			ExtraHandlers: map[types.ContractType]handlers.Handler{
				customContractType: nil,
			},
		})
		require.ErrorContains(t, err, "nil handler")
	})
}
