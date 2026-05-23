package contract_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	singlekeyidentity "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	singlekeystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

// A single-key identity reuses the same key (and therefore the same script) for
// every contract of a given type, so it backs exactly one address per type.
// NewContract treats a repeat request as idempotent reuse and returns the
// stored contract instead of erroring, unlike an HD identity where a duplicate
// script signals a real problem.
func TestManagerSingleKeyReuse(t *testing.T) {
	for _, contractType := range []types.ContractType{
		types.ContractTypeDefault, types.ContractTypeBoarding,
	} {
		t.Run(string(contractType), func(t *testing.T) {
			env := newMockedEnv(t)

			skStore, err := singlekeystore.NewStore()
			require.NoError(t, err)
			id, err := singlekeyidentity.NewIdentity(skStore)
			require.NoError(t, err)
			_, err = id.Create(t.Context(), chaincfg.RegressionNetParams, testPassword, "")
			require.NoError(t, err)
			_, err = id.Unlock(t.Context(), testPassword)
			require.NoError(t, err)

			svc, err := store.NewStore(store.Config{
				StoreType: types.SQLStore,
				Args:      t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(svc.Close)
			cstore := svc.ContractStore()

			mgr, err := contract.NewManager(contract.Args{
				Store:       cstore,
				KeyProvider: id,
				Client:      env.transport,
				Indexer:     env.indexer,
				Explorer:    env.explorer,
				Network:     testNetwork,
			})
			require.NoError(t, err)
			t.Cleanup(mgr.Close)

			first, err := mgr.NewContract(
				t.Context(), contractType, contract.WithLabel("first-label"),
			)
			require.NoError(t, err)
			require.NotEmpty(t, first.Script)
			require.Equal(t, "first-label", first.Label)

			// Second request of the same type returns the stored contract, no
			// error. The label passed here is ignored: reuse returns the existing
			// contract as-is rather than re-labeling it.
			second, err := mgr.NewContract(
				t.Context(), contractType, contract.WithLabel("second-label"),
			)
			require.NoError(t, err)
			require.Equal(t, first.Script, second.Script)
			require.Equal(t, first.Address, second.Address)
			require.Equal(t, "first-label", second.Label)

			// Only one contract is actually stored.
			persisted, err := cstore.GetContractsByType(t.Context(), contractType)
			require.NoError(t, err)
			require.Len(t, persisted, 1)
		})
	}
}

// stuckHDProvider is a deliberately broken HD key provider used to force the one
// situation a healthy HD identity never reaches on its own: deriving a duplicate
// script.
//
// A correct HD identity advances its derivation index on every call (m/0/0,
// m/0/1, m/0/2, ...), so each contract gets a distinct key, a distinct pubkey,
// and therefore a distinct script, it never collides. That happy path is covered
// by TestManagerNewContract's "advance the key index" case.
//
// To exercise NewContract's HD duplicate-handling branch we need a real
// collision, so this fake violates that invariant: it reports a non-single-key
// type, but its NextKeyId never advances and GetKey always returns the same
// pubkey. Two NewContract calls therefore derive the identical script.
type stuckHDProvider struct{ pub *btcec.PublicKey }

func (p stuckHDProvider) GetType() string {
	return "hd"
}

func (p stuckHDProvider) GetKeyIndex(context.Context, string) (uint32, error) {
	return 0, nil
}

func (p stuckHDProvider) NextKeyId(context.Context, string) (string, error) {
	return "m/0/0", nil
}

func (p stuckHDProvider) GetKey(_ context.Context, id string) (*identity.KeyRef, error) {
	return &identity.KeyRef{Id: id, PubKey: p.pub}, nil
}

// With the stuck provider above, the second NewContract derives a script that is
// already stored. Because the provider is not a single-key identity, the manager
// treats the collision as a real problem (the derivation index failed to
// advance) and returns an "already exists" error rather than idempotently
// reusing the contract, which is the single-key behavior asserted in
// TestManagerSingleKeyReuse.
func TestManagerHDDuplicateScriptErrors(t *testing.T) {
	for _, contractType := range []types.ContractType{
		types.ContractTypeDefault, types.ContractTypeBoarding,
	} {
		t.Run(string(contractType), func(t *testing.T) {
			env := newMockedEnv(t)

			svc, err := store.NewStore(store.Config{
				StoreType: types.SQLStore,
				Args:      t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(svc.Close)

			mgr, err := contract.NewManager(contract.Args{
				Store:       svc.ContractStore(),
				KeyProvider: stuckHDProvider{pub: newTestPubKey(t)},
				Client:      env.transport,
				Indexer:     env.indexer,
				Explorer:    env.explorer,
				Network:     testNetwork,
			})
			require.NoError(t, err)
			t.Cleanup(mgr.Close)

			// First derivation: nothing is stored yet, so this succeeds and is
			// persisted.
			_, err = mgr.NewContract(t.Context(), contractType)
			require.NoError(t, err)

			// The stuck index re-derives the same script; for an HD identity
			// that is an error, not a reuse.
			_, err = mgr.NewContract(t.Context(), contractType)
			require.ErrorContains(t, err, "already exists")
		})
	}
}

// errOnLookupStore wraps a contract store and forces GetContractsByScripts to
// fail while leaving the rest of the store working.
type errOnLookupStore struct {
	types.ContractStore
	err error
}

func (s errOnLookupStore) GetContractsByScripts(
	context.Context, []string,
) ([]types.Contract, error) {
	return nil, s.err
}

// NewContract must not swallow a failure from the existing-contract lookup: it
// returns the wrapped error instead of falling through to AddContract, where the
// real cause would otherwise be masked by a misleading UNIQUE constraint error.
func TestManagerNewContractLookupError(t *testing.T) {
	env := newMockedEnv(t)

	svc, err := store.NewStore(store.Config{
		StoreType: types.SQLStore,
		Args:      t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(svc.Close)

	lookupErr := errors.New("lookup err")
	mgr, err := contract.NewManager(contract.Args{
		Store:       errOnLookupStore{ContractStore: svc.ContractStore(), err: lookupErr},
		KeyProvider: env.identity,
		Client:      env.transport,
		Indexer:     env.indexer,
		Explorer:    env.explorer,
		Network:     testNetwork,
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)

	_, err = mgr.NewContract(t.Context(), types.ContractTypeDefault)
	require.ErrorContains(t, err, "failed to look up existing contract")
	require.ErrorContains(t, err, "lookup err")
}
