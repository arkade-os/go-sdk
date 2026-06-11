package contract_test

import (
	"testing"

	singlekeyidentity "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey"
	singlekeystore "github.com/arkade-os/arkd/pkg/client-lib/identity/singlekey/store/inmemory"
	"github.com/arkade-os/go-sdk/contract"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

// TestScanSingleKeyDeprecatedSigner verifies a single-key wallet discovers a
// pre-rotation (deprecated-signer) offchain vtxo even though a current-signer
// contract of the same type may already exist (EC-9).
func TestScanSingleKeyDeprecatedSigner(t *testing.T) {
	env := newMockedEnv(t)
	deprecated := env.addDeprecatedSigner(t)

	skStore, err := singlekeystore.NewStore()
	require.NoError(t, err)
	id, err := singlekeyidentity.NewIdentity(skStore)
	require.NoError(t, err)
	_, err = id.Create(t.Context(), chaincfg.RegressionNetParams, testPassword, "")
	require.NoError(t, err)
	_, err = id.Unlock(t.Context(), testPassword)
	require.NoError(t, err)

	svc, err := store.NewStore(store.Config{StoreType: types.SQLStore, Args: t.TempDir()})
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

	// Derive the single-key offchain contract for the DEPRECATED signer and
	// mark it used in the indexer. The single-key key id is the one produced by
	// NextKeyId(""); resolve it through the identity.
	keyId, err := id.NextKeyId(t.Context(), "")
	require.NoError(t, err)
	keyRef, err := id.GetKey(t.Context(), keyId)
	require.NoError(t, err)
	offchain := defaultHandler.NewHandler(env.transport, testNetwork, false)
	depContracts, err := offchain.CandidateContracts(
		t.Context(), *keyRef, []*btcec.PublicKey{deprecated},
	)
	require.NoError(t, err)
	require.Len(t, depContracts, 1)
	env.indexer.usedScripts = map[string]struct{}{depContracts[0].Script: {}}

	require.NoError(t, mgr.ScanContracts(t.Context(), 5))

	persisted, err := cstore.GetContractsByType(t.Context(), types.ContractTypeDefault)
	require.NoError(t, err)
	require.Len(t, persisted, 1)
	require.Equal(t, depContracts[0].Script, persisted[0].Script)
	require.Equal(t, xOnlyHex(t, deprecated), persisted[0].Params[signerKeyParam])
}

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
