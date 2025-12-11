package e2e

import (
	"context"
	"fmt"
	"testing"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestOffchainTx(t *testing.T) {
	t.Parallel()

	// In this test Alice sends several times to Bob to create a chain of offchain txs
	t.Run("chain of txs", func(t *testing.T) {
		ctx := context.Background()
		alice := setupClient(t)
		bob := setupClient(t)

		faucetOffchain(t, alice, 0.001)

		_, bobAddress, _, err := bob.Receive(ctx)
		require.NoError(t, err)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)

		txid, err := alice.SendOffChain(ctx, []types.Receiver{{
			To:     bobAddress,
			Amount: 1000,
		}})
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent := <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobVtxo1 := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 1000, int(bobVtxo1.Amount))
		require.Equal(t, txid, bobVtxo1.Txid)

		bobVtxos, _, err := bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 1)

		txid, err = alice.SendOffChain(ctx, []types.Receiver{{
			To:     bobAddress,
			Amount: 10000,
		}})
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobVtxo2 := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 10000, int(bobVtxo2.Amount))
		require.Equal(t, txid, bobVtxo2.Txid)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 2)

		txid, err = alice.SendOffChain(ctx, []types.Receiver{{
			To:     bobAddress,
			Amount: 10000,
		}})
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobVtxo3 := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 10000, int(bobVtxo3.Amount))
		require.Equal(t, txid, bobVtxo3.Txid)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 3)

		txid, err = alice.SendOffChain(ctx, []types.Receiver{{
			To:     bobAddress,
			Amount: 10000,
		}}, arksdk.WithoutExpirySorting())
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobVtxo4 := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 10000, int(bobVtxo4.Amount))
		require.Equal(t, txid, bobVtxo4.Txid)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 4)

		// bobVtxos should be unique
		uniqueVtxos := make(map[string]struct{})
		for _, v := range bobVtxos {
			uniqueVtxos[fmt.Sprintf("%s:%d", v.Txid, v.VOut)] = struct{}{}
		}
		require.Len(t, uniqueVtxos, len(bobVtxos))
	})

	// In this test Alice sends many times to Bob who then sends all back to Alice in a single
	// offchain tx composed by many checkpoint txs, as the number of the inputs of the ark tx
	t.Run("send with multiple inputs", func(t *testing.T) {
		ctx := t.Context()
		const numInputs = 5
		const amount = 2100

		alice := setupClient(t)
		bob := setupClient(t)

		_, aliceOffchainAddr, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceOffchainAddr)

		_, bobOffchainAddr, _, err := bob.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		faucetOffchain(t, alice, 0.001)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)

		for range numInputs {
			txid, err := alice.SendOffChain(ctx, []types.Receiver{{
				To:     bobOffchainAddr,
				Amount: amount,
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent := <-bobVtxoCh
			require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			bobVtxo := bobVtxoEvent.Vtxos[0]
			require.Equal(t, amount, int(bobVtxo.Amount))
			require.Equal(t, txid, bobVtxo.Txid)
		}

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)

		txid, err := bob.SendOffChain(ctx, []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: numInputs * amount,
		}})
		require.NoError(t, err)

		// next event received by alice vtxo channel should be the added event
		// related to the offchain send
		aliceVtxoEvent := <-aliceVtxoCh
		require.Equal(t, aliceVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, aliceVtxoEvent.Vtxos, 1)
		aliceVtxo := aliceVtxoEvent.Vtxos[0]
		require.Equal(t, numInputs*amount, int(aliceVtxo.Amount))
		require.Equal(t, txid, aliceVtxo.Txid)
	})

	// In this test Alice sends to Bob a sub-dust VTXO. Bob can't spend or settle his VTXO.
	// He must receive other offchain funds to be able to settle them into a non-sub-dust that
	// can be spent
	t.Run("sub dust", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)
		bob := setupClient(t)

		faucetOffchain(t, alice, 0.00021)

		_, aliceOffchainAddr, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceOffchainAddr)

		_, bobOffchainAddr, _, err := bob.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)

		txid, err := alice.SendOffChain(ctx, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 100, // Sub-dust amount
		}})
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent := <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobVtxo := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 100, int(bobVtxo.Amount))
		require.Equal(t, txid, bobVtxo.Txid)

		// bob can't spend subdust VTXO via ark tx
		_, err = bob.SendOffChain(ctx, []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: 100,
		}})
		require.Error(t, err)

		// bob can't settle VTXO because he didn't collect enough funds to settle it
		_, err = bob.Settle(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to register intent")

		txid, err = alice.SendOffChain(ctx, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 1000, // Another sub-dust amount
		}})
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobSecondVtxo := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 1000, int(bobSecondVtxo.Amount))
		require.Equal(t, txid, bobSecondVtxo.Txid)

		// bob can now settle VTXO because he collected enough funds to settle it
		_, err = bob.Settle(ctx)
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the settlement
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		bobSettledVtxo := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 1000+100, int(bobSettledVtxo.Amount))
	})
}
