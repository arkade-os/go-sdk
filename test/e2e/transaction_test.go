package e2e

import (
	"context"
	"fmt"
	"sync"
	"testing"

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

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var bobVtxo1 types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobVtxo1 = event.Vtxos[0]
				break
			}
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 1000}})
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(1000), bobVtxo1.Amount)

		bobVtxos, _, err := bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 1)

		wg.Add(1)
		var bobVtxo2 types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobVtxo2 = event.Vtxos[0]
				break
			}
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(10000), bobVtxo2.Amount)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 2)

		wg.Add(1)
		var bobVtxo3 types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobVtxo3 = event.Vtxos[0]
				break
			}
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(10000), bobVtxo3.Amount)

		bobVtxos, _, err = bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.Len(t, bobVtxos, 3)

		wg.Add(1)
		var bobVtxo4 types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobVtxo4 = event.Vtxos[0]
				break
			}
		}()
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{To: bobAddress, Amount: 10000}})
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(10000), bobVtxo4.Amount)

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
		wg := &sync.WaitGroup{}

		for range numInputs {
			wg.Add(1)
			var bobVtxo types.Vtxo
			go func() {
				defer wg.Done()
				for event := range bobVtxoCh {
					if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
						continue
					}
					bobVtxo = event.Vtxos[0]
					break
				}
			}()

			_, err := alice.SendOffChain(ctx, false, []types.Receiver{{
				To:     bobOffchainAddr,
				Amount: amount,
			}})
			require.NoError(t, err)
			wg.Wait()
			require.Equal(t, uint64(amount), bobVtxo.Amount)
		}

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)

		wg.Add(1)
		var aliceVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range aliceVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				aliceVtxo = event.Vtxos[0]
				break
			}
		}()

		_, err = bob.SendOffChain(ctx, false, []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: numInputs * amount,
		}})
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(numInputs*amount), aliceVtxo.Amount)
	})

	// In this test Alice sends to Bob a sub-dust VTXO. Bob can't spend or settle his VTXO.
	// He must receive other offchain funds to be able to settle them into a non-sub-dust that
	// can be spent
	t.Run("sub dust", func(t *testing.T) {
		t.Skip("revert once arkd fix is released: https://github.com/arkade-os/arkd/pull/795")
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

		wg := &sync.WaitGroup{}
		wg.Add(1)

		var bobVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobVtxo = event.Vtxos[0]
				break
			}
		}()

		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 100, // Sub-dust amount
		}})
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(100), bobVtxo.Amount)

		_, err = bob.SendOffChain(ctx, false, []types.Receiver{{
			To:     aliceOffchainAddr,
			Amount: 100,
		}})
		require.Error(t, err)

		// bob can't settle VTXO because he didn't collect enough funds to settle it
		_, err = bob.Settle(ctx)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to register intent")

		wg.Add(1)
		var bobSecondVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobSecondVtxo = event.Vtxos[0]
				break
			}
		}()

		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 1000, // Another sub-dust amount
		}})
		require.NoError(t, err)

		wg.Wait()

		require.Equal(t, uint64(1000), bobSecondVtxo.Amount)

		// bob can now settle VTXO because he collected enough funds to settle it
		wg.Add(1)
		var bobSettledVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobSecondVtxo = event.Vtxos[0]
				break
			}
		}()

		_, err = bob.Settle(ctx)
		require.NoError(t, err)

		wg.Wait()
		require.Equal(t, uint64(1000+100), bobSettledVtxo.Amount)
	})
}
