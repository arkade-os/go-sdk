package e2e

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	types "github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestOffchainTx(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient
		setupClientWithWallet := backend.setupClientWithWallet

		// In this test Alice sends several times to Bob to create a chain of offchain txs
		t.Run("chain of txs", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			faucetOffchain(t, alice, 0.001)

			bobAddress, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)

			txid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobAddress,
				Amount: 1000,
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent := <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			bobVtxo1 := bobVtxoEvent.Vtxos[0]
			require.Equal(t, 1000, int(bobVtxo1.Amount))
			require.Equal(t, txid, bobVtxo1.Txid)

			bobVtxos, _, err := bob.ListVtxos(ctx)
			require.NoError(t, err)
			require.Len(t, bobVtxos, 1)

			txid, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobAddress,
				Amount: 10000,
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent = <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			bobVtxo2 := bobVtxoEvent.Vtxos[0]
			require.Equal(t, 10000, int(bobVtxo2.Amount))
			require.Equal(t, txid, bobVtxo2.Txid)

			bobVtxos, _, err = bob.ListVtxos(ctx)
			require.NoError(t, err)
			require.Len(t, bobVtxos, 2)

			txid, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobAddress,
				Amount: 10000,
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent = <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			bobVtxo3 := bobVtxoEvent.Vtxos[0]
			require.Equal(t, 10000, int(bobVtxo3.Amount))
			require.Equal(t, txid, bobVtxo3.Txid)

			bobVtxos, _, err = bob.ListVtxos(ctx)
			require.NoError(t, err)
			require.Len(t, bobVtxos, 3)

			txid, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobAddress,
				Amount: 10000,
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent = <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
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

			aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceOffchainAddr)

			bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			faucetOffchain(t, alice, 0.001)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)

			for range numInputs {
				txid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{{
					To:     bobOffchainAddr,
					Amount: amount,
				}})
				require.NoError(t, err)

				// next event received by bob vtxo channel should be the added event
				// related to the offchain send
				bobVtxoEvent := <-bobVtxoCh
				require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
				require.Len(t, bobVtxoEvent.Vtxos, 1)
				bobVtxo := bobVtxoEvent.Vtxos[0]
				require.Equal(t, amount, int(bobVtxo.Amount))
				require.Equal(t, txid, bobVtxo.Txid)
			}

			aliceVtxoCh := alice.GetVtxoEventChannel(ctx)

			txid, err := bob.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     aliceOffchainAddr,
				Amount: numInputs * amount,
			}})
			require.NoError(t, err)

			// next event received by alice vtxo channel should be the added event
			// related to the offchain send
			for aliceVtxoEvent := range aliceVtxoCh {
				if aliceVtxoEvent.Vtxos[0].Txid != txid {
					continue
				}
				require.Equal(t, types.VtxosAdded, aliceVtxoEvent.Type)
				require.Len(t, aliceVtxoEvent.Vtxos, 1)
				aliceVtxo := aliceVtxoEvent.Vtxos[0]
				require.Equal(t, txid, aliceVtxo.Txid)
				require.Equal(t, numInputs*amount, int(aliceVtxo.Amount))
				break
			}
		})

		// In this test Alice sends to Bob a sub-dust VTXO. Bob can't spend or settle his VTXO.
		// He must receive other offchain funds to be able to settle them into a non-sub-dust that
		// can be spent
		t.Run("sub dust", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			faucetOffchain(t, alice, 0.00021)

			aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceOffchainAddr)

			bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			bobVtxoCh := bob.GetVtxoEventChannel(ctx)

			txid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobOffchainAddr,
				Amount: 100, // Sub-dust amount
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent := <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			bobVtxo := bobVtxoEvent.Vtxos[0]
			require.Equal(t, 100, int(bobVtxo.Amount))
			require.Equal(t, txid, bobVtxo.Txid)

			// bob can't spend subdust VTXO via ark tx
			_, err = bob.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     aliceOffchainAddr,
				Amount: 100,
			}})
			require.Error(t, err)

			// bob can't settle VTXO because he didn't collect enough funds to settle it
			_, err = bob.Settle(ctx)
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to register intent")

			txid, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
				To:     bobOffchainAddr,
				Amount: 1000, // Another sub-dust amount
			}})
			require.NoError(t, err)

			// next event received by bob vtxo channel should be the added event
			// related to the offchain send
			bobVtxoEvent = <-bobVtxoCh
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
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
			require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
			require.Len(t, bobVtxoEvent.Vtxos, 1)
			bobSettledVtxo := bobVtxoEvent.Vtxos[0]
			require.Equal(t, 1000+100, int(bobSettledVtxo.Amount))
		})

		// In this test Alice submits a tx and then calls FinalizePendingTxs to finalize it, simulating
		// the manual finalization of a pending (non-finalized) tx
		t.Run("finalize pending tx (manual)", func(t *testing.T) {
			ctx := t.Context()
			explorer, err := mempool_explorer.NewExplorer(
				"http://localhost:3000", arklib.BitcoinRegTest,
			)
			require.NoError(t, err)

			alice, aliceWallet, arkClient := setupClientWithWallet(t, "")

			vtxo := faucetOffchain(t, alice, 0.00021)

			finalizedPendingTxs, err := alice.FinalizePendingTxs(ctx, nil)
			require.NoError(t, err)
			require.Empty(t, finalizedPendingTxs)

			_, offchainAddresses, _, _, err := aliceWallet.GetAddresses(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, offchainAddresses)
			offchainAddress := offchainAddresses[0]

			serverParams, err := arkClient.GetInfo(ctx)
			require.NoError(t, err)

			vtxoScript, err := script.ParseVtxoScript(offchainAddress.Tapscripts)
			require.NoError(t, err)
			forfeitClosures := vtxoScript.ForfeitClosures()
			require.Len(t, forfeitClosures, 1)
			closure := forfeitClosures[0]

			scriptBytes, err := closure.Script()
			require.NoError(t, err)

			_, vtxoTapTree, err := vtxoScript.TapTree()
			require.NoError(t, err)

			merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
				txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
			)
			require.NoError(t, err)

			ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
			require.NoError(t, err)

			tapscript := &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: merkleProof.Script,
			}

			checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
			require.NoError(t, err)

			vtxoHash, err := chainhash.NewHashFromStr(vtxo.Txid)
			require.NoError(t, err)

			addr, err := arklib.DecodeAddressV0(offchainAddress.Address)
			require.NoError(t, err)
			pkscript, err := addr.GetPkScript()
			require.NoError(t, err)

			ptx, checkpointsPtx, err := offchain.BuildTxs(
				[]offchain.VtxoInput{
					{
						Outpoint: &wire.OutPoint{
							Hash:  *vtxoHash,
							Index: vtxo.VOut,
						},
						Tapscript:          tapscript,
						Amount:             int64(vtxo.Amount),
						RevealedTapscripts: offchainAddress.Tapscripts,
					},
				},
				[]*wire.TxOut{
					{
						Value:    int64(vtxo.Amount),
						PkScript: pkscript,
					},
				},
				checkpointTapscript,
			)
			require.NoError(t, err)

			encodedCheckpoints := make([]string, 0, len(checkpointsPtx))
			for _, checkpoint := range checkpointsPtx {
				encoded, err := checkpoint.B64Encode()
				require.NoError(t, err)
				encodedCheckpoints = append(encodedCheckpoints, encoded)
			}

			// sign the ark transaction
			encodedArkTx, err := ptx.B64Encode()
			require.NoError(t, err)
			signedArkTx, err := aliceWallet.SignTransaction(ctx, explorer, encodedArkTx)
			require.NoError(t, err)

			txid, _, _, err := arkClient.SubmitTx(ctx, signedArkTx, encodedCheckpoints)
			require.NoError(t, err)
			require.NotEmpty(t, txid)

			time.Sleep(time.Second)

			history, err := alice.GetTransactionHistory(ctx)
			require.NoError(t, err)
			require.False(t, slices.ContainsFunc(history, func(tx clientTypes.Transaction) bool {
				return tx.TransactionKey.String() == txid
			}))

			var incomingFunds []clientTypes.Vtxo
			var incomingErr error
			wg := &sync.WaitGroup{}
			wg.Go(func() {
				incomingFunds, incomingErr = alice.NotifyIncomingFunds(ctx, offchainAddress.Address)
			})

			finalizedTxIds, err := alice.FinalizePendingTxs(ctx, nil)
			require.NoError(t, err)
			require.NotEmpty(t, finalizedTxIds)
			require.Equal(t, 1, len(finalizedTxIds))
			require.Equal(t, txid, finalizedTxIds[0])

			wg.Wait()
			require.NoError(t, incomingErr)
			require.NotEmpty(t, incomingFunds)
			require.Len(t, incomingFunds, 1)
			require.Equal(t, txid, incomingFunds[0].Txid)

			time.Sleep(time.Second)

			history, err = alice.GetTransactionHistory(ctx)
			require.NoError(t, err)
			require.True(t, slices.ContainsFunc(history, func(tx clientTypes.Transaction) bool {
				return tx.TransactionKey.String() == txid
			}))
		})

		// In this test Alice submits a tx without finalizing it, then her wallet is restored with a
		// client that automatically finalizes the pending tx
		t.Run("finalize pending tx (auto)", func(t *testing.T) {
			ctx := t.Context()
			explorer, err := mempool_explorer.NewExplorer(
				"http://localhost:3000", arklib.BitcoinRegTest,
			)
			require.NoError(t, err)

			alice, aliceWallet, arkClient := setupClientWithWallet(t, "")

			_, bobWallet, _ := setupClientWithWallet(t, "")

			vtxo := faucetOffchain(t, alice, 0.00021)

			_, aliceOffchainAddr, _, err := aliceWallet.NewAddress(ctx, false)
			require.NoError(t, err)
			require.NotEmpty(t, aliceOffchainAddr)

			_, bobOffchainAddr, _, err := bobWallet.NewAddress(ctx, false)
			require.NoError(t, err)
			require.NotEmpty(t, bobOffchainAddr)

			serverParams, err := arkClient.GetInfo(ctx)
			require.NoError(t, err)

			vtxoScript, err := script.ParseVtxoScript(aliceOffchainAddr.Tapscripts)
			require.NoError(t, err)
			forfeitClosures := vtxoScript.ForfeitClosures()
			require.Len(t, forfeitClosures, 1)
			closure := forfeitClosures[0]

			scriptBytes, err := closure.Script()
			require.NoError(t, err)

			_, vtxoTapTree, err := vtxoScript.TapTree()
			require.NoError(t, err)

			merkleProof, err := vtxoTapTree.GetTaprootMerkleProof(
				txscript.NewBaseTapLeaf(scriptBytes).TapHash(),
			)
			require.NoError(t, err)

			ctrlBlock, err := txscript.ParseControlBlock(merkleProof.ControlBlock)
			require.NoError(t, err)

			tapscript := &waddrmgr.Tapscript{
				ControlBlock:   ctrlBlock,
				RevealedScript: merkleProof.Script,
			}

			checkpointTapscript, err := hex.DecodeString(serverParams.CheckpointTapscript)
			require.NoError(t, err)

			vtxoHash, err := chainhash.NewHashFromStr(vtxo.Txid)
			require.NoError(t, err)

			addr, err := arklib.DecodeAddressV0(bobOffchainAddr.Address)
			require.NoError(t, err)
			pkscript, err := addr.GetPkScript()
			require.NoError(t, err)

			ptx, checkpointsPtx, err := offchain.BuildTxs(
				[]offchain.VtxoInput{
					{
						Outpoint: &wire.OutPoint{
							Hash:  *vtxoHash,
							Index: vtxo.VOut,
						},
						Tapscript:          tapscript,
						Amount:             int64(vtxo.Amount),
						RevealedTapscripts: aliceOffchainAddr.Tapscripts,
					},
				},
				[]*wire.TxOut{
					{
						Value:    int64(vtxo.Amount),
						PkScript: pkscript,
					},
				},
				checkpointTapscript,
			)
			require.NoError(t, err)

			encodedCheckpoints := make([]string, 0, len(checkpointsPtx))
			for _, checkpoint := range checkpointsPtx {
				encoded, err := checkpoint.B64Encode()
				require.NoError(t, err)
				encodedCheckpoints = append(encodedCheckpoints, encoded)
			}

			// sign the ark transaction
			encodedArkTx, err := ptx.B64Encode()
			require.NoError(t, err)
			signedArkTx, err := aliceWallet.SignTransaction(ctx, explorer, encodedArkTx)
			require.NoError(t, err)

			txid, _, _, err := arkClient.SubmitTx(ctx, signedArkTx, encodedCheckpoints)
			require.NoError(t, err)
			require.NotEmpty(t, txid)

			// Dump the private key and load it into a new client with enabled finalization of
			// pending transactions
			key, err := alice.Dump(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, key)

			time.Sleep(time.Second)

			history, err := alice.GetTransactionHistory(ctx)
			require.NoError(t, err)
			require.False(t, slices.ContainsFunc(history, func(tx clientTypes.Transaction) bool {
				return tx.TransactionKey.String() == txid
			}))

			// Create a new client that automatically finalizes pending txs
			restoredAlice, _, _ := setupClientWithWallet(t, key)

			// // No pending txs should be finalized as they've been all handled in the background
			finalizedTxIds, err := restoredAlice.FinalizePendingTxs(ctx, nil)
			require.NoError(t, err)
			require.Empty(t, finalizedTxIds)

			history, err = restoredAlice.GetTransactionHistory(ctx)
			require.NoError(t, err)
			require.True(t, slices.ContainsFunc(history, func(tx clientTypes.Transaction) bool {
				return tx.TransactionKey.String() == txid
			}))
		})
	})
}

// TestAutoSettle exercises the WithAutoSettle() opt-in end-to-end against a
// live arkd. The VTXO expiry can be several minutes out, so the test first
// asserts the computed schedule and then waits relative to that scheduled
// fire time.
func TestAutoSettle(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		ctx := t.Context()

		alice := backend.setupClientWithOptions(t, sdk.WithAutoSettle())

		// Subscribe to vtxo events BEFORE faucet so we observe both the
		// VtxosAdded (faucet) and the VtxoSettled / subsequent VtxosAdded
		// (auto-settle) events on the same channel.
		vtxoCh := alice.GetVtxoEventChannel(ctx)

		// Sanity: WhenNextSettlement should be zero before any vtxos arrive.
		require.True(t, alice.WhenNextSettlement().IsZero(),
			"WhenNextSettlement should be zero before any vtxos exist")

		// Fund alice with an offchain VTXO.
		fundedVtxo := faucetOffchain(t, alice, 0.0001)
		require.False(t, fundedVtxo.ExpiresAt.IsZero(),
			"funded vtxo must have a non-zero ExpiresAt")

		// Read SessionDuration from the server config.
		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)
		require.Greater(t, cfg.SessionDuration, int64(0))
		sessionDuration := time.Duration(cfg.SessionDuration) * time.Second

		// Compute expected fire time using the same formula the SDK uses.
		expectedFireAt := fundedVtxo.ExpiresAt.Add(-2 * sessionDuration)
		require.Greater(t, time.Until(expectedFireAt), 5*time.Second,
			"test arkd config must leave enough time to observe WhenNextSettlement")

		// Poll WhenNextSettlement up to 5 seconds: the auto-settle loop
		// schedules the timer asynchronously after the VtxosAdded event
		// arrives, so the schedule may not be visible the instant the faucet
		// returns.
		var nextSettle time.Time
		require.Eventually(t, func() bool {
			nextSettle = alice.WhenNextSettlement()
			return !nextSettle.IsZero()
		}, 10*time.Second, 50*time.Millisecond,
			"WhenNextSettlement was never set after faucet")

		// The SQL store persists expiry timestamps at second precision. If the
		// scheduler observes the initial DB scan instead of the event payload,
		// allow that small truncation difference.
		require.WithinDuration(t, expectedFireAt, nextSettle, time.Second,
			"WhenNextSettlement does not match expected fireAt")

		// Wait for the auto-settle to complete. We accept either VtxoSettled
		// (the vtxo we just funded got settled) OR a subsequent VtxosAdded
		// event whose vtxo's CommitmentTxids points back to a *different*
		// commitment from the faucet — both indicate the round closed.
		//
		// The schedule is expiry-based, not sessionDuration-based. Wait until
		// the actual scheduled fire time plus a small round-completion grace.
		settleWait := time.Until(nextSettle) + 3*sessionDuration
		if minWait := 3 * sessionDuration; settleWait < minWait {
			settleWait = minWait
		}
		deadline := time.After(settleWait)
		settled := false
	WAIT:
		for !settled {
			select {
			case event, ok := <-vtxoCh:
				if !ok {
					break WAIT
				}
				switch event.Type {
				case types.VtxoSettled:
					settled = true
				case types.VtxosAdded:
					// Fresh round output for alice with a new commitment txid.
					for _, v := range event.Vtxos {
						if v.Txid != fundedVtxo.Txid {
							settled = true
							break
						}
					}
				}
			case <-deadline:
				t.Fatalf(
					"auto-settle did not complete within %s "+
						"(WhenNextSettlement was %s, %s ago)",
					settleWait, nextSettle, time.Since(nextSettle),
				)
			}
		}
		require.True(t, settled, "auto-settle did not produce a settle/refresh event")

		// After firing, WhenNextSettlement must reset to zero (until the
		// next VtxosAdded re-arms it). Be tolerant of a brief race where
		// the loop is racing the timer callback to clear the field.
		require.Eventually(t, func() bool {
			next := alice.WhenNextSettlement()
			// Either zero (cleared post-fire) or a fresh schedule keyed off
			// the new vtxo's ExpiresAt is acceptable.
			return next.IsZero() || next.After(time.Now())
		}, 5*time.Second, 50*time.Millisecond,
			"post-settle nextSettleAt is in an unexpected state")
	})
}
