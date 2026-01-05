package e2e

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	arksdk "github.com/arkade-os/go-sdk"
	mempool_explorer "github.com/arkade-os/go-sdk/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

const (
	withoutFinalizePendingTxs = true
	withFinalizePendingTxs    = !withoutFinalizePendingTxs
)

func TestOffchainTx(t *testing.T) {
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

	// In this test Alice submits a tx and then calls FinalizePendingTxs to finalize it, simulating
	// the manual finalization of a pending (non-finalized) tx
	t.Run("finalize pending tx (manual)", func(t *testing.T) {
		ctx := t.Context()
		explorer, err := mempool_explorer.NewExplorer(
			"http://localhost:3000", arklib.BitcoinRegTest,
		)
		require.NoError(t, err)

		alice, aliceWallet, arkClient := setupClientWithWallet(t, withoutFinalizePendingTxs, "")
		t.Cleanup(func() { alice.Stop() })
		t.Cleanup(func() { arkClient.Close() })

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
		require.False(t, slices.ContainsFunc(history, func(tx types.Transaction) bool {
			return tx.TransactionKey.String() == txid
		}))

		var incomingFunds []types.Vtxo
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
		require.True(t, slices.ContainsFunc(history, func(tx types.Transaction) bool {
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

		alice, aliceWallet, arkClient := setupClientWithWallet(t, withoutFinalizePendingTxs, "")
		t.Cleanup(func() { alice.Stop() })
		t.Cleanup(func() { arkClient.Close() })

		vtxo := faucetOffchain(t, alice, 0.00021)

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

		// Dump the private key and load it into a new client with enabled finalization of
		// pending transactions
		key, err := alice.Dump(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, key)

		time.Sleep(time.Second)

		history, err := alice.GetTransactionHistory(ctx)
		require.NoError(t, err)
		require.False(t, slices.ContainsFunc(history, func(tx types.Transaction) bool {
			return tx.TransactionKey.String() == txid
		}))

		// Create a new client that automatically finalizes pending txs
		restoredAlice, _, _ := setupClientWithWallet(t, withFinalizePendingTxs, key)
		t.Cleanup(func() { restoredAlice.Stop() })

		// No pending txs should be finalized as they've been all handled in the background
		finalizedTxIds, err := restoredAlice.FinalizePendingTxs(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, finalizedTxIds)

		time.Sleep(3 * time.Second)

		history, err = restoredAlice.GetTransactionHistory(ctx)
		require.NoError(t, err)
		require.True(t, slices.ContainsFunc(history, func(tx types.Transaction) bool {
			return tx.TransactionKey.String() == txid
		}))
	})
}
