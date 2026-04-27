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
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	types "github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/stretchr/testify/require"
)

func TestOffchainTx(t *testing.T) {
	// In this test Alice sends several times to Bob to create a chain of offchain txs
	t.Run("chain of txs", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")
		bob := setupClient(t, "")

		aliceFaucetAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		faucetOffchain(t, alice, aliceFaucetAddr, 0.001)

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

		alice := setupClient(t, "")
		bob := setupClient(t, "")

		aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceOffchainAddr)

		bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		faucetOffchain(t, alice, aliceOffchainAddr, 0.001)

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
		alice := setupClient(t, "")
		bob := setupClient(t, "")

		aliceFundingAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		faucetOffchain(t, alice, aliceFundingAddr, 0.00021)

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
		alice := setupClient(t, "")
		aliceWallet := alice.Wallet()
		arkClient := alice.Client()

		aliceFundingAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)

		vtxo := faucetOffchain(t, alice, aliceFundingAddr, 0.00021)

		finalizedPendingTxs, err := alice.FinalizePendingTxs(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, finalizedPendingTxs)

		_, offchainAddresses, _, _ := deriveWalletAddresses(t, ctx, alice, aliceWallet)
		require.NotEmpty(t, offchainAddresses)
		offchainAddress := findOffchainAddressByScript(t, offchainAddresses, vtxo.Script)

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
		signedArkTx, err := aliceWallet.SignTransaction(
			ctx, encodedArkTx, map[string]string{
				hex.EncodeToString(ptx.Inputs[0].WitnessUtxo.PkScript): offchainAddress.KeyID,
			},
		)
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
		alice := setupClient(t, "")
		aliceWallet := alice.Wallet()
		arkClient := alice.Client()

		aliceFundingAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)

		bob := setupClient(t, "")
		bobWallet := bob.Wallet()
		_, err = bob.NewOffchainAddress(ctx)
		require.NoError(t, err)

		vtxo := faucetOffchain(t, alice, aliceFundingAddr, 0.00021)

		_, aliceOffchainAddrs, _, _ := deriveWalletAddresses(t, ctx, alice, aliceWallet)
		require.NotEmpty(t, aliceOffchainAddrs)
		matchedAliceOffchainAddr := findOffchainAddressByScript(t, aliceOffchainAddrs, vtxo.Script)
		aliceOffchainAddr := &matchedAliceOffchainAddr
		require.NotEmpty(t, aliceOffchainAddr)

		_, bobOffchainAddrs, _, _ := deriveWalletAddresses(t, ctx, bob, bobWallet)
		require.NotEmpty(t, bobOffchainAddrs)
		bobOffchainAddr := &bobOffchainAddrs[0]
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
		signedArkTx, err := aliceWallet.SignTransaction(
			ctx, encodedArkTx, map[string]string{
				hex.EncodeToString(ptx.Inputs[0].WitnessUtxo.PkScript): aliceOffchainAddr.KeyID,
			},
		)
		require.NoError(t, err)

		txid, _, _, err := arkClient.SubmitTx(ctx, signedArkTx, encodedCheckpoints)
		require.NoError(t, err)
		require.NotEmpty(t, txid)

		// Dump the wallet seed and load it into a new client with enabled finalization of
		// pending transactions.
		seed, err := alice.Dump(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, seed)

		time.Sleep(time.Second)

		history, err := alice.GetTransactionHistory(ctx)
		require.NoError(t, err)
		require.False(t, slices.ContainsFunc(history, func(tx clientTypes.Transaction) bool {
			return tx.TransactionKey.String() == txid
		}))

		// Create a new client that resumes pending tx finalization on restore.
		restoredAlice := setupClient(t, seed)

		finalizedTxIds, err := restoredAlice.FinalizePendingTxs(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, finalizedTxIds)

		require.Eventually(t, func() bool {
			history, err = restoredAlice.GetTransactionHistory(ctx)
			if err != nil {
				return false
			}

			return slices.ContainsFunc(history, func(tx clientTypes.Transaction) bool {
				return tx.TransactionKey.String() == txid
			})
		}, 30*time.Second, 500*time.Millisecond)
	})
}
