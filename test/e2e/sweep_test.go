package e2e_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/redemption"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestCheckpointSweep(t *testing.T) {
	ctx := t.Context()
	alice := setupClient(t, "", arksdk.WithoutAutoSettle())

	// create a VTXO spent by a checkpoint tx
	rootVtxo := faucetOffchain(t, alice, 0.00021)
	aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceOffchainAddr)
	aliceVtxoCh := alice.GetVtxoEventChannel(ctx)
	_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     aliceOffchainAddr,
		Amount: rootVtxo.Amount,
	}})
	require.NoError(t, err)

	var leafVtxo clientTypes.Vtxo
	require.Eventually(t, func() bool {
		select {
		case vtxoEvent := <-aliceVtxoCh:
			if vtxoEvent.Type == types.VtxosAdded && len(vtxoEvent.Vtxos) > 0 {
				leafVtxo = vtxoEvent.Vtxos[0]
			}
		default:
		}
		return leafVtxo.Amount != 0
	}, 15*time.Second, 100*time.Millisecond, "timed out waiting for preconfirmed vtxo")

	// unroll the root VTXO by broadcasting its redeem branch. We deliberately
	// do NOT broadcast the child ark tx, so the checkpoint output stays unspent
	// and arkd sweeps it once its exit delay expires.
	exp, err := mempoolexplorer.NewExplorer(
		explorerUrl, arklib.BitcoinRegTest, mempoolexplorer.WithTracker(false),
	)
	require.NoError(t, err)
	branch, err := redemption.NewRedeemBranch(ctx, exp, alice.Indexer(), rootVtxo)
	require.NoError(t, err)
	for parentTx, err := branch.NextRedeemTx(); err == nil; parentTx, err = branch.NextRedeemTx() {
		bumpAndBroadcastTx(t, parentTx, exp)
	}
	time.Sleep(5 * time.Second)

	// expire the checkpoint delay so arkd can sweep
	generateBlocks(t, 20)

	// verify the sweep event reaches go-sdk wallet and update
	require.Eventually(t, func() bool {
		vtxos, _, err := alice.ListVtxos(ctx)
		if err != nil {
			return false
		}
		for _, v := range vtxos {
			if v.Outpoint == leafVtxo.Outpoint && v.Swept {
				return true
			}
		}
		return false
	}, 90*time.Second, 3*time.Second,
		"wallet did not mark the leaf vtxo as swept after checkpoint sweep")
}

func bumpAndBroadcastTx(t *testing.T, tx string, exp explorer.Explorer) {
	t.Helper()

	var transaction wire.MsgTx
	require.NoError(t, transaction.Deserialize(hex.NewDecoder(strings.NewReader(tx))))

	childTx := bumpAnchorTx(t, &transaction, exp)

	_, err := exp.Broadcast(tx, childTx)
	require.NoError(t, err)

	generateBlocks(t, 1)
}

func bumpAnchorTx(t *testing.T, parent *wire.MsgTx, exp explorer.Explorer) string {
	t.Helper()

	randomPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	tapKey := txscript.ComputeTaprootKeyNoScript(randomPrivKey.PubKey())
	addr, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(tapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)

	anchor, err := txutils.FindAnchorOutpoint(parent)
	require.NoError(t, err)

	fees := uint64(10000)

	faucetOnchain(t, addr.EncodeAddress(), 0.01)

	changeAmount := 1_000_000 - fees

	pkScript, err := txscript.PayToAddrScript(addr)
	require.NoError(t, err)

	inputs := []*wire.OutPoint{anchor}
	sequences := []uint32{wire.MaxTxInSequenceNum}

	time.Sleep(5 * time.Second)

	selectedCoins, err := exp.GetUtxos([]string{addr.EncodeAddress()})
	require.NoError(t, err)
	require.Len(t, selectedCoins, 1)

	utxo := selectedCoins[0]
	txid, err := chainhash.NewHashFromStr(utxo.Txid)
	require.NoError(t, err)
	inputs = append(inputs, &wire.OutPoint{Hash: *txid, Index: utxo.Vout})
	sequences = append(sequences, wire.MaxTxInSequenceNum)

	ptx, err := psbt.New(
		inputs,
		[]*wire.TxOut{{Value: int64(changeAmount), PkScript: pkScript}},
		3,
		0,
		sequences,
	)
	require.NoError(t, err)

	ptx.Inputs[0].WitnessUtxo = txutils.AnchorOutput()
	ptx.Inputs[1].WitnessUtxo = &wire.TxOut{
		Value:    int64(selectedCoins[0].Amount),
		PkScript: pkScript,
	}

	coinTxHash, err := chainhash.NewHashFromStr(selectedCoins[0].Txid)
	require.NoError(t, err)

	prevoutFetcher := txscript.NewMultiPrevOutFetcher(map[wire.OutPoint]*wire.TxOut{
		*anchor: txutils.AnchorOutput(),
		{Hash: *coinTxHash, Index: selectedCoins[0].Vout}: {
			Value:    int64(selectedCoins[0].Amount),
			PkScript: pkScript,
		},
	})

	txsighashes := txscript.NewTxSigHashes(ptx.UnsignedTx, prevoutFetcher)

	preimage, err := txscript.CalcTaprootSignatureHash(
		txsighashes, txscript.SigHashDefault, ptx.UnsignedTx, 1, prevoutFetcher,
	)
	require.NoError(t, err)

	sig, err := schnorr.Sign(txscript.TweakTaprootPrivKey(*randomPrivKey, nil), preimage)
	require.NoError(t, err)

	ptx.Inputs[1].TaprootKeySpendSig = sig.Serialize()

	for inIndex := range ptx.Inputs[1:] {
		_, err := psbt.MaybeFinalize(ptx, inIndex+1)
		require.NoError(t, err)
	}

	childTx, err := txutils.ExtractWithAnchors(ptx)
	require.NoError(t, err)

	var serializedTx bytes.Buffer
	require.NoError(t, childTx.Serialize(&serializedTx))

	return hex.EncodeToString(serializedTx.Bytes())
}
