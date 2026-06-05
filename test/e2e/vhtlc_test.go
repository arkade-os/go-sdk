package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/swap"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

// TestVHTLCClaimDirect tests the basic VHTLC claim path via SwapHandler.ClaimVHTLC.
// Adapted from fulmine TestVHTLC.
// Flow:
//  1. Create VHTLC opts with sender=receiver (self-claim scenario)
//  2. Fund the VHTLC by sending offchain
//  3. Claim with preimage via SwapHandler.ClaimVHTLC
//  4. Verify claim returns a valid txid
func TestVHTLCClaimDirect(t *testing.T) {
	t.Parallel()
	alice, privKey := setupSwapClient(t)
	ctx := t.Context()

	// Fund alice with offchain sats so she can send to the VHTLC
	faucetOffchain(t, alice, 0.001)

	cfg, err := alice.GetConfigData(ctx)
	require.NoError(t, err)

	preimage, preimageHash := generatePreimage(t)

	// sender = receiver = alice (self-claim test)
	pubKey := privKey.PubKey()
	// Use a future block height for refund locktime (not needed for claim)
	refundLocktime := uint32(time.Now().Unix() + 86400)

	opts := makeVhtlcOpts(t, pubKey, pubKey, cfg.SignerPubKey, preimageHash, refundLocktime)

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(cfg.Network.Addr)
	require.NoError(t, err)
	require.NotEmpty(t, vhtlcAddr)

	// Fund the VHTLC
	fundVHTLC(t, alice, vhtlcAddr, 1000)

	// Create swap handler (boltzSvc=nil since we only need VHTLC operations)
	handler, err := swap.NewSwapHandler(alice, nil, explorerUrl, privKey, 300)
	require.NoError(t, err)

	// Verify VHTLC has funds
	vtxos, err := handler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)
	require.NotEmpty(t, vtxos, "VHTLC should have funded vtxos")

	// Claim the VHTLC
	claimTxid, err := handler.ClaimVHTLC(ctx, preimage, opts, nil)
	require.NoError(t, err)
	require.NotEmpty(t, claimTxid)
	t.Logf("VHTLC claimed successfully: txid=%s", claimTxid)
}

// TestVHTLCClaimSettlement tests the VHTLC claim via batch settlement
// (SettleVHTLCWithClaimPath). Adapted from fulmine TestClaimVhtlcSettlement.
// Flow:
//  1. Create VHTLC with sender=receiver
//  2. Fund the VHTLC
//  3. Wait for VTXO to become recoverable (settle to force into next round)
//  4. Claim via SettleVHTLCWithClaimPath (batch session)
//  5. Verify balance is preserved (minus dust/fees)
func TestVHTLCClaimSettlement(t *testing.T) {
	t.Parallel()
	alice, privKey := setupSwapClient(t)
	ctx := t.Context()

	// Get initial balance
	faucetOffchain(t, alice, 0.001)

	balanceBefore, err := alice.Balance(ctx)
	require.NoError(t, err)

	cfg, err := alice.GetConfigData(ctx)
	require.NoError(t, err)

	preimage, preimageHash := generatePreimage(t)

	pubKey := privKey.PubKey()
	refundLocktime := uint32(time.Now().Unix() + 86400)

	opts := makeVhtlcOpts(t, pubKey, pubKey, cfg.SignerPubKey, preimageHash, refundLocktime)
	registerVHTLCContract(t, alice, opts)

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(cfg.Network.Addr)
	require.NoError(t, err)

	fundAmount := uint64(1000)

	fundVHTLC(t, alice, vhtlcAddr, fundAmount)

	handler, err := swap.NewSwapHandler(alice, nil, explorerUrl, privKey, 300)
	require.NoError(t, err)

	// Verify VHTLC has funds before settlement
	vtxos, err := handler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)
	require.NotEmpty(t, vtxos, "VHTLC should have funded vtxos")

	// Settle VHTLC via claim path (batch session)
	settleTxid, err := handler.SettleVHTLCWithClaimPath(ctx, opts, preimage, nil)
	require.NoError(t, err)
	require.NotEmpty(t, settleTxid)
	t.Logf("VHTLC settled via claim path: txid=%s", settleTxid)

	time.Sleep(1 * time.Second)

	// Verify balance is approximately the same (funds returned minus fees)
	balanceAfter, err := alice.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
		"offchain balance should be preserved after self-claim settlement")
}

// TestVHTLCRefundSettlement tests the VHTLC refund path via batch settlement
// (SettleVhtlcWithRefundPath). Adapted from fulmine TestRefundVhtlcSettlement.
// Uses a past refund locktime (Jan 1, 2020) so the CLTV is already expired.
// Flow:
//  1. Create VHTLC with a past refund locktime and a separate receiver
//  2. Fund the VHTLC
//  3. Refund via SettleVhtlcWithRefundPath
//  4. Verify balance is preserved
func TestVHTLCRefundSettlement(t *testing.T) {
	t.Parallel()
	alice, privKey := setupSwapClient(t)
	ctx := t.Context()

	faucetOffchain(t, alice, 0.001)

	balanceBefore, err := alice.Balance(ctx)
	require.NoError(t, err)

	cfg, err := alice.GetConfigData(ctx)
	require.NoError(t, err)

	_, preimageHash := generatePreimage(t)

	// Alice is sender. Use a separate receiver key.
	receiverPrivKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Use a timestamp far in the past (Jan 1, 2020) so CLTV is already expired in regtest.
	// This ensures the refund-without-receiver path is available immediately.
	pastRefundLocktime := uint32(1577836800) // Jan 1, 2020 00:00:00 UTC

	opts := makeVhtlcOpts(
		t,
		privKey.PubKey(),
		receiverPrivKey.PubKey(),
		cfg.SignerPubKey,
		preimageHash,
		pastRefundLocktime,
	)
	registerVHTLCContract(t, alice, opts)

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(cfg.Network.Addr)
	require.NoError(t, err)

	fundAmount := uint64(1000)

	fundVHTLC(t, alice, vhtlcAddr, fundAmount)

	handler, err := swap.NewSwapHandler(alice, nil, explorerUrl, privKey, 300)
	require.NoError(t, err)

	// Verify VHTLC has funds
	vtxos, err := handler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)
	require.NotEmpty(t, vtxos, "VHTLC should have funded vtxos")

	// Settle VHTLC via refund path (batch session)
	settleTxid, err := handler.SettleVhtlcWithRefundPath(ctx, opts, nil)
	require.NoError(t, err)
	require.NotEmpty(t, settleTxid)
	t.Logf("VHTLC settled via refund path: txid=%s", settleTxid)

	time.Sleep(2 * time.Second)

	// Verify balance returned to approximately initial value
	balanceAfter, err := alice.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
		"offchain balance should be preserved after refund settlement")
}

// TestVHTLCDelegateRefund tests the VHTLC delegate refund flow.
// Adapted from fulmine TestSettleVHTLCByDelegateRefund.
//
// This tests the delegate pattern where a counterparty (receiver) completes
// a batch session on behalf of the VTXO owner (sender) using a pre-signed
// intent proof and partial forfeit transaction.
//
// Flow:
//  1. Sender creates and funds a VHTLC with a separate receiver
//  2. Sender builds delegate intent proof and partial forfeit tx
//  3. Receiver acts as delegate to complete the refund settlement
//     via SettleVHTLCWithCollaborativeRefundPath
//  4. Verify sender's balance is restored
func TestVHTLCDelegateRefund(t *testing.T) {
	t.Parallel()
	// Setup sender (the VTXO owner who will delegate the refund)
	sender, senderPrivKey := setupSwapClient(t)
	// Setup receiver (acts as the delegate who completes the refund)
	receiver, receiverPrivKey := setupSwapClient(t)

	ctx := t.Context()

	// Fund sender with offchain sats
	faucetOffchain(t, sender, 0.001)

	// Settle so sender has spendable VTXOs
	_, err := sender.Settle(ctx)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	senderBalance, err := sender.Balance(ctx)
	require.NoError(t, err)
	senderOffchainBalanceInit := senderBalance.OffchainBalance.Total

	senderCfg, err := sender.GetConfigData(ctx)
	require.NoError(t, err)

	_, preimageHash := generatePreimage(t)

	senderPubKey := senderPrivKey.PubKey()
	receiverPubKey := receiverPrivKey.PubKey()

	opts := makeVhtlcOpts(
		t,
		senderPubKey,
		receiverPubKey,
		senderCfg.SignerPubKey,
		preimageHash,
		uint32(time.Now().Unix()+86400),
	)
	registerVHTLCContract(t, sender, opts)
	registerVHTLCContract(t, receiver, opts)

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(senderCfg.Network.Addr)
	require.NoError(t, err)

	// Fund the VHTLC
	fundVHTLC(t, sender, vhtlcAddr, 1000)

	// Get funded VHTLC vtxo info
	senderHandler, err := swap.NewSwapHandler(sender, nil, explorerUrl, senderPrivKey, 300)
	require.NoError(t, err)

	vtxos, err := senderHandler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)
	require.NotEmpty(t, vtxos, "VHTLC should have funded vtxos")
	vhtlcVtxo := vtxos[0]

	// Get sender's offchain address for the refund destination
	_, offchainAddrs, _, _, err := sender.GetAddresses(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, offchainAddrs)

	senderOffchainAddr, err := arklib.DecodeAddressV0(offchainAddrs[0])
	require.NoError(t, err)
	senderPkScript, err := senderOffchainAddr.GetPkScript()
	require.NoError(t, err)

	// Build delegate intent proof (sender signs)
	intentProof, intentMessage, err := buildDelegateIntentProof(
		t,
		ctx,
		sender,
		hex.EncodeToString(receiverPubKey.SerializeCompressed()),
		vhtlcVtxo,
		vhtlcAddr,
		vhtlcScript,
		senderPkScript,
	)
	require.NoError(t, err)

	// Build partial forfeit tx (sender signs)
	forfeitOutputAddr, err := btcutil.DecodeAddress(senderCfg.ForfeitAddress, nil)
	require.NoError(t, err)
	forfeitOutputScript, err := txscript.PayToAddrScript(forfeitOutputAddr)
	require.NoError(t, err)

	partialForfeitTx, err := buildDelegatePartialForfeit(
		t,
		ctx,
		sender,
		vhtlcVtxo,
		vhtlcAddr,
		vhtlcScript,
		forfeitOutputScript,
		int64(senderCfg.Dust),
	)
	require.NoError(t, err)

	// Receiver acts as delegate to settle the VHTLC refund
	receiverHandler, err := swap.NewSwapHandler(receiver, nil, explorerUrl, receiverPrivKey, 300)
	require.NoError(t, err)

	// Create a signer session for the receiver (the delegate cosigner)
	receiverSignerSession := tree.NewTreeSignerSession(receiverPrivKey)

	settleTxid, err := receiverHandler.SettleVHTLCWithCollaborativeRefundPath(
		ctx, opts,
		partialForfeitTx, intentProof, intentMessage,
		receiverSignerSession,
		nil,
	)
	require.NoError(t, err)
	require.NotEmpty(t, settleTxid)
	t.Logf("VHTLC delegate refund settled: txid=%s", settleTxid)

	time.Sleep(2 * time.Second)

	// Verify sender's balance is restored
	senderBalance, err = sender.Balance(ctx)
	require.NoError(t, err)
	require.Equal(t, senderOffchainBalanceInit, senderBalance.OffchainBalance.Total,
		"sender's offchain balance should be restored after delegate refund")
}

// buildDelegateIntentProof constructs the intent proof PSBT that the VTXO owner
// (sender) signs, authorizing the delegate (receiver) to complete the refund
// via a batch session.
func buildDelegateIntentProof(
	t *testing.T,
	ctx context.Context,
	senderArkClient arksdk.Wallet,
	receiverPubKeyHex string,
	vhtlcVtxo clientTypes.Vtxo,
	vhtlcAddress string,
	vhtlcScript *vhtlc.VHTLCScript,
	senderPkScript []byte,
) (string, string, error) {
	t.Helper()

	// Parse VHTLC outpoint
	vhtlcTxHash, err := chainhash.NewHashFromStr(vhtlcVtxo.Txid)
	require.NoError(t, err)

	vtxoOutpoint := &wire.OutPoint{
		Hash:  *vhtlcTxHash,
		Index: vhtlcVtxo.VOut,
	}

	vhtlcAddr, err := arklib.DecodeAddressV0(vhtlcAddress)
	require.NoError(t, err)
	vhtlcPkScript, err := vhtlcAddr.GetPkScript()
	require.NoError(t, err)

	scriptOpts := vhtlcScript.Opts()
	csvSequence, err := arklib.BIP68Sequence(scriptOpts.UnilateralClaimDelay)
	require.NoError(t, err)

	validAt := time.Now()
	intentMsg, err := intent.RegisterMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeRegister,
		},
		ExpireAt:            validAt.Add(5 * time.Minute).Unix(),
		ValidAt:             validAt.Unix(),
		CosignersPublicKeys: []string{receiverPubKeyHex},
	}.Encode()
	require.NoError(t, err)

	intentProof, err := intent.New(
		intentMsg,
		[]intent.Input{
			{
				OutPoint: vtxoOutpoint,
				Sequence: csvSequence,
				WitnessUtxo: &wire.TxOut{
					Value:    int64(vhtlcVtxo.Amount),
					PkScript: vhtlcPkScript,
				},
			},
		},
		[]*wire.TxOut{
			{
				Value:    int64(vhtlcVtxo.Amount),
				PkScript: senderPkScript,
			},
		},
	)
	require.NoError(t, err)

	// Add refund tapscript (with receiver) to both inputs
	refundTapscript, err := vhtlcScript.RefundTapscript(true)
	require.NoError(t, err)
	cb, err := refundTapscript.ControlBlock.ToBytes()
	require.NoError(t, err)
	exitLeaf := &psbt.TaprootTapLeafScript{
		ControlBlock: cb,
		Script:       refundTapscript.RevealedScript,
		LeafVersion:  txscript.BaseLeafVersion,
	}
	intentProof.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{exitLeaf}
	intentProof.Inputs[1].TaprootLeafScript = []*psbt.TaprootTapLeafScript{exitLeaf}

	err = txutils.SetArkPsbtField(
		&intentProof.Packet, 1,
		txutils.VtxoTaprootTreeField,
		vhtlcScript.GetRevealedTapscripts(),
	)
	require.NoError(t, err)

	encodedProof, err := intentProof.B64Encode()
	require.NoError(t, err)

	signedProof, err := senderArkClient.SignTransaction(ctx, encodedProof)
	require.NoError(t, err)

	return signedProof, intentMsg, nil
}

// buildDelegatePartialForfeit constructs and partially signs a forfeit
// transaction for the delegate refund flow.
func buildDelegatePartialForfeit(
	t *testing.T,
	ctx context.Context,
	senderArkClient arksdk.Wallet,
	vhtlcVtxo clientTypes.Vtxo,
	vhtlcAddress string,
	vhtlcScript *vhtlc.VHTLCScript,
	forfeitOutputScript []byte,
	connectorAmount int64,
) (string, error) {
	t.Helper()

	vhtlcTxHash, err := chainhash.NewHashFromStr(vhtlcVtxo.Txid)
	require.NoError(t, err)

	vhtlcOutpoint := &wire.OutPoint{
		Hash:  *vhtlcTxHash,
		Index: vhtlcVtxo.VOut,
	}

	vhtlcAmount := int64(vhtlcVtxo.Amount)

	vhtlcAddr, err := arklib.DecodeAddressV0(vhtlcAddress)
	require.NoError(t, err)
	vhtlcPkScript, err := vhtlcAddr.GetPkScript()
	require.NoError(t, err)

	forfeitPtx, err := tree.BuildForfeitTxWithOutput(
		[]*wire.OutPoint{vhtlcOutpoint},
		[]uint32{wire.MaxTxInSequenceNum},
		[]*wire.TxOut{
			{
				Value:    vhtlcAmount,
				PkScript: vhtlcPkScript,
			},
		},
		&wire.TxOut{
			Value:    vhtlcAmount + connectorAmount,
			PkScript: forfeitOutputScript,
		},
		0,
	)
	require.NoError(t, err)

	updater, err := psbt.NewUpdater(forfeitPtx)
	require.NoError(t, err)

	err = updater.AddInSighashType(txscript.SigHashAnyOneCanPay|txscript.SigHashAll, 0)
	require.NoError(t, err)

	refundTapscript, err := vhtlcScript.RefundTapscript(true)
	require.NoError(t, err)

	controlBlockBytes, err := refundTapscript.ControlBlock.ToBytes()
	require.NoError(t, err)

	updater.Upsbt.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: controlBlockBytes,
			Script:       refundTapscript.RevealedScript,
			LeafVersion:  txscript.BaseLeafVersion,
		},
	}

	b64PartialForfeit, err := updater.Upsbt.B64Encode()
	require.NoError(t, err)

	signedPartialForfeit, err := senderArkClient.SignTransaction(ctx, b64PartialForfeit)
	require.NoError(t, err)

	return signedPartialForfeit, nil
}

// TestVHTLCClaimWithOutpoint verifies that ClaimVHTLC targets the specified VTXO
// by outpoint when multiple VTXOs exist at the same VHTLC address.
func TestVHTLCClaimWithOutpoint(t *testing.T) {
	t.Parallel()
	alice, privKey := setupSwapClient(t)
	ctx := t.Context()

	faucetOffchain(t, alice, 0.001)

	cfg, err := alice.GetConfigData(ctx)
	require.NoError(t, err)

	preimage, preimageHash := generatePreimage(t)
	pubKey := privKey.PubKey()
	refundLocktime := uint32(time.Now().Unix() + 86400)

	opts := makeVhtlcOpts(t, pubKey, pubKey, cfg.SignerPubKey, preimageHash, refundLocktime)

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(cfg.Network.Addr)
	require.NoError(t, err)

	// Fund two VTXOs at the same VHTLC address
	fundVHTLC(t, alice, vhtlcAddr, 1000) // first VTXO
	fundVHTLC(t, alice, vhtlcAddr, 2000) // second VTXO

	handler, err := swap.NewSwapHandler(alice, nil, explorerUrl, privKey, 300)
	require.NoError(t, err)

	vtxos, err := handler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)
	require.Len(t, vtxos, 2, "expected exactly 2 VTXOs at VHTLC address")

	// Find the 2000-sat VTXO (target) and 1000-sat VTXO (should survive)
	var targetVtxo, otherVtxo *clientTypes.Vtxo
	for i := range vtxos {
		if vtxos[i].Amount == 2000 {
			targetVtxo = &vtxos[i]
		} else {
			otherVtxo = &vtxos[i]
		}
	}
	require.NotNil(t, targetVtxo, "2000-sat VTXO not found")
	require.NotNil(t, otherVtxo, "1000-sat VTXO not found")

	// Claim the 2000-sat VTXO by explicit outpoint
	claimTxid, err := handler.ClaimVHTLC(ctx, preimage, opts, &clientTypes.Outpoint{
		Txid: targetVtxo.Txid,
		VOut: targetVtxo.VOut,
	})
	require.NoError(t, err)
	require.NotEmpty(t, claimTxid)
	t.Logf("Claimed VTXO %s:%d in tx %s", targetVtxo.Txid, targetVtxo.VOut, claimTxid)

	// Wait for indexer to reflect spent status
	time.Sleep(3 * time.Second)

	// Verify the 1000-sat VTXO is still unspent
	remaining, err := handler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)
	var survivorFound bool
	for _, v := range remaining {
		if v.Txid == otherVtxo.Txid && v.VOut == otherVtxo.VOut {
			require.False(t, v.Spent, "1000-sat VTXO should not be spent")
			survivorFound = true
		}
	}
	require.True(t, survivorFound, "1000-sat VTXO should still be present")
}

// TestVHTLCClaimOldestVtxo verifies that ClaimVHTLC with nil outpoint selects
// the oldest VTXO (by CreatedAt ascending) when multiple exist.
func TestVHTLCClaimOldestVtxo(t *testing.T) {
	t.Parallel()
	alice, privKey := setupSwapClient(t)
	ctx := t.Context()

	faucetOffchain(t, alice, 0.001)

	cfg, err := alice.GetConfigData(ctx)
	require.NoError(t, err)

	preimage, preimageHash := generatePreimage(t)
	pubKey := privKey.PubKey()
	refundLocktime := uint32(time.Now().Unix() + 86400)

	opts := makeVhtlcOpts(t, pubKey, pubKey, cfg.SignerPubKey, preimageHash, refundLocktime)

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(cfg.Network.Addr)
	require.NoError(t, err)

	// Fund three VTXOs with delays to ensure distinct CreatedAt timestamps
	fundVHTLC(t, alice, vhtlcAddr, 1000) // oldest
	time.Sleep(2 * time.Second)
	fundVHTLC(t, alice, vhtlcAddr, 2000) // middle
	time.Sleep(2 * time.Second)
	fundVHTLC(t, alice, vhtlcAddr, 3000) // newest

	handler, err := swap.NewSwapHandler(alice, nil, explorerUrl, privKey, 300)
	require.NoError(t, err)

	// Claim with nil outpoint — should select oldest (1000-sat) VTXO
	claimTxid, err := handler.ClaimVHTLC(ctx, preimage, opts, nil)
	require.NoError(t, err)
	require.NotEmpty(t, claimTxid)
	t.Logf("Claimed oldest VTXO in tx %s", claimTxid)

	// Wait for indexer
	time.Sleep(3 * time.Second)

	vtxos, err := handler.GetVHTLCFunds(ctx, []vhtlc.Opts{opts})
	require.NoError(t, err)

	// Verify: 1000-sat VTXO should be spent; 2000 and 3000 should not be
	spentAmounts := make(map[uint64]bool)
	for _, v := range vtxos {
		if v.Spent {
			spentAmounts[v.Amount] = true
		}
	}
	require.True(t, spentAmounts[1000], "1000-sat (oldest) VTXO should be spent")
	require.False(t, spentAmounts[2000], "2000-sat VTXO should not be spent")
	require.False(t, spentAmounts[3000], "3000-sat VTXO should not be spent")
}

// makeVhtlcOpts constructs vhtlc.Opts for a test scenario.
// Sender and receiver are the same key for simplicity in basic tests.
// serverPubKey is obtained from the server configuration.
func makeVhtlcOpts(
	t *testing.T,
	sender, receiver, server *btcec.PublicKey,
	preimageHash []byte,
	refundLocktime uint32,
) vhtlc.Opts {
	t.Helper()
	return vhtlc.Opts{
		Sender:         sender,
		Receiver:       receiver,
		Server:         server,
		PreimageHash:   preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(refundLocktime),
		UnilateralClaimDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 512,
		},
		UnilateralRefundDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 512,
		},
		UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeSecond,
			Value: 1024,
		},
	}
}

// registerVHTLCContract registers a VHTLC in the wallet's contract manager
// so that SignTransaction can find the tapscripts during batch settlement.
func registerVHTLCContract(
	t *testing.T, w arksdk.Wallet, opts vhtlc.Opts,
) {
	t.Helper()

	_, err := w.ContractManager().NewContract(
		t.Context(), types.ContractTypeVHTLC,
		contract.WithParams(&opts),
	)
	require.NoError(t, err)
}

// generatePreimage creates a random 32-byte preimage and returns
// the preimage bytes and the RIPEMD160(SHA256(preimage)) hash.
func generatePreimage(t *testing.T) ([]byte, []byte) {
	t.Helper()
	preimage := make([]byte, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)
	sha256Hash := sha256.Sum256(preimage)
	return preimage, input.Ripemd160H(sha256Hash[:])
}

// fundVHTLC sends offchain funds to the VHTLC address and waits for the
// VTXO to appear in the indexer.
func fundVHTLC(
	t *testing.T,
	client arksdk.Wallet,
	vhtlcAddress string,
	amount uint64,
) {
	t.Helper()
	ctx := t.Context()

	txid, err := client.SendOffChain(ctx, []clientTypes.Receiver{
		{To: vhtlcAddress, Amount: amount},
	})
	require.NoError(t, err)
	require.NotEmpty(t, txid)
	t.Logf("Funded VHTLC %s with %d sats, txid=%s", vhtlcAddress, amount, txid)

	// Wait for the indexer to pick up the new VTXO
	time.Sleep(3 * time.Second)
}
