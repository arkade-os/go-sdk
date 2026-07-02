package swap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/ccoveille/go-safecast"
	decodepay "github.com/nbd-wtf/ln-decodepay"

	log "github.com/sirupsen/logrus"
)

var ErrorNoVtxosFound = fmt.Errorf("no vtxos found for the given vhtlc opts")

type SwapHandler struct {
	arkWallet         arksdk.Wallet
	boltzSvc          *boltz.Api
	explorerClient    ExplorerClient
	timeout           uint32
	config            clientTypes.Config
	htlcMu            sync.RWMutex
	htlcKeysByAddress map[string]*btcec.PrivateKey
}

type SwapStatus int

const (
	SwapPending SwapStatus = iota
	SwapFailed
	SwapSuccess
)

type Swap struct {
	Id           string
	Invoice      string
	TxId         string
	Timestamp    int64
	RedeemTxid   string
	Status       SwapStatus
	PreimageHash []byte
	TimeoutInfo  boltz.TimeoutBlockHeights
	Opts         *vhtlc.Opts
	Amount       uint64
}

func NewSwapHandler(
	arkClient arksdk.Wallet,
	boltzSvc *boltz.Api,
	esploraURL string,
	timeout uint32,
) (*SwapHandler, error) {
	cfg, err := arkClient.GetConfigData(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get config data: %w", err)
	}
	return &SwapHandler{
		arkWallet:         arkClient,
		boltzSvc:          boltzSvc,
		explorerClient:    NewExplorerClient(esploraURL),
		timeout:           timeout,
		config:            *cfg,
		htlcKeysByAddress: make(map[string]*btcec.PrivateKey),
	}, nil
}

func (h *SwapHandler) PayInvoice(
	ctx context.Context, invoice string, unilateralRefund func(swap Swap) error,
) (*Swap, error) {
	if len(invoice) <= 0 {
		return nil, fmt.Errorf("missing invoice")
	}

	return h.submarineSwap(ctx, invoice, unilateralRefund)
}

func (h *SwapHandler) PayOffer(
	ctx context.Context, offer string, lightningUrl string, unilateralRefund func(swap Swap) error,
) (*Swap, error) {
	// Decode the offer to get the amount
	decodedOffer, err := DecodeBolt12Offer(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to decode offer: %v", err)
	}

	amountInSats := decodedOffer.AmountInSats
	if amountInSats == 0 {
		return nil, fmt.Errorf("offer amount must be greater than 0")
	}

	boltzApi := h.boltzSvc
	if lightningUrl != "" {
		boltzApi = &boltz.Api{URL: lightningUrl}
	}

	response, err := boltzApi.FetchBolt12Invoice(boltz.FetchBolt12InvoiceRequest{
		Offer:  offer,
		Amount: amountInSats,
		Note:   decodedOffer.DescriptionStr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch invoice: %v", err)
	}
	if response.Error != "" {
		return nil, fmt.Errorf("failed to fetch invoice: %s", response.Error)
	}

	return h.submarineSwap(ctx, response.Invoice, unilateralRefund)
}

func (h *SwapHandler) GetInvoice(
	ctx context.Context, amount uint64, postProcess func(swap Swap) error,
) (Swap, error) {
	return h.reverseSwap(ctx, amount, postProcess)
}

func (h *SwapHandler) GetVHTLCFunds(
	ctx context.Context, vhtlcOpts []vhtlc.Opts,
) ([]clientTypes.Vtxo, error) {
	vHTLCs := make([]*vhtlc.VHTLCScript, 0, len(vhtlcOpts))
	for _, opts := range vhtlcOpts {
		vHTLC, err := vhtlc.NewVHTLCScriptFromOpts(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to parse VHTLC from opts: %w", err)
		}
		vHTLCs = append(vHTLCs, vHTLC)
	}

	return h.getVHTLCFunds(ctx, vHTLCs)
}

func (h *SwapHandler) GetVHTLCSpendingTx(
	ctx context.Context, vhtlcOpts vhtlc.Opts, outpoint *clientTypes.Outpoint,
) (string, bool, error) {
	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(vhtlcOpts)
	if err != nil {
		return "", false, fmt.Errorf("failed to create VHTLC script: %w", err)
	}

	vtxo, pending, err := h.selectClaimableVTXO(ctx, vhtlcScript, outpoint)
	if err != nil {
		return "", false, err
	}

	if pending {
		tx, err := h.getPendingVHTLCTx(ctx, *vtxo, vhtlcScript)
		if err != nil {
			return "", false, fmt.Errorf("failed to get pending tx: %w", err)
		}
		return tx, true, nil
	}

	txs, err := h.arkWallet.Indexer().GetVirtualTxs(ctx, []string{vtxo.ArkTxid})
	if err != nil {
		return "", false, fmt.Errorf("failed to get virtual tx: %w", err)
	}
	if len(txs.Txs) == 0 {
		return "", false, fmt.Errorf("no virtual tx found for txid %s", vtxo.ArkTxid)
	}

	return txs.Txs[0], false, nil
}

// getPendingVHTLCTx retrieves the pending tx for a VTXO without finalizing it.
func (h *SwapHandler) getPendingVHTLCTx(
	ctx context.Context, vtxo clientTypes.Vtxo, vhtlcScript *vhtlc.VHTLCScript,
) (string, error) {
	inputs := []pendingTxIntentInput{{
		Vtxo: clientTypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: vhtlcScript.GetRevealedTapscripts(),
		},
		Closure:  vhtlcScript.RefundWithoutReceiverClosure,
		Sequence: wire.MaxTxInSequenceNum - 1,
	}}

	proof, message, err := getPendingTxIntent(
		inputs,
		uint32(vhtlcScript.RefundWithoutReceiverClosure.Locktime),
	)
	if err != nil {
		return "", err
	}

	signedProof, err := h.arkWallet.SignTransaction(ctx, proof)
	if err != nil {
		return "", fmt.Errorf("failed to sign pending tx proof: %w", err)
	}

	pendingTxs, err := h.arkWallet.Client().GetPendingTx(ctx, signedProof, message)
	if err != nil {
		return "", err
	}

	if len(pendingTxs) == 0 {
		return "", fmt.Errorf("no pending txs found")
	}

	return pendingTxs[0].FinalArkTx, nil
}

func (h *SwapHandler) ClaimVHTLC(
	ctx context.Context, preimage []byte, vhtlcOpts vhtlc.Opts, outpoint *clientTypes.Outpoint,
) (string, error) {
	vHTLC, err := vhtlc.NewVHTLCScriptFromOpts(vhtlcOpts)
	if err != nil {
		return "", err
	}
	if err := h.ensureLocalVHTLCContractForSigning(ctx, vhtlcOpts); err != nil {
		return "", err
	}

	vtxo, pending, err := h.selectClaimableVTXO(ctx, vHTLC, outpoint)
	if err != nil {
		return "", err
	}
	if pending {
		txids, err := h.finalizePendingClaimVHTLCTxs(ctx, *vtxo, vHTLC, preimage)
		if err != nil {
			return "", fmt.Errorf("failed to finalize pending txs: %w", err)
		}
		if len(txids) > 0 {
			return txids[0], nil
		}
		return "", fmt.Errorf("vtxo is pending but no pending txs found to finalize")
	}

	//this is safety net for Boltz Fulmine if VTXO is recoverable in the moment of Claim
	if vtxo.IsRecoverable() && vtxo.Amount >= h.config.Dust {
		txid, err := h.SettleVHTLCWithClaimPath(ctx, vhtlcOpts, preimage, &vtxo.Outpoint)
		if err != nil {
			return "", fmt.Errorf("failed to settle vhtlc with claim path: %w", err)
		}

		log.Infof("recoverable vhtlc settled with claim path: %s", txid)
		return txid, nil
	}

	vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
	if err != nil {
		return "", err
	}
	vtxoOutpoint := &wire.OutPoint{
		Hash:  *vtxoTxHash,
		Index: vtxo.VOut,
	}

	// self send output
	myAddr, err := h.arkWallet.NewOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	decodedAddr, err := arklib.DecodeAddressV0(myAddr)
	if err != nil {
		return "", err
	}

	pkScript, err := script.P2TRScript(decodedAddr.VtxoTapKey)
	if err != nil {
		return "", err
	}

	amount, err := safecast.Convert[int64](vtxo.Amount)
	if err != nil {
		return "", err
	}

	claimTapscript, err := vHTLC.ClaimTapscript()
	if err != nil {
		return "", err
	}

	arkTx, checkpoints, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				RevealedTapscripts: vHTLC.GetRevealedTapscripts(),
				Outpoint:           vtxoOutpoint,
				Amount:             amount,
				Tapscript:          claimTapscript,
			},
		},
		[]*wire.TxOut{
			{
				Value:    amount,
				PkScript: pkScript,
			},
		},
		checkpointExitScript(h.config),
	)
	if err != nil {
		return "", err
	}

	signTransaction := func(tx *psbt.Packet) (string, error) {
		// add the preimage to the checkpoint input
		if err := txutils.SetArkPsbtField(
			tx, 0, txutils.ConditionWitnessField, wire.TxWitness{preimage},
		); err != nil {
			return "", err
		}

		encoded, err := tx.B64Encode()
		if err != nil {
			return "", err
		}

		return h.arkWallet.SignTransaction(ctx, encoded)
	}

	signedArkTx, err := signTransaction(arkTx)
	if err != nil {
		return "", err
	}

	checkpointTxs := make([]string, 0, len(checkpoints))
	for _, ptx := range checkpoints {
		tx, err := ptx.B64Encode()
		if err != nil {
			return "", err
		}
		checkpointTxs = append(checkpointTxs, tx)
	}

	arkTxid, finalArkTx, signedCheckpoints, err := h.arkWallet.Client().SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", err
	}

	if err := verifyFinalArkTx(
		finalArkTx, h.config.SignerPubKey, getInputTapLeaves(arkTx),
	); err != nil {
		return "", err
	}

	finalCheckpoints, err := verifyAndSignCheckpoints(
		signedCheckpoints, checkpoints, h.config.SignerPubKey, signTransaction,
	)
	if err != nil {
		return "", err
	}

	if err := h.arkWallet.Client().FinalizeTx(ctx, arkTxid, finalCheckpoints); err != nil {
		return "", err
	}

	return arkTxid, nil
}

func (h *SwapHandler) RefundSwap(
	ctx context.Context, swapType, swapId string, withReceiver bool, vhtlcOpts vhtlc.Opts,
	outpoint *clientTypes.Outpoint,
) (string, error) {
	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(vhtlcOpts)
	if err != nil {
		return "", err
	}
	if err := h.ensureLocalVHTLCContractForSigning(ctx, vhtlcOpts); err != nil {
		return "", err
	}

	vtxo, pending, err := h.selectClaimableVTXO(ctx, vhtlcScript, outpoint)
	if err != nil {
		return "", err
	}
	if pending {
		txids, err := h.finalizePendingRefundVHTLCTxs(ctx, *vtxo, vhtlcScript)
		if err != nil {
			return "", fmt.Errorf("failed to finalize pending txs: %w", err)
		}
		if len(txids) > 0 {
			return txids[0], nil
		}
		return "", fmt.Errorf("vtxo is pending but no pending txs found to finalize")
	}

	//this is safety net for Boltz Fulmine if VTXO is recoverable in the moment of Refund
	if vtxo.IsRecoverable() && vtxo.Amount >= h.config.Dust {
		txid, err := h.SettleVhtlcWithRefundPath(ctx, vhtlcOpts, &vtxo.Outpoint)
		if err != nil {
			return "", fmt.Errorf("failed to settle vhtlc with refund path: %w", err)
		}

		log.Infof("recoverable vhtlc settled with refund path: %s", txid)
		return txid, nil
	}

	vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
	if err != nil {
		return "", err
	}
	vtxoOutpoint := &wire.OutPoint{
		Hash:  *vtxoTxHash,
		Index: vtxo.VOut,
	}

	refundTapscript, err := vhtlcScript.RefundTapscript(withReceiver)
	if err != nil {
		return "", err
	}

	offchainAddress, err := h.arkWallet.NewOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	offchainPkScript, err := offchainAddressPkScript(offchainAddress)
	if err != nil {
		return "", err
	}

	dest, err := hex.DecodeString(offchainPkScript)
	if err != nil {
		return "", err
	}

	amount, err := safecast.Convert[int64](vtxo.Amount)
	if err != nil {
		return "", err
	}

	refundTx, checkpointPtxs, err := offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				RevealedTapscripts: vhtlcScript.GetRevealedTapscripts(),
				Outpoint:           vtxoOutpoint,
				Amount:             amount,
				Tapscript:          refundTapscript,
			},
		},
		[]*wire.TxOut{
			{
				Value:    amount,
				PkScript: dest,
			},
		},
		checkpointExitScript(h.config),
	)
	if err != nil {
		return "", err
	}

	if len(checkpointPtxs) != 1 {
		return "", fmt.Errorf(
			"failed to build refund tx: expected 1 checkpoint tx got %d", len(checkpointPtxs),
		)
	}
	unsignedRefundTx, err := refundTx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode unsigned refund tx: %s", err)
	}
	unsignedCheckpointTx, err := checkpointPtxs[0].B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode unsigned refund checkpoint tx: %s", err)
	}

	signTransaction := func(tx *psbt.Packet) (string, error) {
		encoded, err := tx.B64Encode()
		if err != nil {
			return "", err
		}
		return h.arkWallet.SignTransaction(ctx, encoded)
	}

	// user signing
	signedRefundTx, err := signTransaction(refundTx)
	if err != nil {
		return "", fmt.Errorf("failed to sign refund tx: %s", err)
	}
	signedCheckpointTx, err := signTransaction(checkpointPtxs[0])
	if err != nil {
		return "", fmt.Errorf("failed to sign refund checkpoint tx: %s", err)
	}

	signedRefundPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedRefundTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to decode refund tx signed by us: %s", err)
	}

	signedCheckpointPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedCheckpointTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to decode checkpoint tx signed by us: %s", err)
	}

	pubKeysToVerify := []*btcec.PublicKey{vhtlcOpts.Sender, vhtlcOpts.Server}
	checkpointsList := append([]*psbt.Packet{}, signedCheckpointPsbt)

	// if withReceiver is enabled, boltz should sign the transactions
	if withReceiver {
		pubKeysToVerify = append(pubKeysToVerify, vhtlcOpts.Receiver)

		// Determine which refund function to use based on swap type
		var refundFunc func(string, boltz.RefundSwapRequest) (*boltz.RefundSwapResponse, error)
		switch swapType {
		case SwapTypeSubmarine:
			refundFunc = h.boltzSvc.RefundSubmarine
		case SwapTypeChain:
			refundFunc = h.boltzSvc.RefundChainSwap
		default:
			return "", fmt.Errorf("unsupported swap type for collaborative refund: %s", swapType)
		}

		boltzSignedRefundPtx, boltzSignedCheckpointPtx, err := h.collaborativeRefund(
			refundFunc, swapId, unsignedRefundTx, unsignedCheckpointTx)

		if err != nil {
			return "", err
		}

		for i := range signedRefundPsbt.Inputs {
			boltzIn := boltzSignedRefundPtx.Inputs[i]
			// Boltz may legitimately omit a partial sig for inputs it
			// can't (or won't) co-sign — e.g. underfunded swaps that
			// only return sigs for a subset of inputs. Skip those
			// rather than indexing into an empty slice and panicking.
			if len(boltzIn.TaprootScriptSpendSig) == 0 {
				continue
			}
			partialSig := boltzIn.TaprootScriptSpendSig[0]
			signedRefundPsbt.Inputs[i].TaprootScriptSpendSig =
				append(signedRefundPsbt.Inputs[i].TaprootScriptSpendSig, partialSig)
		}

		checkpointsList = append(checkpointsList, boltzSignedCheckpointPtx)

	}

	signedRefund, err := signedRefundPsbt.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode final refund tx: %s", err)
	}

	arkTxid, finalRefundTx, serverSignedCheckpoints, err := h.arkWallet.Client().SubmitTx(
		ctx, signedRefund, []string{unsignedCheckpointTx},
	)
	if err != nil {
		return "", err
	}

	finalRefundPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalRefundTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to decode refund tx signed by server: %s", err)
	}

	serverCheckpointPtx, err := psbt.NewFromRawBytes(
		strings.NewReader(serverSignedCheckpoints[0]), true,
	)
	if err != nil {
		return "", fmt.Errorf("failed to decode checkpoint tx signed by us: %s", err)
	}

	if err := verifySignatures(
		[]*psbt.Packet{finalRefundPtx}, pubKeysToVerify, getInputTapLeaves(refundTx),
	); err != nil {
		return "", err
	}

	// combine checkpoint Transactions
	checkpointsList = append(checkpointsList, serverCheckpointPtx)
	finalCheckpointPtx, err := combineTapscripts(checkpointsList)
	if err != nil {
		return "", fmt.Errorf("failed to combine checkpoint txs: %s", err)
	}

	if err := verifySignatures(
		[]*psbt.Packet{finalCheckpointPtx}, pubKeysToVerify,
		getInputTapLeaves(serverCheckpointPtx),
	); err != nil {
		return "", err
	}

	finalCheckpointTx, err := finalCheckpointPtx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode final checkpoint tx: %s", err)
	}

	if err := h.arkWallet.Client().FinalizeTx(
		ctx, arkTxid, []string{finalCheckpointTx},
	); err != nil {
		return "", fmt.Errorf("failed to finalize refund tx: %w", err)
	}

	return arkTxid, nil
}

// SettleVHTLCWithClaimPath settles a VHTLC using the claim path (revealing preimage) via batch session.
// This is used for reverse submarine swaps where Fulmine is the receiver.
func (h *SwapHandler) SettleVHTLCWithClaimPath(
	ctx context.Context, vhtlcOpts vhtlc.Opts, preimage []byte, outpoint *clientTypes.Outpoint,
) (string, error) {
	if err := validatePreimage(preimage, vhtlcOpts.PreimageHash); err != nil {
		return "", err
	}

	session, err := h.getBatchSessionArgs(ctx, vhtlcOpts, outpoint, nil)
	if err != nil {
		return "", err
	}

	proof, message, err := getClaimIntent(session, preimage)
	if err != nil {
		return "", fmt.Errorf("failed to build claim intent: %w", err)
	}

	signedProof, err := h.arkWallet.SignTransaction(ctx, proof)
	if err != nil {
		return "", fmt.Errorf("failed to sign intent proof: %w", err)
	}

	intentID, err := h.arkWallet.Client().RegisterIntent(ctx, signedProof, message)
	if err != nil {
		return "", fmt.Errorf("failed to register VHTLC claim intent: %w", err)
	}

	topics := getEventTopics(session.vtxos, session.signerSession.GetPublicKey())
	eventsCh, cancel, err := h.arkWallet.Client().GetEventStream(ctx, topics)
	if err != nil {
		return "", fmt.Errorf("failed to get event stream: %w", err)
	}
	defer cancel()

	claimHandler, err := newClaimBatchSessionHandler(
		h.arkWallet,
		intentID,
		session.vtxos,
		[]clientTypes.Receiver{{To: session.destinationAddr, Amount: session.totalAmount}},
		preimage,
		map[string]*vhtlc.VHTLCScript{session.vtxos[0].Script: session.vhtlcScript},
		h.config,
		session.signerSession,
	)
	if err != nil {
		return "", fmt.Errorf("failed to setup claim batch session handler: %w", err)
	}

	txid, _, _, _, _, err := client.JoinBatchSession(ctx, eventsCh, claimHandler)
	if err != nil {
		return "", fmt.Errorf("batch session failed: %w", err)
	}

	log.Debugf("successfully claimed VHTLC in round %s", txid)
	return txid, nil
}

// SettleVhtlcWithRefundPath settles a VHTLC using the refund path via batch session.
// This is used for submarine swaps where Fulmine is the sender and needs to recover funds.
func (h *SwapHandler) SettleVhtlcWithRefundPath(
	ctx context.Context, vhtlcOpts vhtlc.Opts, outpoint *clientTypes.Outpoint,
) (string, error) {
	session, err := h.getBatchSessionArgs(ctx, vhtlcOpts, outpoint, nil)
	if err != nil {
		return "", err
	}

	proof, message, err := getRefundIntent(session)
	if err != nil {
		return "", fmt.Errorf("failed to build refund intent: %w", err)
	}

	signedProof, err := h.arkWallet.SignTransaction(ctx, proof)
	if err != nil {
		return "", fmt.Errorf("failed to sign intent proof: %w", err)
	}

	intentID, err := h.arkWallet.Client().RegisterIntent(ctx, signedProof, message)
	if err != nil {
		return "", fmt.Errorf("failed to register VHTLC refund intent: %w", err)
	}

	topics := getEventTopics(session.vtxos, session.signerSession.GetPublicKey())
	eventsCh, cancel, err := h.arkWallet.Client().GetEventStream(ctx, topics)
	if err != nil {
		return "", fmt.Errorf("failed to get event stream: %w", err)
	}
	defer cancel()

	withReceiver := true
	withoutReceiver := !withReceiver
	refundHandler, err := newRefundBatchSessionHandler(
		h.arkWallet,
		h.arkWallet.Client(),
		intentID,
		session.vtxos,
		[]clientTypes.Receiver{{To: session.destinationAddr, Amount: session.totalAmount}},
		withoutReceiver,
		map[string]*vhtlc.VHTLCScript{session.vtxos[0].Script: session.vhtlcScript},
		h.config,
		session.signerSession,
	)
	if err != nil {
		return "", fmt.Errorf("failed to setup refund batch session handler: %w", err)
	}

	txid, _, _, _, _, err := client.JoinBatchSession(ctx, eventsCh, refundHandler)
	if err != nil {
		return "", fmt.Errorf("batch session failed: %w", err)
	}

	log.Debugf("successfully refunded VHTLC in round %s", txid)
	return txid, nil
}

func (h *SwapHandler) SettleVHTLCWithCollaborativeRefundPath(
	ctx context.Context, vhtlcOpts vhtlc.Opts,
	partialForfeitTx, proof, message string, signerSession tree.SignerSession,
	outpoint *clientTypes.Outpoint,
) (string, error) {
	session, err := h.getBatchSessionArgs(ctx, vhtlcOpts, outpoint, &signerSession)
	if err != nil {
		return "", err
	}

	signedProof, err := h.arkWallet.SignTransaction(ctx, proof)
	if err != nil {
		return "", fmt.Errorf("failed to cosign intent proof: %w", err)
	}

	intentId, err := h.arkWallet.Client().RegisterIntent(ctx, signedProof, message)
	if err != nil {
		return "", fmt.Errorf("failed to register intent: %w", err)
	}

	withReceiver := true
	handler, err := newCollabRefundBatchSessionHandler(
		h.arkWallet,
		h.arkWallet.Client(),
		intentId,
		session.vtxos,
		[]clientTypes.Receiver{{To: session.destinationAddr, Amount: session.totalAmount}},
		withReceiver,
		map[string]*vhtlc.VHTLCScript{session.vtxos[0].Script: session.vhtlcScript},
		h.config,
		session.signerSession,
		partialForfeitTx,
	)
	if err != nil {
		return "", fmt.Errorf("failed to setup collab refund batch session handler: %w", err)
	}

	topics := getEventTopics(session.vtxos, session.signerSession.GetPublicKey())

	eventsCh, cancel, err := h.arkWallet.Client().GetEventStream(ctx, topics)
	if err != nil {
		return "", fmt.Errorf("failed to get event stream: %w", err)
	}
	defer cancel()

	txid, _, _, _, _, err := client.JoinBatchSession(ctx, eventsCh, handler)
	if err != nil {
		return "", fmt.Errorf("batch session failed: %w", err)
	}

	log.Debugf("successfully completed delegate refund in round %s", txid)
	return txid, nil
}

func (h *SwapHandler) submarineSwap(
	ctx context.Context, invoice string, unilateralRefund func(swap Swap) error,
) (*Swap, error) {
	var (
		preimageHash []byte
		refundKeyRef *identity.KeyRef
		err          error
	)

	if len(invoice) == 0 {
		return nil, fmt.Errorf("missing invoice")
	}
	if unilateralRefund == nil {
		return nil, fmt.Errorf("missing callback for unilateral refund")
	}

	// TODO: move to decodeInvoice
	if IsBolt12Invoice(invoice) {
		decodedInvoice, err := DecodeBolt12Invoice(invoice)
		if err != nil {
			return nil, fmt.Errorf("failed to decode bolt12 invoice: %v", err)
		}
		preimageHash = decodedInvoice.PaymentHash160
	} else {
		_, hash, err := decodeInvoice(invoice)
		if err != nil {
			return nil, fmt.Errorf("failed to decode invoice: %v", err)
		}
		preimageHash = hash
	}

	refundKeyRef, err = h.arkWallet.Identity().NewKey(ctx)
	if err != nil {
		return nil, err
	}

	// Create the swap
	swap, err := h.boltzSvc.CreateSwap(boltz.CreateSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		Invoice:         invoice,
		RefundPublicKey: hex.EncodeToString(refundKeyRef.PubKey.SerializeCompressed()),
		PaymentTimeout:  h.timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to make submarine swap: %v", err)
	}

	receiverPubkey, err := parsePubkey(swap.ClaimPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid claim pubkey: %v", err)
	}

	vhtlcAddress, _, vhtlcOpts, err := h.buildLocalSenderVHTLC(
		receiverPubkey,
		preimageHash,
		arklib.AbsoluteLocktime(swap.TimeoutBlockHeights.RefundLocktime),
		parseLocktime(swap.TimeoutBlockHeights.UnilateralClaim),
		parseLocktime(swap.TimeoutBlockHeights.UnilateralRefund),
		parseLocktime(swap.TimeoutBlockHeights.UnilateralRefundWithoutReceiver),
		refundKeyRef.PubKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to verify vHTLC: %v", err)
	}
	if swap.Address != vhtlcAddress {
		return nil, fmt.Errorf("boltz is trying to scam us, vHTLCs do not match")
	}
	if err := h.storeLocalVHTLCContract(ctx, *refundKeyRef, *vhtlcOpts); err != nil {
		return nil, err
	}

	ws := h.boltzSvc.NewWebsocket()
	if err := ws.ConnectAndSubscribe(ctx, []string{swap.Id}, 5*time.Second); err != nil {
		return nil, err
	}

	receivers := []clientTypes.Receiver{{To: swap.Address, Amount: swap.ExpectedAmount}}
	var txid string
	for range 3 {
		// Fund the VHTLC
		txid, err = h.arkWallet.SendOffChain(ctx, receivers)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "vtxo_already_spent") {
				continue
			}
			return nil, fmt.Errorf("failed to pay to vHTLC address: %v", err)
		}
		break
	}
	if err != nil {
		log.WithError(err).Error("failed to pay to vHTLC address")
		return nil, fmt.Errorf("something went wrong, please retry")
	}

	swapDetails := &Swap{
		Id:           swap.Id,
		Invoice:      invoice,
		TxId:         txid,
		PreimageHash: preimageHash,
		Timestamp:    time.Now().Unix(),
		TimeoutInfo:  swap.TimeoutBlockHeights,
		Status:       SwapPending,
		Opts:         vhtlcOpts,
		Amount:       swap.ExpectedAmount,
	}

	contextTimeout := time.Second * time.Duration(h.timeout)
	timeoutCtx, cancel := context.WithTimeout(ctx, contextTimeout)
	defer cancel()
	ctx = timeoutCtx

	for {
		select {
		case update, ok := <-ws.Updates:
			if !ok {
				oldWs := ws
				nextWs := h.boltzSvc.NewWebsocket()
				if err := nextWs.ConnectAndSubscribe(
					ctx, []string{swap.Id}, 5*time.Second,
				); err != nil {
					continue
				}
				_ = oldWs.Close()
				ws = nextWs
				continue
			}

			switch boltz.ParseEvent(update.Status) {
			case boltz.TransactionLockupFailed, boltz.InvoiceFailedToPay:
				// Refund the VHTLC if the swap fails
				withReceiver := true
				swapDetails.Status = SwapFailed

				txid, err := h.RefundSwap(
					context.Background(), SwapTypeSubmarine, swap.Id, withReceiver, *vhtlcOpts, nil,
				)
				if err != nil {
					log.WithError(err).Warnf("failed to refund swap %s collaboratively", swap.Id)
					go func() {
						if err := unilateralRefund(*swapDetails); err != nil {
							log.WithError(err).Errorf(
								"failed to refund swap %s unilaterally", swap.Id,
							)
						}
					}()
				}
				swapDetails.RedeemTxid = txid

				return swapDetails, nil
			case boltz.TransactionClaimed, boltz.InvoiceSettled:
				swapDetails.Status = SwapSuccess

				return swapDetails, nil
			}
		case <-ctx.Done():
			swapDetails.Status = SwapFailed
			go func() {
				if err := unilateralRefund(*swapDetails); err != nil {
					log.WithError(err).Errorf("failed to refund swap %s unilaterally", swap.Id)
				}
			}()

			return swapDetails, nil
		}
	}

}

func (h *SwapHandler) reverseSwap(
	ctx context.Context, amount uint64, postProcess func(swap Swap) error,
) (Swap, error) {
	var (
		preimage, preimageHashSHA256, preimageHashHASH160 []byte
		claimKeyRef                                       *identity.KeyRef
		err                                               error
	)

	claimKeyRef, err = h.arkWallet.Identity().NewKey(ctx)
	if err != nil {
		return Swap{}, err
	}

	preimageSigner, err := h.requirePreimageSigner()
	if err != nil {
		return Swap{}, err
	}
	preimage, preimageHashSHA256, preimageHashHASH160, err = genPreimageInfo(
		ctx, preimageSigner, *claimKeyRef,
	)
	if err != nil {
		return Swap{}, fmt.Errorf("failed to generate preimage: %w", err)
	}

	swap, err := h.boltzSvc.CreateReverseSwap(boltz.CreateReverseSwapRequest{
		From:           boltz.CurrencyBtc,
		To:             boltz.CurrencyArk,
		InvoiceAmount:  amount,
		ClaimPublicKey: hex.EncodeToString(claimKeyRef.PubKey.SerializeCompressed()),
		PreimageHash:   hex.EncodeToString(preimageHashSHA256),
	})
	if err != nil {
		return Swap{}, fmt.Errorf("failed to make reverse submarine swap: %v", err)
	}

	// verify vHTLC
	senderPubkey, err := parsePubkey(swap.RefundPublicKey)
	if err != nil {
		return Swap{}, fmt.Errorf("invalid refund pubkey: %v", err)
	}

	// verify preimage hash and invoice amount
	invoiceAmount, gotPreimageHash, err := decodeInvoice(swap.Invoice)
	if err != nil {
		return Swap{}, fmt.Errorf("failed to decode invoice: %v", err)
	}

	if !bytes.Equal(preimageHashHASH160, gotPreimageHash) {
		return Swap{}, fmt.Errorf(
			"invalid preimage hash: expected %x, got %x",
			preimageHashHASH160, gotPreimageHash,
		)
	}
	if invoiceAmount != amount {
		return Swap{}, fmt.Errorf(
			"invalid invoice amount: expected %d, got %d", amount, invoiceAmount,
		)
	}

	vhtlcAddress, _, vhtlcOpts, err := h.buildLocalReceiverVHTLC(
		senderPubkey,
		gotPreimageHash,
		arklib.AbsoluteLocktime(swap.TimeoutBlockHeights.RefundLocktime),
		parseLocktime(swap.TimeoutBlockHeights.UnilateralClaim),
		parseLocktime(swap.TimeoutBlockHeights.UnilateralRefund),
		parseLocktime(swap.TimeoutBlockHeights.UnilateralRefundWithoutReceiver),
		claimKeyRef.PubKey,
	)
	if err != nil {
		return Swap{}, fmt.Errorf("failed to verify vHTLC: %v", err)
	}

	swapDetails := Swap{
		Id:           swap.Id,
		Invoice:      swap.Invoice,
		PreimageHash: preimageHashHASH160,
		TimeoutInfo:  swap.TimeoutBlockHeights,
		Timestamp:    time.Now().Unix(),
		Status:       SwapPending,
		Amount:       swap.OnchainAmount,
		Opts:         vhtlcOpts,
	}
	if err != nil {
		return swapDetails, fmt.Errorf("failed to verify vHTLC: %v", err)
	}

	if swap.LockupAddress != vhtlcAddress {
		return swapDetails, fmt.Errorf("boltz is trying to scam us, vHTLCs do not match")
	}
	if err := h.storeLocalVHTLCContract(ctx, *claimKeyRef, *vhtlcOpts); err != nil {
		return swapDetails, err
	}

	inv, err := decodepay.Decodepay(swap.Invoice)
	if err != nil {
		return swapDetails, fmt.Errorf("failed to decode invoice: %v", err)
	}

	go func(swapDetails Swap) {
		if reedeemTxId, err := h.waitAndClaim(
			inv.Expiry, swapDetails.Id, preimage, vhtlcOpts,
		); err != nil {
			swapDetails.Status = SwapFailed
			log.WithError(err).Error("failed to claim VHTLC")
		} else {
			swapDetails.RedeemTxid = reedeemTxId
			swapDetails.Status = SwapSuccess
		}

		if err := postProcess(swapDetails); err != nil {
			log.WithError(err).Error("failed to post process swap")
		}
	}(swapDetails)
	return swapDetails, nil
}

func (h *SwapHandler) getVHTLCFunds(
	ctx context.Context, vhtlcs []*vhtlc.VHTLCScript,
) ([]clientTypes.Vtxo, error) {
	scripts := make([]string, 0, len(vhtlcs))
	for _, vHTLC := range vhtlcs {
		tapKey, _, err := vHTLC.TapTree()
		if err != nil {
			return nil, err
		}

		outScript, err := script.P2TRScript(tapKey)
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, hex.EncodeToString(outScript))
	}

	resp, err := h.arkWallet.Indexer().GetVtxos(ctx, indexer.WithScripts(scripts))
	if err != nil {
		return nil, err
	}
	return resp.Vtxos, nil
}

func (h *SwapHandler) getPendingVHTLCFunds(
	ctx context.Context, vhtlcs []*vhtlc.VHTLCScript,
) ([]clientTypes.Vtxo, error) {
	scripts := make([]string, 0, len(vhtlcs))
	for _, vHTLC := range vhtlcs {
		tapKey, _, err := vHTLC.TapTree()
		if err != nil {
			return nil, err
		}

		outScript, err := script.P2TRScript(tapKey)
		if err != nil {
			return nil, err
		}
		scripts = append(scripts, hex.EncodeToString(outScript))
	}

	resp, err := h.arkWallet.Indexer().GetVtxos(
		ctx, indexer.WithScripts(scripts), indexer.WithPendingOnly(),
	)
	if err != nil {
		return nil, err
	}
	return resp.Vtxos, nil
}

func (h *SwapHandler) waitAndClaim(
	invoiceExpiry int, swapId string, preimage []byte, vhtlcOpts *vhtlc.Opts,
) (string, error) {
	expiryDuration := time.Duration(invoiceExpiry) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), expiryDuration*2)
	defer cancel()

	ws := h.boltzSvc.NewWebsocket()

	err := ws.ConnectAndSubscribe(ctx, []string{swapId}, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = ws.Close() }()

	var txid string
	for {
		select {
		case update, ok := <-ws.Updates:
			if !ok {
				oldWs := ws
				nextWs := h.boltzSvc.NewWebsocket()
				if err := nextWs.ConnectAndSubscribe(
					ctx, []string{swapId}, 5*time.Second,
				); err != nil {
					continue
				}
				_ = oldWs.Close()
				ws = nextWs
				continue
			}
			parsedStatus := boltz.ParseEvent(update.Status)

			confirmed := false
			switch parsedStatus {
			case boltz.TransactionMempool:
				confirmed = true
			case boltz.InvoiceFailedToPay, boltz.TransactionFailed, boltz.TransactionLockupFailed:
				return "", fmt.Errorf("failed to receive payment: %s", update.Status)
			}
			if confirmed {
				interval := 200 * time.Millisecond
				log.Debug("claiming VHTLC with preimage...")
				if err := retry(ctx, interval, func(ctx context.Context) (bool, error) {
					var err error
					txid, err = h.ClaimVHTLC(ctx, preimage, *vhtlcOpts, nil)
					if err != nil {
						if errors.Is(err, ErrorNoVtxosFound) {
							return false, nil
						}
						return false, err
					}

					return true, nil
				}); err != nil {
					return "", err
				}
				log.Debugf("successfully claimed VHTLC with tx: %s", txid)
				return txid, nil
			}
		case <-ctx.Done():
			return "", fmt.Errorf("timed out waiting for boltz to detect payment")
		}
	}
}

const (
	SwapTypeSubmarine = "submarine"
	SwapTypeChain     = "chain"
)

func (h *SwapHandler) collaborativeRefund(
	requestRefund func(string, boltz.RefundSwapRequest) (*boltz.RefundSwapResponse, error),
	swapId, refundTx, checkpointTx string,
) (*psbt.Packet, *psbt.Packet, error) {
	refundResp, err := requestRefund(swapId, boltz.RefundSwapRequest{
		Transaction: refundTx,
		Checkpoint:  checkpointTx,
	})
	if err != nil {
		return nil, nil, err
	}

	refundPtx, err := psbt.NewFromRawBytes(strings.NewReader(refundResp.Transaction), true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode refund tx signed by boltz: %s", err)
	}

	checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(refundResp.Checkpoint), true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode checkpoint tx signed by boltz: %s", err)
	}

	return refundPtx, checkpointPtx, nil
}

// getBatchSessionArgs takes care of preparing the arguments for the batch session to either claim
// or refund a vhtlc.
// NOTE: signerSession is meant to not be nil only if the collaborative refund path is used.
func (h *SwapHandler) getBatchSessionArgs(
	ctx context.Context,
	vhtlcOpts vhtlc.Opts,
	outpoint *clientTypes.Outpoint,
	signerSession *tree.SignerSession,
) (*batchSessionArgs, error) {
	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(vhtlcOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create VHTLC script: %w", err)
	}

	vtxo, pending, err := h.selectClaimableVTXO(ctx, vhtlcScript, outpoint)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, fmt.Errorf("vtxo is pending finalization, call FinalizePendingTxs first")
	}

	myAddr, err := h.arkWallet.NewOffchainAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get offchain address: %w", err)
	}

	if signerSession == nil {
		ephemeralSignerSession, err := h.arkWallet.Identity().NewVtxoTreeSigner(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create ephemeral signer session: %w", err)
		}
		signerSession = &ephemeralSignerSession
	}

	vtxoTapscripts := []clientTypes.VtxoWithTapTree{{
		Vtxo:       *vtxo,
		Tapscripts: vhtlcScript.GetRevealedTapscripts(),
	}}

	return &batchSessionArgs{
		vhtlcScript:     vhtlcScript,
		totalAmount:     vtxo.Amount,
		destinationAddr: myAddr,
		signerSession:   *signerSession,
		vtxos:           vtxoTapscripts,
	}, nil
}

func (h *SwapHandler) selectClaimableVTXO(
	ctx context.Context,
	vhtlcScript *vhtlc.VHTLCScript,
	outpoint *clientTypes.Outpoint,
) (*clientTypes.Vtxo, bool, error) {
	spendableVtxos, err := h.getVHTLCFunds(ctx, []*vhtlc.VHTLCScript{vhtlcScript})
	if err != nil {
		return nil, false, err
	}

	pendingVtxos, err := h.getPendingVHTLCFunds(ctx, []*vhtlc.VHTLCScript{vhtlcScript})
	if err != nil {
		return nil, false, err
	}

	if len(spendableVtxos) == 0 && len(pendingVtxos) == 0 {
		return nil, false, ErrorNoVtxosFound
	}

	pendingByOutpoint := make(map[string]bool)
	candidateVtxos := make([]clientTypes.Vtxo, 0, len(spendableVtxos)+len(pendingVtxos))
	seenOutpoints := make(map[string]struct{}, len(spendableVtxos)+len(pendingVtxos))

	for _, vtxo := range spendableVtxos {
		key := vtxo.Outpoint.String()
		candidateVtxos = append(candidateVtxos, vtxo)
		seenOutpoints[key] = struct{}{}
	}

	for _, vtxo := range pendingVtxos {
		key := vtxo.Outpoint.String()
		pendingByOutpoint[key] = true

		if _, seen := seenOutpoints[key]; seen {
			continue
		}

		candidateVtxos = append(candidateVtxos, vtxo)
		seenOutpoints[key] = struct{}{}
	}

	if len(candidateVtxos) == 0 {
		return nil, false, ErrorNoVtxosFound
	}

	if outpoint != nil {
		for i := range candidateVtxos {
			v := &candidateVtxos[i]
			if v.Txid == outpoint.Txid && v.VOut == outpoint.VOut {
				return v, pendingByOutpoint[v.Outpoint.String()], nil
			}
		}
		return nil, false, fmt.Errorf("outpoint %s not found among VTXOs for this VHTLC", outpoint)
	}

	sort.Slice(candidateVtxos, func(i, j int) bool {
		a, b := candidateVtxos[i], candidateVtxos[j]

		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		if a.Txid != b.Txid {
			return a.Txid < b.Txid
		}
		return a.VOut < b.VOut
	})

	v := &candidateVtxos[0]
	return v, pendingByOutpoint[v.Outpoint.String()], nil
}

func (h *SwapHandler) finalizePendingVHTLCTxs(
	ctx context.Context,
	inputs []pendingTxIntentInput,
	locktime uint32,
	signCheckpoint func(string) (string, error),
) ([]string, error) {
	proof, message, err := getPendingTxIntent(inputs, locktime)
	if err != nil {
		return nil, err
	}

	signedProof, err := h.arkWallet.SignTransaction(ctx, proof)
	if err != nil {
		return nil, fmt.Errorf("failed to sign pending tx proof: %w", err)
	}

	pendingTxs, err := h.arkWallet.Client().GetPendingTx(ctx, signedProof, message)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(pendingTxs))
	for _, tx := range pendingTxs {
		finalCheckpoints := make([]string, 0, len(tx.SignedCheckpointTxs))
		for _, checkpoint := range tx.SignedCheckpointTxs {
			signedCheckpoint, err := signCheckpoint(checkpoint)
			if err != nil {
				return nil, fmt.Errorf("failed to sign checkpoint tx: %w", err)
			}
			finalCheckpoints = append(finalCheckpoints, signedCheckpoint)
		}

		if err := h.arkWallet.Client().FinalizeTx(ctx, tx.Txid, finalCheckpoints); err != nil {
			return nil, fmt.Errorf("failed to finalize tx %s: %w", tx.Txid, err)
		}

		txids = append(txids, tx.Txid)
	}

	return txids, nil
}

func (h *SwapHandler) finalizePendingClaimVHTLCTxs(
	ctx context.Context, vtxo clientTypes.Vtxo, vhtlcScript *vhtlc.VHTLCScript, preimage []byte,
) ([]string, error) {
	signCheckpoint := func(checkpoint string) (string, error) {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		if err != nil {
			return "", err
		}

		if err := txutils.SetArkPsbtField(
			ptx, 0, txutils.ConditionWitnessField, wire.TxWitness{preimage},
		); err != nil {
			return "", err
		}

		encoded, err := ptx.B64Encode()
		if err != nil {
			return "", err
		}

		return h.arkWallet.SignTransaction(ctx, encoded)
	}

	return h.finalizePendingVHTLCTxs(ctx, []pendingTxIntentInput{{
		Vtxo: clientTypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: vhtlcScript.GetRevealedTapscripts(),
		},
		Closure:          vhtlcScript.ClaimClosure,
		Sequence:         wire.MaxTxInSequenceNum,
		ConditionWitness: wire.TxWitness{preimage},
	}}, 0, signCheckpoint)
}

func (h *SwapHandler) finalizePendingRefundVHTLCTxs(
	ctx context.Context, vtxo clientTypes.Vtxo, vhtlcScript *vhtlc.VHTLCScript,
) ([]string, error) {
	signCheckpoint := func(checkpoint string) (string, error) {
		return h.arkWallet.SignTransaction(ctx, checkpoint)
	}

	return h.finalizePendingVHTLCTxs(ctx, []pendingTxIntentInput{{
		Vtxo: clientTypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: vhtlcScript.GetRevealedTapscripts(),
		},
		Closure:  vhtlcScript.RefundWithoutReceiverClosure,
		Sequence: wire.MaxTxInSequenceNum - 1,
	}}, uint32(vhtlcScript.RefundWithoutReceiverClosure.Locktime), signCheckpoint)
}
