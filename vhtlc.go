package arksdk

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/offchain"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/ccoveille/go-safecast"
	log "github.com/sirupsen/logrus"
)

// ErrNoVtxosFound is returned by the VHTLC APIs when the contract exists but has no vtxos
// funding it yet. Callers can match it with errors.Is to poll until funds land.
var ErrNoVtxosFound = fmt.Errorf("no vtxos found for vhtlc contract")

func (w *wallet) CreateVHTLC(
	ctx context.Context, args contract.VHTLCContractArgs,
) (*vhtlc.VHTLCScript, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	contractType := types.ContractTypeVHTLC
	if args.NonInteractiveEmulator != nil && args.NonInteractiveReceiver != nil {
		contractType = types.ContractTypeNonInteractiveVHTLC
	}

	contract, err := w.contractManager.NewContract(ctx, contractType, contract.WithParams(args))
	if err != nil {
		return nil, err
	}

	return w.vhtlcScript(ctx, *contract)
}

// ListVHTLC returns the vhtlc contracts tracked by the wallet, optionally filtered by script
// with the WithScript option.
func (w *wallet) ListVHTLCs(
	ctx context.Context, opts ...VHTLCOption,
) ([]vhtlc.VHTLCScript, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	o := defaultVhtlcOpts()
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}

	var contracts []types.Contract
	if len(o.scripts) > 0 {
		found, err := w.contractManager.GetContracts(
			ctx, contract.WithScripts(o.scripts),
		)
		if err != nil {
			return nil, err
		}
		contracts = found
	} else {
		for _, contractType := range []types.ContractType{
			types.ContractTypeVHTLC, types.ContractTypeNonInteractiveVHTLC,
		} {
			found, err := w.contractManager.GetContracts(ctx, contract.WithType(contractType))
			if err != nil {
				return nil, err
			}
			contracts = append(contracts, found...)
		}
	}

	vhtlcs := make([]vhtlc.VHTLCScript, 0, len(contracts))
	for _, vhtlcContract := range contracts {
		// Skip anything that is not a vhtlc, eg. when filtering by the script of another
		// contract type.
		if vhtlcContract.Type != types.ContractTypeVHTLC &&
			vhtlcContract.Type != types.ContractTypeNonInteractiveVHTLC {
			continue
		}

		script, err := w.vhtlcScript(ctx, vhtlcContract)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to rebuild vhtlc script for contract %s: %w", vhtlcContract.Script, err,
			)
		}
		vhtlcs = append(vhtlcs, *script)
	}
	return vhtlcs, nil
}

func (w *wallet) ClaimVHTLC(
	ctx context.Context, vhtlcScript string, preimage vhtlc.Preimage, opts ...VHTLCOption,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	spend, err := w.resolveVHTLCSpend(ctx, vhtlcScript, opts)
	if err != nil {
		return "", err
	}
	if !spend.isReceiver {
		return "", fmt.Errorf(
			"vhtlc %s cannot be claimed by us, we can only refund it", vhtlcScript,
		)
	}

	// Fail fast if the preimage doesn't match the contract's hash, instead of hitting an
	// obscure server error at submit time.
	if err := preimage.Validate(); err != nil {
		return "", err
	}
	_, preimageHash := preimage.Hash()
	if !bytes.Equal(preimageHash, spend.vhtlcOpts.PreimageHash) {
		return "", fmt.Errorf(
			"invalid preimage hash: got %x, expected %x",
			spend.vhtlcOpts.PreimageHash, preimageHash,
		)
	}

	if txid, done, err := w.redeemPendingOrRecoverableVHTLC(
		ctx, spend, preimage,
	); done || err != nil {
		return txid, err
	}

	claimTapscript, err := spend.vHTLC.ClaimTapscript()
	if err != nil {
		return "", err
	}

	arkTx, checkpoints, err := w.buildVHTLCSpendTxs(ctx, spend, claimTapscript)
	if err != nil {
		return "", err
	}

	// The claim path requires revealing the preimage as condition witness.
	signTransaction := func(tx *psbt.Packet) (string, error) {
		return w.signPacket(ctx, tx, wire.TxWitness{preimage})
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

	arkTxid, finalArkTx, signedCheckpoints, err := w.Client().SubmitTx(
		ctx, signedArkTx, checkpointTxs,
	)
	if err != nil {
		return "", err
	}

	if err := verifyFinalArkTx(finalArkTx, spend.signerKey, getInputTapLeaves(arkTx)); err != nil {
		return "", err
	}

	finalCheckpoints, err := verifyAndSignCheckpoints(
		signedCheckpoints, checkpoints, spend.signerKey, signTransaction,
	)
	if err != nil {
		return "", err
	}

	if err := w.Client().FinalizeTx(ctx, arkTxid, finalCheckpoints); err != nil {
		return "", err
	}

	return arkTxid, nil
}

func (w *wallet) RefundVHTLC(
	ctx context.Context, vhtlcScript string, opts ...VHTLCOption,
) (string, string, error) {
	if err := w.safeCheck(); err != nil {
		return "", "", err
	}

	spend, err := w.resolveVHTLCSpend(ctx, vhtlcScript, opts)
	if err != nil {
		return "", "", err
	}
	if spend.isReceiver {
		return "", "", fmt.Errorf(
			"vhtlc %s cannot be refunded by us, we can only claim it", vhtlcScript,
		)
	}

	if txid, done, err := w.redeemPendingOrRecoverableVHTLC(ctx, spend, nil); done || err != nil {
		return txid, "", err
	}

	// The refund path requires the receiver's signature: return both txs signed by us only, the
	// caller is in charge of collecting the counterparty's signature and finalizing the refund.
	_, _, signedRefundTx, signedCheckpointTx, err := w.buildAndSignRefundTxs(ctx, spend, true)
	if err != nil {
		return "", "", err
	}

	return signedRefundTx, signedCheckpointTx, nil
}

func (w *wallet) UnilateralRefundVHTLC(
	ctx context.Context, vhtlcScript string, opts ...VHTLCOption,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	spend, err := w.resolveVHTLCSpend(ctx, vhtlcScript, opts)
	if err != nil {
		return "", err
	}
	if spend.isReceiver {
		return "", fmt.Errorf(
			"vhtlc %s cannot be refunded by us, we can only claim it", vhtlcScript,
		)
	}

	if txid, done, err := w.redeemPendingOrRecoverableVHTLC(ctx, spend, nil); done || err != nil {
		return txid, err
	}

	refundTx, checkpointPtx, signedRefundTx, signedCheckpointTx, err := w.buildAndSignRefundTxs(
		ctx, spend, false,
	)
	if err != nil {
		return "", err
	}

	unsignedCheckpointTx, err := checkpointPtx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode unsigned refund checkpoint tx: %s", err)
	}

	signedCheckpointPsbt, err := psbt.NewFromRawBytes(strings.NewReader(signedCheckpointTx), true)
	if err != nil {
		return "", fmt.Errorf("failed to decode checkpoint tx signed by us: %s", err)
	}

	arkTxid, finalRefundTx, serverSignedCheckpoints, err := w.Client().SubmitTx(
		ctx, signedRefundTx, []string{unsignedCheckpointTx},
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
		return "", fmt.Errorf("failed to decode checkpoint tx signed by server: %s", err)
	}

	pubKeysToVerify := []*btcec.PublicKey{spend.vhtlcOpts.Sender, spend.vhtlcOpts.Server}

	if err := verifySignatures(
		[]*psbt.Packet{finalRefundPtx}, pubKeysToVerify, getInputTapLeaves(refundTx),
	); err != nil {
		return "", err
	}

	// combine checkpoint transactions
	finalCheckpointPtx, err := combineTapscripts(
		[]*psbt.Packet{signedCheckpointPsbt, serverCheckpointPtx},
	)
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

	if err := w.Client().FinalizeTx(
		ctx, arkTxid, []string{finalCheckpointTx},
	); err != nil {
		return "", fmt.Errorf("failed to finalize refund tx: %w", err)
	}

	return arkTxid, nil
}

func (w *wallet) DeleteVHTLCs(ctx context.Context, scripts []string) error {
	if err := w.safeCheck(); err != nil {
		return err
	}
	return w.store.ContractStore().DisableContracts(ctx, scripts)
}

// vhtlcSpendContext gathers everything needed to spend a vhtlc vtxo: the contract data, the
// reconstructed vhtlc script and the selected vtxo.
type vhtlcSpendContext struct {
	vHTLC              *vhtlc.VHTLCScript
	vhtlcOpts          vhtlc.Opts
	checkpointExitPath []byte
	signerKey          *btcec.PublicKey
	vtxo               *clienttypes.Vtxo
	pending            bool
	isReceiver         bool
}

// resolveVHTLCSpend fetches the vhtlc contract matching the given script, rebuilds the vhtlc
// script from its args and selects the vtxo to spend, either the one given as option or the
// oldest funding the contract.
func (w *wallet) resolveVHTLCSpend(
	ctx context.Context, vhtlcScript string, opts []VHTLCOption,
) (*vhtlcSpendContext, error) {
	o := defaultVhtlcOpts()
	for _, opt := range opts {
		if err := opt(o); err != nil {
			return nil, err
		}
	}

	scripts := []string{vhtlcScript}
	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, fmt.Errorf("failed to get vhtlc contract %s: %w", scripts[0], err)
	}
	if len(contracts) <= 0 {
		return nil, fmt.Errorf("vhtlc contract %s not found", scripts[0])
	}
	vhtlcContract := contracts[0]

	handler, err := w.contractManager.GetHandler(ctx, vhtlcContract)
	if err != nil {
		return nil, err
	}
	checkpointExitPath, err := handler.GetCheckpointExitPath(vhtlcContract)
	if err != nil {
		return nil, err
	}
	signerKey, err := handler.GetSignerKey(vhtlcContract)
	if err != nil {
		return nil, err
	}

	vHTLC, err := w.vhtlcScript(ctx, vhtlcContract)
	if err != nil {
		return nil, err
	}

	vtxo, pending, err := w.selectClaimableVTXO(ctx, vhtlcContract.Script, o.outpoint)
	if err != nil {
		return nil, err
	}

	args, err := handler.GetArgs(vhtlcContract)
	if err != nil {
		return nil, err
	}
	parsed, ok := args.(vhtlchandler.ContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type: got %T, expected %T",
			args, vhtlchandler.ContractArgs{},
		)
	}

	return &vhtlcSpendContext{
		vHTLC:              vHTLC,
		vhtlcOpts:          vHTLC.Opts(),
		checkpointExitPath: checkpointExitPath,
		signerKey:          signerKey,
		vtxo:               vtxo,
		pending:            pending,
		isReceiver:         len(parsed.ReceiverKeyId) > 0,
	}, nil
}

// redeemPendingOrRecoverableVHTLC handles the vtxos that can't be spent with a direct offchain
// tx: pending ones are finalized, while recoverable (swept) ones are settled within a batch
// session. A nil preimage selects the refund path, otherwise the claim one is used.
// It returns false if the vtxo is spendable and the caller can proceed with the direct spend.
func (w *wallet) redeemPendingOrRecoverableVHTLC(
	ctx context.Context, spend *vhtlcSpendContext, preimage vhtlc.Preimage,
) (string, bool, error) {
	if spend.pending {
		var txids []string
		var err error
		if preimage != nil {
			txids, err = w.finalizePendingClaimVHTLCTxs(ctx, *spend.vtxo, spend.vHTLC, preimage)
		} else {
			txids, err = w.finalizePendingRefundVHTLCTxs(ctx, *spend.vtxo, spend.vHTLC)
		}
		if err != nil {
			return "", true, fmt.Errorf("failed to finalize pending txs: %w", err)
		}
		if len(txids) <= 0 {
			return "", true, fmt.Errorf("vtxo is pending but no pending txs found to finalize")
		}
		return txids[0], true, nil
	}

	// If the vtxo expired or was swept, it can't be spent with an offchain tx anymore, redeem
	// it within a batch session instead.
	if spend.vtxo.IsRecoverable() {
		if spend.vtxo.Amount < w.dustAmount {
			return "", true, fmt.Errorf(
				"cannot redeem recoverable vhtlc vtxo %s: amount %d is below dust %d",
				spend.vtxo.Outpoint, spend.vtxo.Amount, w.dustAmount,
			)
		}

		txid, err := w.settleVHTLC(ctx, spend, preimage)
		if err != nil {
			return "", true, fmt.Errorf("failed to settle recoverable vhtlc: %w", err)
		}

		log.Infof("recoverable vhtlc settled in round %s", txid)
		return txid, true, nil
	}

	return "", false, nil
}

// buildVHTLCSpendTxs builds the ark and checkpoint txs spending the selected vhtlc vtxo with the
// given tapscript, sending the whole amount to a fresh offchain address of ours.
func (w *wallet) buildVHTLCSpendTxs(
	ctx context.Context, spend *vhtlcSpendContext, tapscript *waddrmgr.Tapscript,
) (*psbt.Packet, []*psbt.Packet, error) {
	vtxoTxHash, err := chainhash.NewHashFromStr(spend.vtxo.Txid)
	if err != nil {
		return nil, nil, err
	}

	// self send output
	myAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return nil, nil, err
	}

	decodedAddr, err := arklib.DecodeAddressV0(myAddr)
	if err != nil {
		return nil, nil, err
	}

	pkScript, err := decodedAddr.GetPkScript()
	if err != nil {
		return nil, nil, err
	}

	amount, err := safecast.Convert[int64](spend.vtxo.Amount)
	if err != nil {
		return nil, nil, err
	}

	return offchain.BuildTxs(
		[]offchain.VtxoInput{
			{
				RevealedTapscripts: spend.vHTLC.GetRevealedTapscripts(),
				Outpoint: &wire.OutPoint{
					Hash:  *vtxoTxHash,
					Index: spend.vtxo.VOut,
				},
				Amount:    amount,
				Tapscript: tapscript,
			},
		},
		[]*wire.TxOut{
			{
				Value:    amount,
				PkScript: pkScript,
			},
		},
		spend.checkpointExitPath,
	)
}

// buildAndSignRefundTxs builds the refund and checkpoint txs spending the selected vhtlc vtxo
// with the refund path (with or without receiver) and signs them with our key only.
func (w *wallet) buildAndSignRefundTxs(
	ctx context.Context, spend *vhtlcSpendContext, withReceiver bool,
) (*psbt.Packet, *psbt.Packet, string, string, error) {
	refundTapscript, err := spend.vHTLC.RefundTapscript(withReceiver)
	if err != nil {
		return nil, nil, "", "", err
	}

	refundTx, checkpointPtxs, err := w.buildVHTLCSpendTxs(ctx, spend, refundTapscript)
	if err != nil {
		return nil, nil, "", "", err
	}

	if len(checkpointPtxs) != 1 {
		return nil, nil, "", "", fmt.Errorf(
			"failed to build refund tx: expected 1 checkpoint tx got %d", len(checkpointPtxs),
		)
	}

	signedRefundTx, err := w.signPacket(ctx, refundTx, nil)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to sign refund tx: %s", err)
	}
	signedCheckpointTx, err := w.signPacket(ctx, checkpointPtxs[0], nil)
	if err != nil {
		return nil, nil, "", "", fmt.Errorf("failed to sign refund checkpoint tx: %s", err)
	}

	return refundTx, checkpointPtxs[0], signedRefundTx, signedCheckpointTx, nil
}

// settleVHTLC redeems a recoverable (swept) vhtlc vtxo within a batch session, using the claim
// path (revealing the preimage) if preimage is not nil, or the refund without receiver path
// otherwise.
func (w *wallet) settleVHTLC(
	ctx context.Context, spend *vhtlcSpendContext, preimage []byte,
) (string, error) {
	if preimage != nil {
		if err := validatePreimage(preimage, spend.vhtlcOpts.PreimageHash); err != nil {
			return "", err
		}
	}

	cfgData, err := w.GetConfigData(ctx)
	if err != nil {
		return "", err
	}

	myAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get offchain address: %w", err)
	}

	signerSession, err := w.Identity().NewVtxoTreeSigner(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create ephemeral signer session: %w", err)
	}

	session := &batchSessionArgs{
		vhtlcScript:     spend.vHTLC,
		totalAmount:     spend.vtxo.Amount,
		destinationAddr: myAddr,
		signerSession:   signerSession,
		vtxos: []clienttypes.VtxoWithTapTree{{
			Vtxo:       *spend.vtxo,
			Tapscripts: spend.vHTLC.GetRevealedTapscripts(),
		}},
	}

	proof, message, err := getSettleIntent(session, preimage)
	if err != nil {
		return "", fmt.Errorf("failed to build settle intent: %w", err)
	}

	signedProof, err := w.SignTransaction(ctx, proof)
	if err != nil {
		return "", fmt.Errorf("failed to sign intent proof: %w", err)
	}

	intentID, err := w.Client().RegisterIntent(ctx, signedProof, message)
	if err != nil {
		return "", fmt.Errorf("failed to register vhtlc settle intent: %w", err)
	}

	outpoints := make([]clienttypes.Outpoint, 0, len(session.vtxos))
	for _, vtxo := range session.vtxos {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	topics := clientlib.GetEventStreamTopics(outpoints, []tree.SignerSession{signerSession})
	eventsCh, cancel, err := w.Client().GetEventStream(ctx, topics)
	if err != nil {
		return "", fmt.Errorf("failed to get event stream: %w", err)
	}
	defer cancel()

	var builder forfeitTxBuilder = &refundForfeitTxBuilder{withReceiver: false}
	if preimage != nil {
		builder = &claimForfeitTxBuilder{preimage: preimage}
	}

	handler, err := newSettleBatchSessionHandler(
		w,
		intentID,
		session.vtxos,
		[]clienttypes.Receiver{{To: session.destinationAddr, Amount: session.totalAmount}},
		builder,
		map[string]*vhtlc.VHTLCScript{session.vtxos[0].Script: session.vhtlcScript},
		*cfgData,
		signerSession,
	)
	if err != nil {
		return "", fmt.Errorf("failed to setup batch session handler: %w", err)
	}

	txid, _, _, _, _, err := clientlib.JoinBatchSession(ctx, eventsCh, handler)
	if err != nil {
		return "", fmt.Errorf("batch session failed: %w", err)
	}

	log.Debugf("successfully settled vhtlc in round %s", txid)
	return txid, nil
}

// signPacket signs the given tx with the wallet, optionally setting the given condition witness
// on the first input beforehand.
func (w *wallet) signPacket(
	ctx context.Context, tx *psbt.Packet, conditionWitness wire.TxWitness,
) (string, error) {
	if len(conditionWitness) > 0 {
		if err := txutils.SetArkPsbtField(
			tx, 0, txutils.ConditionWitnessField, conditionWitness,
		); err != nil {
			return "", err
		}
	}

	encoded, err := tx.B64Encode()
	if err != nil {
		return "", err
	}

	return w.SignTransaction(ctx, encoded)
}

func (w *wallet) vhtlcScript(
	ctx context.Context, contract types.Contract,
) (*vhtlc.VHTLCScript, error) {
	handler, err := w.contractManager.GetHandler(ctx, contract)
	if err != nil {
		return nil, err
	}

	contractArgs, err := handler.GetArgs(contract)
	if err != nil {
		return nil, err
	}

	if contract.Type == types.ContractTypeNonInteractiveVHTLC {
		parsed, ok := contractArgs.(vhtlchandler.NonInteractiveContractArgs)
		if !ok {
			return nil, fmt.Errorf(
				"invalid contract args type: got %T, expected %T",
				contractArgs, vhtlchandler.NonInteractiveContractArgs{},
			)
		}

		return vhtlc.NewVHTLCScriptFromOpts(vhtlc.Opts{
			Sender:                               parsed.Sender,
			Receiver:                             parsed.Receiver,
			Server:                               parsed.Signer,
			PreimageHash:                         parsed.PreimageHash,
			RefundLocktime:                       parsed.RefundLocktime,
			UnilateralClaimDelay:                 parsed.UnilateralClaimDelay,
			UnilateralRefundDelay:                parsed.UnilateralRefundDelay,
			UnilateralRefundWithoutReceiverDelay: parsed.UnilateralRefundWithoutReceiverDelay,
			NonInteractiveClaim: &vhtlc.NonInteractiveClaimOpts{
				ReceiverPkScript: parsed.NonInteractiveReceiver,
				EmulatorPubKey:   parsed.NonInteractiveEmulator,
			},
		})
	}

	parsed, ok := contractArgs.(vhtlchandler.ContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type: got %T, expected %T",
			contractArgs, vhtlchandler.ContractArgs{},
		)
	}

	return vhtlc.NewVHTLCScriptFromOpts(vhtlc.Opts{
		Sender:                               parsed.Sender,
		Receiver:                             parsed.Receiver,
		Server:                               parsed.Signer,
		PreimageHash:                         parsed.PreimageHash,
		RefundLocktime:                       parsed.RefundLocktime,
		UnilateralClaimDelay:                 parsed.UnilateralClaimDelay,
		UnilateralRefundDelay:                parsed.UnilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: parsed.UnilateralRefundWithoutReceiverDelay,
	})
}

func (w *wallet) selectClaimableVTXO(
	ctx context.Context, vhtlcScript string, outpoint *clienttypes.Outpoint,
) (*clienttypes.Vtxo, bool, error) {
	spendableVtxos, err := w.getVHTLCFunds(ctx, []string{vhtlcScript})
	if err != nil {
		return nil, false, err
	}

	pendingVtxos, err := w.getVHTLCFunds(ctx, []string{vhtlcScript}, indexer.WithPendingOnly())
	if err != nil {
		return nil, false, err
	}

	if len(spendableVtxos) == 0 && len(pendingVtxos) == 0 {
		return nil, false, ErrNoVtxosFound
	}

	pendingByOutpoint := make(map[string]bool)
	candidateVtxos := make([]clienttypes.Vtxo, 0, len(spendableVtxos)+len(pendingVtxos))
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
		return nil, false, ErrNoVtxosFound
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

func (w *wallet) fetchPendingVHTLCTxs(
	ctx context.Context,
	inputs []pendingTxIntentInput, locktime uint32, signCheckpoint func(string) (string, error),
) ([]client.AcceptedOffchainTx, error) {
	proof, message, err := getPendingTxIntent(inputs, locktime)
	if err != nil {
		return nil, err
	}

	signedProof, err := w.SignTransaction(ctx, proof)
	if err != nil {
		return nil, fmt.Errorf("failed to sign pending tx proof: %w", err)
	}

	pendingTxs, err := w.Client().GetPendingTx(ctx, signedProof, message)
	if err != nil {
		return nil, err
	}

	txs := make([]client.AcceptedOffchainTx, 0, len(pendingTxs))
	for _, tx := range pendingTxs {
		checkpointTxs := make([]string, 0, len(tx.SignedCheckpointTxs))
		for _, checkpoint := range tx.SignedCheckpointTxs {
			signedCheckpoint, err := signCheckpoint(checkpoint)
			if err != nil {
				return nil, fmt.Errorf("failed to sign checkpoint tx: %w", err)
			}
			checkpointTxs = append(checkpointTxs, signedCheckpoint)
		}
		txs = append(txs, client.AcceptedOffchainTx{
			Txid:                tx.Txid,
			FinalArkTx:          tx.FinalArkTx,
			SignedCheckpointTxs: checkpointTxs,
		})
	}
	return txs, nil
}

func (w *wallet) finalizePendingVHTLCTxs(
	ctx context.Context,
	inputs []pendingTxIntentInput, locktime uint32, signCheckpoint func(string) (string, error),
) ([]string, error) {
	pendingTxs, err := w.fetchPendingVHTLCTxs(ctx, inputs, locktime, signCheckpoint)
	if err != nil {
		return nil, err
	}

	txids := make([]string, 0, len(pendingTxs))
	for _, tx := range pendingTxs {
		if err := w.Client().FinalizeTx(ctx, tx.Txid, tx.SignedCheckpointTxs); err != nil {
			return nil, fmt.Errorf("failed to finalize tx %s: %w", tx.Txid, err)
		}
		txids = append(txids, tx.Txid)
	}
	return txids, nil
}

func (w *wallet) finalizePendingClaimVHTLCTxs(
	ctx context.Context, vtxo clienttypes.Vtxo, vhtlcScript *vhtlc.VHTLCScript, preimage []byte,
) ([]string, error) {
	signCheckpoint := func(checkpoint string) (string, error) {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(checkpoint), true)
		if err != nil {
			return "", err
		}
		return w.signPacket(ctx, ptx, wire.TxWitness{preimage})
	}

	return w.finalizePendingVHTLCTxs(ctx, []pendingTxIntentInput{{
		Vtxo: clienttypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: vhtlcScript.GetRevealedTapscripts(),
		},
		Closure:          vhtlcScript.ClaimClosure,
		Sequence:         wire.MaxTxInSequenceNum,
		ConditionWitness: wire.TxWitness{preimage},
	}}, 0, signCheckpoint)
}

func (w *wallet) finalizePendingRefundVHTLCTxs(
	ctx context.Context, vtxo clienttypes.Vtxo, vhtlcScript *vhtlc.VHTLCScript,
) ([]string, error) {
	signCheckpoint := func(checkpoint string) (string, error) {
		return w.SignTransaction(ctx, checkpoint)
	}

	return w.finalizePendingVHTLCTxs(ctx, []pendingTxIntentInput{{
		Vtxo: clienttypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: vhtlcScript.GetRevealedTapscripts(),
		},
		Closure:  vhtlcScript.RefundWithoutReceiverClosure,
		Sequence: wire.MaxTxInSequenceNum - 1,
	}}, uint32(vhtlcScript.RefundWithoutReceiverClosure.Locktime), signCheckpoint)
}

func (w *wallet) getVHTLCFunds(
	ctx context.Context, vhtlcScripts []string, opts ...indexer.GetVtxosOption,
) ([]clienttypes.Vtxo, error) {
	opts = append(opts, indexer.WithScripts(vhtlcScripts))
	resp, err := w.Indexer().GetVtxos(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return resp.Vtxos, nil
}
