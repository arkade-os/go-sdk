package arksdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

// musig2BatchSessionHandler implements the Musig2 methods
type musig2BatchSessionHandler struct {
	SweepClosure    script.CSVMultisigClosure
	SignerSession   tree.SignerSession
	TransportClient client.Client
}

func (h *musig2BatchSessionHandler) OnTreeSigningStarted(
	ctx context.Context, event client.TreeSigningStartedEvent, vtxoTree *tree.TxTree,
) (bool, error) {
	signerPubKey := h.SignerSession.GetPublicKey()
	if !slices.Contains(event.CosignersPubkeys, signerPubKey) {
		return true, nil
	}

	script, err := h.SweepClosure.Script()
	if err != nil {
		return false, fmt.Errorf("failed to get sweep closure script: %w", err)
	}

	commitmentTx, err := psbt.NewFromRawBytes(strings.NewReader(event.UnsignedCommitmentTx), true)
	if err != nil {
		return false, fmt.Errorf("failed to parse commitment tx: %w", err)
	}

	if len(commitmentTx.UnsignedTx.TxOut) == 0 {
		// no tree to sign, skip
		return true, nil
	}

	batchOutput := commitmentTx.UnsignedTx.TxOut[0]
	batchOutputAmount := batchOutput.Value

	sweepTapLeaf := txscript.NewBaseTapLeaf(script)
	sweepTapTree := txscript.AssembleTaprootScriptTree(sweepTapLeaf)
	root := sweepTapTree.RootNode.TapHash()

	if err := h.SignerSession.Init(root.CloneBytes(), batchOutputAmount, vtxoTree); err != nil {
		return false, err
	}

	nonces, err := h.SignerSession.GetNonces()
	if err != nil {
		return false, err
	}

	return false, h.TransportClient.SubmitTreeNonces(
		ctx,
		event.Id,
		h.SignerSession.GetPublicKey(),
		nonces,
	)
}

func (h *musig2BatchSessionHandler) OnTreeNonces(
	ctx context.Context, event client.TreeNoncesEvent,
) (bool, error) {
	hasAllNonces, err := h.SignerSession.AggregateNonces(event.Txid, event.Nonces)
	if err != nil {
		return false, err
	}

	if !hasAllNonces {
		return false, nil
	}

	sigs, err := h.SignerSession.Sign()
	if err != nil {
		return false, err
	}

	if err := h.TransportClient.SubmitTreeSignatures(
		ctx, event.Id, h.SignerSession.GetPublicKey(), sigs,
	); err != nil {
		return false, err
	}

	return true, nil
}

func (h *musig2BatchSessionHandler) OnTreeNoncesAggregated(
	ctx context.Context, event client.TreeNoncesAggregatedEvent,
) (bool, error) {
	return false, nil
}

// batchSessionArgs holds the shared state for VHTLC settlement operations.
// This struct encapsulates all the common setup data needed by both claim and refund paths.
type batchSessionArgs struct {
	vhtlcScript     *vhtlc.VHTLCScript
	totalAmount     uint64
	destinationAddr string
	signerSession   tree.SignerSession
	vtxos           []clientTypes.VtxoWithTapTree
}

type batchSessionHandler struct {
	musig2BatchSessionHandler
	arkWallet *wallet

	intentId       string
	vtxos          []clientTypes.VtxoWithTapTree
	vtxosToForfeit []clientTypes.VtxoWithTapTree
	receivers      []clientTypes.Receiver
	vhtlcScripts   map[string]*vhtlc.VHTLCScript
	config         clientTypes.Config

	batchSessionId string
}

func newBatchSessionHandler(
	arkClient *wallet,
	intentId string,
	vtxos []clientTypes.VtxoWithTapTree,
	receivers []clientTypes.Receiver,
	vhtlcScripts map[string]*vhtlc.VHTLCScript,
	config clientTypes.Config,
	signerSession tree.SignerSession,
) (*batchSessionHandler, error) {
	if arkClient.Client() == nil {
		return nil, fmt.Errorf("missing transport client")
	}
	if intentId == "" {
		return nil, fmt.Errorf("missing intent id")
	}
	if len(vtxos) <= 0 {
		return nil, fmt.Errorf("missing vtxos")
	}
	if len(receivers) <= 0 {
		return nil, fmt.Errorf("missing receivers")
	}
	if signerSession == nil {
		return nil, fmt.Errorf("missing signer session")
	}
	vtxosToForfeit := make([]clientTypes.VtxoWithTapTree, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if _, ok := vhtlcScripts[vtxo.Script]; !ok {
			return nil, fmt.Errorf("missing vhtlc script for vtxo %s", vtxo.Outpoint)
		}
		if !vtxo.IsRecoverable() {
			vtxosToForfeit = append(vtxosToForfeit, vtxo)
		}
	}

	return &batchSessionHandler{
		musig2BatchSessionHandler: musig2BatchSessionHandler{
			SignerSession:   signerSession,
			TransportClient: arkClient.Client(),
		},
		arkWallet:      arkClient,
		intentId:       intentId,
		vtxos:          vtxos,
		receivers:      receivers,
		vhtlcScripts:   vhtlcScripts,
		config:         config,
		vtxosToForfeit: vtxosToForfeit,
	}, nil
}

func (h *batchSessionHandler) OnStreamStarted(
	ctx context.Context, event client.StreamStartedEvent,
) error {
	return nil
}

func (h *batchSessionHandler) OnBatchStarted(
	ctx context.Context, event client.BatchStartedEvent,
) (bool, time.Duration, error) {
	buf := sha256.Sum256([]byte(h.intentId))
	hashedIntentId := hex.EncodeToString(buf[:])

	for _, id := range event.HashedIntentIds {
		if id == hashedIntentId {
			if err := h.TransportClient.ConfirmRegistration(ctx, h.intentId); err != nil {
				return false, -1, err
			}
			h.batchSessionId = event.Id
			batchExpiry := parseLocktime(uint32(event.BatchExpiry))
			h.SweepClosure = script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{h.config.ForfeitPubKey},
				},
				Locktime: batchExpiry,
			}
			log.Debugf("batch %s started with our intent %s", event.Id, h.intentId)
			return false, time.Duration(event.BatchExpiry) * time.Second, nil
		}
	}
	log.Debug("intent id not found in batch proposal, waiting for next one...")
	return true, -1, nil
}

func (h *batchSessionHandler) OnBatchFinalized(
	ctx context.Context, event client.BatchFinalizedEvent,
) error {
	if event.Id == h.batchSessionId {
		log.Debugf("batch completed in commitment tx %s", event.Txid)
	}
	return nil
}

func (h *batchSessionHandler) OnBatchFailed(
	ctx context.Context, event client.BatchFailedEvent,
) error {
	return fmt.Errorf("batch failed: %s", event.Reason)
}

func (h *batchSessionHandler) OnTreeTxEvent(
	ctx context.Context, event client.TreeTxEvent,
) error {
	return nil
}

func (h *batchSessionHandler) OnTreeSignatureEvent(
	ctx context.Context, event client.TreeSignatureEvent,
) error {
	return nil
}

func (h *batchSessionHandler) createAndSignForfeits(
	ctx context.Context, connectorsLeaves []*psbt.Packet, builder forfeitTxBuilder,
) ([]string, error) {
	parsedForfeitAddr, err := btcutil.DecodeAddress(h.config.ForfeitAddress, nil)
	if err != nil {
		return nil, err
	}

	forfeitPkScript, err := txscript.PayToAddrScript(parsedForfeitAddr)
	if err != nil {
		return nil, err
	}

	if len(connectorsLeaves) != len(h.vtxosToForfeit) {
		return nil, fmt.Errorf(
			"insufficient connectors: got %d, need %d",
			len(connectorsLeaves),
			len(h.vtxosToForfeit),
		)
	}

	signedForfeitTxs := make([]string, 0, len(h.vtxosToForfeit))
	for i, vtxo := range h.vtxosToForfeit {
		connectorTx := connectorsLeaves[i]

		connector, connectorOutpoint, err := extractConnector(connectorTx)
		if err != nil {
			return nil, fmt.Errorf(
				"connector not found for vtxo %s: %w",
				vtxo.Outpoint.String(),
				err,
			)
		}

		vhtlcScript := h.vhtlcScripts[vtxo.Script]
		_, vtxoTapTree, err := vhtlcScript.TapTree()
		if err != nil {
			return nil, err
		}

		signingClosure := builder.getSigningClosure(vhtlcScript)

		signingScript, err := signingClosure.Script()
		if err != nil {
			return nil, err
		}

		signingLeaf := txscript.NewBaseTapLeaf(signingScript)
		proof, err := vtxoTapTree.GetTaprootMerkleProof(signingLeaf.TapHash())
		if err != nil {
			return nil, fmt.Errorf("failed to get taproot merkle proof for settlement: %w", err)
		}

		tapscript := &psbt.TaprootTapLeafScript{
			ControlBlock: proof.ControlBlock,
			Script:       proof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}

		vtxoLocktime, vtxoSequence := extractLocktimeAndSequence(signingClosure)

		forfeitTx, err := builder.buildTx(
			vtxo, tapscript, connector, connectorOutpoint,
			vtxoLocktime, vtxoSequence, forfeitPkScript,
		)
		if err != nil {
			return nil, err
		}

		signedForfeitTx, err := h.arkWallet.SignTransaction(ctx, forfeitTx)
		if err != nil {
			return nil, fmt.Errorf("failed to sign forfeit: %w", err)
		}

		signedForfeitTxs = append(signedForfeitTxs, signedForfeitTx)
	}

	return signedForfeitTxs, nil
}

// settleBatchSessionHandler handles joining a batch session to redeem a vhtlc, either via the
// claim or the refund path depending on the given forfeit tx builder.
type settleBatchSessionHandler struct {
	batchSessionHandler
	builder forfeitTxBuilder
}

func newSettleBatchSessionHandler(
	arkClient *wallet,
	intentId string,
	vtxos []clientTypes.VtxoWithTapTree,
	receivers []clientTypes.Receiver,
	builder forfeitTxBuilder,
	vhtlcScripts map[string]*vhtlc.VHTLCScript,
	config clientTypes.Config,
	signerSession tree.SignerSession,
) (*settleBatchSessionHandler, error) {
	if builder == nil {
		return nil, fmt.Errorf("missing forfeit tx builder")
	}
	handler, err := newBatchSessionHandler(
		arkClient, intentId, vtxos, receivers, vhtlcScripts, config, signerSession,
	)
	if err != nil {
		return nil, err
	}

	return &settleBatchSessionHandler{
		batchSessionHandler: *handler,
		builder:             builder,
	}, nil
}

func (h *settleBatchSessionHandler) OnBatchFinalization(
	ctx context.Context, event client.BatchFinalizationEvent, vtxoTree, connectorTree *tree.TxTree,
) ([]string, error) {
	if connectorTree == nil {
		if len(h.vtxosToForfeit) > 0 {
			return nil, fmt.Errorf("connector tree is nil")
		}
		// All vtxos expired, nothing to do
		return nil, nil
	}

	forfeits, err := h.createAndSignForfeits(ctx, connectorTree.Leaves(), h.builder)
	if err != nil {
		return nil, fmt.Errorf("failed to create and sign forfeits: %w", err)
	}

	if len(forfeits) > 0 {
		if err := h.TransportClient.SubmitSignedForfeitTxs(ctx, forfeits, ""); err != nil {
			return nil, fmt.Errorf("failed to submit signed forfeits: %w", err)
		}
	}

	return forfeits, nil
}

type forfeitTxBuilder interface {
	buildTx(
		vtxo clientTypes.VtxoWithTapTree, signingPath *psbt.TaprootTapLeafScript,
		connector *wire.TxOut, connectorOutpoint *wire.OutPoint,
		vtxoLocktime arklib.AbsoluteLocktime, vtxoSequence uint32,
		forfeitPkScript []byte,
	) (string, error)
	getSigningClosure(vhtlcScript *vhtlc.VHTLCScript) script.Closure
}

type claimForfeitTxBuilder struct {
	preimage []byte
}

func (b *claimForfeitTxBuilder) buildTx(
	vtxo clientTypes.VtxoWithTapTree, tapscript *psbt.TaprootTapLeafScript,
	connector *wire.TxOut, connectorOutpoint *wire.OutPoint,
	vtxoLocktime arklib.AbsoluteLocktime, vtxoSequence uint32,
	forfeitPkScript []byte,
) (string, error) {
	tx, err := buildForfeitTx(
		vtxo, tapscript, connector, connectorOutpoint,
		vtxoLocktime, vtxoSequence, forfeitPkScript,
	)
	if err != nil {
		return "", err
	}
	if err := txutils.SetArkPsbtField(
		tx, 0, txutils.ConditionWitnessField, wire.TxWitness{b.preimage},
	); err != nil {
		return "", fmt.Errorf("failed to inject preimage: %w", err)
	}

	txStr, err := tx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode forfeit tx: %w", err)
	}
	return txStr, nil
}

func (b *claimForfeitTxBuilder) getSigningClosure(vhtlcScript *vhtlc.VHTLCScript) script.Closure {
	return vhtlcScript.ClaimClosure
}

type refundForfeitTxBuilder struct {
	withReceiver bool
}

func (b *refundForfeitTxBuilder) buildTx(
	vtxo clientTypes.VtxoWithTapTree, tapscript *psbt.TaprootTapLeafScript,
	connector *wire.TxOut, connectorOutpoint *wire.OutPoint,
	vtxoLocktime arklib.AbsoluteLocktime, vtxoSequence uint32,
	forfeitPkScript []byte,
) (string, error) {
	tx, err := buildForfeitTx(
		vtxo, tapscript, connector, connectorOutpoint,
		vtxoLocktime, vtxoSequence, forfeitPkScript,
	)
	if err != nil {
		return "", err
	}

	txStr, err := tx.B64Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode forfeit tx: %w", err)
	}
	return txStr, nil
}

func (b *refundForfeitTxBuilder) getSigningClosure(vhtlcScript *vhtlc.VHTLCScript) script.Closure {
	if b.withReceiver {
		return vhtlcScript.RefundClosure
	}
	return vhtlcScript.RefundWithoutReceiverClosure
}

func extractConnector(connectorTx *psbt.Packet) (*wire.TxOut, *wire.OutPoint, error) {
	for outIndex, output := range connectorTx.UnsignedTx.TxOut {
		if bytes.Equal(txutils.ANCHOR_PKSCRIPT, output.PkScript) {
			continue
		}

		return output, &wire.OutPoint{
			Hash:  connectorTx.UnsignedTx.TxHash(),
			Index: uint32(outIndex),
		}, nil
	}

	return nil, nil, fmt.Errorf("connector output not found")
}

func buildForfeitTx(
	vtxo clientTypes.VtxoWithTapTree, signingPath *psbt.TaprootTapLeafScript,
	connector *wire.TxOut, connectorOutpoint *wire.OutPoint,
	vtxoLocktime arklib.AbsoluteLocktime, vtxoSequence uint32,
	outScript []byte,
) (*psbt.Packet, error) {
	vtxoOutputScript, err := hex.DecodeString(vtxo.Script)
	if err != nil {
		return nil, fmt.Errorf("invalid vtxo script: %w", err)
	}

	vtxoTxHash, err := chainhash.NewHashFromStr(vtxo.Txid)
	if err != nil {
		return nil, fmt.Errorf("invalid vtxo txid: %w", err)
	}

	inputs := []*wire.OutPoint{{
		Hash:  *vtxoTxHash,
		Index: vtxo.VOut,
	}, connectorOutpoint}
	sequences := []uint32{vtxoSequence, wire.MaxTxInSequenceNum}
	prevouts := []*wire.TxOut{{
		Value:    int64(vtxo.Amount),
		PkScript: vtxoOutputScript,
	}, connector}

	tx, err := tree.BuildForfeitTx(inputs, sequences, prevouts, outScript, uint32(vtxoLocktime))
	if err != nil {
		return nil, fmt.Errorf("failed to build forfeit tx: %w", err)
	}

	tx.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{signingPath}
	return tx, nil
}
