package swap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	log "github.com/sirupsen/logrus"
)

func (h *SwapManager) ArkadeToBtcChainSwap(
	ctx context.Context, btcAddress string, amount uint64,
) (*swaptypes.Swap, error) {
	claimKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral claim key for HTLC: %w", err)
	}

	keyProvider := h.wallet.Identity()
	contractManager := h.wallet.ContractManager()
	handler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	if err != nil {
		return nil, err
	}
	h.contractMu.Lock()
	unlockContractMu := sync.OnceFunc(h.contractMu.Unlock)
	defer unlockContractMu()

	keyRef, err := h.getNewKey(ctx, handler)
	if err != nil {
		return nil, fmt.Errorf("failed to get new key: %w", err)
	}

	// If the identity supports schnorr signing, use it to generate a deterministic preimage,
	// otherwise use a random preimage
	preimageSigner, ok := keyProvider.(PreimageSigner)
	persistPreimage := ok
	var preimage vhtlc.Preimage
	if ok {
		preimage, err = DerivePreimage(ctx, preimageSigner, *keyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to generate deterministic preimage: %w", err)
		}
	} else {
		preimage = make([]byte, 32)
		if _, err := rand.Read(preimage); err != nil {
			return nil, fmt.Errorf("failed to generate random preimage: %w", err)
		}
	}

	preimageHashSHA256, preimageHashHASH160 := preimage.Hash()

	swapResp, err := h.boltzSvc.CreateChainSwap(boltz.CreateChainSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		PreimageHash:    hex.EncodeToString(preimageHashSHA256),
		ClaimPublicKey:  hex.EncodeToString(claimKey.PubKey().SerializeCompressed()),
		RefundPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		UserLockAmount:  amount,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create chain swap with Boltz: %w", err)
	}

	receiverPubkey, err := parsePubkey(swapResp.LockupDetails.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid claim pubkey: %v", err)
	}

	contract, err := handler.NewContract(ctx, vhtlchandler.ContractArgs{
		SenderKeyId:    keyRef.Id,
		Sender:         keyRef.PubKey,
		Receiver:       receiverPubkey,
		PreimageHash:   preimageHashHASH160,
		RefundLocktime: arklib.AbsoluteLocktime(swapResp.LockupDetails.Timeouts.Refund),
		UnilateralClaimDelay: parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralClaim),
		),
		UnilateralRefundDelay: parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralRefund),
		),
		UnilateralRefundWithoutReceiverDelay: parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralRefundWithoutReceiver),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild contract: %w", err)
	}

	if contract.Address != swapResp.LockupDetails.LockupAddress {
		return nil, fmt.Errorf(
			"vhtlc address mismatch: rebuilt %s, got %s from boltz",
			contract.Address, swapResp.LockupDetails.LockupAddress,
		)
	}

	args, err := handler.GetArgs(*contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get contract args for swap %s: %w", swapResp.Id, err)
	}
	parsed, ok := args.(vhtlchandler.ContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type for swap %s: got %T, expected %T",
			swapResp.Id, args, vhtlchandler.ContractArgs{},
		)
	}

	// Rebuild the BTC HTLC and verify its address matches the one got from Boltz, so that we
	// are sure that we can claim the BTC UTXO before we send the VTXO. Done directly instead
	// of via the contract manager because HTLCs are locked by ephemeral keys instead of wallet
	// ones, so the receiver doesn't need to be online to receive.
	refundKey, err := parsePubkey(swapResp.ClaimDetails.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid refund pubkey for swap %s: %w", swapResp.Id, err)
	}

	htlcScript, err := htlc.NewHTLCScriptFromOpts(htlc.Opts{
		ClaimKey:       claimKey.PubKey(),
		RefundKey:      refundKey,
		PreimageHash:   preimageHashHASH160,
		RefundLocktime: arklib.AbsoluteLocktime(swapResp.ClaimDetails.TimeoutBlockHeight),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild htlc for swap %s: %w", swapResp.Id, err)
	}

	// Boltz is the sender of the BTC HTLC in this direction, its key comes first in the
	// MuSig2 aggregation of the taproot internal key.
	htlcAddress, err := htlcScript.Address(networkNameToParams(h.config.Network.Name), true)
	if err != nil {
		return nil, fmt.Errorf("failed to encode htlc address for swap %s: %w", swapResp.Id, err)
	}
	if htlcAddress != swapResp.ClaimDetails.LockupAddress {
		return nil, fmt.Errorf(
			"htlc address mismatch: rebuilt %s, got %s from boltz",
			htlcAddress, swapResp.ClaimDetails.LockupAddress,
		)
	}

	if err := contractManager.ImportContract(ctx, *contract); err != nil {
		return nil, err
	}
	unlockContractMu()

	ws := h.boltzSvc.NewWebsocket()
	if err := ws.ConnectAndSubscribe(ctx, []string{swapResp.Id}, 5*time.Second); err != nil {
		return nil, err
	}

	swap := &swaptypes.Swap{
		Id:          swapResp.Id,
		From:        boltz.CurrencyArk,
		To:          boltz.CurrencyBtc,
		CreatedAt:   time.Now(),
		Status:      int(SwapStatusPending),
		VHTLCScript: contract.Script,
		Amount:      amount,
		ChainSwap: &swaptypes.ChainSwapInfo{
			Address:            swapResp.ClaimDetails.LockupAddress,
			PrivateKey:         hex.EncodeToString(claimKey.Serialize()),
			DestinationAddress: btcAddress,
			ServerPublicKey:    swapResp.ClaimDetails.ServerPublicKey,
			RefundLocktime:     uint32(swapResp.ClaimDetails.TimeoutBlockHeight),
		},
	}
	if persistPreimage {
		swap.Preimage = preimage
	}
	if err := h.persistSwap(ctx, *swap); err != nil {
		return nil, err
	}

	h.bgWg.Go(func() {
		ctx, cancel := context.WithTimeout(h.ctx, h.swapTimeout)
		defer cancel()

		fail := func(err error, msg string) {
			// If the manager is shutting down, leave the swap pending for the next startup's
			// recovery instead of marking it and writing to a store that's about to close.
			if h.ctx.Err() != nil {
				return
			}
			log.WithError(err).Errorf("%s for swap %s", msg, swapResp.Id)
			swap.Status = int(SwapStatusFailed)
			if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
				log.WithError(err).Errorf("failed to update swap %s", swapResp.Id)
			}
		}

		quoteAccepted := false
		for {
			select {
			case update, ok := <-ws.Updates:
				if !ok {
					nextWs, err := h.reconnectBoltzWebsocket(ctx, ws, swapResp.Id)
					if err != nil {
						fail(err, "failed to reconnect websocket")
						return
					}
					if nextWs == nil {
						continue
					}
					ws = nextWs
					continue
				}

				switch boltz.ParseEvent(update.Status) {
				case boltz.SwapCreated:
					// Boltz accepted the swap, fund the VHTLC to start it.
					txid, err := h.wallet.SendOffChain(ctx, []clientTypes.Receiver{{
						To:     swapResp.LockupDetails.LockupAddress,
						Amount: swap.Amount,
					}})
					if err != nil {
						fail(err, "failed to fund vhtlc")
						return
					}

					swap.FundingTxid = txid
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}
				case boltz.TransactionLockupFailed:
					// Our lockup doesn't match the swap amount, fetch and accept a new quote.
					// Boltz may send this event more than once, react to it only once.
					if quoteAccepted {
						continue
					}
					quote, err := h.boltzSvc.GetChainSwapQuote(swapResp.Id)
					if err != nil {
						fail(err, "lockup failed and we failed to get a new quote")
						return
					}
					if err := h.boltzSvc.AcceptChainSwapQuote(swapResp.Id, *quote); err != nil {
						fail(err, "lockup failed and we failed to accept the new quote")
						return
					}
					quoteAccepted = true
				case boltz.TransactionServerMempoool:
					// Boltz locked up the BTC, claim it to the destination address.
					swap.ChainSwap.FundingTxid = update.Transaction.Id
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}

					claimTxid, err := h.claimBtcLockup(
						swapResp.Id, htlcScript, claimKey, preimage, btcAddress,
						update.Transaction.Hex,
					)
					if err != nil {
						fail(err, "failed to claim btc lockup")
						return
					}

					swap.Status = int(SwapStatusSuccess)
					swap.ChainSwap.RedeemTxid = claimTxid
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
					}
					return
				case boltz.SwapExpired, boltz.TransactionFailed:
					// Boltz can't complete the swap, refund the VHTLC collaboratively or
					// schedule a unilateral refund as fallback.
					if _, _, err := h.refundSwap(context.Background(), swap, parsed); err != nil {
						fail(err, fmt.Sprintf(
							"swap failed with status %s and we failed to refund it",
							update.Status,
						))
					}
					return
				}
			case <-ctx.Done():
				// A shutdown cancellation leaves the swap pending for the next startup's
				// recovery; only a genuine timeout fails it and schedules the refund.
				if h.ctx.Err() != nil {
					return
				}

				swap.Status = int(SwapStatusFailed)
				if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
					log.WithError(err).Errorf("failed to update swap %s", swapResp.Id)
				}

				log.Debugf(
					"process aborted while waiting for updates for swap %s, "+
						"trying to schedule a unilrateral refund before aborting...", swapResp.Id,
				)
				if err := h.scheduleUnilateralRefund(ctx, swap, parsed.RefundLocktime); err != nil {
					log.WithError(err).Errorf(
						"failed to schedule refund of swap %s unilaterally", swapResp.Id,
					)
				}

				return
			}
		}
	})

	return swap, nil
}

// claimBtcLockup claims the BTC locked up by Boltz to the destination address. It first tries
// a cooperative MuSig2 key-path spend, then falls back to a script-path spend of the claim
// leaf revealing the preimage.
func (h *SwapManager) claimBtcLockup(
	swapId string, htlcScript *htlc.HTLCScript, claimKey *btcec.PrivateKey,
	preimage []byte, btcAddress, lockupTxHex string,
) (string, error) {
	explorerSvc := h.wallet.Explorer()

	lockupTx, err := deserializeTransaction(lockupTxHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode lockup tx: %w", err)
	}
	lockupPkScript, err := htlcScript.PkScript(true)
	if err != nil {
		return "", fmt.Errorf("failed to get htlc output script: %w", err)
	}

	vout := -1
	var lockupAmount uint64
	for i, out := range lockupTx.TxOut {
		if bytes.Equal(out.PkScript, lockupPkScript) {
			vout, lockupAmount = i, uint64(out.Value)
			break
		}
	}
	if vout < 0 {
		return "", fmt.Errorf("htlc output not found in lockup tx %s", lockupTx.TxHash())
	}

	claimTx, err := constructClaimTransaction(explorerSvc, h.config.Dust, claimTransactionParams{
		lockupTxid:      lockupTx.TxHash().String(),
		lockupVout:      uint32(vout),
		lockupAmount:    lockupAmount,
		destinationAddr: btcAddress,
		network:         networkNameToParams(h.config.Network.Name),
	})
	if err != nil {
		return "", fmt.Errorf("failed to construct claim tx: %w", err)
	}

	prevOutFetcher := NewPrevOutputFetcher(
		&wire.TxOut{Value: int64(lockupAmount), PkScript: lockupPkScript},
		claimTx.TxIn[0].PreviousOutPoint,
	)

	witness, err := h.signClaimCooperative(
		swapId, htlcScript, claimKey, preimage, claimTx, prevOutFetcher,
	)
	if err != nil {
		log.WithError(err).Warnf(
			"failed to sign claim tx for swap %s cooperatively, "+
				"falling back to script-path spend", swapId,
		)
		witness, err = signClaimScriptPath(htlcScript, claimKey, preimage, claimTx, prevOutFetcher)
		if err != nil {
			return "", err
		}
	}
	claimTx.TxIn[0].Witness = witness

	claimTxHex, err := serializeTransaction(claimTx)
	if err != nil {
		return "", fmt.Errorf("failed to serialize claim tx: %w", err)
	}
	txid, err := explorerSvc.Broadcast(claimTxHex)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast claim tx: %w", err)
	}
	return txid, nil
}

// signClaimCooperative computes the key-path witness of the claim tx by exchanging MuSig2
// nonces and partial signatures with Boltz, revealing the preimage to let them claim the
// VHTLC on their side.
func (h *SwapManager) signClaimCooperative(
	swapId string, htlcScript *htlc.HTLCScript, claimKey *btcec.PrivateKey, preimage []byte,
	claimTx *wire.MsgTx, prevOutFetcher txscript.PrevOutputFetcher,
) (wire.TxWitness, error) {
	musigSession, err := newLocalMuSig2Session(claimKey, htlcScript.RefundKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create musig2 session: %w", err)
	}
	ourNonce, err := musigSession.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	claimTxHex, err := serializeTransaction(claimTx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize claim tx: %w", err)
	}

	boltzResp, err := h.boltzSvc.SubmitChainSwapClaim(swapId, boltz.ChainSwapClaimRequest{
		Preimage: hex.EncodeToString(preimage),
		ToSign: boltz.ToSign{
			Nonce:   SerializePubNonce(ourNonce),
			ClaimTx: claimTxHex,
			Index:   0,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit claim to boltz: %w", err)
	}

	boltzNonce, err := ParsePubNonce(boltzResp.PubNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boltz nonce: %w", err)
	}
	boltzPartialSig, err := ParsePartialSignatureScalar32(boltzResp.PartialSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boltz partial sig: %w", err)
	}

	msg, err := TaprootMessage(claimTx, 0, prevOutFetcher)
	if err != nil {
		return nil, fmt.Errorf("failed to compute taproot message: %w", err)
	}

	combinedNonce, err := musigSession.AggregateNonces(boltzNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate nonces: %w", err)
	}

	merkleRoot := htlcScript.MerkleRoot()
	ourPartialSig, err := musigSession.PartialSign(combinedNonce, msg, merkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to make our partial sig: %w", err)
	}
	if ourPartialSig.R == nil {
		return nil, fmt.Errorf("missing nonce point in our partial sig")
	}

	finalSig, err := CombineFinalSig(
		ourPartialSig.R,
		[]*musig2.PartialSignature{ourPartialSig, boltzPartialSig},
		musigSession.Keys(), msg, merkleRoot,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to combine sigs: %w", err)
	}

	tweakedKey, err := ComputeTweakedOutputKey(musigSession.Keys(), merkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tweaked key: %w", err)
	}
	if err := VerifyFinalSig(msg, finalSig, tweakedKey); err != nil {
		return nil, fmt.Errorf("failed to verify final sig: %w", err)
	}

	return wire.TxWitness{finalSig.Serialize()}, nil
}

// signClaimScriptPath computes the script-path witness of the claim tx by signing the claim
// leaf with the ephemeral claim key and revealing the preimage in the witness.
func signClaimScriptPath(
	htlcScript *htlc.HTLCScript, claimKey *btcec.PrivateKey, preimage []byte,
	claimTx *wire.MsgTx, prevOutFetcher txscript.PrevOutputFetcher,
) (wire.TxWitness, error) {
	tapscript, err := htlcScript.ClaimTapscript(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim tapscript: %w", err)
	}

	sigHashes := txscript.NewTxSigHashes(claimTx, prevOutFetcher)
	sigHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, claimTx, 0, prevOutFetcher,
		txscript.NewBaseTapLeaf(tapscript.RevealedScript),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tapscript sighash: %w", err)
	}

	var msg [32]byte
	copy(msg[:], sigHash)
	sig, err := signLocalSchnorr(claimKey, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign claim tx: %w", err)
	}

	ctrlBlock, err := tapscript.ControlBlock.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize control block: %w", err)
	}

	return wire.TxWitness{
		sig.Serialize(), preimage, tapscript.RevealedScript, ctrlBlock,
	}, nil
}
