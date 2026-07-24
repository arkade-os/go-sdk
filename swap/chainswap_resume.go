package swap

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/go-sdk/contract"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	log "github.com/sirupsen/logrus"
)

type ResumeChainSwapParams struct {
	SwapID             string
	From               boltz.Currency
	To                 boltz.Currency
	Amount             uint64
	PreimageHex        string
	BoltzResponseJSON  string
	UserBtcAddress     string
	UserLockTxid       string
	ServerLockTxid     string
	ClaimTxid          string
	RefundTxid         string
	BTCHTLCPrivateKey  string
	Status             ChainSwapStatus
	Error              string
	Timestamp          int64
	Network            *chaincfg.Params
	EventCallback      ChainSwapEventCallback
	UnilateralRefundCB func(swapId string, opts vhtlc.Opts) error
}

func (h *SwapHandler) ResumeChainSwap(
	ctx context.Context,
	params ResumeChainSwapParams,
) (*ChainSwap, error) {
	if params.SwapID == "" {
		return nil, fmt.Errorf("swap id is required")
	}
	if params.BoltzResponseJSON == "" {
		return nil, fmt.Errorf("boltz response json is required")
	}
	if params.PreimageHex == "" {
		return nil, fmt.Errorf("preimage is required")
	}
	if params.From == "" || params.To == "" {
		return nil, fmt.Errorf("swap direction is required")
	}

	preimage, err := hex.DecodeString(params.PreimageHex)
	if err != nil {
		return nil, fmt.Errorf("decode preimage: %w", err)
	}

	var swapResp boltz.CreateChainSwapResponse
	if err := json.Unmarshal([]byte(params.BoltzResponseJSON), &swapResp); err != nil {
		return nil, fmt.Errorf("unmarshal boltz response: %w", err)
	}

	arkToBtc := params.From == boltz.CurrencyArk && params.To == boltz.CurrencyBtc
	btcToArk := params.From == boltz.CurrencyBtc && params.To == boltz.CurrencyArk
	if !arkToBtc && !btcToArk {
		return nil, fmt.Errorf("unsupported swap direction: %s -> %s", params.From, params.To)
	}
	var addr string
	if arkToBtc {
		addr = swapResp.LockupDetails.LockupAddress
	} else {
		addr = swapResp.ClaimDetails.LockupAddress
	}

	decoded, err := arklib.DecodeAddressV0(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode address vhtlc address %s : %w", addr, err)
	}
	vhtlcOutScript, err := script.P2TRScript(decoded.VtxoTapKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vhtlc address to p2tr script: %w", err)
	}

	contractManager := h.arkWallet.ContractManager()
	scripts := []string{hex.EncodeToString(vhtlcOutScript)}
	contracts, err := contractManager.GetContracts(
		ctx, contract.WithScripts(scripts),
	)
	if err != nil {
		return nil, fmt.Errorf("failed tot get vhtlc contract %s: %w", scripts[0], err)
	}
	if len(contracts) <= 0 {
		return nil, fmt.Errorf("vhtlc contract %s not found", scripts[0])
	}

	contract := contracts[0]
	handler, err := contractManager.GetHandler(ctx, contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get handler for vhtlc contract %s: %w", scripts[0], err)
	}

	contractArgs, err := handler.GetArgs(contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get args for vhtlc contract %s: %w", scripts[0], err)
	}

	parsed, ok := contractArgs.(vhtlchandler.ContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type: got %T, expected %T",
			contractArgs, vhtlchandler.ContractArgs{},
		)
	}
	vhtlcOpts := vhtlc.Opts{
		Sender:                               parsed.Sender,
		Receiver:                             parsed.Receiver,
		Server:                               parsed.Signer,
		PreimageHash:                         parsed.PreimageHash,
		RefundLocktime:                       parsed.RefundLocktime,
		UnilateralClaimDelay:                 parsed.UnilateralClaimDelay,
		UnilateralRefundDelay:                parsed.UnilateralRefundDelay,
		UnilateralRefundWithoutReceiverDelay: parsed.UnilateralRefundWithoutReceiverDelay,
	}

	if params.Network == nil {
		return nil, fmt.Errorf("network is required")
	}

	if params.BTCHTLCPrivateKey == "" {
		return nil, fmt.Errorf("BTC HTLC private key is required")
	}
	htlcKeyBytes, err := hex.DecodeString(params.BTCHTLCPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode BTC HTLC private key: %w", err)
	}
	htlcKey, _ := btcec.PrivKeyFromBytes(htlcKeyBytes)

	btcLockupAddress := swapResp.LockupDetails.LockupAddress
	btcServerPubKey := swapResp.LockupDetails.ServerPublicKey
	if arkToBtc {
		btcLockupAddress = swapResp.ClaimDetails.LockupAddress
		btcServerPubKey = swapResp.ClaimDetails.ServerPublicKey
	}

	if err := validateBtcLockupAddress(
		params.Network,
		btcLockupAddress,
		btcServerPubKey,
		htlcKey.PubKey(),
		swapResp.GetSwapTree(arkToBtc),
	); err != nil {
		return nil, fmt.Errorf("BTC lockup address validation failed: %w", err)
	}

	swap := &ChainSwap{
		Id:                   params.SwapID,
		Amount:               params.Amount,
		Preimage:             preimage,
		VhtlcOpts:            vhtlcOpts,
		UserBtcLockupAddress: params.UserBtcAddress,
		BTCHTLCPrivateKey:    params.BTCHTLCPrivateKey,
		UserLockTxid:         params.UserLockTxid,
		ServerLockTxid:       params.ServerLockTxid,
		ClaimTxid:            params.ClaimTxid,
		RefundTxid:           params.RefundTxid,
		Timestamp:            params.Timestamp,
		Status:               params.Status,
		Error:                params.Error,
		SwapRespJson:         params.BoltzResponseJSON,
		onEvent:              h.persistChainSwapEventCallback(params.EventCallback),
	}

	if swap.Timestamp == 0 {
		swap.Timestamp = time.Now().Unix()
	}

	log.Infof("Resuming chain swap %s (%s→%s)", swap.Id, params.From, params.To)

	monitorCtx := chainSwapMonitorContext(ctx)
	if arkToBtc {
		if params.UserBtcAddress == "" {
			return nil, fmt.Errorf(
				"btc destination address missing for Ark→BTC swap %s",
				params.SwapID,
			)
		}

		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("panic in monitorAndClaimArkToBtcSwap: %v", r)
				}
			}()

			h.monitorAndClaimArkToBtcSwap(
				monitorCtx,
				params.Network,
				params.EventCallback,
				params.UnilateralRefundCB,
				htlcKey,
				preimage,
				params.UserBtcAddress,
				&swapResp,
				swap,
			)
		}()

		return swap, nil
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic in monitorBtcToArkChainSwap: %v", r)
			}
		}()

		h.monitorBtcToArkChainSwap(
			monitorCtx,
			params.EventCallback,
			preimage,
			htlcKey,
			&swapResp,
			swap,
		)
	}()

	return swap, nil
}
