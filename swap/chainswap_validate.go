package swap

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func validateVHTLC(
	ctx context.Context,
	h *SwapHandler,
	isArkToBtc bool,
	swapResp *boltz.CreateChainSwapResponse,
	preimageHashHASH160 []byte,
	localPubkey *btcec.PublicKey,
) (*vhtlc.Opts, error) {
	var (
		vhtlcAddr                                                                         string
		vhtlcAddress                                                                      string
		vhtlcOpts                                                                         *vhtlc.Opts
		refundLocktime                                                                    arklib.AbsoluteLocktime
		unilateralClaimDelay, unilateralRefundDelay, unilateralRefundWithoutReceiverDelay arklib.RelativeLocktime
	)

	if isArkToBtc {
		vhtlcAddr = swapResp.LockupDetails.LockupAddress
		counterpartyReceiverKey, err := parsePubkey(swapResp.LockupDetails.ServerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid Boltz claim public key: %w", err)
		}

		refundLocktime = arklib.AbsoluteLocktime(swapResp.LockupDetails.Timeouts.Refund)
		unilateralClaimDelay = parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralClaim),
		)
		unilateralRefundDelay = parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralRefund),
		)
		unilateralRefundWithoutReceiverDelay = parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralRefundWithoutReceiver),
		)

		if localPubkey == nil {
			keyRef, err := h.localVHTLCKeyForAddress(ctx, vhtlcAddr)
			if err != nil {
				return nil, err
			}
			localPubkey = keyRef.PubKey
		}

		vhtlcAddress, _, vhtlcOpts, err = h.buildLocalSenderVHTLC(
			counterpartyReceiverKey,
			preimageHashHASH160[:],
			refundLocktime,
			unilateralClaimDelay,
			unilateralRefundDelay,
			unilateralRefundWithoutReceiverDelay,
			localPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to compute VHTLC: %w", err)
		}
	} else {
		vhtlcAddr = swapResp.ClaimDetails.LockupAddress
		counterpartySenderKey, err := parsePubkey(swapResp.ClaimDetails.ServerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid Boltz claim public key: %w", err)
		}

		refundLocktime = arklib.AbsoluteLocktime(swapResp.ClaimDetails.Timeouts.Refund)
		unilateralClaimDelay = parseLocktime(uint32(swapResp.ClaimDetails.Timeouts.UnilateralClaim))
		unilateralRefundDelay = parseLocktime(
			uint32(swapResp.ClaimDetails.Timeouts.UnilateralRefund),
		)
		unilateralRefundWithoutReceiverDelay = parseLocktime(
			uint32(swapResp.ClaimDetails.Timeouts.UnilateralRefundWithoutReceiver),
		)

		if localPubkey == nil {
			keyRef, err := h.localVHTLCKeyForAddress(ctx, vhtlcAddr)
			if err != nil {
				return nil, err
			}
			localPubkey = keyRef.PubKey
		}

		vhtlcAddress, _, vhtlcOpts, err = h.buildLocalReceiverVHTLC(
			counterpartySenderKey,
			preimageHashHASH160[:],
			refundLocktime,
			unilateralClaimDelay,
			unilateralRefundDelay,
			unilateralRefundWithoutReceiverDelay,
			localPubkey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to compute VHTLC: %w", err)
		}
	}

	if vhtlcAddr != vhtlcAddress {
		return nil, fmt.Errorf(
			"VHTLC address mismatch - potential scam!\nExpected: %s\nGot: %s",
			vhtlcAddress,
			vhtlcAddr,
		)
	}
	return vhtlcOpts, nil
}

// HTLCComponents contains the parsed components from a Boltz HTLC claim leaf.
type HTLCComponents = htlc.ClaimLeafComponents

// RefundHTLCComponents contains the parsed components from a Boltz HTLC refund
// leaf.
type RefundHTLCComponents = htlc.RefundLeafComponents

// validateClaimLeafScript parses and validates a Boltz HTLC claim leaf script.
// The expected structure follows Boltz's HTLC format:
//
//	OP_SIZE
//	OP_PUSHBYTES_1 0x20
//	OP_EQUALVERIFY
//	OP_HASH160
//	OP_PUSHBYTES_20 <preimage_hash>
//	OP_EQUALVERIFY
//	OP_PUSHBYTES_32 <claim_pubkey>
//	OP_CHECKSIG
//
// Example:
//
//	output: "82012088a914608bc8a727928e8aa18c7a2489c003deb47ff08388207599756afc49ebf5a6f3ac5848ef0afe934edd7b669bca02029acf10cc7f83acac"
//	-> preimageHash: 608bc8a727928e8aa18c7a2489c003deb47ff083
//	-> claimPubKey: 7599756afc49ebf5a6f3ac5848ef0afe934edd7b669bca02029acf10cc7f83ac
func validateClaimLeafScript(outputHex string) (*HTLCComponents, error) {
	return htlc.ParseClaimLeafScriptHex(outputHex)
}

// validateBtcClaimOrRefundPossible validates the Bitcoin HTLC (swap tree) parameters for a chain swap.
// It supports both claim path and refund path validation based on the arkToBtc parameter.
//
// When arkToBtc is true (Ark → BTC swap):
//   - Validates the claim path: user can claim BTC using preimage
//   - Requires: serverPubKeyHex, claimPubKey, preimageHash
//   - refundPubKey and expectedTimeout are ignored
//
// When arkToBtc is false (BTC → Ark swap):
//   - Validates the refund path: user can refund BTC after timeout
//   - Requires: refundPubKey, expectedTimeout
//   - serverPubKeyHex, claimPubKey, and preimageHash are ignored
func validateBtcClaimOrRefundPossible(
	swapTree boltz.SwapTree,
	arkToBtc bool,
	serverPubKeyHex string,
	claimPubKey *btcec.PublicKey,
	preimageHash []byte,
	refundPubKey *btcec.PublicKey,
	expectedTimeout uint32,
) error {
	if arkToBtc {
		// Validate claim path - user claims BTC from Boltz
		return validateClaimPath(swapTree, serverPubKeyHex, claimPubKey, preimageHash)
	}
	return validateRefundPath(swapTree, refundPubKey, expectedTimeout)
}

// validateClaimPath validates the Bitcoin HTLC claim path.
// This validates the taproot script structure, public keys, and script validity for the claim leaf.
func validateClaimPath(
	swapTree boltz.SwapTree,
	serverPubKeyHex string,
	claimPubKey *btcec.PublicKey,
	preimageHash []byte,
) error {
	if err := validateSwapTree(swapTree); err != nil {
		return fmt.Errorf("invalid swap tree: %w", err)
	}

	components, err := validateClaimLeafScript(swapTree.ClaimLeaf.Output)
	if err != nil {
		return fmt.Errorf("invalid claim leaf HTLC script: %w", err)
	}

	if serverPubKeyHex == "" {
		return fmt.Errorf("server public key is empty")
	}
	serverPubKey, err := parsePubkey(serverPubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid server public key: %w", err)
	}

	if len(serverPubKey.SerializeCompressed()) != 33 {
		return fmt.Errorf(
			"server public key must be 33 bytes compressed, got %d",
			len(serverPubKey.SerializeCompressed()),
		)
	}

	if claimPubKey == nil {
		return fmt.Errorf("claim public key is nil")
	}
	if len(claimPubKey.SerializeCompressed()) != 33 {
		return fmt.Errorf(
			"claim public key must be 33 bytes compressed, got %d",
			len(claimPubKey.SerializeCompressed()),
		)
	}

	claimPubKeyXOnly := claimPubKey.SerializeCompressed()[1:]
	if !bytes.Equal(claimPubKeyXOnly, components.ClaimPubKey[:]) {
		return fmt.Errorf(
			"claim pubkey mismatch: expected %x, got %x in script",
			claimPubKeyXOnly,
			components.ClaimPubKey[:],
		)
	}

	if len(preimageHash) != 20 {
		return fmt.Errorf("preimage hash must be 20, got %d", len(preimageHash))
	}

	if !bytes.Equal(preimageHash, components.PreimageHash[:]) {
		return fmt.Errorf(
			"preimage hash mismatch: expected %x, got %x in script",
			preimageHash,
			components.PreimageHash[:],
		)
	}

	return nil
}

// ValidateRefundLeafScript parses and validates a Boltz HTLC refund leaf script.
// The expected structure follows Boltz's refund format:
//
//	OP_PUSHBYTES_32 <refund_pubkey>
//	OP_CHECKSIGVERIFY
//	OP_PUSHBYTES_2 <timeout>
//	OP_CHECKLOCKTIMEVERIFY (absolute block height)
//
// Note: Boltz uses CLTV (absolute timelock) not CSV (relative timelock) for refund paths.
//
// Example:
//
//	input: "207599756afc49ebf5a6f3ac5848ef0afe934edd7b669bca02029acf10cc7f83acad02f802b1"
//	-> refundPubKey: 7599756afc49ebf5a6f3ac5848ef0afe934edd7b669bca02029acf10cc7f83ac
//	-> timeout: 760 blocks (0x02f8 little-endian)
func ValidateRefundLeafScript(outputHex string) (*RefundHTLCComponents, error) {
	return htlc.ParseRefundLeafScriptHex(outputHex)
}

// validateRefundPath validates the Bitcoin HTLC refund path for a chain swap.
// This ensures the user can refund their BTC if Boltz fails to deliver VTXOs.
func validateRefundPath(
	swapTree boltz.SwapTree,
	refundPubKey *btcec.PublicKey,
	expectedTimeout uint32,
) error {
	if err := validateSwapTree(swapTree); err != nil {
		return fmt.Errorf("invalid swap tree: %w", err)
	}

	components, err := ValidateRefundLeafScript(swapTree.RefundLeaf.Output)
	if err != nil {
		return fmt.Errorf("invalid refund leaf HTLC script: %w", err)
	}

	// Validate refund pubkey
	if refundPubKey == nil {
		return fmt.Errorf("refund public key is nil")
	}
	refundPubKeyXOnly := refundPubKey.SerializeCompressed()[1:]
	if !bytes.Equal(refundPubKeyXOnly, components.RefundPubKey[:]) {
		return fmt.Errorf(
			"refund pubkey mismatch: expected %x, got %x in script",
			refundPubKeyXOnly,
			components.RefundPubKey[:],
		)
	}

	if components.Timeout != expectedTimeout {
		return fmt.Errorf(
			"timeout mismatch: expected %d blocks, got %d blocks in script",
			expectedTimeout,
			components.Timeout,
		)
	}

	const MinRefundTimeout = 144
	if components.Timeout < MinRefundTimeout {
		return fmt.Errorf(
			"timeout too short: got %d blocks, minimum safe timeout is %d blocks",
			components.Timeout,
			MinRefundTimeout,
		)
	}

	return nil
}

func validateBtcLockupAddress(
	network *chaincfg.Params,
	expectedAddr string,
	serverPubKeyHex string,
	clientPubKey *btcec.PublicKey,
	swapTree boltz.SwapTree,
) error {
	serverPubKey, err := parsePubkey(serverPubKeyHex)
	if err != nil {
		return fmt.Errorf("parse server pubkey: %w", err)
	}

	merkleRoot, err := computeSwapTreeMerkleRoot(swapTree)
	if err != nil {
		return fmt.Errorf("compute merkle root: %w", err)
	}

	agg, _, _, err := musig2.AggregateKeys(
		[]*btcec.PublicKey{serverPubKey, clientPubKey},
		false,
	)
	if err != nil {
		return fmt.Errorf("musig2 aggregate keys: %w", err)
	}

	tweakedKey := txscript.ComputeTaprootOutputKey(agg.FinalKey, merkleRoot)

	xonly := schnorr.SerializePubKey(tweakedKey)
	addr, err := encodeP2TRAddress(network, xonly)
	if err != nil {
		return fmt.Errorf("encode p2tr address: %w", err)
	}

	if addr != expectedAddr {
		return fmt.Errorf("btc lockup address mismatch: expected=%s derived=%s", expectedAddr, addr)
	}

	return nil
}

func validateSwapTree(swapTree boltz.SwapTree) error {
	if swapTree.ClaimLeaf.Output == "" {
		return fmt.Errorf("claim leaf output is empty")
	}

	if swapTree.ClaimLeaf.Version != 0xc0 {
		return fmt.Errorf(
			"invalid claim leaf version: expected 0xc0, got 0x%x",
			swapTree.ClaimLeaf.Version,
		)
	}

	if swapTree.RefundLeaf.Output == "" {
		return fmt.Errorf("refund leaf output is empty")
	}

	if swapTree.RefundLeaf.Version != 0xc0 {
		return fmt.Errorf(
			"invalid refund leaf version: expected 0xc0, got 0x%x",
			swapTree.RefundLeaf.Version,
		)
	}

	if _, err := hex.DecodeString(swapTree.ClaimLeaf.Output); err != nil {
		return fmt.Errorf("claim leaf script is not valid hex: %w", err)
	}

	if _, err := hex.DecodeString(swapTree.RefundLeaf.Output); err != nil {
		return fmt.Errorf("refund leaf script is not valid hex: %w", err)
	}

	return nil
}

func encodeP2TRAddress(net *chaincfg.Params, xonlyPubKey []byte) (string, error) {
	if len(xonlyPubKey) != 32 {
		return "", fmt.Errorf("x-only pubkey must be 32 bytes, got %d", len(xonlyPubKey))
	}

	tapAddr, err := btcutil.NewAddressTaproot(xonlyPubKey, net)
	if err != nil {
		return "", err
	}
	return tapAddr.EncodeAddress(), nil
}
