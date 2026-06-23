package htlcHandler

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	paramOwnerKeyID       = "ownerKeyId"
	paramOwnerKey         = "ownerKey"
	paramServerKey        = "serverKey"
	paramClaimLeafScript  = "claimLeafScript"
	paramRefundLeafScript = "refundLeafScript"

	supportedLeafVersion = uint8(txscript.BaseLeafVersion)
)

// Leaf identifies one Boltz BTC HTLC tapscript leaf.
type Leaf struct {
	Output string
}

// Opts are the parameters needed to create a BTC HTLC lockup contract.
// Server is the Boltz/server MuSig key. The wallet-owned key is supplied by
// the contract manager as keyRef and must appear in either the claim or refund
// leaf script.
type Opts struct {
	Server     *btcec.PublicKey
	ClaimLeaf  Leaf
	RefundLeaf Leaf
}

// Handler creates Bitcoin HTLC lockup contracts for chain swaps.
type Handler struct {
	network arklib.Network
}

func NewHandler(network arklib.Network) handlers.Handler {
	return &Handler{network: network}
}

// Derivable returns false because BTC HTLC contracts require the Boltz swap
// tree and server key. They cannot be discovered from the wallet key alone.
func (h *Handler) Derivable() bool { return false }

func (h *Handler) NewContract(
	_ context.Context, keyRef identity.KeyRef, params any,
) (*types.Contract, error) {
	p, ok := params.(*Opts)
	if !ok || p == nil {
		return nil, fmt.Errorf("htlc handler requires *htlcHandler.Opts, got %T", params)
	}

	return createContract(*p, keyRef, h.network)
}

func (h *Handler) GetKeyRef(c types.Contract) (*identity.KeyRef, error) {
	keyID, err := requireParam(c, paramOwnerKeyID)
	if err != nil {
		return nil, err
	}
	pubHex, err := requireParam(c, paramOwnerKey)
	if err != nil {
		return nil, err
	}
	pub, err := parseStoredPubKey(pubHex)
	if err != nil {
		return nil, fmt.Errorf("htlc contract %s: invalid owner key: %w", c.Script, err)
	}
	return &identity.KeyRef{Id: keyID, PubKey: pub}, nil
}

func (h *Handler) GetKeyRefs(c types.Contract) (map[string]string, error) {
	keyRef, err := h.GetKeyRef(c)
	if err != nil {
		return nil, err
	}

	return map[string]string{c.Script: keyRef.Id}, nil
}

func (h *Handler) GetSignerKey(c types.Contract) (*btcec.PublicKey, error) {
	return nil, nil
}

// GetExitDelay returns nil because BTC HTLC refund uses an absolute CLTV
// encoded in the refund leaf, not an Ark relative exit delay.
func (h *Handler) GetExitDelay(types.Contract) (*arklib.RelativeLocktime, error) {
	return nil, nil
}

func (h *Handler) GetTapscripts(c types.Contract) ([]string, error) {
	claimScript, err := parseLeafFromContract(c, paramClaimLeafScript)
	if err != nil {
		return nil, err
	}
	refundScript, err := parseLeafFromContract(c, paramRefundLeafScript)
	if err != nil {
		return nil, err
	}
	return []string{
		hex.EncodeToString(claimScript),
		hex.EncodeToString(refundScript),
	}, nil
}

func createContract(
	p Opts,
	keyRef identity.KeyRef,
	network arklib.Network,
) (*types.Contract, error) {
	if keyRef.Id == "" {
		return nil, fmt.Errorf("missing owner key ID")
	}
	if keyRef.PubKey == nil {
		return nil, fmt.Errorf("missing owner key")
	}
	if p.Server == nil {
		return nil, fmt.Errorf("missing server key")
	}

	claimScript, err := parseLeaf(p.ClaimLeaf, "claim")
	if err != nil {
		return nil, err
	}
	refundScript, err := parseLeaf(p.RefundLeaf, "refund")
	if err != nil {
		return nil, err
	}

	ownerKeyXOnly := schnorr.SerializePubKey(keyRef.PubKey)
	if !isHTLCLeafWithKey(claimScript, ownerKeyXOnly) && !isHTLCLeafWithKey(refundScript, ownerKeyXOnly) {
		return nil, fmt.Errorf("owner key is not present in HTLC tapscripts")
	}

	aggregateKey, _, _, err := musig2.AggregateKeys(
		[]*btcec.PublicKey{p.Server, keyRef.PubKey},
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate HTLC keys: %w", err)
	}

	claimLeafHash := tapLeafHash(claimScript)
	refundLeafHash := tapLeafHash(refundScript)
	merkleRoot := merkleRoot(claimLeafHash[:], refundLeafHash[:])
	taprootKey := txscript.ComputeTaprootOutputKey(aggregateKey.FinalKey, merkleRoot)

	outputScript, err := txscript.PayToTaprootScript(taprootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTLC output script: %w", err)
	}

	btcNetwork := utils.ToBitcoinNetwork(network)
	address, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), &btcNetwork)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTLC address: %w", err)
	}

	return &types.Contract{
		Type: types.ContractTypeHTLC,
		Params: map[string]string{
			paramOwnerKeyID:       keyRef.Id,
			paramOwnerKey:         hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
			paramServerKey:        hex.EncodeToString(p.Server.SerializeCompressed()),
			paramClaimLeafScript:  hex.EncodeToString(claimScript),
			paramRefundLeafScript: hex.EncodeToString(refundScript),
		},
		Script:    hex.EncodeToString(outputScript),
		Address:   address.EncodeAddress(),
		State:     types.ContractStateActive,
		CreatedAt: time.Now(),
	}, nil
}

func parseLeaf(leaf Leaf, name string) ([]byte, error) {
	if leaf.Output == "" {
		return nil, fmt.Errorf("%s leaf script is empty", name)
	}
	script, err := hex.DecodeString(leaf.Output)
	if err != nil {
		return nil, fmt.Errorf("%s leaf script is not valid hex: %w", name, err)
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("%s leaf script is empty", name)
	}
	return script, nil
}

func parseLeafFromContract(
	c types.Contract, scriptParam string,
) ([]byte, error) {
	scriptHex, err := requireParam(c, scriptParam)
	if err != nil {
		return nil, err
	}
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		return nil, fmt.Errorf("htlc contract %s: invalid leaf script hex: %w", c.Script, err)
	}
	if len(script) == 0 {
		return nil, fmt.Errorf("htlc contract %s: empty leaf script", c.Script)
	}
	return script, nil
}

func requireParam(c types.Contract, name string) (string, error) {
	if len(c.Params) == 0 {
		return "", fmt.Errorf("htlc contract %s has no params", c.Script)
	}
	value, ok := c.Params[name]
	if !ok {
		return "", fmt.Errorf("htlc contract %s is missing %s", c.Script, name)
	}
	if value == "" {
		return "", fmt.Errorf("htlc contract %s has empty %s", c.Script, name)
	}
	return value, nil
}

func parseStoredPubKey(pubHex string) (*btcec.PublicKey, error) {
	buf, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
	}
	const compressedPubKeyLen = 33
	if len(buf) != compressedPubKeyLen {
		return nil, fmt.Errorf(
			"expected compressed key length %d, got %d", compressedPubKeyLen, len(buf),
		)
	}
	if buf[0] != 0x02 && buf[0] != 0x03 {
		return nil, fmt.Errorf("expected compressed key prefix 0x02 or 0x03, got 0x%02x", buf[0])
	}
	return btcec.ParsePubKey(buf)
}

func merkleRoot(left, right []byte) []byte {
	if bytes.Compare(left, right) > 0 {
		left, right = right, left
	}

	branch := append(append([]byte{}, left...), right...)
	return chainhash.TaggedHash(chainhash.TagTapBranch, branch)[:]
}

func tapLeafHash(script []byte) [32]byte {
	var b bytes.Buffer
	b.WriteByte(supportedLeafVersion)
	_ = wire.WriteVarInt(&b, 0, uint64(len(script)))
	b.Write(script)
	sum := chainhash.TaggedHash(chainhash.TagTapLeaf, b.Bytes())

	return *sum
}

func isHTLCLeafWithKey(script, xOnlyPub []byte) bool {
	return isHTLCClaimLeafWithKey(script, xOnlyPub) || isHTLCRefundLeafWithKey(script, xOnlyPub)
}

func isHTLCClaimLeafWithKey(script, xOnlyPub []byte) bool {
	if len(xOnlyPub) != schnorr.PubKeyBytesLen {
		return false
	}
	const claimLeafLen = 61
	if len(script) != claimLeafLen {
		return false
	}
	const preimageLen = 32
	return script[0] == txscript.OP_SIZE &&
		script[1] == txscript.OP_DATA_1 &&
		script[2] == preimageLen &&
		script[3] == txscript.OP_EQUALVERIFY &&
		script[4] == txscript.OP_HASH160 &&
		script[5] == txscript.OP_DATA_20 &&
		script[26] == txscript.OP_EQUALVERIFY &&
		script[27] == txscript.OP_DATA_32 &&
		bytes.Equal(script[28:60], xOnlyPub) &&
		script[60] == txscript.OP_CHECKSIG
}

func isHTLCRefundLeafWithKey(script, xOnlyPub []byte) bool {
	if len(xOnlyPub) != schnorr.PubKeyBytesLen {
		return false
	}
	const minRefundLeafLen = 38
	if len(script) < minRefundLeafLen ||
		script[0] != txscript.OP_DATA_32 ||
		!bytes.Equal(script[1:33], xOnlyPub) ||
		script[33] != txscript.OP_CHECKSIGVERIFY {
		return false
	}

	timeoutLen := int(script[34])
	if timeoutLen < 1 || timeoutLen > 4 {
		return false
	}
	if len(script) != 36+timeoutLen {
		return false
	}
	return script[35+timeoutLen] == txscript.OP_CHECKLOCKTIMEVERIFY
}
