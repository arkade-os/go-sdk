package e2e_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	indexergrpc "github.com/arkade-os/arkd/pkg/client-lib/indexer/grpc"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

const (
	solverHTTPAddr = "http://localhost:7271"
	arkdGRPCAddr   = "localhost:7070"
)

// TestNonInteractiveClaim creates a VHTLC with the non-interactive claim option
// and lets bancod solver claim the VHTLC instead of the recipient.
func TestNonInteractiveClaim(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	sender, _ := setupSwapClient(t)

	cfg, err := sender.GetConfigData(ctx)
	require.NoError(t, err)

	// Create receiver "wallet" (just a keypair)
	receiverPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	receiverPkScript, err := txscript.PayToTaprootScript(receiverPriv.PubKey())
	require.NoError(t, err)

	// Fetch solver + introspector pubkeys from bancod
	solverPub, introPub := fetchSolverPubKeysHTTP(t)

	// Generate preimage
	preimg := make([]byte, 32)
	_, err = rand.Read(preimg)
	require.NoError(t, err)
	// Build the NIC VHTLC and encrypted extension packet
	preimageHash := btcutil.Hash160(preimg)

	// Build arkade enforcement script
	arkadeScript, err := enforcePayTo(t, receiverPkScript)
	require.NoError(t, err)

	// Build VHTLC with NIC opts
	opts := vhtlc.Opts{
		Sender:       cfg.SignerPubKey, // doesn't matter for NIC claim path
		Receiver:     receiverPriv.PubKey(),
		Server:       cfg.SignerPubKey,
		PreimageHash: preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(
			time.Now().Add(24 * time.Hour).Unix(),
		),
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
		NonInteractiveClaim: &vhtlc.NonInteractiveClaimOpts{
			ReceiverPkScript:   receiverPkScript,
			IntrospectorPubKey: introPub,
		},
	}

	vhtlcScript, err := vhtlc.NewVHTLCScriptFromOpts(opts)
	require.NoError(t, err)

	vhtlcAddr, err := vhtlcScript.Address(cfg.Network.Addr)
	require.NoError(t, err)
	t.Logf("VHTLC address: %s", vhtlcAddr)

	// Encrypt just the raw 32-byte preimage (new format)
	ciphertext, err := eciesEncrypt(solverPub, preimg)
	require.NoError(t, err)

	// Build extension packet: ciphertext + plaintext arkade script
	claimPkt := buildClaimPacket(t, ciphertext, arkadeScript)

	// Build taptree for the PSBT output so solver can decode the VHTLC
	tapKey, _, err := vhtlcScript.TapTree()
	require.NoError(t, err)
	pkScript, err := txscript.PayToTaprootScript(tapKey)
	require.NoError(t, err)
	encodedTaptree, err := txutils.TapTree(vhtlcScript.GetRevealedTapscripts()).Encode()
	require.NoError(t, err)
	tapTrees := map[string][]byte{
		hex.EncodeToString(pkScript): encodedTaptree,
	}

	// Fund sender
	faucetOffchain(t, sender, 0.001)

	// Fund the VHTLC with extension packet + taptree on the output
	const amount uint64 = 10_000
	txid, err := sender.SendOffChain(ctx, []clientTypes.Receiver{
		{To: vhtlcAddr, Amount: amount},
	},
		clientwallet.WithExtraPacket(claimPkt),
		clientwallet.WithTxOutsTaprootTree(tapTrees),
	)
	require.NoError(t, err)
	require.NotEmpty(t, txid)
	t.Logf("Funding tx: %s", txid)

	// Wait for solver (bancod) to auto-claim
	v := pollForVtxoAtScript(t, ctx, receiverPkScript, 60*time.Second)
	require.Equal(t, amount, v.Amount, "solver should pay the full input value to the receiver")
	t.Logf("Claimed: %s:%d amount=%d", v.Txid, v.VOut, v.Amount)
}

func fetchSolverPubKeysHTTP(t *testing.T) (*btcec.PublicKey, *btcec.PublicKey) {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/v1/preimage/solver-pubkey", solverHTTPAddr))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var result struct {
		SolverPubKey       string `json:"solver_pub_key"`
		IntrospectorPubKey string `json:"emulator_pub_key"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	solverRaw, err := hex.DecodeString(result.SolverPubKey)
	require.NoError(t, err)
	solver, err := btcec.ParsePubKey(solverRaw)
	require.NoError(t, err)
	introRaw, err := hex.DecodeString(result.IntrospectorPubKey)
	require.NoError(t, err)
	intro, err := btcec.ParsePubKey(introRaw)
	require.NoError(t, err)
	return solver, intro
}

func enforcePayTo(t *testing.T, receiverPkScript []byte) ([]byte, error) {
	t.Helper()
	require.Len(t, receiverPkScript, 34)
	witnessProgram := receiverPkScript[2:]
	return txscript.NewScriptBuilder().
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_DUP).
		AddOp(arkade.OP_INSPECTOUTPUTSCRIPTPUBKEY).
		AddOp(arkade.OP_1).
		AddOp(arkade.OP_EQUALVERIFY).
		AddData(witnessProgram).
		AddOp(arkade.OP_EQUALVERIFY).
		AddOp(arkade.OP_INSPECTOUTPUTVALUE).
		AddOp(arkade.OP_PUSHCURRENTINPUTINDEX).
		AddOp(arkade.OP_INSPECTINPUTVALUE).
		AddOp(arkade.OP_GREATERTHANOREQUAL).
		Script()
}

func pollForVtxoAtScript(
	t *testing.T, ctx context.Context, pkScript []byte, timeout time.Duration,
) struct {
	Txid   string
	VOut   uint32
	Amount uint64
} {
	t.Helper()
	idx, err := indexergrpc.NewClient(arkdGRPCAddr)
	require.NoError(t, err)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := idx.GetVtxos(ctx,
			indexer.WithScripts([]string{hex.EncodeToString(pkScript)}),
			indexer.WithSpendableOnly(),
		)
		if err == nil && len(resp.Vtxos) > 0 {
			v := resp.Vtxos[0]
			return struct {
				Txid   string
				VOut   uint32
				Amount uint64
			}{Txid: v.Txid, VOut: v.VOut, Amount: v.Amount}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no VTXO at pkScript %s within %v", hex.EncodeToString(pkScript), timeout)
	return struct {
		Txid   string
		VOut   uint32
		Amount uint64
	}{}
}

// --- Inlined ECIES + packet helpers (from bancod/pkg/preimage, avoids import) ---

const (
	eciesNonceLen   = 12
	eciesHkdfInfo   = "solverd/preimage/v1"
	claimPktType    = 0x04
	tlvCiphertext   = 0x01
	tlvArkadeScript = 0x02
)

func eciesEncrypt(recipient *btcec.PublicKey, plaintext []byte) ([]byte, error) {
	ephPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	ephPub := ephPriv.PubKey().SerializeCompressed()
	symKey := eciesDeriveKey(ephPriv, recipient, ephPub)
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, eciesNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, ephPub)
	out := make([]byte, 0, 33+eciesNonceLen+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func eciesDeriveKey(priv *btcec.PrivateKey, peer *btcec.PublicKey, salt []byte) []byte {
	var jp btcec.JacobianPoint
	peer.AsJacobian(&jp)
	var result btcec.JacobianPoint
	btcec.ScalarMultNonConst(&priv.Key, &jp, &result)
	result.ToAffine()
	x := result.X.Bytes()
	shared := make([]byte, 32)
	copy(shared, x[:])
	r := hkdf.New(func() hash.Hash { return sha256.New() }, shared, salt, []byte(eciesHkdfInfo))
	out := make([]byte, 32)
	_, _ = io.ReadFull(r, out)
	return out
}

func buildClaimPacket(t *testing.T, ciphertext, arkadeScript []byte) extension.Packet {
	t.Helper()
	var buf []byte
	// TLV: ciphertext
	buf = append(buf, tlvCiphertext)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(ciphertext)))
	buf = append(buf, ciphertext...)
	// TLV: arkade script
	buf = append(buf, tlvArkadeScript)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(arkadeScript)))
	buf = append(buf, arkadeScript...)
	return extension.UnknownPacket{PacketType: claimPktType, Data: buf}
}
