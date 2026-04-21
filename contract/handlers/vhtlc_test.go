package handlers_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func vhtlcParams(t *testing.T, cfg *clientTypes.Config) (
	sender, receiver *btcec.PrivateKey,
	preimage []byte,
	raw map[string]string,
) {
	t.Helper()

	var err error
	sender, err = btcec.NewPrivateKey()
	require.NoError(t, err)
	receiver, err = btcec.NewPrivateKey()
	require.NoError(t, err)

	preimage = []byte("test-preimage-secret")
	hash := btcutil.Hash160(preimage)

	// claimDelay: 144 blocks
	claimLocktime := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	claimSeq, err := arklib.BIP68Sequence(claimLocktime)
	require.NoError(t, err)

	// refundDelay: 288 blocks
	refundLocktime := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 288}
	refundSeq, err := arklib.BIP68Sequence(refundLocktime)
	require.NoError(t, err)

	// refundNoReceiverDelay: 432 blocks
	noRcvrLocktime := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 432}
	noRcvrSeq, err := arklib.BIP68Sequence(noRcvrLocktime)
	require.NoError(t, err)

	raw = map[string]string{
		"sender":                hex.EncodeToString(schnorr.SerializePubKey(sender.PubKey())),
		"receiver":              hex.EncodeToString(schnorr.SerializePubKey(receiver.PubKey())),
		"hash":                  hex.EncodeToString(hash),
		"refundLocktime":        "1000", // block height 1000
		"claimDelay":            strconv.FormatUint(uint64(claimSeq), 10),
		"refundDelay":           strconv.FormatUint(uint64(refundSeq), 10),
		"refundNoReceiverDelay": strconv.FormatUint(uint64(noRcvrSeq), 10),
	}
	return
}

func TestVHTLCHandler_Type(t *testing.T) {
	t.Parallel()
	h := &handlers.VHTLCHandler{}
	require.Equal(t, handlers.TypeVHTLC, h.Type())
}

func TestVHTLCHandler_DeriveContract(t *testing.T) {
	t.Parallel()

	h := &handlers.VHTLCHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	senderPriv, receiverPriv, _, raw := vhtlcParams(t, cfg)
	ctx := context.Background()

	c, err := h.DeriveContract(ctx, key, cfg, raw)
	require.NoError(t, err)
	require.NotNil(t, c)

	require.Equal(t, handlers.TypeVHTLC, c.Type)
	require.Equal(t, "test-key", c.Params["keyId"])

	// Must produce exactly 6 tapscripts.
	require.Len(t, c.Tapscripts, 6)

	// VHTLC is offchain-only — no boarding or onchain facets.
	require.Empty(t, c.Boarding)
	require.Empty(t, c.Onchain)

	// Address matches manual derivation with the same 6-leaf tree.
	hash := btcutil.Hash160([]byte("test-preimage-secret"))
	condScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(hash).
		AddOp(txscript.OP_EQUAL).
		Script()
	require.NoError(t, err)

	claimSeq, _ := strconv.ParseUint(raw["claimDelay"], 10, 32)
	refundSeq, _ := strconv.ParseUint(raw["refundDelay"], 10, 32)
	noRcvrSeq, _ := strconv.ParseUint(raw["refundNoReceiverDelay"], 10, 32)

	claimLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	refundLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 288}
	noRcvrLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 432}
	_ = claimSeq
	_ = refundSeq
	_ = noRcvrSeq

	refVtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.ConditionMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{receiverPriv.PubKey(), cfg.SignerPubKey},
				},
				Condition: condScript,
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					senderPriv.PubKey(),
					receiverPriv.PubKey(),
					cfg.SignerPubKey,
				},
			},
			&script.CLTVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{senderPriv.PubKey(), cfg.SignerPubKey},
				},
				Locktime: arklib.AbsoluteLocktime(1000),
			},
			&script.ConditionCSVMultisigClosure{
				CSVMultisigClosure: script.CSVMultisigClosure{
					MultisigClosure: script.MultisigClosure{
						PubKeys: []*btcec.PublicKey{receiverPriv.PubKey()},
					},
					Locktime: claimLT,
				},
				Condition: condScript,
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{senderPriv.PubKey(), receiverPriv.PubKey()},
				},
				Locktime: refundLT,
			},
			&script.CSVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{senderPriv.PubKey()},
				},
				Locktime: noRcvrLT,
			},
		},
	}

	refTapKey, _, err := refVtxoScript.TapTree()
	require.NoError(t, err)

	refAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
		VtxoTapKey: refTapKey,
	}
	refEncoded, err := refAddr.EncodeV0()
	require.NoError(t, err)
	require.Equal(t, refEncoded, c.Address)

	// Each tapscript in the derived contract must match the reference leaf scripts.
	refTapscripts, err := refVtxoScript.Encode()
	require.NoError(t, err)
	require.Equal(t, refTapscripts, c.Tapscripts)
}

func TestVHTLCHandler_MissingParams(t *testing.T) {
	t.Parallel()

	h := &handlers.VHTLCHandler{}
	key := testKey(t)
	cfg := testCfg(t)

	for _, tc := range []struct {
		name   string
		remove string
	}{
		{"missing sender", "sender"},
		{"missing receiver", "receiver"},
		{"missing hash", "hash"},
		{"missing refundLocktime", "refundLocktime"},
		{"missing claimDelay", "claimDelay"},
		{"missing refundDelay", "refundDelay"},
		{"missing refundNoReceiverDelay", "refundNoReceiverDelay"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, raw := vhtlcParams(t, cfg)
			delete(raw, tc.remove)
			_, err := h.DeriveContract(context.Background(), key, cfg, raw)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.remove)
		})
	}

	t.Run("nil rawParams", func(t *testing.T) {
		t.Parallel()
		_, err := h.DeriveContract(context.Background(), key, cfg, nil)
		require.Error(t, err)
	})

	t.Run("hash wrong length", func(t *testing.T) {
		t.Parallel()
		_, _, _, raw := vhtlcParams(t, cfg)
		raw["hash"] = hex.EncodeToString([]byte("tooshort"))
		_, err := h.DeriveContract(context.Background(), key, cfg, raw)
		require.Error(t, err)
		require.ErrorContains(t, err, "20 bytes")
	})
}

func TestVHTLCHandler_Deterministic(t *testing.T) {
	t.Parallel()

	h := &handlers.VHTLCHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	_, _, _, raw := vhtlcParams(t, cfg)

	c1, err := h.DeriveContract(context.Background(), key, cfg, raw)
	require.NoError(t, err)
	c2, err := h.DeriveContract(context.Background(), key, cfg, raw)
	require.NoError(t, err)

	require.Equal(t, c1.Script, c2.Script)
	require.Equal(t, c1.Address, c2.Address)
	require.Equal(t, c1.Tapscripts, c2.Tapscripts)
}

func TestVHTLCHandler_SelectPath(t *testing.T) {
	t.Parallel()

	h := &handlers.VHTLCHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	senderPriv, receiverPriv, preimage, raw := vhtlcParams(t, cfg)

	c, err := h.DeriveContract(context.Background(), key, cfg, raw)
	require.NoError(t, err)

	senderPubKey := schnorr.SerializePubKey(senderPriv.PubKey())
	receiverPubKey := schnorr.SerializePubKey(receiverPriv.PubKey())
	blockHeight := uint32(2000) // > refundLocktime(1000)

	t.Run("unknown role returns nil", func(t *testing.T) {
		t.Parallel()
		unknownKey := make([]byte, 32)
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  unknownKey,
		})
		require.NoError(t, err)
		require.Nil(t, sel)
	})

	t.Run("receiver collaborative with preimage → claim leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  receiverPubKey,
			Preimage:      preimage,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)
		require.True(t, bytes.Equal(preimage, sel.ExtraWitness[0]))
		// Leaf must be tapscripts[0] (claim)
		refScript, _ := hex.DecodeString(c.Tapscripts[0])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("receiver collaborative without preimage → nil", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  receiverPubKey,
		})
		require.NoError(t, err)
		require.Nil(t, sel)
	})

	t.Run("sender collaborative CLTV satisfied → refundWithoutReceiver leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  senderPubKey,
			BlockHeight:   &blockHeight,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)
		refScript, _ := hex.DecodeString(c.Tapscripts[2])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("sender collaborative CLTV not satisfied → nil", func(t *testing.T) {
		t.Parallel()
		low := uint32(500) // below refundLocktime(1000)
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  senderPubKey,
			BlockHeight:   &low,
		})
		require.NoError(t, err)
		require.Nil(t, sel)
	})

	t.Run("receiver unilateral with preimage → unilateralClaim leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  receiverPubKey,
			Preimage:      preimage,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)
		require.True(t, bytes.Equal(preimage, sel.ExtraWitness[0]))
		refScript, _ := hex.DecodeString(c.Tapscripts[3])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("sender unilateral → unilateralRefundWithoutReceiver leaf", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  senderPubKey,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)
		require.Empty(t, sel.ExtraWitness)
		refScript, _ := hex.DecodeString(c.Tapscripts[5])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})
}

func TestVHTLCHandler_GetSpendablePaths(t *testing.T) {
	t.Parallel()

	h := &handlers.VHTLCHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	senderPriv, receiverPriv, preimage, raw := vhtlcParams(t, cfg)

	c, err := h.DeriveContract(context.Background(), key, cfg, raw)
	require.NoError(t, err)

	senderPubKey := schnorr.SerializePubKey(senderPriv.PubKey())
	receiverPubKey := schnorr.SerializePubKey(receiverPriv.PubKey())

	t.Run("receiver collaborative with preimage → 1 path (claim)", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  receiverPubKey,
			Preimage:      preimage,
		})
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.Nil(t, paths[0].Sequence)
		require.NotEmpty(t, paths[0].ExtraWitness)
	})

	t.Run("sender collaborative → 1 path (refundWithoutReceiver)", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  senderPubKey,
		})
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.Nil(t, paths[0].Sequence)
	})

	t.Run("receiver unilateral with preimage → 1 path (unilateralClaim)", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  receiverPubKey,
			Preimage:      preimage,
		})
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.NotNil(t, paths[0].Sequence)
		require.NotEmpty(t, paths[0].ExtraWitness)
	})

	t.Run("sender unilateral → 1 path (unilateralRefundWithoutReceiver)", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  senderPubKey,
		})
		require.NoError(t, err)
		require.Len(t, paths, 1)
		require.NotNil(t, paths[0].Sequence)
	})

	t.Run("unknown role → 0 paths", func(t *testing.T) {
		t.Parallel()
		paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
			WalletPubKey: make([]byte, 32),
		})
		require.NoError(t, err)
		require.Empty(t, paths)
	})
}

func TestVHTLCHandler_SerializeDeserialize(t *testing.T) {
	t.Parallel()

	h := &handlers.VHTLCHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	_, _, _, raw := vhtlcParams(t, cfg)

	c, err := h.DeriveContract(context.Background(), key, cfg, raw)
	require.NoError(t, err)

	// Round-trip: deserialize the stored params and re-derive — must produce the same contract.
	got, err := h.DeserializeParams(c.Params)
	require.NoError(t, err)
	require.NotNil(t, got)

	c2, err := h.DeriveContract(context.Background(), key, cfg, c.Params)
	require.NoError(t, err)
	require.Equal(t, c.Script, c2.Script)
	require.Equal(t, c.Address, c2.Address)
	require.Equal(t, c.Tapscripts, c2.Tapscripts)
}
