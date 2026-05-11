package contract_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/go-sdk/contract"
	sdktypes "github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func vhtlcHash160(b []byte) []byte { return btcutil.Hash160(b) }

func vhtlcTestRawParams(
	t *testing.T,
) (senderPriv, receiverPriv *btcec.PrivateKey, preimage []byte, raw map[string]string) {
	t.Helper()

	var err error
	senderPriv, err = btcec.NewPrivateKey()
	require.NoError(t, err)
	receiverPriv, err = btcec.NewPrivateKey()
	require.NoError(t, err)

	preimage = []byte("test-preimage-secret")
	hash := vhtlcHash160(preimage)

	claimLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	claimSeq, err := arklib.BIP68Sequence(claimLT)
	require.NoError(t, err)

	refundLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 288}
	refundSeq, err := arklib.BIP68Sequence(refundLT)
	require.NoError(t, err)

	noRcvrLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 432}
	noRcvrSeq, err := arklib.BIP68Sequence(noRcvrLT)
	require.NoError(t, err)

	raw = map[string]string{
		contract.ParamVHTLCSender: hex.EncodeToString(
			schnorr.SerializePubKey(senderPriv.PubKey()),
		),
		contract.ParamVHTLCReceiver: hex.EncodeToString(
			schnorr.SerializePubKey(receiverPriv.PubKey()),
		),
		contract.ParamVHTLCHash:                  hex.EncodeToString(hash),
		contract.ParamVHTLCRefundLocktime:        "1000",
		contract.ParamVHTLCClaimDelay:            strconv.FormatUint(uint64(claimSeq), 10),
		contract.ParamVHTLCRefundDelay:           strconv.FormatUint(uint64(refundSeq), 10),
		contract.ParamVHTLCRefundNoReceiverDelay: strconv.FormatUint(uint64(noRcvrSeq), 10),
	}
	return
}

func TestVHTLCHandler_DeriveContract(t *testing.T) {
	t.Parallel()

	h := &contract.VHTLCHandler{}
	cfg := testCfg(t)
	ctx := context.Background()
	senderPriv, receiverPriv, _, raw := vhtlcTestRawParams(t)

	c, err := h.DeriveContract(ctx, raw, cfg)
	require.NoError(t, err)
	require.NotNil(t, c)

	require.Equal(t, sdktypes.ContractTypeVHTLC, c.Type)

	// Exactly 6 tapscripts.
	require.Len(t, c.GetTapscripts(), 6)

	// All participant keys are stored in params.
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(senderPriv.PubKey())),
		c.Params[contract.ParamVHTLCSender],
	)
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(receiverPriv.PubKey())),
		c.Params[contract.ParamVHTLCReceiver],
	)
	require.Equal(t,
		hex.EncodeToString(schnorr.SerializePubKey(cfg.SignerKey)),
		c.Params[contract.ParamVHTLCServer],
	)

	// Address matches manual derivation of the same 6-leaf tap tree.
	preimage := []byte("test-preimage-secret")
	hash := vhtlcHash160(preimage)
	condScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).AddData(hash).AddOp(txscript.OP_EQUAL).Script()
	require.NoError(t, err)

	claimLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 144}
	refundLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 288}
	noRcvrLT := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 432}

	refVtxoScript := &script.TapscriptsVtxoScript{
		Closures: []script.Closure{
			&script.ConditionMultisigClosure{
				Condition: condScript,
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{receiverPriv.PubKey(), cfg.SignerKey},
				},
			},
			&script.MultisigClosure{
				PubKeys: []*btcec.PublicKey{
					senderPriv.PubKey(),
					receiverPriv.PubKey(),
					cfg.SignerKey,
				},
			},
			&script.CLTVMultisigClosure{
				MultisigClosure: script.MultisigClosure{
					PubKeys: []*btcec.PublicKey{senderPriv.PubKey(), cfg.SignerKey},
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
		Signer:     cfg.SignerKey,
		VtxoTapKey: refTapKey,
	}
	refEncoded, err := refAddr.EncodeV0()
	require.NoError(t, err)
	require.Equal(t, refEncoded, c.Address)

	refPkScript, err := txscript.PayToTaprootScript(refTapKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(refPkScript), c.Script)

	refTs, err := refVtxoScript.Encode()
	require.NoError(t, err)
	require.Equal(t, refTs, c.GetTapscripts())
}

func TestVHTLCHandler_MissingParams(t *testing.T) {
	t.Parallel()

	h := &contract.VHTLCHandler{}
	cfg := testCfg(t)

	for _, tc := range []struct {
		name   string
		remove string
	}{
		{"missing sender", contract.ParamVHTLCSender},
		{"missing receiver", contract.ParamVHTLCReceiver},
		{"missing hash", contract.ParamVHTLCHash},
		{"missing refundLocktime", contract.ParamVHTLCRefundLocktime},
		{"missing claimDelay", contract.ParamVHTLCClaimDelay},
		{"missing refundDelay", contract.ParamVHTLCRefundDelay},
		{"missing refundNoReceiverDelay", contract.ParamVHTLCRefundNoReceiverDelay},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, _, raw := vhtlcTestRawParams(t)
			delete(raw, tc.remove)
			_, err := h.DeriveContract(context.Background(), raw, cfg)
			require.Error(t, err)
			require.ErrorContains(t, err, tc.remove)
		})
	}

	t.Run("nil rawParams", func(t *testing.T) {
		t.Parallel()
		_, err := h.DeriveContract(context.Background(), nil, cfg)
		require.Error(t, err)
	})

	t.Run("hash wrong length", func(t *testing.T) {
		t.Parallel()
		_, _, _, raw := vhtlcTestRawParams(t)
		raw[contract.ParamVHTLCHash] = hex.EncodeToString([]byte("tooshort"))
		_, err := h.DeriveContract(context.Background(), raw, cfg)
		require.Error(t, err)
		require.ErrorContains(t, err, "20 bytes")
	})
}

func TestVHTLCHandler_Deterministic(t *testing.T) {
	t.Parallel()

	h := &contract.VHTLCHandler{}
	cfg := testCfg(t)
	_, _, _, raw := vhtlcTestRawParams(t)

	c1, err := h.DeriveContract(context.Background(), raw, cfg)
	require.NoError(t, err)
	c2, err := h.DeriveContract(context.Background(), raw, cfg)
	require.NoError(t, err)

	require.Equal(t, c1.Script, c2.Script)
	require.Equal(t, c1.Address, c2.Address)
	require.Equal(t, c1.GetTapscripts(), c2.GetTapscripts())
}

func TestVHTLCHandler_RoundTripParams(t *testing.T) {
	t.Parallel()

	h := &contract.VHTLCHandler{}
	cfg := testCfg(t)
	_, _, _, raw := vhtlcTestRawParams(t)

	c, err := h.DeriveContract(context.Background(), raw, cfg)
	require.NoError(t, err)

	// Re-derive using stored params — must produce the same contract.
	c2, err := h.DeriveContract(context.Background(), c.Params, cfg)
	require.NoError(t, err)
	require.Equal(t, c.Script, c2.Script)
	require.Equal(t, c.Address, c2.Address)
	require.Equal(t, c.GetTapscripts(), c2.GetTapscripts())
}

func TestVHTLCHandler_SelectPath(t *testing.T) {
	t.Parallel()

	h := &contract.VHTLCHandler{}
	cfg := testCfg(t)
	senderPriv, receiverPriv, preimage, raw := vhtlcTestRawParams(t)

	c, err := h.DeriveContract(context.Background(), raw, cfg)
	require.NoError(t, err)

	senderPubKey := schnorr.SerializePubKey(senderPriv.PubKey())
	receiverPubKey := schnorr.SerializePubKey(receiverPriv.PubKey())
	blockAbove := uint32(2000) // > refundLocktime(1000)
	blockBelow := uint32(500)  // < refundLocktime(1000)

	t.Run("unknown role returns nil", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  make([]byte, 32),
		})
		require.NoError(t, err)
		require.Nil(t, sel)
	})

	t.Run("receiver collaborative with preimage → claim leaf[0]", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  receiverPubKey,
			Preimage:      preimage,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.Nil(t, sel.Sequence)
		require.Nil(t, sel.Locktime)
		require.True(t, bytes.Equal(preimage, sel.ExtraWitness[0]))
		refScript, _ := hex.DecodeString(c.GetTapscripts()[0])
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

	t.Run(
		"sender collaborative CLTV satisfied → refundWithoutReceiver leaf[2]",
		func(t *testing.T) {
			t.Parallel()
			sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
				Collaborative: true,
				WalletPubKey:  senderPubKey,
				BlockHeight:   &blockAbove,
			})
			require.NoError(t, err)
			require.NotNil(t, sel)
			require.Nil(t, sel.Sequence)
			require.NotNil(t, sel.Locktime)
			require.Equal(t, uint32(1000), *sel.Locktime)
			refScript, _ := hex.DecodeString(c.GetTapscripts()[2])
			require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
		},
	)

	t.Run("sender collaborative CLTV not satisfied → nil", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  senderPubKey,
			BlockHeight:   &blockBelow,
		})
		require.NoError(t, err)
		require.Nil(t, sel)
	})

	t.Run("receiver unilateral with preimage → unilateralClaim leaf[3]", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  receiverPubKey,
			Preimage:      preimage,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)
		require.Nil(t, sel.Locktime)
		require.True(t, bytes.Equal(preimage, sel.ExtraWitness[0]))
		refScript, _ := hex.DecodeString(c.GetTapscripts()[3])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("receiver unilateral without preimage → nil", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  receiverPubKey,
		})
		require.NoError(t, err)
		require.Nil(t, sel)
	})

	t.Run("sender unilateral → unilateralRefundWithoutReceiver leaf[5]", func(t *testing.T) {
		t.Parallel()
		sel, err := h.SelectPath(context.Background(), c, contract.PathContext{
			Collaborative: false,
			WalletPubKey:  senderPubKey,
		})
		require.NoError(t, err)
		require.NotNil(t, sel)
		require.NotNil(t, sel.Sequence)
		require.Nil(t, sel.Locktime)
		require.Empty(t, sel.ExtraWitness)
		refScript, _ := hex.DecodeString(c.GetTapscripts()[5])
		require.Equal(t, txscript.NewBaseTapLeaf(refScript), sel.Leaf)
	})

	t.Run("fewer than 6 tapscripts returns error", func(t *testing.T) {
		t.Parallel()
		bad := &sdktypes.Contract{
			Params: map[string]string{
				contract.ParamTapscripts: `["aa","bb","cc","dd","ee"]`,
			},
		}
		_, err := h.SelectPath(context.Background(), bad, contract.PathContext{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "6 tapscripts")
	})
}

func TestVHTLCHandler_GetSpendablePaths(t *testing.T) {
	t.Parallel()

	h := &contract.VHTLCHandler{}
	cfg := testCfg(t)
	senderPriv, receiverPriv, preimage, raw := vhtlcTestRawParams(t)

	c, err := h.DeriveContract(context.Background(), raw, cfg)
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

	t.Run(
		"sender collaborative CLTV satisfied → 1 path (refundWithoutReceiver)",
		func(t *testing.T) {
			t.Parallel()
			blockAbove := uint32(2000) // > refundLocktime(1000)
			paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
				Collaborative: true,
				WalletPubKey:  senderPubKey,
				BlockHeight:   &blockAbove,
			})
			require.NoError(t, err)
			require.Len(t, paths, 1)
			require.Nil(t, paths[0].Sequence)
			require.NotNil(t, paths[0].Locktime)
		},
	)

	t.Run("sender collaborative CLTV not satisfied → 0 paths", func(t *testing.T) {
		t.Parallel()
		blockBelow := uint32(500) // < refundLocktime(1000)
		paths, err := h.GetSpendablePaths(context.Background(), c, contract.PathContext{
			Collaborative: true,
			WalletPubKey:  senderPubKey,
			BlockHeight:   &blockBelow,
		})
		require.NoError(t, err)
		require.Empty(t, paths)
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

	t.Run("fewer than 6 tapscripts returns error", func(t *testing.T) {
		t.Parallel()
		bad := &sdktypes.Contract{
			Params: map[string]string{
				contract.ParamTapscripts: `["aa","bb","cc","dd","ee"]`,
			},
		}
		_, err := h.GetSpendablePaths(context.Background(), bad, contract.PathContext{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "6 tapscripts")
	})
}
