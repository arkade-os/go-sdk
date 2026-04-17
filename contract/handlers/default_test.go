package handlers_test

import (
	"context"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

func testKey(t *testing.T) wallet.KeyRef {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return wallet.KeyRef{Id: "test-key", PubKey: priv.PubKey()}
}

func testCfg(t *testing.T) *clientTypes.Config {
	t.Helper()
	serverPriv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return &clientTypes.Config{
		SignerPubKey: serverPriv.PubKey(),
		Network:      arklib.BitcoinRegTest,
		UnilateralExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 144,
		},
		BoardingExitDelay: arklib.RelativeLocktime{
			Type:  arklib.LocktimeTypeBlock,
			Value: 1008,
		},
	}
}

func TestDefaultHandler_Type(t *testing.T) {
	t.Parallel()
	h := &handlers.DefaultHandler{}
	require.Equal(t, handlers.TypeDefault, h.Type())
}

func TestDefaultHandler_DeriveContract(t *testing.T) {
	t.Parallel()

	h := &handlers.DefaultHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	c, err := h.DeriveContract(ctx, key, cfg)
	require.NoError(t, err)
	require.NotNil(t, c)

	// ── Type and state ────────────────────────────────────────────────────
	require.Equal(t, handlers.TypeDefault, c.Type)
	require.Equal(t, "test-key", c.Params["keyId"])
	require.Equal(t, arklib.LocktimeTypeBlock, c.Delay.Type)

	// ── Offchain (Arkade) address matches arklib reference derivation ─────
	offchainScript := script.NewDefaultVtxoScript(
		key.PubKey, cfg.SignerPubKey, cfg.UnilateralExitDelay,
	)
	refVtxoTapKey, _, err := offchainScript.TapTree()
	require.NoError(t, err)

	refArkAddr := &arklib.Address{
		HRP:        cfg.Network.Addr,
		Signer:     cfg.SignerPubKey,
		VtxoTapKey: refVtxoTapKey,
	}
	refEncoded, err := refArkAddr.EncodeV0()
	require.NoError(t, err)
	require.Equal(t, refEncoded, c.Address)

	// ── Script (hex pkScript) matches P2TR output for the tap key ─────────
	refPkScript, err := txscript.PayToTaprootScript(refVtxoTapKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(refPkScript), c.Script)

	// ── Boarding address matches arklib reference derivation ──────────────
	boardingScript := script.NewDefaultVtxoScript(
		key.PubKey, cfg.SignerPubKey, cfg.BoardingExitDelay,
	)
	boardingTapKey, _, err := boardingScript.TapTree()
	require.NoError(t, err)

	refBoarding, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(boardingTapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, refBoarding.EncodeAddress(), c.Boarding)

	// ── Onchain address is bare key-path P2TR ─────────────────────────────
	refOnchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	refOnchain, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(refOnchainTapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, refOnchain.EncodeAddress(), c.Onchain)

	// ── Tapscripts are non-empty strings ─────────────────────────────────
	require.NotEmpty(t, c.Tapscripts)
	require.NotEmpty(t, c.BoardingTapscripts)
}

func TestDefaultHandler_DeterministicOutput(t *testing.T) {
	t.Parallel()

	h := &handlers.DefaultHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	c1, err := h.DeriveContract(ctx, key, cfg)
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, key, cfg)
	require.NoError(t, err)

	require.Equal(t, c1.Script, c2.Script)
	require.Equal(t, c1.Address, c2.Address)
	require.Equal(t, c1.Boarding, c2.Boarding)
	require.Equal(t, c1.Onchain, c2.Onchain)
}

func TestDefaultHandler_DifferentKeysDifferentContracts(t *testing.T) {
	t.Parallel()

	h := &handlers.DefaultHandler{}
	cfg := testCfg(t)
	ctx := context.Background()

	c1, err := h.DeriveContract(ctx, testKey(t), cfg)
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, testKey(t), cfg)
	require.NoError(t, err)

	require.NotEqual(t, c1.Script, c2.Script)
	require.NotEqual(t, c1.Address, c2.Address)
	require.NotEqual(t, c1.Boarding, c2.Boarding)
	require.NotEqual(t, c1.Onchain, c2.Onchain)
}

func TestDefaultHandler_SerializeDeserializeParams(t *testing.T) {
	t.Parallel()

	h := &handlers.DefaultHandler{}

	in := map[string]string{"keyId": "abc", "extra": "val"}
	out, err := h.SerializeParams(in)
	require.NoError(t, err)
	require.Equal(t, in, out)

	got, err := h.DeserializeParams(out)
	require.NoError(t, err)
	require.Equal(t, in, got)

	_, err = h.SerializeParams(42)
	require.Error(t, err)
}
