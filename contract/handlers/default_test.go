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

	c, err := h.DeriveContract(ctx, key, cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, c)

	require.Equal(t, handlers.TypeDefault, c.Type)
	require.Equal(t, "test-key", c.Params["keyId"])
	require.Equal(t, arklib.LocktimeTypeBlock, c.Delay.Type)

	// Offchain address matches arklib reference derivation.
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

	// pkScript matches P2TR for the tap key.
	refPkScript, err := txscript.PayToTaprootScript(refVtxoTapKey)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(refPkScript), c.Script)

	// Boarding address matches reference.
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

	// Onchain address is bare key-path P2TR.
	refOnchainTapKey := txscript.ComputeTaprootKeyNoScript(key.PubKey)
	refOnchain, err := btcutil.NewAddressTaproot(
		schnorr.SerializePubKey(refOnchainTapKey), &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	require.Equal(t, refOnchain.EncodeAddress(), c.Onchain)

	require.Len(t, c.Tapscripts, 2)
	require.Len(t, c.BoardingTapscripts, 2)
}

func TestDefaultHandler_DeterministicOutput(t *testing.T) {
	t.Parallel()

	h := &handlers.DefaultHandler{}
	key := testKey(t)
	cfg := testCfg(t)
	ctx := context.Background()

	c1, err := h.DeriveContract(ctx, key, cfg, nil)
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, key, cfg, nil)
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

	c1, err := h.DeriveContract(ctx, testKey(t), cfg, nil)
	require.NoError(t, err)
	c2, err := h.DeriveContract(ctx, testKey(t), cfg, nil)
	require.NoError(t, err)

	require.NotEqual(t, c1.Script, c2.Script)
	require.NotEqual(t, c1.Address, c2.Address)
	require.NotEqual(t, c1.Boarding, c2.Boarding)
	require.NotEqual(t, c1.Onchain, c2.Onchain)
}
