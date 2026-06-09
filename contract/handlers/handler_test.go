package handlers_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	htlcHandler "github.com/arkade-os/go-sdk/contract/handlers/htlc"
	vhtlcHandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

const (
	offchainMode = "offchain"
	onchainMode  = "onchain"
	htlcMode     = "htlc"
	vhtlcMode    = "vhtlc"

	// Values below and above 512 exercise block-based and second-based
	// relative locktime parsing.
	testUnilateralExitDelay int64 = 144
	testBoardingExitDelay   int64 = 1024

	// Real CSV-multisig closure encoded as hex. Offchain GetKeyRefs uses this
	// as the synthetic checkpoint script exit path.
	testCheckpointTapscript = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"
)

var testNetwork = arklib.BitcoinRegTest

type handlerInterfaceContractCase struct {
	name            string
	handler         func(t *testing.T) handlers.Handler
	params          func(t *testing.T, keyRef identity.KeyRef) any
	expectType      types.ContractType
	expectDerivable bool
	expectExitDelay bool
}

func TestHandlerInterfaceContract(t *testing.T) {
	cases := []handlerInterfaceContractCase{
		{
			name:            offchainMode,
			handler:         func(t *testing.T) handlers.Handler { return newTestDefaultHandler(t, false) },
			expectType:      types.ContractTypeDefault,
			expectDerivable: true,
			expectExitDelay: true,
		},
		{
			name:            onchainMode,
			handler:         func(t *testing.T) handlers.Handler { return newTestDefaultHandler(t, true) },
			expectType:      types.ContractTypeBoarding,
			expectDerivable: true,
			expectExitDelay: true,
		},
		{
			name:    htlcMode,
			handler: func(t *testing.T) handlers.Handler { return htlcHandler.NewHandler(testNetwork) },
			params: func(t *testing.T, keyRef identity.KeyRef) any {
				t.Helper()
				return newTestHTLCOpts(t, keyRef.PubKey)
			},
			expectType:      types.ContractTypeHTLC,
			expectDerivable: false,
		},
		{
			name: vhtlcMode,
			handler: func(t *testing.T) handlers.Handler {
				t.Helper()
				return vhtlcHandler.NewHandler(
					&mockClient{info: newTestInfo(newTestPubKey(t))},
					testNetwork,
				)
			},
			params: func(t *testing.T, _ identity.KeyRef) any {
				t.Helper()
				return newTestVHTLCOpts(t)
			},
			expectType:      types.ContractTypeVHTLC,
			expectDerivable: false,
			expectExitDelay: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.handler(t)
			require.Equal(t, tc.expectDerivable, h.Derivable())

			keyRef := newTestKeyRef(t)
			built, err := h.NewContract(t.Context(), keyRef, testParams(t, tc.params, keyRef))
			require.NoError(t, err)
			c := *built

			require.Equal(t, tc.expectType, c.Type)
			require.Equal(t, types.ContractStateActive, c.State)
			require.NotEmpty(t, c.Script)
			require.NotEmpty(t, c.Address)
			require.False(t, c.CreatedAt.IsZero())

			ref, err := h.GetKeyRef(c)
			require.NoError(t, err)
			require.NotNil(t, ref)
			require.Equal(t, keyRef.Id, ref.Id)
			require.Equal(
				t,
				schnorr.SerializePubKey(keyRef.PubKey),
				schnorr.SerializePubKey(ref.PubKey),
			)

			keyRefs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			require.Equal(t, keyRef.Id, keyRefs[c.Script])

			signer, err := h.GetSignerKey(c)
			require.NoError(t, err)
			require.NotNil(t, signer)

			delay, err := h.GetExitDelay(c)
			require.NoError(t, err)
			if tc.expectExitDelay {
				require.NotNil(t, delay)
				require.NotZero(t, delay.Value)
			} else {
				require.Nil(t, delay)
			}

			scripts, err := h.GetTapscripts(c)
			require.NoError(t, err)
			require.NotEmpty(t, scripts)
		})
	}
}

func testParams(
	t *testing.T,
	params func(t *testing.T, keyRef identity.KeyRef) any,
	keyRef identity.KeyRef,
) any {
	t.Helper()
	if params == nil {
		return nil
	}
	return params(t, keyRef)
}

func newTestDefaultHandler(t *testing.T, isOnchain bool) handlers.Handler {
	t.Helper()
	info := newTestInfo(newTestPubKey(t))
	return defaultHandler.NewHandler(
		&mockClient{info: info}, testNetwork, isOnchain,
	)
}

func newTestKeyRef(t *testing.T) identity.KeyRef {
	t.Helper()
	return identity.KeyRef{Id: "m/0/0", PubKey: newTestPubKey(t)}
}

func newTestPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}

func newTestInfo(signerKey *btcec.PublicKey) *client.Info {
	return &client.Info{
		SignerPubKey:        hex.EncodeToString(signerKey.SerializeCompressed()),
		UnilateralExitDelay: testUnilateralExitDelay,
		BoardingExitDelay:   testBoardingExitDelay,
		CheckpointTapscript: testCheckpointTapscript,
	}
}

func newTestVHTLCOpts(t *testing.T) *vhtlc.Opts {
	t.Helper()
	preimage := make([]byte, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)
	sha256Hash := sha256.Sum256(preimage)

	return &vhtlc.Opts{
		Sender:         newTestPubKey(t),
		Receiver:       newTestPubKey(t),
		Server:         newTestPubKey(t),
		PreimageHash:   input.Ripemd160H(sha256Hash[:]),
		RefundLocktime: arklib.AbsoluteLocktime(1577836800),
		UnilateralClaimDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: 512,
		},
		UnilateralRefundDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: 512,
		},
		UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: 1024,
		},
	}
}

func newTestHTLCOpts(t *testing.T, ownerKey *btcec.PublicKey) *htlcHandler.Opts {
	t.Helper()
	return &htlcHandler.Opts{
		Server: newTestPubKey(t),
		ClaimLeaf: htlcHandler.Leaf{
			Output: hex.EncodeToString(newTestClaimLeafScript(t, ownerKey)),
		},
		RefundLeaf: htlcHandler.Leaf{
			Output: hex.EncodeToString(newTestRefundLeafScript(t, newTestPubKey(t))),
		},
	}
}

func newTestClaimLeafScript(t *testing.T, claimKey *btcec.PublicKey) []byte {
	t.Helper()
	preimageHash := make([]byte, 20)
	_, err := rand.Read(preimageHash)
	require.NoError(t, err)

	scriptBytes, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_SIZE).
		AddData([]byte{0x20}).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_HASH160).
		AddData(preimageHash).
		AddOp(txscript.OP_EQUALVERIFY).
		AddData(schnorr.SerializePubKey(claimKey)).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	require.NoError(t, err)
	return scriptBytes
}

func newTestRefundLeafScript(t *testing.T, refundKey *btcec.PublicKey) []byte {
	t.Helper()
	scriptBytes, err := txscript.NewScriptBuilder().
		AddData(schnorr.SerializePubKey(refundKey)).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData([]byte{0xf8, 0x02}).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		Script()
	require.NoError(t, err)
	return scriptBytes
}
