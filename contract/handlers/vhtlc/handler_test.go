package vhtlcHandler

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

var testNetwork = arklib.BitcoinRegTest

type invalidCase struct {
	name          string
	params        map[string]string
	expectedError string
}

func TestVHTLCHandlerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		_, keyRef, opts, c := newVHTLCContract(t, newTestVHTLCOpts(t))

		require.Equal(t, ContractTypeVHTLC, c.Type)
		require.Equal(t, types.ContractStateActive, c.State)
		require.NotEmpty(t, c.Script)
		require.NotEmpty(t, c.Address)
		require.False(t, c.CreatedAt.IsZero())
		assertVHTLCContract(t, c, keyRef, opts)
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandler(testNetwork)
		keyRef := newTestKeyRef(t)

		t.Run("nil params", func(t *testing.T) {
			got, err := h.NewContract(t.Context(), keyRef, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "requires *vhtlc.Opts")
			require.Nil(t, got)
		})

		t.Run("wrong params type", func(t *testing.T) {
			got, err := h.NewContract(t.Context(), keyRef, "not-opts")
			require.Error(t, err)
			require.ErrorContains(t, err, "requires *vhtlc.Opts")
			require.Nil(t, got)
		})

		cases := []struct {
			name          string
			mutate        func(*vhtlc.Opts)
			expectedError string
		}{
			{
				name:          "missing sender",
				mutate:        func(o *vhtlc.Opts) { o.Sender = nil },
				expectedError: "missing sender pubkey",
			},
			{
				name:          "missing receiver",
				mutate:        func(o *vhtlc.Opts) { o.Receiver = nil },
				expectedError: "missing receiver pubkey",
			},
			{
				name:          "missing server",
				mutate:        func(o *vhtlc.Opts) { o.Server = nil },
				expectedError: "missing server pubkey",
			},
			{
				name:          "missing preimage hash",
				mutate:        func(o *vhtlc.Opts) { o.PreimageHash = nil },
				expectedError: "missing preimage hash",
			},
			{
				name:          "invalid preimage hash length",
				mutate:        func(o *vhtlc.Opts) { o.PreimageHash = []byte{0x01, 0x02} },
				expectedError: "preimage hash must be 20 bytes",
			},
			{
				name:          "zero refund locktime",
				mutate:        func(o *vhtlc.Opts) { o.RefundLocktime = 0 },
				expectedError: "refund locktime must be greater than 0",
			},
			{
				name: "invalid claim delay",
				mutate: func(o *vhtlc.Opts) {
					o.UnilateralClaimDelay = arklib.RelativeLocktime{
						Type: arklib.LocktimeTypeSecond, Value: 1,
					}
				},
				expectedError: "invalid unilateral claim delay",
			},
			{
				name: "invalid non-interactive claim",
				mutate: func(o *vhtlc.Opts) {
					o.NonInteractiveClaim = &vhtlc.NonInteractiveClaimOpts{
						ReceiverPkScript:   []byte{0x51},
						IntrospectorPubKey: newTestPubKey(t),
					}
				},
				expectedError: "receiver pkScript must be 34 bytes",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				opts := newTestVHTLCOpts(t)
				tc.mutate(opts)
				got, err := h.NewContract(t.Context(), keyRef, opts)
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				require.Nil(t, got)
			})
		}
	})
}

func TestVHTLCHandlerGetKeyRef(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h, keyRef, _, c := newVHTLCContract(t, newTestVHTLCOpts(t))

		ref, err := h.GetKeyRef(c)
		require.NoError(t, err)
		require.NotNil(t, ref)
		require.Equal(t, keyRef.Id, ref.Id)
		require.Equal(
			t,
			schnorr.SerializePubKey(keyRef.PubKey),
			schnorr.SerializePubKey(ref.PubKey),
		)
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandler(testNetwork)
		cases := []invalidCase{
			{name: "no params", params: nil, expectedError: "no params"},
			{
				name:          "missing ownerKeyId",
				params:        map[string]string{paramOwnerKey: "abcd"},
				expectedError: "missing param",
			},
			{
				name:          "empty ownerKeyId",
				params:        map[string]string{paramOwnerKeyID: "", paramOwnerKey: "abcd"},
				expectedError: "missing param",
			},
			{
				name:          "missing owner key",
				params:        map[string]string{paramOwnerKeyID: "m/0/0"},
				expectedError: "missing param",
			},
			{
				name:          "invalid owner key hex",
				params:        map[string]string{paramOwnerKeyID: "m/0/0", paramOwnerKey: "nothex"},
				expectedError: "invalid owner key hex",
			},
			{
				name: "invalid owner key",
				params: map[string]string{
					paramOwnerKeyID: "m/0/0",
					paramOwnerKey:   hex.EncodeToString([]byte{0x00, 0x01}),
				},
				expectedError: "invalid owner key",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				ref, err := h.GetKeyRef(types.Contract{Script: "broken", Params: c.params})
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Nil(t, ref)
			})
		}
	})
}

func TestVHTLCHandlerGetKeyRefs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h, keyRef, _, c := newVHTLCContract(t, newTestVHTLCOpts(t))

		refs, err := h.GetKeyRefs(c)
		require.NoError(t, err)
		require.Len(t, refs, 1)
		require.Equal(t, keyRef.Id, refs[c.Script])
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandler(testNetwork)
		cases := []invalidCase{
			{name: "no params", params: nil, expectedError: "no params"},
			{
				name: "invalid owner key",
				params: map[string]string{
					paramOwnerKeyID: "m/0/0",
					paramOwnerKey:   hex.EncodeToString([]byte{0x00, 0x01}),
				},
				expectedError: "invalid owner key",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				refs, err := h.GetKeyRefs(types.Contract{Script: "broken", Params: c.params})
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Nil(t, refs)
			})
		}
	})
}

func TestVHTLCHandlerGetSignerKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h, _, opts, c := newVHTLCContract(t, newTestVHTLCOpts(t))

		signer, err := h.GetSignerKey(c)
		require.NoError(t, err)
		require.NotNil(t, signer)
		require.Equal(t, opts.Server.SerializeCompressed(), signer.SerializeCompressed())
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandler(testNetwork)
		cases := []invalidCase{
			{name: "no params", params: nil, expectedError: "no params"},
			{
				name:          "missing server key",
				params:        map[string]string{paramOwnerKeyID: "m/0/0"},
				expectedError: "missing param",
			},
			{
				name:          "empty server key",
				params:        map[string]string{paramServer: ""},
				expectedError: "missing param",
			},
			{
				name:          "invalid server key hex",
				params:        map[string]string{paramServer: "nothex"},
				expectedError: "invalid server hex",
			},
			{
				name: "invalid server key",
				params: map[string]string{
					paramServer: hex.EncodeToString([]byte{0x00, 0x01}),
				},
				expectedError: "invalid server",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				signer, err := h.GetSignerKey(types.Contract{Script: "broken", Params: c.params})
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Nil(t, signer)
			})
		}
	})
}

func TestVHTLCHandlerGetExitDelay(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		h, _, opts, c := newVHTLCContract(t, newTestVHTLCOpts(t))

		delay, err := h.GetExitDelay(c)
		require.NoError(t, err)
		require.NotNil(t, delay)
		require.Equal(t, opts.UnilateralRefundWithoutReceiverDelay.Type, delay.Type)
		require.Equal(t, opts.UnilateralRefundWithoutReceiverDelay.Value, delay.Value)
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandler(testNetwork)
		cases := []invalidCase{
			{name: "no params", params: nil, expectedError: "no params"},
			{
				name:          "missing delay type",
				params:        map[string]string{paramOwnerKeyID: "m/0/0"},
				expectedError: "missing param",
			},
			{
				name: "missing delay value",
				params: map[string]string{
					paramRefundWithoutReceiverDelayType: "second",
				},
				expectedError: "missing param",
			},
			{
				name: "invalid delay value",
				params: map[string]string{
					paramRefundWithoutReceiverDelayType:  "second",
					paramRefundWithoutReceiverDelayValue: "notanumber",
				},
				expectedError: "invalid",
			},
			{
				name: "unknown delay type",
				params: map[string]string{
					paramRefundWithoutReceiverDelayType:  "unknown",
					paramRefundWithoutReceiverDelayValue: "1024",
				},
				expectedError: "unknown locktime type",
			},
		}

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				delay, err := h.GetExitDelay(types.Contract{Script: "broken", Params: c.params})
				require.Error(t, err)
				require.ErrorContains(t, err, c.expectedError)
				require.Nil(t, delay)
			})
		}
	})
}

func TestVHTLCHandlerGetTapscripts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("standard", func(t *testing.T) {
			h, _, _, c := newVHTLCContract(t, newTestVHTLCOpts(t))

			scripts, err := h.GetTapscripts(c)
			require.NoError(t, err)
			require.Len(t, scripts, 6)
			for _, s := range scripts {
				require.NotEmpty(t, s)
			}
		})

		t.Run("non-interactive claim", func(t *testing.T) {
			h, _, _, c := newVHTLCContract(t, newTestVHTLCOptsWithNIC(t))

			scripts, err := h.GetTapscripts(c)
			require.NoError(t, err)
			require.Len(t, scripts, 7)
			for _, s := range scripts {
				require.NotEmpty(t, s)
			}
		})
	})

	t.Run("invalid", func(t *testing.T) {
		h := NewHandler(testNetwork)
		cases := []struct {
			name          string
			nilParams     bool
			mutate        func(t *testing.T, p map[string]string)
			expectedError string
		}{
			{name: "no params", nilParams: true, expectedError: "no params"},
			{
				name:          "missing sender",
				mutate:        func(_ *testing.T, p map[string]string) { delete(p, paramSender) },
				expectedError: "missing param",
			},
			{
				name:          "invalid sender hex",
				mutate:        func(_ *testing.T, p map[string]string) { p[paramSender] = "nothex" },
				expectedError: "invalid sender hex",
			},
			{
				name: "invalid sender",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramSender] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid sender",
			},
			{
				name:          "missing receiver",
				mutate:        func(_ *testing.T, p map[string]string) { delete(p, paramReceiver) },
				expectedError: "missing param",
			},
			{
				name: "invalid receiver hex",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramReceiver] = "nothex"
				},
				expectedError: "invalid receiver hex",
			},
			{
				name: "invalid receiver",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramReceiver] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid receiver",
			},
			{
				name:          "missing server",
				mutate:        func(_ *testing.T, p map[string]string) { delete(p, paramServer) },
				expectedError: "missing param",
			},
			{
				name:          "invalid server hex",
				mutate:        func(_ *testing.T, p map[string]string) { p[paramServer] = "nothex" },
				expectedError: "invalid server hex",
			},
			{
				name: "invalid server",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramServer] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid server",
			},
			{
				name: "missing preimage hash",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramPreimageHash)
				},
				expectedError: "missing param",
			},
			{
				name: "invalid preimage hash hex",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramPreimageHash] = "nothex"
				},
				expectedError: "invalid preimage hash",
			},
			{
				name: "invalid preimage hash length",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramPreimageHash] = hex.EncodeToString([]byte{0x01, 0x02})
				},
				expectedError: "preimage hash must be 20 bytes",
			},
			{
				name: "missing refund locktime",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramRefundLocktime)
				},
				expectedError: "missing param",
			},
			{
				name: "invalid refund locktime",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramRefundLocktime] = "notanumber"
				},
				expectedError: "invalid refund locktime",
			},
			{
				name: "zero refund locktime",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramRefundLocktime] = "0"
				},
				expectedError: "refund locktime must be greater than 0",
			},
			{
				name: "missing claim delay type",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramClaimDelayType)
				},
				expectedError: "missing param",
			},
			{
				name: "missing claim delay value",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramClaimDelayValue)
				},
				expectedError: "missing param",
			},
			{
				name: "invalid claim delay value",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramClaimDelayValue] = "notanumber"
				},
				expectedError: "invalid claimDelayValue",
			},
			{
				name: "unknown claim delay type",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramClaimDelayType] = "unknown"
				},
				expectedError: "unknown locktime type",
			},
			{
				name: "missing refund delay type",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramRefundDelayType)
				},
				expectedError: "missing param",
			},
			{
				name: "invalid refund delay value",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramRefundDelayValue] = "notanumber"
				},
				expectedError: "invalid refundDelayValue",
			},
			{
				name: "unknown refund delay type",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramRefundDelayType] = "unknown"
				},
				expectedError: "unknown locktime type",
			},
			{
				name: "missing refund without receiver delay type",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramRefundWithoutReceiverDelayType)
				},
				expectedError: "missing param",
			},
			{
				name: "missing refund without receiver delay value",
				mutate: func(_ *testing.T, p map[string]string) {
					delete(p, paramRefundWithoutReceiverDelayValue)
				},
				expectedError: "missing param",
			},
			{
				name: "invalid refund without receiver delay value",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramRefundWithoutReceiverDelayValue] = "notanumber"
				},
				expectedError: "invalid refundWithoutReceiverDelayValue",
			},
			{
				name: "unknown refund without receiver delay type",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramRefundWithoutReceiverDelayType] = "unknown"
				},
				expectedError: "unknown locktime type",
			},
			{
				name: "invalid NIC receiver pkScript hex",
				mutate: func(_ *testing.T, p map[string]string) {
					p[paramNICReceiverPkScript] = "nothex"
				},
				expectedError: "invalid NIC receiver pkScript",
			},
			{
				name: "missing NIC introspector key",
				mutate: func(t *testing.T, p map[string]string) {
					p[paramNICReceiverPkScript] = hex.EncodeToString(newTestP2TRPkScript(t))
					delete(p, paramNICIntrospectorPubKey)
				},
				expectedError: "missing param",
			},
			{
				name: "invalid NIC introspector key hex",
				mutate: func(t *testing.T, p map[string]string) {
					p[paramNICReceiverPkScript] = hex.EncodeToString(newTestP2TRPkScript(t))
					p[paramNICIntrospectorPubKey] = "nothex"
				},
				expectedError: "invalid nicIntrospectorPubKey hex",
			},
			{
				name: "invalid NIC introspector key",
				mutate: func(t *testing.T, p map[string]string) {
					p[paramNICReceiverPkScript] = hex.EncodeToString(newTestP2TRPkScript(t))
					p[paramNICIntrospectorPubKey] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid nicIntrospectorPubKey",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var params map[string]string
				if !tc.nilParams {
					params = newVHTLCParams(t)
					tc.mutate(t, params)
				}
				scripts, err := h.GetTapscripts(types.Contract{Script: "broken", Params: params})
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				require.Nil(t, scripts)
			})
		}
	})
}

func newVHTLCContract(
	t *testing.T, opts *vhtlc.Opts,
) (*Handler, identity.KeyRef, *vhtlc.Opts, types.Contract) {
	t.Helper()
	h := NewHandler(testNetwork)
	keyRef := newTestKeyRef(t)
	built, err := h.NewContract(t.Context(), keyRef, opts)
	require.NoError(t, err)
	return h, keyRef, opts, *built
}

func newVHTLCParams(t *testing.T) map[string]string {
	t.Helper()
	_, _, _, c := newVHTLCContract(t, newTestVHTLCOpts(t))
	return copyParams(c.Params)
}

func copyParams(params map[string]string) map[string]string {
	cp := make(map[string]string, len(params))
	for k, v := range params {
		cp[k] = v
	}
	return cp
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

func newTestVHTLCOptsWithNIC(t *testing.T) *vhtlc.Opts {
	t.Helper()
	opts := newTestVHTLCOpts(t)
	opts.NonInteractiveClaim = &vhtlc.NonInteractiveClaimOpts{
		ReceiverPkScript:   newTestP2TRPkScript(t),
		IntrospectorPubKey: newTestPubKey(t),
	}
	return opts
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

func newTestP2TRPkScript(t *testing.T) []byte {
	t.Helper()
	pkScript, err := txscript.PayToTaprootScript(newTestPubKey(t))
	require.NoError(t, err)
	return pkScript
}

func assertVHTLCContract(
	t *testing.T, c types.Contract, keyRef identity.KeyRef, opts *vhtlc.Opts,
) {
	t.Helper()
	require.Equal(t, keyRef.Id, c.Params[paramOwnerKeyID])
	require.Equal(
		t,
		hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
		c.Params[paramOwnerKey],
	)
	require.Equal(
		t,
		hex.EncodeToString(opts.Server.SerializeCompressed()),
		c.Params[paramServer],
	)
	require.Contains(t, c.Address, testNetwork.Addr)
}
