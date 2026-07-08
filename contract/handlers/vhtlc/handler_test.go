package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

// This suite covers the VHTLC-specific behavior of the two handlers: args
// validation, sender/receiver key roles and per-param parsing failures. The
// behavior shared with the other handler kinds (contract shape, signer key,
// exit delay, tapscripts, checkpoint aliases) is exercised by the generalized
// fixtures in contract/handlers/handler_test.go.

var testNetwork = arklib.BitcoinRegTest

const (
	testCheckpointTapscript = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"

	// >= 512 so delays round-trip as second-based locktimes, and >= the mock
	// server's UnilateralExitDelay so args validation passes.
	testServerExitDelay int64 = 144
)

func TestNewContractArgsValidation(t *testing.T) {
	t.Run("vhtlc handler", func(t *testing.T) {
		h := newTestHandler(t)

		t.Run("rejects non-interactive args", func(t *testing.T) {
			args := NonInteractiveContractArgs{
				ContractArgs:           newTestContractArgs(t),
				NonInteractiveReceiver: newTestP2TRPkScript(t),
				NonInteractiveEmulator: newTestPubKey(t),
			}
			got, err := h.NewContract(t.Context(), args)
			require.Error(t, err)
			require.ErrorContains(t, err, "invalid contract args type")
			require.Nil(t, got)
		})

		cases := []struct {
			name          string
			mutate        func(*ContractArgs)
			expectedError string
		}{
			{
				name: "missing sender and receiver key ids",
				mutate: func(a *ContractArgs) {
					a.SenderKeyId = ""
					a.ReceiverKeyId = ""
				},
				expectedError: "key id ref must be provided",
			},
			{
				name:          "missing sender pubkey",
				mutate:        func(a *ContractArgs) { a.Sender = nil },
				expectedError: "missing sender pubkey",
			},
			{
				name:          "missing receiver pubkey",
				mutate:        func(a *ContractArgs) { a.Receiver = nil },
				expectedError: "missing receiver pubkey",
			},
			{
				name:          "missing preimage hash",
				mutate:        func(a *ContractArgs) { a.PreimageHash = nil },
				expectedError: "missing preimage hash",
			},
			{
				name:          "invalid preimage hash length",
				mutate:        func(a *ContractArgs) { a.PreimageHash = []byte{0x01, 0x02} },
				expectedError: "preimage hash must be 20 bytes",
			},
			{
				name:          "zero refund locktime",
				mutate:        func(a *ContractArgs) { a.RefundLocktime = 0 },
				expectedError: "refund locktime must be greater than 0",
			},
			{
				name: "claim delay below server minimum",
				mutate: func(a *ContractArgs) {
					a.UnilateralClaimDelay.Value = uint32(testServerExitDelay) - 1
				},
				expectedError: "unilateral claim delay must be greater than",
			},
			{
				name: "refund delay below server minimum",
				mutate: func(a *ContractArgs) {
					a.UnilateralRefundDelay.Value = uint32(testServerExitDelay) - 1
				},
				expectedError: "unilateral refund delay must be greater than",
			},
			{
				name: "refund without receiver delay below server minimum",
				mutate: func(a *ContractArgs) {
					a.UnilateralRefundWithoutReceiverDelay.Value = uint32(testServerExitDelay) - 1
				},
				expectedError: "unilateral refund without receiver delay must be greater than",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				args := newTestContractArgs(t)
				tc.mutate(&args)
				got, err := h.NewContract(t.Context(), args)
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				require.Nil(t, got)
			})
		}
	})

	t.Run("non-interactive handler", func(t *testing.T) {
		h := newTestNonInteractiveHandler(t)

		t.Run("rejects plain vhtlc args", func(t *testing.T) {
			got, err := h.NewContract(t.Context(), newTestContractArgs(t))
			require.Error(t, err)
			require.ErrorContains(t, err, "invalid contract args type")
			require.Nil(t, got)
		})

		t.Run("missing non-interactive receiver script", func(t *testing.T) {
			args := NonInteractiveContractArgs{
				ContractArgs:           newTestContractArgs(t),
				NonInteractiveEmulator: newTestPubKey(t),
			}
			got, err := h.NewContract(t.Context(), args)
			require.Error(t, err)
			require.ErrorContains(t, err, "missing non-interactive receiver script")
			require.Nil(t, got)
		})

		t.Run("missing non-interactive emulator pubkey", func(t *testing.T) {
			args := NonInteractiveContractArgs{
				ContractArgs:           newTestContractArgs(t),
				NonInteractiveReceiver: newTestP2TRPkScript(t),
			}
			got, err := h.NewContract(t.Context(), args)
			require.Error(t, err)
			require.ErrorContains(t, err, "missing non-interactive emulator pubkey")
			require.Nil(t, got)
		})
	})
}

func TestNewContractSignerKey(t *testing.T) {
	t.Run("nil signer uses the key fetched from server params", func(t *testing.T) {
		signer := newTestPubKey(t)
		h := newTestHandlerWithSigner(t, signer)

		built, err := h.NewContract(t.Context(), newTestContractArgs(t))
		require.NoError(t, err)
		require.Equal(
			t,
			hex.EncodeToString(schnorr.SerializePubKey(signer)),
			built.Params[signerKeyParam],
		)
	})

	t.Run("matching signer is accepted", func(t *testing.T) {
		signer := newTestPubKey(t)
		h := newTestHandlerWithSigner(t, signer)

		args := newTestContractArgs(t)
		args.Signer = signer

		built, err := h.NewContract(t.Context(), args)
		require.NoError(t, err)
		require.Equal(
			t,
			hex.EncodeToString(schnorr.SerializePubKey(signer)),
			built.Params[signerKeyParam],
		)
	})

	t.Run("x-only signer matches regardless of y parity", func(t *testing.T) {
		// Callers typically hold the signer key from an x-only source (ark
		// address, persisted signerKey param), which always parses to the
		// even-Y point. Force an odd-Y server key so the two encodings of
		// the same signer identity differ as curve points.
		signer := newTestOddYPubKey(t)
		h := newTestHandlerWithSigner(t, signer)

		xOnlySigner, err := schnorr.ParsePubKey(schnorr.SerializePubKey(signer))
		require.NoError(t, err)

		args := newTestContractArgs(t)
		args.Signer = xOnlySigner

		built, err := h.NewContract(t.Context(), args)
		require.NoError(t, err)
		require.Equal(
			t, hex.EncodeToString(schnorr.SerializePubKey(signer)), built.Params[signerKeyParam],
		)
	})

	t.Run("mismatching signer is rejected", func(t *testing.T) {
		h := newTestHandlerWithSigner(t, newTestPubKey(t))

		args := newTestContractArgs(t)
		args.Signer = newTestPubKey(t)

		built, err := h.NewContract(t.Context(), args)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid signer key")
		require.Nil(t, built)
	})
}

func TestKeyRoles(t *testing.T) {
	t.Run("sender-owned contract", func(t *testing.T) {
		h := newTestHandler(t)
		args := newTestContractArgs(t)

		built, err := h.NewContract(t.Context(), args)
		require.NoError(t, err)
		c := *built

		require.Equal(t, args.SenderKeyId, c.Params[senderKeyIdParam])
		require.NotContains(t, c.Params, receiverKeyIdParam)

		ref, err := h.GetKeyRef(c)
		require.NoError(t, err)
		require.Equal(t, args.SenderKeyId, ref.Id)
		require.Equal(
			t,
			schnorr.SerializePubKey(args.Sender),
			schnorr.SerializePubKey(ref.PubKey),
		)
	})

	t.Run("receiver-owned contract", func(t *testing.T) {
		h := newTestHandler(t)
		args := newTestContractArgs(t)
		args.SenderKeyId = ""
		args.ReceiverKeyId = "m/1/0"

		built, err := h.NewContract(t.Context(), args)
		require.NoError(t, err)
		c := *built

		require.Equal(t, args.ReceiverKeyId, c.Params[receiverKeyIdParam])
		require.NotContains(t, c.Params, senderKeyIdParam)

		ref, err := h.GetKeyRef(c)
		require.NoError(t, err)
		require.Equal(t, args.ReceiverKeyId, ref.Id)
		require.Equal(
			t,
			schnorr.SerializePubKey(args.Receiver),
			schnorr.SerializePubKey(ref.PubKey),
		)

		// The receiver takes part in the claim and refund closures, so the
		// contract script plus two checkpoint aliases must be returned.
		refs, err := h.GetKeyRefs(c)
		require.NoError(t, err)
		require.Len(t, refs, 3)
		for _, id := range refs {
			require.Equal(t, args.ReceiverKeyId, id)
		}

		// GetArgs must recover the key id under the same role it was
		// persisted with.
		gotArgs, err := h.GetArgs(c)
		require.NoError(t, err)
		got, ok := gotArgs.(ContractArgs)
		require.True(t, ok)
		require.Equal(t, args.ReceiverKeyId, got.ReceiverKeyId)
		require.Empty(t, got.SenderKeyId)
	})

	t.Run("prefers sender when both key ids are set", func(t *testing.T) {
		h := newTestHandler(t)
		args := newTestContractArgs(t)
		args.ReceiverKeyId = "m/1/0"

		built, err := h.NewContract(t.Context(), args)
		require.NoError(t, err)

		ref, err := h.GetKeyRef(*built)
		require.NoError(t, err)
		require.Equal(t, args.SenderKeyId, ref.Id)
		require.Equal(
			t,
			schnorr.SerializePubKey(args.Sender),
			schnorr.SerializePubKey(ref.PubKey),
		)
	})
}

func TestGetKeyRefInvalid(t *testing.T) {
	h := newTestHandler(t)

	cases := []struct {
		name          string
		nilParams     bool
		mutate        func(p map[string]string)
		expectedError string
	}{
		{
			name:          "no params",
			nilParams:     true,
			expectedError: "has no parameters",
		},
		{
			name: "missing sender and receiver key ids",
			mutate: func(p map[string]string) {
				delete(p, senderKeyIdParam)
				delete(p, receiverKeyIdParam)
			},
			expectedError: "missing sender or receiver key ID",
		},
		{
			name: "invalid sender key format",
			mutate: func(p map[string]string) {
				p[senderKeyParam] = "nothex"
			},
			expectedError: "invalid sender key format",
		},
		{
			name: "invalid sender key",
			mutate: func(p map[string]string) {
				p[senderKeyParam] = hex.EncodeToString([]byte{0x00, 0x01})
			},
			expectedError: "invalid sender key",
		},
		{
			name: "invalid receiver key format",
			mutate: func(p map[string]string) {
				delete(p, senderKeyIdParam)
				p[receiverKeyIdParam] = "m/1/0"
				p[receiverKeyParam] = "nothex"
			},
			expectedError: "invalid receiver key format",
		},
		{
			name: "invalid receiver key",
			mutate: func(p map[string]string) {
				delete(p, senderKeyIdParam)
				p[receiverKeyIdParam] = "m/1/0"
				p[receiverKeyParam] = hex.EncodeToString([]byte{0x00, 0x01})
			},
			expectedError: "invalid receiver key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var params map[string]string
			if !tc.nilParams {
				params = newTestParams(t)
				tc.mutate(params)
			}
			ref, err := h.GetKeyRef(types.Contract{Script: "broken", Params: params})
			require.Error(t, err)
			require.ErrorContains(t, err, tc.expectedError)
			require.Nil(t, ref)
		})
	}
}

func TestGetExitDelayInvalid(t *testing.T) {
	h := newTestHandler(t)

	cases := []struct {
		name          string
		nilParams     bool
		mutate        func(p map[string]string)
		expectedError string
	}{
		{
			name:          "no params",
			nilParams:     true,
			expectedError: "has no parameters",
		},
		{
			name: "missing delay",
			mutate: func(p map[string]string) {
				delete(p, unilateralRefundWithoutReceiverDelayParam)
			},
			expectedError: "missing unilateral refund without receiver delay",
		},
		{
			name: "invalid delay",
			mutate: func(p map[string]string) {
				p[unilateralRefundWithoutReceiverDelayParam] = "notanumber"
			},
			expectedError: "invalid format",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var params map[string]string
			if !tc.nilParams {
				params = newTestParams(t)
				tc.mutate(params)
			}
			delay, err := h.GetExitDelay(types.Contract{Script: "broken", Params: params})
			require.Error(t, err)
			require.ErrorContains(t, err, tc.expectedError)
			require.Nil(t, delay)
		})
	}
}

func TestGetTapscriptsInvalid(t *testing.T) {
	h := newTestHandler(t)

	cases := []struct {
		name          string
		mutate        func(t *testing.T, p map[string]string)
		expectedError string
	}{
		{
			name:          "missing sender key",
			mutate:        func(_ *testing.T, p map[string]string) { delete(p, senderKeyParam) },
			expectedError: "missing sender key",
		},
		{
			name: "invalid sender key format",
			mutate: func(_ *testing.T, p map[string]string) {
				p[senderKeyParam] = "nothex"
			},
			expectedError: "invalid sender key format",
		},
		{
			name:          "missing receiver key",
			mutate:        func(_ *testing.T, p map[string]string) { delete(p, receiverKeyParam) },
			expectedError: "missing receiver key",
		},
		{
			name: "invalid receiver key",
			mutate: func(_ *testing.T, p map[string]string) {
				p[receiverKeyParam] = hex.EncodeToString([]byte{0x00, 0x01})
			},
			expectedError: "invalid receiver key",
		},
		{
			name:          "missing signer key",
			mutate:        func(_ *testing.T, p map[string]string) { delete(p, signerKeyParam) },
			expectedError: "missing signer key",
		},
		{
			name: "invalid signer key",
			mutate: func(_ *testing.T, p map[string]string) {
				p[signerKeyParam] = hex.EncodeToString([]byte{0x00, 0x01})
			},
			expectedError: "invalid signer key",
		},
		{
			name:          "missing preimage hash",
			mutate:        func(_ *testing.T, p map[string]string) { delete(p, preimageHashParam) },
			expectedError: "missing preimage hash",
		},
		{
			name: "invalid preimage hash format",
			mutate: func(_ *testing.T, p map[string]string) {
				p[preimageHashParam] = "nothex"
			},
			expectedError: "invalid preimage hash format",
		},
		{
			name: "missing refund locktime",
			mutate: func(_ *testing.T, p map[string]string) {
				delete(p, refundLocktimeParam)
			},
			expectedError: "missing refund locktime",
		},
		{
			name: "invalid refund locktime",
			mutate: func(_ *testing.T, p map[string]string) {
				p[refundLocktimeParam] = "notanumber"
			},
			expectedError: "invalid refund locktime format",
		},
		{
			name: "missing unilateral claim delay",
			mutate: func(_ *testing.T, p map[string]string) {
				delete(p, unilateralClaimDelayParam)
			},
			expectedError: "missing unilateral claim delay",
		},
		{
			name: "invalid unilateral claim delay",
			mutate: func(_ *testing.T, p map[string]string) {
				p[unilateralClaimDelayParam] = "notanumber"
			},
			expectedError: "invalid format",
		},
		{
			name: "missing unilateral refund delay",
			mutate: func(_ *testing.T, p map[string]string) {
				delete(p, unilateralRefundDelayParam)
			},
			expectedError: "missing unilateral refund delay",
		},
		{
			name: "missing unilateral refund without receiver delay",
			mutate: func(_ *testing.T, p map[string]string) {
				delete(p, unilateralRefundWithoutReceiverDelayParam)
			},
			expectedError: "missing unilateral refund without receiver delay",
		},
		{
			name: "invalid non-interactive receiver script hex",
			mutate: func(_ *testing.T, p map[string]string) {
				p[nonInteractiveReceiverParam] = "nothex"
			},
			expectedError: "invalid non interactive receiver script",
		},
		{
			name: "non-interactive receiver without emulator key",
			mutate: func(t *testing.T, p map[string]string) {
				p[nonInteractiveReceiverParam] = hex.EncodeToString(newTestP2TRPkScript(t))
			},
			expectedError: "empty emulator key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := newTestParams(t)
			tc.mutate(t, params)
			scripts, err := h.GetTapscripts(types.Contract{Script: "broken", Params: params})
			require.Error(t, err)
			require.ErrorContains(t, err, tc.expectedError)
			require.Nil(t, scripts)
		})
	}
}

func TestGetArgsInvalid(t *testing.T) {
	t.Run("vhtlc handler", func(t *testing.T) {
		h := newTestHandler(t)

		cases := []struct {
			name          string
			mutate        func(p map[string]string)
			expectedError string
		}{
			{
				name:          "missing signer key",
				mutate:        func(p map[string]string) { delete(p, signerKeyParam) },
				expectedError: "missing signer key",
			},
			{
				name:          "empty sender key",
				mutate:        func(p map[string]string) { delete(p, senderKeyParam) },
				expectedError: "empty sender key",
			},
			{
				name:          "invalid sender key format",
				mutate:        func(p map[string]string) { p[senderKeyParam] = "nothex" },
				expectedError: "invalid sender key format",
			},
			{
				name: "invalid sender key",
				mutate: func(p map[string]string) {
					p[senderKeyParam] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid sender key",
			},
			{
				name:          "empty receiver key",
				mutate:        func(p map[string]string) { delete(p, receiverKeyParam) },
				expectedError: "empty receiver key",
			},
			{
				name: "invalid receiver key",
				mutate: func(p map[string]string) {
					p[receiverKeyParam] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid receiver key",
			},
			{
				name:          "empty preimage hash",
				mutate:        func(p map[string]string) { delete(p, preimageHashParam) },
				expectedError: "empty preimage hash",
			},
			{
				name:          "invalid preimage hash format",
				mutate:        func(p map[string]string) { p[preimageHashParam] = "nothex" },
				expectedError: "invalid preimage hash format",
			},
			{
				name: "invalid preimage hash length",
				mutate: func(p map[string]string) {
					p[preimageHashParam] = hex.EncodeToString([]byte{0x01, 0x02})
				},
				expectedError: "invalid preimage hash len",
			},
			{
				name:          "empty refund locktime",
				mutate:        func(p map[string]string) { delete(p, refundLocktimeParam) },
				expectedError: "empty absolute locktime",
			},
			{
				name:          "invalid refund locktime",
				mutate:        func(p map[string]string) { p[refundLocktimeParam] = "notanumber" },
				expectedError: "invalid absolute locktime format",
			},
			{
				name:          "zero refund locktime",
				mutate:        func(p map[string]string) { p[refundLocktimeParam] = "0" },
				expectedError: "zero absolute locktime",
			},
			{
				name:          "empty claim delay",
				mutate:        func(p map[string]string) { delete(p, unilateralClaimDelayParam) },
				expectedError: "empty relative locktime",
			},
			{
				name: "invalid claim delay",
				mutate: func(p map[string]string) {
					p[unilateralClaimDelayParam] = "notanumber"
				},
				expectedError: "invalid relative locktime format",
			},
			{
				name: "zero refund delay",
				mutate: func(p map[string]string) {
					p[unilateralRefundDelayParam] = "0"
				},
				expectedError: "zero relative locktime",
			},
			{
				name: "empty refund without receiver delay",
				mutate: func(p map[string]string) {
					delete(p, unilateralRefundWithoutReceiverDelayParam)
				},
				expectedError: "empty relative locktime",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				params := newTestParams(t)
				tc.mutate(params)
				got, err := h.GetArgs(types.Contract{Script: "broken", Params: params})
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				require.Nil(t, got)
			})
		}
	})

	t.Run("non-interactive handler", func(t *testing.T) {
		h := newTestNonInteractiveHandler(t)

		cases := []struct {
			name          string
			mutate        func(p map[string]string)
			expectedError string
		}{
			{
				name: "missing non-interactive receiver script",
				mutate: func(p map[string]string) {
					delete(p, nonInteractiveReceiverParam)
				},
				expectedError: "empty non interactive receiver script",
			},
			{
				name: "invalid non-interactive receiver script",
				mutate: func(p map[string]string) {
					p[nonInteractiveReceiverParam] = "nothex"
				},
				expectedError: "invalid non interactive receiver script format",
			},
			{
				name: "missing non-interactive emulator key",
				mutate: func(p map[string]string) {
					delete(p, nonInteractiveEmulatorParam)
				},
				expectedError: "empty emulator key",
			},
			{
				name: "invalid non-interactive emulator key",
				mutate: func(p map[string]string) {
					p[nonInteractiveEmulatorParam] = hex.EncodeToString([]byte{0x00, 0x01})
				},
				expectedError: "invalid emulator key",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				params := newTestNIParams(t)
				tc.mutate(params)
				got, err := h.GetArgs(types.Contract{Script: "broken", Params: params})
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedError)
				require.Nil(t, got)
			})
		}
	})
}

func newTestHandler(t *testing.T) *vhtlcHandler {
	t.Helper()
	h := NewHandler(newTestClient(t), testNetwork).(vhtlcHandler)
	return &h
}

func newTestNonInteractiveHandler(t *testing.T) *vhtlcNonInteractiveHandler {
	t.Helper()
	h := NewNonInteractiveHandler(newTestClient(t), testNetwork).(vhtlcNonInteractiveHandler)
	return &h
}

func newTestHandlerWithSigner(t *testing.T, signer *btcec.PublicKey) *vhtlcHandler {
	t.Helper()
	h := NewHandler(newTestClientWithSigner(t, signer), testNetwork).(vhtlcHandler)
	return &h
}

func newTestClient(t *testing.T) *mockInfoClient {
	t.Helper()
	return newTestClientWithSigner(t, newTestPubKey(t))
}

func newTestClientWithSigner(t *testing.T, signer *btcec.PublicKey) *mockInfoClient {
	t.Helper()
	return &mockInfoClient{
		info: &client.Info{
			SignerPubKey:        hex.EncodeToString(signer.SerializeCompressed()),
			UnilateralExitDelay: testServerExitDelay,
			CheckpointTapscript: testCheckpointTapscript,
		},
	}
}

// newTestParams returns the params of a freshly built sender-owned contract,
// ready to be mutated by the failure-path tables.
func newTestParams(t *testing.T) map[string]string {
	t.Helper()
	h := newTestHandler(t)
	built, err := h.NewContract(t.Context(), newTestContractArgs(t))
	require.NoError(t, err)
	return built.Params
}

// newTestNIParams is the non-interactive counterpart of newTestParams.
func newTestNIParams(t *testing.T) map[string]string {
	t.Helper()
	h := newTestNonInteractiveHandler(t)
	built, err := h.NewContract(t.Context(), NonInteractiveContractArgs{
		ContractArgs:           newTestContractArgs(t),
		NonInteractiveReceiver: newTestP2TRPkScript(t),
		NonInteractiveEmulator: newTestPubKey(t),
	})
	require.NoError(t, err)
	return built.Params
}

func newTestContractArgs(t *testing.T) ContractArgs {
	t.Helper()
	return ContractArgs{
		SenderKeyId:    "m/0/0",
		Sender:         newTestPubKey(t),
		Receiver:       newTestPubKey(t),
		PreimageHash:   newTestPreimageHash(t),
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

func newTestPreimageHash(t *testing.T) []byte {
	t.Helper()
	preimage := make([]byte, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)
	return btcutil.Hash160(preimage)
}

func newTestPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return priv.PubKey()
}

// newTestOddYPubKey generates a key whose compressed encoding has odd Y
// parity (0x03 prefix), i.e. a point that differs from its x-only (even-Y)
// schnorr normalization.
func newTestOddYPubKey(t *testing.T) *btcec.PublicKey {
	t.Helper()
	for {
		pk := newTestPubKey(t)
		if pk.SerializeCompressed()[0] == 0x03 {
			return pk
		}
	}
}

func newTestP2TRPkScript(t *testing.T) []byte {
	t.Helper()
	pkScript, err := txscript.PayToTaprootScript(newTestPubKey(t))
	require.NoError(t, err)
	return pkScript
}

type mockInfoClient struct {
	client.Client
	info *client.Info
}

func (m *mockInfoClient) GetInfo(_ context.Context) (*client.Info, error) {
	return m.info, nil
}
