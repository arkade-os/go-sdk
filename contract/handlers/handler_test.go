package handlers_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	vhtlcHandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/require"
)

const (
	// < 512 → block-based RelativeLocktime.
	testUnilateralExitDelay int64 = 144
	// >= 512 → second-based RelativeLocktime.
	testBoardingExitDelay int64 = 1024

	// A real CSV-multisig closure encoded as hex — used as the test
	// checkpoint tapscript whenever an offchain test needs GetKeyRefs to
	// successfully decode and rebuild the synthetic checkpoint script.
	testCheckpointTapscript = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"

	// Default/boarding contract param keys.
	ownerKeyParam           = "ownerKey"
	ownerKeyIdParam         = "ownerKeyId"
	signerKeyParam          = "signerKey"
	exitDelayParam          = "exitDelay"
	checkpointExitPathParam = "checkpointExitPath"

	// VHTLC contract param keys, mirrored from the vhtlc package where they
	// are unexported.
	senderKeyIdParam                          = "senderKeyId"
	receiverKeyIdParam                        = "receiverKeyId"
	senderKeyParam                            = "senderKey"
	receiverKeyParam                          = "receiverKey"
	preimageHashParam                         = "preimageHash"
	refundLocktimeParam                       = "refundLocktime"
	unilateralClaimDelayParam                 = "unilateralClaimDelay"
	unilateralRefundDelayParam                = "unilateralRefundDelay"
	unilateralRefundWithoutReceiverDelayParam = "unilateralRefundWithoutReceiverDelay"
	nonInteractiveReceiverParam               = "nonInteractiveReceiver"
	nonInteractiveEmulatorParam               = "nonInteractiveEmulator"

	// VHTLC test locktimes. The unilateral delays must be >= the mock
	// server's UnilateralExitDelay to pass args validation, and >= 512 so
	// they round-trip as second-based locktimes.
	testVhtlcRefundLocktime             uint64 = 1577836800
	testVhtlcClaimDelay                 uint32 = 512
	testVhtlcRefundDelay                uint32 = 512
	testVhtlcRefundWithoutReceiverDelay uint32 = 1024
)

var testNetwork = arklib.BitcoinRegTest

// handlerFixture is one row of the parametrization driving every TestHandler*:
// each handler kind is built through newHandler and fed NewContract args built
// by newArgs so that GetKeyRef round-trips back to the same key reference.
// Handler-specific expectations (contract type, params, entry counts) live on
// the fixture; handler-specific failure modes stay in each handler's own
// package tests.
type handlerFixture struct {
	name             string
	expectType       types.ContractType
	newHandler       func(c client.Client) handlers.Handler
	newArgs          func(t *testing.T, keyRef identity.KeyRef) any
	wrongArgsErr     string
	expectExitDelay  arklib.RelativeLocktime
	expectKeyRefs    int
	expectTapscripts int
	// assertContract checks handler-specific params and address encoding on a
	// freshly built contract. args is the value previously returned by newArgs.
	assertContract func(t *testing.T, c types.Contract, keyRef identity.KeyRef, args any)
	// assertArgs checks that the args recovered via GetArgs match the ones the
	// contract was originally built from (origArgs is the newArgs value).
	assertArgs func(t *testing.T, c types.Contract, keyRef identity.KeyRef, origArgs, gotArgs any)
}

// defaultFixtures covers the two derivable handler kinds built from the
// default handler factory. Their param-level failure modes are asserted in
// the tables guarded by these fixtures below.
var defaultFixtures = []handlerFixture{
	{
		name:       "default",
		expectType: types.ContractTypeDefault,
		newHandler: func(c client.Client) handlers.Handler {
			return defaultHandler.NewHandler(c, testNetwork, false)
		},
		newArgs: func(t *testing.T, keyRef identity.KeyRef) any {
			return keyRef
		},
		wrongArgsErr: "invalid params type",
		expectExitDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeBlock, Value: uint32(testUnilateralExitDelay),
		},
		expectKeyRefs:    2,
		expectTapscripts: 2,
		assertContract: func(t *testing.T, c types.Contract, keyRef identity.KeyRef, _ any) {
			assertOwnerParams(t, c, keyRef)
			require.Equal(
				t, strconv.FormatInt(testUnilateralExitDelay, 10), c.Params[exitDelayParam],
			)
			require.Equal(t, testCheckpointTapscript, c.Params[checkpointExitPathParam])
			require.Contains(t, c.Address, testNetwork.Addr)
		},
		assertArgs: assertOwnerArgs,
	},
	{
		name:       "boarding",
		expectType: types.ContractTypeBoarding,
		newHandler: func(c client.Client) handlers.Handler {
			return defaultHandler.NewHandler(c, testNetwork, true)
		},
		newArgs: func(t *testing.T, keyRef identity.KeyRef) any {
			return keyRef
		},
		wrongArgsErr: "invalid params type",
		expectExitDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: uint32(testBoardingExitDelay),
		},
		expectKeyRefs:    1,
		expectTapscripts: 2,
		assertContract: func(t *testing.T, c types.Contract, keyRef identity.KeyRef, _ any) {
			assertOwnerParams(t, c, keyRef)
			require.Equal(
				t, strconv.FormatInt(testBoardingExitDelay, 10), c.Params[exitDelayParam],
			)
			require.NotContains(t, c.Params, checkpointExitPathParam)
			require.Contains(t, c.Address, "bcrt1p")
		},
		assertArgs: assertOwnerArgs,
	},
}

// vhtlcFixtures covers the two VHTLC handler kinds. The wallet key plays the
// sender role, so GetKeyRefs is expected to alias the two sender closures
// (refund, refund-without-receiver) on top of the contract script.
var vhtlcFixtures = []handlerFixture{
	{
		name:       "vhtlc",
		expectType: types.ContractTypeVHTLC,
		newHandler: func(c client.Client) handlers.Handler {
			return vhtlcHandler.NewHandler(c, testNetwork)
		},
		newArgs: func(t *testing.T, keyRef identity.KeyRef) any {
			return newTestVhtlcArgs(t, keyRef)
		},
		wrongArgsErr: "invalid contract args type",
		expectExitDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: testVhtlcRefundWithoutReceiverDelay,
		},
		expectKeyRefs:    3,
		expectTapscripts: 6,
		assertContract: func(t *testing.T, c types.Contract, keyRef identity.KeyRef, args any) {
			assertVhtlcParams(t, c, keyRef, args.(vhtlcHandler.ContractArgs))
			require.NotContains(t, c.Params, nonInteractiveReceiverParam)
			require.NotContains(t, c.Params, nonInteractiveEmulatorParam)
		},
		assertArgs: func(
			t *testing.T, c types.Contract, _ identity.KeyRef, origArgs, gotArgs any,
		) {
			got, ok := gotArgs.(vhtlcHandler.ContractArgs)
			require.True(t, ok, "GetArgs must return the args type NewContract accepts")
			assertVhtlcArgs(t, c, origArgs.(vhtlcHandler.ContractArgs), got)
		},
	},
	{
		name:       "vhtlc non-interactive",
		expectType: types.ContractTypeNonInteractiveVHTLC,
		newHandler: func(c client.Client) handlers.Handler {
			return vhtlcHandler.NewNonInteractiveHandler(c, testNetwork)
		},
		newArgs: func(t *testing.T, keyRef identity.KeyRef) any {
			return vhtlcHandler.NonInteractiveContractArgs{
				ContractArgs:           newTestVhtlcArgs(t, keyRef),
				NonInteractiveReceiver: newTestP2TRPkScript(t),
				NonInteractiveEmulator: newTestPubKey(t),
			}
		},
		wrongArgsErr: "invalid contract args type",
		expectExitDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: testVhtlcRefundWithoutReceiverDelay,
		},
		expectKeyRefs:    3,
		expectTapscripts: 7,
		assertContract: func(t *testing.T, c types.Contract, keyRef identity.KeyRef, args any) {
			nicArgs := args.(vhtlcHandler.NonInteractiveContractArgs)
			assertVhtlcParams(t, c, keyRef, nicArgs.ContractArgs)
			require.Equal(
				t,
				hex.EncodeToString(nicArgs.NonInteractiveReceiver),
				c.Params[nonInteractiveReceiverParam],
			)
			require.Equal(
				t,
				hex.EncodeToString(schnorr.SerializePubKey(nicArgs.NonInteractiveEmulator)),
				c.Params[nonInteractiveEmulatorParam],
			)
		},
		assertArgs: func(
			t *testing.T, c types.Contract, _ identity.KeyRef, origArgs, gotArgs any,
		) {
			orig := origArgs.(vhtlcHandler.NonInteractiveContractArgs)
			got, ok := gotArgs.(vhtlcHandler.NonInteractiveContractArgs)
			require.True(t, ok, "GetArgs must return the args type NewContract accepts")
			assertVhtlcArgs(t, c, orig.ContractArgs, got.ContractArgs)
			require.Equal(t, orig.NonInteractiveReceiver, got.NonInteractiveReceiver)
			require.Equal(
				t,
				schnorr.SerializePubKey(orig.NonInteractiveEmulator),
				schnorr.SerializePubKey(got.NonInteractiveEmulator),
			)
		},
	},
}

var allFixtures = append(append([]handlerFixture{}, defaultFixtures...), vhtlcFixtures...)

// offchainFixtures are the handler kinds that attach a checkpoint exit path
// to their contracts, so GetKeyRefs must decode it.
var offchainFixtures = []handlerFixture{
	defaultFixtures[0], vhtlcFixtures[0], vhtlcFixtures[1],
}

func TestHandlerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				_, keyRef, args, c := f.newTestContract(t)

				require.Equal(t, f.expectType, c.Type)
				require.Equal(t, types.ContractStateActive, c.State)
				require.NotEmpty(t, c.Script)
				require.NotEmpty(t, c.Address)
				require.False(t, c.CreatedAt.IsZero())
				require.NotEmpty(t, c.Params[signerKeyParam])
				f.assertContract(t, c, keyRef, args)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				keyRef := newTestKeyRef(t)

				cases := []struct {
					name          string
					info          *client.Info
					infoErr       error
					args          any
					expectedError string
				}{
					{
						name:          "GetInfo fails",
						infoErr:       errors.New("transport error"),
						expectedError: "failed to get server params",
					},
					{
						name:          "invalid signer pubkey hex",
						info:          &client.Info{SignerPubKey: "not-hex"},
						expectedError: "invalid format",
					},
					{
						name: "invalid signer pubkey bytes",
						info: &client.Info{
							SignerPubKey: hex.EncodeToString([]byte{0x01, 0x02}),
						},
						expectedError: "failed to parse signer pubkey",
					},
					{
						name:          "wrong args type",
						info:          newTestInfo(t, newTestPubKey(t)),
						args:          42,
						expectedError: f.wrongArgsErr,
					},
				}

				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						h := f.newHandler(&mockClient{info: c.info, infoErr: c.infoErr})
						args := c.args
						if args == nil {
							args = f.newArgs(t, keyRef)
						}
						got, err := h.NewContract(t.Context(), args)
						require.Error(t, err)
						require.ErrorContains(t, err, c.expectedError)
						require.Nil(t, got)
					})
				}
			})
		}
	})
}

func TestHandlerGetKeyRef(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h, keyRef, _, c := f.newTestContract(t)

				ref, err := h.GetKeyRef(c)
				require.NoError(t, err)
				require.NotNil(t, ref)
				require.Equal(t, keyRef.Id, ref.Id)
				// Schnorr serialization is x-only and drops y-parity, so
				// compare the canonical encodings, not the parsed *PublicKey.
				require.Equal(
					t,
					schnorr.SerializePubKey(keyRef.PubKey),
					schnorr.SerializePubKey(ref.PubKey),
				)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("no params", func(t *testing.T) {
			for _, f := range allFixtures {
				t.Run(f.name, func(t *testing.T) {
					h := f.newTestHandler(t)
					ref, err := h.GetKeyRef(types.Contract{Script: "broken"})
					require.Error(t, err)
					require.ErrorContains(t, err, "has no parameters")
					require.Nil(t, ref)
				})
			}
		})

		// Param-level failure modes are default-handler specific; the vhtlc
		// equivalents are covered in the vhtlc package tests.
		for _, f := range defaultFixtures {
			t.Run(f.name, func(t *testing.T) {
				h := f.newTestHandler(t)

				cases := []struct {
					name          string
					params        map[string]string
					expectedError string
				}{
					{
						name:          "missing key id",
						params:        map[string]string{ownerKeyParam: "abcd"},
						expectedError: "missing owner key ID",
					},
					{
						name: "empty key id",
						params: map[string]string{
							ownerKeyIdParam: "",
							ownerKeyParam:   "abcd",
						},
						expectedError: "empty owner key ID",
					},
					{
						name:          "missing owner key",
						params:        map[string]string{ownerKeyIdParam: "m/0/0"},
						expectedError: "missing owner key",
					},
					{
						name: "invalid owner key format",
						params: map[string]string{
							ownerKeyIdParam: "m/0/0",
							ownerKeyParam:   "nothex",
						},
						expectedError: "invalid owner key format",
					},
					{
						name: "invalid owner key",
						params: map[string]string{
							ownerKeyIdParam: "m/0/0",
							ownerKeyParam:   hex.EncodeToString([]byte{0x00, 0x01}),
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
	})
}

func TestHandlerGetKeyRefs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h, keyRef, _, c := f.newTestContract(t)

				refs, err := h.GetKeyRefs(c)
				require.NoError(t, err)
				// One entry for the contract's own script plus one synthetic
				// checkpoint script per closure the wallet key takes part in —
				// all mapping to the same wallet key id.
				require.Len(t, refs, f.expectKeyRefs)
				require.Equal(t, keyRef.Id, refs[c.Script])
				for script, id := range refs {
					require.NotEmpty(t, script)
					require.Equal(t, keyRef.Id, id)
				}
			})
		}
	})

	t.Run("boarding short-circuits before reading checkpointExitPath", func(t *testing.T) {
		// The boarding handler must not consult the checkpoint param
		// at all — pin this so a refactor that lifts the param read
		// above the isOnchain branch can't silently break boarding.
		boarding := defaultFixtures[1]
		h, keyRef, _, c := boarding.newTestContract(t)
		delete(c.Params, checkpointExitPathParam)

		refs, err := h.GetKeyRefs(c)
		require.NoError(t, err)
		require.Len(t, refs, 1)
		require.Equal(t, keyRef.Id, refs[c.Script])
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("inner getter failure propagates", func(t *testing.T) {
			// Smoke test: the per-param failure paths are exhaustively
			// covered by each handler's own tests. Here we only pin that
			// GetKeyRefs forwards them rather than silently swallowing.
			for _, f := range allFixtures {
				t.Run(f.name, func(t *testing.T) {
					h := f.newTestHandler(t)
					refs, err := h.GetKeyRefs(types.Contract{Script: "broken"})
					require.Error(t, err)
					require.Nil(t, refs)
				})
			}
		})

		checkpointCases := []struct {
			name            string
			mutateContract  func(c *types.Contract)
			wantErrContains string
		}{
			{
				name: "missing checkpointExitPath",
				mutateContract: func(c *types.Contract) {
					delete(c.Params, checkpointExitPathParam)
				},
				wantErrContains: "missing checkpoint exit path",
			},
			{
				name: "malformed checkpointExitPath hex",
				mutateContract: func(c *types.Contract) {
					c.Params[checkpointExitPathParam] = "nothex"
				},
				wantErrContains: "invalid checkpoint exit path format",
			},
			{
				name: "well-formed hex that is not a CSV multisig closure",
				mutateContract: func(c *types.Contract) {
					c.Params[checkpointExitPathParam] = hex.EncodeToString([]byte{0x00, 0x01, 0x02})
				},
				// The closure decoder either errors out or returns
				// valid=false; both paths surface "checkpoint exit path"
				// in the wrapped error.
				wantErrContains: "checkpoint exit path",
			},
		}

		for _, f := range offchainFixtures {
			for _, tc := range checkpointCases {
				t.Run(f.name+": "+tc.name, func(t *testing.T) {
					h, _, _, c := f.newTestContract(t)
					tc.mutateContract(&c)

					refs, err := h.GetKeyRefs(c)
					require.Error(t, err)
					require.ErrorContains(t, err, tc.wantErrContains)
					require.Nil(t, refs)
				})
			}
		}
	})
}

func TestHandlerGetSignerKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h, _, _, c := f.newTestContract(t)

				signer, err := h.GetSignerKey(c)
				require.NoError(t, err)
				require.NotNil(t, signer)
				require.Equal(
					t,
					c.Params[signerKeyParam],
					hex.EncodeToString(schnorr.SerializePubKey(signer)),
				)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		// The signer key param and its error messages are shared by every
		// handler kind, so the table runs against all of them.
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h := f.newTestHandler(t)

				cases := []struct {
					name          string
					params        map[string]string
					expectedError string
				}{
					{
						name:          "no params",
						params:        nil,
						expectedError: "has no parameters",
					},
					{
						name:          "missing signer key",
						params:        map[string]string{ownerKeyIdParam: "m/0/0"},
						expectedError: "missing signer key",
					},
					{
						name: "invalid signer key format",
						params: map[string]string{
							signerKeyParam: "nothex",
						},
						expectedError: "invalid signer key format",
					},
					{
						name: "invalid signer key",
						params: map[string]string{
							signerKeyParam: hex.EncodeToString([]byte{0x00, 0x01}),
						},
						expectedError: "invalid signer key",
					},
				}

				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						signer, err := h.GetSignerKey(
							types.Contract{Script: "broken", Params: c.params},
						)
						require.Error(t, err)
						require.ErrorContains(t, err, c.expectedError)
						require.Nil(t, signer)
					})
				}
			})
		}
	})
}

func TestHandlerGetExitDelay(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h, _, _, c := f.newTestContract(t)

				delay, err := h.GetExitDelay(c)
				require.NoError(t, err)
				require.NotNil(t, delay)
				require.Equal(t, f.expectExitDelay.Type, delay.Type)
				require.Equal(t, f.expectExitDelay.Value, delay.Value)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		// Param-level failure modes are default-handler specific; the vhtlc
		// equivalents are covered in the vhtlc package tests.
		for _, f := range defaultFixtures {
			t.Run(f.name, func(t *testing.T) {
				h := f.newTestHandler(t)

				cases := []struct {
					name          string
					params        map[string]string
					expectedError string
				}{
					{
						name:          "no params",
						params:        nil,
						expectedError: "has no parameters",
					},
					{
						name:          "missing exit delay",
						params:        map[string]string{ownerKeyIdParam: "m/0/0"},
						expectedError: "missing exit delay",
					},
					{
						name: "invalid exit delay format",
						params: map[string]string{
							exitDelayParam: "notanumber",
						},
						expectedError: "invalid exit delay format",
					},
				}

				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						delay, err := h.GetExitDelay(
							types.Contract{Script: "broken", Params: c.params},
						)
						require.Error(t, err)
						require.ErrorContains(t, err, c.expectedError)
						require.Nil(t, delay)
					})
				}
			})
		}
	})
}

func TestHandlerGetTapscripts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h, _, _, c := f.newTestContract(t)

				scripts, err := h.GetTapscripts(c)
				require.NoError(t, err)
				require.Len(t, scripts, f.expectTapscripts)
				for _, s := range scripts {
					require.NotEmpty(t, s)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("no params", func(t *testing.T) {
			for _, f := range allFixtures {
				t.Run(f.name, func(t *testing.T) {
					h := f.newTestHandler(t)
					scripts, err := h.GetTapscripts(types.Contract{Script: "broken"})
					require.Error(t, err)
					require.Nil(t, scripts)
				})
			}
		})

		// Param-level failure modes are default-handler specific; the vhtlc
		// equivalents are covered in the vhtlc package tests.
		for _, f := range defaultFixtures {
			t.Run(f.name, func(t *testing.T) {
				h := f.newTestHandler(t)

				// Each case strips a different required param so the corresponding
				// inner getter (KeyRef / SignerKey / ExitDelay) is the one that fails.
				validParams := func() map[string]string {
					return map[string]string{
						ownerKeyIdParam: "m/0/0",
						ownerKeyParam: hex.EncodeToString(
							schnorr.SerializePubKey(newTestPubKey(t)),
						),
						signerKeyParam: hex.EncodeToString(
							schnorr.SerializePubKey(newTestPubKey(t)),
						),
						exitDelayParam: "144",
					}
				}

				cases := []struct {
					name          string
					mutate        func(map[string]string)
					expectedError string
				}{
					{
						name:          "missing key ID",
						mutate:        func(p map[string]string) { delete(p, ownerKeyIdParam) },
						expectedError: "failed to get key reference",
					},
					{
						name:          "missing signer key",
						mutate:        func(p map[string]string) { delete(p, signerKeyParam) },
						expectedError: "failed to get signer key",
					},
					{
						name:          "missing exit delay",
						mutate:        func(p map[string]string) { delete(p, exitDelayParam) },
						expectedError: "failed to get exit delay",
					},
				}

				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						params := validParams()
						c.mutate(params)
						scripts, err := h.GetTapscripts(
							types.Contract{Script: "broken", Params: params},
						)
						require.Error(t, err)
						require.ErrorContains(t, err, c.expectedError)
						require.Nil(t, scripts)
					})
				}
			})
		}
	})
}

func TestHandlerGetArgs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, f := range allFixtures {
			t.Run(f.name, func(t *testing.T) {
				h, keyRef, args, c := f.newTestContract(t)

				got, err := h.GetArgs(c)
				require.NoError(t, err)
				require.NotNil(t, got)
				f.assertArgs(t, c, keyRef, args, got)

				// The recovered args must be directly usable by NewContract
				// to rebuild the very same contract.
				rebuilt, err := h.NewContract(t.Context(), got)
				require.NoError(t, err)
				require.Equal(t, c.Type, rebuilt.Type)
				require.Equal(t, c.Script, rebuilt.Script)
				require.Equal(t, c.Address, rebuilt.Address)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		// Per-param failure modes are handler-specific and covered in each
		// handler's own package tests; here we only pin the shared guard.
		t.Run("no params", func(t *testing.T) {
			for _, f := range allFixtures {
				t.Run(f.name, func(t *testing.T) {
					h := f.newTestHandler(t)
					got, err := h.GetArgs(types.Contract{Script: "broken"})
					require.Error(t, err)
					require.Nil(t, got)
				})
			}
		})
	})
}

func (f handlerFixture) newTestHandler(t *testing.T) handlers.Handler {
	t.Helper()
	return f.newHandler(&mockClient{info: newTestInfo(t, newTestPubKey(t))})
}

// newTestContract builds a fresh contract through the fixture's handler and
// returns everything a test needs to assert against it.
func (f handlerFixture) newTestContract(
	t *testing.T,
) (handlers.Handler, identity.KeyRef, any, types.Contract) {
	t.Helper()
	h := f.newTestHandler(t)
	keyRef := newTestKeyRef(t)
	args := f.newArgs(t, keyRef)
	built, err := h.NewContract(t.Context(), args)
	require.NoError(t, err)
	return h, keyRef, args, *built
}

func assertOwnerParams(t *testing.T, c types.Contract, keyRef identity.KeyRef) {
	t.Helper()
	require.Equal(t, keyRef.Id, c.Params[ownerKeyIdParam])
	require.Equal(
		t,
		hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
		c.Params[ownerKeyParam],
	)
}

// assertOwnerArgs pins the GetArgs contract for the derivable handler kinds:
// the recovered args are the very key reference the contract was built from.
func assertOwnerArgs(
	t *testing.T, _ types.Contract, keyRef identity.KeyRef, _, gotArgs any,
) {
	t.Helper()
	got, ok := gotArgs.(identity.KeyRef)
	require.True(t, ok, "GetArgs must return the args type NewContract accepts")
	require.Equal(t, keyRef.Id, got.Id)
	require.Equal(
		t,
		schnorr.SerializePubKey(keyRef.PubKey),
		schnorr.SerializePubKey(got.PubKey),
	)
}

// assertVhtlcArgs compares the ContractArgs recovered via GetArgs against the
// ones the contract was originally built from. The signer key is not part of
// the original args (it comes from server params), so it is checked against
// the persisted signerKey param instead.
func assertVhtlcArgs(
	t *testing.T, c types.Contract, orig, got vhtlcHandler.ContractArgs,
) {
	t.Helper()
	require.Equal(t, orig.SenderKeyId, got.SenderKeyId)
	require.Equal(t, orig.ReceiverKeyId, got.ReceiverKeyId)
	require.Equal(
		t, schnorr.SerializePubKey(orig.Sender), schnorr.SerializePubKey(got.Sender),
	)
	require.Equal(
		t, schnorr.SerializePubKey(orig.Receiver), schnorr.SerializePubKey(got.Receiver),
	)
	require.NotNil(t, got.Signer)
	require.Equal(
		t,
		c.Params[signerKeyParam],
		hex.EncodeToString(schnorr.SerializePubKey(got.Signer)),
	)
	require.Equal(t, orig.PreimageHash, got.PreimageHash)
	require.Equal(t, orig.RefundLocktime, got.RefundLocktime)
	require.Equal(t, orig.UnilateralClaimDelay, got.UnilateralClaimDelay)
	require.Equal(t, orig.UnilateralRefundDelay, got.UnilateralRefundDelay)
	require.Equal(
		t,
		orig.UnilateralRefundWithoutReceiverDelay,
		got.UnilateralRefundWithoutReceiverDelay,
	)
}

func assertVhtlcParams(
	t *testing.T, c types.Contract, keyRef identity.KeyRef, args vhtlcHandler.ContractArgs,
) {
	t.Helper()
	require.Equal(t, keyRef.Id, c.Params[senderKeyIdParam])
	// The wallet key is the sender, so no receiver key id must be persisted.
	require.NotContains(t, c.Params, receiverKeyIdParam)
	require.Equal(
		t,
		hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
		c.Params[senderKeyParam],
	)
	require.Equal(
		t,
		hex.EncodeToString(schnorr.SerializePubKey(args.Receiver)),
		c.Params[receiverKeyParam],
	)
	require.Equal(t, hex.EncodeToString(args.PreimageHash), c.Params[preimageHashParam])
	require.Equal(
		t,
		strconv.FormatUint(testVhtlcRefundLocktime, 10),
		c.Params[refundLocktimeParam],
	)
	require.Equal(
		t,
		strconv.FormatUint(uint64(testVhtlcClaimDelay), 10),
		c.Params[unilateralClaimDelayParam],
	)
	require.Equal(
		t,
		strconv.FormatUint(uint64(testVhtlcRefundDelay), 10),
		c.Params[unilateralRefundDelayParam],
	)
	require.Equal(
		t,
		strconv.FormatUint(uint64(testVhtlcRefundWithoutReceiverDelay), 10),
		c.Params[unilateralRefundWithoutReceiverDelayParam],
	)
	require.Equal(t, testCheckpointTapscript, c.Params[checkpointExitPathParam])
	require.Contains(t, c.Address, testNetwork.Addr)
}

func newTestVhtlcArgs(t *testing.T, keyRef identity.KeyRef) vhtlcHandler.ContractArgs {
	t.Helper()
	return vhtlcHandler.ContractArgs{
		SenderKeyId:    keyRef.Id,
		Sender:         keyRef.PubKey,
		Receiver:       newTestPubKey(t),
		PreimageHash:   newTestPreimageHash(t),
		RefundLocktime: arklib.AbsoluteLocktime(testVhtlcRefundLocktime),
		UnilateralClaimDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: testVhtlcClaimDelay,
		},
		UnilateralRefundDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: testVhtlcRefundDelay,
		},
		UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
			Type: arklib.LocktimeTypeSecond, Value: testVhtlcRefundWithoutReceiverDelay,
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

func newTestP2TRPkScript(t *testing.T) []byte {
	t.Helper()
	pkScript, err := txscript.PayToTaprootScript(newTestPubKey(t))
	require.NoError(t, err)
	return pkScript
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

func newTestInfo(t *testing.T, signerKey *btcec.PublicKey) *client.Info {
	t.Helper()
	return &client.Info{
		SignerPubKey:        hex.EncodeToString(signerKey.SerializeCompressed()),
		UnilateralExitDelay: testUnilateralExitDelay,
		BoardingExitDelay:   testBoardingExitDelay,
		CheckpointTapscript: testCheckpointTapscript,
	}
}
