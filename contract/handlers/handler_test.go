package handlers_test

import (
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/contract/handlers"
	defaultHandler "github.com/arkade-os/go-sdk/contract/handlers/default"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const (
	offchainMode = "offchain"
	onchainMode  = "onchain"

	// < 512 → block-based RelativeLocktime.
	testUnilateralExitDelay int64 = 144
	// >= 512 → second-based RelativeLocktime.
	testBoardingExitDelay int64 = 1024

	// A real CSV-multisig closure encoded as hex — used as the test
	// checkpoint tapscript whenever an offchain test needs GetKeyRefs to
	// successfully decode and rebuild the synthetic checkpoint script.
	testCheckpointTapscript = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"

	ownerKeyParam           = "ownerKey"
	ownerKeyIdParam         = "ownerKeyId"
	signerKeyParam          = "signerKey"
	exitDelayParam          = "exitDelay"
	checkpointExitPathParam = "checkpointExitPath"
)

var testNetwork = arklib.BitcoinRegTest

// modeFixture is one row of the parametrization driving every TestHandler*:
// each handler kind (offchain default vs onchain boarding) is built once via
// the factory's isOnchain flag and is expected to produce contracts of the
// matching type.
type modeFixture struct {
	name       string
	isOnchain  bool
	expectType types.ContractType
}

var modeFixtures = []modeFixture{
	{name: offchainMode, isOnchain: false, expectType: types.ContractTypeDefault},
	{name: onchainMode, isOnchain: true, expectType: types.ContractTypeBoarding},
}

func TestHandlerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)
				keyRef := newTestKeyRef(t)

				built, err := h.NewContract(t.Context(), keyRef)
				require.NoError(t, err)
				c := *built

				require.Equal(t, mode.expectType, c.Type)
				require.Equal(t, types.ContractStateActive, c.State)
				require.NotEmpty(t, c.Script)
				require.NotEmpty(t, c.Address)
				require.False(t, c.CreatedAt.IsZero())
				require.Equal(t, keyRef.Id, c.Params[ownerKeyIdParam])
				require.Equal(
					t,
					hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
					c.Params[ownerKeyParam],
				)
				require.NotEmpty(t, c.Params[signerKeyParam])

				if mode.isOnchain {
					require.Equal(
						t,
						strconv.FormatInt(testBoardingExitDelay, 10),
						c.Params[exitDelayParam],
					)
					require.Contains(t, c.Address, "bcrt1p")
				} else {
					require.Equal(
						t,
						strconv.FormatInt(testUnilateralExitDelay, 10),
						c.Params[exitDelayParam],
					)
					require.Contains(t, c.Address, testNetwork.Addr)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				keyRef := newTestKeyRef(t)

				cases := []struct {
					name          string
					info          *client.Info
					infoErr       error
					expectedError string
				}{
					{
						name:          "GetInfo fails",
						infoErr:       errors.New("transport error"),
						expectedError: "failed to get server info",
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
				}

				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						h := defaultHandler.NewHandler(
							&mockTransportClient{info: c.info, infoErr: c.infoErr},
							testNetwork, mode.isOnchain,
						)
						got, err := h.NewContract(t.Context(), keyRef)
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
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)
				keyRef := newTestKeyRef(t)

				built, err := h.NewContract(t.Context(), keyRef)
				require.NoError(t, err)
				c := *built

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
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)

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
		t.Run("offchain returns contract and checkpoint scripts", func(t *testing.T) {
			h := newTestHandler(t, false)
			keyRef := newTestKeyRef(t)

			built, err := h.NewContract(t.Context(), keyRef)
			require.NoError(t, err)
			c := *built

			refs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			// Two entries: the contract's own script and the synthetic
			// checkpoint script — both must map to the owner key id since
			// the same wallet key signs in both contexts.
			require.Len(t, refs, 2)
			require.Equal(t, keyRef.Id, refs[c.Script])
			for _, v := range refs {
				require.Equal(t, keyRef.Id, v)
			}
			// The two map keys must be distinct scripts.
			var checkpointScript string
			for k := range refs {
				if k != c.Script {
					checkpointScript = k
				}
			}
			require.NotEmpty(t, checkpointScript)
			require.NotEqual(t, c.Script, checkpointScript)
		})

		t.Run("boarding returns only the contract script", func(t *testing.T) {
			h := newTestHandler(t, true)
			keyRef := newTestKeyRef(t)

			built, err := h.NewContract(t.Context(), keyRef)
			require.NoError(t, err)
			c := *built

			refs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			require.Len(t, refs, 1)
			require.Equal(t, keyRef.Id, refs[c.Script])
		})

		t.Run("boarding short-circuits before reading checkpointExitPath", func(t *testing.T) {
			// The boarding handler must not consult the checkpoint param
			// at all — pin this so a refactor that lifts the param read
			// above the isOnchain branch can't silently break boarding.
			h := newTestHandler(t, true)
			keyRef := newTestKeyRef(t)

			built, err := h.NewContract(t.Context(), keyRef)
			require.NoError(t, err)
			c := *built
			delete(c.Params, checkpointExitPathParam)

			refs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			require.Len(t, refs, 1)
			require.Equal(t, keyRef.Id, refs[c.Script])
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("offchain: getScript failure propagates", func(t *testing.T) {
			// Smoke test: the inner GetKeyRef / GetSignerKey / GetExitDelay
			// failure paths are exhaustively covered by their own tests.
			// Here we only pin that GetKeyRefs forwards them rather than
			// silently swallowing.
			h := newTestHandler(t, false)
			refs, err := h.GetKeyRefs(types.Contract{Script: "broken"})
			require.Error(t, err)
			require.Nil(t, refs)
		})

		offchainCases := []struct {
			name             string
			mutateContract   func(c *types.Contract)
			wantErrContains  string
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

		for _, tc := range offchainCases {
			t.Run("offchain: "+tc.name, func(t *testing.T) {
				h := newTestHandler(t, false)
				built, err := h.NewContract(t.Context(), newTestKeyRef(t))
				require.NoError(t, err)
				c := *built
				tc.mutateContract(&c)

				refs, err := h.GetKeyRefs(c)
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrContains)
				require.Nil(t, refs)
			})
		}
	})
}

func TestHandlerGetSignerKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)
				keyRef := newTestKeyRef(t)

				built, err := h.NewContract(t.Context(), keyRef)
				require.NoError(t, err)
				c := *built

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
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)

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
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)
				keyRef := newTestKeyRef(t)

				built, err := h.NewContract(t.Context(), keyRef)
				require.NoError(t, err)
				c := *built

				delay, err := h.GetExitDelay(c)
				require.NoError(t, err)
				require.NotNil(t, delay)

				if mode.isOnchain {
					require.Equal(t, arklib.LocktimeTypeSecond, delay.Type)
					require.Equal(t, uint32(testBoardingExitDelay), delay.Value)
				} else {
					require.Equal(t, arklib.LocktimeTypeBlock, delay.Type)
					require.Equal(t, uint32(testUnilateralExitDelay), delay.Value)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)

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
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)
				keyRef := newTestKeyRef(t)

				built, err := h.NewContract(t.Context(), keyRef)
				require.NoError(t, err)
				c := *built

				scripts, err := h.GetTapscripts(c)
				require.NoError(t, err)
				require.NotEmpty(t, scripts)
				for _, s := range scripts {
					require.NotEmpty(t, s)
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range modeFixtures {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestHandler(t, mode.isOnchain)

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

func newTestHandler(t *testing.T, isOnchain bool) handlers.Handler {
	t.Helper()
	info := newTestInfo(t, newTestPubKey(t))
	return defaultHandler.NewHandler(
		&mockTransportClient{info: info}, testNetwork, isOnchain,
	)
}

func newTestKeyRef(t *testing.T) wallet.KeyRef {
	t.Helper()
	return wallet.KeyRef{Id: "m/0/0", PubKey: newTestPubKey(t)}
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
