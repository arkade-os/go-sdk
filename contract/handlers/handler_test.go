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
)

var (
	testNetwork = arklib.BitcoinRegTest
	contracts   = map[types.ContractType][]string{
		types.ContractTypeDefault: {offchainMode, onchainMode},
	}
)

func TestHandlerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for ct, modes := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)
				keyRef := newTestKeyRef(t)

				for _, mode := range modes {
					t.Run(mode, func(t *testing.T) {
						var opts []handlers.ContractOption
						if mode == onchainMode {
							opts = []handlers.ContractOption{handlers.WithIsOnchain()}
						}
						built, err := h.NewContract(t.Context(), keyRef, opts...)
						require.NoError(t, err)
						c := *built

						t.Run(mode, func(t *testing.T) {
							require.Equal(t, ct, c.Type)
							require.Equal(t, types.ContractStateActive, c.State)
							require.NotEmpty(t, c.Script)
							require.NotEmpty(t, c.Address)
							require.False(t, c.CreatedAt.IsZero())
							require.Equal(t, keyRef.Id, c.Params[types.ContractParamOwnerKeyId])
							require.Equal(
								t,
								hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
								c.Params[types.ContractParamOwnerKey],
							)
							require.NotEmpty(t, c.Params[types.ContractParamSignerKey])

							switch mode {
							case offchainMode:
								require.Equal(t, "false", c.Params[types.ContractParamIsOnchain])
								require.Equal(
									t,
									strconv.FormatInt(testUnilateralExitDelay, 10),
									c.Params[types.ContractParamExitDelay],
								)
								require.Contains(t, c.Address, testNetwork.Addr)
							case onchainMode:
								require.Equal(t, "true", c.Params[types.ContractParamIsOnchain])
								require.Equal(
									t,
									strconv.FormatInt(testBoardingExitDelay, 10),
									c.Params[types.ContractParamExitDelay],
								)
								require.Contains(t, c.Address, "bcrt1p")
							}
						})
					})
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for ct := range contracts {
			t.Run(string(ct), func(t *testing.T) {
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
							testNetwork,
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
		for ct, modes := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)
				keyRef := newTestKeyRef(t)

				for _, mode := range modes {
					t.Run(mode, func(t *testing.T) {
						var opts []handlers.ContractOption
						if mode == onchainMode {
							opts = []handlers.ContractOption{handlers.WithIsOnchain()}
						}
						built, err := h.NewContract(t.Context(), keyRef, opts...)
						require.NoError(t, err)
						c := *built

						t.Run(mode, func(t *testing.T) {
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
					})
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for ct := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)

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
						params:        map[string]string{types.ContractParamOwnerKey: "abcd"},
						expectedError: "missing owner key ID",
					},
					{
						name: "empty key id",
						params: map[string]string{
							types.ContractParamOwnerKeyId: "",
							types.ContractParamOwnerKey:   "abcd",
						},
						expectedError: "empty owner key ID",
					},
					{
						name:          "missing owner key",
						params:        map[string]string{types.ContractParamOwnerKeyId: "m/0/0"},
						expectedError: "missing owner key",
					},
					{
						name: "invalid owner key format",
						params: map[string]string{
							types.ContractParamOwnerKeyId: "m/0/0",
							types.ContractParamOwnerKey:   "nothex",
						},
						expectedError: "invalid owner key format",
					},
					{
						name: "invalid owner key",
						params: map[string]string{
							types.ContractParamOwnerKeyId: "m/0/0",
							types.ContractParamOwnerKey:   hex.EncodeToString([]byte{0x00, 0x01}),
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

func TestHandlerGetSignerKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for ct, modes := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)
				keyRef := newTestKeyRef(t)

				for _, mode := range modes {
					t.Run(mode, func(t *testing.T) {
						var opts []handlers.ContractOption
						if mode == onchainMode {
							opts = []handlers.ContractOption{handlers.WithIsOnchain()}
						}
						built, err := h.NewContract(t.Context(), keyRef, opts...)
						require.NoError(t, err)
						c := *built

						t.Run(mode, func(t *testing.T) {
							signer, err := h.GetSignerKey(c)
							require.NoError(t, err)
							require.NotNil(t, signer)
							require.Equal(
								t,
								c.Params[types.ContractParamSignerKey],
								hex.EncodeToString(schnorr.SerializePubKey(signer)),
							)
						})
					})
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for ct := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)

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
						params:        map[string]string{types.ContractParamOwnerKeyId: "m/0/0"},
						expectedError: "missing signer key",
					},
					{
						name: "invalid signer key format",
						params: map[string]string{
							types.ContractParamSignerKey: "nothex",
						},
						expectedError: "invalid signer key format",
					},
					{
						name: "invalid signer key",
						params: map[string]string{
							types.ContractParamSignerKey: hex.EncodeToString([]byte{0x00, 0x01}),
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
		for ct, modes := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)
				keyRef := newTestKeyRef(t)

				for _, mode := range modes {
					t.Run(mode, func(t *testing.T) {
						var opts []handlers.ContractOption
						if mode == onchainMode {
							opts = []handlers.ContractOption{handlers.WithIsOnchain()}
						}
						built, err := h.NewContract(t.Context(), keyRef, opts...)
						require.NoError(t, err)
						c := *built

						t.Run(mode, func(t *testing.T) {
							delay, err := h.GetExitDelay(c)
							require.NoError(t, err)
							require.NotNil(t, delay)

							switch mode {
							case offchainMode:
								require.Equal(t, arklib.LocktimeTypeBlock, delay.Type)
								require.Equal(t, uint32(testUnilateralExitDelay), delay.Value)
							case onchainMode:
								require.Equal(t, arklib.LocktimeTypeSecond, delay.Type)
								require.Equal(t, uint32(testBoardingExitDelay), delay.Value)
							}
						})
					})
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for ct := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)

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
						params:        map[string]string{types.ContractParamOwnerKeyId: "m/0/0"},
						expectedError: "missing exit delay",
					},
					{
						name: "invalid exit delay format",
						params: map[string]string{
							types.ContractParamExitDelay: "notanumber",
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
		for ct, modes := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)
				keyRef := newTestKeyRef(t)

				for _, mode := range modes {
					t.Run(mode, func(t *testing.T) {
						var opts []handlers.ContractOption
						if mode == onchainMode {
							opts = []handlers.ContractOption{handlers.WithIsOnchain()}
						}
						built, err := h.NewContract(t.Context(), keyRef, opts...)
						require.NoError(t, err)
						c := *built

						t.Run(mode, func(t *testing.T) {
							scripts, err := h.GetTapscripts(c)
							require.NoError(t, err)
							require.NotEmpty(t, scripts)
							for _, s := range scripts {
								require.NotEmpty(t, s)
							}
						})
					})
				}
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for ct := range contracts {
			t.Run(string(ct), func(t *testing.T) {
				h := newTestHandler(t)

				// Each case strips a different required param so the corresponding
				// inner getter (KeyRef / SignerKey / ExitDelay) is the one that fails.
				validParams := func() map[string]string {
					return map[string]string{
						types.ContractParamOwnerKeyId: "m/0/0",
						types.ContractParamOwnerKey: hex.EncodeToString(
							schnorr.SerializePubKey(newTestPubKey(t)),
						),
						types.ContractParamSignerKey: hex.EncodeToString(
							schnorr.SerializePubKey(newTestPubKey(t)),
						),
						types.ContractParamExitDelay: "144",
					}
				}

				cases := []struct {
					name          string
					mutate        func(map[string]string)
					expectedError string
				}{
					{
						name:          "missing key ID",
						mutate:        func(p map[string]string) { delete(p, types.ContractParamOwnerKeyId) },
						expectedError: "failed to get key reference",
					},
					{
						name:          "missing signer key",
						mutate:        func(p map[string]string) { delete(p, types.ContractParamSignerKey) },
						expectedError: "failed to get signer key",
					},
					{
						name:          "missing exit delay",
						mutate:        func(p map[string]string) { delete(p, types.ContractParamExitDelay) },
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

func newTestHandler(t *testing.T) handlers.Handler {
	t.Helper()
	info := newTestInfo(t, newTestPubKey(t))
	return defaultHandler.NewHandler(&mockTransportClient{info: info}, testNetwork)
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
	}
}
