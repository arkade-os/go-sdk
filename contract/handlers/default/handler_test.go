package defaultHandler

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/contract/handlers"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

const (
	offchainMode = "offchain"
	onchainMode  = "onchain"

	testUnilateralExitDelay int64 = 144
	testBoardingExitDelay   int64 = 1024

	testCheckpointTapscript = "03a80040b27520dfcaec558c7e78cf3e38b898ba8a43cfb5727266bae32c5c5b3aeb32c558aa0bac"
)

var testNetwork = arklib.BitcoinRegTest

type invalidCase struct {
	name          string
	params        map[string]string
	expectedError string
}

type defaultHandlerMode struct {
	name            string
	isOnchain       bool
	expectType      types.ContractType
	expectDelay     int64
	expectDelayType arklib.RelativeLocktimeType
	expectAddress   string
}

var defaultHandlerModes = []defaultHandlerMode{
	{
		name:            offchainMode,
		isOnchain:       false,
		expectType:      types.ContractTypeDefault,
		expectDelay:     testUnilateralExitDelay,
		expectDelayType: arklib.LocktimeTypeBlock,
		expectAddress:   testNetwork.Addr,
	},
	{
		name:            onchainMode,
		isOnchain:       true,
		expectType:      types.ContractTypeBoarding,
		expectDelay:     testBoardingExitDelay,
		expectDelayType: arklib.LocktimeTypeSecond,
		expectAddress:   "bcrt1p",
	},
}

var defaultInvalidGetKeyRef = []invalidCase{
	{name: "no params", params: nil, expectedError: "has no parameters"},
	{
		name:          "missing key id",
		params:        map[string]string{ownerKeyParam: "abcd"},
		expectedError: "missing owner key ID",
	},
	{
		name:          "empty key id",
		params:        map[string]string{ownerKeyIdParam: "", ownerKeyParam: "abcd"},
		expectedError: "empty owner key ID",
	},
	{
		name:          "missing owner key",
		params:        map[string]string{ownerKeyIdParam: "m/0/0"},
		expectedError: "missing owner key",
	},
	{
		name:          "invalid owner key format",
		params:        map[string]string{ownerKeyIdParam: "m/0/0", ownerKeyParam: "nothex"},
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

var defaultInvalidGetSignerKey = []invalidCase{
	{name: "no params", params: nil, expectedError: "has no parameters"},
	{
		name:          "missing signer key",
		params:        map[string]string{ownerKeyIdParam: "m/0/0"},
		expectedError: "missing signer key",
	},
	{
		name:          "invalid signer key format",
		params:        map[string]string{signerKeyParam: "nothex"},
		expectedError: "invalid signer key format",
	},
	{
		name:          "invalid signer key",
		params:        map[string]string{signerKeyParam: hex.EncodeToString([]byte{0x00, 0x01})},
		expectedError: "invalid signer key",
	},
}

var defaultInvalidGetExitDelay = []invalidCase{
	{name: "no params", params: nil, expectedError: "has no parameters"},
	{
		name:          "missing exit delay",
		params:        map[string]string{ownerKeyIdParam: "m/0/0"},
		expectedError: "missing exit delay",
	},
	{
		name:          "invalid exit delay format",
		params:        map[string]string{exitDelayParam: "notanumber"},
		expectedError: "invalid exit delay format",
	},
}

func TestDefaultHandlerNewContract(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestDefaultHandler(t, mode.isOnchain)
				keyRef := newTestKeyRef(t)

				built, err := h.NewContract(t.Context(), keyRef, nil)
				require.NoError(t, err)
				c := *built

				require.Equal(t, mode.expectType, c.Type)
				require.Equal(t, types.ContractStateActive, c.State)
				require.NotEmpty(t, c.Script)
				require.NotEmpty(t, c.Address)
				require.False(t, c.CreatedAt.IsZero())
				assertDefaultContract(t, mode, c, keyRef)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
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
				}

				for _, c := range cases {
					t.Run(c.name, func(t *testing.T) {
						h := NewHandler(
							&mockClient{info: c.info, infoErr: c.infoErr},
							testNetwork,
							mode.isOnchain,
						)
						got, err := h.NewContract(t.Context(), keyRef, nil)
						require.Error(t, err)
						require.ErrorContains(t, err, c.expectedError)
						require.Nil(t, got)
					})
				}
			})
		}
	})
}

func TestDefaultHandlerGetKeyRef(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h, keyRef, c := newDefaultContract(t, mode)

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
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestDefaultHandler(t, mode.isOnchain)
				for _, c := range defaultInvalidGetKeyRef {
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

func TestDefaultHandlerGetKeyRefs(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Run("offchain returns contract and checkpoint scripts", func(t *testing.T) {
			h, keyRef, c := newDefaultContract(t, defaultHandlerModes[0])

			refs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			require.Len(t, refs, 2)
			require.Equal(t, keyRef.Id, refs[c.Script])
			for _, v := range refs {
				require.Equal(t, keyRef.Id, v)
			}

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
			h, keyRef, c := newDefaultContract(t, defaultHandlerModes[1])

			refs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			require.Len(t, refs, 1)
			require.Equal(t, keyRef.Id, refs[c.Script])
		})

		t.Run("boarding short-circuits before reading checkpointExitPath", func(t *testing.T) {
			h, keyRef, c := newDefaultContract(t, defaultHandlerModes[1])
			delete(c.Params, checkpointExitPathParam)

			refs, err := h.GetKeyRefs(c)
			require.NoError(t, err)
			require.Len(t, refs, 1)
			require.Equal(t, keyRef.Id, refs[c.Script])
		})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("offchain: getScript failure propagates", func(t *testing.T) {
			h := newTestDefaultHandler(t, false)
			refs, err := h.GetKeyRefs(types.Contract{Script: "broken"})
			require.Error(t, err)
			require.Nil(t, refs)
		})

		offchainCases := []struct {
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
				wantErrContains: "checkpoint exit path",
			},
		}

		for _, tc := range offchainCases {
			t.Run("offchain: "+tc.name, func(t *testing.T) {
				h, _, c := newDefaultContract(t, defaultHandlerModes[0])
				tc.mutateContract(&c)

				refs, err := h.GetKeyRefs(c)
				require.Error(t, err)
				require.ErrorContains(t, err, tc.wantErrContains)
				require.Nil(t, refs)
			})
		}
	})
}

func TestDefaultHandlerGetSignerKey(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h, _, c := newDefaultContract(t, mode)

				signer, err := h.GetSignerKey(c)
				require.NoError(t, err)
				require.NotNil(t, signer)
				assertDefaultSignerKey(t, c, signer)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestDefaultHandler(t, mode.isOnchain)
				for _, c := range defaultInvalidGetSignerKey {
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

func TestDefaultHandlerGetExitDelay(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h, _, c := newDefaultContract(t, mode)

				delay, err := h.GetExitDelay(c)
				require.NoError(t, err)
				require.NotNil(t, delay)
				assertDefaultExitDelay(t, mode, delay)
			})
		}
	})

	t.Run("invalid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestDefaultHandler(t, mode.isOnchain)
				for _, c := range defaultInvalidGetExitDelay {
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

func TestDefaultHandlerGetTapscripts(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h, _, c := newDefaultContract(t, mode)

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
		for _, mode := range defaultHandlerModes {
			t.Run(mode.name, func(t *testing.T) {
				h := newTestDefaultHandler(t, mode.isOnchain)

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

func newTestDefaultHandler(t *testing.T, isOnchain bool) handlers.Handler {
	t.Helper()
	info := newTestInfo(newTestPubKey(t))
	return NewHandler(&mockClient{info: info}, testNetwork, isOnchain)
}

func newDefaultContract(
	t *testing.T, mode defaultHandlerMode,
) (handlers.Handler, identity.KeyRef, types.Contract) {
	t.Helper()
	h := newTestDefaultHandler(t, mode.isOnchain)
	keyRef := newTestKeyRef(t)
	built, err := h.NewContract(t.Context(), keyRef, nil)
	require.NoError(t, err)
	return h, keyRef, *built
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

func assertDefaultContract(
	t *testing.T, mode defaultHandlerMode, c types.Contract, keyRef identity.KeyRef,
) {
	t.Helper()
	require.Equal(t, keyRef.Id, c.Params[ownerKeyIdParam])
	require.Equal(
		t,
		hex.EncodeToString(schnorr.SerializePubKey(keyRef.PubKey)),
		c.Params[ownerKeyParam],
	)
	require.NotEmpty(t, c.Params[signerKeyParam])
	require.Equal(t, strconv.FormatInt(mode.expectDelay, 10), c.Params[exitDelayParam])
	require.Contains(t, c.Address, mode.expectAddress)
}

func assertDefaultSignerKey(t *testing.T, c types.Contract, signer *btcec.PublicKey) {
	t.Helper()
	require.Equal(t, c.Params[signerKeyParam], hex.EncodeToString(schnorr.SerializePubKey(signer)))
}

func assertDefaultExitDelay(
	t *testing.T, mode defaultHandlerMode, delay *arklib.RelativeLocktime,
) {
	t.Helper()
	require.Equal(t, mode.expectDelayType, delay.Type)
	require.Equal(t, uint32(mode.expectDelay), delay.Value)
}

type mockClient struct {
	info    *client.Info
	infoErr error
}

func (f *mockClient) GetInfo(_ context.Context) (*client.Info, error) {
	return f.info, f.infoErr
}

func (f *mockClient) RegisterIntent(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (f *mockClient) DeleteIntent(_ context.Context, _, _ string) error { return nil }

func (f *mockClient) EstimateIntentFee(
	_ context.Context, _, _ string,
) (int64, error) {
	return 0, nil
}

func (f *mockClient) ConfirmRegistration(_ context.Context, _ string) error { return nil }

func (f *mockClient) SubmitTreeNonces(
	_ context.Context, _, _ string, _ tree.TreeNonces,
) error {
	return nil
}

func (f *mockClient) SubmitTreeSignatures(
	_ context.Context, _, _ string, _ tree.TreePartialSigs,
) error {
	return nil
}

func (f *mockClient) SubmitSignedForfeitTxs(
	_ context.Context, _ []string, _ string,
) error {
	return nil
}

func (f *mockClient) GetEventStream(
	_ context.Context, _ []string,
) (<-chan client.BatchEventChannel, func(), error) {
	return nil, func() {}, nil
}

func (f *mockClient) SubmitTx(
	_ context.Context, _ string, _ []string,
) (string, string, []string, error) {
	return "", "", nil, nil
}

func (f *mockClient) FinalizeTx(_ context.Context, _ string, _ []string) error {
	return nil
}

func (f *mockClient) GetPendingTx(
	_ context.Context, _, _ string,
) ([]client.AcceptedOffchainTx, error) {
	return nil, nil
}

func (f *mockClient) GetTransactionsStream(
	_ context.Context,
) (<-chan client.TransactionEvent, func(), error) {
	return nil, func() {}, nil
}

func (f *mockClient) ModifyStreamTopics(
	_ context.Context, _, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (f *mockClient) OverwriteStreamTopics(
	_ context.Context, _ []string,
) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (f *mockClient) Close() {}
