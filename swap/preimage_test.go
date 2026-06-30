package swap

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	arkidentity "github.com/arkade-os/arkd/pkg/client-lib/identity"
	sdkidentity "github.com/arkade-os/go-sdk/identity"
	identityinmemorystore "github.com/arkade-os/go-sdk/identity/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

func TestBuildPreimageMessage(t *testing.T) {
	privKey, _ := btcec.PrivKeyFromBytes([]byte{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	})

	payload, err := buildPreimageMessagePayload(privKey.PubKey(), 1)
	require.NoError(t, err)

	expectedPayload := make([]byte, 0, len(preimageTagV1)+32+4)
	expectedPayload = append(expectedPayload, []byte(preimageTagV1)...)
	expectedPayload = append(expectedPayload, schnorr.SerializePubKey(privKey.PubKey())...)
	var index [4]byte
	binary.LittleEndian.PutUint32(index[:], 1)
	expectedPayload = append(expectedPayload, index[:]...)

	require.Equal(t, expectedPayload, payload)

	msg, err := buildPreimageMessage(privKey.PubKey(), 1)
	require.NoError(t, err)

	expected := sha256.Sum256(expectedPayload)
	require.Equal(t, expected, msg)
}

func TestGenPreimageInfo(t *testing.T) {
	privKey, _ := btcec.PrivKeyFromBytes([]byte{
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
		2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	})
	keyRef := arkidentity.KeyRef{
		Id:     "m/0/7",
		PubKey: privKey.PubKey(),
	}
	signer := preimageTestSigner{privKey: privKey}

	preimage, shaHash, hash160, err := genPreimageInfo(
		context.Background(), signer, keyRef,
	)
	require.NoError(t, err)
	preimageAgain, shaHashAgain, hash160Again, err := genPreimageInfo(
		context.Background(), signer, keyRef,
	)
	require.NoError(t, err)

	require.Len(t, preimage, 32)
	require.Equal(t, preimage, preimageAgain)
	require.Equal(t, shaHash, shaHashAgain)
	require.Equal(t, hash160, hash160Again)

	expectedSHA := sha256.Sum256(preimage)
	require.Equal(t, expectedSHA[:], shaHash)
	require.Equal(t, input.Ripemd160H(expectedSHA[:]), hash160)
}

func TestGenPreimageMatchesDotnetVectors(t *testing.T) {
	fixture := loadPreimageVectorFixture(t)
	networks := map[string]chaincfg.Params{
		"mainnet": chaincfg.MainNetParams,
		"regtest": chaincfg.RegressionNetParams,
	}

	for networkName, networkVectors := range fixture.Vectors {
		params, ok := networks[networkName]
		require.Truef(t, ok, "unsupported fixture network %q", networkName)

		t.Run(networkName, func(t *testing.T) {
			ctx := context.Background()
			wallet, signer := newPreimageVectorIdentity(t, ctx, params, fixture.Seed)

			for keyIndex, vectors := range networkVectors.KeyIndexed {
				keyIndex := keyIndex
				vectors := vectors
				t.Run("key"+keyIndex, func(t *testing.T) {
					_, err := strconv.ParseUint(keyIndex, 10, 32)
					require.NoError(t, err)

					keyRef, err := wallet.GetKey(ctx, fmt.Sprintf("m/0/%s", keyIndex))
					require.NoError(t, err)

					for _, vector := range vectors {
						vector := vector
						t.Run(
							fmt.Sprintf("derivation%d", vector.DerivationIndex),
							func(t *testing.T) {
								payload, err := buildPreimageMessagePayload(
									keyRef.PubKey, vector.DerivationIndex,
								)
								require.NoError(t, err)
								require.Equal(
									t,
									vector.ExpectedPreimageMessage,
									hex.EncodeToString(payload),
								)

								preimage, err := genPreimage(
									ctx, signer, *keyRef, vector.DerivationIndex,
								)
								require.NoError(t, err)
								require.Equal(
									t,
									vector.ExpectedPreimage,
									hex.EncodeToString(preimage),
								)
							},
						)
					}
				})
			}
		})
	}
}

type preimageTestSigner struct {
	privKey *btcec.PrivateKey
}

func (s preimageTestSigner) SignSchnorrBIP340(
	_ context.Context,
	_ string,
	msg [32]byte,
) (*schnorr.Signature, error) {
	var auxRand [32]byte
	return schnorr.Sign(s.privKey, msg[:], schnorr.CustomNonce(auxRand))
}

type preimageVectorFixture struct {
	Seed    string                           `json:"seed"`
	Vectors map[string]preimageNetworkVector `json:"vectors"`
}

type preimageNetworkVector struct {
	KeyIndexed map[string][]preimageVector `json:"keyIndexed"`
}

type preimageVector struct {
	DerivationIndex         uint32 `json:"derivationIndex"`
	ExpectedPreimageMessage string `json:"expectedPreimageMessage"`
	ExpectedPreimage        string `json:"expectedPreimage"`
}

func loadPreimageVectorFixture(t *testing.T) preimageVectorFixture {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "preimage_vectors.json"))
	require.NoError(t, err)

	var fixture preimageVectorFixture
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.NotEmpty(t, fixture.Seed)
	require.NotEmpty(t, fixture.Vectors)

	return fixture
}

func newPreimageVectorIdentity(
	t *testing.T,
	ctx context.Context,
	network chaincfg.Params,
	seed string,
) (arkidentity.Identity, sdkidentity.KeyedPreimageSigner) {
	t.Helper()

	wallet, err := sdkidentity.NewIdentity(identityinmemorystore.NewStore())
	require.NoError(t, err)

	_, err = wallet.Create(ctx, network, "password", seed)
	require.NoError(t, err)

	_, err = wallet.Unlock(ctx, "password")
	require.NoError(t, err)

	signer, ok := wallet.(sdkidentity.KeyedPreimageSigner)
	require.True(t, ok)

	return wallet, signer
}
