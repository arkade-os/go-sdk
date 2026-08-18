package swap_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	hdidentity "github.com/arkade-os/go-sdk/identity"
	identityinmemorystore "github.com/arkade-os/go-sdk/identity/store/inmemory"
	"github.com/arkade-os/go-sdk/swap"
	"github.com/stretchr/testify/require"
)

var (
	networks = map[string]arklib.Network{
		arklib.Bitcoin.Name:        arklib.Bitcoin,
		arklib.BitcoinRegTest.Name: arklib.BitcoinRegTest,
	}
)

func TestDerivePreimage(t *testing.T) {
	ctx := t.Context()
	fixture := loadFixtures(t)

	for networkName, vectors := range fixture.Vectors {
		network, ok := networks[networkName]
		require.True(t, ok)

		t.Run(networkName, func(t *testing.T) {
			identitySvc := newTestIdentity(t, ctx, network, fixture.Seed)
			signer, ok := identitySvc.(swap.PreimageSigner)
			require.True(t, ok)

			for _, vector := range vectors {
				v := vector
				t.Run(fmt.Sprintf("keyIndex%d", v.DerivationIndex), func(t *testing.T) {
					keyPath := fmt.Sprintf("m/0/%d", v.DerivationIndex)
					keyRef, err := identitySvc.GetKey(ctx, keyPath)
					require.NoError(t, err)

					payload, err := swap.BuildPreimageMessage(keyRef.PubKey, 0)
					require.NoError(t, err)
					require.Equal(
						t, v.ExpectedPreimageMessage, hex.EncodeToString(payload),
					)

					preimage, err := swap.DerivePreimage(ctx, signer, *keyRef)
					require.NoError(t, err)
					require.Equal(t, v.ExpectedPreimage, hex.EncodeToString(preimage))
				},
				)
			}
		})
	}
}

type fixtures struct {
	Seed    string                   `json:"seed"`
	Vectors map[string][]testVectors `json:"vectors"`
}

type testVectors struct {
	DerivationIndex         uint32 `json:"derivationIndex"`
	ExpectedPreimageMessage string `json:"expectedPreimageMessage"`
	ExpectedPreimage        string `json:"expectedPreimage"`
}

func loadFixtures(t *testing.T) fixtures {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "preimage_vectors.json"))
	require.NoError(t, err)

	var fixture fixtures
	require.NoError(t, json.Unmarshal(data, &fixture))
	require.NotEmpty(t, fixture.Seed)
	require.NotEmpty(t, fixture.Vectors)

	return fixture
}

func newTestIdentity(
	t *testing.T, ctx context.Context, network arklib.Network, seed string,
) identity.Identity {
	t.Helper()

	identitySvc, err := hdidentity.NewIdentity(identityinmemorystore.NewStore())
	require.NoError(t, err)

	_, err = identitySvc.Create(ctx, network, "password", seed)
	require.NoError(t, err)

	_, err = identitySvc.Unlock(ctx, "password")
	require.NoError(t, err)

	return identitySvc
}
