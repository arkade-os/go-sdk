package e2e

import (
	"testing"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestTransactionHistory(t *testing.T) {
	ctx := t.Context()
	alice := setupClient(t)

	history, err := alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Empty(t, history)

	_, _, aliceBoardingAddr, err := alice.Receive(ctx)
	require.NoError(t, err)

	aliceTxChan := alice.GetTransactionEventChannel(ctx)

	// Alice sends fund to boarding address
	faucetOnchain(t, aliceBoardingAddr, 0.00021)

	aliceTxEvent := <-aliceTxChan
	require.Equal(t, aliceTxEvent.Type, types.TxsAdded)
}
