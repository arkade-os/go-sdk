package e2e_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestClaimVHTLC(t *testing.T) {
	t.Run("claim offchain", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		// Fund alice with offchain sats so she can send to the VHTLC
		faucetOffchain(t, alice, 0.001)

		balanceBefore, err := alice.Balance(ctx)
		require.NoError(t, err)

		// Let's have fun and use alice's key also as sender, just for the sake of demonstration.
		sender, err := alice.Identity().NewKey(ctx)
		require.NoError(t, err)
		require.NotNil(t, sender)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		preimage, preimageHash := newPreimage(t)

		vhtlc, err := alice.CreateVHTLC(ctx, contract.VHTLCContractArgs{
			Sender:         sender.PubKey,
			PreimageHash:   preimageHash,
			RefundLocktime: arklib.AbsoluteLocktime(5), // 5 blocks
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 10,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 12,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 14,
			},
		})
		require.NoError(t, err)

		vhtlcAddr, err := vhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)
		require.NotEmpty(t, vhtlcAddr)

		// Fund the VHTLC
		fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
			{To: vhtlcAddr, Amount: 5000},
		})
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxid)

		pkScript, err := vhtlc.PkScript()
		require.NoError(t, err)
		require.NotNil(t, pkScript)

		// Verify VHTLC has funds
		require.Eventually(t, func() bool {
			res, err := alice.Indexer().GetVtxos(
				ctx, indexer.WithScripts([]string{hex.EncodeToString(pkScript)}),
			)
			return err == nil && res != nil && len(res.Vtxos) > 0
		}, 5*time.Second, 100*time.Millisecond, "failed to get funds for vhtlc %x", pkScript)

		claimTxid, err := alice.ClaimVHTLC(ctx, hex.EncodeToString(pkScript), preimage)
		require.NoError(t, err)
		require.NotEmpty(t, claimTxid)

		// Wait for the indexer to reflect the spent status
		time.Sleep(2 * time.Second)

		// Verify the vhtlc vtxo has been spent by the claim tx
		vtxos, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		require.True(t, vtxos[0].Spent)
		require.Equal(t, claimTxid, vtxos[0].ArkTxid)

		// Verify balance is preserved: alice funded the vhtlc and claimed it back
		balanceAfter, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
			"offchain balance should be preserved after claiming the self-funded vhtlc")
	})

	// Verifies that ClaimVHTLC targets the specified vtxo by outpoint when multiple vtxos
	// exist at the same VHTLC address.
	t.Run("claim with outpoint", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		faucetOffchain(t, alice, 0.001)

		// The sender is a counterparty, alice is the receiver of the VHTLC.
		sender, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		preimage, preimageHash := newPreimage(t)

		vhtlc, err := alice.CreateVHTLC(ctx, contract.VHTLCContractArgs{
			Sender:         sender.PubKey(),
			PreimageHash:   preimageHash,
			RefundLocktime: arklib.AbsoluteLocktime(5), // 5 blocks
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 10,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 12,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 14,
			},
		})
		require.NoError(t, err)

		vhtlcAddr, err := vhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)

		pkScript, err := vhtlc.PkScript()
		require.NoError(t, err)

		// Fund two vtxos at the same VHTLC address
		for _, amount := range []uint64{1000, 2000} {
			fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
				{To: vhtlcAddr, Amount: amount},
			})
			require.NoError(t, err)
			require.NotEmpty(t, fundingTxid)
		}

		var vtxos []clientTypes.Vtxo
		require.Eventually(t, func() bool {
			var err error
			vtxos, err = getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) == 2
		}, 5*time.Second, 100*time.Millisecond, "failed to get funds for vhtlc %x", pkScript)

		// Find the 2000-sat vtxo (target) and the 1000-sat one (must survive the claim)
		var targetVtxo, otherVtxo *clientTypes.Vtxo
		for i := range vtxos {
			if vtxos[i].Amount == 2000 {
				targetVtxo = &vtxos[i]
			} else {
				otherVtxo = &vtxos[i]
			}
		}
		require.NotNil(t, targetVtxo, "2000-sat vtxo not found")
		require.NotNil(t, otherVtxo, "1000-sat vtxo not found")

		// Claim the 2000-sat vtxo by explicit outpoint
		claimTxid, err := alice.ClaimVHTLC(
			ctx, hex.EncodeToString(pkScript), preimage,
			arksdk.WithOutpoint(clientTypes.Outpoint{
				Txid: targetVtxo.Txid,
				VOut: targetVtxo.VOut,
			}),
		)
		require.NoError(t, err)
		require.NotEmpty(t, claimTxid)

		// Wait for the indexer to reflect the spent status
		time.Sleep(3 * time.Second)

		// Verify the 2000-sat vtxo is spent by the claim, while the 1000-sat one survived
		remaining, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)
		var targetFound, survivorFound bool
		for _, v := range remaining {
			switch {
			case v.Txid == targetVtxo.Txid && v.VOut == targetVtxo.VOut:
				require.True(t, v.Spent, "2000-sat vtxo should be spent")
				require.Equal(t, claimTxid, v.ArkTxid)
				targetFound = true
			case v.Txid == otherVtxo.Txid && v.VOut == otherVtxo.VOut:
				require.False(t, v.Spent, "1000-sat vtxo should not be spent")
				survivorFound = true
			}
		}
		require.True(t, targetFound, "2000-sat vtxo should still be listed")
		require.True(t, survivorFound, "1000-sat vtxo should still be present")
	})

	// Verifies that ClaimVHTLC without explicit outpoint selects the oldest vtxo
	// (by CreatedAt ascending) when multiple exist.
	t.Run("claim oldest vtxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		faucetOffchain(t, alice, 0.001)

		// The sender is a counterparty, alice is the receiver of the VHTLC.
		sender, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		preimage, preimageHash := newPreimage(t)

		vhtlc, err := alice.CreateVHTLC(ctx, contract.VHTLCContractArgs{
			Sender:         sender.PubKey(),
			PreimageHash:   preimageHash,
			RefundLocktime: arklib.AbsoluteLocktime(5), // 5 blocks
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 10,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 12,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 14,
			},
		})
		require.NoError(t, err)

		vhtlcAddr, err := vhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)

		pkScript, err := vhtlc.PkScript()
		require.NoError(t, err)

		// Fund three vtxos with delays to ensure distinct CreatedAt timestamps
		for _, amount := range []uint64{1000, 2000, 3000} {
			fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
				{To: vhtlcAddr, Amount: amount},
			})
			require.NoError(t, err)
			require.NotEmpty(t, fundingTxid)

			time.Sleep(2 * time.Second)
		}

		// Claim without target outpoint, the oldest (1000-sat) vtxo should be selected
		claimTxid, err := alice.ClaimVHTLC(ctx, hex.EncodeToString(pkScript), preimage)
		require.NoError(t, err)
		require.NotEmpty(t, claimTxid)

		// Wait for the indexer to reflect the spent status
		time.Sleep(3 * time.Second)

		vtxos, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)

		// Verify the 1000-sat vtxo is spent by the claim, while the 2000 and 3000 ones are not
		for _, v := range vtxos {
			if v.Amount == 1000 {
				require.True(t, v.Spent, "1000-sat (oldest) vtxo should be spent")
				require.Equal(t, claimTxid, v.ArkTxid)
				continue
			}
			require.False(t, v.Spent, "%d-sat vtxo should not be spent", v.Amount)
		}
	})

	// Verifies claiming a swept VHTLC: ClaimVHTLC detects the vtxo is recoverable and redeems
	// it within a batch session instead of spending it with an offchain tx.
	//
	// Must run last: it mines enough blocks to expire every vtxo, which would sweep the funds
	// of the other subtests if they ran afterwards.
	t.Run("claim recoverable", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		faucetOffchain(t, alice, 0.001)

		balanceBefore, err := alice.Balance(ctx)
		require.NoError(t, err)

		// The sender is a counterparty, alice is the receiver of the VHTLC.
		sender, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		preimage, preimageHash := newPreimage(t)

		vhtlc, err := alice.CreateVHTLC(ctx, contract.VHTLCContractArgs{
			Sender:         sender.PubKey(),
			PreimageHash:   preimageHash,
			RefundLocktime: arklib.AbsoluteLocktime(uint32(time.Now().Unix() + 86400)),
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 512,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 512,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 1024,
			},
		})
		require.NoError(t, err)

		vhtlcAddr, err := vhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)

		pkScript, err := vhtlc.PkScript()
		require.NoError(t, err)

		// Fund the VHTLC
		fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
			{To: vhtlcAddr, Amount: 1000},
		})
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxid)

		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0
		}, 5*time.Second, 100*time.Millisecond, "failed to get funds for vhtlc %x", pkScript)

		// Make the vhtlc vtxo expire and wait for the server to sweep it
		generateBlocks(t, 181)

		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0 && vtxos[0].IsRecoverable()
		}, 30*time.Second, time.Second, "vhtlc vtxo should become recoverable")

		// Claim the swept VHTLC: the wallet redeems it within a batch session
		commitmentTxid, err := alice.ClaimVHTLC(ctx, hex.EncodeToString(pkScript), preimage)
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTxid)

		time.Sleep(time.Second)

		// Verify the vhtlc vtxo has been redeemed and is not recoverable anymore
		vtxos, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		require.Equal(t, commitmentTxid, vtxos[0].SettledBy)

		// Verify balance is preserved (funds returned)
		balanceAfter, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
			"offchain balance should be preserved after claim settlement")
	})
}

func TestRefundVHTLC(t *testing.T) {
	t.Run("refund collaboratively", func(t *testing.T) {
		ctx := t.Context()
		// Alice is the sender and funds the vhtlc, bob is the receiver: both track the
		// contract and cooperate to refund it.
		alice := setupClient(t, "")
		bob := setupClient(t, "")

		faucetOffchain(t, alice, 0.001)

		balanceBefore, err := alice.Balance(ctx)
		require.NoError(t, err)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		// The parties exchange their pubkeys beforehand: both contract managers assign the
		// first vhtlc key deterministically (m/0/0).
		aliceKey, err := alice.Identity().GetKey(ctx, "m/0/0")
		require.NoError(t, err)
		bobKey, err := bob.Identity().GetKey(ctx, "m/0/0")
		require.NoError(t, err)

		// The refund paths never reveal the preimage, only its hash is needed.
		_, preimageHash := newPreimage(t)

		contractArgs := contract.VHTLCContractArgs{
			PreimageHash:   preimageHash,
			RefundLocktime: arklib.AbsoluteLocktime(uint32(time.Now().Unix() + 86400)),
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 512,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 512,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 1024,
			},
		}

		// Alice creates the contract as sender, bob as receiver...
		aliceArgs := contractArgs
		aliceArgs.Receiver = bobKey.PubKey
		aliceVhtlc, err := alice.CreateVHTLC(ctx, aliceArgs)
		require.NoError(t, err)

		bobArgs := contractArgs
		bobArgs.Sender = aliceKey.PubKey
		bobVhtlc, err := bob.CreateVHTLC(ctx, bobArgs)
		require.NoError(t, err)

		// ...and both must derive the same address.
		vhtlcAddr, err := aliceVhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)
		bobVhtlcAddr, err := bobVhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)
		require.Equal(t, vhtlcAddr, bobVhtlcAddr)

		pkScript, err := aliceVhtlc.PkScript()
		require.NoError(t, err)

		// Fund the VHTLC
		fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
			{To: vhtlcAddr, Amount: 5000},
		})
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxid)

		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0
		}, 5*time.Second, 100*time.Millisecond, "failed to get funds for vhtlc %x", pkScript)

		// Alice builds the refund txs and signs them as sender, then hands them over to bob
		// who countersigns them as receiver.
		refundTx, checkpointTx, err := alice.RefundVHTLC(ctx, hex.EncodeToString(pkScript))
		require.NoError(t, err)
		require.NotEmpty(t, refundTx)
		require.NotEmpty(t, checkpointTx)

		signedRefundTx, err := bob.SignTransaction(ctx, refundTx)
		require.NoError(t, err)
		signedCheckpointTx, err := bob.SignTransaction(ctx, checkpointTx)
		require.NoError(t, err)

		// Submit the fully signed refund via alice's client.
		arkTxid, _, serverSignedCheckpointTxs, err := alice.Client().SubmitTx(
			ctx, signedRefundTx, []string{signedCheckpointTx},
		)
		require.NoError(t, err)
		require.NotEmpty(t, arkTxid)

		// The checkpoint returned by the server carries only its signature, both parties must
		// add theirs before finalizing.
		checkpointSignedByAlice, err := alice.SignTransaction(ctx, serverSignedCheckpointTxs[0])
		require.NoError(t, err)
		finalCheckpointTx, err := bob.SignTransaction(ctx, checkpointSignedByAlice)
		require.NoError(t, err)

		err = alice.Client().FinalizeTx(ctx, arkTxid, []string{finalCheckpointTx})
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		// Verify the vhtlc vtxo has been spent by the refund tx
		vtxos, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		require.True(t, vtxos[0].Spent)
		require.Equal(t, arkTxid, vtxos[0].ArkTxid)

		// Verify balance is preserved (funds returned to alice)
		balanceAfter, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
			"offchain balance should be preserved after collaborative refund")
	})

	// Verifies the unilateral refund of a live VHTLC vtxo: with an already expired refund
	// locktime, UnilateralRefundVHTLC spends it with an offchain tx using the
	// refund-without-receiver path, ie. without the receiver's signature.
	t.Run("refund unilaterally", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		faucetOffchain(t, alice, 0.001)

		balanceBefore, err := alice.Balance(ctx)
		require.NoError(t, err)

		// The receiver is a counterparty, alice is the sender of the VHTLC.
		receiver, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		_, preimageHash := newPreimage(t)

		vhtlc, err := alice.CreateVHTLC(ctx, contract.VHTLCContractArgs{
			Receiver:       receiver.PubKey(),
			PreimageHash:   preimageHash,
			RefundLocktime: arklib.AbsoluteLocktime(2),
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 12,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 14,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeBlock,
				Value: 16,
			},
		})
		require.NoError(t, err)

		vhtlcAddr, err := vhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)

		pkScript, err := vhtlc.PkScript()
		require.NoError(t, err)

		// Fund the VHTLC
		fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
			{To: vhtlcAddr, Amount: 5000},
		})
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxid)

		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0
		}, 5*time.Second, 100*time.Millisecond, "failed to get funds for vhtlc %x", pkScript)

		// Mine 3 blocks to make the VHTLC refundable
		generateBlocks(t, 3)
		time.Sleep(5 * time.Second)

		// Refund the VHTLC unilaterally: the vtxo is live, so it's spent with an offchain tx
		refundTxid, err := alice.UnilateralRefundVHTLC(ctx, hex.EncodeToString(pkScript))
		require.NoError(t, err)
		require.NotEmpty(t, refundTxid)

		time.Sleep(2 * time.Second)

		// Verify the vhtlc vtxo has been spent by the refund tx: the vtxo is consumed by the
		// checkpoint tx (SpentBy), in turn spent by the refund ark tx (ArkTxid).
		vtxos, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		require.True(t, vtxos[0].Spent)
		require.Equal(t, refundTxid, vtxos[0].ArkTxid)

		// Verify balance is preserved (funds returned)
		balanceAfter, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
			"offchain balance should be preserved after unilateral refund")
	})

	// Verifies refunding a swept VHTLC: UnilateralRefundVHTLC detects the vtxo is recoverable
	// and redeems it within a batch session instead of spending it with an offchain tx. Uses a
	// past refund locktime (Jan 1, 2020) so the CLTV is already expired.
	//
	// Must run last: it mines enough blocks to expire every vtxo, which would sweep the funds
	// of the other subtests if they ran afterwards.
	t.Run("refund recoverable", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		faucetOffchain(t, alice, 0.001)

		balanceBefore, err := alice.Balance(ctx)
		require.NoError(t, err)

		// The receiver is a counterparty, alice is the sender of the VHTLC.
		receiver, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		cfg, err := alice.GetConfigData(ctx)
		require.NoError(t, err)

		_, preimageHash := newPreimage(t)

		vhtlc, err := alice.CreateVHTLC(ctx, contract.VHTLCContractArgs{
			Receiver:     receiver.PubKey(),
			PreimageHash: preimageHash,
			// Use a timestamp far in the past (Jan 1, 2020) so CLTV is already expired in
			// regtest. This ensures the refund-without-receiver path is available immediately.
			RefundLocktime: arklib.AbsoluteLocktime(1577836800),
			UnilateralClaimDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 512,
			},
			UnilateralRefundDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 512,
			},
			UnilateralRefundWithoutReceiverDelay: arklib.RelativeLocktime{
				Type:  arklib.LocktimeTypeSecond,
				Value: 1024,
			},
		})
		require.NoError(t, err)

		vhtlcAddr, err := vhtlc.Address(cfg.Network.Addr)
		require.NoError(t, err)

		pkScript, err := vhtlc.PkScript()
		require.NoError(t, err)

		// Fund the VHTLC
		fundingTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
			{To: vhtlcAddr, Amount: 1000},
		})
		require.NoError(t, err)
		require.NotEmpty(t, fundingTxid)

		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0
		}, 5*time.Second, 100*time.Millisecond, "failed to get funds for vhtlc %x", pkScript)

		// Make the vhtlc vtxo expire and wait for the server to sweep it
		generateBlocks(t, 181)

		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0 && vtxos[0].IsRecoverable()
		}, 30*time.Second, time.Second, "vhtlc vtxo should become recoverable")

		// Refund the swept VHTLC: the wallet redeems it within a batch session
		commitmentTxid, err := alice.UnilateralRefundVHTLC(ctx, hex.EncodeToString(pkScript))
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTxid)

		time.Sleep(2 * time.Second)

		// Verify the vhtlc vtxo has been redeemed and is not recoverable anymore
		vtxos, err := getVHTLCFunds(t, alice, pkScript)
		require.NoError(t, err)
		require.NotEmpty(t, vtxos)
		require.Equal(t, commitmentTxid, vtxos[0].SettledBy)

		// Verify balance is preserved (funds returned)
		balanceAfter, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total)
	})
}

// newPreimage returns a random preimage and its HASH160.
func newPreimage(t *testing.T) (vhtlc.Preimage, []byte) {
	t.Helper()

	preimage := make(vhtlc.Preimage, 32)
	_, err := rand.Read(preimage)
	require.NoError(t, err)

	_, hash := preimage.Hash()
	return preimage, hash
}

// getVHTLCFunds returns the vtxos funding the vhtlc identified by the given output script.
func getVHTLCFunds(
	t *testing.T, w arksdk.Wallet, pkScript []byte,
) ([]clientTypes.Vtxo, error) {
	res, err := w.Indexer().GetVtxos(
		t.Context(), indexer.WithScripts([]string{hex.EncodeToString(pkScript)}),
	)
	if err != nil {
		return nil, err
	}
	return res.Vtxos, nil
}
