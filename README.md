## Arkade Go SDK

The complete API documentation for the Go SDK is automatically generated and published on **pkg.go.dev** with each GitHub release. To view the documentation, visit: [https://pkg.go.dev/github.com/arkade-os/go-sdk](https://pkg.go.dev/github.com/arkade-os/go-sdk)

## Installation

To install the Arkade Go SDK, use the following command:

```bash
go get github.com/arkade-os/go-sdk
```

## Usage

Here's a comprehensive guide on how to use the Arkade Go SDK:

### 1. Setting up the Ark Client

`NewArkClient(datadir string, verbose bool, opts ...ClientOption)` accepts two required parameters plus optional client options:

- `datadir` — path to the directory where wallet and transaction data are persisted. Pass `""` to use in-memory storage (useful for testing).
- `verbose` — when `true`, debug-level logs are printed after the wallet is unlocked.
- `opts` — optional `ClientOption` values:
  - `WithRefreshDbInterval(d time.Duration)` — enable periodic background refresh of the local database from the server. Must be at least 30s. Disabled by default (zero value).

This gives four basic combinations, plus optional client options:

```go
import arksdk "github.com/arkade-os/go-sdk"

// In-memory storage, no logs (testing)
client, err := arksdk.NewArkClient("", false)

// In-memory storage, verbose logs (testing with debug output)
client, err := arksdk.NewArkClient("", true)

// Persistent storage, no logs (production)
client, err := arksdk.NewArkClient("/path/to/data/dir", false)

// Persistent storage, verbose logs (production with debug output)
client, err := arksdk.NewArkClient("/path/to/data/dir", true)

// Persistent storage with periodic DB refresh every 5 minutes
client, err := arksdk.NewArkClient(
    "/path/to/data/dir", false, arksdk.WithRefreshDbInterval(5 * time.Minute),
)
```

Once you have a client, call `Init` to connect it to an Ark server and set up the wallet:

```go
// Minimal — single-key wallet, default explorer URL for the network.
if err := client.Init(ctx, "localhost:7070", "your_seed", "your_password"); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}

// Restore an existing wallet from seed.
if err := client.Init(ctx, "localhost:7070", "your_seed", "your_password"); err != nil {
    return fmt.Errorf("failed to restore wallet: %s", err)
}

// Custom explorer URL.
if err := client.Init(
    ctx, "localhost:7070", "your_seed", "your_password",
    arksdk.WithExplorerURL("https://example.com"),
); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}

// Bring your own wallet implementation.
if err := client.Init(
    ctx, "localhost:7070", "your_seed", "your_password",
    arksdk.WithWallet(myWalletService),
); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}
```

### 2. Client Configuration Options

`Init` has the following signature:

```go
Init(ctx context.Context, serverUrl, seed, password string, opts ...InitOption) error
```

- `serverUrl` — address of the Ark server (e.g. `"localhost:7070"`).
- `seed` — hex-encoded private key for wallet initialization or restoration.
- `password` — password used to encrypt and protect the wallet.
- `opts` — optional functional options:
  - `WithExplorerURL(url string)` — override the default mempool explorer URL for the network.
  - `WithWallet(wallet wallet.WalletService)` — supply a custom wallet implementation instead of the built-in single-key wallet.

Note: Always keep your seed and password secure. Never share them or store them in plaintext.

### 3. Wallet Operations

#### Unlock and Lock the Wallet

```go
if err := arkClient.Unlock(ctx, password); err != nil {
    log.Fatal(err)
}
defer arkClient.Lock(ctx)
```

#### Receive Funds

The old `Receive` API has been split into three dedicated methods:

```go
onchainAddr, err := arkClient.NewOnchainAddress(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Onchain address: %s", onchainAddr)

boardingAddr, err := arkClient.NewBoardingAddress(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Boarding address: %s", boardingAddr)

offchainAddr, err := arkClient.NewOffchainAddress(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Offchain address: %s", offchainAddr)
```

#### Check Balance

```go
balance, err := arkClient.Balance(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Onchain balance: %d", balance.OnchainBalance.SpendableAmount)
log.Infof("Offchain balance: %d", balance.OffchainBalance.Total)

// Asset balances are keyed by asset ID (string).
for assetID, amount := range balance.AssetBalances {
    log.Infof("Asset %s balance: %d", assetID, amount)
}
```

#### Send Offchain

```go
import clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"

// Send sats offchain.
receivers := []clientTypes.Receiver{
    {To: recipientOffchainAddr, Amount: 1000},
}
txid, err := arkClient.SendOffChain(ctx, receivers)
if err != nil {
    log.Fatal(err)
}
log.Infof("Transaction completed: %s", txid)

// Send assets offchain. If not specified, like in this example, the real recipient's amount defaults to 330 sats (dust).
assetReceivers := []clientTypes.Receiver{
    {
        To: recipientOffchainAddr,
        Assets: []clientTypes.Asset{
            {AssetId: assetID, Amount: 1200},
        },
    },
}
txid, err = arkClient.SendOffChain(ctx, assetReceivers)
if err != nil {
    log.Fatal(err)
}
log.Infof("Asset transfer completed: %s", txid)
```

#### Submit Transaction

`SendOffChain` is useful for simple send operations. But complex contract or collaborative transactions require more flexibility. In this case, you can use the `TransportClient.SubmitTx` and `TransportClient.FinalizeTx` APIs.

```go
// Create a new transport client
transportClient, err := grpcclient.NewClient("localhost:7070")
require.NoError(t, err)

// Use ark-lib/tree util function to build ark and checkpoint transactions.
arkTx, checkpointTxs, err := offchain.BuildTxs(
	[]offchain.VtxoInput{
		// ... your inputs here
	},
	[]*wire.TxOut{
		// ... your outputs here
	},
	batchOutputSweepClosure,
)

signedArkTx, err := arkClient.SignTransaction(ctx, arkTx)
if err != nil {
	return "", err
}

arkTxid, _, signedCheckpointTxs, err := grpcclient.SubmitTx(ctx, signedArkTx, checkpointTxs)
if err != nil {
	return "", err
}

// Counter-sign and checkpoint txs and send them back to the server to complete the process.
finalCheckpointTxs := make([]string, 0, len(signedCheckpointTxs))
for _, checkpointTx := range signedCheckpointTxs {
	finalCheckpointTx, err := a.SignTransaction(ctx, checkpointTx)
	if err != nil {
		return "", nil
	}
	finalCheckpointTxs = append(finalCheckpointTxs, finalCheckpointTx)
}

if err = a.client.FinalizeTx(ctx, arkTxid, finalCheckpointTxs); err != nil {
	return "", err
}
```

#### Asset Operations

Arkade supports issuing, transferring, reissuing, and burning custom assets offchain.

**Concepts:**
- An **asset** is identified by a string asset ID derived from the genesis transaction ID and group index.
- A **control asset** is a special asset that grants authority to reissue a given asset. Holding the control asset vtxo in your wallet is required to call `ReissueAsset`.
- Without a control asset, an issued asset has a fixed, immutable supply.

##### Issue Asset

```go
import (
    "github.com/arkade-os/arkd/pkg/ark-lib/asset"
    clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

// 1. Fixed supply — no control asset. Returns one asset ID.
txid, assetIds, err := arkClient.IssueAsset(ctx, 5000, nil, nil)
if err != nil {
    log.Fatal(err)
}
assetID := assetIds[0].String()
log.Infof("Issued asset %s in tx %s", assetID, txid)

// 2. With a new control asset issued together with the controlled one.
//    Returns two asset IDs: [controlAssetId, issuedAssetId].
txid, assetIds, err = arkClient.IssueAsset(ctx, 5000, clientTypes.NewControlAsset{Amount: 1}, nil)
if err != nil {
    log.Fatal(err)
}
controlAssetID := assetIds[0].String()
assetID = assetIds[1].String()
log.Infof("Control asset: %s, issued asset: %s", controlAssetID, assetID)

// 3. With an existing control asset.
//    Returns one asset ID for the newly issued asset.
txid, assetIds, err = arkClient.IssueAsset(
    ctx, 5000, clientTypes.ExistingControlAsset{ID: controlAssetID}, nil,
)
if err != nil {
    log.Fatal(err)
}
log.Infof("Issued asset %s under existing control asset", assetIds[0].String())

// Optional: attach metadata to the asset.
meta := []asset.Metadata{
    {Key: "name", Value: "My Token"},
    {Key: "ticker", Value: "MTK"},
}
txid, assetIds, err = arkClient.IssueAsset(ctx, 5000, clientTypes.NewControlAsset{Amount: 1}, meta)
```

##### Reissue Asset

The caller must hold the control asset vtxo in their wallet.

```go
txid, err := arkClient.ReissueAsset(ctx, assetID, 1000)
if err != nil {
    log.Fatal(err)
}
log.Infof("Reissued 1000 units of %s in tx %s", assetID, txid)
```

##### Burn Asset

Destroys the specified amount. Any remaining balance is returned to the caller's address as change.

```go
txid, err := arkClient.BurnAsset(ctx, assetID, 500)
if err != nil {
    log.Fatal(err)
}
log.Infof("Burned 500 units of %s in tx %s", assetID, txid)
```


### 4. Advanced Usage

#### Multiple Recipients

You can send to multiple recipients in a single transaction:

```go
receivers := []clientTypes.Receiver{
    {To: recipient1OffchainAddr, Amount: amount1},
    {To: recipient2OffchainAddr, Amount: amount2},
}
txid, err = arkClient.SendOffChain(ctx, receivers)
```

#### Settle

Finalize pending boarding or preconfirmed funds into a commitment transaction:

```go
// Basic settle
txid, err := arkClient.Settle(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("commmitment tx: %s", txid)

// Settle with automatic retries on failure (max 5)
txid, err = arkClient.Settle(ctx, arksdk.WithRetries(3))
if err != nil {
    log.Fatal(err)
}
log.Infof("commmitment tx: %s", txid)
```

#### Cooperative Exit

To move funds from offchain to onchain:

```go
// Basic collaborative exit
txid, err := arkClient.CollaborativeExit(ctx, onchainAddress, redeemAmount)
if err != nil {
    log.Fatal(err)
}
log.Infof("commmitment tx: %s", txid)

// Collaborative exit with automatic retries on failure (max 5)
txid, err = arkClient.CollaborativeExit(ctx, onchainAddress, redeemAmount, arksdk.WithRetries(3))
if err != nil {
    log.Fatal(err)
}
log.Infof("Redeemed with tx: %s", txid)
```

### 5. Additional Client Functions

The `ArkClient` interface exposes a number of utility methods beyond the
basic workflow shown above. Here is a quick overview:

- `GetVersion()` - return the SDK version.
- `GetConfigData(ctx)` - retrieve Ark server configuration details.
- `Init(ctx, serverUrl, seed, password, opts...)` - create or restore a wallet and connect to the server. See §2 for available options.
- `IsLocked(ctx)` - check if the wallet is currently locked.
- `Unlock(ctx, password)` / `Lock(ctx)` - unlock or lock the wallet.
- `IsSynced(ctx) <-chan types.SyncEvent` - returns a channel that emits once the local database has finished syncing after unlock.
- `Balance(ctx)` - query onchain and offchain balances. The returned struct includes `AssetBalances map[string]uint64` keyed by asset ID.
- `IssueAsset(ctx, amount, controlAsset, metadata)` — mint a new offchain asset. Pass `nil` for a fixed-supply asset, `types.NewControlAsset{Amount}` to create a reissuable asset with a new control asset, or `types.ExistingControlAsset{ID}` to issue under an existing control asset. Returns the ark txid and the resulting asset IDs.
- `ReissueAsset(ctx, assetId, amount)` — mint additional supply of an existing controllable asset. Requires the caller to hold the corresponding control asset vtxo.
- `BurnAsset(ctx, assetID, amount)` — permanently destroy a quantity of an asset. Remaining balance is returned as change to the caller's address.
- `GetAddresses(ctx)` - return all known onchain, offchain, boarding and redemption addresses.
- `NewOnchainAddress(ctx)` / `NewBoardingAddress(ctx)` / `NewOffchainAddress(ctx)` - derive a fresh address of the respective type.
- `SendOffChain(ctx, receivers)` - send funds offchain. Each `clientTypes.Receiver` can carry an `Assets []clientTypes.Asset` slice to transfer assets alongside sats.
- `Settle(ctx, opts ...BatchSessionOption) (string, error)` - finalize pending or preconfirmed funds into a commitment transaction. Accepts `WithRetries(n)` to retry on failure (max 5 retries).
- `RegisterIntent(...)` / `DeleteIntent(...)` - manage spend intents for collaborative transactions.
- `CollaborativeExit(ctx, addr, amount, opts ...BatchSessionOption) (string, error)` - redeem offchain funds onchain. Accepts `WithRetries(n)` to retry on failure (max 5 retries).
- `Unroll(ctx) error` - broadcast unroll transactions when ready.
- `CompleteUnroll(ctx, to string) (string, error)` - finalize an unroll and sweep to an onchain address.
- `OnboardAgainAllExpiredBoardings(ctx) (string, error)` - onboard again using expired boarding UTXOs.
- `WithdrawFromAllExpiredBoardings(ctx, to string) (string, error)` - withdraw expired boarding amounts onchain.
- `ListVtxos(ctx) (spendable, spent []clientTypes.Vtxo, err error)` - list virtual UTXOs. Each `Vtxo` includes an `Assets []types.Asset` field listing any assets it carries.
- `ListSpendableVtxos(ctx)` - list only spendable virtual UTXOs.
- `Dump(ctx) (seed string, error)` - export the wallet seed.
- `GetTransactionHistory(ctx)` - fetch past transactions.
- `GetTransactionEventChannel(ctx)`, `GetVtxoEventChannel(ctx)` and `GetUtxoEventChannel(ctx)` - subscribe to wallet events.
- `FinalizePendingTxs(ctx, createdAfter *time.Time) ([]string, error)` - finalize any pending transactions, optionally filtered by creation time.
- `RedeemNotes(ctx, notes)` - redeem Ark notes back to your wallet.
- `SignTransaction(ctx, tx)` - sign an arbitrary transaction.
- `NotifyIncomingFunds(ctx, address)` - wait until a specific offchain address receives funds.
- `Stop()` - stop any running listeners.

### 6. Transport Client

For lower-level control over transaction batching you can use the `TransportClient` interface directly:

- `GetInfo(ctx)` - return server configuration and network data.
- `RegisterIntent(ctx, signature, message)` and `DeleteIntent(ctx, signature, message)` - manage collaborative intents.
- `ConfirmRegistration(ctx, intentID)` - confirm intent registration on chain.
- `SubmitTreeNonces(ctx, batchId, cosignerPubkey, nonces)` and `SubmitTreeSignatures(ctx, batchId, cosignerPubkey, sigs)` - coordinate cosigner trees.
- `SubmitSignedForfeitTxs(ctx, signedForfeitTxs, signedCommitmentTx)` - provide fully signed forfeit and commitment transactions.
- `GetEventStream(ctx, topics)` - subscribe to batch events from the server.
- `SubmitTx(ctx, signedArkTx, checkpointTxs)` and `FinalizeTx(ctx, arkTxid, finalCheckpointTxs)` - submit collaborative transactions.
- `GetTransactionsStream(ctx)` - stream transaction notifications.
- `Close()` - close the transport connection.

See the [pkg.go.dev documentation](https://pkg.go.dev/github.com/arkade-os/go-sdk) for detailed API information.

### Testing

Run integration tests ([start nigiri](https://github.com/arkade-os/arkd/blob/e33bee6196586b5f4d6ed57abe071458f49ed7ed/README.md?plain=1#L263) if needed first):

```sh
make regtest
make integrationtest
make regtestdown
```

## Full Example

The snippet below shows the complete flow from client creation to an offchain send:

```go
package main

import (
    "context"
    "fmt"
    "log"

    arksdk "github.com/arkade-os/go-sdk"
    clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

func main() {
    ctx := context.Background()
	prvkey := "ff694aab53abf53843f5cd1ffd8d488d743b08b35f48598bdcbab3f71d430e01"
	password := "secret"
	serverUrl := "localhost:7070"

    // Create a persistent client with debug logs enabled.
    client, err := arksdk.NewArkClient("/path/to/data/dir", true)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Stop()

    // Connect to the server and set up the wallet.
    if err := client.Init(ctx, serverUrl, prvkey, password); err != nil {
        log.Fatal(err)
    }

    // Unlock the wallet to start syncing.
    if err := client.Unlock(ctx, password); err != nil {
        log.Fatal(err)
    }
    defer client.Lock(ctx)

    // Wait for the local database to finish syncing.
    syncCh := client.IsSynced(ctx)
    if event := <-syncCh; event.Err != nil {
        log.Fatal(event.Err)
    }

    // Generate a fresh offchain address to receive funds.
    offchainAddr, err := client.NewOffchainAddress(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Offchain address:", offchainAddr)

    // Check balance.
    balance, err := client.Balance(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Offchain balance: %d sats\n", balance.OffchainBalance.Total)

    // Send offchain.
    receivers := []clientTypes.Receiver{
        {To: "<recipient_offchain_addr>", Amount: 1000},
    }
    txid, err := client.SendOffChain(ctx, receivers)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Transaction ID:", txid)
}
```

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub repository](https://github.com/arkade-os/go-sdk/issues).

Happy coding with Ark and Go! 🚀
