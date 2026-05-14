## Arkade Go SDK

The complete API documentation for the Go SDK is automatically generated and published on **pkg.go.dev** with each GitHub release. To view the documentation, visit: [https://pkg.go.dev/github.com/arkade-os/go-sdk](https://pkg.go.dev/github.com/arkade-os/go-sdk)

## Installation

To install the Arkade Go SDK, use the following command:

```bash
go get github.com/arkade-os/go-sdk
```

## Usage

Here's a comprehensive guide on how to use the Arkade Go SDK:

### 1. Setting up the Wallet

`NewWallet(datadir string, opts ...WalletOption)` creates a brand new wallet and can't be used to load an existing one.  
`LoadWallet(datadir string, opts ...WalletOption)` loads an existing wallet and can't be used to create a new one.  
Both accept one required parameter plus optional wallet options:
- `datadir` — path to the directory where wallet and transaction data are persisted. Pass `""` to use in-memory storage (useful for testing; loading from an in-memory datadir won't work for obvious reasons).
- `opts` — optional `WalletOption` values:
  - `WithRefreshDbInterval(d time.Duration)` — enable periodic background refresh of the local database from the server. Must be at least 30s. Disabled by default (zero value).
  - `WithVerbose()` — enables verbose logging.
  - `WithGapLimit(n uint32)` — HD discovery gap limit used on unlock to recover externally-funded addresses. Defaults to a reasonable BIP-44-style value.
  - `WithIdentity(svc identity.Identity)` — inject a custom key-management implementation. By default the SDK creates an HD identity (BIP86) backed by the persistent datadir; see the `identity` package for the default implementation.
  - `WithScheduler(svc scheduler.SchedulerService)` — inject a custom scheduler implementation for auto-settle. Defaults to a gocron-backed in-process scheduler.
  - `WithoutAutoSettle()` — disable the background auto-settle loop entirely. By default the wallet schedules a Settle at ~90% of each spendable vtxo's remaining lifetime and re-schedules as fresher vtxos arrive.

```go
import arksdk (
    "errors"
    "log"

    "github.com/arkade-os/go-sdk"
)

// In-memory storage
wallet, err := arksdk.NewWallet("")

// Persistent storage
var wallet arksdk.Wallet
var err error
// Try to load the wallet (with default options).
wallet, err = arksdk.LoadWallet("/path/to/data/dir")
if err != nil {
    if !errors.Is(err, arksdk.ErrNotInitialized) {
        return err
    }
    // If not initialized, create a new one (with default options).
    wallet, err = arksdk.NewWallet("/path/to/data/dir")
    if err != nil {
        log.Fatal(err)
    }
}

// Wallet with periodic DB refresh every 5 minutes and verbose logs
wallet, err := arksdk.NewWallet(
    "/path/to/data/dir", arksdk.WithRefreshDbInterval(5 * time.Minute), arksdk.WithVerbose(),
)
```

Once you have a wallet, call `Init` to connect it to an Arkade server and set up the identity:

```go
// Generate a fresh HD identity (default). Pass an empty seed.
if err := wallet.Init(ctx, "localhost:7070", "", "your_password"); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}

// Restore an existing HD identity from its BIP39 mnemonic.
if err := wallet.Init(
    ctx, "localhost:7070", "abandon abandon ...", "your_password",
); err != nil {
    return fmt.Errorf("failed to restore wallet: %s", err)
}

// Custom explorer URL.
if err := wallet.Init(
    ctx, "localhost:7070", "your_seed", "your_password",
    arksdk.WithExplorerURL("https://example.com"),
); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}

// Use a self-hosted ElectrumX server (plaintext TCP or TLS).
if err := wallet.Init(
    ctx, "localhost:7070", "your_seed", "your_password",
    arksdk.WithElectrumExplorer("ssl://electrum.example.com:50002"),
); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}

// ElectrumX over local plaintext TCP (useful for regtest).
if err := wallet.Init(
    ctx, "localhost:7070", "your_seed", "your_password",
    arksdk.WithElectrumExplorer("tcp://127.0.0.1:50000"),
); err != nil {
    return fmt.Errorf("failed to initialize wallet: %s", err)
}
```

After `Init` + `Unlock`, wait for sync to complete before using balances or
history. The SDK performs HD key discovery on unlock and restores any known
offchain, boarding, redemption, and direct onchain state from the configured
gap limit (see `WithGapLimit` in §1).

```go
if err := wallet.Unlock(ctx, "your_password"); err != nil {
    return err
}

syncEvent := <-wallet.IsSynced(ctx)
if syncEvent.Err != nil {
    return syncEvent.Err
}
```

Each call to `NewOnchainAddress`, `NewBoardingAddress`, and `NewOffchainAddress`
allocates a fresh derived key, so `GetAddresses()` returns the full discovered
address set rather than a single stable address per family.

### 2. Init Options

`Init` has the following signature:

```go
Init(ctx context.Context, serverUrl, seed, password string, opts ...InitOption) error
```

- `serverUrl` — address of the Arkade server (e.g. `"localhost:7070"`).
- `seed` — BIP39 mnemonic. Pass `""` to have the SDK generate a fresh one (recoverable via `Dump`).
- `password` — used to encrypt and protect the identity material at rest.
- `opts` — optional functional options:
  - `WithExplorerURL(url string)` — override the default explorer URL for the network.
  - `WithElectrumExplorer(serverURL string)` — use an ElectrumX server instead of mempool.space. The URL must start with `tcp://` (plaintext) or `ssl://` (TLS). Mutually exclusive with `WithExplorerURL`.
  - `WithElectrumPackageBroadcastURL(url string)` — set an esplora-compatible REST URL for broadcasting transaction packages (required for zero-fee v3 / P2A anchor transactions). Only valid when using `WithElectrumExplorer`.

To plug in a non-HD identity (hardware wallet, KMS, remote signer, …), inject
it at construction time via `arksdk.WithIdentity(svc)` — see §1.

**Default explorer URLs per network:**

| Network  | Default explorer |
|----------|-----------------|
| mainnet  | `https://mempool.space/api` (mempool.space) |
| testnet  | `https://mempool.space/testnet/api` (mempool.space) |
| signet   | `https://mempool.space/signet/api` (mempool.space) |
| mutinynet | `https://mutinynet.com/api` (mempool.space) |
| regtest  | `tcp://127.0.0.1:50000` (ElectrumX) |

> **Regtest migration note:** the regtest default changed from `http://127.0.0.1:3000` (esplora) to `tcp://127.0.0.1:50000` (ElectrumX). If your regtest setup uses an esplora server instead, pass `WithExplorerURL("http://127.0.0.1:3000")` (or your actual URL) to `Init` to restore the previous behaviour.

Note: Always keep your seed and password secure. Never share them or store them in plaintext.

### 3. Wallet Operations

#### Unlock and Lock the Wallet

```go
if err := wallet.Unlock(ctx, password); err != nil {
    log.Fatal(err)
}
defer wallet.Lock(ctx)
```

#### Receive Funds

The old `Receive` API has been split into three dedicated methods:

```go
onchainAddr, err := wallet.NewOnchainAddress(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Onchain address: %s", onchainAddr)

boardingAddr, err := wallet.NewBoardingAddress(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Boarding address: %s", boardingAddr)

offchainAddr, err := wallet.NewOffchainAddress(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("Offchain address: %s", offchainAddr)
```

#### Check Balance

```go
balance, err := wallet.Balance(ctx)
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
txid, err := wallet.SendOffChain(ctx, receivers)
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
txid, err = wallet.SendOffChain(ctx, assetReceivers)
if err != nil {
    log.Fatal(err)
}
log.Infof("Asset transfer completed: %s", txid)
```

#### Submit Transaction

`SendOffChain` is useful for simple send operations. But complex contract or collaborative transactions require more flexibility. In this case, you can use the `Client.SubmitTx` and `Client.FinalizeTx` APIs (the transport client, exposed via `wallet.Client()` or built standalone with `grpcclient.NewClient`).

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

signedArkTx, err := wallet.SignTransaction(ctx, arkTx)
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
txid, assetIds, err := wallet.IssueAsset(ctx, 5000, nil, nil)
if err != nil {
    log.Fatal(err)
}
assetID := assetIds[0].String()
log.Infof("Issued asset %s in tx %s", assetID, txid)

// 2. With a new control asset issued together with the controlled one.
//    Returns two asset IDs: [controlAssetId, issuedAssetId].
txid, assetIds, err = wallet.IssueAsset(ctx, 5000, clientTypes.NewControlAsset{Amount: 1}, nil)
if err != nil {
    log.Fatal(err)
}
controlAssetID := assetIds[0].String()
assetID = assetIds[1].String()
log.Infof("Control asset: %s, issued asset: %s", controlAssetID, assetID)

// 3. With an existing control asset.
//    Returns one asset ID for the newly issued asset.
txid, assetIds, err = wallet.IssueAsset(
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
txid, assetIds, err = wallet.IssueAsset(ctx, 5000, clientTypes.NewControlAsset{Amount: 1}, meta)
```

##### Reissue Asset

The caller must hold the control asset vtxo in their wallet.

```go
txid, err := wallet.ReissueAsset(ctx, assetID, 1000)
if err != nil {
    log.Fatal(err)
}
log.Infof("Reissued 1000 units of %s in tx %s", assetID, txid)
```

##### Burn Asset

Destroys the specified amount. Any remaining balance is returned to the caller's address as change.

```go
txid, err := wallet.BurnAsset(ctx, assetID, 500)
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
txid, err = wallet.SendOffChain(ctx, receivers)
```

#### Settle

Finalize pending boarding or preconfirmed funds into a commitment transaction:

```go
// Basic settle
txid, err := wallet.Settle(ctx)
if err != nil {
    log.Fatal(err)
}
log.Infof("commitment tx: %s", txid)

// Settle with automatic retries on failure (max 5)
txid, err = wallet.Settle(ctx, arksdk.WithRetries(3))
if err != nil {
    log.Fatal(err)
}
log.Infof("commitment tx: %s", txid)
```

#### Cooperative Exit

To redeem offchain funds to onchain:

```go
// Basic collaborative exit
txid, err := wallet.CollaborativeExit(ctx, onchainAddress, redeemAmount)
if err != nil {
    log.Fatal(err)
}
log.Infof("commitment tx: %s", txid)

// Collaborative exit with automatic retries on failure (max 5)
txid, err = wallet.CollaborativeExit(ctx, onchainAddress, redeemAmount, arksdk.WithRetries(3))
if err != nil {
    log.Fatal(err)
}
log.Infof("Redeemed with tx: %s", txid)
```

### 5. Additional Wallet Methods

The `Wallet` interface exposes a number of utility methods beyond the basic
workflow shown above. Here is a quick overview:

#### Lifecycle & metadata

- `Version() string` - return the SDK version.
- `Init(ctx, serverUrl, seed, password, opts...)` - create or restore an identity and connect to the server. See §2 for available options.
- `IsLocked(ctx)` - check if the wallet is currently locked.
- `Unlock(ctx, password)` / `Lock(ctx)` - unlock or lock the wallet.
- `IsSynced(ctx) <-chan types.SyncEvent` - returns a channel that emits once the local database has finished syncing after unlock.
- `Reset(ctx)` - wipe the local state (clears stores and locks the identity). Use for "logout" / re-init flows.
- `Stop()` - stop any running background loops (sync, listeners, scheduler).

#### Dependency accessors

These return the underlying services so callers can drive lower-level flows directly:

- `Store() types.Store` - the wallet's persistent store (per-domain repositories).
- `Identity() identity.Identity` - the active identity (HD by default).
- `Explorer() explorer.Explorer` - the mempool explorer client.
- `Indexer() indexer.Indexer` - the arkd indexer client.
- `Client() client.Client` - the transport client. See §6.
- `ContractManager() contract.Manager` - the contract manager. See the [`contract`](./contract/doc.go) package for its surface.

#### Balances and addresses

- `Balance(ctx)` - query onchain and offchain balances. The returned struct includes `AssetBalances map[string]uint64` keyed by asset ID.
- `GetAddresses(ctx)` - return all known onchain, offchain, boarding and redemption addresses.
- `NewOnchainAddress(ctx)` / `NewBoardingAddress(ctx)` / `NewOffchainAddress(ctx)` - derive a fresh address of the respective type.

#### Assets

- `IssueAsset(ctx, amount, controlAsset, metadata)` — mint a new offchain asset. Pass `nil` for a fixed-supply asset, `types.NewControlAsset{Amount}` to create a reissuable asset with a new control asset, or `types.ExistingControlAsset{ID}` to issue under an existing control asset. Returns the ark txid and the resulting asset IDs.
- `ReissueAsset(ctx, assetId, amount)` — mint additional supply of an existing controllable asset. Requires the caller to hold the corresponding control asset vtxo.
- `BurnAsset(ctx, assetID, amount)` — permanently destroy a quantity of an asset. Remaining balance is returned as change to the caller's address.

#### Spending and batching

- `SendOffChain(ctx, receivers)` - send funds offchain. Each `clientTypes.Receiver` can carry an `Assets []clientTypes.Asset` slice to transfer assets alongside sats.
- `Settle(ctx, opts ...BatchSessionOption) (string, error)` - finalize pending or preconfirmed funds into a commitment transaction. Accepts `WithRetries(n)` to retry on failure (max 5 retries).
- `RegisterIntent(...)` / `DeleteIntent(...)` - manage spend intents for collaborative transactions.
- `CollaborativeExit(ctx, addr, amount, opts ...BatchSessionOption) (string, error)` - redeem offchain funds onchain. Accepts `WithRetries(n)` to retry on failure (max 5 retries).
- `Unroll(ctx) error` - broadcast unroll transactions when ready.
- `CompleteUnroll(ctx, to string) (string, error)` - finalize an unroll and sweep to an onchain address.
- `OnboardAgainAllExpiredBoardings(ctx) (string, error)` - onboard again using expired boarding UTXOs.
- `WithdrawFromAllExpiredBoardings(ctx, to string) (string, error)` - withdraw expired boarding amounts onchain.
- `WhenNextSettlement() time.Time` - inspect the next auto-settle firing time. Returns the zero value when auto-settle is disabled or nothing is scheduled.

#### State, signing, and notifications

- `ListVtxos(ctx) (spendable, spent []clientTypes.Vtxo, err error)` - list virtual UTXOs. Each `Vtxo` includes an `Assets []types.Asset` field listing any assets it carries.
- `ListSpendableVtxos(ctx)` - list only spendable virtual UTXOs.
- `Dump(ctx) (seed string, error)` - export the identity's seed (BIP39 mnemonic for the default HD identity).
- `GetTransactionHistory(ctx)` - fetch past transactions.
- `GetTransactionEventChannel(ctx)`, `GetVtxoEventChannel(ctx)` and `GetUtxoEventChannel(ctx)` - subscribe to wallet events.
- `FinalizePendingTxs(ctx, createdAfter *time.Time) ([]string, error)` - finalize any pending transactions, optionally filtered by creation time.
- `RedeemNotes(ctx, notes)` - redeem Arkade notes back to your wallet.
- `SignTransaction(ctx, tx)` - sign an arbitrary transaction.
- `NotifyIncomingFunds(ctx, address)` - wait until a specific offchain address receives funds and return the resulting vtxos.

### 6. Transport Client

For lower-level control over transaction batching you can use the `client.Client` transport interface directly (obtained via `wallet.Client()` or constructed standalone):

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

The snippet below shows the complete flow from wallet creation to an offchain send:

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
    seed := "" // empty → generate a fresh BIP39 mnemonic; recoverable via Dump
    password := "secret"
    serverUrl := "localhost:7070"

    // Create a persistent wallet.
    wallet, err := arksdk.NewWallet("/path/to/data/dir")
    if err != nil {
        log.Fatal(err)
    }
    defer wallet.Stop()

    // Connect to the server and set up the identity.
    if err := wallet.Init(ctx, serverUrl, seed, password); err != nil {
        log.Fatal(err)
    }

    // Unlock the wallet to start syncing.
    if err := wallet.Unlock(ctx, password); err != nil {
        log.Fatal(err)
    }
    defer wallet.Lock(ctx)

    // Wait for the local database to finish syncing.
    syncCh := wallet.IsSynced(ctx)
    if event := <-syncCh; event.Err != nil {
        log.Fatal(event.Err)
    }

    // Generate a fresh offchain address to receive funds.
    offchainAddr, err := wallet.NewOffchainAddress(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Offchain address:", offchainAddr)

    // Check balance.
    balance, err := wallet.Balance(ctx)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Offchain balance: %d sats\n", balance.OffchainBalance.Total)

    // Send offchain.
    receivers := []clientTypes.Receiver{
        {To: "<recipient_offchain_addr>", Amount: 1000},
    }
    txid, err := wallet.SendOffChain(ctx, receivers)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Transaction ID:", txid)
}
```

## Support

If you encounter any issues or have questions, please file an issue on our [GitHub repository](https://github.com/arkade-os/go-sdk/issues).
