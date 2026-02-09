# Lightning Network Integration

Arkade integrates with the Lightning Network through **Boltz submarine swaps**, allowing
users to move funds seamlessly between Arkade virtual UTXOs (VTXOs) and Lightning
invoices. The bridge leverages **Virtual HTLCs (VHTLCs)** — a trustless, off-chain HTLC
construct native to the Ark protocol — so that swaps settle without on-chain
transactions when things go well, and funds can always be recovered when they don't.

> **Reference implementation**: The TypeScript package
> [`@arkade-os/boltz-swap`](https://github.com/arkade-os/boltz-swap) provides a
> production-ready Lightning integration built on top of the Arkade TypeScript SDK.
> The patterns documented here are protocol-level and apply equally to Go
> integrations.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Concepts](#key-concepts)
3. [Receive from Lightning (Reverse Submarine Swap)](#receive-from-lightning-reverse-submarine-swap)
4. [Send to Lightning (Submarine Swap)](#send-to-lightning-submarine-swap)
5. [Refunding Stuck Payments](#refunding-stuck-payments)
6. [Manually Claiming Payments](#manually-claiming-payments)
7. [VHTLC Script Structure](#vhtlc-script-structure)
8. [Swap Lifecycle States](#swap-lifecycle-states)
9. [Error Types](#error-types)
10. [Architecture Diagram](#architecture-diagram)

---

## Overview

Arkade's Lightning integration works via a **swap provider** — currently
[Boltz Exchange](https://boltz.exchange) — that acts as the counterparty for each
swap. There are two directions:

| Direction | Swap Type | You lock… | You receive… |
|-----------|-----------|-----------|--------------|
| **Receive from Lightning** | Reverse submarine swap | Nothing (payer sends LN payment) | VHTLC in Arkade |
| **Send to Lightning** | Submarine swap | VHTLC in Arkade | Lightning invoice paid |

Both directions use a **VHTLC** (Virtual Hash Time-Lock Contract) as the atomic
swap primitive, ensuring that either the swap completes in full or both parties
can recover their funds.

---

## Key Concepts

### Virtual HTLC (VHTLC)

A VHTLC is an off-chain HTLC that lives inside the Ark protocol's virtual
transaction tree. It is composed of multiple Tapscript leaves that encode
different spending conditions:

| Leaf | Spending Condition | Purpose |
|------|-------------------|---------|
| **Claim** | Receiver + Server + preimage | Normal claim by the receiver |
| **Refund** | Sender + Server + timelock | Cooperative refund after timeout |
| **Unilateral Claim** | Receiver + preimage + timelock | Fallback claim without server |
| **Unilateral Refund** | Sender + timelock | Fallback refund without server |
| **Unilateral Refund Without Receiver** | Sender + longer timelock | Last-resort refund without receiver or server |

The server (Ark Service Provider, or ASP) is a co-signer on the cooperative
paths, providing instant finality. The unilateral paths serve as escape hatches
if the server becomes unresponsive.

### Preimage and Payment Hash

Every swap revolves around a **preimage** (a random 32-byte secret) and its
**payment hash** (`SHA-256(preimage)`). The Lightning invoice embeds the payment
hash. Revealing the preimage proves payment was made and unlocks the VHTLC.

### Swap Provider (Boltz)

The swap provider coordinates the atomic swap between Arkade and Lightning. It:
- Creates Lightning invoices and hold invoices
- Locks funds into VHTLCs
- Monitors swap status and settles invoices
- Co-signs refund transactions when swaps fail

---

## Receive from Lightning (Reverse Submarine Swap)

This flow allows a user to receive a Lightning payment and have the funds appear
as a VHTLC in their Arkade wallet.

### Flow

```
Payer (Lightning)          Boltz              Your Wallet (Arkade)
      │                      │                       │
      │                      │  1. createReverseSwap  │
      │                      │◄──────────────────────│
      │                      │    (claimPubKey,       │
      │                      │     preimageHash,      │
      │                      │     invoiceAmount)      │
      │                      │                       │
      │                      │  2. Returns invoice    │
      │                      │     + lockup address   │
      │                      │────────────────────────►│
      │                      │                       │
      │  3. Pay invoice      │                       │
      │─────────────────────►│                       │
      │                      │                       │
      │                      │  4. Lock funds in VHTLC│
      │                      │   (on Ark virtual tree)│
      │                      │                       │
      │                      │  5. Status: mempool    │
      │                      │────────────────────────►│
      │                      │                       │
      │                      │  6. claimVHTLC         │
      │                      │◄──────────────────────│
      │                      │   (reveal preimage)    │
      │                      │                       │
      │                      │  7. Invoice settled    │
      │                      │────────────────────────►│
      │                      │                       │
```

### Step-by-Step

1. **Generate a preimage**: Create a random 32-byte preimage and compute
   `preimageHash = SHA-256(preimage)`.

2. **Create reverse swap**: Call the Boltz API with your claim public key,
   the preimage hash, and the desired invoice amount. Boltz returns:
   - A Lightning **invoice** for the payer
   - A **lockup address** (the VHTLC address in Arkade)
   - **Timeout block heights** for the various spending paths
   - Boltz's **refund public key**

3. **Share the invoice**: Give the Lightning invoice to the payer.

4. **Monitor swap status**: Watch for Boltz status updates. When the status
   reaches `transaction.mempool` or `transaction.confirmed`, the VHTLC is
   funded and ready to claim.

5. **Claim the VHTLC**: Build an off-chain transaction that:
   - Spends the VHTLC using the **claim** leaf (receiver + server + preimage)
   - Sends the funds to your own Arkade address
   - Submit and finalize via the Ark transport client (`SubmitTx` / `FinalizeTx`)

6. **Invoice settles**: Once the claim is processed, Boltz settles the
   Lightning invoice with the payer. The swap is complete.

### Go SDK Integration Pattern

```go
// 1. Get your claim public key
claimPubKey := wallet.GetPublicKey()

// 2. Generate preimage
preimage := make([]byte, 32)
rand.Read(preimage)
preimageHash := sha256.Sum256(preimage)

// 3. Create reverse swap via Boltz API
// POST https://api.boltz.exchange/v2/swap/reverse
reverseSwap := boltzClient.CreateReverseSwap(CreateReverseSwapRequest{
    InvoiceAmount:  50000,
    ClaimPublicKey: hex.EncodeToString(claimPubKey),
    PreimageHash:   hex.EncodeToString(preimageHash[:]),
})

// 4. Share reverseSwap.Invoice with the payer

// 5. Monitor status via Boltz WebSocket or polling
// When status is "transaction.mempool" or "transaction.confirmed":

// 6. Build VHTLC claim leaf script
// 7. Build off-chain transaction spending the VHTLC
// 8. Sign and submit via arkClient's transport client
signedArkTx, err := arkClient.SignTransaction(ctx, arkTx)
arkTxid, finalArkTx, signedCheckpointTxs, err := transportClient.SubmitTx(
    ctx, signedArkTx, checkpointTxs,
)

// 9. Counter-sign checkpoints and finalize
for _, cp := range signedCheckpointTxs {
    signedCp, _ := arkClient.SignTransaction(ctx, cp)
    finalCheckpoints = append(finalCheckpoints, signedCp)
}
transportClient.FinalizeTx(ctx, arkTxid, finalCheckpoints)
```

---

## Send to Lightning (Submarine Swap)

This flow allows a user to pay a Lightning invoice using funds from their Arkade
wallet.

### Flow

```
Your Wallet (Arkade)       Boltz              Recipient (Lightning)
      │                      │                       │
      │  1. createSubmarine   │                       │
      │     Swap(invoice,     │                       │
      │      refundPubKey)    │                       │
      │─────────────────────►│                       │
      │                      │                       │
      │  2. Returns swap      │                       │
      │     address +         │                       │
      │     expected amount   │                       │
      │◄─────────────────────│                       │
      │                      │                       │
      │  3. Send VTXO to     │                       │
      │     swap address     │                       │
      │─────────────────────►│                       │
      │   (via SendOffChain)  │                       │
      │                      │                       │
      │                      │  4. Pay LN invoice    │
      │                      │──────────────────────►│
      │                      │                       │
      │                      │  5. Preimage revealed  │
      │                      │◄──────────────────────│
      │                      │                       │
      │  6. Status: claimed   │                       │
      │◄─────────────────────│                       │
      │                      │                       │
```

### Step-by-Step

1. **Create submarine swap**: Call the Boltz API with the Lightning invoice
   to pay and your refund public key. Boltz returns:
   - A **swap address** (VHTLC address in Arkade)
   - The **expected amount** to send (invoice amount + fees)
   - Boltz's **claim public key**
   - **Timeout block heights**

2. **Send funds to the swap address**: Use `SendOffChain` or build a custom
   off-chain transaction to send the expected amount to the swap address. The
   swap address is an Arkade address encoding a VHTLC where:
   - Boltz can claim with the preimage (after paying the invoice)
   - You can refund after the timeout

3. **Boltz pays the Lightning invoice**: Once Boltz detects your VHTLC
   payment, it pays the Lightning invoice to the recipient.

4. **Preimage revealed**: When the recipient reveals the preimage to settle the
   Lightning payment, Boltz uses it to claim the VHTLC.

5. **Swap completes**: The status moves to `transaction.claimed`. You can
   retrieve the preimage from Boltz as proof of payment.

### Go SDK Integration Pattern

```go
// 1. Get your refund public key
refundPubKey := wallet.GetPublicKey()

// 2. Create submarine swap via Boltz API
// POST https://api.boltz.exchange/v2/swap/submarine
submarineSwap := boltzClient.CreateSubmarineSwap(CreateSubmarineSwapRequest{
    Invoice:        "lnbc500u1pj...",
    RefundPublicKey: hex.EncodeToString(refundPubKey),
})

// 3. Send funds to the swap address
receivers := []types.Receiver{
    {To: submarineSwap.Address, Amount: submarineSwap.ExpectedAmount},
}
txid, err := arkClient.SendOffChain(ctx, receivers)

// 4. Monitor status via Boltz WebSocket or polling
// Wait for "transaction.claimed" status

// 5. Retrieve preimage as proof of payment
preimage := boltzClient.GetSwapPreimage(submarineSwap.ID)
```

---

## Refunding Stuck Payments

A submarine swap (send to Lightning) can get **stuck** if:
- The Lightning invoice expires before Boltz can pay it
- Boltz fails to route the payment
- The swap times out
- A network error interrupts the process

In these cases, your funds are locked in a VHTLC at the swap address. You need
to execute a **refund** to recover them.

### When Is a Refund Needed?

Monitor the swap status. These statuses indicate the swap failed and a refund is
possible:

| Status | Meaning |
|--------|---------|
| `swap.expired` | The swap timed out |
| `invoice.failedToPay` | Boltz could not pay the Lightning invoice |
| `transaction.lockupFailed` | The lockup transaction failed |

### Refund Flow

```
Your Wallet                Boltz              Ark Server (ASP)
      │                      │                       │
      │  1. Detect failed    │                       │
      │     swap status      │                       │
      │◄─────────────────────│                       │
      │                      │                       │
      │  2. Build refund tx  │                       │
      │     (VHTLC refund    │                       │
      │      leaf: sender +  │                       │
      │      server)         │                       │
      │                      │                       │
      │  3. Request Boltz    │                       │
      │     co-signature     │                       │
      │─────────────────────►│                       │
      │                      │                       │
      │  4. Boltz signs its  │                       │
      │     part             │                       │
      │◄─────────────────────│                       │
      │                      │                       │
      │  5. Combine sigs     │                       │
      │     + submit to ASP  │                       │
      │──────────────────────────────────────────────►│
      │                      │                       │
      │  6. ASP co-signs     │                       │
      │     and finalizes    │                       │
      │◄─────────────────────────────────────────────│
      │                      │                       │
      │  Funds returned to   │                       │
      │  your Arkade wallet  │                       │
```

### Step-by-Step

1. **Detect the failure**: Poll the swap status or listen for WebSocket
   updates. If the status is `swap.expired`, `invoice.failedToPay`, or
   `transaction.lockupFailed`, a refund is needed.

2. **Locate the VHTLC**: Query the indexer for VTXOs at the swap address.
   These are the locked funds to recover.

3. **Build the refund transaction**: Construct an off-chain transaction that
   spends the VHTLC using the **refund** leaf:
   - If the VTXO is **not recoverable** (still in the virtual tree): use the
     cooperative refund path (sender + Boltz + server). Request Boltz's
     co-signature via `POST /v2/swap/submarine/{id}/refund`, then submit to
     the ASP.
   - If the VTXO is **recoverable** (has been swept on-chain): use the
     `refundWithoutReceiver` leaf and join a batch via `RegisterIntent`.

4. **Get Boltz co-signature** (non-recoverable path): Send the unsigned
   refund transaction and checkpoint transaction to Boltz. Boltz signs its
   portion and returns the partially signed transactions.

5. **Sign your portion**: Sign the refund and checkpoint transactions with
   your wallet key.

6. **Combine signatures**: Merge the Boltz signatures with yours.

7. **Submit to the ASP**: Call `SubmitTx` with the combined refund
   transaction, then `FinalizeTx` with the signed checkpoints.

8. **Funds returned**: The refund transaction moves your funds from the VHTLC
   back to your Arkade wallet address.

### Go SDK Integration Pattern

```go
// 1. Detect failed swap
status := boltzClient.GetSwapStatus(swapID)
if status == "swap.expired" || status == "invoice.failedToPay" {
    // Refund is needed
}

// 2. Query the VHTLC VTXO from the indexer
vtxos, err := indexer.GetVtxos(ctx, swapAddressScript)

// 3. Build the VHTLC refund leaf script
// The refund leaf requires: sender (you) + Boltz + server signatures
refundLeaf := buildVHTLCRefundLeaf(yourPubKey, boltzPubKey, serverPubKey, timeout)

// 4. Build the off-chain refund transaction
refundTx, checkpointTxs := buildOffchainTx(vtxoInput, yourOutput, checkpointScript)

// 5. Request Boltz co-signature
boltzSigned := boltzClient.RefundSubmarineSwap(swapID, refundTx, checkpointTxs[0])

// 6. Sign your part
yourSignedRefundTx, _ := arkClient.SignTransaction(ctx, refundTx)
yourSignedCheckpoint, _ := arkClient.SignTransaction(ctx, checkpointTxs[0])

// 7. Combine signatures
combinedRefundTx := combineTapscriptSigs(boltzSigned.RefundTx, yourSignedRefundTx)
combinedCheckpoint := combineTapscriptSigs(boltzSigned.Checkpoint, yourSignedCheckpoint)

// 8. Submit to ASP
arkTxid, _, signedCheckpoints, _ := transportClient.SubmitTx(ctx, combinedRefundTx, checkpointTxs)

// 9. Finalize
transportClient.FinalizeTx(ctx, arkTxid, finalCheckpoints)
```

### Unilateral Refund (Emergency Path)

If Boltz is unresponsive (refuses to co-sign the refund), you can use the
**unilateral refund** path after the timelock expires:

1. Wait for the `unilateralRefund` timelock to expire.
2. Build a transaction spending the VHTLC using only your signature.
3. Broadcast the transaction on-chain (this exits the Ark virtual tree).

This is similar to the `Unroll` / `CompleteUnroll` mechanism in the Go SDK for
recovering funds from an unresponsive ASP.

---

## Manually Claiming Payments

A reverse submarine swap (receive from Lightning) may need **manual claiming**
if:
- The automatic claim process was interrupted
- The application crashed after the Lightning invoice was paid
- Network issues prevented the claim from completing

### When Is Manual Claiming Needed?

The swap status will show `transaction.mempool` or `transaction.confirmed` but
the funds haven't been moved to your address yet — the VHTLC is funded but
unclaimed.

### Claim Flow

```
Your Wallet                                  Ark Server (ASP)
      │                                            │
      │  1. Query VHTLC VTXO from indexer          │
      │                                            │
      │  2. Build claim tx using claim leaf:        │
      │     receiver (you) + server + preimage      │
      │                                            │
      │  3. Sign with VHTLC identity                │
      │     (wallet key + preimage witness)         │
      │                                            │
      │  4. SubmitTx to ASP                        │
      │────────────────────────────────────────────►│
      │                                            │
      │  5. ASP validates preimage, co-signs        │
      │◄───────────────────────────────────────────│
      │                                            │
      │  6. Sign checkpoints, FinalizeTx           │
      │────────────────────────────────────────────►│
      │                                            │
      │  Funds in your Arkade wallet                │
```

### Step-by-Step

1. **Retrieve swap data**: Load the pending reverse swap from storage,
   including the preimage and the Boltz response.

2. **Verify the VHTLC**: Reconstruct the VHTLC script from the swap
   parameters and verify the lockup address matches.

3. **Query the VTXO**: Use the indexer to find the funded VTXO at the lockup
   address.

4. **Build the claim transaction**:
   - Use the **claim** leaf (receiver + server + preimage)
   - The output sends the funds to your Arkade address
   - The witness must include the preimage to satisfy the hash lock

5. **Sign with VHTLC identity**: The claim requires a special signing context
   that includes both your wallet signature and the preimage as an extra
   witness element in the PSBT.

6. **Submit and finalize**: Call `SubmitTx` with the signed claim transaction
   and checkpoint transactions, then counter-sign the checkpoints and call
   `FinalizeTx`.

### Claiming Recoverable VTXOs

If the VHTLC's parent transaction has been unrolled (broadcast on-chain), the
VTXO becomes **recoverable**. In this case, instead of building an off-chain
transaction, you must **join a batch**:

1. Create a `RegisterIntent` with the VHTLC input and your desired output.
2. Listen for batch events via `GetEventStream`.
3. Participate in the batch signing process (submit nonces and signatures).
4. The commitment transaction settles your claim.

This is the same batch-joining mechanism the SDK uses for settlement via
`Settle()`.

### Go SDK Integration Pattern

```go
// 1. Load the pending swap (preimage, Boltz response, etc.)
preimage := loadPreimage(swapID)

// 2. Reconstruct and verify the VHTLC script
vhtlcScript := buildVHTLCScript(
    preimageHash,
    yourPubKey,
    boltzRefundPubKey,
    serverPubKey,
    timeoutBlockHeights,
)

// 3. Query the funded VTXO
vtxos, _ := indexer.GetVtxos(ctx, vhtlcPkScript)
vtxo := vtxos[0]

// 4. Build the claim transaction
claimLeaf := vhtlcScript.ClaimLeaf()
claimTx, checkpointTxs := buildOffchainTx(vtxoInput, myOutput, checkpointScript)

// 5. Sign with preimage witness
// The signing context must include the preimage as an extra witness
signedClaimTx, _ := signWithPreimage(ctx, claimTx, preimage)

// 6. Submit and finalize
arkTxid, _, signedCheckpoints, _ := transportClient.SubmitTx(ctx, signedClaimTx, checkpointTxs)
// Counter-sign checkpoints...
transportClient.FinalizeTx(ctx, arkTxid, finalCheckpoints)
```

---

## VHTLC Script Structure

A VHTLC is a Taproot output with multiple script leaves organized as a Tapscript
tree. Below is the structure of each leaf:

### Claim Leaf (Cooperative Claim)
```
OP_RIPEMD160 <ripemd160(sha256(preimage))> OP_EQUALVERIFY
<receiver_pubkey> OP_CHECKSIGVERIFY
<server_pubkey> OP_CHECKSIG
```
**Signers**: Receiver + Server
**Witness**: `<server_sig> <receiver_sig> <preimage>`
**Use case**: Normal claim after Lightning payment is received.

### Refund Leaf (Cooperative Refund)
```
<timeout_blockheight> OP_CHECKLOCKTIMEVERIFY OP_DROP
<sender_pubkey> OP_CHECKSIGVERIFY
<server_pubkey> OP_CHECKSIG
```
**Signers**: Sender + Server
**Witness**: `<server_sig> <sender_sig>`
**Use case**: Cooperative refund after the swap timeout.

### Unilateral Claim Leaf
```
<claim_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
OP_RIPEMD160 <ripemd160(sha256(preimage))> OP_EQUALVERIFY
<receiver_pubkey> OP_CHECKSIG
```
**Signers**: Receiver only
**Witness**: `<receiver_sig> <preimage>`
**Use case**: Fallback claim without server cooperation.

### Unilateral Refund Leaf
```
<refund_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
<sender_pubkey> OP_CHECKSIG
```
**Signers**: Sender only
**Witness**: `<sender_sig>`
**Use case**: Fallback refund without server cooperation.

### Unilateral Refund Without Receiver Leaf
```
<longer_refund_delay> OP_CHECKSEQUENCEVERIFY OP_DROP
<sender_pubkey> OP_CHECKSIG
```
**Signers**: Sender only
**Witness**: `<sender_sig>`
**Use case**: Last-resort refund without server or receiver cooperation.

---

## Swap Lifecycle States

Boltz provides real-time status updates for each swap via WebSocket or polling.

### Reverse Swap States (Receive from Lightning)

| Status | Description | Action |
|--------|-------------|--------|
| `swap.created` | Swap created, waiting for Lightning payment | Share invoice with payer |
| `transaction.mempool` | VHTLC funded, in mempool | **Claim the VHTLC** |
| `transaction.confirmed` | VHTLC funded, confirmed on-chain | **Claim the VHTLC** |
| `invoice.settled` | Lightning invoice settled, swap complete | ✅ Done |
| `invoice.expired` | Invoice expired before payment | Swap failed |
| `swap.expired` | Swap timed out | Swap failed |
| `transaction.failed` | VHTLC funding failed | Swap failed |
| `transaction.refunded` | Boltz reclaimed funds | Swap failed |

### Submarine Swap States (Send to Lightning)

| Status | Description | Action |
|--------|-------------|--------|
| `invoice.set` | Swap created, waiting for your payment | Send VTXO to swap address |
| `transaction.claimed` | Boltz claimed the VHTLC (invoice paid) | ✅ Done — retrieve preimage |
| `swap.expired` | Swap timed out | **Refund needed** |
| `invoice.failedToPay` | Boltz couldn't pay the invoice | **Refund needed** |
| `transaction.lockupFailed` | Lockup transaction failed | **Refund needed** |

---

## Error Types

When integrating Lightning swaps, handle these error categories:

| Error | Cause | Recovery |
|-------|-------|----------|
| **InvoiceExpiredError** | Lightning invoice expired before payment | Create a new swap |
| **InvoiceFailedToPayError** | Boltz failed to route the payment | Refund the VHTLC |
| **SwapExpiredError** | Swap timed out | Refund the VHTLC |
| **TransactionFailedError** | Transaction broadcast failed | Retry or refund |
| **TransactionLockupFailedError** | VHTLC lockup failed | Refund the VHTLC |
| **InsufficientFundsError** | Not enough Arkade balance | Top up wallet |
| **NetworkError** | API or network connectivity issue | Retry |

Always check the `isRefundable` flag on errors. If set, the error includes the
`pendingSwap` object needed to execute the refund.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                         │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │  Ark Client   │    │ Boltz Client │    │ Swap Manager  │  │
│  │  (go-sdk)     │    │ (HTTP/WS)    │    │ (optional)    │  │
│  └──────┬───────┘    └──────┬───────┘    └───────┬───────┘  │
│         │                   │                     │          │
└─────────┼───────────────────┼─────────────────────┼──────────┘
          │                   │                     │
          │                   │                     │
   ┌──────▼───────┐   ┌──────▼───────┐    ┌───────▼────────┐
   │  Ark Server   │   │    Boltz     │    │   Persistence  │
   │  (arkd)       │   │   Exchange   │    │   (swap state) │
   │               │   │              │    │                │
   │ • SubmitTx    │   │ • Create     │    │ • Pending swaps│
   │ • FinalizeTx  │   │   swaps      │    │ • Swap history │
   │ • GetInfo     │   │ • Monitor    │    │ • Refund state │
   │ • Indexer     │   │   status     │    │                │
   │ • EventStream │   │ • Co-sign    │    └────────────────┘
   └──────┬───────┘   │   refunds    │
          │           └──────┬───────┘
          │                  │
   ┌──────▼──────────────────▼───────┐
   │         Bitcoin Network          │
   │                                  │
   │  On-chain settlement layer for   │
   │  unilateral exits and recovery   │
   └──────────────────────────────────┘
```

### Component Responsibilities

- **Ark Client (go-sdk)**: Manages VTXOs, signs transactions, communicates with
  the ASP. Used to build and submit off-chain transactions for claims/refunds.
- **Boltz Client**: HTTP/WebSocket client for the Boltz API. Creates swaps,
  monitors status, and retrieves co-signatures for refunds.
- **Swap Manager** (optional): Background process that monitors all pending
  swaps and automatically claims/refunds when status changes. Handles app
  restarts by loading pending swaps from persistence.
- **Ark Server (arkd)**: The ASP that co-signs virtual transactions, manages the
  VTXO tree, and provides the indexer for querying VTXOs.
- **Boltz Exchange**: The swap counterparty that bridges Arkade and Lightning.
- **Persistence**: Local storage for swap state, enabling recovery after crashes
  or restarts.

---

## Further Reading

- [Boltz API Documentation](https://api.docs.boltz.exchange/)
- [Boltz Swap Lifecycle](https://api.docs.boltz.exchange/lifecycle.html)
- [Arkade TypeScript SDK](https://github.com/arkade-os/ts-sdk)
- [Arkade Boltz Swap Package](https://github.com/arkade-os/boltz-swap)
- [Ark Protocol Specification](https://arkdev.info)
