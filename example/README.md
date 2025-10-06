# Explorer Demo Examples

This directory contains example programs demonstrating the multi-connection explorer functionality.

## Multi-Connection Demo

The `multi_connection_demo.go` demonstrates the explorer's ability to handle high-volume address subscriptions using multiple concurrent WebSocket connections with batching and deduplication.

### Usage

```bash
go run example/multi_connection_demo.go [flags]
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-addresses` | int | 100 | Number of addresses to generate and subscribe |
| `-connections` | int | 3 | Maximum number of concurrent WebSocket connections |
| `-batch-size` | int | 25 | Number of addresses per batch (see explanation below) |
| `-batch-delay` | duration | 50ms | Pause between sending batches (see explanation below) |
| `-url` | string | https://mempool.space/api | Explorer API URL |
| `-max-events` | int | 5 | Maximum events to receive before stopping (0 = unlimited) |
| `-show-all` | bool | false | Show all subscribed addresses (not just first 3) |

#### Understanding Batching

When subscribing to many addresses, they are split into **batches** to avoid overwhelming the WebSocket connection:

**Example**: 100 addresses with `batch-size=25` and `batch-delay=50ms`
```
Time 0ms:    Send batch 1 (addresses 1-25)
Time 50ms:   Send batch 2 (addresses 26-50)
Time 100ms:  Send batch 3 (addresses 51-75)
Time 150ms:  Send batch 4 (addresses 76-100)
Total time: ~150ms
```

**Why batch-delay matters:**
- **0ms delay**: All batches sent immediately (fast but may overwhelm server)
- **50ms delay**: Spreads requests over time (polite, avoids rate limiting)
- **200ms delay**: Very conservative (slow but safest for rate-limited APIs)

**Visual comparison:**

```
No delay (batch-delay=0):
[Batch1][Batch2][Batch3][Batch4] ← All sent instantly
└─ Fast but risky

With delay (batch-delay=50ms):
[Batch1]--50ms--[Batch2]--50ms--[Batch3]--50ms--[Batch4]
└─ Balanced approach

Large delay (batch-delay=200ms):
[Batch1]------200ms------[Batch2]------200ms------[Batch3]------200ms------[Batch4]
└─ Very safe but slow
```

### Examples

#### Default Configuration (100 addresses, 3 connections)
```bash
go run example/multi_connection_demo.go
```

#### Stress Test: 500 addresses on single connection
```bash
go run example/multi_connection_demo.go \
  -addresses 500 \
  -connections 1 \
  -batch-size 500 \
  -batch-delay 0
```

#### High Volume: 1000 addresses across 5 connections
```bash
go run example/multi_connection_demo.go \
  -addresses 1000 \
  -connections 5 \
  -batch-size 50 \
  -batch-delay 100ms
```

#### Conservative: Small batches with delays
```bash
go run example/multi_connection_demo.go \
  -addresses 200 \
  -connections 2 \
  -batch-size 10 \
  -batch-delay 200ms
```

#### Listen indefinitely for events
```bash
go run example/multi_connection_demo.go \
  -addresses 50 \
  -max-events 0
```

### Performance Results

Based on testing with mempool.space:

| Addresses | Connections | Batch Size | Delay | Time | Status |
|-----------|-------------|------------|-------|------|--------|
| 100 | 3 | 25 | 50ms | ~150ms | ✅ Success |
| 500 | 1 | 25 | 50ms | ~960ms | ✅ Success |
| 500 | 1 | 500 | 0ms | ~500µs | ✅ Success |
| 1000 | 1 | 500 | 0ms | ~790µs | ✅ Success |
| 1000 | 5 | 50 | 100ms | ~1.7s | ✅ Success |

### Architecture

The demo showcases:
- **Connection Pool**: Multiple concurrent WebSocket connections
- **Hash-based Routing**: Consistent address-to-connection mapping
- **Batching**: Prevents overwhelming individual connections
- **Deduplication**: Global address map prevents duplicate subscriptions
- **Graceful Fallback**: Automatic fallback to HTTP polling if WebSocket fails
- **Runtime Verification**: Validates actual service configuration vs requested parameters

### Verification Features

The demo verifies the actual runtime configuration from the explorer service:
- **Connection Count**: Actual number of active WebSocket connections
- **Batch Configuration**: Confirmed batch size and delay settings
- **Subscription Count**: Real-time count of subscribed addresses
- **Fallback Detection**: Automatically detects when polling mode is active

## Alice to Bob Example

The `alice_to_bob/` directory contains a complete example of sending Bitcoin transactions using the Ark protocol.

```bash
go run example/alice_to_bob/alice_to_bob.go
```

This example demonstrates:
- Setting up Ark clients
- Onboarding funds
- Sending off-chain transactions
- Settling transactions
