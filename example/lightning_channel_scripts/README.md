# Lightning Network Channels on Arkade

This example demonstrates how to create **Lightning Network channel funding outputs** using Arkade's custom VTXo script feature.

## Overview

Arkade serves as a **channel factory** for Lightning Network channels. The Arkade Server participates in channel lifecycle operations (funding, renewal, resizing, closing) but **does NOT participate in payment forwarding**. HTLCs route over standard Lightning rails between channel participants.

## Dual-Path Taproot Structure

Every Lightning channel output requires **TWO Taproot script leaves**:

### Leaf 1: Standard Lightning Script
```
OP_CHECKSIG(Alice) OP_CHECKSIGADD(Bob) OP_2 OP_NUMEQUAL
```
- Used for normal Lightning operation
- Lightning commitment transactions spend via this path
- Follows BOLT specifications exactly

### Leaf 2: Lightning Script + CSV Timeout
```
OP_CHECKSIG(Alice) OP_CHECKSIGADD(Bob) OP_2 OP_NUMEQUAL
OP_CSV(<batch_expiry_blocks>) OP_DROP
```
- Enables unilateral exit if Arkade Server becomes unavailable
- CSV delay matches the Batch expiry window
- **Fallback of last resort** - not used during normal operation

## Key Design Principles

### ✅ Server Participates In:
- Channel funding (creating the channel VTXO)
- Channel renewal (before VTXO expiry)
- Channel resizing (modifying capacity allocation)
- Channel closing (cooperative and force close coordination)

### ❌ Server Does NOT Participate In:
- Payment forwarding (HTLCs route over standard Lightning rails)
- Lightning commitment transaction signing
- Revocation secret rotation
- HTLC resolution

**Critical Principle**: The Server's public key **does NOT appear** in Lightning commitment transactions or HTLC scripts.

## Channel Lifecycle

### 1. Funding
1. Alice and Bob submit an Arkade transaction that produces a VTXO
2. VTXO script structure:
   - Internal Key: MuSig2(Alice, Bob)
   - Script Path 1: 2-of-2 multisig (standard Lightning)
   - Script Path 2: 2-of-2 multisig + CSV timeout (Ark escape hatch)
3. With **preconfirmation**: Channel usable immediately
4. For **Bitcoin finality**: Wait for next Batch settlement
5. Exchange initial Lightning commitment transactions (standard BOLT flow)

### 2. Normal Operation
- Alice and Bob exchange Lightning commitment transactions
- Rotate revocation secrets per BOLT specifications
- Forward HTLCs using standard Lightning flows
- **Server has NO role** during normal operation

### 3. Renewal (Before VTXO Expiry)
**Simple Path**: Non-interactive renewal
- Either party submits Arkade transaction attaching channel VTXO to new Batch
- No quiescence required
- Continue operating on new VTXO

**Advanced Path**: Renewal with Bitcoin finality
- Quiesce channel (pause HTLC forwarding)
- Request new VTXO in upcoming Batch
- Create Lightning commitment transactions on new VTXO
- Sign forfeit transaction on old VTXO (prevents double-spend)
- Unquiesce and resume

### 4. Force Close
**Primary Mechanism**: Cooperative force close with Server
- Contact Arkade Server
- Create Arkade transaction executing force close
- Broadcast latest Lightning commitment transaction
- Resolution proceeds via standard Lightning semantics

**Fallback**: Unilateral exit (if Server unavailable)
- Wait for Ark CSV timeout to become valid
- Broadcast unilateral exit transaction
- High cost due to potential tree unrolling
- Use only if Server disappears

## Critical Constraint: HTLC/VTXO Expiry Coordination

**Rule**: `htlc.cltv_expiry < batch_expiry - SAFETY_MARGIN`

### Why This Matters
If an HTLC's CLTV timeout extends past the VTXO's Batch expiry:
1. HTLC may still be pending
2. VTXO timeout path becomes valid
3. Counterparty can bypass channel and claim funds via Ark CSV path
4. HTLC resolution becomes unreliable

This breaks the Lightning security model.

### Implementation
```go
const SAFETY_MARGIN = 2016 // ~2 weeks in blocks

func validateHTLCExpiry(htlc *HTLC, batchExpiry uint32) error {
    if htlc.CLTVExpiry >= batchExpiry - SAFETY_MARGIN {
        return fmt.Errorf(
            "HTLC CLTV expiry %d exceeds batch expiry %d minus safety margin",
            htlc.CLTVExpiry, batchExpiry,
        )
    }
    return nil
}
```

**Safety Margin** must account for:
- Onchain confirmation time (6+ blocks recommended)
- Force close resolution time
- Network congestion buffer

## Running the Example

```bash
cd example/lightning_channel_scripts
go run main.go
```

This will:
1. Generate keys for Alice and Bob (channel participants)
2. Create a Lightning channel script builder
3. Initialize Arkade client with custom scripts
4. Generate channel funding addresses
5. Display key concepts and implementation notes

## Script Builder Implementation

The `LightningChannelScriptBuilder` implements the `VtxoScriptBuilder` interface:

```go
type LightningChannelScriptBuilder struct {
    AliceKey *btcec.PublicKey  // First channel participant
    BobKey   *btcec.PublicKey  // Second channel participant
}

func (l *LightningChannelScriptBuilder) BuildOffchainScript(
    userPubKey, signerPubKey *btcec.PublicKey,
    exitDelay arklib.RelativeLocktime,
) ([]string, error) {
    // Build dual-path Taproot:
    // Leaf 1: Standard 2-of-2 Lightning multisig
    // Leaf 2: Same multisig + CSV timeout

    lightningScript := buildLightning2of2Script(l.AliceKey, l.BobKey)
    csvScript := append(lightningScript, OP_CSV, exitDelay...)

    return encodeTaprootTree(lightningScript, csvScript)
}
```

## Integration with LND

To integrate this with LND (Lightning Labs' implementation):

1. **Intercept Funding Transaction Creation**
   - Hook into LND's `OpenChannel` RPC
   - Replace onchain funding tx with Arkade VTXO creation
   - Use custom script builder for channel scripts

2. **Script Generation Adaptation**
   - For each LND-generated Lightning script
   - Create Leaf 1 with unmodified LND script
   - Create Leaf 2 with LND script + CSV delay
   - Build Taproot tree with both leaves

3. **HTLC Acceptance Validation**
   - Hook into `update_add_htlc` validation
   - Add constraint check: `htlc.cltv_expiry < batch_expiry - SAFETY_MARGIN`
   - Reject HTLCs violating constraint

4. **Renewal Monitoring**
   - Track batch_expiry for each channel's VTXO
   - Trigger renewal at 25% lifetime remaining
   - Implement automated renewal for user wallets

5. **Force Close Handling**
   - Check Server availability
   - Use cooperative force close if available
   - Fall back to unilateral exit only if Server unavailable

## Reference Implementation

For a complete implementation, see:
- **Vincenzo Palazzo's lampo.rs**: Rust Lightning implementation with Arkade integration
- Repository: https://github.com/vincenzopalazzo/lampo.rs
- Relevant code: `lampo-ark-wallet/src/lib.rs` (line 173+)

## Security Considerations

### ✅ Best Practices
- Always enforce HTLC/VTXO expiry constraint
- Monitor VTXO expiry and renew with sufficient buffer (25% lifetime)
- Use cooperative force close as primary mechanism
- Encourage users to obtain Bitcoin finality for high-value channels
- Implement proper fee bumping for commitment transactions (RBF/CPFP)

### ❌ Anti-Patterns
- **DO NOT** include Server key in Lightning commitment transaction scripts
- **DO NOT** use unilateral exit as primary force close mechanism
- **DO NOT** accept HTLCs with timeouts extending past VTXO expiry
- **DO NOT** wait until last minute to renew VTXOs
- **DO NOT** involve Server in HTLC forwarding or payment routing

## Additional Resources

- **BOLT Specifications**: https://github.com/lightning/bolts
- **Arkade Protocol**: https://docs.arklabs.xyz/ark.pdf
- **BIP 341 (Taproot)**: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
- **BIP 65 (CLTV)**: https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki
- **BIP 112 (CSV)**: https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki

## Next Steps

To implement a production Lightning channel on Arkade:

1. **Implement Full Script Generation**
   - to_local output scripts
   - to_remote output scripts
   - HTLC offered and received scripts
   - Anchor outputs (if using option_anchors)

2. **Add HTLC Validation**
   - CLTV expiry checking
   - Safety margin configuration
   - Clear error messages for rejected HTLCs

3. **Implement Renewal Logic**
   - VTXO expiry monitoring
   - Automated renewal triggers
   - Quiescence handling for advanced renewal

4. **Build Force Close Handling**
   - Server availability checking
   - Cooperative force close implementation
   - Unilateral exit fallback
   - Fee bumping strategies

5. **Testing**
   - Test all script spending paths
   - Verify BOLT compliance
   - Test expiry edge cases
   - Validate security properties

## License

This example is provided as-is for educational purposes. Use at your own risk in production environments.
