#!/bin/bash
# Show balances for all regtest services.
# Usage: bash test/infra/balances.sh

adminUrl="http://127.0.0.1:7071"
boltzFulmineUrl="http://127.0.0.1:7003/api/v1"
lndBoltz="docker exec boltz-lnd lncli --network=regtest"
lndClient="docker exec lnd lncli --network=regtest"
clnBoltz="docker exec boltz-cln lightning-cli --network=regtest"
clnClient="docker exec cln lightning-cli --network=regtest"

fmt="  %-22s %s\n"

echo "=== arkd wallet ==="
resp=$(curl -sf "$adminUrl/v1/admin/wallet/balance" 2>/dev/null)
if [ $? -eq 0 ]; then
    available=$(echo "$resp" | jq -r '.mainAccount.available // "n/a"')
    printf "$fmt" "onchain (BTC):" "$available"
else
    echo "  (unreachable)"
fi

echo ""
echo "=== boltz-fulmine ==="
resp=$(curl -sf "$boltzFulmineUrl/balance" 2>/dev/null)
if [ $? -eq 0 ]; then
    amount=$(echo "$resp" | jq -r '.amount // "n/a"')
    printf "$fmt" "balance (sats):" "$amount"
    # count vtxos (total and unspent)
    vtxo_resp=$(curl -sf "$boltzFulmineUrl/vtxos" 2>/dev/null)
    if [ $? -eq 0 ]; then
        total=$(echo "$vtxo_resp" | jq '[.vtxos[]?] | length')
        unspent=$(echo "$vtxo_resp" | jq '[.vtxos[]? | select(.isSpent == false)] | length')
        printf "$fmt" "vtxos (total):" "$total"
        printf "$fmt" "vtxos (unspent):" "$unspent"
    fi
else
    echo "  (unreachable)"
fi

echo ""
echo "=== lnd (client) ==="
resp=$($lndClient walletbalance 2>/dev/null)
if [ $? -eq 0 ]; then
    confirmed=$(echo "$resp" | jq -r '.confirmed_balance // "n/a"')
    printf "$fmt" "onchain (sats):" "$confirmed"
else
    echo "  (unreachable)"
fi
resp=$($lndClient channelbalance 2>/dev/null)
if [ $? -eq 0 ]; then
    local_bal=$(echo "$resp" | jq -r '.local_balance.sat // "n/a"')
    remote_bal=$(echo "$resp" | jq -r '.remote_balance.sat // "n/a"')
    printf "$fmt" "channel local (sats):" "$local_bal"
    printf "$fmt" "channel remote (sats):" "$remote_bal"
fi

echo ""
echo "=== boltz-lnd ==="
resp=$($lndBoltz walletbalance 2>/dev/null)
if [ $? -eq 0 ]; then
    confirmed=$(echo "$resp" | jq -r '.confirmed_balance // "n/a"')
    printf "$fmt" "onchain (sats):" "$confirmed"
else
    echo "  (unreachable)"
fi
resp=$($lndBoltz channelbalance 2>/dev/null)
if [ $? -eq 0 ]; then
    local_bal=$(echo "$resp" | jq -r '.local_balance.sat // "n/a"')
    remote_bal=$(echo "$resp" | jq -r '.remote_balance.sat // "n/a"')
    printf "$fmt" "channel local (sats):" "$local_bal"
    printf "$fmt" "channel remote (sats):" "$remote_bal"
fi

echo ""
echo "=== cln (client) ==="
resp=$($clnClient listfunds 2>/dev/null)
if [ $? -eq 0 ]; then
    onchain=$(echo "$resp" | jq '[.outputs[]? | select(.status=="confirmed") | .amount_msat] | add // 0 | . / 1000 | floor')
    chan_local=$(echo "$resp" | jq '[.channels[]? | .our_amount_msat] | add // 0 | . / 1000 | floor')
    chan_remote=$(echo "$resp" | jq '[.channels[]? | (.amount_msat - .our_amount_msat)] | add // 0 | . / 1000 | floor')
    printf "$fmt" "onchain (sats):" "$onchain"
    printf "$fmt" "channel local (sats):" "$chan_local"
    printf "$fmt" "channel remote (sats):" "$chan_remote"
else
    echo "  (unreachable)"
fi

echo ""
echo "=== boltz-cln ==="
resp=$($clnBoltz listfunds 2>/dev/null)
if [ $? -eq 0 ]; then
    onchain=$(echo "$resp" | jq '[.outputs[]? | select(.status=="confirmed") | .amount_msat] | add // 0 | . / 1000 | floor')
    chan_local=$(echo "$resp" | jq '[.channels[]? | .our_amount_msat] | add // 0 | . / 1000 | floor')
    chan_remote=$(echo "$resp" | jq '[.channels[]? | (.amount_msat - .our_amount_msat)] | add // 0 | . / 1000 | floor')
    printf "$fmt" "onchain (sats):" "$onchain"
    printf "$fmt" "channel local (sats):" "$chan_local"
    printf "$fmt" "channel remote (sats):" "$chan_remote"
else
    echo "  (unreachable)"
fi

echo ""
echo "=== mock-boltz ==="
resp=$(curl -sf "http://127.0.0.1:9101/health" 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "  status: healthy"
else
    echo "  status: unreachable"
fi
