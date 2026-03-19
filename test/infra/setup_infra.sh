#!/bin/bash
set -o pipefail

# Unified setup script for go-sdk regtest infrastructure.
#
# Usage:
#   bash test/infra/setup_infra.sh              # full stack (arkd + boltz + LN)
#   bash test/infra/setup_infra.sh --arkd-only  # arkd only (for basic regtest)
#
# Phase 1: Provision arkd (wait for ready, create/unlock wallet, fund via faucet)
# Phase 2: Provision Boltz stack (boltz-fulmine, LN channels, liquidity)

# --- Config ---
arkdOnly=false
if [ "$1" = "--arkd-only" ]; then
    arkdOnly=true
fi

adminUrl="http://127.0.0.1:7071"
arkdPassword="secret"
composeFile="test/infra/docker-compose.yml"

boltzFulmineUrl="http://127.0.0.1:7003/api/v1"
boltzPassword="password"
arkdInternalUrl="http://arkd:7070"
channelAmount=5000000
invoiceAmount=1500000
invoiceAmountMsat=1500000000
now=$(date +"%Y-%m-%d %H:%M:%S")
status=""
out=""
err=""

# --- Commands ---
compose="docker compose -f $composeFile"
lndBoltz="docker exec boltz-lnd lncli --network=regtest"
clnBoltz="docker exec boltz-cln lightning-cli --network=regtest"
lndClient="docker exec lnd lncli --network=regtest"
clnClient="docker exec cln lightning-cli --network=regtest"

# --- Helpers ---
run_quiet() {
    local output
    output=$("$@" 2>&1)
    status=$?
    if [ $status -eq 0 ]; then
        out="$output"
        return 0
    else
        err="$output"
        return $status
    fi
}

exit() {
    echo "$@"
    builtin exit 1
}

retry() {
    local rc
    for i in {1..6}; do
        err=$("$@" 2>&1)
        rc=$?
        if [ "$rc" -eq 0 ]; then
            status=0
            return 0
        fi
        status="$rc"
        sleep 6
    done
    return "$status"
}

# ============================================================
# Phase 1: Provision arkd
# ============================================================

echo "waiting for arkd to be ready..."
for i in $(seq 1 40); do
    resp=$(curl -sf "$adminUrl/v1/admin/wallet/status" 2>/dev/null)
    if [ $? -eq 0 ]; then
        break
    fi
    printf "  attempt %d/40: arkd not ready yet\n" "$i"
    if [ "$i" -eq 40 ]; then
        exit "arkd did not become ready after 40 attempts"
    fi
    sleep 3
done

initialized=$(echo "$resp" | jq -r .initialized)
unlocked=$(echo "$resp" | jq -r .unlocked)
synced=$(echo "$resp" | jq -r .synced)

if [ "$initialized" = "true" ] && [ "$unlocked" = "false" ]; then
    echo "unlocking wallet..."
    curl -sf -X POST "$adminUrl/v1/admin/wallet/unlock" \
        -H 'Content-Type: application/json' \
        -d "{\"password\": \"$arkdPassword\"}" > /dev/null \
        || exit "failed to unlock wallet"
elif [ "$initialized" = "true" ] && [ "$unlocked" = "true" ] && [ "$synced" = "true" ]; then
    echo "wallet already initialized and synced"
else
    echo "getting wallet seed..."
    seed=$(curl -sf "$adminUrl/v1/admin/wallet/seed" | jq -r .seed)
    if [ $? -ne 0 ] || [ -z "$seed" ] || [ "$seed" = "null" ]; then
        exit "failed to get wallet seed"
    fi

    echo "creating wallet..."
    curl -sf -X POST "$adminUrl/v1/admin/wallet/create" \
        -H 'Content-Type: application/json' \
        -d "{\"seed\": \"$seed\", \"password\": \"$arkdPassword\"}" > /dev/null \
        || exit "failed to create wallet"

    echo "unlocking wallet..."
    curl -sf -X POST "$adminUrl/v1/admin/wallet/unlock" \
        -H 'Content-Type: application/json' \
        -d "{\"password\": \"$arkdPassword\"}" > /dev/null \
        || exit "failed to unlock wallet"
fi

echo "waiting for wallet to be synced..."
for i in $(seq 1 60); do
    resp=$(curl -sf "$adminUrl/v1/admin/wallet/status" 2>/dev/null)
    synced=$(echo "$resp" | jq -r .synced)
    unlocked=$(echo "$resp" | jq -r .unlocked)
    if [ "$synced" = "true" ] && [ "$unlocked" = "true" ]; then
        break
    fi
    if [ "$i" -eq 60 ]; then
        exit "wallet did not sync after 60 attempts"
    fi
    sleep 2
done

# Fund arkd wallet up to 75 BTC
balance=$(curl -sf "$adminUrl/v1/admin/wallet/balance" | jq -r '.mainAccount.available')
if [ $? -ne 0 ] || [ -z "$balance" ]; then
    exit "failed to get wallet balance"
fi

delta=$(echo "75 - $balance" | bc | cut -d. -f1)
if [ "$delta" -gt 0 ] 2>/dev/null; then
    addr=$(curl -sf "$adminUrl/v1/admin/wallet/address" | jq -r .address)
    if [ $? -ne 0 ] || [ -z "$addr" ] || [ "$addr" = "null" ]; then
        exit "failed to get wallet address"
    fi
    for i in $(seq 1 "$delta"); do
        nigiri faucet "$addr" > /dev/null || exit "failed to fund arkd wallet"
    done
fi
echo "setup arkd completed"

if [ "$arkdOnly" = true ]; then
    builtin exit 0
fi

# ============================================================
# Phase 2: Provision Boltz stack
# ============================================================

echo "ensuring Boltz services are running..."
if ! run_quiet $compose up -d --no-deps boltz-fulmine boltz-cln boltz-lnd boltz-postgres; then
    echo "  warning: some services may already be running: $err"
fi
sleep 5

echo "waiting for LN nodes to be healthy..."
for i in {1..30}; do
    lnd_h=$(docker inspect --format='{{.State.Health.Status}}' boltz-lnd 2>/dev/null)
    cln_h=$(docker inspect --format='{{.State.Health.Status}}' boltz-cln 2>/dev/null)
    pg_h=$(docker inspect --format='{{.State.Health.Status}}' boltz-postgres 2>/dev/null)
    if [ "$lnd_h" = "healthy" ] && [ "$cln_h" = "healthy" ] && [ "$pg_h" = "healthy" ]; then
        echo "  all Boltz dependencies healthy"
        break
    fi
    sleep 5
done

if ! run_quiet $compose up -d --no-deps boltz; then
    echo "  warning: boltz may already be running: $err"
fi
sleep 5

echo "provisioning boltz-fulmine..."
seed=$(curl -s $boltzFulmineUrl/wallet/genseed | jq -r .hex)
if [ $? -ne 0 ] || [ -z "$seed" ] || [ "$seed" = "null" ]; then
    exit "  failed to generate seed for boltz-fulmine"
fi

err=$(curl -s -X POST $boltzFulmineUrl/wallet/create -H 'Content-Type: application/json' \
    -d "{\"private_key\": \"$seed\", \"password\": \"$boltzPassword\", \"server_url\": \"$arkdInternalUrl\"}")
if [ $? -ne 0 ]; then
    exit "  failed to initialize boltz-fulmine (err=$err)"
else
    echo "  boltz-fulmine initialized"
fi
sleep 1

err=$(curl -s -X POST $boltzFulmineUrl/wallet/unlock -H 'Content-Type: application/json' \
    -d "{\"password\": \"$boltzPassword\"}")
if [ $? -ne 0 ]; then
    exit "  failed to unlock boltz-fulmine (err=$err)"
else
    echo "  boltz-fulmine unlocked"
fi
sleep 1

addr=$(curl -s -X POST $boltzFulmineUrl/onboard -H 'Content-Type: application/json' | jq -r .address)
if [ $? -ne 0 ] || [ -z "$addr" ] || [ "$addr" = "null" ]; then
    exit "  failed to get boltz-fulmine boarding address"
fi
err=$(nigiri faucet $addr 5)
if [ $? -ne 0 ]; then
    exit "  failed to fund boltz-fulmine boarding address (addr=$addr) (err=$err)"
fi
sleep 5

err=$(curl -s $boltzFulmineUrl/settle)
if [ $? -ne 0 ]; then
    exit "  failed to settle boltz-fulmine (err=$err)"
else
    echo "  boltz-fulmine funded offchain with 5 BTC"
fi

echo "provisioning LN channels..."
lndPubkey=$($lndClient getinfo | jq -r .identity_pubkey)
lndBoltzPubkey=$($lndBoltz getinfo | jq -r .identity_pubkey)

err=$($lndBoltz connect $lndPubkey@lnd:9735)
if [ $? -ne 0 ]; then
    echo "  warning: lnd peer connect returned error (may already be connected): $err"
fi
echo "  lnd peers connected"
sleep 10

clnPubkey=$($clnClient getinfo | jq -r .id)
clnBoltzPubkey=$($clnBoltz getinfo | jq -r .id)

err=$($clnBoltz connect $clnPubkey cln 9935)
if [ $? -ne 0 ]; then
    echo "  warning: cln peer connect returned error (may already be connected): $err"
fi
echo "  cln peers connected"

for i in $(seq 1 5); do
    err=$(nigiri faucet lnd)
    if [ $? -ne 0 ]; then
        exit "  failed to fund lnd (round $i) (err=$err)"
    fi
done
sleep 1

addr=$($lndBoltz newaddress p2wkh | jq -r .address)
for i in $(seq 1 5); do
    err=$(nigiri faucet $addr)
    if [ $? -ne 0 ]; then
        exit "  failed to fund boltz-lnd (round $i, addr=$addr) (err=$err)"
    fi
done
echo "  funded lnd nodes onchain with 5 BTC each"
sleep 1

for i in $(seq 1 5); do
    err=$(nigiri faucet cln)
    if [ $? -ne 0 ]; then
        exit "  failed to fund cln (round $i) (err=$err)"
    fi
done
sleep 1

addr=$($clnBoltz --network=regtest newaddr bech32 | jq -r .bech32)
for i in $(seq 1 5); do
    err=$(nigiri faucet $addr)
    if [ $? -ne 0 ]; then
        exit "  failed to fund boltz-cln (round $i, addr=$addr) (err=$err)"
    fi
done
echo "  funded cln nodes onchain with 5 BTC each"
sleep 5

retry $lndBoltz openchannel --node_key=$lndPubkey --local_amt=$channelAmount
if [ $? -ne 0 ]; then
    exit "  failed to open channel boltz-lnd -> lnd (err=$err)"
fi
sleep 1

retry $lndClient openchannel --node_key=$lndBoltzPubkey --local_amt=$channelAmount
if [ $? -ne 0 ]; then
    exit "  failed to open channel lnd -> boltz-lnd (err=$err)"
else
    echo "  opened channels boltz-lnd <-> lnd"
fi

retry $clnBoltz fundchannel id=$clnPubkey amount=$channelAmount
if [ $? -ne 0 ]; then
    exit "  failed to open channel boltz-cln -> cln (err=$err)"
fi
sleep 1

retry $clnClient fundchannel id=$clnBoltzPubkey amount=$channelAmount
if [ $? -ne 0 ]; then
    exit "  failed to open channel cln -> boltz-cln (err=$err)"
else
    echo "  opened channels boltz-cln <-> cln"
fi

err=$(nigiri rpc --generate 10)
if [ $? -ne 0 ]; then
    exit "  failed to mine blocks (err=$err)"
fi
sleep 10

invoice=$($lndClient addinvoice --amt $invoiceAmount | jq -r .payment_request)
retry $lndBoltz payinvoice $invoice --force
if [ $? -ne 0 ]; then
    exit "  failed to pay lnd invoice (err=$err)"
fi
sleep 1

invoice=$($lndBoltz addinvoice --amt $invoiceAmount | jq -r .payment_request)
retry $lndClient payinvoice $invoice --force
if [ $? -ne 0 ]; then
    exit "  failed to pay boltz-lnd invoice (err=$err)"
else
    echo "  paid invoices boltz-lnd <-> lnd"
fi

invoice=$($clnClient invoice $invoiceAmountMsat "$now" "" | jq -r .bolt11)
retry $clnBoltz pay $invoice
if [ $? -ne 0 ]; then
    exit "  failed to pay cln invoice (err=$err)"
fi
sleep 1

invoice=$($clnBoltz invoice $invoiceAmountMsat "$now" "" | jq -r .bolt11)
retry $clnClient pay $invoice
if [ $? -ne 0 ]; then
    exit "  failed to pay boltz-cln invoice (err=$err)"
else
    echo "  paid invoices boltz-cln <-> cln"
fi

run_quiet docker restart boltz
sleep 5

echo "Boltz stack setup complete"
echo ""
bash test/infra/balances.sh
