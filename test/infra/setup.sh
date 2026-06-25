#!/bin/bash
set -o pipefail

# vars
composeFile="test/infra/docker-compose.yml"
password="password"
fulmineBoltzUrl="http://127.0.0.1:7003/api/v1"
arkdUrl="http://arkd:7070"
channelAmount=1000000
invoiceAmount=300000
invoiceAmountMsat=300000000
now=$(date +"%Y-%m-%d %H:%M:%S")
status=""
out=""
err=""
arkd_status_response=""

# commands
compose="docker compose -f $composeFile"
arkd="docker exec arkd arkd"
lndBoltz="docker exec boltz-lnd lncli --network=regtest"
clnBoltz="docker exec boltz-cln lightning-cli --network=regtest"
lndClient="docker exec lnd lncli --network=regtest"
clnClient="docker exec cln lightning-cli --network=regtest"

run_quiet() {
    local output

    # capture both stdout and stderr and return status without relying on errexit
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

# wait_for_onboard polls the /onboard endpoint until it returns a non-null
# address, working around the "service is syncing" window right after unlock.
# Echoes the address on success.
wait_for_onboard() {
    local url="$1"
    local response addr
    for _ in {1..30}; do
        response=$(curl -s -X POST "$url/onboard" -H 'Content-Type: application/json')
        addr=$(echo "$response" | jq -r '.address // empty')
        if [ -n "$addr" ] && [ "$addr" != "null" ]; then
            echo "$addr"
            return 0
        fi
        sleep 2
    done
    return 1
}

provision_boltz_fulmine() {
    echo "provisioning Fulmine used by Boltz..."
    # Wait for boltz-fulmine REST API to be reachable
    for _ in {1..30}; do
        if curl -s "$fulmineBoltzUrl/wallet/status" >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done

    seedResponse=$(curl -s $fulmineBoltzUrl/wallet/genseed)
    mnemonic=$(echo "$seedResponse" | jq -r '.mnemonic // empty')
    seed=$(echo "$seedResponse" | jq -r '.hex // empty')
    if [ $? -ne 0 ] || { [ -z "$mnemonic" ] && [ -z "$seed" ]; }; then
        exit "  ❌ failed to generate seed (response=$seedResponse)"
    fi

    if [ -n "$mnemonic" ]; then
        createPayload="{\"mnemonic\": \"$mnemonic\", \"password\": \"$password\", \"server_url\": \"$arkdUrl\"}"
    else
        createPayload="{\"private_key\": \"$seed\", \"password\": \"$password\", \"server_url\": \"$arkdUrl\"}"
    fi

    err=$(curl -s -X POST $fulmineBoltzUrl/wallet/create -H 'Content-Type: application/json' \
        -d "$createPayload")
    if [ $? -ne 0 ]; then
        exit "  ❌ failed to initialize (status=$status) (err=$err)"
    else
        echo "  ✅ initialized"
    fi
    sleep 1

    err=$(curl -s -X POST $fulmineBoltzUrl/wallet/unlock -H 'Content-Type: application/json' \
        -d "{\"password\": \"$password\"}")
    if [ $? -ne 0 ]; then
        exit "  ❌ failed to unlock (status=$status) (err=$err)"
    else
        echo "  ✅ unlocked"
    fi
    sleep 1

    addr=$(wait_for_onboard $fulmineBoltzUrl)
    if [ $? -ne 0 ] || [ -z "$addr" ]; then
        exit "  ❌ failed to get boarding address (status=$status) (err=$err)"
    fi

    err=$(nigiri faucet $addr 1)
    if [ $? -ne 0 ]; then
        exit "  ❌ failed to fund boarding address (addr=$addr) (status=$status) (err=$err)"
    fi
    sleep 5

    err=$(curl -s --max-time 20 $fulmineBoltzUrl/settle)
    if [ $? -ne 0 ]; then
        exit "  ❌ failed to settle (status=$status) (err=$err)"
    else
        echo "  ✅ funded offchain with 1 BTC"
    fi
}

wait_for_arkd_wallet_ready() {
    local response curl_status initialized unlocked synced

    for _ in {1..60}; do
        response=$(curl -sS --max-time 2 http://127.0.0.1:7071/v1/admin/wallet/status 2>&1)
        curl_status=$?
        if [ $curl_status -eq 0 ]; then
            arkd_status_response="$response"
            initialized=$(echo "$response" | jq -r '.initialized // false' 2>/dev/null)
            unlocked=$(echo "$response" | jq -r '.unlocked // false' 2>/dev/null)
            synced=$(echo "$response" | jq -r '.synced // false' 2>/dev/null)
            if [ "$initialized" = "true" ] && [ "$unlocked" = "true" ] && [ "$synced" = "true" ]; then
                return 0
            fi
        else
            arkd_status_response="curl failed with status $curl_status: $response"
        fi
        sleep 2
    done

    return 1
}

dump_compose_diagnostics() {
    echo "  --- docker compose ps ---"
    $compose ps || true

    echo "  --- docker compose logs (last 200 lines) ---"
    if [ "$#" -gt 0 ]; then
        $compose logs --no-color --tail=200 "$@" || true
    else
        $compose logs --no-color --tail=200 || true
    fi
}

echo "starting bitcoin stack..."
if ! run_quiet $compose down -v; then
    exit "  ❌ failed to tear down existing stack (status=$status) (err=$err)"
else
    echo "  ✅ stopped existing stack"
fi

if ! run_quiet nigiri stop --delete; then
    exit "  ❌ failed to tear down existing bitcoin stack (status=$status) (err=$err)"
else
    echo "  ✅ stopped existing bitcoin stack"
fi

if ! run_quiet nigiri start --ln; then
    exit "  ❌ failed (status=$status) (err=$err)"
else
    echo "  ✅ started"
fi

echo "setting up Arkade server stack..."
if ! run_quiet $compose up -d arkd; then
    exit "  ❌ failed to start stack (status=$status) (err=$err)"
else
    echo "  ✅ stack started"
fi

# Wait for arkd's admin REST listener to come up (longer than a fixed sleep
# would reliably wait — arkd-wallet sync can take ~10-15s on a fresh stack).
arkd_admin_ready=0
for _ in {1..30}; do
    if docker exec arkd wget -q -O- http://127.0.0.1:7071/v1/admin/wallet/seed >/dev/null 2>&1; then
        arkd_admin_ready=1
        break
    fi
    sleep 2
done
if [ $arkd_admin_ready -ne 1 ]; then
    dump_compose_diagnostics pgnbxplorer nbxplorer arkd-wallet arkd
    exit "  ❌ arkd admin API did not become ready"
fi

echo "provisioning Arkade server..."
err=$($arkd wallet create --password $password)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to initialize (status=$status) (err=$err)"
else
    echo "  ✅ initialized"
fi
sleep 1

err=$($arkd wallet unlock --password $password)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to unlock (status=$status) (err=$err)"
else
    echo "  ✅ unlocked"
fi

if ! wait_for_arkd_wallet_ready; then
    dump_compose_diagnostics pgnbxplorer nbxplorer arkd-wallet arkd
    exit "  ❌ arkd wallet did not become ready after unlock (last response: $arkd_status_response)"
else
    echo "  ✅ wallet ready"
fi

addr=$($arkd wallet address)
if [ $? -ne 0 ] || [ -z "$addr" ]; then
    exit "  ❌ failed to get wallet address"
fi

funded_count=0
for i in {1..21}; do
    err=$(nigiri faucet $addr)
    if [ $? -ne 0 ]; then
        exit "  ❌ failed to fund (status=$status) (err=$err)"
    fi
    funded_count=$((funded_count + 1))
    sleep 1
done
echo "  ✅ funded onchain with $funded_count BTC"

if ! wait_for_arkd_wallet_ready; then
    dump_compose_diagnostics pgnbxplorer nbxplorer arkd-wallet arkd
    exit "  ❌ arkd wallet did not become ready after funding (last response: $arkd_status_response)"
else
    echo "  ✅ wallet synced"
fi

echo "setting up Solver stack..."
if ! run_quiet $compose up -d --no-recreate emulator solver; then
    dump_compose_diagnostics pgnbxplorer nbxplorer arkd-wallet arkd emulator solver
    exit "  ❌ failed to start stack (status=$status) (err=$err)"
else
    echo "  ✅ stack started"
fi

# Wait for solver's HTTP listener and the preimage plugin to be running.
solver_ready=0
last_solver_response=""
for _ in {1..30}; do
    response=$(curl -sS --max-time 2 http://127.0.0.1:7271/v1/plugins 2>&1)
    curl_status=$?
    if [ $curl_status -eq 0 ]; then
        last_solver_response="$response"
    else
        last_solver_response="curl failed with status $curl_status: $response"
    fi

    if [ $curl_status -eq 0 ] && [ -n "$response" ] && [ "$(echo "$response" | jq -r '.preimage.running // false' 2>/dev/null)" = "true" ]; then
        solver_ready=1
        break
    fi
    sleep 2
done
if [ $solver_ready -ne 1 ]; then
    dump_compose_diagnostics pgnbxplorer nbxplorer arkd-wallet arkd emulator solver
    exit "  ❌ solver preimage plugin did not become ready (last response: $last_solver_response)"
else
    echo "  ✅ solver ready (preimage plugin running)"
fi

echo "setting up Boltz stack..."
if ! run_quiet $compose up -d --no-recreate boltz mock-boltz boltz-fulmine; then
    exit "  ❌ failed to start stack (status=$status) (err=$err)"
else
    echo "  ✅ stack started"
fi
sleep 5

echo "provisioning LN..."
lndPubkey=$($lndClient getinfo | jq -r .identity_pubkey)
lndBoltzPubkey=$($lndBoltz getinfo | jq -r .identity_pubkey)

err=$($lndBoltz connect $lndPubkey@lnd:9735)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to connect lnd peers (status=$status) (err=$err)"
else
    echo "  ✅ lnd peers connected"
fi
sleep 10

clnPubkey=$($clnClient getinfo | jq -r .id)
clnBoltzPubkey=$($clnBoltz getinfo | jq -r .id)

err=$($clnBoltz connect $clnPubkey cln 9935)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to connect cln peers (status=$status) (err=$err)"
else
    echo "  ✅ cln peers connected"
fi

err=$(nigiri faucet lnd)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to fund lnd (status=$status) (err=$err)"
fi
sleep 1

addr=$($lndBoltz newaddress p2wkh | jq -r .address)
err=$(nigiri faucet $addr)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to fund boltz-lnd (addr=$addr) (status=$status) (err=$err)"
else
    echo "  ✅ funded lnd nodes onchain with 1 BTC"
fi
sleep 1

err=$(nigiri faucet cln)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to fund cln (status=$status) (err=$err)"
fi
sleep 1

addr=$($clnBoltz --network=regtest newaddr bech32 | jq -r .bech32)
err=$(nigiri faucet $addr)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to fund boltz-cln (addr=$addr) (status=$status) (err=$err)"
else
    echo "  ✅ funded cln nodes onchain with 1 BTC"
fi
sleep 5

# Mine blocks to confirm any pending channels before opening new ones
nigiri rpc --generate 6 >/dev/null 2>&1
sleep 3

retry $lndBoltz openchannel --node_key=$lndPubkey --local_amt=$channelAmount
if [ $? -ne 0 ]; then
    exit "  ❌ failed to open channel boltz-lnd -> lnd (status=$status) (err=$err)"
fi

nigiri rpc --generate 6 >/dev/null 2>&1
sleep 3

retry $lndClient openchannel --node_key=$lndBoltzPubkey --local_amt=$channelAmount
if [ $? -ne 0 ]; then
    exit "  ❌ failed to open channel boltz-lnd <- lnd (status=$status) (err=$err)"
else 
    echo "  ✅ opened channels boltz-lnd <-> lnd"
fi


nigiri rpc --generate 6 >/dev/null 2>&1
sleep 3

retry $clnBoltz fundchannel id=$clnPubkey amount=$channelAmount
if [ $? -ne 0 ]; then
    exit "  ❌ failed to open channel boltz-cln -> cln (status=$status) (err=$err)"
fi

nigiri rpc --generate 6 >/dev/null 2>&1
sleep 3

retry $clnClient fundchannel id=$clnBoltzPubkey amount=$channelAmount
if [ $? -ne 0 ]; then
    exit "  ❌ failed to open channel boltz-cln <- cln (status=$status) (err=$err)"
else 
    echo "  ✅ opened channels boltz-cln <-> cln"
fi

err=$(nigiri rpc --generate 10)
if [ $? -ne 0 ]; then
    exit "  ❌ failed to mine blocks (status=$status) (err=$err)"
fi
sleep 10

invoice=$($lndClient addinvoice --amt $invoiceAmount | jq -r .payment_request)
retry $lndBoltz payinvoice $invoice --force
if [ $? -ne 0 ]; then
    exit "  ❌ failed to pay lnd invoice (invoice=$invoice) (status=$status) (err=$err)"
fi
sleep 1

invoice=$($lndBoltz addinvoice --amt $invoiceAmount | jq -r .payment_request)
retry $lndClient payinvoice $invoice --force
if [ $? -ne 0 ]; then
    exit "  ❌ failed to pay boltz-lnd invoice (invoice=$invoice) (status=$status) (err=$err)"
else
    echo "  ✅ paid invoices boltz-lnd <-> lnd"
fi

invoice=$($clnClient invoice $invoiceAmountMsat "$now" "" | jq -r .bolt11)
retry $clnBoltz pay $invoice
if [ $? -ne 0 ]; then
    exit "  ❌ failed to pay cln invoice (invoice=$invoice) (status=$status) (err=$err)"
fi
sleep 1

invoice=$($clnBoltz invoice $invoiceAmountMsat "$now" "" | jq -r .bolt11)
retry $clnClient pay $invoice
if [ $? -ne 0 ]; then
    exit "  ❌ failed to pay boltz-cln invoice (invoice=$invoice) (status=$status) (err=$err)"
else
    echo "  ✅ paid invoices boltz-cln <-> cln"
fi

run_quiet docker restart boltz
provision_boltz_fulmine

echo "✅ setup complete"
