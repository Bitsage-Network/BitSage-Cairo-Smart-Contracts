#!/bin/bash

echo "🎯 ACTIVATING ALL CONTRACTS IN STARKSCAN"
echo "========================================"
echo ""

# Contract addresses
TREASURY_TIMELOCK="0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7"
CIRO_TOKEN="0x03c0f7574905d7cbc2cca18d6c090265fa35b572d8e9dc62efeb5339908720d8"
CDC_POOL="0x05f73c551dbfda890090c8ee89858992dfeea9794a63ad83e6b1706e9836aeba"
JOB_MANAGER="0x00bf025663b8a7c7e43393f082b10afe66bd9ddb06fb5e521e3adbcf693094bd"
REPUTATION_MANAGER="0x02f0ce7e13e113e91f3a4669f742e7470f2bdfb3c7146aff1d449fddf92b7dc0"
SIMPLE_EVENTS="0x02b4841412c3c27eab3c6e7cf2baefea15c3570bf349b68e215a82815a2abea8"

# Account addresses
DEPLOYER_ADDRESS="0x2f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"
TARGET_ADDRESS="0x1176a1bd84444c89232ec27754698e5d2e7e1a7f1539f12027f28b23ec9f3d8"

# Keystore and account
KEYSTORE="/Users/vaamx/cironetwork/ciro-network/CIRO_Network_Backup/20250711_061352/testnet_keystore.json"
ACCOUNT="temp_account.json"

echo "📋 Contracts to activate:"
echo "  • Treasury Timelock: $TREASURY_TIMELOCK"
echo "  • CIRO Token: $CIRO_TOKEN" 
echo "  • CDC Pool: $CDC_POOL"
echo "  • Job Manager: $JOB_MANAGER"
echo "  • Reputation Manager: $REPUTATION_MANAGER"
echo "  • SimpleEvents: $SIMPLE_EVENTS"
echo ""

# Helper function for transactions
invoke_contract() {
    local contract=$1
    local function=$2
    shift 2
    echo "🔄 Calling $contract.$function..."
    
    starkli invoke \
        --keystore "$KEYSTORE" \
        --account "$ACCOUNT" \
        --network sepolia \
        "$contract" \
        "$function" \
        "$@" || echo "❌ Failed: $function"
    
    sleep 2
}

# Helper function for view calls (generates "Account Calls" in StarkScan)
call_contract() {
    local contract=$1
    local function=$2
    shift 2
    echo "👁️  Reading $contract.$function..."
    
    starkli call \
        --network sepolia \
        "$contract" \
        "$function" \
        "$@" || echo "❌ Failed: $function"
    
    sleep 1
}

echo "🚀 Step 1: Generate MORE SimpleEvents"
echo "======================================"
invoke_contract "$SIMPLE_EVENTS" "emit_event" "StarkScan Test 1"
invoke_contract "$SIMPLE_EVENTS" "emit_event" "StarkScan Test 2" 
invoke_contract "$SIMPLE_EVENTS" "emit_event" "Activity Check"

echo ""
echo "🚀 Step 2: Generate CIRO Token Activity"
echo "========================================"
# Small transfer (under 10k tokens threshold)
invoke_contract "$CIRO_TOKEN" "transfer" "$TARGET_ADDRESS" "1000000000000000000" "0"  # 1 token
invoke_contract "$CIRO_TOKEN" "approve" "$TREASURY_TIMELOCK" "5000000000000000000" "0"  # 5 tokens

# Generate view calls for Account Calls
call_contract "$CIRO_TOKEN" "name"
call_contract "$CIRO_TOKEN" "symbol" 
call_contract "$CIRO_TOKEN" "decimals"
call_contract "$CIRO_TOKEN" "total_supply"
call_contract "$CIRO_TOKEN" "balance_of" "$DEPLOYER_ADDRESS"

echo ""
echo "🚀 Step 3: Generate Treasury Timelock Activity"  
echo "==============================================="
# Try basic view calls first
call_contract "$TREASURY_TIMELOCK" "get_required_approvals"
call_contract "$TREASURY_TIMELOCK" "get_timelock_delay"

echo ""
echo "🚀 Step 4: Generate CDC Pool Activity"
echo "====================================="
# View calls for CDC Pool
call_contract "$CDC_POOL" "get_total_stake"
call_contract "$CDC_POOL" "get_stake_of" "$DEPLOYER_ADDRESS"

echo ""
echo "🚀 Step 5: Generate Job Manager Activity"
echo "========================================"
call_contract "$JOB_MANAGER" "get_job_count"
call_contract "$JOB_MANAGER" "is_worker_registered" "$DEPLOYER_ADDRESS"

echo ""
echo "🚀 Step 6: Generate Reputation Manager Activity" 
echo "==============================================="
call_contract "$REPUTATION_MANAGER" "get_worker_reputation" "$DEPLOYER_ADDRESS"
call_contract "$REPUTATION_MANAGER" "get_total_workers"

echo ""
echo "✅ ACTIVATION COMPLETE!"
echo "======================="
echo ""
echo "🌐 Check StarkScan for activity:"
echo "  • SimpleEvents: https://sepolia.starkscan.co/contract/$SIMPLE_EVENTS"
echo "  • CIRO Token: https://sepolia.starkscan.co/contract/$CIRO_TOKEN"
echo "  • Treasury Timelock: https://sepolia.starkscan.co/contract/$TREASURY_TIMELOCK"
echo "  • CDC Pool: https://sepolia.starkscan.co/contract/$CDC_POOL"
echo "  • Job Manager: https://sepolia.starkscan.co/contract/$JOB_MANAGER"
echo "  • Reputation Manager: https://sepolia.starkscan.co/contract/$REPUTATION_MANAGER"