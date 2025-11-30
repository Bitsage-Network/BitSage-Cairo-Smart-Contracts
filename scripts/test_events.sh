#!/bin/bash

# CIRO Network Event Testing Script
# Generates events across all deployed contracts for indexer testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Contract addresses
CIRO_TOKEN="0x03c0f7574905d7cbc2cca18d6c090265fa35b572d8e9dc62efeb5339908720d8"
TREASURY_TIMELOCK="0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7"

# Accounts
DEPLOYER_ADDR="0x737c361e784a8f58508c211d50e397059590a416c373ed527b9a45287eacfc2"
TEST_ACCOUNT="0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"
ADMIN_ACCOUNT="0x076aa95e263cb7f4ccabf4f6eff1cfdb04bd9d5d37da4484d1ace0cfeb822b8c"

# Keystore
KEYSTORE="../CIRO_Network_Backup/20250711_061352/testnet_keystore.json"
TEST_KEYSTORE="temp_account.json"
NETWORK="sepolia"

echo -e "${BLUE}🎯 CIRO Network Event Testing${NC}"
echo -e "${BLUE}=============================${NC}"
echo ""

# Function to test invoke
test_invoke() {
    local contract=$1
    local function=$2
    local params=$3
    local account=$4
    local keystore=$5
    local description=$6
    
    echo -e "${YELLOW}Testing: $description${NC}"
    echo "Contract: $contract"
    echo "Function: $function $params"
    echo "Account: $account"
    echo ""
    
    if result=$(echo "test" | starkli invoke "$contract" "$function" $params --account "$account" --keystore "$keystore" --network "$NETWORK" 2>&1); then
        echo -e "${GREEN}✅ SUCCESS${NC}"
        echo "Result: $result"
        echo ""
        return 0
    else
        echo -e "${RED}❌ FAILED${NC}"
        echo "Error: $result"
        echo ""
        return 1
    fi
}

echo -e "${BLUE}Phase 1: Deploy Deployer Account${NC}"
echo "The deployer account has tokens but isn't deployed yet."
echo "Let's deploy it first so we can transfer tokens..."
echo ""

# Deploy the deployer account
echo "Deploying deployer account..."
if echo "test" | starkli account deploy ../CIRO_Network_Backup/20250711_061352/internal_docs/testnet_deployer.json --keystore "$KEYSTORE" --network "$NETWORK" 2>&1; then
    echo -e "${GREEN}✅ Deployer account deployed${NC}"
else
    echo -e "${YELLOW}⚠️ Deployer account might already be deployed or deployment failed${NC}"
fi

echo ""
echo -e "${BLUE}Phase 2: CIRO Token Events${NC}"
echo ""

# Test 1: Approve tokens (generates Approval event)
test_invoke "$CIRO_TOKEN" "approve" "$TEST_ACCOUNT 0x3e8" "../CIRO_Network_Backup/20250711_061352/internal_docs/testnet_deployer.json" "$KEYSTORE" "Approve 1000 tokens to test account"

# Test 2: Transfer tokens (generates Transfer event)
test_invoke "$CIRO_TOKEN" "transfer" "$TEST_ACCOUNT 0x64" "../CIRO_Network_Backup/20250711_061352/internal_docs/testnet_deployer.json" "$KEYSTORE" "Transfer 100 tokens to test account"

echo ""
echo -e "${BLUE}Phase 3: Treasury Timelock Events${NC}"
echo ""

# Test 3: Try to propose a transaction (generates ProposalCreated event)
test_invoke "$TREASURY_TIMELOCK" "propose_transaction" "$CIRO_TOKEN 0x0 0x0 0x746573745f70726f706f73616c" "$TEST_KEYSTORE" "$KEYSTORE" "Propose test transaction"

echo ""
echo -e "${BLUE}Event Testing Summary${NC}"
echo -e "${BLUE}====================${NC}"
echo "Event testing completed at: $(date)"
echo ""
echo "Expected events generated:"
echo "1. Approval event (CIRO Token)"
echo "2. Transfer event (CIRO Token)"  
echo "3. ProposalCreated event (Treasury Timelock)"
echo ""
echo "Next: Start indexer to capture these events"
