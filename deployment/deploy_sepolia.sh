#!/bin/bash
# BitSage Network - Sepolia Testnet Deployment Script
# This script deploys all contracts in the correct order

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
RPC_URL="https://rpc.starknet-testnet.lava.build"
NETWORK="sepolia"

# Check for required environment variables
if [ -z "$DEPLOYER_PRIVATE_KEY" ]; then
    echo -e "${RED}Error: DEPLOYER_PRIVATE_KEY not set${NC}"
    echo "Export your private key: export DEPLOYER_PRIVATE_KEY=0x..."
    exit 1
fi

if [ -z "$DEPLOYER_ADDRESS" ]; then
    echo -e "${RED}Error: DEPLOYER_ADDRESS not set${NC}"
    echo "Export your account address: export DEPLOYER_ADDRESS=0x..."
    exit 1
fi

# Output file for deployed addresses
DEPLOYED_ADDRESSES="deployment/deployed_addresses_sepolia.json"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  BitSage Network - Sepolia Deployment ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "RPC: ${YELLOW}$RPC_URL${NC}"
echo -e "Deployer: ${YELLOW}$DEPLOYER_ADDRESS${NC}"
echo ""

# Initialize addresses JSON
echo "{" > $DEPLOYED_ADDRESSES
echo '  "network": "sepolia",' >> $DEPLOYED_ADDRESSES
echo '  "rpc_url": "'$RPC_URL'",' >> $DEPLOYED_ADDRESSES
echo '  "deployer": "'$DEPLOYER_ADDRESS'",' >> $DEPLOYED_ADDRESSES
echo '  "deployed_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",' >> $DEPLOYED_ADDRESSES
echo '  "contracts": {' >> $DEPLOYED_ADDRESSES

# Build contracts first
echo -e "${YELLOW}Building contracts...${NC}"
cd /Users/vaamx/bitsage-network/BitSage-Cairo-Smart-Contracts
scarb build

# Get compiled contract paths
CONTRACTS_DIR="target/dev"

# Function to deploy a contract
deploy_contract() {
    local name=$1
    local class_hash_var=$2
    local constructor_args=$3

    echo -e "${YELLOW}Deploying $name...${NC}"

    # Declare the contract class
    echo "  Declaring class..."
    local declare_output=$(sncast --url $RPC_URL \
        declare \
        --contract-name $name \
        --private-key $DEPLOYER_PRIVATE_KEY \
        --account-address $DEPLOYER_ADDRESS \
        2>&1) || true

    # Extract class hash (handle both new declaration and already declared)
    local class_hash=""
    if echo "$declare_output" | grep -q "class_hash"; then
        class_hash=$(echo "$declare_output" | grep "class_hash" | awk '{print $2}' | tr -d ',')
    elif echo "$declare_output" | grep -q "already declared"; then
        class_hash=$(echo "$declare_output" | grep -oE '0x[a-fA-F0-9]+' | head -1)
    fi

    if [ -z "$class_hash" ]; then
        echo -e "${RED}Failed to get class hash for $name${NC}"
        echo "$declare_output"
        return 1
    fi

    echo "  Class hash: $class_hash"

    # Deploy the contract
    echo "  Deploying instance..."
    local deploy_output=$(sncast --url $RPC_URL \
        deploy \
        --class-hash $class_hash \
        --private-key $DEPLOYER_PRIVATE_KEY \
        --account-address $DEPLOYER_ADDRESS \
        $constructor_args \
        2>&1)

    local contract_address=$(echo "$deploy_output" | grep "contract_address" | awk '{print $2}' | tr -d ',')

    if [ -z "$contract_address" ]; then
        echo -e "${RED}Failed to deploy $name${NC}"
        echo "$deploy_output"
        return 1
    fi

    echo -e "${GREEN}  Deployed at: $contract_address${NC}"

    # Export for use in subsequent deployments
    eval "$class_hash_var=$contract_address"

    # Add to JSON (with comma handling)
    if [ "$name" != "SageToken" ]; then
        echo "," >> $DEPLOYED_ADDRESSES
    fi
    echo '    "'$name'": {' >> $DEPLOYED_ADDRESSES
    echo '      "class_hash": "'$class_hash'",' >> $DEPLOYED_ADDRESSES
    echo '      "address": "'$contract_address'"' >> $DEPLOYED_ADDRESSES
    echo -n '    }' >> $DEPLOYED_ADDRESSES
}

# ============================================
# DEPLOYMENT ORDER (dependencies matter!)
# ============================================

echo -e "\n${BLUE}Step 1/8: Deploying SAGE Token${NC}"
# Constructor: owner
deploy_contract "SageToken" "SAGE_ADDRESS" "--constructor-calldata $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 2/8: Deploying Prover Staking${NC}"
# Constructor: sage_token, owner
deploy_contract "ProverStaking" "STAKING_ADDRESS" "--constructor-calldata $SAGE_ADDRESS $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 3/8: Deploying Reputation Manager${NC}"
# Constructor: owner
deploy_contract "ReputationManager" "REPUTATION_ADDRESS" "--constructor-calldata $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 4/8: Deploying CDC Pool${NC}"
# Constructor: sage_token, staking_contract, owner
deploy_contract "CDCPool" "CDC_POOL_ADDRESS" "--constructor-calldata $SAGE_ADDRESS $STAKING_ADDRESS $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 5/8: Deploying Payment Router${NC}"
# Constructor: sage_token, owner
deploy_contract "PaymentRouter" "PAYMENT_ROUTER_ADDRESS" "--constructor-calldata $SAGE_ADDRESS $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 6/8: Deploying Job Manager${NC}"
# Constructor: sage_token, payment_router, cdc_pool, reputation_manager, owner
deploy_contract "JobManager" "JOB_MANAGER_ADDRESS" "--constructor-calldata $SAGE_ADDRESS $PAYMENT_ROUTER_ADDRESS $CDC_POOL_ADDRESS $REPUTATION_ADDRESS $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 7/8: Deploying Faucet${NC}"
# Constructor: sage_token, owner
deploy_contract "Faucet" "FAUCET_ADDRESS" "--constructor-calldata $SAGE_ADDRESS $DEPLOYER_ADDRESS"

echo -e "\n${BLUE}Step 8/8: Deploying Optimistic TEE${NC}"
# Constructor: staking_contract, owner
deploy_contract "OptimisticTEE" "TEE_ADDRESS" "--constructor-calldata $STAKING_ADDRESS $DEPLOYER_ADDRESS"

# Close JSON
echo "" >> $DEPLOYED_ADDRESSES
echo "  }" >> $DEPLOYED_ADDRESSES
echo "}" >> $DEPLOYED_ADDRESSES

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Deployed addresses saved to: ${YELLOW}$DEPLOYED_ADDRESSES${NC}"
echo ""
echo "Contract Addresses:"
echo "  SAGE Token:      $SAGE_ADDRESS"
echo "  Prover Staking:  $STAKING_ADDRESS"
echo "  Reputation:      $REPUTATION_ADDRESS"
echo "  CDC Pool:        $CDC_POOL_ADDRESS"
echo "  Payment Router:  $PAYMENT_ROUTER_ADDRESS"
echo "  Job Manager:     $JOB_MANAGER_ADDRESS"
echo "  Faucet:          $FAUCET_ADDRESS"
echo "  Optimistic TEE:  $TEE_ADDRESS"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Fund the faucet with SAGE tokens"
echo "2. Configure the prover staking tiers"
echo "3. Update rust-node/src/obelysk/starknet/network.rs with these addresses"
