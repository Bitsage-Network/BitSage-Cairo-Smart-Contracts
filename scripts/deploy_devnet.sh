#!/bin/bash
# BitSage Local Devnet Deployment Script
# Deploys core contracts to starknet-devnet for local testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Devnet configuration
DEVNET_URL="http://localhost:5050"
STARKLI="$HOME/.starkli/bin/starkli"

# Pre-funded devnet account (from seed 0)
DEPLOYER_ADDRESS="0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691"
DEPLOYER_PRIVATE_KEY="0x71d7bb07b9a64f6f78ac4c816aff4da9"

# Contract artifacts directory
CONTRACTS_DIR="$(dirname "$0")/../target/dev"
OUTPUT_FILE="$(dirname "$0")/../deployment/deployed_addresses_devnet.json"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  BitSage Devnet Deployment Script${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check devnet is running
echo -e "${YELLOW}Checking devnet status...${NC}"
if ! curl -s "$DEVNET_URL/is_alive" > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Devnet is not running on $DEVNET_URL${NC}"
    echo "Start it with: starknet-devnet --seed 0 --accounts 3 --port 5050"
    exit 1
fi
echo -e "${GREEN}Devnet is alive!${NC}"
echo ""

# Create keystore file for starkli
KEYSTORE_DIR="$HOME/.starkli-wallets/devnet"
mkdir -p "$KEYSTORE_DIR"

# Create account file
cat > "$KEYSTORE_DIR/account.json" << EOF
{
  "version": 1,
  "variant": {
    "type": "open_zeppelin",
    "version": 1,
    "public_key": "0x039d9e6ce352ad4530a0ef5d5a18fd3303c3606a7fa6ac5b620020ad681cc33b"
  },
  "deployment": {
    "status": "deployed",
    "class_hash": "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564",
    "address": "$DEPLOYER_ADDRESS"
  }
}
EOF

# Create keystore (unencrypted for devnet)
cat > "$KEYSTORE_DIR/keystore.json" << EOF
{
  "crypto": {
    "cipher": "plain",
    "ciphertext": "$DEPLOYER_PRIVATE_KEY"
  },
  "version": 1
}
EOF

echo -e "${YELLOW}Deployer: $DEPLOYER_ADDRESS${NC}"
echo ""

# Function to declare a contract and return class hash
declare_contract() {
    local contract_name=$1
    local contract_file="$CONTRACTS_DIR/sage_contracts_${contract_name}.contract_class.json"

    if [ ! -f "$contract_file" ]; then
        echo -e "${RED}Contract file not found: $contract_file${NC}"
        return 1
    fi

    echo -e "${YELLOW}Declaring $contract_name...${NC}"

    # Declare the contract
    local result=$($STARKLI declare "$contract_file" \
        --rpc "$DEVNET_URL" \
        --private-key "$DEPLOYER_PRIVATE_KEY" \
        --account "$KEYSTORE_DIR/account.json" \
        --watch 2>&1)

    # Extract class hash from output
    local class_hash=$(echo "$result" | grep -oE '0x[0-9a-fA-F]+' | head -1)
    echo -e "${GREEN}Class hash: $class_hash${NC}"
    echo "$class_hash"
}

# Function to deploy a contract
deploy_contract() {
    local class_hash=$1
    shift
    local constructor_args=("$@")

    echo -e "${YELLOW}Deploying contract...${NC}"

    local result=$($STARKLI deploy "$class_hash" "${constructor_args[@]}" \
        --rpc "$DEVNET_URL" \
        --private-key "$DEPLOYER_PRIVATE_KEY" \
        --account "$KEYSTORE_DIR/account.json" \
        --watch 2>&1)

    # Extract contract address from output
    local contract_address=$(echo "$result" | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    echo -e "${GREEN}Contract address: $contract_address${NC}"
    echo "$contract_address"
}

# Initialize output JSON
echo "{" > "$OUTPUT_FILE"
echo '  "network": "devnet",' >> "$OUTPUT_FILE"
echo '  "rpc_url": "http://localhost:5050",' >> "$OUTPUT_FILE"
echo "  \"deployer\": \"$DEPLOYER_ADDRESS\"," >> "$OUTPUT_FILE"
echo '  "deployed_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",' >> "$OUTPUT_FILE"
echo '  "contracts": {' >> "$OUTPUT_FILE"

# ============================================
# DEPLOY CONTRACTS
# ============================================

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deploying Core Contracts${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 1. SAGEToken
echo -e "${GREEN}[1/5] SAGEToken${NC}"
SAGE_CLASS=$(declare_contract "SAGEToken")
# Constructor: owner, initial_supply_low, initial_supply_high
SAGE_ADDRESS=$(deploy_contract "$SAGE_CLASS" "$DEPLOYER_ADDRESS" "u256:1000000000000000000000000000")
echo "    \"SAGEToken\": {\"class_hash\": \"$SAGE_CLASS\", \"address\": \"$SAGE_ADDRESS\"}," >> "$OUTPUT_FILE"
echo ""

# 2. ProverStaking
echo -e "${GREEN}[2/5] ProverStaking${NC}"
STAKING_CLASS=$(declare_contract "ProverStaking")
# Constructor: owner, sage_token, min_stake_low, min_stake_high
STAKING_ADDRESS=$(deploy_contract "$STAKING_CLASS" "$DEPLOYER_ADDRESS" "$SAGE_ADDRESS" "u256:1000000000000000000000")
echo "    \"ProverStaking\": {\"class_hash\": \"$STAKING_CLASS\", \"address\": \"$STAKING_ADDRESS\"}," >> "$OUTPUT_FILE"
echo ""

# 3. Faucet
echo -e "${GREEN}[3/5] Faucet${NC}"
FAUCET_CLASS=$(declare_contract "Faucet")
# Constructor: owner, sage_token
FAUCET_ADDRESS=$(deploy_contract "$FAUCET_CLASS" "$DEPLOYER_ADDRESS" "$SAGE_ADDRESS")
echo "    \"Faucet\": {\"class_hash\": \"$FAUCET_CLASS\", \"address\": \"$FAUCET_ADDRESS\"}," >> "$OUTPUT_FILE"
echo ""

# 4. ValidatorRegistry
echo -e "${GREEN}[4/5] ValidatorRegistry${NC}"
VALIDATOR_CLASS=$(declare_contract "ValidatorRegistry")
# Constructor: owner, staking_contract
VALIDATOR_ADDRESS=$(deploy_contract "$VALIDATOR_CLASS" "$DEPLOYER_ADDRESS" "$STAKING_ADDRESS")
echo "    \"ValidatorRegistry\": {\"class_hash\": \"$VALIDATOR_CLASS\", \"address\": \"$VALIDATOR_ADDRESS\"}," >> "$OUTPUT_FILE"
echo ""

# 5. JobManager
echo -e "${GREEN}[5/5] JobManager${NC}"
JOB_CLASS=$(declare_contract "JobManager")
# Constructor: owner, cdc_pool (use deployer as placeholder), reputation_manager (placeholder)
JOB_ADDRESS=$(deploy_contract "$JOB_CLASS" "$DEPLOYER_ADDRESS" "$DEPLOYER_ADDRESS" "$DEPLOYER_ADDRESS")
echo "    \"JobManager\": {\"class_hash\": \"$JOB_CLASS\", \"address\": \"$JOB_ADDRESS\"}" >> "$OUTPUT_FILE"
echo ""

# Close JSON
echo '  }' >> "$OUTPUT_FILE"
echo '}' >> "$OUTPUT_FILE"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Addresses saved to: ${YELLOW}$OUTPUT_FILE${NC}"
echo ""
echo -e "${GREEN}Contract Addresses:${NC}"
echo -e "  SAGEToken:         $SAGE_ADDRESS"
echo -e "  ProverStaking:     $STAKING_ADDRESS"
echo -e "  Faucet:            $FAUCET_ADDRESS"
echo -e "  ValidatorRegistry: $VALIDATOR_ADDRESS"
echo -e "  JobManager:        $JOB_ADDRESS"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Fund faucet: starkli invoke $SAGE_ADDRESS transfer $FAUCET_ADDRESS u256:100000000000000000000000 --rpc $DEVNET_URL"
echo "  2. Update dashboard to use devnet addresses"
echo "  3. Connect wallet and test!"
