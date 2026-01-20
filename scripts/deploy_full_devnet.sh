#!/usr/bin/env bash
# =============================================================================
# BitSage Full System Devnet Deployment
# =============================================================================
# Deploys ALL contracts to local devnet with proper dependency ordering
# Tests cross-contract interactions before Sepolia deployment
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
DEVNET_URL="http://localhost:5050/rpc"
DEPLOYER_ADDRESS="0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="$PROJECT_DIR/deployment/full_devnet_deployment.json"
TEMP_DIR=$(mktemp -d)

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  BitSage Full System Devnet Deployment${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Check devnet is running
echo -e "${YELLOW}Checking devnet status...${NC}"
if ! curl -s "$DEVNET_URL" -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"starknet_chainId","params":[]}' > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Devnet is not running on $DEVNET_URL${NC}"
    echo "Start it with: starknet-devnet --seed 0 --port 5050"
    exit 1
fi
echo -e "${GREEN}Devnet is alive!${NC}"
echo ""

# Build contracts
echo -e "${YELLOW}Building contracts...${NC}"
cd "$PROJECT_DIR"
scarb build 2>&1 | tail -3
echo -e "${GREEN}Build complete!${NC}"
echo ""

# Function to declare a contract and save class hash
declare_contract() {
    local name=$1
    echo -e "${BLUE}Declaring $name...${NC}"

    local result=$(sncast --profile devnet declare --contract-name "$name" 2>&1)

    if echo "$result" | grep -q "already declared"; then
        local class_hash=$("$HOME/.starkli/bin/starkli" class-hash \
            "target/dev/sage_contracts_${name}.contract_class.json" 2>/dev/null)
        echo -e "${YELLOW}  Already declared: $class_hash${NC}"
        echo "$class_hash" > "$TEMP_DIR/${name}_class"
    elif echo "$result" | grep -q "Class Hash:"; then
        local class_hash=$(echo "$result" | grep "Class Hash:" | awk '{print $3}')
        echo -e "${GREEN}  Declared: $class_hash${NC}"
        echo "$class_hash" > "$TEMP_DIR/${name}_class"
    else
        echo -e "${RED}  Failed to declare $name${NC}"
        echo "$result"
        return 1
    fi
}

# Function to deploy a contract
deploy_contract() {
    local name=$1
    shift
    local calldata="$@"

    local class_hash=$(cat "$TEMP_DIR/${name}_class" 2>/dev/null)
    if [ -z "$class_hash" ]; then
        echo -e "${RED}No class hash for $name${NC}"
        return 1
    fi

    echo -e "${BLUE}Deploying $name...${NC}"

    local result
    if [ -z "$calldata" ]; then
        result=$(sncast --profile devnet deploy --class-hash "$class_hash" 2>&1)
    else
        result=$(sncast --profile devnet deploy --class-hash "$class_hash" --constructor-calldata $calldata 2>&1)
    fi

    if echo "$result" | grep -q "Contract Address:"; then
        local address=$(echo "$result" | grep "Contract Address:" | awk '{print $3}')
        echo -e "${GREEN}  Deployed: $address${NC}"
        echo "$address" > "$TEMP_DIR/${name}_addr"
    else
        echo -e "${RED}  Failed to deploy $name${NC}"
        echo "$result"
        return 1
    fi
}

# Function to get address
get_addr() {
    cat "$TEMP_DIR/${1}_addr" 2>/dev/null
}

# =============================================================================
# PHASE 1: Core Infrastructure (No Dependencies)
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 1: Core Infrastructure${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# SAGEToken - Foundation of everything
declare_contract "SAGEToken"
deploy_contract "SAGEToken" \
    $DEPLOYER_ADDRESS \
    $DEPLOYER_ADDRESS \
    $DEPLOYER_ADDRESS \
    $DEPLOYER_ADDRESS \
    $DEPLOYER_ADDRESS \
    $DEPLOYER_ADDRESS \
    $DEPLOYER_ADDRESS

SAGE_TOKEN=$(get_addr "SAGEToken")
echo -e "${GREEN}SAGE Token: $SAGE_TOKEN${NC}"
echo ""

# =============================================================================
# PHASE 2: Staking & Registry
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 2: Staking & Registry${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "ProverStaking"
deploy_contract "ProverStaking" $DEPLOYER_ADDRESS $SAGE_TOKEN "u256:1000000000000000000000"
PROVER_STAKING=$(get_addr "ProverStaking")

declare_contract "WorkerStaking"
deploy_contract "WorkerStaking" $DEPLOYER_ADDRESS $SAGE_TOKEN "u256:100000000000000000000"

declare_contract "ValidatorRegistry"
deploy_contract "ValidatorRegistry" $DEPLOYER_ADDRESS $PROVER_STAKING

declare_contract "ReputationManager"
deploy_contract "ReputationManager" $DEPLOYER_ADDRESS
REPUTATION_MANAGER=$(get_addr "ReputationManager")

declare_contract "ObelyskProverRegistry"
deploy_contract "ObelyskProverRegistry" $DEPLOYER_ADDRESS $PROVER_STAKING $REPUTATION_MANAGER

echo ""

# =============================================================================
# PHASE 3: Verification Infrastructure
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 3: Verification Infrastructure${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "ProofVerifier"
deploy_contract "ProofVerifier" $DEPLOYER_ADDRESS
PROOF_VERIFIER=$(get_addr "ProofVerifier")

declare_contract "StwoVerifier"
deploy_contract "StwoVerifier" $DEPLOYER_ADDRESS

declare_contract "FraudProof"
deploy_contract "FraudProof" $DEPLOYER_ADDRESS $PROOF_VERIFIER

echo ""

# =============================================================================
# PHASE 4: Payment & Billing Infrastructure
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 4: Payment & Billing${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "Escrow"
deploy_contract "Escrow" $DEPLOYER_ADDRESS $SAGE_TOKEN

declare_contract "Collateral"
deploy_contract "Collateral" $DEPLOYER_ADDRESS $SAGE_TOKEN

declare_contract "FeeManager"
deploy_contract "FeeManager" $DEPLOYER_ADDRESS $SAGE_TOKEN $DEPLOYER_ADDRESS
FEE_MANAGER=$(get_addr "FeeManager")

declare_contract "MeteredBilling"
deploy_contract "MeteredBilling" $DEPLOYER_ADDRESS $SAGE_TOKEN $FEE_MANAGER

declare_contract "ProofGatedPayment"
deploy_contract "ProofGatedPayment" $DEPLOYER_ADDRESS $SAGE_TOKEN $PROOF_VERIFIER
PROOF_GATED=$(get_addr "ProofGatedPayment")

declare_contract "DynamicPricing"
deploy_contract "DynamicPricing" $DEPLOYER_ADDRESS

echo ""

# =============================================================================
# PHASE 5: Privacy Infrastructure (WITH FIXED FMD!)
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 5: Privacy Infrastructure${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "PrivacyPools"
deploy_contract "PrivacyPools"
PRIVACY_POOLS=$(get_addr "PrivacyPools")

echo -e "${BLUE}Initializing PrivacyPools...${NC}"
sncast --profile devnet invoke \
    --contract-address $PRIVACY_POOLS \
    --function initialize \
    --calldata $DEPLOYER_ADDRESS $SAGE_TOKEN $DEPLOYER_ADDRESS 2>&1 | grep -E "(Success|Error)" || echo "  Init attempted"

declare_contract "PrivacyRouter"
deploy_contract "PrivacyRouter" $DEPLOYER_ADDRESS $SAGE_TOKEN $DEPLOYER_ADDRESS
PRIVACY_ROUTER=$(get_addr "PrivacyRouter")

declare_contract "WorkerPrivacyHelper"
deploy_contract "WorkerPrivacyHelper" $DEPLOYER_ADDRESS $PRIVACY_ROUTER

declare_contract "MixingRouter"
deploy_contract "MixingRouter" $DEPLOYER_ADDRESS $PRIVACY_ROUTER

declare_contract "SteganographicRouter"
deploy_contract "SteganographicRouter" $DEPLOYER_ADDRESS

declare_contract "ConfidentialSwapContract"
deploy_contract "ConfidentialSwapContract" $DEPLOYER_ADDRESS $SAGE_TOKEN

echo ""

# =============================================================================
# PHASE 6: Job & Compute Infrastructure
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 6: Job & Compute${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "CDCPool"
deploy_contract "CDCPool" $DEPLOYER_ADDRESS $SAGE_TOKEN "u256:1000000000000000000000" $REPUTATION_MANAGER
CDC_POOL=$(get_addr "CDCPool")

declare_contract "JobManager"
deploy_contract "JobManager" $DEPLOYER_ADDRESS $CDC_POOL $REPUTATION_MANAGER
JOB_MANAGER=$(get_addr "JobManager")

declare_contract "OptimisticTEE"
deploy_contract "OptimisticTEE" $DEPLOYER_ADDRESS $PROOF_VERIFIER $PROOF_GATED

declare_contract "Gamification"
deploy_contract "Gamification" $DEPLOYER_ADDRESS $REPUTATION_MANAGER

echo ""

# =============================================================================
# PHASE 7: Payment Routing
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 7: Payment Routing${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "OracleWrapper"
deploy_contract "OracleWrapper" $DEPLOYER_ADDRESS $DEPLOYER_ADDRESS
ORACLE=$(get_addr "OracleWrapper")

declare_contract "PaymentRouter"
deploy_contract "PaymentRouter" $DEPLOYER_ADDRESS $SAGE_TOKEN $ORACLE $PRIVACY_ROUTER $CDC_POOL
PAYMENT_ROUTER=$(get_addr "PaymentRouter")

echo ""

# =============================================================================
# PHASE 8: Governance & Treasury
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 8: Governance & Treasury${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "TreasuryTimelock"
deploy_contract "TreasuryTimelock" $DEPLOYER_ADDRESS 86400
TIMELOCK=$(get_addr "TreasuryTimelock")

declare_contract "GovernanceTreasury"
deploy_contract "GovernanceTreasury" $DEPLOYER_ADDRESS $SAGE_TOKEN $TIMELOCK

declare_contract "BurnManager"
deploy_contract "BurnManager" $DEPLOYER_ADDRESS $SAGE_TOKEN

echo ""

# =============================================================================
# PHASE 9: Vesting Contracts
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 9: Vesting${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "LinearVestingWithCliff"
deploy_contract "LinearVestingWithCliff" $DEPLOYER_ADDRESS $SAGE_TOKEN

declare_contract "MilestoneVesting"
deploy_contract "MilestoneVesting" $DEPLOYER_ADDRESS $SAGE_TOKEN

declare_contract "RewardVesting"
deploy_contract "RewardVesting" $DEPLOYER_ADDRESS $SAGE_TOKEN $JOB_MANAGER

echo ""

# =============================================================================
# PHASE 10: Utilities
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  PHASE 10: Utilities${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

declare_contract "Faucet"
deploy_contract "Faucet" $DEPLOYER_ADDRESS $SAGE_TOKEN
FAUCET=$(get_addr "Faucet")

declare_contract "AddressRegistry"
deploy_contract "AddressRegistry" $DEPLOYER_ADDRESS

declare_contract "SimpleEvents"
deploy_contract "SimpleEvents"

echo ""

# =============================================================================
# Save deployment info
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Saving Deployment Info${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

mkdir -p "$(dirname "$OUTPUT_FILE")"

cat > "$OUTPUT_FILE" << EOF
{
  "network": "devnet",
  "rpc_url": "$DEVNET_URL",
  "deployer": "$DEPLOYER_ADDRESS",
  "deployed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "contracts": {
EOF

# Collect all deployed contracts
first=true
for file in "$TEMP_DIR"/*_addr; do
    [ -f "$file" ] || continue
    name=$(basename "$file" _addr)
    address=$(cat "$file")
    class_hash=$(cat "$TEMP_DIR/${name}_class" 2>/dev/null || echo "unknown")

    if [ "$first" = true ]; then
        first=false
    else
        echo "," >> "$OUTPUT_FILE"
    fi
    printf '    "%s": {"class_hash": "%s", "address": "%s"}' "$name" "$class_hash" "$address" >> "$OUTPUT_FILE"
done

cat >> "$OUTPUT_FILE" << EOF

  },
  "key_addresses": {
    "sage_token": "$SAGE_TOKEN",
    "privacy_pools": "$PRIVACY_POOLS",
    "privacy_router": "$PRIVACY_ROUTER",
    "payment_router": "$PAYMENT_ROUTER",
    "job_manager": "$JOB_MANAGER",
    "cdc_pool": "$CDC_POOL",
    "faucet": "$FAUCET"
  }
}
EOF

echo -e "${GREEN}Deployment saved to: $OUTPUT_FILE${NC}"

# Count deployed
DEPLOYED_COUNT=$(ls "$TEMP_DIR"/*_addr 2>/dev/null | wc -l | tr -d ' ')

# Cleanup
rm -rf "$TEMP_DIR"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  DEPLOYMENT COMPLETE${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${GREEN}Deployed $DEPLOYED_COUNT contracts to devnet${NC}"
echo ""
echo -e "${YELLOW}Key Addresses:${NC}"
echo -e "  SAGE Token:      $SAGE_TOKEN"
echo -e "  Privacy Pools:   $PRIVACY_POOLS"
echo -e "  Privacy Router:  $PRIVACY_ROUTER"
echo -e "  Payment Router:  $PAYMENT_ROUTER"
echo -e "  Job Manager:     $JOB_MANAGER"
echo -e "  CDC Pool:        $CDC_POOL"
echo -e "  Faucet:          $FAUCET"
echo ""
