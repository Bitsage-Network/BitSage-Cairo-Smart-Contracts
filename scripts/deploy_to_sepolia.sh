#!/bin/bash
# Deploy BitSage Cairo Contracts to Starknet Sepolia Testnet

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}  BitSage Starknet Deployment${NC}"
echo -e "${GREEN}  Network: Sepolia Testnet${NC}"
echo -e "${GREEN}=====================================${NC}"

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

if ! command -v scarb &> /dev/null; then
    echo -e "${RED}❌ scarb not found. Install from https://docs.swmansion.com/scarb/${NC}"
    exit 1
fi

if ! command -v starkli &> /dev/null; then
    echo -e "${RED}❌ starkli not found. Install from https://github.com/xJonathanLEI/starkli${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All prerequisites installed${NC}"

# Environment setup
NETWORK="sepolia"
RPC_URL="${STARKNET_RPC_URL:-https://starknet-sepolia.public.blastapi.io/rpc/v0_7}"
ACCOUNT_FILE="${STARKNET_ACCOUNT:-$HOME/.starknet_accounts/deployer.json}"
KEYSTORE_FILE="${STARKNET_KEYSTORE:-$HOME/.starknet_accounts/deployer_keystore.json}"

echo -e "\n${YELLOW}Configuration:${NC}"
echo -e "  RPC URL: ${RPC_URL}"
echo -e "  Account: ${ACCOUNT_FILE}"
echo -e "  Keystore: ${KEYSTORE_FILE}"

# Check if account exists
if [ ! -f "$ACCOUNT_FILE" ]; then
    echo -e "${RED}❌ Account file not found: ${ACCOUNT_FILE}${NC}"
    echo -e "${YELLOW}Create one with: starkli account fetch <ADDRESS> --output ${ACCOUNT_FILE}${NC}"
    exit 1
fi

if [ ! -f "$KEYSTORE_FILE" ]; then
    echo -e "${RED}❌ Keystore file not found: ${KEYSTORE_FILE}${NC}"
    echo -e "${YELLOW}Create one with: starkli signer keystore new ${KEYSTORE_FILE}${NC}"
    exit 1
fi

# Build contracts
echo -e "\n${YELLOW}Building Cairo contracts...${NC}"
cd "$(dirname "$0")/.."
scarb build

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Contract build failed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Contracts built successfully${NC}"

# Create deployment log
DEPLOYMENT_LOG="deployment_$(date +%Y%m%d_%H%M%S).log"
echo "Deployment started at $(date)" > "$DEPLOYMENT_LOG"

# Deploy contracts
echo -e "\n${YELLOW}Deploying contracts to Sepolia...${NC}"

# 1. Deploy JobManager
echo -e "\n${YELLOW}[1/2] Deploying JobManager...${NC}"

JOB_MANAGER_CLASS_HASH=$(starkli declare \
    target/dev/bitsage_JobManager.contract_class.json \
    --rpc "$RPC_URL" \
    --account "$ACCOUNT_FILE" \
    --keystore "$KEYSTORE_FILE" \
    2>&1 | tee -a "$DEPLOYMENT_LOG" | grep -oP 'Class hash declared: \K0x[0-9a-fA-F]+')

if [ -z "$JOB_MANAGER_CLASS_HASH" ]; then
    echo -e "${YELLOW}JobManager already declared or declaration failed. Attempting deployment with existing class hash...${NC}"
    # Try to get existing class hash from previous deployments
    JOB_MANAGER_CLASS_HASH=$(grep "JobManager class hash:" "$DEPLOYMENT_LOG" 2>/dev/null | tail -1 | awk '{print $NF}')
fi

echo -e "${GREEN}JobManager class hash: ${JOB_MANAGER_CLASS_HASH}${NC}"
echo "JobManager class hash: $JOB_MANAGER_CLASS_HASH" >> "$DEPLOYMENT_LOG"

# Deploy JobManager instance
# Constructor parameters: owner_address
OWNER_ADDRESS=$(starkli account address --account "$ACCOUNT_FILE")

echo -e "${YELLOW}Deploying JobManager instance...${NC}"
JOB_MANAGER_ADDRESS=$(starkli deploy \
    "$JOB_MANAGER_CLASS_HASH" \
    "$OWNER_ADDRESS" \
    --rpc "$RPC_URL" \
    --account "$ACCOUNT_FILE" \
    --keystore "$KEYSTORE_FILE" \
    2>&1 | tee -a "$DEPLOYMENT_LOG" | grep -oP 'Contract deployed: \K0x[0-9a-fA-F]+')

echo -e "${GREEN}✅ JobManager deployed at: ${JOB_MANAGER_ADDRESS}${NC}"
echo "JobManager address: $JOB_MANAGER_ADDRESS" >> "$DEPLOYMENT_LOG"

# 2. Deploy ProofVerifier
echo -e "\n${YELLOW}[2/2] Deploying ProofVerifier...${NC}"

PROOF_VERIFIER_CLASS_HASH=$(starkli declare \
    target/dev/bitsage_ProofVerifier.contract_class.json \
    --rpc "$RPC_URL" \
    --account "$ACCOUNT_FILE" \
    --keystore "$KEYSTORE_FILE" \
    2>&1 | tee -a "$DEPLOYMENT_LOG" | grep -oP 'Class hash declared: \K0x[0-9a-fA-F]+')

if [ -z "$PROOF_VERIFIER_CLASS_HASH" ]; then
    echo -e "${YELLOW}ProofVerifier already declared. Using existing class hash...${NC}"
    PROOF_VERIFIER_CLASS_HASH=$(grep "ProofVerifier class hash:" "$DEPLOYMENT_LOG" 2>/dev/null | tail -1 | awk '{print $NF}')
fi

echo -e "${GREEN}ProofVerifier class hash: ${PROOF_VERIFIER_CLASS_HASH}${NC}"
echo "ProofVerifier class hash: $PROOF_VERIFIER_CLASS_HASH" >> "$DEPLOYMENT_LOG"

# Deploy ProofVerifier instance
echo -e "${YELLOW}Deploying ProofVerifier instance...${NC}"
PROOF_VERIFIER_ADDRESS=$(starkli deploy \
    "$PROOF_VERIFIER_CLASS_HASH" \
    "$OWNER_ADDRESS" \
    --rpc "$RPC_URL" \
    --account "$ACCOUNT_FILE" \
    --keystore "$KEYSTORE_FILE" \
    2>&1 | tee -a "$DEPLOYMENT_LOG" | grep -oP 'Contract deployed: \K0x[0-9a-fA-F]+')

echo -e "${GREEN}✅ ProofVerifier deployed at: ${PROOF_VERIFIER_ADDRESS}${NC}"
echo "ProofVerifier address: $PROOF_VERIFIER_ADDRESS" >> "$DEPLOYMENT_LOG"

# Save deployment addresses to JSON
cat > deployed_contracts.json <<EOF
{
  "network": "sepolia",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "contracts": {
    "JobManager": {
      "address": "${JOB_MANAGER_ADDRESS}",
      "class_hash": "${JOB_MANAGER_CLASS_HASH}"
    },
    "ProofVerifier": {
      "address": "${PROOF_VERIFIER_ADDRESS}",
      "class_hash": "${PROOF_VERIFIER_CLASS_HASH}"
    }
  },
  "deployer": "${OWNER_ADDRESS}",
  "rpc_url": "${RPC_URL}"
}
EOF

echo -e "\n${GREEN}=====================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}=====================================${NC}"
echo -e "\n${YELLOW}Deployed Contracts:${NC}"
echo -e "  JobManager:     ${JOB_MANAGER_ADDRESS}"
echo -e "  ProofVerifier:  ${PROOF_VERIFIER_ADDRESS}"
echo -e "\n${YELLOW}Deployment info saved to:${NC}"
echo -e "  deployed_contracts.json"
echo -e "  ${DEPLOYMENT_LOG}"
echo -e "\n${YELLOW}View on Voyager:${NC}"
echo -e "  https://sepolia.voyager.online/contract/${JOB_MANAGER_ADDRESS}"
echo -e "  https://sepolia.voyager.online/contract/${PROOF_VERIFIER_ADDRESS}"

