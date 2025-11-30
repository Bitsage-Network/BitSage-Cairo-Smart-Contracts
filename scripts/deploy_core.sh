#!/bin/bash

# CIRO Network - Core System Deployment Script
# Deploys the essential contracts needed for basic network operation
# Based on successful Reputation Manager deployment pattern

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_FILE="$PROJECT_ROOT/core_deployment_$(date +%Y%m%d_%H%M%S).json"

# Default values - can be overridden by environment variables
NETWORK=${NETWORK:-"sepolia"}
ACCOUNT_CONFIG=${ACCOUNT_CONFIG:-"temp_account.json"}
KEYSTORE_PATH=${KEYSTORE_PATH:-"../CIRO_Network_Backup/20250711_061352/testnet_keystore.json"}
KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD:-"test"}
DRY_RUN=${DRY_RUN:-false}

print_header() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}  CIRO Network - Core Deployment${NC}"
    echo -e "${BLUE}  $(date)${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}📋 $1${NC}"
    echo ""
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

declare_contract() {
    local contract_name="$1"
    local contract_file="$2"
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would declare $contract_name"
        echo "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        return
    fi
    
    print_info "Declaring $contract_name..."
    
    if [ ! -f "$contract_file" ]; then
        print_error "$contract_name contract class not found: $contract_file"
        exit 1
    fi
    
    local class_hash
    if class_hash=$(echo "$KEYSTORE_PASSWORD" | starkli declare "$contract_file" \
        --account "$ACCOUNT_CONFIG" \
        --keystore "$KEYSTORE_PATH" \
        --network "$NETWORK" 2>&1 | grep "Class hash declared:" | awk '{print $4}'); then
        
        if [ -n "$class_hash" ]; then
            print_success "$contract_name declared: $class_hash"
            echo "$class_hash"
        else
            print_error "Failed to extract class hash for $contract_name"
            exit 1
        fi
    else
        print_error "Failed to declare $contract_name"
        exit 1
    fi
}

deploy_contract() {
    local contract_name="$1"
    local class_hash="$2"
    shift 2
    local constructor_args=("$@")
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would deploy $contract_name"
        echo "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        return
    fi
    
    print_info "Deploying $contract_name..."
    
    # Build the command
    local cmd="echo \"$KEYSTORE_PASSWORD\" | starkli deploy \"$class_hash\" --account \"$ACCOUNT_CONFIG\" --keystore \"$KEYSTORE_PATH\" --network \"$NETWORK\""
    
    # Add constructor arguments
    for arg in "${constructor_args[@]}"; do
        cmd="$cmd \"$arg\""
    done
    
    local contract_address
    if contract_address=$(eval $cmd 2>&1 | grep "Contract deployed:" | awk '{print $3}'); then
        
        if [ -n "$contract_address" ]; then
            print_success "$contract_name deployed: $contract_address"
            echo "$contract_address"
        else
            print_error "Failed to extract contract address for $contract_name"
            exit 1
        fi
    else
        print_error "Failed to deploy $contract_name"
        exit 1
    fi
}

main() {
    print_header
    
    if [ "$DRY_RUN" = true ]; then
        print_info "🧪 Running in DRY RUN mode"
        echo ""
    fi
    
    print_step "Building Contracts"
    scarb build
    print_success "Build completed"
    echo ""
    
    local target_dir="$PROJECT_ROOT/target/dev"
    
    print_step "Deploying Core CIRO Network Contracts"
    
    # Get deployer address
    DEPLOYER_ADDRESS="0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"
    
    # 1. Deploy CIRO Token
    print_info "Step 1/4: CIRO Token"
    CIRO_TOKEN_CLASS=$(declare_contract "CIRO Token" "$target_dir/ciro_contracts_CIROToken.contract_class.json")
    CIRO_TOKEN_ADDRESS=$(deploy_contract "CIRO Token" "$CIRO_TOKEN_CLASS" "$DEPLOYER_ADDRESS")
    echo ""
    
    # 2. Deploy Governance Treasury
    print_info "Step 2/4: Governance Treasury" 
    GOVERNANCE_TREASURY_CLASS=$(declare_contract "Governance Treasury" "$target_dir/ciro_contracts_GovernanceTreasury.contract_class.json")
    GOVERNANCE_TREASURY_ADDRESS=$(deploy_contract "Governance Treasury" "$GOVERNANCE_TREASURY_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS")
    echo ""
    
    # 3. Deploy Job Manager
    print_info "Step 3/4: Job Manager"
    JOB_MANAGER_CLASS=$(declare_contract "Job Manager" "$target_dir/ciro_contracts_JobManager.contract_class.json")
    JOB_MANAGER_ADDRESS=$(deploy_contract "Job Manager" "$JOB_MANAGER_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$GOVERNANCE_TREASURY_ADDRESS" "0x0")
    echo ""
    
    # 4. Deploy CDC Pool
    print_info "Step 4/4: CDC Pool"
    CDC_POOL_CLASS=$(declare_contract "CDC Pool" "$target_dir/ciro_contracts_CDCPool.contract_class.json")
    CDC_POOL_ADDRESS=$(deploy_contract "CDC Pool" "$CDC_POOL_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$JOB_MANAGER_ADDRESS")
    echo ""
    
    print_step "Deployment Summary"
    echo -e "${GREEN}🎉 Core contracts deployed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Contract Addresses:${NC}"
    echo -e "   CIRO Token:         ${BLUE}$CIRO_TOKEN_ADDRESS${NC}"
    echo -e "   Governance Treasury:${BLUE}$GOVERNANCE_TREASURY_ADDRESS${NC}"
    echo -e "   Job Manager:        ${BLUE}$JOB_MANAGER_ADDRESS${NC}"
    echo -e "   CDC Pool:           ${BLUE}$CDC_POOL_ADDRESS${NC}"
    echo ""
    
    # Save deployment info
    cat > "$DEPLOYMENT_FILE" << EOF
{
  "network": "$NETWORK",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "deployer": "$DEPLOYER_ADDRESS",
  "core_contracts": {
    "ciro_token": {
      "address": "$CIRO_TOKEN_ADDRESS",
      "class_hash": "$CIRO_TOKEN_CLASS"
    },
    "governance_treasury": {
      "address": "$GOVERNANCE_TREASURY_ADDRESS", 
      "class_hash": "$GOVERNANCE_TREASURY_CLASS"
    },
    "job_manager": {
      "address": "$JOB_MANAGER_ADDRESS",
      "class_hash": "$JOB_MANAGER_CLASS"
    },
    "cdc_pool": {
      "address": "$CDC_POOL_ADDRESS",
      "class_hash": "$CDC_POOL_CLASS"
    }
  }
}
EOF
    
    print_success "Deployment info saved to: $DEPLOYMENT_FILE"
    echo ""
    print_info "Next: Deploy Reputation Manager with CDC Pool address: $CDC_POOL_ADDRESS"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --network)
            NETWORK="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

main "$@"