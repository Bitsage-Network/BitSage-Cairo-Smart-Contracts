#!/bin/bash

# CIRO Network - Complete System Deployment Script
# Deploys all core contracts in correct order with proper dependencies
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
DEPLOYMENT_FILE="$PROJECT_ROOT/deployment_$(date +%Y%m%d_%H%M%S).json"
LOG_FILE="$PROJECT_ROOT/deployment_$(date +%Y%m%d_%H%M%S).log"

# Default values - can be overridden by environment variables
NETWORK=${NETWORK:-"sepolia"}
ACCOUNT_CONFIG=${ACCOUNT_CONFIG:-"temp_account.json"}
KEYSTORE_PATH=${KEYSTORE_PATH:-"../CIRO_Network_Backup/20250711_061352/testnet_keystore.json"}
DRY_RUN=${DRY_RUN:-false}

# Logging function
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}  CIRO Network - Complete System Deployment${NC}"
    echo -e "${BLUE}  $(date)${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo ""
    log "Starting CIRO Network deployment"
}

print_step() {
    echo -e "${GREEN}📋 Step $1: $2${NC}"
    log "STEP $1: $2"
    echo ""
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
    log "INFO: $1"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
    log "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
    log "ERROR: $1"
}

check_prerequisites() {
    print_step "1" "Checking Prerequisites"
    
    # Check if required tools are installed
    if ! command -v scarb &> /dev/null; then
        print_error "Scarb is not installed. Please install it first."
        exit 1
    fi
    
    if ! command -v starkli &> /dev/null; then
        print_error "Starkli is not installed. Please install it first."
        exit 1
    fi
    
    # Check if account config exists
    if [ ! -f "$ACCOUNT_CONFIG" ]; then
        print_error "Account config not found: $ACCOUNT_CONFIG"
        print_info "Please create an account config or update ACCOUNT_CONFIG variable"
        exit 1
    fi
    
    # Check if keystore exists
    if [ ! -f "$KEYSTORE_PATH" ]; then
        print_error "Keystore not found: $KEYSTORE_PATH"
        print_info "Please update KEYSTORE_PATH variable"
        exit 1
    fi
    
    print_success "All prerequisites check passed!"
    print_info "Network: $NETWORK"
    print_info "Account: $ACCOUNT_CONFIG"
    print_info "Keystore: $KEYSTORE_PATH"
    echo ""
}

build_contracts() {
    print_step "2" "Building Contracts"
    
    cd "$PROJECT_ROOT"
    
    print_info "Cleaning previous build..."
    scarb clean
    
    print_info "Building contracts..."
    if scarb build; then
        print_success "Contracts built successfully!"
    else
        print_error "Contract build failed!"
        exit 1
    fi
    
    echo ""
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
    if class_hash=$(echo "test" | starkli declare "$contract_file" \
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
        print_info "DRY RUN: Would deploy $contract_name with class hash $class_hash"
        echo "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        return
    fi
    
    print_info "Deploying $contract_name..."
    
    local deploy_cmd="echo \"test\" | starkli deploy \"$class_hash\" --account \"$ACCOUNT_CONFIG\" --keystore \"$KEYSTORE_PATH\" --network \"$NETWORK\""
    
    # Add constructor arguments
    for arg in "${constructor_args[@]}"; do
        deploy_cmd="$deploy_cmd \"$arg\""
    done
    
    local contract_address
    if contract_address=$(eval $deploy_cmd 2>&1 | grep "Contract deployed:" | awk '{print $3}'); then
        
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

deploy_core_contracts() {
    print_step "3" "Declaring Contract Implementations"
    
    local target_dir="$PROJECT_ROOT/target/dev"
    
    # Declare CIRO Token
    CIRO_TOKEN_CLASS=$(declare_contract "CIRO Token" "$target_dir/ciro_contracts_CIROToken.contract_class.json")
    
    # Declare Job Manager
    JOB_MANAGER_CLASS=$(declare_contract "Job Manager" "$target_dir/ciro_contracts_JobManager.contract_class.json")
    
    # Declare CDC Pool
    CDC_POOL_CLASS=$(declare_contract "CDC Pool" "$target_dir/ciro_contracts_CDCPool.contract_class.json")
    
    # Declare Reputation Manager
    REPUTATION_MANAGER_CLASS=$(declare_contract "Reputation Manager" "$target_dir/ciro_contracts_ReputationManager.contract_class.json")
    
    # Declare Governance Treasury
    GOVERNANCE_TREASURY_CLASS=$(declare_contract "Governance Treasury" "$target_dir/ciro_contracts_GovernanceTreasury.contract_class.json")
    
    # Declare Treasury Timelock
    TREASURY_TIMELOCK_CLASS=$(declare_contract "Treasury Timelock" "$target_dir/ciro_contracts_TreasuryTimelock.contract_class.json")
    
    # Declare Vesting Contracts
    LINEAR_VESTING_CLASS=$(declare_contract "Linear Vesting" "$target_dir/ciro_contracts_LinearVestingWithCliff.contract_class.json")
    MILESTONE_VESTING_CLASS=$(declare_contract "Milestone Vesting" "$target_dir/ciro_contracts_MilestoneVesting.contract_class.json")
    BURN_MANAGER_CLASS=$(declare_contract "Burn Manager" "$target_dir/ciro_contracts_BurnManager.contract_class.json")
    
    echo ""
}

deploy_contract_instances() {
    print_step "4" "Deploying Contract Instances"
    
    # Get deployer address
    DEPLOYER_ADDRESS=$(echo "test" | starkli account address --account "$ACCOUNT_CONFIG" --keystore "$KEYSTORE_PATH" 2>/dev/null || echo "0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca")
    
    # Deploy CIRO Token (constructor: admin)
    print_info "Deploying CIRO Token instance..."
    CIRO_TOKEN_ADDRESS=$(deploy_contract "CIRO Token" "$CIRO_TOKEN_CLASS" "$DEPLOYER_ADDRESS")
    
    # Deploy Governance Treasury (constructor: admin, token)
    print_info "Deploying Governance Treasury instance..."
    GOVERNANCE_TREASURY_ADDRESS=$(deploy_contract "Governance Treasury" "$GOVERNANCE_TREASURY_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS")
    
    # Note: Treasury Timelock requires Array parameters which are complex for shell scripts
    # It will need to be deployed manually or with a custom deployment script
    print_info "Treasury Timelock (class: $TREASURY_TIMELOCK_CLASS) - requires manual deployment with Array parameters"
    
    # Deploy Job Manager (constructor: admin, payment_token, treasury, cdc_pool)
    # We'll use a placeholder for CDC Pool and update later
    print_info "Deploying Job Manager instance..."
    JOB_MANAGER_ADDRESS=$(deploy_contract "Job Manager" "$JOB_MANAGER_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$GOVERNANCE_TREASURY_ADDRESS" "0x0")
    
    # Deploy CDC Pool (constructor: admin, token, job_manager)
    print_info "Deploying CDC Pool instance..."
    CDC_POOL_ADDRESS=$(deploy_contract "CDC Pool" "$CDC_POOL_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$JOB_MANAGER_ADDRESS")
    
    # Deploy Reputation Manager (constructor: admin, cdc_pool, job_manager, update_rate_limit)
    print_info "Deploying Reputation Manager instance..."
    REPUTATION_MANAGER_ADDRESS=$(deploy_contract "Reputation Manager" "$REPUTATION_MANAGER_CLASS" "$DEPLOYER_ADDRESS" "$CDC_POOL_ADDRESS" "$JOB_MANAGER_ADDRESS" "300")
    
    # Deploy Linear Vesting (constructor: admin, token, governance)
    print_info "Deploying Linear Vesting instance..."
    LINEAR_VESTING_ADDRESS=$(deploy_contract "Linear Vesting" "$LINEAR_VESTING_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$GOVERNANCE_TREASURY_ADDRESS")
    
    # Deploy Milestone Vesting (constructor: admin, token, governance)
    print_info "Deploying Milestone Vesting instance..."
    MILESTONE_VESTING_ADDRESS=$(deploy_contract "Milestone Vesting" "$MILESTONE_VESTING_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$GOVERNANCE_TREASURY_ADDRESS")
    
    # Deploy Burn Manager (constructor: admin, token, treasury)
    print_info "Deploying Burn Manager instance..."
    BURN_MANAGER_ADDRESS=$(deploy_contract "Burn Manager" "$BURN_MANAGER_CLASS" "$DEPLOYER_ADDRESS" "$CIRO_TOKEN_ADDRESS" "$GOVERNANCE_TREASURY_ADDRESS")
    
    echo ""
}

verify_deployment() {
    print_step "5" "Verifying Deployment"
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would verify deployment"
        return
    fi
    
    print_info "Verifying contract deployments..."
    
    # Check if all addresses were generated
    local contracts=(
        "CIRO_TOKEN_ADDRESS"
        "JOB_MANAGER_ADDRESS" 
        "CDC_POOL_ADDRESS"
        "REPUTATION_MANAGER_ADDRESS"
        "GOVERNANCE_TREASURY_ADDRESS"
        "LINEAR_VESTING_ADDRESS"
        "MILESTONE_VESTING_ADDRESS"
        "BURN_MANAGER_ADDRESS"
    )
    
    for contract in "${contracts[@]}"; do
        local address=$(eval echo \$$contract)
        if [ -z "$address" ] || [ "$address" = "0x0" ]; then
            print_error "$contract failed to deploy!"
            exit 1
        fi
    done
    
    print_success "All contracts deployed successfully!"
    echo ""
}

save_deployment_info() {
    print_step "6" "Saving Deployment Information"
    
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    cat > "$DEPLOYMENT_FILE" << EOF
{
  "network": "$NETWORK",
  "deployed_at": "$timestamp",
  "deployer": "$DEPLOYER_ADDRESS",
  "account_config": "$ACCOUNT_CONFIG",
  "keystore": "$KEYSTORE_PATH",
  "contracts": {
    "ciro_token": {
      "address": "$CIRO_TOKEN_ADDRESS",
      "class_hash": "$CIRO_TOKEN_CLASS"
    },
    "job_manager": {
      "address": "$JOB_MANAGER_ADDRESS",
      "class_hash": "$JOB_MANAGER_CLASS"
    },
    "cdc_pool": {
      "address": "$CDC_POOL_ADDRESS",
      "class_hash": "$CDC_POOL_CLASS"
    },
    "reputation_manager": {
      "address": "$REPUTATION_MANAGER_ADDRESS",
      "class_hash": "$REPUTATION_MANAGER_CLASS"
    },
    "governance_treasury": {
      "address": "$GOVERNANCE_TREASURY_ADDRESS",
      "class_hash": "$GOVERNANCE_TREASURY_CLASS"
    },
    "treasury_timelock": {
      "address": "MANUAL_DEPLOYMENT_REQUIRED",
      "class_hash": "$TREASURY_TIMELOCK_CLASS",
      "note": "Requires manual deployment with Array constructor parameters"
    },
    "linear_vesting": {
      "address": "$LINEAR_VESTING_ADDRESS",
      "class_hash": "$LINEAR_VESTING_CLASS"
    },
    "milestone_vesting": {
      "address": "$MILESTONE_VESTING_ADDRESS",
      "class_hash": "$MILESTONE_VESTING_CLASS"
    },
    "burn_manager": {
      "address": "$BURN_MANAGER_ADDRESS",
      "class_hash": "$BURN_MANAGER_CLASS"
    }
  }
}
EOF

    print_success "Deployment info saved to: $DEPLOYMENT_FILE"
    print_success "Deployment log saved to: $LOG_FILE"
    echo ""
}

print_summary() {
    print_step "7" "Deployment Summary"
    
    echo -e "${GREEN}🎉 CIRO Network Deployment Completed Successfully!${NC}"
    echo ""
    echo -e "${YELLOW}📋 Core Contract Addresses:${NC}"
    echo -e "   CIRO Token:           ${BLUE}$CIRO_TOKEN_ADDRESS${NC}"
    echo -e "   Job Manager:          ${BLUE}$JOB_MANAGER_ADDRESS${NC}" 
    echo -e "   CDC Pool:             ${BLUE}$CDC_POOL_ADDRESS${NC}"
    echo -e "   Reputation Manager:   ${BLUE}$REPUTATION_MANAGER_ADDRESS${NC}"
    echo ""
    echo -e "${YELLOW}📋 Governance Contracts:${NC}"
    echo -e "   Governance Treasury:  ${BLUE}$GOVERNANCE_TREASURY_ADDRESS${NC}"
    echo -e "   Linear Vesting:       ${BLUE}$LINEAR_VESTING_ADDRESS${NC}"
    echo -e "   Milestone Vesting:    ${BLUE}$MILESTONE_VESTING_ADDRESS${NC}"
    echo -e "   Burn Manager:         ${BLUE}$BURN_MANAGER_ADDRESS${NC}"
    echo ""
    echo -e "${YELLOW}🔗 Network:${NC} $NETWORK"
    echo -e "${YELLOW}📄 Deployment info:${NC} $DEPLOYMENT_FILE"
    echo -e "${YELLOW}📄 Deployment log:${NC} $LOG_FILE"
    echo ""
    echo -e "${GREEN}Next Steps:${NC}"
    echo "  1. Update frontend with contract addresses above"
    echo "  2. Configure cross-contract permissions"
    echo "  3. Initialize vesting schedules"
    echo "  4. Set up monitoring and health checks"
    echo "  5. Update Job Manager CDC Pool reference"
    echo ""
}

show_help() {
    echo "CIRO Network Complete System Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --network NETWORK         Target network (default: sepolia)"
    echo "  --account ACCOUNT         Account config file (default: temp_account.json)"
    echo "  --keystore KEYSTORE       Keystore file path"
    echo "  --dry-run                 Simulate deployment without execution"
    echo "  --help                    Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  NETWORK                   Target network"
    echo "  ACCOUNT_CONFIG           Account config file path"
    echo "  KEYSTORE_PATH            Keystore file path"
    echo "  DRY_RUN                  Set to 'true' for dry run"
    echo ""
    echo "Examples:"
    echo "  $0 --network sepolia"
    echo "  $0 --account my_account.json --keystore my_keystore.json"
    echo "  $0 --dry-run"
    echo "  DRY_RUN=true $0"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --account)
            ACCOUNT_CONFIG="$2"
            shift 2
            ;;
        --keystore)
            KEYSTORE_PATH="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    print_header
    
    if [ "$DRY_RUN" = true ]; then
        print_info "🧪 Running in DRY RUN mode - no actual deployment will occur"
        echo ""
    fi
    
    check_prerequisites
    build_contracts
    deploy_core_contracts
    deploy_contract_instances
    verify_deployment
    save_deployment_info
    print_summary
    
    log "CIRO Network deployment completed successfully"
}

# Handle script interruption
trap 'print_error "Deployment interrupted!"; log "Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"