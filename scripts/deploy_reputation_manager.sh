#!/bin/bash

# CIRO Network Reputation Manager Deployment Script
# Deploys the ReputationManager contract with proper integration
# Uses keystore and deployment patterns from CIRO_Network_Backup

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NETWORK="sepolia"
KEYSTORE_PATH="../CIRO_Network_Backup/20250711_061352/testnet_keystore.json"
RPC_URL="https://starknet-sepolia.public.blastapi.io"
EXPLORER_URL="https://sepolia.starkscan.co"

# Contract build artifacts
CONTRACTS_DIR="target/dev"
REPUTATION_MANAGER_ARTIFACT="ciro_contracts_ReputationManager"

# Deployment tracking
DEPLOYMENT_LOG="reputation_manager_deployment_$(date +%Y%m%d_%H%M%S).log"
DEPLOYMENT_FILE="reputation_manager_deployment.json"

# Contract addresses from backup deployment
# These should be updated with actual deployed addresses
CDC_POOL_ADDRESS="0x05d9e1c8839eae6fbdbb756ed73a8f5d9d1533e4283e1d0445b0b00252e06fb5"
JOB_MANAGER_ADDRESS="0x0197378e15788f4822dbce9f05b4fda8376a09ab6f1a408515bd1e9226e40b4d"
ADMIN_ADDRESS="0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

# Deployment parameters
UPDATE_RATE_LIMIT=300  # 5 minutes between reputation updates

# Functions
print_header() {
    echo -e "\n${PURPLE}======================================${NC}"
    echo -e "${PURPLE}  CIRO Network Reputation Manager${NC}"
    echo -e "${PURPLE}  Testnet Deployment Script${NC}"
    echo -e "${PURPLE}  $(date)${NC}"
    echo -e "${PURPLE}======================================${NC}\n"
}

log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$DEPLOYMENT_LOG"
}

print_status() {
    local message="$1"
    echo -e "${BLUE}[INFO]${NC} $message"
    log "INFO: $message"
}

print_success() {
    local message="$1"
    echo -e "${GREEN}[SUCCESS]${NC} $message"
    log "SUCCESS: $message"
}

print_warning() {
    local message="$1"
    echo -e "${YELLOW}[WARNING]${NC} $message"
    log "WARNING: $message"
}

print_error() {
    local message="$1"
    echo -e "${RED}[ERROR]${NC} $message"
    log "ERROR: $message"
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if starkli is installed
    if ! command -v starkli &> /dev/null; then
        print_error "starkli is not installed. Please install it first."
        print_status "Install with: curl https://get.starkli.sh | sh"
        exit 1
    fi
    
    # Check if scarb is installed
    if ! command -v scarb &> /dev/null; then
        print_error "scarb is not installed. Please install it first."
        exit 1
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "Scarb.toml" ]]; then
        print_error "Scarb.toml not found. Please run this script from the cairo-contracts directory."
        exit 1
    fi
    
    # Check if keystore exists
    if [[ ! -f "$KEYSTORE_PATH" ]]; then
        print_error "Keystore not found at $KEYSTORE_PATH"
        print_status "Please ensure the backup directory is available."
        exit 1
    fi
    
    print_success "Prerequisites check completed"
}

build_contracts() {
    print_status "Building contracts..."
    
    # Clean previous build
    scarb clean
    
    # Build contracts
    if scarb build; then
        print_success "Contracts built successfully"
    else
        print_error "Contract build failed"
        exit 1
    fi
    
    # Verify reputation manager artifact exists
    local contract_file="$CONTRACTS_DIR/${REPUTATION_MANAGER_ARTIFACT}.contract_class.json"
    if [[ ! -f "$contract_file" ]]; then
        print_error "Reputation Manager contract artifact not found at $contract_file"
        exit 1
    fi
    
    print_success "Reputation Manager artifact verified at $contract_file"
}

declare_contract() {
    print_status "Declaring Reputation Manager contract..."
    
    local contract_file="$CONTRACTS_DIR/${REPUTATION_MANAGER_ARTIFACT}.contract_class.json"
    
    # Declare contract with retry logic
    local class_hash=""
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        print_status "Declaration attempt $((retry_count + 1))..."
        
        # Debug: Show the actual command being run
        echo "Running: starkli declare $contract_file --account ../CIRO_Network_Backup/20250711_061352/internal_docs/testnet_account.json --keystore $KEYSTORE_PATH --rpc $RPC_URL --network $NETWORK"
        
        # Capture full output to see errors
        declare_output=$(starkli declare "$contract_file" \
            --account "../CIRO_Network_Backup/20250711_061352/internal_docs/testnet_account.json" \
            --keystore "$KEYSTORE_PATH" \
            --rpc "$RPC_URL" \
            --network "$NETWORK" 2>&1)
        
        echo "Declare output: $declare_output"
        
        if class_hash=$(echo "$declare_output" | grep "Class hash declared:" | awk '{print $4}'); then
            if [[ -n "$class_hash" ]]; then
                break
            fi
        fi
        
        retry_count=$((retry_count + 1))
        print_warning "Declaration attempt $retry_count failed: $declare_output"
        if [[ $retry_count -lt $max_retries ]]; then
            sleep 10
        fi
    done
    
    if [[ -z "$class_hash" ]]; then
        print_error "Failed to declare Reputation Manager contract after $max_retries attempts"
        exit 1
    fi
    
    print_success "Declared Reputation Manager with class hash: $class_hash"
    
    # Export for use in deployment
    export REPUTATION_MANAGER_CLASS_HASH="$class_hash"
    
    # Save to declarations file
    echo "{\"reputation_manager_class_hash\": \"$class_hash\"}" > reputation_manager_declarations.json
    
    # Wait for confirmation
    sleep 5
}

deploy_contract() {
    print_status "Deploying Reputation Manager contract..."
    
    if [[ -z "$REPUTATION_MANAGER_CLASS_HASH" ]]; then
        print_error "Class hash not available. Declaration may have failed."
        exit 1
    fi
    
    print_status "Using class hash: $REPUTATION_MANAGER_CLASS_HASH"
    print_status "Constructor arguments:"
    print_status "  Admin: $ADMIN_ADDRESS"
    print_status "  CDC Pool: $CDC_POOL_ADDRESS"
    print_status "  Job Manager: $JOB_MANAGER_ADDRESS"
    print_status "  Rate Limit: $UPDATE_RATE_LIMIT seconds"
    
    # Deploy contract
    local contract_address=""
    if contract_address=$(starkli deploy \
        "$REPUTATION_MANAGER_CLASS_HASH" \
        "$ADMIN_ADDRESS" \
        "$CDC_POOL_ADDRESS" \
        "$JOB_MANAGER_ADDRESS" \
        "$UPDATE_RATE_LIMIT" \
        --keystore "$KEYSTORE_PATH" \
        --rpc "$RPC_URL" \
        --network "$NETWORK" 2>&1 | grep "Contract deployed:" | awk '{print $3}'); then
        
        print_success "Reputation Manager deployed at: $contract_address"
        export REPUTATION_MANAGER_ADDRESS="$contract_address"
    else
        print_error "Failed to deploy Reputation Manager contract"
        exit 1
    fi
    
    # Wait for deployment confirmation
    sleep 10
}

verify_deployment() {
    print_status "Verifying deployment..."
    
    if [[ -z "$REPUTATION_MANAGER_ADDRESS" ]]; then
        print_error "Contract address not available for verification"
        return 1
    fi
    
    # Test basic contract function
    print_status "Testing get_network_stats function..."
    if starkli call "$REPUTATION_MANAGER_ADDRESS" get_network_stats --rpc "$RPC_URL" > /dev/null 2>&1; then
        print_success "Contract is responsive and functional"
    else
        print_warning "Contract verification failed - but deployment may still be successful"
    fi
    
    # Check contract on explorer
    print_status "Contract should be visible at: $EXPLORER_URL/contract/$REPUTATION_MANAGER_ADDRESS"
}

save_deployment_info() {
    print_status "Saving deployment information..."
    
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    cat > "$DEPLOYMENT_FILE" << EOF
{
  "reputation_manager": {
    "contract_address": "$REPUTATION_MANAGER_ADDRESS",
    "class_hash": "$REPUTATION_MANAGER_CLASS_HASH",
    "network": "$NETWORK",
    "deployed_at": "$timestamp",
    "deployer_keystore": "$KEYSTORE_PATH",
    "constructor_params": {
      "admin_address": "$ADMIN_ADDRESS",
      "cdc_pool_address": "$CDC_POOL_ADDRESS", 
      "job_manager_address": "$JOB_MANAGER_ADDRESS",
      "update_rate_limit": $UPDATE_RATE_LIMIT
    },
    "explorer_urls": {
      "contract": "$EXPLORER_URL/contract/$REPUTATION_MANAGER_ADDRESS",
      "transactions": "$EXPLORER_URL/contract/$REPUTATION_MANAGER_ADDRESS#transactions"
    }
  }
}
EOF
    
    print_success "Deployment info saved to: $DEPLOYMENT_FILE"
}

run_integration_tests() {
    print_status "Running basic integration tests..."
    
    if [[ -z "$REPUTATION_MANAGER_ADDRESS" ]]; then
        print_warning "Cannot run integration tests - contract address not available"
        return 1
    fi
    
    # Test 1: Check initial network stats
    print_status "Test 1: Checking initial network stats..."
    if starkli call "$REPUTATION_MANAGER_ADDRESS" get_network_stats --rpc "$RPC_URL" &> /dev/null; then
        print_success "✓ Network stats query successful"
    else
        print_error "✗ Network stats query failed"
        return 1
    fi
    
    # More integration tests could be added here
    print_success "Basic integration tests completed"
}

print_summary() {
    print_status "Deployment Summary"
    
    echo -e "${GREEN}🎉 Reputation Manager Deployment Completed!${NC}"
    echo ""
    echo -e "${YELLOW}📋 Deployment Details:${NC}"
    echo -e "   Contract Address: ${BLUE}$REPUTATION_MANAGER_ADDRESS${NC}"
    echo -e "   Class Hash:      ${BLUE}$REPUTATION_MANAGER_CLASS_HASH${NC}"
    echo -e "   Network:         ${BLUE}$NETWORK${NC}"
    echo -e "   Admin:           ${BLUE}$ADMIN_ADDRESS${NC}"
    echo ""
    echo -e "${YELLOW}🔗 Explorer Links:${NC}"
    echo -e "   Contract: ${CYAN}$EXPLORER_URL/contract/$REPUTATION_MANAGER_ADDRESS${NC}"
    echo ""
    echo -e "${YELLOW}📄 Files Created:${NC}"
    echo -e "   Deployment Info: ${BLUE}$DEPLOYMENT_FILE${NC}"
    echo -e "   Deployment Log:  ${BLUE}$DEPLOYMENT_LOG${NC}"
    echo ""
    echo -e "${GREEN}Next Steps:${NC}"
    echo "  1. Update CDC Pool and Job Manager to use new Reputation Manager"
    echo "  2. Initialize reputation for existing workers" 
    echo "  3. Set reputation thresholds for different job types"
    echo "  4. Monitor reputation system performance"
    echo ""
}

show_help() {
    echo "CIRO Network Reputation Manager Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --admin ADDRESS       Override admin address"
    echo "  --cdc-pool ADDRESS    Override CDC Pool contract address"
    echo "  --job-manager ADDRESS Override Job Manager contract address"
    echo "  --rate-limit SECONDS  Override update rate limit (default: 300)"
    echo "  --network NETWORK     Override network (default: sepolia)"
    echo "  --dry-run            Simulate deployment without actual execution"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  $0 --admin 0x123... --rate-limit 600"
    echo "  $0 --dry-run"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --admin)
            ADMIN_ADDRESS="$2"
            shift 2
            ;;
        --cdc-pool)
            CDC_POOL_ADDRESS="$2"
            shift 2
            ;;
        --job-manager)
            JOB_MANAGER_ADDRESS="$2"
            shift 2
            ;;
        --rate-limit)
            UPDATE_RATE_LIMIT="$2"
            shift 2
            ;;
        --network)
            NETWORK="$2"
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
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_status "🧪 Running in DRY RUN mode - no actual deployment will occur"
        echo ""
    fi
    
    check_prerequisites
    build_contracts
    
    if [[ "$DRY_RUN" != "true" ]]; then
        declare_contract
        deploy_contract
        verify_deployment
        save_deployment_info
        run_integration_tests
    else
        print_status "DRY RUN: Would declare and deploy Reputation Manager contract"
    fi
    
    print_summary
}

# Handle script interruption
trap 'print_error "Deployment interrupted!"; exit 1' INT TERM

# Run main function
main "$@" 