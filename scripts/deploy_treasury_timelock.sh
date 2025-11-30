#!/bin/bash

# CIRO Network - Treasury Timelock Manual Deployment Script
# This script handles the complex Array constructor parameters for Treasury Timelock

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK="sepolia"
ACCOUNT_CONFIG="temp_account.json"
KEYSTORE_PATH="../CIRO_Network_Backup/20250711_061352/testnet_keystore.json"

# PRODUCTION SECURITY CONFIGURATION
# Based on comprehensive security analysis and best practices
DEFAULT_ADMIN="0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"
DEFAULT_TIMELOCK_DELAY="172800"  # 48 hours in seconds (PRODUCTION SECURITY)
DEFAULT_THRESHOLD="3"            # Require 3 of 5 signatures (PRODUCTION SECURITY)

# Production multisig members (3-of-5 security model)
DEFAULT_MULTISIG_MEMBERS=(
    "0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"  # Admin/Lead
    "0x076aa95e263cb7f4ccabf4f6eff1cfdb04bd9d5d37da4484d1ace0cfeb822b8c"  # Core Member 1
    "0x023e82c4a0e9f8c4e0895f35979c78c9ebeeae57bb6503368da6ac19810fddcc"  # Core Member 2
    "0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"  # Community Rep (placeholder)
    "0x076aa95e263cb7f4ccabf4f6eff1cfdb04bd9d5d37da4484d1ace0cfeb822b8c"  # Technical Lead (placeholder)
)

# Production emergency members (2-of-3 emergency response)
DEFAULT_EMERGENCY_MEMBERS=(
    "0x02f5248a6b08cd6a52cb9db812e98c675be165cf803a56ac06aefbce74d1f2ca"  # Admin/Emergency Lead
    "0x076aa95e263cb7f4ccabf4f6eff1cfdb04bd9d5d37da4484d1ace0cfeb822b8c"  # Security Officer
    "0x023e82c4a0e9f8c4e0895f35979c78c9ebeeae57bb6503368da6ac19810fddcc"  # Technical Lead
)

print_header() {
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}  CIRO Network - Treasury Timelock Deployment${NC}"
    echo -e "${BLUE}  $(date)${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo ""
}

print_step() {
    echo -e "${GREEN}📋 Step $1: $2${NC}"
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

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --admin <address>              Admin address (default: $DEFAULT_ADMIN)"
    echo "  --threshold <number>           Multisig threshold (default: $DEFAULT_THRESHOLD)"
    echo "  --timelock-delay <seconds>     Timelock delay in seconds (default: $DEFAULT_TIMELOCK_DELAY)"
    echo "  --multisig-members <addr1,addr2,...>  Multisig member addresses (comma-separated)"
    echo "  --emergency-members <addr1,addr2,...> Emergency member addresses (comma-separated)"
    echo "  --dry-run                      Show what would be deployed without executing"
    echo "  --help                         Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --admin 0x123... --threshold 3 --timelock-delay 172800"
    echo ""
}

parse_args() {
    ADMIN="$DEFAULT_ADMIN"
    THRESHOLD="$DEFAULT_THRESHOLD"
    TIMELOCK_DELAY="$DEFAULT_TIMELOCK_DELAY"
    MULTISIG_MEMBERS=("${DEFAULT_MULTISIG_MEMBERS[@]}")
    EMERGENCY_MEMBERS=("${DEFAULT_EMERGENCY_MEMBERS[@]}")
    DRY_RUN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --admin)
                ADMIN="$2"
                shift 2
                ;;
            --threshold)
                THRESHOLD="$2"
                shift 2
                ;;
            --timelock-delay)
                TIMELOCK_DELAY="$2"
                shift 2
                ;;
            --multisig-members)
                IFS=',' read -ra MULTISIG_MEMBERS <<< "$2"
                shift 2
                ;;
            --emergency-members)
                IFS=',' read -ra EMERGENCY_MEMBERS <<< "$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

validate_config() {
    print_step "1" "Validating Configuration"
    
    # Validate admin address
    if [[ ! "$ADMIN" =~ ^0x[a-fA-F0-9]{63,64}$ ]]; then
        print_error "Invalid admin address format: $ADMIN"
        exit 1
    fi
    
    # Validate threshold
    if ! [[ "$THRESHOLD" =~ ^[0-9]+$ ]] || [ "$THRESHOLD" -lt 1 ]; then
        print_error "Invalid threshold: $THRESHOLD (must be positive integer)"
        exit 1
    fi
    
    # Validate timelock delay
    if ! [[ "$TIMELOCK_DELAY" =~ ^[0-9]+$ ]] || [ "$TIMELOCK_DELAY" -lt 60 ]; then
        print_error "Invalid timelock delay: $TIMELOCK_DELAY (must be at least 60 seconds)"
        exit 1
    fi
    
    # Validate multisig members
    if [ ${#MULTISIG_MEMBERS[@]} -lt "$THRESHOLD" ]; then
        print_error "Not enough multisig members (${#MULTISIG_MEMBERS[@]}) for threshold ($THRESHOLD)"
        exit 1
    fi
    
    # Validate addresses
    for addr in "${MULTISIG_MEMBERS[@]}"; do
        if [[ ! "$addr" =~ ^0x[a-fA-F0-9]{63,64}$ ]]; then
            print_error "Invalid multisig member address: $addr"
            exit 1
        fi
    done
    
    for addr in "${EMERGENCY_MEMBERS[@]}"; do
        if [[ ! "$addr" =~ ^0x[a-fA-F0-9]{63,64}$ ]]; then
            print_error "Invalid emergency member address: $addr"
            exit 1
        fi
    done
    
    print_success "Configuration validation passed!"
    echo ""
}

show_config() {
    print_step "2" "Deployment Configuration"
    
    print_info "Network: $NETWORK"
    print_info "Admin: $ADMIN"
    print_info "Threshold: $THRESHOLD"
    print_info "Timelock Delay: $TIMELOCK_DELAY seconds ($(($TIMELOCK_DELAY / 3600)) hours)"
    print_info "Multisig Members (${#MULTISIG_MEMBERS[@]}):"
    for i in "${!MULTISIG_MEMBERS[@]}"; do
        print_info "  $((i+1)). ${MULTISIG_MEMBERS[$i]}"
    done
    print_info "Emergency Members (${#EMERGENCY_MEMBERS[@]}):"
    for i in "${!EMERGENCY_MEMBERS[@]}"; do
        print_info "  $((i+1)). ${EMERGENCY_MEMBERS[$i]}"
    done
    echo ""
    
    if [ "$DRY_RUN" = true ]; then
        print_warning "🧪 Running in DRY RUN mode - no actual deployment will occur"
        echo ""
    fi
}

build_constructor_calldata() {
    print_step "3" "Building Constructor Calldata"
    
    # Build multisig members array
    local multisig_calldata=""
    multisig_calldata="${#MULTISIG_MEMBERS[@]}"  # Array length
    for addr in "${MULTISIG_MEMBERS[@]}"; do
        multisig_calldata="$multisig_calldata $addr"
    done
    
    # Build emergency members array  
    local emergency_calldata=""
    emergency_calldata="${#EMERGENCY_MEMBERS[@]}"  # Array length
    for addr in "${EMERGENCY_MEMBERS[@]}"; do
        emergency_calldata="$emergency_calldata $addr"
    done
    
    # Complete constructor arguments
    CONSTRUCTOR_CALLDATA="$multisig_calldata $THRESHOLD $TIMELOCK_DELAY $ADMIN $emergency_calldata"
    
    print_info "Constructor calldata prepared:"
    print_info "  Multisig array: ${#MULTISIG_MEMBERS[@]} members"
    print_info "  Emergency array: ${#EMERGENCY_MEMBERS[@]} members"
    print_info "  Full calldata: $CONSTRUCTOR_CALLDATA"
    echo ""
}

deploy_treasury_timelock() {
    print_step "4" "Deploying Treasury Timelock"
    
    cd "$PROJECT_ROOT"
    
    # Check if contract class exists
    local contract_file="target/dev/ciro_contracts_TreasuryTimelock.contract_class.json"
    if [ ! -f "$contract_file" ]; then
        print_error "Contract class file not found: $contract_file"
        print_info "Run 'scarb build' first to generate contract artifacts"
        exit 1
    fi
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would declare Treasury Timelock contract"
        print_info "DRY RUN: Would deploy with constructor: $CONSTRUCTOR_CALLDATA"
        print_success "DRY RUN: Treasury Timelock deployment simulated successfully!"
        return
    fi
    
    # Declare contract
    print_info "Declaring Treasury Timelock contract..."
    local class_hash
    class_hash=$(echo "test" | starkli declare "$contract_file" \
        --account "$ACCOUNT_CONFIG" \
        --keystore "$KEYSTORE_PATH" \
        --network "$NETWORK" 2>/dev/null | grep -o '0x[a-fA-F0-9]\{64\}' | head -1)
    
    if [ -z "$class_hash" ]; then
        print_error "Failed to declare Treasury Timelock contract"
        exit 1
    fi
    
    print_success "Contract declared with class hash: $class_hash"
    
    # Deploy contract
    print_info "Deploying Treasury Timelock instance..."
    local contract_address
    contract_address=$(echo "test" | starkli deploy "$class_hash" \
        $CONSTRUCTOR_CALLDATA \
        --account "$ACCOUNT_CONFIG" \
        --keystore "$KEYSTORE_PATH" \
        --network "$NETWORK" 2>/dev/null | grep -o '0x[a-fA-F0-9]\{64\}' | head -1)
    
    if [ -z "$contract_address" ]; then
        print_error "Failed to deploy Treasury Timelock contract"
        exit 1
    fi
    
    print_success "Treasury Timelock deployed at: $contract_address"
    
    # Save deployment info
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local deployment_file="treasury_timelock_deployment_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$deployment_file" << EOF
{
  "network": "$NETWORK",
  "deployed_at": "$timestamp",
  "deployer": "$ADMIN",
  "contract": {
    "name": "TreasuryTimelock",
    "address": "$contract_address",
    "class_hash": "$class_hash"
  },
  "configuration": {
    "admin": "$ADMIN",
    "threshold": $THRESHOLD,
    "timelock_delay": $TIMELOCK_DELAY,
    "multisig_members": [$(printf '"%s",' "${MULTISIG_MEMBERS[@]}" | sed 's/,$//')],
    "emergency_members": [$(printf '"%s",' "${EMERGENCY_MEMBERS[@]}" | sed 's/,$//')],
    "member_count": ${#MULTISIG_MEMBERS[@]},
    "emergency_count": ${#EMERGENCY_MEMBERS[@]}
  },
  "constructor_calldata": "$CONSTRUCTOR_CALLDATA"
}
EOF
    
    print_success "Deployment info saved to: $deployment_file"
    echo ""
}

show_summary() {
    print_step "5" "Deployment Summary"
    
    if [ "$DRY_RUN" = true ]; then
        print_info "🧪 DRY RUN COMPLETED - No actual deployment performed"
        print_info "Configuration validated and calldata prepared successfully"
    else
        print_success "🎉 Treasury Timelock deployed successfully!"
        print_info "Network: $NETWORK"
        print_info "Contract Address: $contract_address"
        print_info "Class Hash: $class_hash"
        print_info "Configuration:"
        print_info "  - Admin: $ADMIN"
        print_info "  - Multisig Threshold: $THRESHOLD of ${#MULTISIG_MEMBERS[@]} members"
        print_info "  - Timelock Delay: $TIMELOCK_DELAY seconds ($(($TIMELOCK_DELAY / 3600)) hours)"
        print_info "  - Emergency Members: ${#EMERGENCY_MEMBERS[@]} members"
    fi
    
    echo ""
    print_info "Next Steps:"
    print_info "  1. Test multisig functionality"
    print_info "  2. Configure governance treasury integration"
    print_info "  3. Set up operational procedures"
    print_info "  4. Document emergency procedures"
    echo ""
}

# Main execution
main() {
    print_header
    
    parse_args "$@"
    validate_config
    show_config
    
    # Confirm deployment in production mode
    if [ "$DRY_RUN" = false ]; then
        print_warning "This will deploy Treasury Timelock to $NETWORK network"
        print_warning "Make sure you have reviewed the configuration above"
        read -p "Continue with deployment? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Deployment cancelled by user"
            exit 0
        fi
        echo ""
    fi
    
    build_constructor_calldata
    deploy_treasury_timelock
    show_summary
}

# Handle script interruption
trap 'echo -e "\n${RED}Deployment interrupted${NC}"; exit 1' INT TERM

# Run main function with all arguments
main "$@"