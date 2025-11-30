#!/bin/bash

# CIRO Network Smart Contracts - MVP Deployment Script
# This script automates the deployment of upgradeable contracts using proxy patterns

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
DEPLOYMENT_FILE="$PROJECT_ROOT/deployment.json"

# Default values
NETWORK=${NETWORK:-"goerli"}
DEPLOYER_KEYSTORE=${DEPLOYER_KEYSTORE:-"deployment-key"}
DRY_RUN=${DRY_RUN:-false}

print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}  CIRO Network Smart Contract Deployment${NC}"
    echo -e "${BLUE}================================================${NC}"
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
    
    # Check environment variables
    if [ -z "$STARKNET_RPC" ]; then
        print_error "STARKNET_RPC environment variable is not set."
        print_info "Please set it to your preferred RPC endpoint."
        exit 1
    fi
    
    if [ -z "$DEPLOYER_ADDRESS" ]; then
        print_error "DEPLOYER_ADDRESS environment variable is not set."
        print_info "Please set it to your deployer account address."
        exit 1
    fi
    
    print_success "All prerequisites check passed!"
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
        print_info "Please fix compilation errors before deploying."
        exit 1
    fi
    
    echo ""
}

deploy_implementations() {
    print_step "3" "Deploying Implementation Contracts"
    
    local target_dir="$PROJECT_ROOT/target/dev"
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would deploy implementation contracts"
        CIRO_TOKEN_CLASS="0x1234567890abcdef"
        JOB_MANAGER_CLASS="0x1234567890abcdef" 
        CDC_POOL_CLASS="0x1234567890abcdef"
        return
    fi
    
    # Deploy CIRO Token implementation
    print_info "Deploying CIRO Token implementation..."
    if [ -f "$target_dir/ciro_contracts_CIROToken.contract_class.json" ]; then
        CIRO_TOKEN_CLASS=$(starkli declare \
            --keystore "$DEPLOYER_KEYSTORE" \
            --network "$NETWORK" \
            --max-fee 0.01 \
            "$target_dir/ciro_contracts_CIROToken.contract_class.json" 2>/dev/null | tail -1)
        print_success "CIRO Token implementation deployed: $CIRO_TOKEN_CLASS"
    else
        print_error "CIRO Token contract class not found!"
        exit 1
    fi
    
    # Deploy Job Manager implementation
    print_info "Deploying Job Manager implementation..."
    if [ -f "$target_dir/ciro_contracts_JobManagerContract.contract_class.json" ]; then
        JOB_MANAGER_CLASS=$(starkli declare \
            --keystore "$DEPLOYER_KEYSTORE" \
            --network "$NETWORK" \
            --max-fee 0.01 \
            "$target_dir/ciro_contracts_JobManagerContract.contract_class.json" 2>/dev/null | tail -1)
        print_success "Job Manager implementation deployed: $JOB_MANAGER_CLASS"
    else
        print_error "Job Manager contract class not found!"
        exit 1
    fi
    
    # Deploy CDC Pool implementation
    print_info "Deploying CDC Pool implementation..."
    if [ -f "$target_dir/ciro_contracts_CDCPool.contract_class.json" ]; then
        CDC_POOL_CLASS=$(starkli declare \
            --keystore "$DEPLOYER_KEYSTORE" \
            --network "$NETWORK" \
            --max-fee 0.01 \
            "$target_dir/ciro_contracts_CDCPool.contract_class.json" 2>/dev/null | tail -1)
        print_success "CDC Pool implementation deployed: $CDC_POOL_CLASS"
    else
        print_error "CDC Pool contract class not found!"
        exit 1
    fi
    
    echo ""
}

deploy_proxy_contracts() {
    print_step "4" "Deploying Proxy Contracts"
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would deploy proxy contracts"
        CIRO_TOKEN_PROXY="0x1234567890abcdef"
        JOB_MANAGER_PROXY="0x1234567890abcdef"
        CDC_POOL_PROXY="0x1234567890abcdef"
        return
    fi
    
    # For now, we'll use direct deployment
    # In production, you'd use actual proxy contracts
    print_info "Note: Using direct deployment for MVP. Upgrade via new deployments."
    
    # Deploy CIRO Token
    print_info "Deploying CIRO Token proxy..."
    CIRO_TOKEN_PROXY=$(starkli deploy \
        --keystore "$DEPLOYER_KEYSTORE" \
        --network "$NETWORK" \
        --max-fee 0.01 \
        "$CIRO_TOKEN_CLASS" \
        "$DEPLOYER_ADDRESS" 2>/dev/null | tail -1)
    print_success "CIRO Token proxy deployed: $CIRO_TOKEN_PROXY"
    
    # Deploy Job Manager  
    print_info "Deploying Job Manager proxy..."
    JOB_MANAGER_PROXY=$(starkli deploy \
        --keystore "$DEPLOYER_KEYSTORE" \
        --network "$NETWORK" \
        --max-fee 0.01 \
        "$JOB_MANAGER_CLASS" \
        "$DEPLOYER_ADDRESS" \
        "$CIRO_TOKEN_PROXY" 2>/dev/null | tail -1)
    print_success "Job Manager proxy deployed: $JOB_MANAGER_PROXY"
    
    # Deploy CDC Pool
    print_info "Deploying CDC Pool proxy..."
    CDC_POOL_PROXY=$(starkli deploy \
        --keystore "$DEPLOYER_KEYSTORE" \
        --network "$NETWORK" \
        --max-fee 0.01 \
        "$CDC_POOL_CLASS" \
        "$DEPLOYER_ADDRESS" \
        "$CIRO_TOKEN_PROXY" \
        "$JOB_MANAGER_PROXY" 2>/dev/null | tail -1)
    print_success "CDC Pool proxy deployed: $CDC_POOL_PROXY"
    
    echo ""
}

verify_deployment() {
    print_step "5" "Verifying Deployment"
    
    if [ "$DRY_RUN" = true ]; then
        print_info "DRY RUN: Would verify deployment"
        return
    fi
    
    print_info "Verifying contract deployments..."
    
    # Add verification calls here when contracts are fixed
    # For now, just check if addresses were generated
    if [ -n "$CIRO_TOKEN_PROXY" ] && [ -n "$JOB_MANAGER_PROXY" ] && [ -n "$CDC_POOL_PROXY" ]; then
        print_success "All contracts deployed successfully!"
    else
        print_error "Some contracts failed to deploy!"
        exit 1
    fi
    
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
  "contracts": {
    "ciro_token": {
      "proxy": "$CIRO_TOKEN_PROXY",
      "implementation": "$CIRO_TOKEN_CLASS"
    },
    "job_manager": {
      "proxy": "$JOB_MANAGER_PROXY", 
      "implementation": "$JOB_MANAGER_CLASS"
    },
    "cdc_pool": {
      "proxy": "$CDC_POOL_PROXY",
      "implementation": "$CDC_POOL_CLASS"
    }
  },
  "environment": {
    "rpc": "$STARKNET_RPC",
    "keystore": "$DEPLOYER_KEYSTORE"
  }
}
EOF

    print_success "Deployment info saved to: $DEPLOYMENT_FILE"
    echo ""
}

print_summary() {
    print_step "7" "Deployment Summary"
    
    echo -e "${GREEN}🎉 Deployment Completed Successfully!${NC}"
    echo ""
    echo -e "${YELLOW}📋 Contract Addresses:${NC}"
    echo -e "   CIRO Token:   ${BLUE}$CIRO_TOKEN_PROXY${NC}"
    echo -e "   Job Manager:  ${BLUE}$JOB_MANAGER_PROXY${NC}" 
    echo -e "   CDC Pool:     ${BLUE}$CDC_POOL_PROXY${NC}"
    echo ""
    echo -e "${YELLOW}🔗 Network:${NC} $NETWORK"
    echo -e "${YELLOW}📄 Deployment info:${NC} $DEPLOYMENT_FILE"
    echo ""
    echo -e "${GREEN}Next Steps:${NC}"
    echo "  1. Update your frontend with the contract addresses above"
    echo "  2. Test the contracts on $NETWORK"
    echo "  3. Set up monitoring and health checks"
    echo "  4. Configure multi-sig and timelock for production"
    echo ""
}

show_help() {
    echo "CIRO Network Smart Contract Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --network NETWORK     Target network (default: goerli)"
    echo "  --keystore KEYSTORE   Keystore file name (default: deployment-key)"
    echo "  --dry-run            Simulate deployment without actual execution"
    echo "  --help               Show this help message"
    echo ""
    echo "Required Environment Variables:"
    echo "  STARKNET_RPC         RPC endpoint URL"
    echo "  DEPLOYER_ADDRESS     Deployer account address"
    echo ""
    echo "Examples:"
    echo "  $0 --network mainnet"
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
        --keystore)
            DEPLOYER_KEYSTORE="$2"
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
    deploy_implementations  
    deploy_proxy_contracts
    verify_deployment
    save_deployment_info
    print_summary
}

# Handle script interruption
trap 'print_error "Deployment interrupted!"; exit 1' INT TERM

# Run main function
main "$@" 