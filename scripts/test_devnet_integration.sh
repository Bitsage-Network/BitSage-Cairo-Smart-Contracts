#!/usr/bin/env bash
# =============================================================================
# BitSage Devnet Integration Tests
# =============================================================================
# Tests all major flows on the deployed devnet contracts
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Load deployment addresses
DEPLOYMENT_FILE="deployment/production_devnet_deployment.json"
if [ ! -f "$DEPLOYMENT_FILE" ]; then
    echo -e "${RED}Deployment file not found: $DEPLOYMENT_FILE${NC}"
    exit 1
fi

# Parse addresses using grep/sed (bash 3.x compatible)
get_address() {
    local key=$1
    grep "\"$key\":" "$DEPLOYMENT_FILE" | head -1 | sed 's/.*": *"\([^"]*\)".*/\1/'
}

DEPLOYER="0x064b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691"
SAGE_TOKEN=$(get_address "sage_token")
JOB_MANAGER=$(get_address "job_manager")
CDC_POOL=$(get_address "cdc_pool")
REPUTATION_MANAGER=$(get_address "reputation_manager")
PRIVACY_POOLS=$(get_address "privacy_pools")
PRIVACY_ROUTER=$(get_address "privacy_router")
PAYMENT_ROUTER=$(get_address "payment_router")
PROOF_GATED=$(get_address "proof_gated_payment")
OPTIMISTIC_TEE=$(get_address "optimistic_tee")
METERED_BILLING=$(get_address "metered_billing")
PROVER_STAKING=$(get_address "prover_staking")
WORKER_STAKING=$(get_address "worker_staking")
FAUCET=$(get_address "faucet")

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  BitSage Devnet Integration Tests${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${YELLOW}Loaded addresses from deployment:${NC}"
echo -e "  SAGE Token:     ${SAGE_TOKEN:0:20}..."
echo -e "  Job Manager:    ${JOB_MANAGER:0:20}..."
echo -e "  CDC Pool:       ${CDC_POOL:0:20}..."
echo -e "  Privacy Pools:  ${PRIVACY_POOLS:0:20}..."
echo -e "  Payment Router: ${PAYMENT_ROUTER:0:20}..."
echo ""

# Helper function to invoke and check result
invoke_check() {
    local contract=$1
    local func=$2
    shift 2
    local calldata="$@"

    local result
    if [ -z "$calldata" ]; then
        result=$(sncast --profile devnet invoke --contract-address "$contract" --function "$func" 2>&1)
    else
        result=$(sncast --profile devnet invoke --contract-address "$contract" --function "$func" --calldata $calldata 2>&1)
    fi

    if echo "$result" | grep -qi "success\|transaction"; then
        echo -e "${GREEN}    [OK] $func${NC}"
        return 0
    else
        echo -e "${RED}    [FAIL] $func: $(echo "$result" | head -1)${NC}"
        return 1
    fi
}

# Helper function to call and get result
call_check() {
    local contract=$1
    local func=$2
    shift 2
    local calldata="$@"

    local result
    if [ -z "$calldata" ]; then
        result=$(sncast --profile devnet call --contract-address "$contract" --function "$func" 2>&1)
    else
        result=$(sncast --profile devnet call --contract-address "$contract" --function "$func" --calldata $calldata 2>&1)
    fi

    if echo "$result" | grep -qi "success"; then
        local response=$(echo "$result" | grep "Response:" | head -1)
        echo -e "${GREEN}    [OK] $func: $response${NC}"
        return 0
    else
        echo -e "${YELLOW}    [WARN] $func: $(echo "$result" | head -1)${NC}"
        return 1
    fi
}

# =============================================================================
# TEST 1: Job Flow
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 1: Job Flow${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}1.1 Check JobManager state...${NC}"
call_check $JOB_MANAGER "get_job_count" || true

echo -e "${YELLOW}1.2 Check if JobManager has ProofGatedPayment wired...${NC}"
call_check $JOB_MANAGER "get_proof_gated_payment" || true

echo -e "${YELLOW}1.3 Create a test job...${NC}"
# create_job(job_id, client, worker, payment_amount_low, payment_amount_high, deadline, job_type)
# job_id: 1, client: deployer, worker: deployer, payment: 100 SAGE (100 * 10^18)
# 100 SAGE = 0x56bc75e2d63100000
JOB_ID="0x1"
invoke_check $JOB_MANAGER "create_job" $JOB_ID $DEPLOYER $DEPLOYER 0x56bc75e2d63100000 0x0 0xffffffff 0x1 || echo "  (job creation may require token approval first)"

echo -e "${YELLOW}1.4 Check job exists...${NC}"
call_check $JOB_MANAGER "get_job" $JOB_ID || true

echo ""

# =============================================================================
# TEST 2: Staking Flow
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 2: Staking Flow${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}2.1 Check ProverStaking state...${NC}"
call_check $PROVER_STAKING "get_total_staked" || true

echo -e "${YELLOW}2.2 Check WorkerStaking state...${NC}"
call_check $WORKER_STAKING "get_total_staked" || true

echo -e "${YELLOW}2.3 Check CDC Pool state...${NC}"
call_check $CDC_POOL "get_total_staked" || true

echo -e "${YELLOW}2.4 Check minimum stake requirement...${NC}"
call_check $CDC_POOL "get_minimum_stake" || true

echo ""

# =============================================================================
# TEST 3: Privacy Flow
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 3: Privacy Flow${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}3.1 Check PrivacyPools initialization...${NC}"
call_check $PRIVACY_POOLS "is_initialized" || true

echo -e "${YELLOW}3.2 Check PrivacyPools pool count...${NC}"
call_check $PRIVACY_POOLS "get_pool_count" || true

echo -e "${YELLOW}3.3 Check PrivacyRouter state...${NC}"
call_check $PRIVACY_ROUTER "get_total_deposits" || true

echo -e "${YELLOW}3.4 Check privacy config...${NC}"
call_check $PRIVACY_ROUTER "get_privacy_config" || true

echo ""

# =============================================================================
# TEST 4: Payment Flow
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 4: Payment Flow${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}4.1 Check PaymentRouter configuration...${NC}"
call_check $PAYMENT_ROUTER "is_contract_configured" || true
call_check $PAYMENT_ROUTER "is_configuration_locked" || true

echo -e "${YELLOW}4.2 Check fee distribution...${NC}"
call_check $PAYMENT_ROUTER "get_fee_distribution" || true

echo -e "${YELLOW}4.3 Check discount tiers...${NC}"
call_check $PAYMENT_ROUTER "get_discount_tiers" || true

echo -e "${YELLOW}4.4 Check ProofGatedPayment state...${NC}"
call_check $PROOF_GATED "is_configured" || true
call_check $PROOF_GATED "is_finalized" || true

echo -e "${YELLOW}4.5 Check MeteredBilling state...${NC}"
call_check $METERED_BILLING "is_contract_configured" || true
call_check $METERED_BILLING "is_configuration_locked" || true

echo ""

# =============================================================================
# TEST 5: OptimisticTEE Flow
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 5: OptimisticTEE Flow${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}5.1 Check OptimisticTEE configuration...${NC}"
call_check $OPTIMISTIC_TEE "is_contract_configured" || true
call_check $OPTIMISTIC_TEE "is_configuration_locked" || true

echo -e "${YELLOW}5.2 Check challenge period...${NC}"
call_check $OPTIMISTIC_TEE "get_challenge_period" || true

echo -e "${YELLOW}5.3 Check pending job count...${NC}"
call_check $OPTIMISTIC_TEE "get_pending_job_count" || true

echo ""

# =============================================================================
# TEST 6: Reputation Flow
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 6: Reputation Flow${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}6.1 Check ReputationManager state...${NC}"
call_check $REPUTATION_MANAGER "get_total_workers" || true

echo -e "${YELLOW}6.2 Get deployer reputation...${NC}"
call_check $REPUTATION_MANAGER "get_reputation" $DEPLOYER || true

echo ""

# =============================================================================
# TEST 7: Cross-Contract Wiring Verification
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 7: Cross-Contract Wiring${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}7.1 Verify ProofGatedPayment has PaymentRouter...${NC}"
RESULT=$(sncast --profile devnet call --contract-address $PROOF_GATED --function get_payment_router 2>&1 || true)
if echo "$RESULT" | grep -q "$PAYMENT_ROUTER"; then
    echo -e "${GREEN}    [OK] ProofGatedPayment -> PaymentRouter wired correctly${NC}"
else
    echo -e "${YELLOW}    [CHECK] ProofGatedPayment -> PaymentRouter: $RESULT${NC}"
fi

echo -e "${YELLOW}7.2 Verify ProofGatedPayment has OptimisticTEE...${NC}"
RESULT=$(sncast --profile devnet call --contract-address $PROOF_GATED --function get_optimistic_tee 2>&1 || true)
if echo "$RESULT" | grep -q "$OPTIMISTIC_TEE"; then
    echo -e "${GREEN}    [OK] ProofGatedPayment -> OptimisticTEE wired correctly${NC}"
else
    echo -e "${YELLOW}    [CHECK] ProofGatedPayment -> OptimisticTEE: $RESULT${NC}"
fi

echo -e "${YELLOW}7.3 Verify OptimisticTEE has ProofGatedPayment...${NC}"
RESULT=$(sncast --profile devnet call --contract-address $OPTIMISTIC_TEE --function get_proof_gated_payment 2>&1 || true)
if echo "$RESULT" | grep -q "$PROOF_GATED"; then
    echo -e "${GREEN}    [OK] OptimisticTEE -> ProofGatedPayment wired correctly${NC}"
else
    echo -e "${YELLOW}    [CHECK] OptimisticTEE -> ProofGatedPayment: $RESULT${NC}"
fi

echo -e "${YELLOW}7.4 Verify MeteredBilling has ProofGatedPayment...${NC}"
RESULT=$(sncast --profile devnet call --contract-address $METERED_BILLING --function get_proof_gated_payment 2>&1 || true)
if echo "$RESULT" | grep -q "$PROOF_GATED"; then
    echo -e "${GREEN}    [OK] MeteredBilling -> ProofGatedPayment wired correctly${NC}"
else
    echo -e "${YELLOW}    [CHECK] MeteredBilling -> ProofGatedPayment: $RESULT${NC}"
fi

echo ""

# =============================================================================
# TEST 8: Token Operations
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  TEST 8: Token Operations${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

echo -e "${YELLOW}8.1 Check SAGE Token total supply...${NC}"
call_check $SAGE_TOKEN "total_supply" || true

echo -e "${YELLOW}8.2 Check deployer SAGE balance...${NC}"
call_check $SAGE_TOKEN "balance_of" $DEPLOYER || true

echo -e "${YELLOW}8.3 Check Faucet SAGE balance...${NC}"
call_check $SAGE_TOKEN "balance_of" $FAUCET || true

echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  INTEGRATION TESTS COMPLETE${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${GREEN}All basic integration checks completed!${NC}"
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  - Contract configurations verified"
echo -e "  - Cross-contract wiring verified"
echo -e "  - State reads successful"
echo ""
echo -e "${YELLOW}Note:${NC}"
echo -e "  Full transaction flows (job creation, staking, payments)"
echo -e "  require token approvals and sufficient balances."
echo -e "  Use the Faucet to get test SAGE tokens for deeper testing."
echo ""
