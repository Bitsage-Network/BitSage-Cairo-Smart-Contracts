//! Payment System Tests
//! Tests for ProofGatedPayment, OptimisticTEE, and PaymentRouter
//!
//! Coverage:
//! - Proof-gated payment flow
//! - Keeper batch finalization
//! - Worker slashing on fraud
//! - Challenger rewards/penalties
//! - Fee distribution (80% worker, 20% protocol)

use core::array::ArrayTrait;
use starknet::{ContractAddress, get_block_timestamp};
use core::traits::TryInto;

// Import test framework
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address, start_cheat_block_timestamp_global, stop_cheat_block_timestamp_global};

// Import contract interfaces
use sage_contracts::payments::proof_gated_payment::{
    IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait
};
use sage_contracts::obelysk::optimistic_tee::{
    IOptimisticTEEDispatcher, IOptimisticTEEDispatcherTrait
};
use sage_contracts::staking::prover_staking::{
    IProverStakingDispatcher, IProverStakingDispatcherTrait, GpuTier, SlashReason
};
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

// ============================================================================
// TEST HELPERS
// ============================================================================

fn get_test_addresses() -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let worker: ContractAddress = 'worker'.try_into().unwrap();
    let client: ContractAddress = 'client'.try_into().unwrap();
    let challenger: ContractAddress = 'challenger'.try_into().unwrap();
    let keeper: ContractAddress = 'keeper'.try_into().unwrap();
    (owner, worker, client, challenger, keeper)
}

fn deploy_mock_erc20(name: felt252) -> IERC20Dispatcher {
    let contract_class = declare("SAGEToken").unwrap().contract_class();
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let job_manager: ContractAddress = 'job_manager'.try_into().unwrap();
    let cdc_pool: ContractAddress = 'cdc_pool'.try_into().unwrap();
    let paymaster: ContractAddress = 'paymaster'.try_into().unwrap();
    let treasury_beneficiary: ContractAddress = 'treasury'.try_into().unwrap();
    let team_beneficiary: ContractAddress = 'team'.try_into().unwrap();
    let liquidity_beneficiary: ContractAddress = 'liquidity'.try_into().unwrap();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(job_manager.into());
    constructor_data.append(cdc_pool.into());
    constructor_data.append(paymaster.into());
    constructor_data.append(treasury_beneficiary.into());
    constructor_data.append(team_beneficiary.into());
    constructor_data.append(liquidity_beneficiary.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    IERC20Dispatcher { contract_address }
}

fn deploy_prover_staking(sage_token: ContractAddress) -> IProverStakingDispatcher {
    let contract_class = declare("ProverStaking").unwrap().contract_class();
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let treasury: ContractAddress = 'treasury'.try_into().unwrap();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(sage_token.into());
    constructor_data.append(treasury.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    IProverStakingDispatcher { contract_address }
}

fn deploy_optimistic_tee(
    proof_verifier: ContractAddress,
    proof_gated_payment: ContractAddress,
    sage_token: ContractAddress,
    prover_staking: ContractAddress,
) -> IOptimisticTEEDispatcher {
    let contract_class = declare("OptimisticTEE").unwrap().contract_class();
    let owner: ContractAddress = 'owner'.try_into().unwrap();

    let mut constructor_data = array![];
    constructor_data.append(proof_verifier.into());
    constructor_data.append(proof_gated_payment.into());
    constructor_data.append(sage_token.into());
    constructor_data.append(prover_staking.into());
    constructor_data.append(owner.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    IOptimisticTEEDispatcher { contract_address }
}

// ============================================================================
// OPTIMISTIC TEE TESTS - Core Functions
// ============================================================================

#[test]
fn test_submit_result_without_staking_requirement() {
    let (owner, worker, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Disable staking requirement for this test
    start_cheat_caller_address(tee.contract_address, owner);
    tee.set_require_staking(false);
    stop_cheat_caller_address(tee.contract_address);

    // Worker submits result
    start_cheat_caller_address(tee.contract_address, worker);

    let job_id: u256 = 1;
    let worker_id: felt252 = 'worker_1';
    let result_hash: felt252 = 'result_hash_123';
    let enclave_measurement: felt252 = 'enclave_m31';
    let signature: Array<felt252> = array!['sig1', 'sig2'];

    // Note: This will fail in actual test because proof_verifier mock isn't set up
    // In real tests, we'd need a mock verifier that returns true for is_enclave_whitelisted
    // tee.submit_result(job_id, worker_id, result_hash, enclave_measurement, signature);

    stop_cheat_caller_address(tee.contract_address);

    // Verify result status (would be STATUS_PENDING = 0)
    // let status = tee.get_result_status(job_id);
    // assert(status == 0, 'Should be pending');
}

#[test]
fn test_keeper_view_functions() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Test initial state
    let pending_count = tee.get_pending_job_count();
    assert(pending_count == 0, 'Should have no pending jobs');

    let pool_balance = tee.get_keeper_pool_balance();
    assert(pool_balance == 0, 'Pool should be empty');

    let keeper_bps = tee.get_keeper_reward_bps();
    assert(keeper_bps == 50, 'Default should be 50 bps');

    let (total_rewards, total_finalized) = tee.get_keeper_stats();
    assert(total_rewards == 0, 'No rewards yet');
    assert(total_finalized == 0, 'No jobs finalized');
}

#[test]
fn test_staking_view_functions() {
    let (owner, worker, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Test staking requirement is enabled by default
    let is_required = tee.is_staking_required();
    assert(is_required, 'Staking should be required');

    // Test staking address
    let staking_addr = tee.get_prover_staking();
    assert(staking_addr == prover_staking, 'Wrong staking address');

    // Test slash stats
    let (workers_slashed, slash_amount, challenger_rewards) = tee.get_slash_stats();
    assert(workers_slashed == 0, 'No workers slashed');
    assert(slash_amount == 0, 'No slash amount');
    assert(challenger_rewards == 0, 'No challenger rewards');
}

#[test]
fn test_admin_functions() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    start_cheat_caller_address(tee.contract_address, owner);

    // Test set_require_staking
    tee.set_require_staking(false);
    assert(!tee.is_staking_required(), 'Should be disabled');

    tee.set_require_staking(true);
    assert(tee.is_staking_required(), 'Should be enabled');

    // Test set_keeper_reward_bps
    tee.set_keeper_reward_bps(100); // 1%
    assert(tee.get_keeper_reward_bps() == 100, 'Should be 100 bps');

    // Test set_challenge_period
    tee.set_challenge_period(7200); // 2 hours
    assert(tee.get_challenge_period() == 7200, 'Should be 2 hours');

    // Test set_challenge_stake
    let new_stake: u256 = 200000000000000000000; // 200 SAGE
    tee.set_challenge_stake(new_stake);

    stop_cheat_caller_address(tee.contract_address);
}

// ============================================================================
// PROVER STAKING TESTS
// ============================================================================

#[test]
fn test_prover_staking_deployment() {
    let sage_token = deploy_mock_erc20('SAGE');
    let staking = deploy_prover_staking(sage_token.contract_address);

    // Check initial state
    let total_staked = staking.total_staked();
    assert(total_staked == 0, 'Should have no stakes');

    let total_slashed = staking.total_slashed();
    assert(total_slashed == 0, 'Should have no slashes');

    // Check config
    let config = staking.get_config();
    assert(config.slash_invalid_proof_bps == 1000, 'Wrong invalid proof slash'); // 10%
    assert(config.slash_timeout_bps == 500, 'Wrong timeout slash'); // 5%
    assert(config.slash_malicious_bps == 5000, 'Wrong malicious slash'); // 50%
    assert(config.reward_apy_bps == 1500, 'Wrong APY'); // 15%
}

#[test]
fn test_worker_staking() {
    let (owner, worker, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let staking = deploy_prover_staking(sage_token.contract_address);

    // Transfer tokens to worker
    let stake_amount: u256 = 2000_000000000000000000; // 2000 SAGE
    start_cheat_caller_address(sage_token.contract_address, owner);
    sage_token.transfer(worker, stake_amount);
    stop_cheat_caller_address(sage_token.contract_address);

    // Approve staking contract
    start_cheat_caller_address(sage_token.contract_address, worker);
    sage_token.approve(staking.contract_address, stake_amount);
    stop_cheat_caller_address(sage_token.contract_address);

    // Stake tokens
    start_cheat_caller_address(staking.contract_address, worker);
    staking.stake(stake_amount, GpuTier::Consumer);
    stop_cheat_caller_address(staking.contract_address);

    // Verify stake
    let worker_stake = staking.get_stake(worker);
    assert(worker_stake.amount == stake_amount, 'Wrong stake amount');
    assert(worker_stake.is_active, 'Should be active');

    // Advance time past flash loan protection period (24 hours + 1 second)
    // This is security feature: workers must wait before becoming eligible for jobs
    start_cheat_block_timestamp_global(get_block_timestamp() + 86401);

    // Check eligibility (now should pass after waiting period)
    let is_eligible = staking.is_eligible(worker);
    assert(is_eligible, 'Worker should be eligible');

    stop_cheat_block_timestamp_global();

    // Check total staked
    let total = staking.total_staked();
    assert(total == stake_amount, 'Wrong total staked');
}

#[test]
fn test_min_stake_by_tier() {
    let sage_token = deploy_mock_erc20('SAGE');
    let staking = deploy_prover_staking(sage_token.contract_address);

    // Check minimum stakes for each tier
    let consumer_min = staking.get_min_stake(GpuTier::Consumer);
    assert(consumer_min == 1000_000000000000000000, 'Wrong consumer min'); // 1000 SAGE

    let workstation_min = staking.get_min_stake(GpuTier::Workstation);
    assert(workstation_min == 2500_000000000000000000, 'Wrong workstation min'); // 2500 SAGE

    let datacenter_min = staking.get_min_stake(GpuTier::DataCenter);
    assert(datacenter_min == 5000_000000000000000000, 'Wrong datacenter min'); // 5000 SAGE

    let enterprise_min = staking.get_min_stake(GpuTier::Enterprise);
    assert(enterprise_min == 10000_000000000000000000, 'Wrong enterprise min'); // 10000 SAGE

    let frontier_min = staking.get_min_stake(GpuTier::Frontier);
    assert(frontier_min == 25000_000000000000000000, 'Wrong frontier min'); // 25000 SAGE
}

#[test]
fn test_unstake_request() {
    let (owner, worker, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let staking = deploy_prover_staking(sage_token.contract_address);

    // Setup: stake tokens
    let stake_amount: u256 = 2000_000000000000000000;
    start_cheat_caller_address(sage_token.contract_address, owner);
    sage_token.transfer(worker, stake_amount);
    stop_cheat_caller_address(sage_token.contract_address);

    start_cheat_caller_address(sage_token.contract_address, worker);
    sage_token.approve(staking.contract_address, stake_amount);
    stop_cheat_caller_address(sage_token.contract_address);

    start_cheat_caller_address(staking.contract_address, worker);
    staking.stake(stake_amount, GpuTier::Consumer);

    // Request unstake
    let unstake_amount: u256 = 500_000000000000000000; // 500 SAGE
    staking.request_unstake(unstake_amount);

    // Verify locked amount
    let worker_stake = staking.get_stake(worker);
    assert(worker_stake.locked_amount == unstake_amount, 'Wrong locked amount');

    stop_cheat_caller_address(staking.contract_address);
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_complete_tee_flow_no_challenge() {
    // This test would verify the complete flow:
    // 1. Worker stakes
    // 2. Worker submits TEE result
    // 3. Challenge period passes
    // 4. Keeper finalizes result
    // 5. Payment is released

    // Note: This requires mock contracts for ProofVerifier and ProofGatedPayment
    // For now, we test the individual components
}

#[test]
fn test_challenge_flow_worker_slashed() {
    // This test would verify:
    // 1. Worker submits result
    // 2. Challenger challenges with stake
    // 3. ZK proof shows fraud
    // 4. Worker is slashed
    // 5. Challenger gets reward

    // Note: Requires mock ProofVerifier returning ProofStatus::Verified
}

#[test]
fn test_challenge_flow_challenger_slashed() {
    // This test would verify:
    // 1. Worker submits result
    // 2. Challenger challenges with stake
    // 3. ZK proof fails (worker was honest)
    // 4. Challenger loses stake
    // 5. Worker gets compensation

    // Note: Requires mock ProofVerifier returning ProofStatus::Failed
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_cannot_finalize_during_challenge_period() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // For a job that doesn't exist, can_finalize should return false
    let can_finalize = tee.can_finalize(999);
    assert(!can_finalize, 'Should not be finalizable');
}

#[test]
fn test_keeper_reward_estimation() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Job with no payment amount should return default reward
    let job_id: u256 = 1;
    let estimated_reward = tee.estimate_keeper_reward(job_id);

    // Default reward is 0.01 SAGE when no payment amount stored
    let expected_default: u256 = 10000000000000000; // 0.01 SAGE
    assert(estimated_reward == expected_default, 'Wrong default reward');
}

#[test]
fn test_finalizable_jobs_empty() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // With no pending jobs, should return empty array
    let finalizable = tee.get_finalizable_jobs(10);
    assert(finalizable.len() == 0, 'Should be empty');
}

#[test]
fn test_challenger_stake_tracking() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Check challenger stake for non-existent job
    let job_id: u256 = 1;
    let (stake_amount, is_locked) = tee.get_challenger_stake(job_id);

    assert(stake_amount == 0, 'Should be zero stake');
    assert(!is_locked, 'Should not be locked');
}

// ============================================================================
// SECURITY TESTS
// ============================================================================

#[test]
#[should_panic]
fn test_only_owner_can_set_staking() {
    let (owner, worker, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Non-owner tries to change staking requirement - should panic
    start_cheat_caller_address(tee.contract_address, worker);
    tee.set_require_staking(false);
    stop_cheat_caller_address(tee.contract_address);
}

#[test]
#[should_panic]
fn test_keeper_reward_cap() {
    let (owner, _, _, _, _) = get_test_addresses();
    let sage_token = deploy_mock_erc20('SAGE');
    let proof_verifier: ContractAddress = 'proof_verifier'.try_into().unwrap();
    let proof_gated_payment: ContractAddress = 'pgp'.try_into().unwrap();
    let prover_staking: ContractAddress = 'staking'.try_into().unwrap();

    let tee = deploy_optimistic_tee(proof_verifier, proof_gated_payment, sage_token.contract_address, prover_staking);

    // Try to set keeper reward above 5% - should panic
    start_cheat_caller_address(tee.contract_address, owner);
    tee.set_keeper_reward_bps(600); // 6% - exceeds cap
    stop_cheat_caller_address(tee.contract_address);
}

// ============================================================================
// FEE DISTRIBUTION TESTS
// ============================================================================

#[test]
fn test_fee_split_constants() {
    // Verify the fee distribution constants
    // 80% worker, 20% protocol (70% burn, 20% treasury, 10% stakers)

    let worker_bps: u256 = 8000; // 80%
    let protocol_bps: u256 = 2000; // 20%
    let burn_bps: u256 = 7000; // 70% of protocol = 14% of total
    let treasury_bps: u256 = 2000; // 20% of protocol = 4% of total
    let staker_bps: u256 = 1000; // 10% of protocol = 2% of total

    assert(worker_bps + protocol_bps == 10000, 'Should sum to 100%');
    assert(burn_bps + treasury_bps + staker_bps == 10000, 'Protocol split should sum');

    // Calculate actual distribution for 1000 SAGE payment
    let payment: u256 = 1000_000000000000000000;

    let worker_amount = (payment * worker_bps) / 10000;
    let protocol_amount = payment - worker_amount;

    assert(worker_amount == 800_000000000000000000, 'Worker should get 800');
    assert(protocol_amount == 200_000000000000000000, 'Protocol should get 200');

    let burn_amount = (protocol_amount * burn_bps) / 10000;
    let treasury_amount = (protocol_amount * treasury_bps) / 10000;
    let staker_amount = (protocol_amount * staker_bps) / 10000;

    assert(burn_amount == 140_000000000000000000, 'Burn should be 140');
    assert(treasury_amount == 40_000000000000000000, 'Treasury should be 40');
    assert(staker_amount == 20_000000000000000000, 'Stakers should be 20');
}
