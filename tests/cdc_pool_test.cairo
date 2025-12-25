//! CDCPool Tests
//! Tests for worker management, staking, job allocation, and slashing

use core::array::ArrayTrait;
use starknet::ContractAddress;
use core::traits::TryInto;

use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp_global, stop_cheat_block_timestamp_global
};

use sage_contracts::interfaces::cdc_pool::{
    ICDCPoolDispatcher, ICDCPoolDispatcherTrait,
    WorkerId, JobId, WorkerProfile, WorkerCapabilities, WorkerStatus,
    StakeInfo, SlashReason, ModelRequirements, AllocationResult
};

// =============================================================================
// Test Helpers
// =============================================================================

fn get_test_addresses() -> (ContractAddress, ContractAddress, ContractAddress) {
    let admin: ContractAddress = 'admin'.try_into().unwrap();
    let worker_owner: ContractAddress = 'worker_owner'.try_into().unwrap();
    let sage_token: ContractAddress = 'sage_token'.try_into().unwrap();
    (admin, worker_owner, sage_token)
}

fn deploy_cdc_pool() -> ICDCPoolDispatcher {
    let (admin, _, sage_token) = get_test_addresses();
    let min_stake: u256 = 100_000000000000000000; // 100 SAGE

    let contract_class = declare("CDCPool").unwrap().contract_class();

    let mut constructor_data = array![];
    constructor_data.append(admin.into());
    constructor_data.append(sage_token.into());
    constructor_data.append(min_stake.low.into());
    constructor_data.append(min_stake.high.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    ICDCPoolDispatcher { contract_address }
}

fn create_test_worker_profile() -> WorkerProfile {
    WorkerProfile {
        name: 'TestWorker',
        endpoint_url: 'http://localhost:8080',
        region: 'us-east-1',
        registration_time: 0,
        is_active: true,
    }
}

fn create_test_capabilities() -> WorkerCapabilities {
    WorkerCapabilities {
        gpu_type: 'RTX4090',
        gpu_count: 1,
        vram_gb: 24,
        cpu_cores: 16,
        ram_gb: 64,
        storage_gb: 1000,
        bandwidth_mbps: 1000,
        tee_enabled: false,
        enclave_type: 0,
    }
}

fn create_test_requirements() -> ModelRequirements {
    ModelRequirements {
        min_memory_gb: 8,
        min_compute_units: 100,
        required_gpu_type: 'RTX4090',
        framework_dependencies: array!['pytorch'],
    }
}

// =============================================================================
// Initial State Tests
// =============================================================================

#[test]
fn test_initial_worker_count() {
    let cdc_pool = deploy_cdc_pool();

    let total = cdc_pool.get_total_workers();
    let active = cdc_pool.get_active_workers();

    assert(total == 0, 'Should have 0 total workers');
    assert(active == 0, 'Should have 0 active workers');
}

#[test]
fn test_initial_stake_stats() {
    let cdc_pool = deploy_cdc_pool();

    let total_staked = cdc_pool.get_total_staked();
    assert(total_staked == 0, 'Should have 0 staked');
}

#[test]
fn test_min_stake_set() {
    let cdc_pool = deploy_cdc_pool();

    let min_stake = cdc_pool.get_minimum_stake();
    assert(min_stake == 100_000000000000000000, 'Wrong min stake');
}

// =============================================================================
// Stake Query Tests
// =============================================================================

#[test]
fn test_get_stake_info_unregistered() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    let stake_info = cdc_pool.get_stake_info(worker_owner);
    assert(stake_info.amount == 0, 'Should have 0 stake');
}

#[test]
fn test_get_worker_status_unregistered() {
    let cdc_pool = deploy_cdc_pool();

    let worker_id = WorkerId { value: 999 };
    let status = cdc_pool.get_worker_status(worker_id);

    // Unregistered worker returns default status
    assert(status == WorkerStatus::Inactive, 'Should be inactive');
}

// =============================================================================
// Worker Profile Tests
// =============================================================================

#[test]
fn test_get_worker_profile_unregistered() {
    let cdc_pool = deploy_cdc_pool();

    let worker_id = WorkerId { value: 999 };
    let profile = cdc_pool.get_worker_profile(worker_id);

    assert(profile.name == 0, 'Should have empty name');
}

#[test]
fn test_get_worker_capabilities_unregistered() {
    let cdc_pool = deploy_cdc_pool();

    let worker_id = WorkerId { value: 999 };
    let caps = cdc_pool.get_worker_capabilities(worker_id);

    assert(caps.gpu_count == 0, 'Should have 0 GPUs');
}

// =============================================================================
// Job Allocation Validation Tests
// =============================================================================

#[test]
#[should_panic(expected: ('Priority must be 0-10',))]
fn test_allocate_job_invalid_priority() {
    let cdc_pool = deploy_cdc_pool();

    let job_id = JobId { value: 1 };
    let requirements = create_test_requirements();

    cdc_pool.allocate_job(job_id, requirements, 15, 3600); // Priority 15 > 10
}

#[test]
#[should_panic(expected: ('Max latency must be positive',))]
fn test_allocate_job_zero_latency() {
    let cdc_pool = deploy_cdc_pool();

    let job_id = JobId { value: 1 };
    let requirements = create_test_requirements();

    cdc_pool.allocate_job(job_id, requirements, 5, 0); // Zero latency
}

#[test]
#[should_panic(expected: ('Max latency exceeds 7 days',))]
fn test_allocate_job_excessive_latency() {
    let cdc_pool = deploy_cdc_pool();

    let job_id = JobId { value: 1 };
    let requirements = create_test_requirements();

    cdc_pool.allocate_job(job_id, requirements, 5, 700000); // > 7 days
}

// =============================================================================
// Rewards Tests
// =============================================================================

#[test]
fn test_calculate_pending_rewards_unregistered() {
    let cdc_pool = deploy_cdc_pool();

    let worker_id = WorkerId { value: 999 };
    let pending = cdc_pool.calculate_pending_rewards(worker_id);

    assert(pending == 0, 'Should have 0 pending');
}

// =============================================================================
// Admin Functions Tests
// =============================================================================

#[test]
fn test_pause_contract() {
    let cdc_pool = deploy_cdc_pool();
    let (admin, _, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, admin);
    cdc_pool.pause_contract();
    stop_cheat_caller_address(cdc_pool.contract_address);
}

#[test]
fn test_resume_contract() {
    let cdc_pool = deploy_cdc_pool();
    let (admin, _, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, admin);
    cdc_pool.pause_contract();
    cdc_pool.resume_contract();
    stop_cheat_caller_address(cdc_pool.contract_address);
}

#[test]
#[should_panic(expected: ('Only admin',))]
fn test_only_admin_pause() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, worker_owner);
    cdc_pool.pause_contract();
}

#[test]
#[should_panic(expected: ('Only admin',))]
fn test_only_admin_resume() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, worker_owner);
    cdc_pool.resume_contract();
}

#[test]
#[should_panic(expected: ('Only admin',))]
fn test_only_admin_emergency_remove() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, worker_owner);
    let worker_id = WorkerId { value: 1 };
    cdc_pool.emergency_remove_worker(worker_id, 'violation');
}

// =============================================================================
// Slashing Tests
// =============================================================================

#[test]
#[should_panic(expected: ('Only admin can slash',))]
fn test_only_admin_slash() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, worker_owner);

    let worker_id = WorkerId { value: 1 };
    cdc_pool.slash_worker(worker_id, SlashReason::Offline, array![]);
}

#[test]
#[should_panic(expected: ('Only admin can resolve',))]
fn test_only_admin_resolve_challenge() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    start_cheat_caller_address(cdc_pool.contract_address, worker_owner);

    let worker_id = WorkerId { value: 1 };
    cdc_pool.resolve_slash_challenge(worker_id, true);
}

// =============================================================================
// Unstaking Request Tests
// =============================================================================

#[test]
fn test_get_unstaking_requests_empty() {
    let cdc_pool = deploy_cdc_pool();
    let (_, worker_owner, _) = get_test_addresses();

    let requests = cdc_pool.get_unstaking_requests(worker_owner);
    assert(requests.len() == 0, 'Should have no requests');
}
