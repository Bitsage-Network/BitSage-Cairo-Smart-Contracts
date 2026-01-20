//! JobManager Tests
//! Tests for job submission, cancellation, assignment, and lifecycle

use core::array::ArrayTrait;
use starknet::ContractAddress;
use core::traits::TryInto;

use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address
};

use sage_contracts::interfaces::job_manager::{
    IJobManagerDispatcher, IJobManagerDispatcherTrait,
    JobId, WorkerId, JobState
};

// =============================================================================
// Test Helpers
// =============================================================================

fn get_test_addresses() -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let client: ContractAddress = 'client'.try_into().unwrap();
    let worker: ContractAddress = 'worker'.try_into().unwrap();
    let payment_token: ContractAddress = 'payment_token'.try_into().unwrap();
    (owner, client, worker, payment_token)
}

fn deploy_job_manager() -> IJobManagerDispatcher {
    let (owner, _, _, payment_token) = get_test_addresses();
    let treasury: ContractAddress = 'treasury'.try_into().unwrap();
    let cdc_pool: ContractAddress = 'cdc_pool'.try_into().unwrap();

    let contract_class = declare("JobManager").unwrap().contract_class();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(payment_token.into());
    constructor_data.append(treasury.into());
    constructor_data.append(cdc_pool.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    IJobManagerDispatcher { contract_address }
}

// =============================================================================
// Basic Configuration Tests
// =============================================================================

#[test]
fn test_initial_stats() {
    let job_manager = deploy_job_manager();

    let total_jobs = job_manager.get_total_jobs();
    let active_jobs = job_manager.get_active_jobs();
    let completed_jobs = job_manager.get_completed_jobs();

    assert(total_jobs == 0, 'Should have 0 total jobs');
    assert(active_jobs == 0, 'Should have 0 active jobs');
    assert(completed_jobs == 0, 'Should have 0 completed jobs');
}

#[test]
fn test_is_not_paused_initially() {
    let job_manager = deploy_job_manager();
    assert(!job_manager.is_paused(), 'Should not be paused');
}

#[test]
fn test_get_platform_config() {
    let job_manager = deploy_job_manager();
    let (fee_bps, min_payment, max_duration, _dispute_fee) = job_manager.get_platform_config();

    assert(fee_bps > 0, 'Fee BPS should be set');
    assert(min_payment > 0, 'Min payment should be set');
    assert(max_duration > 0, 'Max duration should be set');
}

// =============================================================================
// Admin Tests
// =============================================================================

#[test]
fn test_pause_unpause() {
    let job_manager = deploy_job_manager();
    let (owner, _, _, _) = get_test_addresses();

    start_cheat_caller_address(job_manager.contract_address, owner);

    job_manager.pause();
    assert(job_manager.is_paused(), 'Should be paused');

    job_manager.unpause();
    assert(!job_manager.is_paused(), 'Should be unpaused');

    stop_cheat_caller_address(job_manager.contract_address);
}

#[test]
fn test_update_config() {
    let job_manager = deploy_job_manager();
    let (owner, _, _, _) = get_test_addresses();

    start_cheat_caller_address(job_manager.contract_address, owner);

    // Update platform fee
    job_manager.update_config('platform_fee_bps', 500);

    stop_cheat_caller_address(job_manager.contract_address);
}

// =============================================================================
// Worker Registration Tests
// =============================================================================

#[test]
fn test_register_worker() {
    let job_manager = deploy_job_manager();
    let (owner, _, worker, _) = get_test_addresses();

    start_cheat_caller_address(job_manager.contract_address, owner);

    let worker_id = WorkerId { value: 1 };
    job_manager.register_worker(worker_id, worker);

    let registered_address = job_manager.get_worker_address(worker_id);
    assert(registered_address == worker, 'Worker not registered');

    stop_cheat_caller_address(job_manager.contract_address);
}

#[test]
fn test_get_worker_count() {
    let job_manager = deploy_job_manager();
    let (owner, _, worker, _) = get_test_addresses();

    start_cheat_caller_address(job_manager.contract_address, owner);

    let initial_count = job_manager.get_worker_count();

    let worker_id = WorkerId { value: 1 };
    job_manager.register_worker(worker_id, worker);

    let new_count = job_manager.get_worker_count();
    assert(new_count == initial_count + 1, 'Worker count not incremented');

    stop_cheat_caller_address(job_manager.contract_address);
}

// =============================================================================
// Job State Tests
// =============================================================================

#[test]
fn test_get_job_details_nonexistent() {
    let job_manager = deploy_job_manager();

    let job_id = JobId { value: 999 };
    let details = job_manager.get_job_details(job_id);

    // For nonexistent jobs, client address should be zero
    let zero_address: starknet::ContractAddress = 0.try_into().unwrap();
    assert(details.client == zero_address, 'Should return empty job');
}

// =============================================================================
// Job Cancellation Tests
// =============================================================================

#[test]
fn test_can_cancel_nonexistent_job() {
    let job_manager = deploy_job_manager();

    let job_id = JobId { value: 999 };
    let can_cancel = job_manager.can_cancel_job(job_id);

    assert(!can_cancel, 'Should not be cancellable');
}

// =============================================================================
// Gas Estimation Tests
// =============================================================================

#[test]
fn test_get_job_gas_efficiency_nonexistent() {
    let job_manager = deploy_job_manager();

    let job_id = JobId { value: 999 };
    let (estimated, reserved, actual) = job_manager.get_job_gas_efficiency(job_id);

    assert(estimated == 0, 'Estimated should be 0');
    assert(reserved == 0, 'Reserved should be 0');
    assert(actual == 0, 'Actual should be 0');
}

// =============================================================================
// Proof Payment Integration Tests
// =============================================================================

#[test]
fn test_is_proof_payment_ready_no_verifier() {
    let job_manager = deploy_job_manager();

    let job_id = JobId { value: 1 };
    // Without proof_gated_payment configured, should return true (legacy mode)
    let is_ready = job_manager.is_proof_payment_ready(job_id);
    assert(is_ready, 'Should be ready in legacy mode');
}

#[test]
fn test_set_proof_gated_payment() {
    let job_manager = deploy_job_manager();
    let (owner, _, _, _) = get_test_addresses();
    let proof_payment: ContractAddress = 'proof_payment'.try_into().unwrap();

    start_cheat_caller_address(job_manager.contract_address, owner);
    job_manager.set_proof_gated_payment(proof_payment);
    stop_cheat_caller_address(job_manager.contract_address);
}
