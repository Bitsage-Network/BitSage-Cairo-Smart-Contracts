//! CDCPool Tests
//! Tests for worker management, staking, job allocation, and slashing

use core::array::ArrayTrait;
use starknet::ContractAddress;
use core::traits::TryInto;

use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address
};

use sage_contracts::interfaces::cdc_pool::{
    ICDCPoolDispatcher, ICDCPoolDispatcherTrait,
    WorkerCapabilities, StakeInfo
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

// =============================================================================
// Initial State Tests
// =============================================================================

#[test]
fn test_initial_active_worker_count() {
    let cdc_pool = deploy_cdc_pool();

    // get_active_workers_count returns the count of active workers
    let active = cdc_pool.get_active_workers_count();
    assert(active == 0, 'Should have 0 active workers');
}

#[test]
fn test_initial_network_stats() {
    let cdc_pool = deploy_cdc_pool();

    // get_network_stats returns (total_workers, active_workers, total_staked, completed_jobs)
    let (total_workers, active_workers, total_staked, _) = cdc_pool.get_network_stats();
    assert(total_workers == 0, 'Should have 0 total workers');
    assert(active_workers == 0, 'Should have 0 active workers');
    assert(total_staked == 0, 'Should have 0 staked');
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
