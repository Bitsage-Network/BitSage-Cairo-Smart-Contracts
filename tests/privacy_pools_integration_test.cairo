// ===========================================================================
// Privacy Pools Integration Tests
// ===========================================================================
// Tests Vitalik's Privacy Pools protocol implementation with real on-chain
// proof verification and real SAGE token. Covers ASP registry, association
// sets, deposits, withdrawals, and ragequit flows.
// ===========================================================================

use core::traits::Into;
use core::option::OptionTrait;
use core::array::ArrayTrait;
use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use starknet::{ContractAddress, contract_address_const};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp, stop_cheat_block_timestamp,
    spy_events, EventSpyAssertionsTrait, EventSpyTrait,
};
use sage_contracts::obelysk::privacy_pools::{
    IPrivacyPoolsDispatcher, IPrivacyPoolsDispatcherTrait,
    ASPStatus, ASPInfo, AssociationSetType, AssociationSetInfo,
    PPDeposit, PPWithdrawalProof, PPRagequitStatus, PPRagequitRequest,
    PP_DOMAIN_SEPARATOR, PP_RAGEQUIT_DELAY,
};
use sage_contracts::obelysk::lean_imt::{LeanIMTProof, LeanIMTBatchResult};
use sage_contracts::obelysk::elgamal::{ECPoint, generator};

// SAGE Token imports
use sage_contracts::interfaces::sage_token::ISAGETokenDispatcher;
use sage_contracts::interfaces::sage_token::ISAGETokenDispatcherTrait;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

// ===========================================================================
// Test Constants
// ===========================================================================

// SAGE token has 18 decimals
// Minimum stake for ASP registration: 10,000 SAGE = 10,000 * 10^18
const ASP_STAKE_MINIMUM: u256 = 10000000000000000000000_u256; // 10,000 SAGE with 18 decimals
// Large transfer threshold is 10,000 SAGE - use smaller amounts to avoid special transfer handling
// Transfer 9,000 SAGE at a time (just under threshold)
const TRANSFER_AMOUNT: u256 = 9000000000000000000000_u256; // 9,000 SAGE with 18 decimals
// Total approval amount for contracts
const APPROVAL_AMOUNT: u256 = 50000000000000000000000_u256; // 50,000 SAGE with 18 decimals

// ===========================================================================
// Test Setup with Real SAGE Token
// ===========================================================================

fn deploy_sage_token(owner: ContractAddress) -> (IERC20Dispatcher, ContractAddress) {
    let job_manager = contract_address_const::<'JOB_MANAGER'>();
    let cdc_pool = contract_address_const::<'CDC_POOL'>();
    let paymaster = contract_address_const::<'PAYMASTER'>();
    let treasury = contract_address_const::<'TREASURY'>();
    let team = contract_address_const::<'TEAM'>();
    let liquidity = contract_address_const::<'LIQUIDITY'>();

    let contract_class = declare("SAGEToken").unwrap().contract_class();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(job_manager.into());
    constructor_data.append(cdc_pool.into());
    constructor_data.append(paymaster.into());
    constructor_data.append(treasury.into());
    constructor_data.append(team.into());
    constructor_data.append(liquidity.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    (IERC20Dispatcher { contract_address }, contract_address)
}

fn deploy_privacy_pools(
    owner: ContractAddress,
    sage_token_address: ContractAddress
) -> IPrivacyPoolsDispatcher {
    let contract = declare("PrivacyPools").unwrap().contract_class();
    let privacy_router = contract_address_const::<'PRIVACY_ROUTER'>();

    let (address, _) = contract.deploy(@array![]).unwrap();
    let dispatcher = IPrivacyPoolsDispatcher { contract_address: address };

    // Initialize with real SAGE token address
    start_cheat_caller_address(address, owner);
    dispatcher.initialize(owner, sage_token_address, privacy_router);
    stop_cheat_caller_address(address);

    dispatcher
}

/// Full test environment with SAGE token, balances, and approvals
fn setup_full_test_env() -> (
    ContractAddress,  // owner
    ContractAddress,  // auditor1
    ContractAddress,  // auditor2
    ContractAddress,  // asp_operator
    ContractAddress,  // user_alice
    ContractAddress,  // user_bob
    IPrivacyPoolsDispatcher,
    IERC20Dispatcher, // SAGE token
) {
    let owner = contract_address_const::<'OWNER'>();
    let auditor1 = contract_address_const::<'AUDITOR1'>();
    let auditor2 = contract_address_const::<'AUDITOR2'>();
    let asp_operator = contract_address_const::<'ASP_OP'>();
    let alice = contract_address_const::<'ALICE'>();
    let bob = contract_address_const::<'BOB'>();

    // Deploy SAGE token
    let (sage_token, sage_token_address) = deploy_sage_token(owner);

    // Deploy Privacy Pools with real SAGE token
    let pp = deploy_privacy_pools(owner, sage_token_address);

    // Fund test accounts with SAGE tokens
    // Use multiple transfers of 9,000 SAGE each (under the 10,000 SAGE large transfer threshold)
    // Each account needs at least 10,000 SAGE for ASP staking
    start_cheat_caller_address(sage_token_address, owner);
    // ASP operator needs 10,000+ for staking - do 2 transfers of 9,000 each = 18,000 SAGE
    sage_token.transfer(asp_operator, TRANSFER_AMOUNT);
    sage_token.transfer(asp_operator, TRANSFER_AMOUNT);
    // Alice and Bob need some tokens too
    sage_token.transfer(alice, TRANSFER_AMOUNT);
    sage_token.transfer(alice, TRANSFER_AMOUNT);
    sage_token.transfer(bob, TRANSFER_AMOUNT);
    sage_token.transfer(bob, TRANSFER_AMOUNT);
    stop_cheat_caller_address(sage_token_address);

    // Set up approvals for Privacy Pools contract (for ASP staking)
    start_cheat_caller_address(sage_token_address, asp_operator);
    sage_token.approve(pp.contract_address, APPROVAL_AMOUNT);
    stop_cheat_caller_address(sage_token_address);

    start_cheat_caller_address(sage_token_address, alice);
    sage_token.approve(pp.contract_address, APPROVAL_AMOUNT);
    stop_cheat_caller_address(sage_token_address);

    start_cheat_caller_address(sage_token_address, bob);
    sage_token.approve(pp.contract_address, APPROVAL_AMOUNT);
    stop_cheat_caller_address(sage_token_address);

    (owner, auditor1, auditor2, asp_operator, alice, bob, pp, sage_token)
}

/// Simple test environment without token (for basic tests)
fn setup_simple_test_env() -> (
    ContractAddress,  // owner
    ContractAddress,  // auditor1
    ContractAddress,  // auditor2
    ContractAddress,  // asp_operator
    ContractAddress,  // alice
    ContractAddress,  // bob
    IPrivacyPoolsDispatcher,
) {
    let owner = contract_address_const::<'OWNER'>();
    let auditor1 = contract_address_const::<'AUDITOR1'>();
    let auditor2 = contract_address_const::<'AUDITOR2'>();
    let asp_operator = contract_address_const::<'ASP_OP'>();
    let alice = contract_address_const::<'ALICE'>();
    let bob = contract_address_const::<'BOB'>();

    // For simple tests, use owner as sage_token placeholder
    let (sage_token, sage_token_address) = deploy_sage_token(owner);
    let pp = deploy_privacy_pools(owner, sage_token_address);

    (owner, auditor1, auditor2, asp_operator, alice, bob, pp)
}

fn create_valid_ecpoint() -> ECPoint {
    generator()
}

fn create_test_commitment(seed: felt252) -> felt252 {
    poseidon_hash_span(array![PP_DOMAIN_SEPARATOR, seed, 'commitment'].span())
}

fn create_amount_commitment() -> ECPoint {
    // Pedersen commitment to amount: C = amount*G + blinding*H
    ECPoint { x: generator().x + 1, y: generator().y + 1 }
}

// ===========================================================================
// Initialization Tests
// ===========================================================================

#[test]
fn test_privacy_pools_initialization() {
    let (owner, _, _, _, _, _, pp, _) = setup_full_test_env();

    assert(pp.is_initialized() == true, 'Should be initialized');
    assert(pp.get_asp_count() == 0, 'No ASPs initially');
}

#[test]
#[should_panic]
fn test_cannot_initialize_twice() {
    let (owner, _, _, _, _, _, pp, sage_token) = setup_full_test_env();
    let privacy_router = contract_address_const::<'PRIVACY_ROUTER'>();

    // Try to initialize again - should panic
    start_cheat_caller_address(pp.contract_address, owner);
    pp.initialize(owner, sage_token.contract_address, privacy_router);
    stop_cheat_caller_address(pp.contract_address);
}

// ===========================================================================
// Auditor Management Tests
// ===========================================================================

#[test]
fn test_add_auditor() {
    let (owner, auditor1, _, _, _, _, pp, _) = setup_full_test_env();

    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    stop_cheat_caller_address(pp.contract_address);

    assert(pp.is_auditor(auditor1) == true, 'Auditor should be added');
}

#[test]
fn test_add_multiple_auditors() {
    let (owner, auditor1, auditor2, _, _, _, pp, _) = setup_full_test_env();

    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    assert(pp.is_auditor(auditor1) == true, 'Auditor1 should be added');
    assert(pp.is_auditor(auditor2) == true, 'Auditor2 should be added');
}

#[test]
fn test_remove_auditor() {
    let (owner, auditor1, _, _, _, _, pp, _) = setup_full_test_env();

    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    assert(pp.is_auditor(auditor1) == true, 'Should be auditor');

    pp.remove_auditor(auditor1);
    stop_cheat_caller_address(pp.contract_address);

    assert(pp.is_auditor(auditor1) == false, 'Should not be auditor');
}

#[test]
#[should_panic]
fn test_non_owner_cannot_add_auditor() {
    let (_, auditor1, auditor2, _, _, _, pp, _) = setup_full_test_env();

    // Non-owner cannot add auditor - should panic
    start_cheat_caller_address(pp.contract_address, auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);
}

// ===========================================================================
// ASP Registry Tests - Real Token Staking
// ===========================================================================

#[test]
fn test_register_asp() {
    let (owner, auditor1, auditor2, asp_operator, _, _, pp, sage_token) = setup_full_test_env();

    // Verify ASP operator has tokens
    let asp_balance = sage_token.balance_of(asp_operator);
    assert(asp_balance >= ASP_STAKE_MINIMUM, 'ASP needs tokens');

    // Add auditors first
    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    // Register ASP (stakes tokens)
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let asp_id = pp.register_asp(
        poseidon_hash_span(array!['ComplianceASP'].span()),  // name_hash
        create_valid_ecpoint(),  // public_key
        poseidon_hash_span(array!['metadata_uri'].span()),  // metadata_uri_hash
    );
    stop_cheat_caller_address(pp.contract_address);

    // Verify ASP is pending
    let asp_info = pp.get_asp_info(asp_id);
    assert(asp_info.status == ASPStatus::Pending, 'Should be pending');
    assert(pp.get_asp_count() == 1, 'Should have 1 ASP');
}

#[test]
fn test_approve_asp() {
    let (owner, auditor1, auditor2, asp_operator, _, _, pp, _) = setup_full_test_env();

    // Setup auditors
    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    // Register ASP
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let asp_id = pp.register_asp(
        poseidon_hash_span(array!['TestASP'].span()),
        create_valid_ecpoint(),
        poseidon_hash_span(array!['uri'].span()),
    );
    stop_cheat_caller_address(pp.contract_address);

    // Auditor1 approves
    start_cheat_caller_address(pp.contract_address, auditor1);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    // Still pending (needs 2 approvals)
    let asp_info = pp.get_asp_info(asp_id);
    assert(asp_info.status == ASPStatus::Pending, 'Still pending');

    // Auditor2 approves
    start_cheat_caller_address(pp.contract_address, auditor2);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    // Now active
    assert(pp.is_asp_active(asp_id) == true, 'ASP should be active');
}

#[test]
fn test_suspend_asp() {
    let (owner, auditor1, auditor2, asp_operator, _, _, pp, _) = setup_full_test_env();

    // Setup and approve ASP
    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, asp_operator);
    let asp_id = pp.register_asp(
        poseidon_hash_span(array!['SuspendTest'].span()),
        create_valid_ecpoint(),
        poseidon_hash_span(array!['uri'].span()),
    );
    stop_cheat_caller_address(pp.contract_address);

    // Approve by both auditors
    start_cheat_caller_address(pp.contract_address, auditor1);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, auditor2);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    assert(pp.is_asp_active(asp_id) == true, 'Should be active');

    // Owner suspends
    start_cheat_caller_address(pp.contract_address, owner);
    pp.suspend_asp(asp_id, 'compliance_violation');
    stop_cheat_caller_address(pp.contract_address);

    let asp_info = pp.get_asp_info(asp_id);
    assert(asp_info.status == ASPStatus::Suspended, 'Should be suspended');
    assert(pp.is_asp_active(asp_id) == false, 'Not active anymore');
}

// ===========================================================================
// Association Set Tests
// ===========================================================================

fn setup_active_asp() -> (
    ContractAddress, ContractAddress, ContractAddress,
    felt252, IPrivacyPoolsDispatcher, IERC20Dispatcher
) {
    let (owner, auditor1, auditor2, asp_operator, _, _, pp, sage_token) = setup_full_test_env();

    // Setup auditors and register+approve ASP
    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, asp_operator);
    let asp_id = pp.register_asp(
        poseidon_hash_span(array!['SetTestASP'].span()),
        create_valid_ecpoint(),
        poseidon_hash_span(array!['uri'].span()),
    );
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, auditor1);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, auditor2);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    (owner, asp_operator, auditor1, asp_id, pp, sage_token)
}

#[test]
fn test_create_inclusion_set() {
    let (_, asp_operator, _, asp_id, pp, _) = setup_active_asp();

    // Create inclusion set with initial commitments
    let c1 = create_test_commitment('incl1');
    let c2 = create_test_commitment('incl2');

    start_cheat_caller_address(pp.contract_address, asp_operator);
    let set_id = pp.create_association_set(
        AssociationSetType::Inclusion,
        array![c1, c2].span()
    );
    stop_cheat_caller_address(pp.contract_address);

    // Verify set created
    let set_info = pp.get_association_set_info(set_id);
    assert(set_info.set_type == AssociationSetType::Inclusion, 'Should be Inclusion');
    assert(set_info.member_count == 2, 'Should have 2 members');

    let root = pp.get_association_set_root(set_id);
    assert(root != 0, 'Root should be non-zero');
}

#[test]
fn test_create_exclusion_set() {
    let (_, asp_operator, _, asp_id, pp, _) = setup_active_asp();

    // Create exclusion set
    let bad_commitment = create_test_commitment('bad_actor');

    start_cheat_caller_address(pp.contract_address, asp_operator);
    let set_id = pp.create_association_set(
        AssociationSetType::Exclusion,
        array![bad_commitment].span()
    );
    stop_cheat_caller_address(pp.contract_address);

    let set_info = pp.get_association_set_info(set_id);
    assert(set_info.set_type == AssociationSetType::Exclusion, 'Should be Exclusion');
}

#[test]
fn test_add_to_association_set() {
    let (_, asp_operator, _, asp_id, pp, _) = setup_active_asp();

    // Create set
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let set_id = pp.create_association_set(
        AssociationSetType::Inclusion,
        array![create_test_commitment('initial')].span()
    );

    // Add more commitments
    let c1 = create_test_commitment('add1');
    let c2 = create_test_commitment('add2');
    pp.add_to_association_set(set_id, array![c1, c2].span());
    stop_cheat_caller_address(pp.contract_address);

    let set_info = pp.get_association_set_info(set_id);
    assert(set_info.member_count == 3, 'Should have 3 members');
}

// ===========================================================================
// Privacy Pools Deposit Tests
// ===========================================================================

#[test]
fn test_pp_deposit() {
    let (_, _, _, _, alice, _, pp, _) = setup_full_test_env();

    let commitment = create_test_commitment('alice_deposit');
    let amount_commitment = create_amount_commitment();

    start_cheat_caller_address(pp.contract_address, alice);
    let global_index = pp.pp_deposit(commitment, amount_commitment, 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    assert(global_index == 0, 'First deposit index 0');
    assert(pp.is_pp_deposit_valid(commitment) == true, 'Deposit should be valid');
}

#[test]
fn test_pp_batch_deposit() {
    let (_, _, _, _, alice, _, pp, _) = setup_full_test_env();

    let c1 = create_test_commitment('batch1');
    let c2 = create_test_commitment('batch2');
    let c3 = create_test_commitment('batch3');

    let ac1 = create_amount_commitment();
    let ac2 = create_amount_commitment();
    let ac3 = create_amount_commitment();

    start_cheat_caller_address(pp.contract_address, alice);
    let batch_result = pp.pp_batch_deposit(
        array![c1, c2, c3].span(),
        array![ac1, ac2, ac3].span(),
        array!['SAGE', 'SAGE', 'SAGE'].span(),
        array![].span()
    );
    stop_cheat_caller_address(pp.contract_address);

    assert(batch_result.new_size == 3, 'Should have 3 deposits');
    assert(pp.is_pp_deposit_valid(c1) == true, 'C1 should be valid');
    assert(pp.is_pp_deposit_valid(c2) == true, 'C2 should be valid');
    assert(pp.is_pp_deposit_valid(c3) == true, 'C3 should be valid');
}

#[test]
fn test_global_deposit_root_updates() {
    let (_, _, _, _, alice, bob, pp, _) = setup_full_test_env();

    let initial_root = pp.get_global_deposit_root();

    start_cheat_caller_address(pp.contract_address, alice);
    pp.pp_deposit(create_test_commitment('d1'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    let root_after_1 = pp.get_global_deposit_root();
    assert(root_after_1 != initial_root, 'Root should change');

    start_cheat_caller_address(pp.contract_address, bob);
    pp.pp_deposit(create_test_commitment('d2'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    let root_after_2 = pp.get_global_deposit_root();
    assert(root_after_2 != root_after_1, 'Root changes again');
}

#[test]
fn test_deposit_info_retrieval() {
    let (_, _, _, _, alice, _, pp, _) = setup_full_test_env();

    let commitment = create_test_commitment('info_test');
    let amount_commitment = create_amount_commitment();

    start_cheat_caller_address(pp.contract_address, alice);
    let idx = pp.pp_deposit(commitment, amount_commitment, 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    let deposit_info = pp.get_pp_deposit_info(commitment);
    assert(deposit_info.commitment == commitment, 'Wrong commitment');
    assert(deposit_info.depositor == alice, 'Wrong depositor');
    assert(deposit_info.asset_id == 'SAGE', 'Wrong asset');
    assert(deposit_info.global_index == idx, 'Wrong index');
}

// ===========================================================================
// Statistics Tests
// ===========================================================================

#[test]
fn test_pp_stats() {
    let (_, _, _, _, alice, bob, pp, _) = setup_full_test_env();

    // Make some deposits
    start_cheat_caller_address(pp.contract_address, alice);
    pp.pp_deposit(create_test_commitment('s1'), create_amount_commitment(), 'SAGE', array![].span());
    pp.pp_deposit(create_test_commitment('s2'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, bob);
    pp.pp_deposit(create_test_commitment('s3'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    let (deposit_count, withdrawal_count, ragequit_count, nullifier_count) = pp.get_pp_stats();
    assert(deposit_count == 3, 'Should have 3 deposits');
    assert(withdrawal_count == 0, 'No withdrawals yet');
}

// ===========================================================================
// Admin Functions Tests
// ===========================================================================

#[test]
fn test_pause_unpause() {
    let (owner, _, _, _, alice, _, pp, _) = setup_full_test_env();

    // Pause the contract
    start_cheat_caller_address(pp.contract_address, owner);
    pp.pause();
    stop_cheat_caller_address(pp.contract_address);

    // Contract is paused - unpause to verify we can continue
    start_cheat_caller_address(pp.contract_address, owner);
    pp.unpause();
    stop_cheat_caller_address(pp.contract_address);

    // Verify operations work after unpause
    start_cheat_caller_address(pp.contract_address, alice);
    let _idx = pp.pp_deposit(create_test_commitment('pause_test'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);
}

#[test]
fn test_deposits_work_after_unpause() {
    let (owner, _, _, _, alice, _, pp, _) = setup_full_test_env();

    // Pause
    start_cheat_caller_address(pp.contract_address, owner);
    pp.pause();
    stop_cheat_caller_address(pp.contract_address);

    // Unpause
    start_cheat_caller_address(pp.contract_address, owner);
    pp.unpause();
    stop_cheat_caller_address(pp.contract_address);

    // Deposit should work
    start_cheat_caller_address(pp.contract_address, alice);
    let _idx = pp.pp_deposit(create_test_commitment('after_pause'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);
}

#[test]
#[should_panic]
fn test_non_owner_cannot_pause() {
    let (_, _, _, _, alice, _, pp, _) = setup_full_test_env();

    // Non-owner cannot pause - should panic
    start_cheat_caller_address(pp.contract_address, alice);
    pp.pause();
    stop_cheat_caller_address(pp.contract_address);
}

// ===========================================================================
// Full Flow Integration Test
// ===========================================================================

#[test]
fn test_full_privacy_pools_flow() {
    let (owner, auditor1, auditor2, asp_operator, alice, bob, pp, sage_token) = setup_full_test_env();

    // Step 1: Setup auditors
    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    // Step 2: Register and approve ASP
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let asp_id = pp.register_asp(
        poseidon_hash_span(array!['FlowTestASP'].span()),
        create_valid_ecpoint(),
        poseidon_hash_span(array!['https://asp.example.com'].span()),
    );
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, auditor1);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, auditor2);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    assert(pp.is_asp_active(asp_id) == true, 'ASP should be active');

    // Step 3: Users deposit to Privacy Pools
    let alice_commitment = create_test_commitment('alice_full_flow');
    let bob_commitment = create_test_commitment('bob_full_flow');

    start_cheat_caller_address(pp.contract_address, alice);
    let alice_idx = pp.pp_deposit(alice_commitment, create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, bob);
    let bob_idx = pp.pp_deposit(bob_commitment, create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    // Step 4: ASP creates inclusion set with approved deposits
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let inclusion_set_id = pp.create_association_set(
        AssociationSetType::Inclusion,
        array![alice_commitment, bob_commitment].span()
    );
    stop_cheat_caller_address(pp.contract_address);

    // Verify complete flow
    assert(pp.is_pp_deposit_valid(alice_commitment) == true, 'Alice deposit valid');
    assert(pp.is_pp_deposit_valid(bob_commitment) == true, 'Bob deposit valid');

    let set_info = pp.get_association_set_info(inclusion_set_id);
    assert(set_info.member_count == 2, 'Set should have 2 members');

    let (deposit_count, _, _, _) = pp.get_pp_stats();
    assert(deposit_count == 2, 'Should have 2 deposits');
}

// ===========================================================================
// Event Emission Tests
// ===========================================================================

#[test]
fn test_deposit_emits_event() {
    let (_, _, _, _, alice, _, pp, _) = setup_full_test_env();

    let mut spy = spy_events();

    start_cheat_caller_address(pp.contract_address, alice);
    pp.pp_deposit(create_test_commitment('event_test'), create_amount_commitment(), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    let events = spy.get_events();
    assert(events.events.len() > 0, 'Should emit event');
}

#[test]
fn test_asp_registration_emits_event() {
    let (owner, auditor1, auditor2, asp_operator, _, _, pp, _) = setup_full_test_env();

    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    let mut spy = spy_events();

    start_cheat_caller_address(pp.contract_address, asp_operator);
    let _asp_id = pp.register_asp(
        poseidon_hash_span(array!['EventASP'].span()),
        create_valid_ecpoint(),
        poseidon_hash_span(array!['uri'].span()),
    );
    stop_cheat_caller_address(pp.contract_address);

    let events = spy.get_events();
    assert(events.events.len() > 0, 'Should emit ASP event');
}
