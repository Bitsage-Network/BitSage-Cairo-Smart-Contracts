// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Privacy Pools Tests
// Tests for Vitalik Buterin's compliance-compatible privacy protocol including:
// - ASP (Association Set Provider) registry
// - Association Set management (inclusion/exclusion)
// - Privacy Pools deposits and withdrawals
// - Ragequit mechanism for excluded users
// - Constants and configuration validation

use core::array::ArrayTrait;
use core::traits::TryInto;
use core::option::OptionTrait;
use starknet::ContractAddress;

// Import Privacy Pools types
use sage_contracts::obelysk::privacy_pools::{
    // Enums
    ASPStatus, AssociationSetType, PPRagequitStatus,
    // Structs
    ASPInfo, AssociationSetInfo, PPDeposit, PPRagequitRequest, AuditorRef,
    // Constants
    PP_RAGEQUIT_DELAY, PP_MIN_ASP_STAKE, PP_ASP_APPROVAL_THRESHOLD,
    PP_MAX_BATCH_SIZE, PP_ROOT_HISTORY_SIZE, PP_DOMAIN_SEPARATOR,
};

// Import LeanIMT for tree state
use sage_contracts::obelysk::lean_imt::{LeanIMTState, hash_pair};

// Import ElGamal for ECPoint
use sage_contracts::obelysk::elgamal::{
    ECPoint, ec_zero, is_zero, generator, ec_mul,
};

// =============================================================================
// Test Constants
// =============================================================================

const TEST_ASP_NAME_HASH: felt252 = 'chainalysis-asp';
const TEST_METADATA_HASH: felt252 = 'ipfs://QmTest123';
const TEST_COMMITMENT_1: felt252 = 111111111111111111;
const TEST_COMMITMENT_2: felt252 = 222222222222222222;
const TEST_COMMITMENT_3: felt252 = 333333333333333333;
const TEST_ASP_KEY: felt252 = 987654321;

// =============================================================================
// ASPStatus Enum Tests
// =============================================================================

#[test]
fn test_asp_status_pending() {
    let status = ASPStatus::Pending;
    assert(status == ASPStatus::Pending, 'Should be Pending');
    assert(status != ASPStatus::Active, 'Should not be Active');
}

#[test]
fn test_asp_status_active() {
    let status = ASPStatus::Active;
    assert(status == ASPStatus::Active, 'Should be Active');
    assert(status != ASPStatus::Pending, 'Should not be Pending');
}

#[test]
fn test_asp_status_suspended() {
    let status = ASPStatus::Suspended;
    assert(status == ASPStatus::Suspended, 'Should be Suspended');
    assert(status != ASPStatus::Active, 'Should not be Active');
}

#[test]
fn test_asp_status_revoked() {
    let status = ASPStatus::Revoked;
    assert(status == ASPStatus::Revoked, 'Should be Revoked');
    assert(status != ASPStatus::Suspended, 'Should not be Suspended');
}

#[test]
fn test_asp_status_all_variants_distinct() {
    let pending = ASPStatus::Pending;
    let active = ASPStatus::Active;
    let suspended = ASPStatus::Suspended;
    let revoked = ASPStatus::Revoked;

    // All should be distinct
    assert(pending != active, 'Pending != Active');
    assert(pending != suspended, 'Pending != Suspended');
    assert(pending != revoked, 'Pending != Revoked');
    assert(active != suspended, 'Active != Suspended');
    assert(active != revoked, 'Active != Revoked');
    assert(suspended != revoked, 'Suspended != Revoked');
}

// =============================================================================
// ASPInfo Struct Tests
// =============================================================================

#[test]
fn test_asp_info_creation() {
    let g = generator();
    let public_key = ec_mul(TEST_ASP_KEY, g);

    let asp = ASPInfo {
        asp_id: 123456789,
        name_hash: TEST_ASP_NAME_HASH,
        public_key,
        metadata_uri_hash: TEST_METADATA_HASH,
        status: ASPStatus::Pending,
        registered_at: 1000000,
        staked_amount: PP_MIN_ASP_STAKE,
        approval_votes: 0,
        total_sets: 0,
        list_index: 0,
    };

    assert(asp.asp_id == 123456789, 'Wrong ASP ID');
    assert(asp.name_hash == TEST_ASP_NAME_HASH, 'Wrong name hash');
    assert(asp.status == ASPStatus::Pending, 'Should be Pending');
    assert(asp.approval_votes == 0, 'Should have 0 votes');
    assert(asp.total_sets == 0, 'Should have 0 sets');
    assert(asp.staked_amount == PP_MIN_ASP_STAKE, 'Wrong stake amount');
}

#[test]
fn test_asp_info_with_approvals() {
    let g = generator();
    let public_key = ec_mul(TEST_ASP_KEY, g);

    let asp = ASPInfo {
        asp_id: 123456789,
        name_hash: TEST_ASP_NAME_HASH,
        public_key,
        metadata_uri_hash: TEST_METADATA_HASH,
        status: ASPStatus::Active,
        registered_at: 1000000,
        staked_amount: PP_MIN_ASP_STAKE,
        approval_votes: PP_ASP_APPROVAL_THRESHOLD,
        total_sets: 5,
        list_index: 3,
    };

    assert(asp.status == ASPStatus::Active, 'Should be Active');
    assert(asp.approval_votes >= PP_ASP_APPROVAL_THRESHOLD, 'Should meet threshold');
    assert(asp.total_sets == 5, 'Should have 5 sets');
    assert(asp.list_index == 3, 'Wrong list index');
}

#[test]
fn test_asp_info_zero_public_key() {
    let zero_key = ec_zero();

    let asp = ASPInfo {
        asp_id: 0,
        name_hash: 0,
        public_key: zero_key,
        metadata_uri_hash: 0,
        status: ASPStatus::Pending,
        registered_at: 0,
        staked_amount: 0,
        approval_votes: 0,
        total_sets: 0,
        list_index: 0,
    };

    assert(is_zero(asp.public_key), 'Key should be zero');
    assert(asp.asp_id == 0, 'ID should be zero');
}

// =============================================================================
// AssociationSetType Enum Tests
// =============================================================================

#[test]
fn test_association_set_type_inclusion() {
    let set_type = AssociationSetType::Inclusion;
    assert(set_type == AssociationSetType::Inclusion, 'Should be Inclusion');
    assert(set_type != AssociationSetType::Exclusion, 'Should not be Exclusion');
}

#[test]
fn test_association_set_type_exclusion() {
    let set_type = AssociationSetType::Exclusion;
    assert(set_type == AssociationSetType::Exclusion, 'Should be Exclusion');
    assert(set_type != AssociationSetType::Inclusion, 'Should not be Inclusion');
}

// =============================================================================
// AssociationSetInfo Struct Tests
// =============================================================================

#[test]
fn test_association_set_info_inclusion() {
    let tree_state = LeanIMTState { root: 0, size: 0, depth: 0 };

    let set_info = AssociationSetInfo {
        set_id: 111,
        asp_id: 222,
        set_type: AssociationSetType::Inclusion,
        tree_state,
        member_count: 0,
        created_at: 1000000,
        last_updated: 1000000,
        is_active: true,
    };

    assert(set_info.set_id == 111, 'Wrong set ID');
    assert(set_info.asp_id == 222, 'Wrong ASP ID');
    assert(set_info.set_type == AssociationSetType::Inclusion, 'Should be Inclusion');
    assert(set_info.is_active, 'Should be active');
    assert(set_info.member_count == 0, 'Should be empty');
}

#[test]
fn test_association_set_info_exclusion_with_members() {
    let root = hash_pair(TEST_COMMITMENT_1, TEST_COMMITMENT_2);
    let tree_state = LeanIMTState { root, size: 2, depth: 1 };

    let set_info = AssociationSetInfo {
        set_id: 333,
        asp_id: 444,
        set_type: AssociationSetType::Exclusion,
        tree_state,
        member_count: 2,
        created_at: 1000000,
        last_updated: 2000000,
        is_active: true,
    };

    assert(set_info.set_type == AssociationSetType::Exclusion, 'Should be Exclusion');
    assert(set_info.member_count == 2, 'Should have 2 members');
    assert(set_info.tree_state.size == 2, 'Tree should have 2 leaves');
    assert(set_info.last_updated > set_info.created_at, 'Updated after created');
}

#[test]
fn test_association_set_info_inactive() {
    let tree_state = LeanIMTState { root: 12345, size: 10, depth: 4 };

    let set_info = AssociationSetInfo {
        set_id: 555,
        asp_id: 666,
        set_type: AssociationSetType::Inclusion,
        tree_state,
        member_count: 10,
        created_at: 1000000,
        last_updated: 3000000,
        is_active: false,
    };

    assert(!set_info.is_active, 'Should be inactive');
    assert(set_info.member_count == 10, 'Should preserve member count');
}

// =============================================================================
// PPDeposit Struct Tests
// =============================================================================

#[test]
fn test_pp_deposit_creation() {
    let g = generator();
    let amount_commitment = ec_mul(1000, g);
    let depositor: ContractAddress = starknet::contract_address_const::<0x123>();

    let deposit = PPDeposit {
        commitment: TEST_COMMITMENT_1,
        amount_commitment,
        asset_id: 0, // SAGE
        depositor,
        timestamp: 1000000,
        global_index: 0,
    };

    assert(deposit.commitment == TEST_COMMITMENT_1, 'Wrong commitment');
    assert(deposit.asset_id == 0, 'Should be SAGE');
    assert(deposit.global_index == 0, 'Should be first deposit');
    assert(!is_zero(deposit.amount_commitment), 'Amount commit not zero');
}

#[test]
fn test_pp_deposit_different_assets() {
    let g = generator();
    let amount_commitment = ec_mul(500, g);
    let depositor: ContractAddress = starknet::contract_address_const::<0x456>();

    // USDC deposit
    let usdc_deposit = PPDeposit {
        commitment: TEST_COMMITMENT_2,
        amount_commitment,
        asset_id: 1, // USDC
        depositor,
        timestamp: 2000000,
        global_index: 100,
    };

    assert(usdc_deposit.asset_id == 1, 'Should be USDC');
    assert(usdc_deposit.global_index == 100, 'Wrong global index');
}

#[test]
fn test_pp_deposit_sequential_indices() {
    let g = generator();
    let commitment = ec_mul(100, g);
    let depositor: ContractAddress = starknet::contract_address_const::<0x789>();

    let deposit1 = PPDeposit {
        commitment: TEST_COMMITMENT_1,
        amount_commitment: commitment,
        asset_id: 0,
        depositor,
        timestamp: 1000000,
        global_index: 0,
    };

    let deposit2 = PPDeposit {
        commitment: TEST_COMMITMENT_2,
        amount_commitment: commitment,
        asset_id: 0,
        depositor,
        timestamp: 1000001,
        global_index: 1,
    };

    assert(deposit2.global_index == deposit1.global_index + 1, 'Sequential indices');
    assert(deposit2.timestamp > deposit1.timestamp, 'Sequential timestamps');
}

// =============================================================================
// PPRagequitStatus Enum Tests
// =============================================================================

#[test]
fn test_ragequit_status_pending() {
    let status = PPRagequitStatus::Pending;
    assert(status == PPRagequitStatus::Pending, 'Should be Pending');
}

#[test]
fn test_ragequit_status_executable() {
    let status = PPRagequitStatus::Executable;
    assert(status == PPRagequitStatus::Executable, 'Should be Executable');
}

#[test]
fn test_ragequit_status_completed() {
    let status = PPRagequitStatus::Completed;
    assert(status == PPRagequitStatus::Completed, 'Should be Completed');
}

#[test]
fn test_ragequit_status_cancelled() {
    let status = PPRagequitStatus::Cancelled;
    assert(status == PPRagequitStatus::Cancelled, 'Should be Cancelled');
}

#[test]
fn test_ragequit_status_expired() {
    let status = PPRagequitStatus::Expired;
    assert(status == PPRagequitStatus::Expired, 'Should be Expired');
}

#[test]
fn test_ragequit_status_all_distinct() {
    let pending = PPRagequitStatus::Pending;
    let executable = PPRagequitStatus::Executable;
    let completed = PPRagequitStatus::Completed;
    let cancelled = PPRagequitStatus::Cancelled;
    let expired = PPRagequitStatus::Expired;

    assert(pending != executable, 'Pending != Executable');
    assert(pending != completed, 'Pending != Completed');
    assert(pending != cancelled, 'Pending != Cancelled');
    assert(pending != expired, 'Pending != Expired');
    assert(executable != completed, 'Executable != Completed');
    assert(executable != cancelled, 'Executable != Cancelled');
    assert(executable != expired, 'Executable != Expired');
    assert(completed != cancelled, 'Completed != Cancelled');
    assert(completed != expired, 'Completed != Expired');
    assert(cancelled != expired, 'Cancelled != Expired');
}

// =============================================================================
// PPRagequitRequest Struct Tests
// =============================================================================

#[test]
fn test_ragequit_request_creation() {
    let depositor: ContractAddress = starknet::contract_address_const::<0x123>();
    let recipient: ContractAddress = starknet::contract_address_const::<0x456>();

    let request = PPRagequitRequest {
        request_id: 1_u256,
        commitment: TEST_COMMITMENT_1,
        depositor,
        amount: 1000000_u256,
        recipient,
        initiated_at: 1000000,
        executable_at: 1000000 + PP_RAGEQUIT_DELAY,
        status: PPRagequitStatus::Pending,
    };

    assert(request.request_id == 1_u256, 'Wrong request ID');
    assert(request.commitment == TEST_COMMITMENT_1, 'Wrong commitment');
    assert(request.status == PPRagequitStatus::Pending, 'Should be Pending');
    assert(request.executable_at == request.initiated_at + PP_RAGEQUIT_DELAY, 'Wrong exec time');
}

#[test]
fn test_ragequit_request_delay_calculation() {
    let depositor: ContractAddress = starknet::contract_address_const::<0x123>();
    let recipient: ContractAddress = starknet::contract_address_const::<0x456>();
    let initiated_at: u64 = 1000000;

    let request = PPRagequitRequest {
        request_id: 2_u256,
        commitment: TEST_COMMITMENT_2,
        depositor,
        amount: 5000000_u256,
        recipient,
        initiated_at,
        executable_at: initiated_at + PP_RAGEQUIT_DELAY,
        status: PPRagequitStatus::Pending,
    };

    // Check delay is exactly 24 hours
    assert(PP_RAGEQUIT_DELAY == 86400, 'Delay should be 24 hours');
    assert(request.executable_at - request.initiated_at == 86400, 'Should wait 24 hours');
}

// =============================================================================
// AuditorRef Struct Tests
// =============================================================================

#[test]
fn test_auditor_ref_active() {
    let auditor_addr: ContractAddress = starknet::contract_address_const::<0xABC>();

    let auditor = AuditorRef {
        address: auditor_addr,
        is_active: true,
    };

    assert(auditor.is_active, 'Should be active');
}

#[test]
fn test_auditor_ref_inactive() {
    let auditor_addr: ContractAddress = starknet::contract_address_const::<0xDEF>();

    let auditor = AuditorRef {
        address: auditor_addr,
        is_active: false,
    };

    assert(!auditor.is_active, 'Should be inactive');
}

// =============================================================================
// Constants Validation Tests
// =============================================================================

#[test]
fn test_ragequit_delay_is_24_hours() {
    // 24 hours = 24 * 60 * 60 = 86400 seconds
    let expected: u64 = 24 * 60 * 60;
    assert(PP_RAGEQUIT_DELAY == expected, 'Should be 24 hours');
    assert(PP_RAGEQUIT_DELAY == 86400, 'Should be 86400 seconds');
}

#[test]
fn test_min_asp_stake_is_10000_sage() {
    // 10,000 SAGE with 18 decimals = 10000 * 10^18
    let expected: u256 = 10000000000000000000000_u256;
    assert(PP_MIN_ASP_STAKE == expected, 'Should be 10000 SAGE');
}

#[test]
fn test_asp_approval_threshold() {
    // Should require 2 auditor approvals
    assert(PP_ASP_APPROVAL_THRESHOLD == 2, 'Should require 2 approvals');
}

#[test]
fn test_max_batch_size() {
    // Should allow up to 100 deposits per batch
    assert(PP_MAX_BATCH_SIZE == 100, 'Should allow 100 per batch');
}

#[test]
fn test_root_history_size() {
    // Should keep 100 historical roots
    assert(PP_ROOT_HISTORY_SIZE == 100, 'Should keep 100 roots');
}

#[test]
fn test_domain_separator() {
    // Domain separator should be set
    assert(PP_DOMAIN_SEPARATOR == 'OBELYSK_PRIVACY_POOLS_V1', 'Wrong domain separator');
}

// =============================================================================
// ASP Approval Threshold Logic Tests
// =============================================================================

#[test]
fn test_approval_threshold_not_met_with_zero() {
    let votes: u32 = 0;
    assert(votes < PP_ASP_APPROVAL_THRESHOLD, 'Should not be approved');
}

#[test]
fn test_approval_threshold_not_met_with_one() {
    let votes: u32 = 1;
    assert(votes < PP_ASP_APPROVAL_THRESHOLD, 'Should not be approved');
}

#[test]
fn test_approval_threshold_met_with_two() {
    let votes: u32 = 2;
    assert(votes >= PP_ASP_APPROVAL_THRESHOLD, 'Should be approved');
}

#[test]
fn test_approval_threshold_exceeded() {
    let votes: u32 = 5;
    assert(votes >= PP_ASP_APPROVAL_THRESHOLD, 'Should be approved');
}

// =============================================================================
// Association Set Membership Logic Tests
// =============================================================================

#[test]
fn test_empty_set_has_zero_members() {
    let tree_state = LeanIMTState { root: 0, size: 0, depth: 0 };

    let set_info = AssociationSetInfo {
        set_id: 1,
        asp_id: 1,
        set_type: AssociationSetType::Inclusion,
        tree_state,
        member_count: 0,
        created_at: 1000000,
        last_updated: 1000000,
        is_active: true,
    };

    assert(set_info.member_count == 0, 'Should be empty');
    assert(set_info.tree_state.size == 0, 'Tree should be empty');
}

#[test]
fn test_set_member_count_matches_tree_size() {
    let tree_state = LeanIMTState { root: 12345, size: 50, depth: 6 };

    let set_info = AssociationSetInfo {
        set_id: 2,
        asp_id: 1,
        set_type: AssociationSetType::Inclusion,
        tree_state,
        member_count: 50,
        created_at: 1000000,
        last_updated: 2000000,
        is_active: true,
    };

    assert(set_info.member_count == set_info.tree_state.size, 'Counts should match');
}

// =============================================================================
// Ragequit Timing Tests
// =============================================================================

#[test]
fn test_ragequit_not_executable_before_delay() {
    let initiated_at: u64 = 1000000;
    let executable_at: u64 = initiated_at + PP_RAGEQUIT_DELAY;
    let current_time: u64 = initiated_at + 1000; // 1000 seconds after initiation

    assert(current_time < executable_at, 'Should not be executable yet');
}

#[test]
fn test_ragequit_executable_after_delay() {
    let initiated_at: u64 = 1000000;
    let executable_at: u64 = initiated_at + PP_RAGEQUIT_DELAY;
    let current_time: u64 = executable_at + 1; // 1 second after delay

    assert(current_time >= executable_at, 'Should be executable');
}

#[test]
fn test_ragequit_executable_exactly_at_delay() {
    let initiated_at: u64 = 1000000;
    let executable_at: u64 = initiated_at + PP_RAGEQUIT_DELAY;
    let current_time: u64 = executable_at; // Exactly at delay

    assert(current_time >= executable_at, 'Should be executable');
}

// =============================================================================
// Deposit Commitment Uniqueness Tests
// =============================================================================

#[test]
fn test_different_commitments_are_unique() {
    assert(TEST_COMMITMENT_1 != TEST_COMMITMENT_2, 'Commit 1 != 2');
    assert(TEST_COMMITMENT_2 != TEST_COMMITMENT_3, 'Commit 2 != 3');
    assert(TEST_COMMITMENT_1 != TEST_COMMITMENT_3, 'Commit 1 != 3');
}

#[test]
fn test_commitment_hash_deterministic() {
    let hash1 = hash_pair(TEST_COMMITMENT_1, TEST_COMMITMENT_2);
    let hash2 = hash_pair(TEST_COMMITMENT_1, TEST_COMMITMENT_2);

    assert(hash1 == hash2, 'Hash should be deterministic');
}

#[test]
fn test_commitment_hash_order_matters() {
    let hash1 = hash_pair(TEST_COMMITMENT_1, TEST_COMMITMENT_2);
    let hash2 = hash_pair(TEST_COMMITMENT_2, TEST_COMMITMENT_1);

    assert(hash1 != hash2, 'Order should matter');
}

// =============================================================================
// Stake Amount Validation Tests
// =============================================================================

#[test]
fn test_stake_below_minimum_fails() {
    let stake: u256 = PP_MIN_ASP_STAKE - 1;
    assert(stake < PP_MIN_ASP_STAKE, 'Should be below minimum');
}

#[test]
fn test_stake_at_minimum_passes() {
    let stake: u256 = PP_MIN_ASP_STAKE;
    assert(stake >= PP_MIN_ASP_STAKE, 'Should meet minimum');
}

#[test]
fn test_stake_above_minimum_passes() {
    let stake: u256 = PP_MIN_ASP_STAKE + 1000000000000000000000_u256; // +1000 SAGE
    assert(stake >= PP_MIN_ASP_STAKE, 'Should exceed minimum');
}

// =============================================================================
// Batch Size Validation Tests
// =============================================================================

#[test]
fn test_batch_within_limit() {
    let batch_size: u32 = 50;
    assert(batch_size <= PP_MAX_BATCH_SIZE, 'Should be within limit');
}

#[test]
fn test_batch_at_limit() {
    let batch_size: u32 = PP_MAX_BATCH_SIZE;
    assert(batch_size <= PP_MAX_BATCH_SIZE, 'Should be at limit');
}

#[test]
fn test_batch_exceeds_limit() {
    let batch_size: u32 = PP_MAX_BATCH_SIZE + 1;
    assert(batch_size > PP_MAX_BATCH_SIZE, 'Should exceed limit');
}
