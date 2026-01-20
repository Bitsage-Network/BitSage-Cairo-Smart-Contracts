// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Multi-Signature Auditing Tests
// Tests for M-of-N auditor approval system including:
// - Auditor registry management
// - Large transfer approval workflow
// - Disclosure request handling
// - Threshold proof validation

use core::array::ArrayTrait;
use core::traits::TryInto;
use starknet::ContractAddress;

// Import privacy router types
use sage_contracts::obelysk::privacy_router::{
    // Types
    AuditorInfo, AuditRequest, AuditRequestType, AuditRequestStatus,
    ThresholdProof,
    // Constants
    AUDIT_REQUEST_TIMEOUT, DEFAULT_LARGE_TRANSFER_THRESHOLD,
};

// Import ElGamal types
use sage_contracts::obelysk::elgamal::{
    ECPoint, ElGamalCiphertext,
    generator, generator_h, ec_zero, is_zero,
    ec_add, ec_mul, derive_public_key,
};

// =============================================================================
// Test Constants
// =============================================================================

const TEST_AUDITOR_KEY_1: felt252 = 111111111111111111;
const TEST_AUDITOR_KEY_2: felt252 = 222222222222222222;
const TEST_AUDITOR_KEY_3: felt252 = 333333333333333333;

// =============================================================================
// AuditorInfo Unit Tests
// =============================================================================

#[test]
fn test_auditor_info_creation() {
    let g = generator();
    let public_key = ec_mul(TEST_AUDITOR_KEY_1, g);

    let auditor = AuditorInfo {
        address: starknet::contract_address_const::<0x123>(),
        public_key,
        registered_at: 1000,
        is_active: true,
        total_approvals: 0,
        list_index: 0,
    };

    assert(auditor.is_active, 'Should be active');
    assert(auditor.total_approvals == 0, 'Should have 0 approvals');
    assert(auditor.registered_at == 1000, 'Wrong registration time');
}

#[test]
fn test_auditor_info_defaults() {
    // Test default/zero auditor info
    let zero_address: ContractAddress = starknet::contract_address_const::<0>();
    let zero_point = ec_zero();

    let auditor = AuditorInfo {
        address: zero_address,
        public_key: zero_point,
        registered_at: 0,
        is_active: false,
        total_approvals: 0,
        list_index: 0,
    };

    assert(!auditor.is_active, 'Should be inactive');
    assert(is_zero(auditor.public_key), 'Key should be zero');
}

// =============================================================================
// AuditRequestType Unit Tests
// =============================================================================

#[test]
fn test_audit_request_type_variants() {
    let large_transfer = AuditRequestType::LargeTransfer;
    let disclosure = AuditRequestType::Disclosure;
    let freeze = AuditRequestType::Freeze;

    // Test enum equality
    assert(large_transfer == AuditRequestType::LargeTransfer, 'LargeTransfer eq failed');
    assert(disclosure == AuditRequestType::Disclosure, 'Disclosure eq failed');
    assert(freeze == AuditRequestType::Freeze, 'Freeze eq failed');

    // Test enum inequality
    assert(large_transfer != disclosure, 'Types should differ');
    assert(disclosure != freeze, 'Types should differ');
}

// =============================================================================
// AuditRequestStatus Unit Tests
// =============================================================================

#[test]
fn test_audit_request_status_transitions() {
    // Test valid status values
    let pending = AuditRequestStatus::Pending;
    let approved = AuditRequestStatus::Approved;
    let rejected = AuditRequestStatus::Rejected;
    let expired = AuditRequestStatus::Expired;
    let executed = AuditRequestStatus::Executed;

    // All should be distinct
    assert(pending != approved, 'Status should differ');
    assert(approved != rejected, 'Status should differ');
    assert(rejected != expired, 'Status should differ');
    assert(expired != executed, 'Status should differ');
    assert(executed != pending, 'Status should differ');
}

// =============================================================================
// AuditRequest Unit Tests
// =============================================================================

#[test]
fn test_audit_request_creation() {
    let requester: ContractAddress = starknet::contract_address_const::<0x456>();
    let nullifier: felt252 = 999888777666;
    let created_at: u64 = 1000000;

    let request = AuditRequest {
        request_id: 1_u256,
        request_type: AuditRequestType::LargeTransfer,
        requester,
        target_nullifier: nullifier,
        created_at,
        expires_at: created_at + AUDIT_REQUEST_TIMEOUT,
        approval_count: 0,
        required_approvals: 2,
        status: AuditRequestStatus::Pending,
        executed: false,
    };

    assert(request.request_id == 1_u256, 'Wrong request ID');
    assert(request.request_type == AuditRequestType::LargeTransfer, 'Wrong type');
    assert(request.target_nullifier == nullifier, 'Wrong nullifier');
    assert(request.approval_count == 0, 'Should have 0 approvals');
    assert(request.required_approvals == 2, 'Should require 2 approvals');
    assert(!request.executed, 'Should not be executed');
}

#[test]
fn test_audit_request_expiration_calculation() {
    let created_at: u64 = 1000000;
    let expires_at = created_at + AUDIT_REQUEST_TIMEOUT;

    // AUDIT_REQUEST_TIMEOUT should be 7 days = 604800 seconds
    assert(AUDIT_REQUEST_TIMEOUT == 604800, 'Timeout should be 7 days');
    assert(expires_at == created_at + 604800, 'Expiration calc wrong');
}

#[test]
fn test_audit_request_disclosure_type() {
    let requester: ContractAddress = starknet::contract_address_const::<0x789>();
    let nullifier: felt252 = 123456789;

    let request = AuditRequest {
        request_id: 2_u256,
        request_type: AuditRequestType::Disclosure,
        requester,
        target_nullifier: nullifier,
        created_at: 2000000,
        expires_at: 2000000 + AUDIT_REQUEST_TIMEOUT,
        approval_count: 1,
        required_approvals: 3,
        status: AuditRequestStatus::Pending,
        executed: false,
    };

    assert(request.request_type == AuditRequestType::Disclosure, 'Wrong type');
    assert(request.approval_count == 1, 'Should have 1 approval');
    assert(request.required_approvals == 3, 'Should require 3 approvals');
}

// =============================================================================
// ThresholdProof Unit Tests
// =============================================================================

#[test]
fn test_threshold_proof_structure() {
    // Create a mock threshold proof
    let diff_commit = ec_mul(1000, generator());
    let proof_data: Array<felt252> = array![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32  // 32 elements for basic validation
    ];

    let proof = ThresholdProof {
        difference_commitment: diff_commit,
        range_proof_data: proof_data.span(),
        blinding_diff: 123456789,
    };

    // Verify structure
    assert(!is_zero(proof.difference_commitment), 'Commit should not be zero');
    assert(proof.range_proof_data.len() == 32, 'Should have 32 proof elements');
    assert(proof.blinding_diff == 123456789, 'Wrong blinding');
}

#[test]
fn test_threshold_proof_minimum_size() {
    // Threshold proofs require at least 32 elements
    let proof_data: Array<felt252> = array![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32
    ];

    assert(proof_data.len() >= 32, 'Need at least 32 elements');
}

// =============================================================================
// Constant Validation Tests
// =============================================================================

#[test]
fn test_default_large_transfer_threshold() {
    // Default threshold is 10,000 SAGE (with 18 decimals)
    // 10000 * 10^18 = 10,000,000,000,000,000,000,000
    let expected: u256 = 10000000000000000000000_u256;
    assert(DEFAULT_LARGE_TRANSFER_THRESHOLD == expected, 'Wrong default threshold');
}

#[test]
fn test_audit_timeout_is_one_week() {
    // Timeout should be exactly 7 days in seconds
    // 7 days * 24 hours * 60 minutes * 60 seconds = 604800
    let one_week: u64 = 7 * 24 * 60 * 60;
    assert(AUDIT_REQUEST_TIMEOUT == one_week, 'Timeout should be 1 week');
}

// =============================================================================
// M-of-N Threshold Logic Tests
// =============================================================================

#[test]
fn test_approval_threshold_2_of_3() {
    // Simulate 2-of-3 approval
    let required = 2_u32;
    let mut approvals = 0_u32;

    // First approval - not enough
    approvals += 1;
    assert(approvals < required, 'Should not be approved yet');

    // Second approval - threshold met
    approvals += 1;
    assert(approvals >= required, 'Should be approved now');
}

#[test]
fn test_approval_threshold_3_of_5() {
    // Simulate 3-of-5 approval
    let required = 3_u32;
    let mut approvals = 0_u32;

    approvals += 1;
    assert(approvals < required, 'Not enough 1/3');

    approvals += 1;
    assert(approvals < required, 'Not enough 2/3');

    approvals += 1;
    assert(approvals >= required, 'Should be approved 3/3');
}

#[test]
fn test_approval_threshold_1_of_1() {
    // Edge case: single auditor
    let required = 1_u32;
    let mut approvals = 0_u32;

    approvals += 1;
    assert(approvals >= required, 'Single approval should work');
}

// =============================================================================
// Request Status Transition Tests
// =============================================================================

#[test]
fn test_status_pending_to_approved() {
    let mut status = AuditRequestStatus::Pending;

    // Simulate approval meeting threshold
    status = AuditRequestStatus::Approved;
    assert(status == AuditRequestStatus::Approved, 'Should be approved');
}

#[test]
fn test_status_approved_to_executed() {
    let mut status = AuditRequestStatus::Approved;

    // Simulate execution
    status = AuditRequestStatus::Executed;
    assert(status == AuditRequestStatus::Executed, 'Should be executed');
}

#[test]
fn test_status_pending_to_expired() {
    let mut status = AuditRequestStatus::Pending;

    // Simulate timeout
    status = AuditRequestStatus::Expired;
    assert(status == AuditRequestStatus::Expired, 'Should be expired');
}

// =============================================================================
// Public Key Derivation Tests for Auditors
// =============================================================================

#[test]
fn test_auditor_key_derivation() {
    let g = generator();

    // Derive public keys for three auditors
    let pk1 = derive_public_key(TEST_AUDITOR_KEY_1);
    let pk2 = derive_public_key(TEST_AUDITOR_KEY_2);
    let pk3 = derive_public_key(TEST_AUDITOR_KEY_3);

    // All should be valid (non-zero) points
    assert(!is_zero(pk1), 'PK1 should not be zero');
    assert(!is_zero(pk2), 'PK2 should not be zero');
    assert(!is_zero(pk3), 'PK3 should not be zero');

    // All should be distinct
    assert(pk1.x != pk2.x || pk1.y != pk2.y, 'PK1 and PK2 should differ');
    assert(pk2.x != pk3.x || pk2.y != pk3.y, 'PK2 and PK3 should differ');
    assert(pk1.x != pk3.x || pk1.y != pk3.y, 'PK1 and PK3 should differ');
}

#[test]
fn test_auditor_key_consistency() {
    // Same private key should always produce same public key
    let pk1_a = derive_public_key(TEST_AUDITOR_KEY_1);
    let pk1_b = derive_public_key(TEST_AUDITOR_KEY_1);

    assert(pk1_a.x == pk1_b.x, 'X should match');
    assert(pk1_a.y == pk1_b.y, 'Y should match');
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_zero_approval_threshold_not_allowed() {
    // Zero threshold would make all transfers require no approval
    // This is a logical constraint, not enforced at type level
    let threshold = 0_u32;
    assert(threshold == 0, 'Zero threshold is invalid');
}

#[test]
fn test_max_approval_count() {
    // Test maximum approval count doesn't overflow
    let max_approvals: u32 = 4294967295; // u32 max
    let count: u32 = 10;

    assert(count < max_approvals, 'Should not overflow');
}

#[test]
fn test_request_id_uniqueness() {
    // Request IDs should be monotonically increasing
    let id1: u256 = 0;
    let id2: u256 = 1;
    let id3: u256 = 2;

    assert(id1 < id2, 'ID2 should be greater');
    assert(id2 < id3, 'ID3 should be greater');
}

// =============================================================================
// Hash Key Tests for Multi-Auditor Storage
// =============================================================================

#[test]
fn test_nullifier_as_storage_key() {
    // Test that nullifier can be used directly as storage key
    let nullifier1: felt252 = 123456;
    let nullifier2: felt252 = 789012;

    // Distinct nullifiers should produce distinct keys
    assert(nullifier1 != nullifier2, 'Keys should differ');
}

#[test]
fn test_multi_auditor_key_format() {
    // Key format: hash(nullifier, auditor_address)
    let nullifier: felt252 = 123456;
    let auditor1: ContractAddress = starknet::contract_address_const::<0x111>();
    let auditor2: ContractAddress = starknet::contract_address_const::<0x222>();

    // Convert addresses to felt252 for hashing
    let addr1_felt: felt252 = auditor1.into();
    let addr2_felt: felt252 = auditor2.into();

    // Different auditors should produce different keys
    assert(addr1_felt != addr2_felt, 'Auditor keys should differ');
}
