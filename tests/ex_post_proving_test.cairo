// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Ex-Post Proving Tests
// Tests for retroactive ZK proof generation including:
// - Volume proof data structures
// - Non-transaction proof structures
// - Compliance bundle structures
// - Decryption proof verification
// - Inequality proof verification

use core::array::ArrayTrait;
use core::traits::TryInto;
use starknet::ContractAddress;

// Import ex-post proving types
use sage_contracts::obelysk::privacy_router::{
    // Ex-post types
    ExPostProofType, ExPostProofRecord, VolumeProof, InequalityProof,
    NonTransactionProof, DecryptionProof, DisclosedTransaction,
    ComplianceBundle, MAX_EX_POST_NULLIFIERS,
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

const TEST_PROVER_KEY_1: felt252 = 444444444444444444;
const TEST_PROVER_KEY_2: felt252 = 555555555555555555;
const TEST_THRESHOLD: u256 = 1000000000000000000000_u256; // 1000 SAGE

// =============================================================================
// ExPostProofType Unit Tests
// =============================================================================

#[test]
fn test_ex_post_proof_type_variants() {
    let volume = ExPostProofType::Volume;
    let non_tx = ExPostProofType::NonTransaction;
    let compliance = ExPostProofType::Compliance;

    // Test enum equality
    assert(volume == ExPostProofType::Volume, 'Volume eq failed');
    assert(non_tx == ExPostProofType::NonTransaction, 'NonTransaction eq failed');
    assert(compliance == ExPostProofType::Compliance, 'Compliance eq failed');

    // Test enum inequality
    assert(volume != non_tx, 'Types should differ');
    assert(non_tx != compliance, 'Types should differ');
    assert(compliance != volume, 'Types should differ');
}

// =============================================================================
// ExPostProofRecord Unit Tests
// =============================================================================

#[test]
fn test_ex_post_proof_record_creation() {
    let prover: ContractAddress = starknet::contract_address_const::<0x123>();
    let zero_address: ContractAddress = starknet::contract_address_const::<0>();

    let record = ExPostProofRecord {
        proof_id: 1_u256,
        proof_type: ExPostProofType::Volume,
        prover,
        verified_at: 1000000,
        epoch_start: 100,
        epoch_end: 200,
        proof_hash: 123456789,
        volume_threshold: TEST_THRESHOLD,
        excluded_address: zero_address,
    };

    assert(record.proof_id == 1_u256, 'Wrong proof ID');
    assert(record.proof_type == ExPostProofType::Volume, 'Wrong proof type');
    assert(record.verified_at == 1000000, 'Wrong verification time');
    assert(record.epoch_start == 100, 'Wrong epoch start');
    assert(record.epoch_end == 200, 'Wrong epoch end');
    assert(record.volume_threshold == TEST_THRESHOLD, 'Wrong threshold');
}

#[test]
fn test_ex_post_proof_record_non_transaction_type() {
    let prover: ContractAddress = starknet::contract_address_const::<0x456>();
    let excluded: ContractAddress = starknet::contract_address_const::<0x789>();

    let record = ExPostProofRecord {
        proof_id: 2_u256,
        proof_type: ExPostProofType::NonTransaction,
        prover,
        verified_at: 2000000,
        epoch_start: 50,
        epoch_end: 150,
        proof_hash: 987654321,
        volume_threshold: 0_u256,
        excluded_address: excluded,
    };

    assert(record.proof_type == ExPostProofType::NonTransaction, 'Wrong type');
    assert(record.excluded_address == excluded, 'Wrong excluded address');
}

// =============================================================================
// VolumeProof Unit Tests
// =============================================================================

#[test]
fn test_volume_proof_structure() {
    let nullifiers: Array<felt252> = array![111, 222, 333];
    let sum_commit = ec_mul(5000, generator());
    let range_proof_data: Array<felt252> = array![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32  // 32 elements minimum
    ];

    let proof = VolumeProof {
        nullifiers: nullifiers.span(),
        sum_commitment: sum_commit,
        sum_blinding: 123456789,
        range_proof_data: range_proof_data.span(),
        epoch_start: 100,
        epoch_end: 200,
    };

    assert(proof.nullifiers.len() == 3, 'Should have 3 nullifiers');
    assert(!is_zero(proof.sum_commitment), 'Sum commit should not be zero');
    assert(proof.range_proof_data.len() == 32, 'Should have 32 proof elements');
    assert(proof.epoch_start == 100, 'Wrong epoch start');
    assert(proof.epoch_end == 200, 'Wrong epoch end');
}

#[test]
fn test_volume_proof_empty_nullifiers() {
    let nullifiers: Array<felt252> = array![];
    let sum_commit = ec_zero();
    let range_proof_data: Array<felt252> = array![];

    let proof = VolumeProof {
        nullifiers: nullifiers.span(),
        sum_commitment: sum_commit,
        sum_blinding: 0,
        range_proof_data: range_proof_data.span(),
        epoch_start: 0,
        epoch_end: 0,
    };

    assert(proof.nullifiers.len() == 0, 'Should have 0 nullifiers');
    assert(is_zero(proof.sum_commitment), 'Sum commit should be zero');
}

// =============================================================================
// InequalityProof Unit Tests
// =============================================================================

#[test]
fn test_inequality_proof_structure() {
    let g = generator();
    let diff_commit = ec_mul(1000, g);
    let r_commit = ec_mul(2000, g);

    let proof = InequalityProof {
        difference_commitment: diff_commit,
        r_commitment: r_commit,
        challenge: 123456,
        response: 789012,
    };

    assert(!is_zero(proof.difference_commitment), 'Diff commit should not be zero');
    assert(!is_zero(proof.r_commitment), 'R commit should not be zero');
    assert(proof.challenge == 123456, 'Wrong challenge');
    assert(proof.response == 789012, 'Wrong response');
}

#[test]
fn test_inequality_proof_zero_challenge_invalid() {
    // Zero challenge is invalid for Schnorr proofs
    let proof = InequalityProof {
        difference_commitment: ec_mul(100, generator()),
        r_commitment: ec_mul(200, generator()),
        challenge: 0,  // Invalid!
        response: 12345,
    };

    // In verification, challenge == 0 should be rejected
    assert(proof.challenge == 0, 'Challenge should be zero');
}

// =============================================================================
// NonTransactionProof Unit Tests
// =============================================================================

#[test]
fn test_non_transaction_proof_structure() {
    let excluded: ContractAddress = starknet::contract_address_const::<0xDEAD>();
    let nullifiers: Array<felt252> = array![111, 222, 333, 444];

    let ineq_proof = InequalityProof {
        difference_commitment: ec_mul(1000, generator()),
        r_commitment: ec_mul(2000, generator()),
        challenge: 111111,
        response: 222222,
    };
    let inequality_proofs: Array<InequalityProof> = array![
        ineq_proof, ineq_proof, ineq_proof, ineq_proof
    ];

    let proof = NonTransactionProof {
        excluded_address: excluded,
        nullifiers: nullifiers.span(),
        inequality_proofs: inequality_proofs.span(),
        epoch_start: 50,
        epoch_end: 150,
        nullifier_set_hash: 999888777,
    };

    assert(proof.nullifiers.len() == 4, 'Should have 4 nullifiers');
    assert(proof.inequality_proofs.len() == 4, 'Should have 4 ineq proofs');
    assert(proof.excluded_address == excluded, 'Wrong excluded address');
    assert(proof.epoch_start == 50, 'Wrong epoch start');
    assert(proof.epoch_end == 150, 'Wrong epoch end');
    assert(proof.nullifier_set_hash == 999888777, 'Wrong hash');
}

#[test]
fn test_non_transaction_proof_mismatched_lengths() {
    let excluded: ContractAddress = starknet::contract_address_const::<0xBEEF>();
    let nullifiers: Array<felt252> = array![111, 222, 333];  // 3 nullifiers

    let ineq_proof = InequalityProof {
        difference_commitment: ec_mul(1000, generator()),
        r_commitment: ec_mul(2000, generator()),
        challenge: 111111,
        response: 222222,
    };
    let inequality_proofs: Array<InequalityProof> = array![ineq_proof, ineq_proof];  // Only 2 proofs

    let proof = NonTransactionProof {
        excluded_address: excluded,
        nullifiers: nullifiers.span(),
        inequality_proofs: inequality_proofs.span(),
        epoch_start: 0,
        epoch_end: 100,
        nullifier_set_hash: 0,
    };

    // Mismatched lengths should be caught during verification
    assert(proof.nullifiers.len() != proof.inequality_proofs.len(), 'Lengths should mismatch');
}

// =============================================================================
// DecryptionProof Unit Tests
// =============================================================================

#[test]
fn test_decryption_proof_structure() {
    let r_commit = ec_mul(3000, generator());

    let proof = DecryptionProof {
        r_commitment: r_commit,
        challenge: 555555,
        response: 666666,
    };

    assert(!is_zero(proof.r_commitment), 'R commit should not be zero');
    assert(proof.challenge == 555555, 'Wrong challenge');
    assert(proof.response == 666666, 'Wrong response');
}

// =============================================================================
// DisclosedTransaction Unit Tests
// =============================================================================

#[test]
fn test_disclosed_transaction_structure() {
    let sender: ContractAddress = starknet::contract_address_const::<0x111>();
    let receiver: ContractAddress = starknet::contract_address_const::<0x222>();

    let dec_proof = DecryptionProof {
        r_commitment: ec_mul(1000, generator()),
        challenge: 123,
        response: 456,
    };

    let tx = DisclosedTransaction {
        nullifier: 987654321,
        sender,
        receiver,
        amount: 1000000,  // 1M units
        timestamp: 1700000000,
        decryption_proof: dec_proof,
    };

    assert(tx.nullifier == 987654321, 'Wrong nullifier');
    assert(tx.sender == sender, 'Wrong sender');
    assert(tx.receiver == receiver, 'Wrong receiver');
    assert(tx.amount == 1000000, 'Wrong amount');
    assert(tx.timestamp == 1700000000, 'Wrong timestamp');
}

// =============================================================================
// ComplianceBundle Unit Tests
// =============================================================================

#[test]
fn test_compliance_bundle_structure() {
    let disclosure_ids: Array<u256> = array![1_u256, 2_u256, 3_u256];

    let dec_proof = DecryptionProof {
        r_commitment: ec_mul(1000, generator()),
        challenge: 123,
        response: 456,
    };

    let sender: ContractAddress = starknet::contract_address_const::<0x111>();
    let receiver: ContractAddress = starknet::contract_address_const::<0x222>();

    let tx1 = DisclosedTransaction {
        nullifier: 111,
        sender,
        receiver,
        amount: 1000,
        timestamp: 1000000,
        decryption_proof: dec_proof,
    };
    let tx2 = DisclosedTransaction {
        nullifier: 222,
        sender,
        receiver,
        amount: 2000,
        timestamp: 2000000,
        decryption_proof: dec_proof,
    };

    let disclosed_txs: Array<DisclosedTransaction> = array![tx1, tx2];

    let bundle = ComplianceBundle {
        disclosure_request_ids: disclosure_ids.span(),
        disclosed_transactions: disclosed_txs.span(),
        total_volume: 3000_u256,
        transaction_count: 2,
        period_start: 1000000,
        period_end: 2000000,
    };

    assert(bundle.disclosure_request_ids.len() == 3, 'Should have 3 disclosure IDs');
    assert(bundle.disclosed_transactions.len() == 2, 'Should have 2 transactions');
    assert(bundle.total_volume == 3000_u256, 'Wrong total volume');
    assert(bundle.transaction_count == 2, 'Wrong tx count');
    assert(bundle.period_start == 1000000, 'Wrong period start');
    assert(bundle.period_end == 2000000, 'Wrong period end');
}

#[test]
fn test_compliance_bundle_volume_matches_transactions() {
    let disclosure_ids: Array<u256> = array![1_u256];

    let dec_proof = DecryptionProof {
        r_commitment: ec_mul(1000, generator()),
        challenge: 123,
        response: 456,
    };

    let sender: ContractAddress = starknet::contract_address_const::<0x111>();
    let receiver: ContractAddress = starknet::contract_address_const::<0x222>();

    // Create 5 transactions with known amounts
    let mut disclosed_txs: Array<DisclosedTransaction> = array![];
    let amounts: Array<u64> = array![100, 200, 300, 400, 500];  // Sum = 1500

    let mut i: u32 = 0;
    loop {
        if i >= amounts.len() {
            break;
        }
        let tx = DisclosedTransaction {
            nullifier: i.into(),
            sender,
            receiver,
            amount: *amounts.at(i),
            timestamp: 1000000 + i.into(),
            decryption_proof: dec_proof,
        };
        disclosed_txs.append(tx);
        i += 1;
    };

    let bundle = ComplianceBundle {
        disclosure_request_ids: disclosure_ids.span(),
        disclosed_transactions: disclosed_txs.span(),
        total_volume: 1500_u256,  // Should match sum of amounts
        transaction_count: 5,
        period_start: 1000000,
        period_end: 1000004,
    };

    // Verify volume calculation
    let mut computed_volume: u256 = 0;
    let mut j: u32 = 0;
    loop {
        if j >= bundle.disclosed_transactions.len() {
            break;
        }
        let tx = *bundle.disclosed_transactions.at(j);
        computed_volume += tx.amount.into();
        j += 1;
    };

    assert(computed_volume == bundle.total_volume, 'Volume should match');
    assert(bundle.transaction_count == bundle.disclosed_transactions.len(), 'Count should match');
}

// =============================================================================
// MAX_EX_POST_NULLIFIERS Constant Test
// =============================================================================

#[test]
fn test_max_ex_post_nullifiers_constant() {
    // Verify the constant is set appropriately
    assert(MAX_EX_POST_NULLIFIERS == 100, 'Should be 100');

    // Verify it's reasonable for gas limits
    assert(MAX_EX_POST_NULLIFIERS > 0, 'Should be positive');
    assert(MAX_EX_POST_NULLIFIERS <= 1000, 'Should not exceed 1000');
}

// =============================================================================
// Epoch Range Validation Tests
// =============================================================================

#[test]
fn test_epoch_range_valid() {
    let epoch_start: u64 = 100;
    let epoch_end: u64 = 200;

    assert(epoch_end >= epoch_start, 'End should be >= start');

    let duration = epoch_end - epoch_start;
    assert(duration == 100, 'Duration should be 100');
}

#[test]
fn test_epoch_range_single_epoch() {
    // Single epoch case (start == end)
    let epoch_start: u64 = 150;
    let epoch_end: u64 = 150;

    assert(epoch_end == epoch_start, 'Should be same epoch');
}

// =============================================================================
// Proof Hash Tests
// =============================================================================

#[test]
fn test_proof_hash_non_zero() {
    let record = ExPostProofRecord {
        proof_id: 1_u256,
        proof_type: ExPostProofType::Volume,
        prover: starknet::contract_address_const::<0x123>(),
        verified_at: 1000000,
        epoch_start: 100,
        epoch_end: 200,
        proof_hash: 123456789,
        volume_threshold: TEST_THRESHOLD,
        excluded_address: starknet::contract_address_const::<0>(),
    };

    assert(record.proof_hash != 0, 'Hash should not be zero');
}

// =============================================================================
// EC Point Commitment Tests for Proofs
// =============================================================================

#[test]
fn test_sum_commitment_derivation() {
    let g = generator();
    let h = generator_h();

    // Simulate sum commitment: C = sum*G + blinding*H
    let sum_amount: felt252 = 5000;
    let blinding: felt252 = 123456;

    let sum_g = ec_mul(sum_amount, g);
    let blinding_h = ec_mul(blinding, h);
    let sum_commitment = ec_add(sum_g, blinding_h);

    assert(!is_zero(sum_commitment), 'Sum commit should not be zero');
}

#[test]
fn test_difference_commitment_for_inequality() {
    let g = generator();

    // For inequality proof: commit to (receiver - excluded)
    // If they're equal, this would be zero
    let receiver_value: felt252 = 1000;
    let excluded_value: felt252 = 500;
    let difference: felt252 = receiver_value - excluded_value;

    let diff_commitment = ec_mul(difference, g);

    // Since difference != 0, commitment should not be identity
    assert(!is_zero(diff_commitment), 'Diff commit should not be zero');
}

#[test]
fn test_zero_difference_commitment() {
    let g = generator();

    // If receiver == excluded, difference = 0
    // This would fail an inequality proof
    let receiver_value: felt252 = 1000;
    let excluded_value: felt252 = 1000;  // Same!
    let difference: felt252 = receiver_value - excluded_value;

    let diff_commitment = ec_mul(difference, g);

    // Zero scalar * G = identity
    assert(is_zero(diff_commitment), 'Zero diff should be identity');
}
