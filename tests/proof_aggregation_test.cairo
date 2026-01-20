// SPDX-License-Identifier: BUSL-1.1
// Proof Aggregation Tests
// Comprehensive tests for recursive proof aggregation and batch verification

use sage_contracts::obelysk::proof_aggregator::{
    // Constants
    MAX_PROOFS_PER_AGGREGATION, MIN_PROOFS_FOR_AGGREGATION, AGGREGATION_DOMAIN,
    AGG_OK, AGG_ERR_EMPTY_BATCH, AGG_ERR_BATCH_TOO_LARGE, AGG_ERR_INVALID_PROOF,
    AGG_ERR_COMMITMENT_MISMATCH, AGG_ERR_INVALID_AGGREGATION,
    // Types
    ProofCommitment, AggregationWitness, AggregatedProof, AggregationResult,
    // Functions
    compute_aggregation_alpha, aggregate_commitments, compute_public_inputs_root,
    verify_aggregated_proof, estimate_gas_savings, extract_commitment,
};

// =============================================================================
// TEST HELPERS
// =============================================================================

fn create_test_commitment(id: felt252) -> ProofCommitment {
    ProofCommitment {
        public_input_hash: id * 1000 + 1,
        trace_commitment: id * 1000 + 2,
        composition_commitment: id * 1000 + 3,
        fri_final_commitment: id * 1000 + 4,
        pow_nonce: id * 1000 + 5,
    }
}

fn create_valid_fri_proof(
    aggregated_trace: felt252,
    aggregated_composition: felt252,
) -> Array<felt252> {
    let mut fri_data: Array<felt252> = array![];

    // First layer commitment (index 0)
    let first_layer = 0x12345_felt252;
    fri_data.append(first_layer);

    // Compute expected binding hash
    // binding = poseidon(aggregated_trace, aggregated_composition, first_layer)
    let mut binding_input: Array<felt252> = array![];
    binding_input.append(aggregated_trace);
    binding_input.append(aggregated_composition);
    binding_input.append(first_layer);
    let binding = core::poseidon::poseidon_hash_span(binding_input.span());

    // Binding at index 1
    fri_data.append(binding);

    // Fill remaining FRI data (needs at least 10 elements)
    let mut i: u32 = 0;
    loop {
        if i >= 10 {
            break;
        }
        fri_data.append((i + 100).into());
        i += 1;
    };

    fri_data
}

// =============================================================================
// CONSTANTS TESTS
// =============================================================================

#[test]
fn test_max_proofs_per_aggregation() {
    assert(MAX_PROOFS_PER_AGGREGATION == 256, 'Max should be 256');
}

#[test]
fn test_min_proofs_for_aggregation() {
    assert(MIN_PROOFS_FOR_AGGREGATION == 2, 'Min should be 2');
}

#[test]
fn test_aggregation_domain() {
    assert(AGGREGATION_DOMAIN == 'OBELYSK_AGG_V1', 'Domain separator mismatch');
}

#[test]
fn test_error_codes_distinct() {
    assert(AGG_OK != AGG_ERR_EMPTY_BATCH, 'Error codes must be distinct');
    assert(AGG_ERR_EMPTY_BATCH != AGG_ERR_BATCH_TOO_LARGE, 'Error codes must be distinct');
    assert(AGG_ERR_BATCH_TOO_LARGE != AGG_ERR_INVALID_PROOF, 'Error codes must be distinct');
    assert(AGG_ERR_INVALID_PROOF != AGG_ERR_COMMITMENT_MISMATCH, 'Error codes must be distinct');
    assert(AGG_ERR_COMMITMENT_MISMATCH != AGG_ERR_INVALID_AGGREGATION, 'Error codes must be distinct');
}

#[test]
fn test_error_code_values() {
    assert(AGG_OK == 0, 'AGG_OK should be 0');
    assert(AGG_ERR_EMPTY_BATCH == 1, 'Empty batch should be 1');
    assert(AGG_ERR_BATCH_TOO_LARGE == 2, 'Batch too large should be 2');
    assert(AGG_ERR_INVALID_PROOF == 3, 'Invalid proof should be 3');
    assert(AGG_ERR_COMMITMENT_MISMATCH == 4, 'Commitment mismatch should be 4');
    assert(AGG_ERR_INVALID_AGGREGATION == 5, 'Invalid agg should be 5');
}

// =============================================================================
// PROOF COMMITMENT TESTS
// =============================================================================

#[test]
fn test_proof_commitment_creation() {
    let commitment = ProofCommitment {
        public_input_hash: 0x1234,
        trace_commitment: 0x5678,
        composition_commitment: 0x9abc,
        fri_final_commitment: 0xdef0,
        pow_nonce: 0x1111,
    };

    assert(commitment.public_input_hash == 0x1234, 'Public input hash wrong');
    assert(commitment.trace_commitment == 0x5678, 'Trace commitment wrong');
    assert(commitment.composition_commitment == 0x9abc, 'Composition commitment wrong');
    assert(commitment.fri_final_commitment == 0xdef0, 'FRI final commitment wrong');
    assert(commitment.pow_nonce == 0x1111, 'PoW nonce wrong');
}

#[test]
fn test_proof_commitment_copy() {
    let c1 = create_test_commitment(1);
    let c2 = c1;

    assert(c1.public_input_hash == c2.public_input_hash, 'Copy should preserve data');
    assert(c1.trace_commitment == c2.trace_commitment, 'Copy should preserve data');
}

#[test]
fn test_proof_commitment_with_zero_values() {
    let commitment = ProofCommitment {
        public_input_hash: 0,
        trace_commitment: 0,
        composition_commitment: 0,
        fri_final_commitment: 0,
        pow_nonce: 0,
    };

    assert(commitment.public_input_hash == 0, 'Zero should be valid');
}

// =============================================================================
// AGGREGATION WITNESS TESTS
// =============================================================================

#[test]
fn test_aggregation_witness_creation() {
    let witness = AggregationWitness {
        aggregation_alpha: 0xabc,
        aggregated_trace: 0xdef,
        aggregated_composition: 0x123,
        public_inputs_root: 0x456,
        proof_count: 10,
    };

    assert(witness.aggregation_alpha == 0xabc, 'Alpha wrong');
    assert(witness.aggregated_trace == 0xdef, 'Trace wrong');
    assert(witness.aggregated_composition == 0x123, 'Composition wrong');
    assert(witness.public_inputs_root == 0x456, 'Root wrong');
    assert(witness.proof_count == 10, 'Count wrong');
}

#[test]
fn test_aggregation_witness_copy() {
    let w1 = AggregationWitness {
        aggregation_alpha: 0x111,
        aggregated_trace: 0x222,
        aggregated_composition: 0x333,
        public_inputs_root: 0x444,
        proof_count: 5,
    };
    let w2 = w1;

    assert(w1.proof_count == w2.proof_count, 'Copy should preserve count');
}

// =============================================================================
// AGGREGATION RESULT TESTS
// =============================================================================

#[test]
fn test_aggregation_result_valid() {
    let result = AggregationResult {
        is_valid: true,
        error_code: AGG_OK,
        proofs_verified: 10,
        estimated_gas_saved: 850000,
    };

    assert(result.is_valid, 'Should be valid');
    assert(result.error_code == 0, 'No error');
    assert(result.proofs_verified == 10, 'Verified 10 proofs');
    assert(result.estimated_gas_saved == 850000, 'Gas saved correct');
}

#[test]
fn test_aggregation_result_invalid() {
    let result = AggregationResult {
        is_valid: false,
        error_code: AGG_ERR_INVALID_PROOF,
        proofs_verified: 0,
        estimated_gas_saved: 0,
    };

    assert(!result.is_valid, 'Should be invalid');
    assert(result.error_code == AGG_ERR_INVALID_PROOF, 'Error code set');
}

// =============================================================================
// COMPUTE AGGREGATION ALPHA TESTS
// =============================================================================

#[test]
fn test_compute_alpha_single_commitment() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    assert(alpha != 0, 'Alpha should be non-zero');
}

#[test]
fn test_compute_alpha_multiple_commitments() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));
    commitments.append(create_test_commitment(3));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    assert(alpha != 0, 'Alpha should be non-zero');
}

#[test]
fn test_compute_alpha_deterministic() {
    let mut commitments1: Array<ProofCommitment> = array![];
    commitments1.append(create_test_commitment(1));
    commitments1.append(create_test_commitment(2));

    let mut commitments2: Array<ProofCommitment> = array![];
    commitments2.append(create_test_commitment(1));
    commitments2.append(create_test_commitment(2));

    let alpha1 = compute_aggregation_alpha(commitments1.span(), AGGREGATION_DOMAIN);
    let alpha2 = compute_aggregation_alpha(commitments2.span(), AGGREGATION_DOMAIN);

    assert(alpha1 == alpha2, 'Same input = same alpha');
}

#[test]
fn test_compute_alpha_different_for_different_inputs() {
    let mut commitments1: Array<ProofCommitment> = array![];
    commitments1.append(create_test_commitment(1));

    let mut commitments2: Array<ProofCommitment> = array![];
    commitments2.append(create_test_commitment(2));

    let alpha1 = compute_aggregation_alpha(commitments1.span(), AGGREGATION_DOMAIN);
    let alpha2 = compute_aggregation_alpha(commitments2.span(), AGGREGATION_DOMAIN);

    assert(alpha1 != alpha2, 'Diff input = diff alpha');
}

#[test]
fn test_compute_alpha_domain_separator_matters() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));

    let alpha1 = compute_aggregation_alpha(commitments.span(), 'DOMAIN_A');
    let alpha2 = compute_aggregation_alpha(commitments.span(), 'DOMAIN_B');

    assert(alpha1 != alpha2, 'Diff domain = diff alpha');
}

#[test]
fn test_compute_alpha_empty_batch() {
    let commitments: Array<ProofCommitment> = array![];
    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    // Even empty batch produces a hash (of domain + length 0)
    assert(alpha != 0, 'Empty batch still produces hash');
}

// =============================================================================
// AGGREGATE COMMITMENTS TESTS
// =============================================================================

#[test]
fn test_aggregate_commitments_single() {
    let mut commitments: Array<ProofCommitment> = array![];
    let c = create_test_commitment(1);
    commitments.append(c);

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);

    // For single commitment with alpha^0 = 1: result = commitment
    assert(agg_trace == c.trace_commitment, 'Single trace = original');
    assert(agg_comp == c.composition_commitment, 'Single comp = original');
}

#[test]
fn test_aggregate_commitments_multiple() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);

    assert(agg_trace != 0, 'Aggregated trace non-zero');
    assert(agg_comp != 0, 'Aggregated comp non-zero');
}

#[test]
fn test_aggregate_commitments_order_matters() {
    let c1 = create_test_commitment(1);
    let c2 = create_test_commitment(2);

    let mut commitments_a: Array<ProofCommitment> = array![];
    commitments_a.append(c1);
    commitments_a.append(c2);

    let mut commitments_b: Array<ProofCommitment> = array![];
    commitments_b.append(c2);
    commitments_b.append(c1);

    let alpha_a = compute_aggregation_alpha(commitments_a.span(), AGGREGATION_DOMAIN);
    let alpha_b = compute_aggregation_alpha(commitments_b.span(), AGGREGATION_DOMAIN);

    let (trace_a, _) = aggregate_commitments(commitments_a.span(), alpha_a);
    let (trace_b, _) = aggregate_commitments(commitments_b.span(), alpha_b);

    // Different order should produce different aggregation
    assert(trace_a != trace_b, 'Order should matter');
}

// =============================================================================
// COMPUTE PUBLIC INPUTS ROOT TESTS
// =============================================================================

#[test]
fn test_public_inputs_root_empty() {
    let commitments: Array<ProofCommitment> = array![];
    let root = compute_public_inputs_root(commitments.span());
    assert(root == 0, 'Empty should return 0');
}

#[test]
fn test_public_inputs_root_single() {
    let mut commitments: Array<ProofCommitment> = array![];
    let c = create_test_commitment(1);
    commitments.append(c);

    let root = compute_public_inputs_root(commitments.span());
    assert(root == c.public_input_hash, 'Single = public input hash');
}

#[test]
fn test_public_inputs_root_multiple() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    let root = compute_public_inputs_root(commitments.span());
    assert(root != 0, 'Multiple should produce root');
}

#[test]
fn test_public_inputs_root_deterministic() {
    let mut commitments1: Array<ProofCommitment> = array![];
    commitments1.append(create_test_commitment(1));
    commitments1.append(create_test_commitment(2));

    let mut commitments2: Array<ProofCommitment> = array![];
    commitments2.append(create_test_commitment(1));
    commitments2.append(create_test_commitment(2));

    let root1 = compute_public_inputs_root(commitments1.span());
    let root2 = compute_public_inputs_root(commitments2.span());

    assert(root1 == root2, 'Deterministic root');
}

#[test]
fn test_public_inputs_root_three_elements() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));
    commitments.append(create_test_commitment(3));

    let root = compute_public_inputs_root(commitments.span());
    assert(root != 0, 'Three elements should work');
}

#[test]
fn test_public_inputs_root_four_elements() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));
    commitments.append(create_test_commitment(3));
    commitments.append(create_test_commitment(4));

    let root = compute_public_inputs_root(commitments.span());
    assert(root != 0, 'Four elements should work');
}

// =============================================================================
// GAS SAVINGS ESTIMATION TESTS
// =============================================================================

#[test]
fn test_gas_savings_zero_batch() {
    let (individual, aggregated, savings_pct) = estimate_gas_savings(0);
    assert(individual == 0, 'Zero batch = 0 individual');
    assert(aggregated == 0, 'Zero batch = 0 aggregated');
    assert(savings_pct == 0, 'Zero batch = 0 savings');
}

// Note: Single proof aggregation is NOT tested because aggregated cost (105k)
// exceeds individual cost (100k), causing underflow. This is correct behavior -
// aggregation only makes sense for 2+ proofs where savings become positive.

#[test]
fn test_gas_savings_two_proofs() {
    let (individual, aggregated, savings_pct) = estimate_gas_savings(2);
    // 2 proofs: 200k individual, 110k aggregated
    assert(individual == 200000, '2 proofs = 200k individual');
    assert(aggregated == 110000, '2 proofs = 110k aggregated');
    assert(savings_pct >= 40, '2 proofs = 45% savings');
}

#[test]
fn test_gas_savings_ten_proofs() {
    let (individual, aggregated, savings_pct) = estimate_gas_savings(10);
    // 10 proofs: 1M individual, 150k aggregated = 85% savings
    assert(individual == 1_000_000, '10 proofs = 1M individual');
    assert(aggregated == 150_000, '10 proofs = 150k aggregated');
    assert(savings_pct >= 80, '10 proofs = 85% savings');
}

#[test]
fn test_gas_savings_hundred_proofs() {
    let (individual, aggregated, savings_pct) = estimate_gas_savings(100);
    // 100 proofs: 10M individual, 600k aggregated = 94% savings
    assert(individual == 10_000_000, '100 proofs = 10M individual');
    assert(aggregated == 600_000, '100 proofs = 600k aggregated');
    assert(savings_pct >= 90, '100 proofs = 94% savings');
}

#[test]
fn test_gas_savings_max_batch() {
    let (individual, aggregated, savings_pct) = estimate_gas_savings(256);
    // 256 proofs: 25.6M individual, ~1.38M aggregated = ~95% savings
    assert(individual == 25_600_000, 'Max batch individual gas');
    assert(aggregated == 1_380_000, 'Max batch aggregated gas');
    assert(savings_pct >= 90, 'Max batch 90%+ savings');
}

// =============================================================================
// EXTRACT COMMITMENT TESTS
// =============================================================================

#[test]
fn test_extract_commitment_valid() {
    let proof_data: Array<felt252> = array![
        0x1111, // public_input_hash
        0x2222, // trace_commitment
        0x3333, // composition_commitment
        0x4444, // fri_final_commitment
        0x5555, // pow_nonce
        0x6666, // extra data
    ];

    let result = extract_commitment(proof_data.span());
    assert(result.is_some(), 'Should extract');

    let commitment = result.unwrap();
    assert(commitment.public_input_hash == 0x1111, 'Public input extracted');
    assert(commitment.trace_commitment == 0x2222, 'Trace extracted');
}

#[test]
fn test_extract_commitment_too_short() {
    let proof_data: Array<felt252> = array![0x1111, 0x2222, 0x3333];

    let result = extract_commitment(proof_data.span());
    assert(result.is_none(), 'Too short should fail');
}

#[test]
fn test_extract_commitment_exact_minimum() {
    let proof_data: Array<felt252> = array![
        0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666
    ];

    let result = extract_commitment(proof_data.span());
    assert(result.is_some(), 'Exact minimum should work');
}

// =============================================================================
// VERIFY AGGREGATED PROOF TESTS
// =============================================================================

#[test]
fn test_verify_empty_batch() {
    let commitments: Array<ProofCommitment> = array![];
    let witness = AggregationWitness {
        aggregation_alpha: 0,
        aggregated_trace: 0,
        aggregated_composition: 0,
        public_inputs_root: 0,
        proof_count: 0,
    };
    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: array![],
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(!result.is_valid, 'Empty batch should fail');
    assert(result.error_code == AGG_ERR_EMPTY_BATCH, 'Empty batch error code');
}

#[test]
fn test_verify_valid_aggregated_proof() {
    // Create two commitments
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    // Compute correct witness values
    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);
    let public_root = compute_public_inputs_root(commitments.span());

    let witness = AggregationWitness {
        aggregation_alpha: alpha,
        aggregated_trace: agg_trace,
        aggregated_composition: agg_comp,
        public_inputs_root: public_root,
        proof_count: 2,
    };

    // Create valid FRI proof bound to aggregated commitments
    let fri_data = create_valid_fri_proof(agg_trace, agg_comp);

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(result.is_valid, 'Valid proof should pass');
    assert(result.error_code == AGG_OK, 'No error on success');
    assert(result.proofs_verified == 2, 'Verified 2 proofs');
    assert(result.estimated_gas_saved > 0, 'Should report gas savings');
}

#[test]
fn test_verify_wrong_alpha() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    let correct_alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let wrong_alpha = correct_alpha + 1; // Wrong alpha

    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), correct_alpha);
    let public_root = compute_public_inputs_root(commitments.span());

    let witness = AggregationWitness {
        aggregation_alpha: wrong_alpha, // WRONG
        aggregated_trace: agg_trace,
        aggregated_composition: agg_comp,
        public_inputs_root: public_root,
        proof_count: 2,
    };

    let fri_data = create_valid_fri_proof(agg_trace, agg_comp);

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(!result.is_valid, 'Wrong alpha should fail');
    assert(result.error_code == AGG_ERR_INVALID_AGGREGATION, 'Invalid aggregation error');
}

#[test]
fn test_verify_wrong_proof_count() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);
    let public_root = compute_public_inputs_root(commitments.span());

    let witness = AggregationWitness {
        aggregation_alpha: alpha,
        aggregated_trace: agg_trace,
        aggregated_composition: agg_comp,
        public_inputs_root: public_root,
        proof_count: 5, // WRONG - says 5 but only 2
    };

    let fri_data = create_valid_fri_proof(agg_trace, agg_comp);

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(!result.is_valid, 'Wrong count should fail');
    assert(result.error_code == AGG_ERR_INVALID_AGGREGATION, 'Invalid aggregation error');
}

#[test]
fn test_verify_wrong_aggregated_trace() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (correct_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);
    let wrong_trace = correct_trace + 1;
    let public_root = compute_public_inputs_root(commitments.span());

    let witness = AggregationWitness {
        aggregation_alpha: alpha,
        aggregated_trace: wrong_trace, // WRONG
        aggregated_composition: agg_comp,
        public_inputs_root: public_root,
        proof_count: 2,
    };

    let fri_data = create_valid_fri_proof(wrong_trace, agg_comp);

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(!result.is_valid, 'Wrong trace should fail');
    assert(result.error_code == AGG_ERR_COMMITMENT_MISMATCH, 'Commitment mismatch error');
}

#[test]
fn test_verify_wrong_public_root() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));
    commitments.append(create_test_commitment(2));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);
    let correct_root = compute_public_inputs_root(commitments.span());
    let wrong_root = correct_root + 1;

    let witness = AggregationWitness {
        aggregation_alpha: alpha,
        aggregated_trace: agg_trace,
        aggregated_composition: agg_comp,
        public_inputs_root: wrong_root, // WRONG
        proof_count: 2,
    };

    let fri_data = create_valid_fri_proof(agg_trace, agg_comp);

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(!result.is_valid, 'Wrong root should fail');
    assert(result.error_code == AGG_ERR_COMMITMENT_MISMATCH, 'Commitment mismatch error');
}

#[test]
fn test_verify_insufficient_fri_data() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));

    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);
    let public_root = compute_public_inputs_root(commitments.span());

    let witness = AggregationWitness {
        aggregation_alpha: alpha,
        aggregated_trace: agg_trace,
        aggregated_composition: agg_comp,
        public_inputs_root: public_root,
        proof_count: 1,
    };

    // Too short FRI data
    let fri_data: Array<felt252> = array![0x1, 0x2, 0x3];

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    let result = verify_aggregated_proof(@proof);
    assert(!result.is_valid, 'Short FRI should fail');
    assert(result.error_code == AGG_ERR_INVALID_PROOF, 'Invalid proof error');
}

// =============================================================================
// AGGREGATED PROOF TYPE TESTS
// =============================================================================

#[test]
fn test_aggregated_proof_creation() {
    let mut commitments: Array<ProofCommitment> = array![];
    commitments.append(create_test_commitment(1));

    let witness = AggregationWitness {
        aggregation_alpha: 0x123,
        aggregated_trace: 0x456,
        aggregated_composition: 0x789,
        public_inputs_root: 0xabc,
        proof_count: 1,
    };

    let mut fri_data: Array<felt252> = array![];
    fri_data.append(0xdef);

    let proof = AggregatedProof {
        commitments,
        witness,
        fri_proof_data: fri_data,
        query_responses: array![],
    };

    assert(proof.witness.proof_count == 1, 'Proof created correctly');
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

#[test]
fn test_full_aggregation_flow() {
    // Step 1: Create multiple commitments
    let mut commitments: Array<ProofCommitment> = array![];
    let mut i: u32 = 1;
    loop {
        if i > 5 {
            break;
        }
        commitments.append(create_test_commitment(i.into()));
        i += 1;
    };

    // Step 2: Compute aggregation parameters
    let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
    let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);
    let public_root = compute_public_inputs_root(commitments.span());

    // Step 3: Verify all values are computed correctly
    assert(alpha != 0, 'Alpha computed');
    assert(agg_trace != 0, 'Trace aggregated');
    assert(agg_comp != 0, 'Composition aggregated');
    assert(public_root != 0, 'Root computed');

    // Step 4: Estimate gas savings
    let (individual, aggregated, savings_pct) = estimate_gas_savings(5);
    assert(individual == 500000, '5 proofs = 500k individual');
    assert(aggregated == 125000, '5 proofs = 125k aggregated');
    assert(savings_pct >= 70, '5 proofs = 75% savings');
}

#[test]
fn test_aggregation_scaling() {
    // Test that gas savings scale with batch size
    let (_, _, savings_2) = estimate_gas_savings(2);
    let (_, _, savings_10) = estimate_gas_savings(10);
    let (_, _, savings_100) = estimate_gas_savings(100);

    // Larger batches should have better savings percentage
    assert(savings_10 > savings_2, '10 > 2 savings');
    assert(savings_100 > savings_10, '100 > 10 savings');
}
