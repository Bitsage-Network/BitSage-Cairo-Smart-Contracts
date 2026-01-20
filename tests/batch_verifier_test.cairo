// SPDX-License-Identifier: BUSL-1.1
// Batch Verifier Tests
// Comprehensive tests for optimized batch proof verification

use sage_contracts::obelysk::batch_verifier::{
    // Types
    BatchConfig, BatchConfigDefault, BatchProofEntry, BatchVerificationResult,
    AggregatedCommitment,
    // Functions
    generate_batch_randomness, aggregate_commitments, verify_batch,
    batch_verify_merkle_paths, aggregate_fri_queries,
};

// =============================================================================
// TEST HELPERS
// =============================================================================

fn create_test_proof_entry(id: felt252, job_id: u256) -> BatchProofEntry {
    // Create proof data that meets minimum requirements
    // Needs: config (4), commitments (2), field elements, FRI layers, PoW
    let mut proof_data: Array<felt252> = array![];

    // Config: pow_bits, log_blowup, log_last_layer, n_queries
    proof_data.append(16); // pow_bits (12-30)
    proof_data.append(4);  // log_blowup (1-16)
    proof_data.append(4);  // log_last_layer
    proof_data.append(16); // n_queries (4-128)

    // Commitments
    proof_data.append(id * 1000 + 100); // trace_commitment
    proof_data.append(id * 1000 + 200); // composition_commitment

    // Field elements (M31 valid: < 2^31-1 = 2147483647)
    let mut i: u32 = 0;
    loop {
        if i >= 30 {
            break;
        }
        proof_data.append((i + 1000).into());
        i += 1;
    };

    BatchProofEntry {
        proof_id: id,
        proof_data,
        public_input_hash: id * 1000 + 1,
        job_id,
    }
}

fn create_minimal_proof_entry(id: felt252) -> BatchProofEntry {
    // Create entry with insufficient proof data
    let proof_data: Array<felt252> = array![0x1, 0x2, 0x3];

    BatchProofEntry {
        proof_id: id,
        proof_data,
        public_input_hash: id,
        job_id: 1_u256,
    }
}

// =============================================================================
// BATCH CONFIG TESTS
// =============================================================================

#[test]
fn test_batch_config_default() {
    let config = BatchConfigDefault::default();
    assert(config.max_batch_size == 50, 'Default batch size 50');
    assert(config.enable_aggregation == true, 'Aggregation enabled');
    assert(config.enable_parallel_queries == true, 'Parallel queries enabled');
    assert(config.min_security_bits == 96, 'Min 96 security bits');
}

#[test]
fn test_batch_config_custom() {
    let config = BatchConfig {
        max_batch_size: 100,
        enable_aggregation: false,
        enable_parallel_queries: false,
        min_security_bits: 128,
    };

    assert(config.max_batch_size == 100, 'Custom batch size');
    assert(!config.enable_aggregation, 'Aggregation disabled');
    assert(!config.enable_parallel_queries, 'Parallel disabled');
    assert(config.min_security_bits == 128, '128 security bits');
}

#[test]
fn test_batch_config_copy() {
    let config1 = BatchConfigDefault::default();
    let config2 = config1;

    assert(config1.max_batch_size == config2.max_batch_size, 'Copy preserves data');
}

// =============================================================================
// BATCH PROOF ENTRY TESTS
// =============================================================================

#[test]
fn test_batch_proof_entry_creation() {
    let mut proof_data: Array<felt252> = array![];
    proof_data.append(0x1234);

    let entry = BatchProofEntry {
        proof_id: 0xabc,
        proof_data,
        public_input_hash: 0xdef,
        job_id: 42_u256,
    };

    assert(entry.proof_id == 0xabc, 'Proof ID set');
    assert(entry.public_input_hash == 0xdef, 'Public input hash set');
    assert(entry.job_id == 42_u256, 'Job ID set');
}

#[test]
fn test_batch_proof_entry_with_full_data() {
    let entry = create_test_proof_entry(1, 100_u256);

    assert(entry.proof_id == 1, 'Proof ID correct');
    assert(entry.job_id == 100_u256, 'Job ID correct');
    assert(entry.proof_data.len() >= 32, 'Sufficient proof data');
}

// =============================================================================
// BATCH VERIFICATION RESULT TESTS
// =============================================================================

#[test]
fn test_batch_verification_result_all_valid() {
    let mut proof_results: Array<(felt252, bool)> = array![];
    proof_results.append((1, true));
    proof_results.append((2, true));
    proof_results.append((3, true));

    let result = BatchVerificationResult {
        total_proofs: 3,
        verified_count: 3,
        failed_count: 0,
        skipped_count: 0,
        aggregated_commitment: 0x12345,
        shared_randomness: 0x67890,
        proof_results,
        estimated_gas_saved: 90000,
    };

    assert(result.total_proofs == 3, 'Total proofs 3');
    assert(result.verified_count == 3, 'All verified');
    assert(result.failed_count == 0, 'None failed');
    assert(result.estimated_gas_saved == 90000, 'Gas saved');
}

#[test]
fn test_batch_verification_result_mixed() {
    let mut proof_results: Array<(felt252, bool)> = array![];
    proof_results.append((1, true));
    proof_results.append((2, false));
    proof_results.append((3, true));

    let result = BatchVerificationResult {
        total_proofs: 3,
        verified_count: 2,
        failed_count: 1,
        skipped_count: 0,
        aggregated_commitment: 0x12345,
        shared_randomness: 0x67890,
        proof_results,
        estimated_gas_saved: 60000,
    };

    assert(result.verified_count == 2, 'Two verified');
    assert(result.failed_count == 1, 'One failed');
}

// =============================================================================
// AGGREGATED COMMITMENT TESTS
// =============================================================================

#[test]
fn test_aggregated_commitment_creation() {
    let agg = AggregatedCommitment {
        trace_commitment: 0xabc,
        composition_commitment: 0xdef,
        proof_count: 5,
        aggregation_alpha: 0x123,
    };

    assert(agg.trace_commitment == 0xabc, 'Trace commitment set');
    assert(agg.composition_commitment == 0xdef, 'Composition set');
    assert(agg.proof_count == 5, 'Proof count 5');
    assert(agg.aggregation_alpha == 0x123, 'Alpha set');
}

#[test]
fn test_aggregated_commitment_copy() {
    let agg1 = AggregatedCommitment {
        trace_commitment: 0x111,
        composition_commitment: 0x222,
        proof_count: 10,
        aggregation_alpha: 0x333,
    };
    let agg2 = agg1;

    assert(agg1.proof_count == agg2.proof_count, 'Copy preserves count');
}

// =============================================================================
// GENERATE BATCH RANDOMNESS TESTS
// =============================================================================

#[test]
fn test_generate_batch_randomness_single_entry() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));

    let randomness = generate_batch_randomness(entries.span(), 1000, 100);
    assert(randomness != 0, 'Randomness non-zero');
}

#[test]
fn test_generate_batch_randomness_multiple_entries() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));
    entries.append(create_test_proof_entry(2, 2_u256));
    entries.append(create_test_proof_entry(3, 3_u256));

    let randomness = generate_batch_randomness(entries.span(), 2000, 200);
    assert(randomness != 0, 'Randomness non-zero');
}

#[test]
fn test_generate_batch_randomness_deterministic() {
    let mut entries1: Array<BatchProofEntry> = array![];
    entries1.append(create_test_proof_entry(1, 1_u256));

    let mut entries2: Array<BatchProofEntry> = array![];
    entries2.append(create_test_proof_entry(1, 1_u256));

    let r1 = generate_batch_randomness(entries1.span(), 1000, 100);
    let r2 = generate_batch_randomness(entries2.span(), 1000, 100);

    assert(r1 == r2, 'Deterministic randomness');
}

#[test]
fn test_generate_batch_randomness_block_dependent() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));

    let r1 = generate_batch_randomness(entries.span(), 1000, 100);
    let r2 = generate_batch_randomness(entries.span(), 1001, 100); // Different timestamp

    assert(r1 != r2, 'Diff blocks = diff random');
}

#[test]
fn test_generate_batch_randomness_entry_dependent() {
    let mut entries1: Array<BatchProofEntry> = array![];
    entries1.append(create_test_proof_entry(1, 1_u256));

    let mut entries2: Array<BatchProofEntry> = array![];
    entries2.append(create_test_proof_entry(2, 1_u256)); // Different proof ID

    let r1 = generate_batch_randomness(entries1.span(), 1000, 100);
    let r2 = generate_batch_randomness(entries2.span(), 1000, 100);

    assert(r1 != r2, 'Diff entries = diff random');
}

// =============================================================================
// AGGREGATE COMMITMENTS TESTS
// =============================================================================

#[test]
fn test_aggregate_commitments_single() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));

    let agg = aggregate_commitments(entries.span(), 0x12345);

    assert(agg.proof_count == 1, 'One proof aggregated');
    assert(agg.trace_commitment != 0, 'Trace non-zero');
    assert(agg.aggregation_alpha == 0x12345, 'Alpha preserved');
}

#[test]
fn test_aggregate_commitments_multiple() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));
    entries.append(create_test_proof_entry(2, 2_u256));
    entries.append(create_test_proof_entry(3, 3_u256));

    let agg = aggregate_commitments(entries.span(), 0x12345);

    assert(agg.proof_count == 3, 'Three proofs aggregated');
    assert(agg.trace_commitment != 0, 'Trace non-zero');
    assert(agg.composition_commitment != 0, 'Composition non-zero');
}

#[test]
fn test_aggregate_commitments_with_minimal_entries() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_minimal_proof_entry(1));
    entries.append(create_minimal_proof_entry(2));

    let agg = aggregate_commitments(entries.span(), 0x12345);

    // Entries with < 6 elements in proof_data are skipped
    assert(agg.proof_count == 0, 'Minimal entries skipped');
}

#[test]
fn test_aggregate_commitments_alpha_matters() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));
    entries.append(create_test_proof_entry(2, 2_u256));

    let agg1 = aggregate_commitments(entries.span(), 0x11111);
    let agg2 = aggregate_commitments(entries.span(), 0x22222);

    assert(agg1.trace_commitment != agg2.trace_commitment, 'Diff alpha = diff result');
}

// =============================================================================
// VERIFY BATCH TESTS
// =============================================================================

#[test]
fn test_verify_batch_empty() {
    let config = BatchConfigDefault::default();
    let entries: Array<BatchProofEntry> = array![];

    let result = verify_batch(config, entries.span(), 1000, 100);

    assert(result.total_proofs == 0, 'Zero proofs');
    assert(result.verified_count == 0, 'None verified');
}

#[test]
fn test_verify_batch_exceeds_max() {
    let config = BatchConfig {
        max_batch_size: 2, // Small limit
        enable_aggregation: true,
        enable_parallel_queries: true,
        min_security_bits: 96,
    };

    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));
    entries.append(create_test_proof_entry(2, 2_u256));
    entries.append(create_test_proof_entry(3, 3_u256)); // Exceeds limit

    let result = verify_batch(config, entries.span(), 1000, 100);

    assert(result.skipped_count == 3, 'All skipped due to limit');
    assert(result.verified_count == 0, 'None verified');
}

#[test]
fn test_verify_batch_with_invalid_proofs() {
    let config = BatchConfigDefault::default();

    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_minimal_proof_entry(1)); // Too short - will be skipped

    let result = verify_batch(config, entries.span(), 1000, 100);

    assert(result.total_proofs == 1, 'One proof submitted');
    assert(result.skipped_count == 1, 'Invalid proof skipped');
}

#[test]
fn test_verify_batch_computes_randomness() {
    let config = BatchConfigDefault::default();

    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));

    let result = verify_batch(config, entries.span(), 1000, 100);

    assert(result.shared_randomness != 0, 'Randomness computed');
}

#[test]
fn test_verify_batch_with_aggregation_disabled() {
    let config = BatchConfig {
        max_batch_size: 50,
        enable_aggregation: false, // Disabled
        enable_parallel_queries: true,
        min_security_bits: 96,
    };

    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));

    let result = verify_batch(config, entries.span(), 1000, 100);

    assert(result.aggregated_commitment == 0, 'No aggregation when disabled');
}

#[test]
fn test_verify_batch_gas_savings() {
    let config = BatchConfigDefault::default();

    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));
    entries.append(create_test_proof_entry(2, 2_u256));
    entries.append(create_test_proof_entry(3, 3_u256));

    let result = verify_batch(config, entries.span(), 1000, 100);

    // 3 proofs: individual = 300k, batch = 210k, savings = 90k
    assert(result.estimated_gas_saved == 90000, 'Gas savings calculated');
}

// =============================================================================
// BATCH MERKLE PATH VERIFICATION TESTS
// =============================================================================

#[test]
fn test_batch_verify_merkle_paths_empty() {
    let queries: Array<(felt252, u32, Span<felt252>, felt252)> = array![];

    let (valid, invalid) = batch_verify_merkle_paths(queries.span());

    assert(valid == 0, 'No valid paths');
    assert(invalid == 0, 'No invalid paths');
}

#[test]
fn test_batch_verify_merkle_paths_single_leaf() {
    // Single leaf: path is empty, root = leaf_hash
    let leaf_hash = 0x12345_felt252;
    let path: Array<felt252> = array![];

    let mut queries: Array<(felt252, u32, Span<felt252>, felt252)> = array![];
    queries.append((leaf_hash, 0, path.span(), leaf_hash)); // root = leaf for single element

    let (valid, invalid) = batch_verify_merkle_paths(queries.span());

    assert(valid == 1, 'One valid path');
    assert(invalid == 0, 'None invalid');
}

// =============================================================================
// AGGREGATE FRI QUERIES TESTS
// =============================================================================

#[test]
fn test_aggregate_fri_queries_empty() {
    let query_values: Array<(felt252, felt252)> = array![];
    let alphas: Array<felt252> = array![];

    let combined = aggregate_fri_queries(query_values.span(), alphas.span());

    assert(combined == 0, 'Empty should be 0');
}

#[test]
fn test_aggregate_fri_queries_single() {
    let mut query_values: Array<(felt252, felt252)> = array![];
    query_values.append((10, 20)); // f(x) = 10, f(-x) = 20

    let mut alphas: Array<felt252> = array![];
    alphas.append(1); // alpha = 1

    let combined = aggregate_fri_queries(query_values.span(), alphas.span());

    // combined = 1 * (10 + 20) = 30
    assert(combined == 30, 'Combined should be 30');
}

#[test]
fn test_aggregate_fri_queries_multiple() {
    let mut query_values: Array<(felt252, felt252)> = array![];
    query_values.append((10, 20)); // sum = 30
    query_values.append((5, 15));  // sum = 20

    let mut alphas: Array<felt252> = array![];
    alphas.append(1);
    alphas.append(2);

    let combined = aggregate_fri_queries(query_values.span(), alphas.span());

    // combined = 1 * 30 + 2 * 20 = 30 + 40 = 70
    assert(combined == 70, 'Combined should be 70');
}

#[test]
fn test_aggregate_fri_queries_mismatched_lengths() {
    let mut query_values: Array<(felt252, felt252)> = array![];
    query_values.append((10, 20));
    query_values.append((5, 15));
    query_values.append((100, 200)); // Extra value - will be ignored

    let mut alphas: Array<felt252> = array![];
    alphas.append(1);
    alphas.append(2);

    let combined = aggregate_fri_queries(query_values.span(), alphas.span());

    // Only first 2 processed due to shorter alphas array
    // combined = 1 * 30 + 2 * 20 = 70
    assert(combined == 70, 'Uses min length');
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

#[test]
fn test_full_batch_verification_flow() {
    let config = BatchConfigDefault::default();

    // Create batch of proof entries
    let mut entries: Array<BatchProofEntry> = array![];
    let mut i: u32 = 1;
    loop {
        if i > 5 {
            break;
        }
        entries.append(create_test_proof_entry(i.into(), i.into()));
        i += 1;
    };

    // Generate batch randomness
    let randomness = generate_batch_randomness(entries.span(), 12345, 100);
    assert(randomness != 0, 'Randomness generated');

    // Aggregate commitments
    let agg = aggregate_commitments(entries.span(), randomness);
    assert(agg.proof_count == 5, 'All 5 proofs aggregated');

    // Verify batch
    let result = verify_batch(config, entries.span(), 12345, 100);
    assert(result.total_proofs == 5, '5 proofs in batch');
    assert(result.shared_randomness == randomness, 'Same randomness used');
}

#[test]
fn test_gas_savings_increase_with_batch_size() {
    let config = BatchConfigDefault::default();

    // Batch of 2
    let mut entries2: Array<BatchProofEntry> = array![];
    entries2.append(create_test_proof_entry(1, 1_u256));
    entries2.append(create_test_proof_entry(2, 2_u256));

    // Batch of 5
    let mut entries5: Array<BatchProofEntry> = array![];
    let mut i: u32 = 1;
    loop {
        if i > 5 {
            break;
        }
        entries5.append(create_test_proof_entry(i.into(), i.into()));
        i += 1;
    };

    let result2 = verify_batch(config, entries2.span(), 1000, 100);
    let result5 = verify_batch(config, entries5.span(), 1000, 100);

    // Larger batch should have more total gas savings
    assert(result5.estimated_gas_saved > result2.estimated_gas_saved, 'Larger batch = more savings');
}

#[test]
fn test_batch_with_mixed_validity() {
    let config = BatchConfigDefault::default();

    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256)); // Valid
    entries.append(create_minimal_proof_entry(2));      // Invalid - too short
    entries.append(create_test_proof_entry(3, 3_u256)); // Valid

    let result = verify_batch(config, entries.span(), 1000, 100);

    assert(result.total_proofs == 3, 'Three proofs submitted');
    assert(result.skipped_count >= 1, 'At least one skipped');
}

#[test]
fn test_randomness_uniqueness_across_batches() {
    let mut entries: Array<BatchProofEntry> = array![];
    entries.append(create_test_proof_entry(1, 1_u256));

    // Different block data should produce different randomness
    let r1 = generate_batch_randomness(entries.span(), 1000, 100);
    let r2 = generate_batch_randomness(entries.span(), 1000, 101);
    let r3 = generate_batch_randomness(entries.span(), 1001, 100);

    assert(r1 != r2, 'Different block = different r');
    assert(r1 != r3, 'Diff timestamp = diff r');
    assert(r2 != r3, 'All unique');
}
