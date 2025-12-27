// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Recursive Proof Aggregation
//
// This module implements proof aggregation for massive gas savings:
// - Aggregate N proofs into 1 aggregated proof
// - On-chain verification cost: O(1) instead of O(N)
// - Estimated savings: 80% for batches of 10+ proofs
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────┐
// │              Proof Aggregation Pipeline                      │
// ├─────────────────────────────────────────────────────────────┤
// │                                                              │
// │   [Proof1] [Proof2] [Proof3] ... [ProofN]                   │
// │       │        │        │           │                        │
// │       ▼        ▼        ▼           ▼                        │
// │   ┌─────────────────────────────────────────────┐           │
// │   │         Off-Chain Aggregator                 │           │
// │   │  1. Verify each proof locally               │           │
// │   │  2. Generate aggregation witness            │           │
// │   │  3. Produce single aggregated proof         │           │
// │   └─────────────────────────────────────────────┘           │
// │                        │                                     │
// │                        ▼                                     │
// │              [Aggregated Proof]                              │
// │                        │                                     │
// │                        ▼                                     │
// │   ┌─────────────────────────────────────────────┐           │
// │   │         On-Chain Verifier                    │           │
// │   │  Single verification = N proofs verified    │           │
// │   └─────────────────────────────────────────────┘           │
// │                                                              │
// │   Gas: 100k (single) vs 100k * N (individual)               │
// │   Savings: 80-95% for large batches                         │
// └─────────────────────────────────────────────────────────────┘

use core::poseidon::poseidon_hash_span;
use core::array::ArrayTrait;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum proofs per aggregation (limited by calldata size)
pub const MAX_PROOFS_PER_AGGREGATION: u32 = 256;

/// Minimum proofs for aggregation to be worthwhile
pub const MIN_PROOFS_FOR_AGGREGATION: u32 = 2;

/// Aggregation domain separator
pub const AGGREGATION_DOMAIN: felt252 = 'OBELYSK_AGG_V1';

// Error codes
pub const AGG_OK: u32 = 0;
pub const AGG_ERR_EMPTY_BATCH: u32 = 1;
pub const AGG_ERR_BATCH_TOO_LARGE: u32 = 2;
pub const AGG_ERR_INVALID_PROOF: u32 = 3;
pub const AGG_ERR_COMMITMENT_MISMATCH: u32 = 4;
pub const AGG_ERR_INVALID_AGGREGATION: u32 = 5;

// =============================================================================
// TYPES
// =============================================================================

/// A single proof commitment (minimal data needed for aggregation)
#[derive(Copy, Drop, Serde)]
pub struct ProofCommitment {
    /// Hash of the public inputs
    pub public_input_hash: felt252,
    /// Trace polynomial commitment
    pub trace_commitment: felt252,
    /// Composition polynomial commitment
    pub composition_commitment: felt252,
    /// FRI final layer commitment
    pub fri_final_commitment: felt252,
    /// Proof-of-work nonce
    pub pow_nonce: felt252,
}

/// Aggregation witness (proves correct aggregation)
#[derive(Copy, Drop, Serde)]
pub struct AggregationWitness {
    /// Random challenge for linear combination
    pub aggregation_alpha: felt252,
    /// Aggregated trace commitment
    pub aggregated_trace: felt252,
    /// Aggregated composition commitment
    pub aggregated_composition: felt252,
    /// Merkle root of all public input hashes
    pub public_inputs_root: felt252,
    /// Number of proofs aggregated
    pub proof_count: u32,
}

/// Full aggregated proof
#[derive(Drop, Serde)]
pub struct AggregatedProof {
    /// Individual proof commitments
    pub commitments: Array<ProofCommitment>,
    /// Aggregation witness
    pub witness: AggregationWitness,
    /// Combined FRI proof data
    pub fri_proof_data: Array<felt252>,
    /// Aggregated query responses
    pub query_responses: Array<felt252>,
}

/// Result of aggregation verification
#[derive(Copy, Drop, Serde)]
pub struct AggregationResult {
    /// Whether aggregation is valid
    pub is_valid: bool,
    /// Error code if invalid
    pub error_code: u32,
    /// Number of proofs verified
    pub proofs_verified: u32,
    /// Gas saved estimate (in units)
    pub estimated_gas_saved: u64,
}

// =============================================================================
// AGGREGATION FUNCTIONS
// =============================================================================

/// Compute aggregation challenge from all proof commitments
pub fn compute_aggregation_alpha(
    commitments: Span<ProofCommitment>,
    domain_separator: felt252,
) -> felt252 {
    let mut input: Array<felt252> = ArrayTrait::new();
    input.append(domain_separator);
    input.append(commitments.len().into());

    let mut i: u32 = 0;
    loop {
        if i >= commitments.len() {
            break;
        }
        let c = *commitments[i];
        input.append(c.public_input_hash);
        input.append(c.trace_commitment);
        input.append(c.composition_commitment);
        i += 1;
    };

    poseidon_hash_span(input.span())
}

/// Aggregate commitments using random linear combination
pub fn aggregate_commitments(
    commitments: Span<ProofCommitment>,
    alpha: felt252,
) -> (felt252, felt252) {
    let mut aggregated_trace: felt252 = 0;
    let mut aggregated_composition: felt252 = 0;
    let mut alpha_power: felt252 = 1;

    let mut i: u32 = 0;
    loop {
        if i >= commitments.len() {
            break;
        }

        let c = *commitments[i];

        // Linear combination: sum(alpha^i * commitment_i)
        aggregated_trace = aggregated_trace + alpha_power * c.trace_commitment;
        aggregated_composition = aggregated_composition + alpha_power * c.composition_commitment;

        // Update alpha power
        alpha_power = alpha_power * alpha;
        i += 1;
    };

    (aggregated_trace, aggregated_composition)
}

/// Compute Merkle root of public input hashes
pub fn compute_public_inputs_root(
    commitments: Span<ProofCommitment>,
) -> felt252 {
    if commitments.len() == 0 {
        return 0;
    }

    if commitments.len() == 1 {
        return (*commitments[0]).public_input_hash;
    }

    // Build Merkle tree from public input hashes
    let mut leaves: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= commitments.len() {
            break;
        }
        leaves.append((*commitments[i]).public_input_hash);
        i += 1;
    };

    compute_merkle_root(leaves.span())
}

/// Compute Merkle root from leaves
fn compute_merkle_root(leaves: Span<felt252>) -> felt252 {
    if leaves.len() == 0 {
        return 0;
    }
    if leaves.len() == 1 {
        return *leaves[0];
    }

    // Iteratively hash pairs until we have a single root
    let mut current_level: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    loop {
        if i >= leaves.len() {
            break;
        }
        current_level.append(*leaves[i]);
        i += 1;
    };

    loop {
        if current_level.len() <= 1 {
            break;
        }

        let mut next_level: Array<felt252> = ArrayTrait::new();
        let mut j: u32 = 0;

        loop {
            if j >= current_level.len() {
                break;
            }

            let left = *current_level.span()[j];
            let right = if j + 1 < current_level.len() {
                *current_level.span()[j + 1]
            } else {
                left // Duplicate for odd number
            };

            let mut hash_input: Array<felt252> = ArrayTrait::new();
            hash_input.append(left);
            hash_input.append(right);
            next_level.append(poseidon_hash_span(hash_input.span()));

            j += 2;
        };

        current_level = next_level;
    };

    if current_level.len() > 0 {
        *current_level.span()[0]
    } else {
        0
    }
}

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verify an aggregated proof
pub fn verify_aggregated_proof(
    proof: @AggregatedProof,
) -> AggregationResult {
    let commitments = proof.commitments.span();
    let witness = proof.witness;

    // Check batch size
    if commitments.len() == 0 {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_EMPTY_BATCH,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    if commitments.len() > MAX_PROOFS_PER_AGGREGATION {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_BATCH_TOO_LARGE,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    // Verify aggregation alpha is correctly computed
    let expected_alpha = compute_aggregation_alpha(commitments, AGGREGATION_DOMAIN);
    if *witness.aggregation_alpha != expected_alpha {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_INVALID_AGGREGATION,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    // Verify aggregated commitments
    let (expected_trace, expected_composition) = aggregate_commitments(
        commitments,
        *witness.aggregation_alpha,
    );

    if *witness.aggregated_trace != expected_trace {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_COMMITMENT_MISMATCH,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    if *witness.aggregated_composition != expected_composition {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_COMMITMENT_MISMATCH,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    // Verify public inputs root
    let expected_root = compute_public_inputs_root(commitments);
    if *witness.public_inputs_root != expected_root {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_COMMITMENT_MISMATCH,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    // Verify proof count matches
    if *witness.proof_count != commitments.len() {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_INVALID_AGGREGATION,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    // Verify FRI proof (simplified - would call full FRI verifier)
    let fri_valid = verify_aggregated_fri(
        proof.fri_proof_data.span(),
        *witness.aggregated_trace,
        *witness.aggregated_composition,
    );

    if !fri_valid {
        return AggregationResult {
            is_valid: false,
            error_code: AGG_ERR_INVALID_PROOF,
            proofs_verified: 0,
            estimated_gas_saved: 0,
        };
    }

    // Calculate gas savings
    // Individual: ~100k gas per proof
    // Aggregated: ~100k gas total + small overhead per proof
    let individual_gas: u64 = commitments.len().into() * 100_000_u64;
    let aggregated_gas: u64 = 100_000_u64 + commitments.len().into() * 5_000_u64;
    let gas_saved = individual_gas - aggregated_gas;

    AggregationResult {
        is_valid: true,
        error_code: AGG_OK,
        proofs_verified: commitments.len(),
        estimated_gas_saved: gas_saved,
    }
}

/// Verify aggregated FRI proof
fn verify_aggregated_fri(
    fri_data: Span<felt252>,
    aggregated_trace: felt252,
    aggregated_composition: felt252,
) -> bool {
    // Minimum FRI proof size check
    if fri_data.len() < 10 {
        return false;
    }

    // Verify FRI proof is bound to the aggregated commitments
    let mut binding_input: Array<felt252> = ArrayTrait::new();
    binding_input.append(aggregated_trace);
    binding_input.append(aggregated_composition);
    binding_input.append(*fri_data[0]); // First FRI layer commitment
    let expected_binding = poseidon_hash_span(binding_input.span());

    // Check binding (stored at index 1)
    let stored_binding = *fri_data[1];
    if stored_binding != expected_binding {
        return false;
    }

    // Additional FRI verification would go here
    // For now, we trust the binding check
    true
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Estimate gas savings for a given batch size
/// Returns (individual_gas, aggregated_gas, savings_percent_x100)
pub fn estimate_gas_savings(batch_size: u32) -> (u64, u64, u64) {
    if batch_size == 0 {
        return (0, 0, 0);
    }

    let batch_u64: u64 = batch_size.into();
    let individual_gas: u64 = batch_u64 * 100_000_u64;
    let aggregated_gas: u64 = 100_000_u64 + batch_u64 * 5_000_u64;
    let savings: u64 = individual_gas - aggregated_gas;

    // Calculate percentage (scaled by 100 for precision)
    let savings_percent = if individual_gas > 0 {
        (savings * 100) / individual_gas
    } else {
        0
    };

    (individual_gas, aggregated_gas, savings_percent)
}

/// Create a proof commitment from raw proof data
pub fn extract_commitment(proof_data: Span<felt252>) -> Option<ProofCommitment> {
    if proof_data.len() < 6 {
        return Option::None;
    }

    Option::Some(ProofCommitment {
        public_input_hash: *proof_data[0],
        trace_commitment: *proof_data[1],
        composition_commitment: *proof_data[2],
        fri_final_commitment: *proof_data[3],
        pow_nonce: *proof_data[4],
    })
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_commitment(id: felt252) -> ProofCommitment {
        ProofCommitment {
            public_input_hash: id,
            trace_commitment: id + 1,
            composition_commitment: id + 2,
            fri_final_commitment: id + 3,
            pow_nonce: id + 4,
        }
    }

    #[test]
    fn test_aggregation_alpha() {
        let mut commitments: Array<ProofCommitment> = ArrayTrait::new();
        commitments.append(create_test_commitment(1));
        commitments.append(create_test_commitment(100));

        let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
        assert(alpha != 0, 'Alpha should be non-zero');
    }

    #[test]
    fn test_aggregate_commitments() {
        let mut commitments: Array<ProofCommitment> = ArrayTrait::new();
        commitments.append(create_test_commitment(1));
        commitments.append(create_test_commitment(100));

        let alpha = compute_aggregation_alpha(commitments.span(), AGGREGATION_DOMAIN);
        let (agg_trace, agg_comp) = aggregate_commitments(commitments.span(), alpha);

        assert(agg_trace != 0, 'Aggregated trace non-zero');
        assert(agg_comp != 0, 'Aggregated comp non-zero');
    }

    #[test]
    fn test_merkle_root() {
        let mut commitments: Array<ProofCommitment> = ArrayTrait::new();
        commitments.append(create_test_commitment(1));
        commitments.append(create_test_commitment(100));
        commitments.append(create_test_commitment(200));

        let root = compute_public_inputs_root(commitments.span());
        assert(root != 0, 'Root should be non-zero');
    }

    #[test]
    fn test_gas_savings_estimate() {
        let (individual, aggregated, savings_pct) = estimate_gas_savings(10);

        // 10 proofs: 1M gas individual, ~150k aggregated
        assert(individual == 1_000_000, 'Individual gas wrong');
        assert(aggregated == 150_000, 'Aggregated gas wrong');
        assert(savings_pct >= 80_u64, 'Should save 80%+');
    }

    #[test]
    fn test_empty_batch() {
        let commitments: Array<ProofCommitment> = ArrayTrait::new();
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
            fri_proof_data: ArrayTrait::new(),
            query_responses: ArrayTrait::new(),
        };

        let result = verify_aggregated_proof(@proof);
        assert(!result.is_valid, 'Empty batch should fail');
        assert(result.error_code == AGG_ERR_EMPTY_BATCH, 'Wrong error code');
    }
}
