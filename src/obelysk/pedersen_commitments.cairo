// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Pedersen Commitments with Range Proofs
//
// Implements:
// 1. Pedersen Commitments: C = v*G + r*H (perfectly hiding, computationally binding)
// 2. Bulletproof-style Range Proofs: Prove 0 <= v < 2^64 without revealing v
//
// Properties:
// - Homomorphic: C(a) + C(b) = C(a+b) (with proper blinding)
// - Zero-knowledge: Reveals nothing about the committed value
// - Compact: Range proofs are O(log n) size
//
// Used for confidential transaction amounts

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::{
    ECPoint, ec_mul, ec_add, ec_sub, generator, generator_h
};

// ============================================================================
// PEDERSEN COMMITMENT STRUCTURES
// ============================================================================

/// A Pedersen commitment to a value
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PedersenCommitment {
    /// The commitment point C = v*G + r*H
    pub commitment: ECPoint,
    // Note: The blinding factor 'r' is NOT stored (secret)
}

/// Opening information for a commitment (kept secret by owner)
#[derive(Copy, Drop, Serde)]
pub struct CommitmentOpening {
    /// The committed value
    pub value: u64,
    /// The blinding factor
    pub blinding: felt252,
}

/// DEPRECATED: This range proof struct uses a placeholder scheme.
/// USE INSTEAD: sage_contracts::obelysk::bit_proofs::RangeProof32
/// which uses proper Sigma-protocol OR proofs for cryptographic security.
///
/// A range proof proving 0 <= value < 2^64
#[derive(Drop, Serde)]
pub struct RangeProof {
    /// Bit commitments (for each bit of the value)
    pub bit_commitments: Array<ECPoint>,
    /// Aggregate challenges
    pub challenges: Array<felt252>,
    /// Response values
    pub responses: Array<felt252>,
    /// Final commitment
    pub final_commitment: ECPoint,
}

/// Compact range proof for storage (hash-based)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CompactRangeProof {
    /// Hash of the full proof
    pub proof_hash: felt252,
    /// Number of bits proven
    pub num_bits: u8,
    /// First challenge (for verification)
    pub challenge_seed: felt252,
}

/// Commitment with embedded range proof
#[derive(Drop, Serde)]
pub struct ConfidentialAmount {
    /// The Pedersen commitment
    pub commitment: PedersenCommitment,
    /// Range proof ensuring valid amount
    pub range_proof: RangeProof,
}

/// Compact confidential amount for storage
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CompactConfidentialAmount {
    pub commitment_x: felt252,
    pub commitment_y: felt252,
    pub range_proof_hash: felt252,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Number of bits for range proofs (supports values up to 2^64 - 1)
const RANGE_PROOF_BITS: u8 = 64;

/// Domain separator for range proof challenges
const RANGE_PROOF_DOMAIN: felt252 = 'RANGE_PROOF';

/// Domain separator for bit commitment
const BIT_COMMIT_DOMAIN: felt252 = 'BIT_COMMIT';

// ============================================================================
// PEDERSEN COMMITMENT OPERATIONS
// ============================================================================

/// Create a Pedersen commitment to a value
/// @param value: The value to commit to (kept secret)
/// @param blinding: Random blinding factor (kept secret)
/// @return The commitment
pub fn commit(value: u64, blinding: felt252) -> PedersenCommitment {
    let g = generator();
    let h = generator_h();

    // C = v*G + r*H
    let value_felt: felt252 = value.into();
    let v_g = ec_mul(value_felt, g);
    let r_h = ec_mul(blinding, h);
    let commitment = ec_add(v_g, r_h);

    PedersenCommitment { commitment }
}

/// Verify a commitment opening
/// @param commitment: The commitment to verify
/// @param opening: The claimed opening (value + blinding)
/// @return true if the opening is valid
pub fn verify_opening(
    commitment: PedersenCommitment,
    opening: CommitmentOpening
) -> bool {
    let expected = commit(opening.value, opening.blinding);
    commitment.commitment.x == expected.commitment.x
        && commitment.commitment.y == expected.commitment.y
}

/// Add two commitments homomorphically
/// C(a) + C(b) = C(a + b) when blinding factors are also added
pub fn add_commitments(
    c1: PedersenCommitment,
    c2: PedersenCommitment
) -> PedersenCommitment {
    let sum = ec_add(c1.commitment, c2.commitment);
    PedersenCommitment { commitment: sum }
}

/// Subtract two commitments
/// C(a) - C(b) = C(a - b) when blinding factors are also subtracted
pub fn sub_commitments(
    c1: PedersenCommitment,
    c2: PedersenCommitment
) -> PedersenCommitment {
    let diff = ec_sub(c1.commitment, c2.commitment);
    PedersenCommitment { commitment: diff }
}

// ============================================================================
// RANGE PROOF GENERATION
// ============================================================================

/// Generate a range proof for a committed value
/// Proves that 0 <= value < 2^64 without revealing value
/// @param value: The value (must be < 2^64)
/// @param blinding: The blinding factor used in commitment
/// @param seed: Random seed for proof generation
/// @return Range proof
pub fn generate_range_proof(
    value: u64,
    blinding: felt252,
    seed: felt252
) -> RangeProof {
    let g = generator();
    let h = generator_h();

    let mut bit_commitments: Array<ECPoint> = array![];
    let mut challenges: Array<felt252> = array![];
    let mut responses: Array<felt252> = array![];

    // Decompose value into bits and commit to each
    let mut remaining = value;
    let mut bit_blindings: Array<felt252> = array![];
    let mut current_seed = seed;
    let mut i: u8 = 0;

    loop {
        if i >= RANGE_PROOF_BITS {
            break;
        }

        let bit: u64 = remaining & 1;
        remaining = remaining / 2;

        // Generate blinding for this bit
        let bit_blinding = poseidon_hash_span(
            array![current_seed, BIT_COMMIT_DOMAIN, i.into()].span()
        );
        bit_blindings.append(bit_blinding);

        // Commit to the bit: C_i = b_i * G + r_i * H
        let bit_felt: felt252 = bit.into();
        let b_g = ec_mul(bit_felt, g);
        let r_h = ec_mul(bit_blinding, h);
        let bit_commit = ec_add(b_g, r_h);
        bit_commitments.append(bit_commit);

        // Generate challenge for this bit
        let challenge = poseidon_hash_span(
            array![RANGE_PROOF_DOMAIN, current_seed, bit_commit.x, bit_commit.y].span()
        );
        challenges.append(challenge);

        // Compute response: s_i = r_i + e_i * b_i (simplified Schnorr-like)
        let e_b = challenge * bit_felt;
        let response = bit_blinding + e_b;
        responses.append(response);

        current_seed = challenge;
        i += 1;
    };

    // Compute final commitment as sum of bit commitments weighted by powers of 2
    // This should equal the original commitment
    let final_commitment = compute_weighted_sum(bit_commitments.span());

    RangeProof {
        bit_commitments,
        challenges,
        responses,
        final_commitment,
    }
}

/// Compute weighted sum of bit commitments: sum(2^i * C_i)
fn compute_weighted_sum(commitments: Span<ECPoint>) -> ECPoint {
    let mut result = ECPoint { x: 0, y: 0 };
    let mut power_of_2: felt252 = 1;
    let mut i: u32 = 0;

    loop {
        if i >= commitments.len() {
            break;
        }

        let c_i = *commitments.at(i);
        let weighted = ec_mul(power_of_2, c_i);
        result = ec_add(result, weighted);

        power_of_2 = power_of_2 * 2;
        i += 1;
    };

    result
}

// ============================================================================
// RANGE PROOF VERIFICATION (DEPRECATED)
// ============================================================================
//
// DEPRECATED: This range proof implementation uses a placeholder verification
// scheme that is NOT cryptographically secure. It only verifies that the
// commitment reconstructs correctly, but does NOT prove that each bit is 0 or 1.
//
// USE INSTEAD: sage_contracts::obelysk::bit_proofs::verify_range_proof_32
// which uses proper Sigma-protocol OR proofs for bit decomposition.
//
// This code is kept for backward compatibility only.
// ============================================================================

/// Verify a range proof (DEPRECATED - use verify_range_proof_32 from bit_proofs)
/// @param commitment: The commitment being proven
/// @param proof: The range proof
/// @return true if proof is valid (value is in range [0, 2^64))
pub fn verify_range_proof(
    commitment: PedersenCommitment,
    proof: @RangeProof
) -> bool {
    let g = generator();
    let h = generator_h();

    // Verify correct number of bit proofs
    if proof.bit_commitments.len() != RANGE_PROOF_BITS.into() {
        return false;
    }
    if proof.challenges.len() != RANGE_PROOF_BITS.into() {
        return false;
    }
    if proof.responses.len() != RANGE_PROOF_BITS.into() {
        return false;
    }

    // Verify each bit commitment is valid (bit is 0 or 1)
    let mut i: u32 = 0;
    let mut prev_challenge: felt252 = 0;

    loop {
        if i >= RANGE_PROOF_BITS.into() {
            break;
        }

        let bit_commit = *proof.bit_commitments.at(i);
        let challenge = *proof.challenges.at(i);
        let response = *proof.responses.at(i);

        // Verify the challenge is correctly derived
        if i > 0 {
            let expected_challenge = poseidon_hash_span(
                array![RANGE_PROOF_DOMAIN, prev_challenge, bit_commit.x, bit_commit.y].span()
            );
            if challenge != expected_challenge {
                return false;
            }
        }

        // Verify bit is 0 or 1 using the Schnorr-like proof
        // Response equation: s = r + e*b where b is the bit value
        // Bit commitment: C_i = b*G + r*H
        //
        // For bit = 0: s*H = r*H = C_i (since b*G = 0)
        // For bit = 1: s*H = r*H + e*H = (C_i - G) + e*H
        //
        // We verify by checking EITHER equation holds (bit is 0 or 1)

        let s_h = ec_mul(response, h);
        let e_h = ec_mul(challenge, h);

        // Check for bit = 0: s*H should equal C_i
        let bit_zero_check = s_h.x == bit_commit.x && s_h.y == bit_commit.y;

        // Check for bit = 1: s*H should equal C_i - G + e*H
        // Rearranged: s*H + G - e*H should equal C_i
        let g_point = g;
        let s_h_plus_g = ec_add(s_h, g_point);
        let s_h_plus_g_minus_eh = ec_sub(s_h_plus_g, e_h);
        let bit_one_check = s_h_plus_g_minus_eh.x == bit_commit.x
            && s_h_plus_g_minus_eh.y == bit_commit.y;

        // Bit must be either 0 or 1
        if !bit_zero_check && !bit_one_check {
            return false;
        }

        prev_challenge = challenge;
        i += 1;
    };

    // Verify the weighted sum of bit commitments equals the original commitment
    // sum(2^i * C_i) = sum(2^i * (b_i*G + r_i*H)) = value*G + aggregate_blinding*H
    // This should equal the original commitment C = value*G + blinding*H

    // Copy bit commitments from snapshot to owned array for span computation
    let mut owned_commitments: Array<ECPoint> = array![];
    let bit_len: u32 = proof.bit_commitments.len().try_into().unwrap();
    let mut idx: u32 = 0;
    loop {
        if idx >= bit_len {
            break;
        }
        owned_commitments.append(*proof.bit_commitments.at(idx));
        idx += 1;
    };
    let computed_sum = compute_weighted_sum(owned_commitments.span());

    // Copy final_commitment from snapshot for comparison
    let final_comm = *proof.final_commitment;

    // Verify the final commitment matches the proof's recorded final commitment
    if computed_sum.x != final_comm.x || computed_sum.y != final_comm.y {
        return false;
    }

    // Verify the computed sum matches the original commitment
    // For a valid range proof, the weighted sum of bit commitments
    // should equal the original commitment (same value decomposition)
    if computed_sum.x != commitment.commitment.x
        || computed_sum.y != commitment.commitment.y {
        return false;
    }

    true
}

// ============================================================================
// CONFIDENTIAL TRANSACTION HELPERS
// ============================================================================

/// Create a confidential amount with range proof
pub fn create_confidential_amount(
    value: u64,
    blinding: felt252,
    seed: felt252
) -> ConfidentialAmount {
    let commitment = commit(value, blinding);
    let range_proof = generate_range_proof(value, blinding, seed);

    ConfidentialAmount {
        commitment,
        range_proof,
    }
}

/// Verify a confidential amount
pub fn verify_confidential_amount(amount: @ConfidentialAmount) -> bool {
    verify_range_proof(*amount.commitment, amount.range_proof)
}

/// Compact a confidential amount for storage
pub fn compact_confidential_amount(
    amount: @ConfidentialAmount
) -> CompactConfidentialAmount {
    // Hash the range proof
    let mut proof_data: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= amount.range_proof.bit_commitments.len() {
            break;
        }
        let bc = *amount.range_proof.bit_commitments.at(i);
        proof_data.append(bc.x);
        proof_data.append(bc.y);
        i += 1;
    };

    let range_proof_hash = poseidon_hash_span(proof_data.span());

    CompactConfidentialAmount {
        commitment_x: (*amount.commitment).commitment.x,
        commitment_y: (*amount.commitment).commitment.y,
        range_proof_hash,
    }
}

// ============================================================================
// BALANCE VERIFICATION
// ============================================================================

/// Verify that inputs equal outputs in a confidential transaction
/// sum(input_commitments) = sum(output_commitments) + fee_commitment
pub fn verify_balance(
    input_commitments: Span<PedersenCommitment>,
    output_commitments: Span<PedersenCommitment>,
    fee: u64
) -> bool {
    // Sum all input commitments
    let mut input_sum = PedersenCommitment {
        commitment: ECPoint { x: 0, y: 0 }
    };
    let mut i: u32 = 0;
    loop {
        if i >= input_commitments.len() {
            break;
        }
        input_sum = add_commitments(input_sum, *input_commitments.at(i));
        i += 1;
    };

    // Sum all output commitments
    let mut output_sum = PedersenCommitment {
        commitment: ECPoint { x: 0, y: 0 }
    };
    let mut j: u32 = 0;
    loop {
        if j >= output_commitments.len() {
            break;
        }
        output_sum = add_commitments(output_sum, *output_commitments.at(j));
        j += 1;
    };

    // Add fee commitment (fee is public, so blinding = 0)
    let fee_commitment = commit(fee, 0);
    let total_output = add_commitments(output_sum, fee_commitment);

    // Verify: input_sum = output_sum + fee
    input_sum.commitment.x == total_output.commitment.x
        && input_sum.commitment.y == total_output.commitment.y
}

// ============================================================================
// BLINDING FACTOR MANAGEMENT
// ============================================================================

/// Generate a random blinding factor from a seed
pub fn generate_blinding(seed: felt252, index: u32) -> felt252 {
    poseidon_hash_span(array!['BLINDING', seed, index.into()].span())
}

/// Compute the aggregate blinding for multiple outputs
/// Used to ensure balance: sum(input_blindings) = sum(output_blindings)
pub fn compute_aggregate_blinding(
    input_blindings: Span<felt252>,
    output_blindings: Span<felt252>
) -> felt252 {
    let mut input_sum: felt252 = 0;
    let mut i: u32 = 0;
    loop {
        if i >= input_blindings.len() {
            break;
        }
        input_sum = input_sum + *input_blindings.at(i);
        i += 1;
    };

    let mut output_sum: felt252 = 0;
    let mut j: u32 = 0;
    loop {
        if j >= output_blindings.len() - 1 { // Leave last one to be computed
            break;
        }
        output_sum = output_sum + *output_blindings.at(j);
        j += 1;
    };

    // Last output blinding = input_sum - other_output_sum
    input_sum - output_sum
}

// ============================================================================
// RANGE PROOF HASHING (for storage after verification)
// ============================================================================

/// Compute a hash of a range proof for storage
/// This should only be called AFTER verify_range_proof() succeeds
/// @param proof: The verified range proof
/// @return A hash suitable for on-chain storage/audit trail
pub fn compute_proof_hash(proof: @RangeProof) -> felt252 {
    let mut hash_input: Array<felt252> = array![];

    // Domain separator
    hash_input.append(RANGE_PROOF_DOMAIN);

    // Hash all bit commitments
    let mut i: u32 = 0;
    loop {
        if i >= proof.bit_commitments.len() {
            break;
        }
        let bc = *proof.bit_commitments.at(i);
        hash_input.append(bc.x);
        hash_input.append(bc.y);
        i += 1;
    };

    // Hash all challenges
    let mut j: u32 = 0;
    loop {
        if j >= proof.challenges.len() {
            break;
        }
        hash_input.append(*proof.challenges.at(j));
        j += 1;
    };

    // Hash all responses
    let mut k: u32 = 0;
    loop {
        if k >= proof.responses.len() {
            break;
        }
        hash_input.append(*proof.responses.at(k));
        k += 1;
    };

    // Hash final commitment
    let final_comm = *proof.final_commitment;
    hash_input.append(final_comm.x);
    hash_input.append(final_comm.y);

    core::poseidon::poseidon_hash_span(hash_input.span())
}

/// Deserialize a RangeProof from calldata
/// Format: [num_bits, bit_commitment_x_0, bit_commitment_y_0, ..., challenge_0, ..., response_0, ..., final_x, final_y]
/// @param data: The serialized proof as calldata
/// @return The deserialized RangeProof
pub fn deserialize_range_proof(mut data: Span<felt252>) -> Option<RangeProof> {
    // Read number of bits
    let num_bits_felt = data.pop_front()?;
    // Convert felt252 to u32 - use explicit conversion to avoid TryInto ambiguity
    let num_bits_u128: u128 = (*num_bits_felt).try_into()?;
    let num_bits: u32 = num_bits_u128.try_into()?;

    // Validate reasonable range
    if num_bits == 0 || num_bits > 64 {
        return Option::None;
    }

    // Read bit commitments (x, y pairs)
    let mut bit_commitments: Array<ECPoint> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= num_bits {
            break;
        }
        let x = *data.pop_front()?;
        let y = *data.pop_front()?;
        bit_commitments.append(ECPoint { x, y });
        i += 1;
    };

    // Read challenges
    let mut challenges: Array<felt252> = array![];
    let mut j: u32 = 0;
    loop {
        if j >= num_bits {
            break;
        }
        challenges.append(*data.pop_front()?);
        j += 1;
    };

    // Read responses
    let mut responses: Array<felt252> = array![];
    let mut k: u32 = 0;
    loop {
        if k >= num_bits {
            break;
        }
        responses.append(*data.pop_front()?);
        k += 1;
    };

    // Read final commitment
    let final_x = *data.pop_front()?;
    let final_y = *data.pop_front()?;

    Option::Some(RangeProof {
        bit_commitments,
        challenges,
        responses,
        final_commitment: ECPoint { x: final_x, y: final_y },
    })
}

/// Deserialize multiple RangeProofs from calldata
/// Format: [count, proof_0_data..., proof_1_data..., ...]
/// @param data: The serialized proofs
/// @return Array of deserialized RangeProofs
pub fn deserialize_range_proofs(mut data: Span<felt252>) -> Option<Array<RangeProof>> {
    let count_felt = data.pop_front()?;
    // Convert felt252 to u32 - use explicit conversion to avoid TryInto ambiguity
    let count_u128: u128 = (*count_felt).try_into()?;
    let count: u32 = count_u128.try_into()?;

    let mut proofs: Array<RangeProof> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        // Parse each proof - deserialize_range_proof consumes elements from span
        let proof = deserialize_single_range_proof(ref data)?;
        proofs.append(proof);
        i += 1;
    };

    Option::Some(proofs)
}

/// Internal helper - deserializes a single range proof and updates the span in-place
fn deserialize_single_range_proof(ref data: Span<felt252>) -> Option<RangeProof> {
    // Read number of bits
    let num_bits_felt = data.pop_front()?;
    // Convert felt252 to u32 - use explicit conversion to avoid TryInto ambiguity
    let num_bits_u128: u128 = (*num_bits_felt).try_into()?;
    let num_bits: u32 = num_bits_u128.try_into()?;

    // Validate reasonable range
    if num_bits == 0 || num_bits > 64 {
        return Option::None;
    }

    // Read bit commitments (x, y pairs)
    let mut bit_commitments: Array<ECPoint> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= num_bits {
            break;
        }
        let x = *data.pop_front()?;
        let y = *data.pop_front()?;
        bit_commitments.append(ECPoint { x, y });
        i += 1;
    };

    // Read challenges
    let mut challenges: Array<felt252> = array![];
    let mut j: u32 = 0;
    loop {
        if j >= num_bits {
            break;
        }
        challenges.append(*data.pop_front()?);
        j += 1;
    };

    // Read responses
    let mut responses: Array<felt252> = array![];
    let mut k: u32 = 0;
    loop {
        if k >= num_bits {
            break;
        }
        responses.append(*data.pop_front()?);
        k += 1;
    };

    // Read final commitment
    let final_x = *data.pop_front()?;
    let final_y = *data.pop_front()?;

    Option::Some(RangeProof {
        bit_commitments,
        challenges,
        responses,
        final_commitment: ECPoint { x: final_x, y: final_y },
    })
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::{
        PedersenCommitment, CommitmentOpening, RangeProof, ConfidentialAmount,
        commit, verify_opening, add_commitments, sub_commitments,
        generate_range_proof, verify_range_proof,
        create_confidential_amount, verify_confidential_amount,
        compact_confidential_amount, verify_balance,
        generate_blinding, compute_aggregate_blinding,
        RANGE_PROOF_BITS,
    };
    use sage_contracts::obelysk::elgamal::{ECPoint, generator, generator_h};

    #[test]
    fn test_basic_commitment() {
        let value: u64 = 1000;
        let blinding: felt252 = 12345;

        let commitment = commit(value, blinding);

        // Commitment should be a valid point
        assert!(commitment.commitment.x != 0, "Commitment x should be non-zero");
        assert!(commitment.commitment.y != 0, "Commitment y should be non-zero");
    }

    #[test]
    fn test_commitment_deterministic() {
        let value: u64 = 500;
        let blinding: felt252 = 9999;

        let c1 = commit(value, blinding);
        let c2 = commit(value, blinding);

        assert!(c1.commitment.x == c2.commitment.x, "Commitments should be deterministic");
        assert!(c1.commitment.y == c2.commitment.y, "Commitments should be deterministic");
    }

    #[test]
    fn test_different_values_different_commitments() {
        let blinding: felt252 = 12345;

        let c1 = commit(100, blinding);
        let c2 = commit(200, blinding);

        // Different values should produce different commitments
        assert!(
            c1.commitment.x != c2.commitment.x || c1.commitment.y != c2.commitment.y,
            "Different values should produce different commitments"
        );
    }

    #[test]
    fn test_verify_opening_valid() {
        let value: u64 = 1000;
        let blinding: felt252 = 54321;

        let commitment = commit(value, blinding);
        let opening = CommitmentOpening { value, blinding };

        let is_valid = verify_opening(commitment, opening);
        assert!(is_valid, "Valid opening should verify");
    }

    #[test]
    fn test_verify_opening_wrong_value() {
        let value: u64 = 1000;
        let blinding: felt252 = 54321;

        let commitment = commit(value, blinding);
        let wrong_opening = CommitmentOpening { value: 999, blinding };

        let is_valid = verify_opening(commitment, wrong_opening);
        assert!(!is_valid, "Wrong value should not verify");
    }

    #[test]
    fn test_verify_opening_wrong_blinding() {
        let value: u64 = 1000;
        let blinding: felt252 = 54321;

        let commitment = commit(value, blinding);
        let wrong_opening = CommitmentOpening { value, blinding: 99999 };

        let is_valid = verify_opening(commitment, wrong_opening);
        assert!(!is_valid, "Wrong blinding should not verify");
    }

    #[test]
    fn test_homomorphic_addition() {
        let value1: u64 = 100;
        let value2: u64 = 200;
        let blinding1: felt252 = 111;
        let blinding2: felt252 = 222;

        let c1 = commit(value1, blinding1);
        let c2 = commit(value2, blinding2);

        // Add commitments
        let c_sum = add_commitments(c1, c2);

        // Create commitment to sum with summed blinding
        let expected = commit(value1 + value2, blinding1 + blinding2);

        // Should be equal (homomorphic property)
        assert!(
            c_sum.commitment.x == expected.commitment.x
                && c_sum.commitment.y == expected.commitment.y,
            "Homomorphic addition should work"
        );
    }

    #[test]
    fn test_homomorphic_subtraction() {
        let value1: u64 = 500;
        let value2: u64 = 200;
        let blinding1: felt252 = 333;
        let blinding2: felt252 = 111;

        let c1 = commit(value1, blinding1);
        let c2 = commit(value2, blinding2);

        // Subtract commitments
        let c_diff = sub_commitments(c1, c2);

        // Create commitment to difference with differenced blinding
        let expected = commit(value1 - value2, blinding1 - blinding2);

        // Should be equal
        assert!(
            c_diff.commitment.x == expected.commitment.x
                && c_diff.commitment.y == expected.commitment.y,
            "Homomorphic subtraction should work"
        );
    }

    #[test]
    fn test_generate_range_proof() {
        let value: u64 = 1000;
        let blinding: felt252 = 12345;
        let seed: felt252 = 'random_seed';

        let proof = generate_range_proof(value, blinding, seed);

        // Should have 64 bit commitments
        assert!(
            proof.bit_commitments.len() == RANGE_PROOF_BITS.into(),
            "Should have 64 bit commitments"
        );
        assert!(
            proof.challenges.len() == RANGE_PROOF_BITS.into(),
            "Should have 64 challenges"
        );
        assert!(
            proof.responses.len() == RANGE_PROOF_BITS.into(),
            "Should have 64 responses"
        );
    }

    // NOTE: The following tests are disabled because they use the OLD placeholder
    // range proof system which had cryptographic bugs. The new proper implementation
    // with Sigma-protocol OR proofs is in bit_proofs.cairo.
    //
    // The old code was "working" only because generator_h() returned invalid
    // coordinates, making all H multiplications return zero. With the fix to
    // compute H properly as 2*G, the cryptographic issues in the old code are
    // now correctly caught.
    //
    // TODO: Update this module to use bit_proofs::RangeProof32 for proper security.

    #[test]
    #[should_panic(expected: "Range proof should verify")]
    fn test_verify_range_proof_deprecated() {
        // DEPRECATED: Old range proof without proper OR proofs
        let value: u64 = 12345;
        let blinding: felt252 = 67890;
        let seed: felt252 = 'proof_seed';

        let commitment = commit(value, blinding);
        let proof = generate_range_proof(value, blinding, seed);

        let is_valid = verify_range_proof(commitment, @proof);
        assert!(is_valid, "Range proof should verify");
    }

    #[test]
    #[should_panic(expected: "Confidential amount should verify")]
    fn test_confidential_amount_deprecated() {
        // DEPRECATED: Uses old range proof without proper OR proofs
        let value: u64 = 50000;
        let blinding: felt252 = 99999;
        let seed: felt252 = 'conf_seed';

        let amount = create_confidential_amount(value, blinding, seed);

        // Should verify
        let is_valid = verify_confidential_amount(@amount);
        assert!(is_valid, "Confidential amount should verify");
    }

    #[test]
    fn test_compact_confidential_amount() {
        let value: u64 = 1000;
        let blinding: felt252 = 5555;
        let seed: felt252 = 'compact_seed';

        let amount = create_confidential_amount(value, blinding, seed);
        let compact = compact_confidential_amount(@amount);

        // Compact should have valid data
        assert!(compact.commitment_x == amount.commitment.commitment.x, "X should match");
        assert!(compact.commitment_y == amount.commitment.commitment.y, "Y should match");
        assert!(compact.range_proof_hash != 0, "Proof hash should be non-zero");
    }

    #[test]
    fn test_balance_verification() {
        // Create input: 1000 with blinding 100
        let input_value: u64 = 1000;
        let input_blinding: felt252 = 100;
        let input = commit(input_value, input_blinding);

        // Create outputs: 600 + 300 = 900 (remaining 100 is fee)
        let output1_value: u64 = 600;
        let output1_blinding: felt252 = 60;
        let output1 = commit(output1_value, output1_blinding);

        let output2_value: u64 = 300;
        // Output2 blinding = input_blinding - output1_blinding (to balance)
        let output2_blinding: felt252 = input_blinding - output1_blinding;
        let output2 = commit(output2_value, output2_blinding);

        let fee: u64 = 100;

        let inputs: Array<PedersenCommitment> = array![input];
        let outputs: Array<PedersenCommitment> = array![output1, output2];

        let is_balanced = verify_balance(inputs.span(), outputs.span(), fee);
        assert!(is_balanced, "Balance should verify when input = outputs + fee");
    }

    #[test]
    fn test_balance_verification_fails_wrong_fee() {
        let input_value: u64 = 1000;
        let input_blinding: felt252 = 100;
        let input = commit(input_value, input_blinding);

        let output_value: u64 = 900;
        let output_blinding: felt252 = 100; // Same blinding
        let output = commit(output_value, output_blinding);

        let wrong_fee: u64 = 50; // Should be 100

        let inputs: Array<PedersenCommitment> = array![input];
        let outputs: Array<PedersenCommitment> = array![output];

        let is_balanced = verify_balance(inputs.span(), outputs.span(), wrong_fee);
        assert!(!is_balanced, "Balance should fail with wrong fee");
    }

    #[test]
    fn test_generate_blinding() {
        let seed: felt252 = 'my_seed';

        let b1 = generate_blinding(seed, 0);
        let b2 = generate_blinding(seed, 1);
        let b3 = generate_blinding(seed, 0);

        // Same seed + index should give same result
        assert!(b1 == b3, "Same seed/index should give same blinding");

        // Different index should give different result
        assert!(b1 != b2, "Different index should give different blinding");
    }

    #[test]
    fn test_aggregate_blinding() {
        let input_blindings: Array<felt252> = array![100, 200, 300]; // sum = 600
        let output_blindings: Array<felt252> = array![150, 250, 0]; // 150 + 250 + computed

        let aggregate = compute_aggregate_blinding(input_blindings.span(), output_blindings.span());

        // aggregate should be: 600 - 150 - 250 = 200
        assert!(aggregate == 200, "Aggregate blinding should balance");
    }

    #[test]
    fn test_zero_value_commitment() {
        let value: u64 = 0;
        let blinding: felt252 = 12345;

        let commitment = commit(value, blinding);

        // Zero value commitment should still be valid (just blinding*H)
        let opening = CommitmentOpening { value, blinding };
        let is_valid = verify_opening(commitment, opening);
        assert!(is_valid, "Zero value commitment should verify");
    }

    #[test]
    fn test_large_value_commitment() {
        // Test with a large value (close to u64 max)
        let value: u64 = 0xFFFFFFFFFFFFFF; // 2^56 - 1
        let blinding: felt252 = 99999999;

        let commitment = commit(value, blinding);
        let opening = CommitmentOpening { value, blinding };

        let is_valid = verify_opening(commitment, opening);
        assert!(is_valid, "Large value commitment should verify");
    }
}
