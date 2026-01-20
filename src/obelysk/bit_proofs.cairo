// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Bit Proofs and Range Proofs with Proper Bit Decomposition
//
// Based on Tongo's SHE library range proofs (range.md)
//
// This module provides cryptographically secure range proofs using:
// 1. Bit decomposition: value = Σ b_i * 2^i
// 2. Bit commitments: V_i = b_i * G + r_i * H
// 3. OR proofs: Prove each V_i commits to 0 or 1
// 4. Consistency: Verify Σ 2^i * V_i = value * G + r * H
//
// The key security property is the OR proof construction:
// - Prover creates a "real" proof for the actual bit value
// - Prover creates a "simulated" proof for the other value
// - Challenge is split: c = c0 + c1 (mod n)
// - Verifier can't tell which proof is real
// - Prover can only succeed if the bit is actually 0 or 1
//
// This prevents:
// - Negative balance attacks (can't prove negative values)
// - Overflow exploits (values must be in range)
// - Hidden value manipulation

use core::poseidon::poseidon_hash_span;
use super::elgamal::{
    ECPoint,
    ec_add, ec_sub, ec_mul, ec_zero, is_zero,
    generator, generator_h,
    reduce_mod_n, mul_mod_n, add_mod_n, sub_mod_n,
};

// =============================================================================
// Constants
// =============================================================================

/// Domain separator for bit proofs
pub const BIT_PROOF_DOMAIN: felt252 = 'obelysk-bit-proof-v1';

/// Domain separator for range proofs
pub const RANGE_PROOF_DOMAIN: felt252 = 'obelysk-range-proof-v1';

/// Number of bits for standard range proof (32 bits = values 0 to 2^32-1)
pub const RANGE_BITS_32: u32 = 32;

/// Number of bits for extended range proof (64 bits)
pub const RANGE_BITS_64: u32 = 64;

// =============================================================================
// Proof Structures
// =============================================================================

/// OR proof that a Pedersen commitment contains either 0 or 1
///
/// This is the fundamental building block for range proofs.
/// Uses the Sigma-protocol OR construction:
/// - One branch is a real Schnorr proof (prover knows witness)
/// - One branch is a simulated proof (prover chooses challenge first)
/// - Verifier can't distinguish which is which
/// - Challenge constraint: c = c0 + c1 (mod n) ties them together
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct BitProof {
    // =========================================================================
    // Branch 0: Proof that commitment is to 0 (V = 0*G + r*H = r*H)
    // Real proof if bit=0, simulated if bit=1
    // =========================================================================
    /// Commitment A0 = k0 * H (or simulated)
    pub a0_x: felt252,
    pub a0_y: felt252,
    /// Challenge for branch 0
    pub c0: felt252,
    /// Response for branch 0: s0 = k0 + c0 * r (or simulated)
    pub s0: felt252,

    // =========================================================================
    // Branch 1: Proof that commitment is to 1 (V = 1*G + r*H, so V - G = r*H)
    // Real proof if bit=1, simulated if bit=0
    // =========================================================================
    /// Commitment A1 = k1 * H (or simulated)
    pub a1_x: felt252,
    pub a1_y: felt252,
    /// Challenge for branch 1
    pub c1: felt252,
    /// Response for branch 1: s1 = k1 + c1 * r (or simulated)
    pub s1: felt252,
}

/// Full range proof using bit decomposition (32-bit)
///
/// Proves that a committed value is in range [0, 2^32 - 1]
/// by decomposing it into 32 bits and proving each bit is 0 or 1.
#[derive(Drop, Serde)]
pub struct RangeProof32 {
    /// 32 bit commitments: V_i = b_i * G + r_i * H
    pub bit_commitments: Array<ECPoint>,
    /// 32 OR proofs (one per bit)
    pub bit_proofs: Array<BitProof>,
    /// Aggregate blinding factor for consistency check
    /// r = Σ 2^i * r_i (allows verifying sum matches)
    pub aggregate_blinding: felt252,
}

/// Compact range proof for storage (stores hash + metadata)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CompactRangeProof32 {
    /// Poseidon hash of the full proof
    pub proof_hash: felt252,
    /// The value commitment this proves
    pub commitment_x: felt252,
    pub commitment_y: felt252,
}

/// Inputs for bit proof verification
#[derive(Copy, Drop, Serde)]
pub struct BitProofInputs {
    /// The commitment being proven (V = b*G + r*H where b ∈ {0,1})
    pub commitment: ECPoint,
    /// Overall challenge (c0 + c1 must equal this mod n)
    pub challenge: felt252,
}

// =============================================================================
// Bit Proof Verification
// =============================================================================

/// Verify an OR proof that a commitment contains 0 or 1
///
/// The verification checks both branches of the OR proof:
/// - Branch 0: V = 0*G + r*H (i.e., V = r*H)
///   Check: s0*H == A0 + c0*V
/// - Branch 1: V = 1*G + r*H (i.e., V - G = r*H)
///   Check: s1*H == A1 + c1*(V - G)
///
/// Additionally verifies the challenge constraint: c0 + c1 = c (mod n)
///
/// # Arguments
/// * `inputs` - The commitment and overall challenge
/// * `proof` - The OR proof
///
/// # Returns
/// * `true` if the proof is valid
pub fn verify_bit_proof(inputs: BitProofInputs, proof: BitProof) -> bool {
    let h = generator_h();
    let g = generator();

    // Extract commitment points from proof
    let a0 = ECPoint { x: proof.a0_x, y: proof.a0_y };
    let a1 = ECPoint { x: proof.a1_x, y: proof.a1_y };

    // Basic validity checks
    if is_zero(a0) || is_zero(a1) {
        return false;
    }
    if proof.s0 == 0 || proof.s1 == 0 {
        return false;
    }

    // =========================================================================
    // Verify challenge constraint: c0 + c1 = c (mod n)
    // This is what ties the two branches together and prevents cheating
    // =========================================================================
    let c_sum = add_mod_n(proof.c0, proof.c1);
    if c_sum != inputs.challenge {
        return false;
    }

    // =========================================================================
    // Verify Branch 0: Proof that V = r*H (commitment to 0)
    // Verification equation: s0 * H == A0 + c0 * V
    // =========================================================================
    let s0_h = ec_mul(proof.s0, h);
    let c0_v = ec_mul(proof.c0, inputs.commitment);
    let rhs0 = ec_add(a0, c0_v);

    if s0_h.x != rhs0.x || s0_h.y != rhs0.y {
        return false;
    }

    // =========================================================================
    // Verify Branch 1: Proof that V - G = r*H (commitment to 1)
    // Verification equation: s1 * H == A1 + c1 * (V - G)
    // =========================================================================
    let v_minus_g = ec_sub(inputs.commitment, g);
    let s1_h = ec_mul(proof.s1, h);
    let c1_v_minus_g = ec_mul(proof.c1, v_minus_g);
    let rhs1 = ec_add(a1, c1_v_minus_g);

    if s1_h.x != rhs1.x || s1_h.y != rhs1.y {
        return false;
    }

    // Both branches verified and challenge constraint satisfied
    true
}

// =============================================================================
// Range Proof Verification (32-bit)
// =============================================================================

/// Verify a 32-bit range proof
///
/// This proves that a committed value is in [0, 2^32 - 1] by:
/// 1. Verifying each of 32 bit proofs (each bit is 0 or 1)
/// 2. Verifying consistency: Σ 2^i * V_i = V (weighted sum equals commitment)
///
/// # Arguments
/// * `value_commitment` - The Pedersen commitment V = value*G + r*H
/// * `proof` - The 32-bit range proof
///
/// # Returns
/// * `true` if the committed value is proven to be in range
pub fn verify_range_proof_32(
    value_commitment: ECPoint,
    proof: @RangeProof32
) -> bool {
    // Verify correct number of components
    if proof.bit_commitments.len() != RANGE_BITS_32.into() {
        return false;
    }
    if proof.bit_proofs.len() != RANGE_BITS_32.into() {
        return false;
    }

    // Compute master challenge from all bit commitments
    let master_challenge = compute_range_challenge(value_commitment, proof.bit_commitments);

    // =========================================================================
    // Step 1: Verify each bit proof
    // Each V_i must commit to either 0 or 1
    // =========================================================================
    let mut i: u32 = 0;
    loop {
        if i >= RANGE_BITS_32 {
            break;
        }

        let bit_commitment = *proof.bit_commitments.at(i);
        let bit_proof = *proof.bit_proofs.at(i);

        // Derive per-bit challenge from master challenge and index
        let bit_challenge = derive_bit_challenge(master_challenge, i);

        let inputs = BitProofInputs {
            commitment: bit_commitment,
            challenge: bit_challenge,
        };

        if !verify_bit_proof(inputs, bit_proof) {
            return false;
        }

        i += 1;
    };

    // =========================================================================
    // Step 2: Verify consistency - weighted sum of bit commitments
    // Σ 2^i * V_i should equal value_commitment
    //
    // If V_i = b_i * G + r_i * H, then:
    // Σ 2^i * V_i = (Σ 2^i * b_i) * G + (Σ 2^i * r_i) * H
    //            = value * G + aggregate_blinding * H
    // =========================================================================
    let reconstructed = compute_weighted_sum_32(proof.bit_commitments);

    if reconstructed.x != value_commitment.x || reconstructed.y != value_commitment.y {
        return false;
    }

    true
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute the master challenge for a range proof
fn compute_range_challenge(
    value_commitment: ECPoint,
    bit_commitments: @Array<ECPoint>
) -> felt252 {
    let mut hash_input: Array<felt252> = array![];

    // Domain separator
    hash_input.append(RANGE_PROOF_DOMAIN);

    // Value commitment
    hash_input.append(value_commitment.x);
    hash_input.append(value_commitment.y);

    // All bit commitments
    let len: u32 = bit_commitments.len().try_into().unwrap();
    let mut i: u32 = 0;
    loop {
        if i >= len {
            break;
        }
        let commit = *bit_commitments.at(i);
        hash_input.append(commit.x);
        hash_input.append(commit.y);
        i += 1;
    };

    reduce_mod_n(poseidon_hash_span(hash_input.span()))
}

/// Derive a per-bit challenge from master challenge
fn derive_bit_challenge(master_challenge: felt252, bit_index: u32) -> felt252 {
    let hash_input = array![
        BIT_PROOF_DOMAIN,
        master_challenge,
        bit_index.into()
    ];
    reduce_mod_n(poseidon_hash_span(hash_input.span()))
}

/// Compute weighted sum: Σ 2^i * V_i for 32 bits
fn compute_weighted_sum_32(commitments: @Array<ECPoint>) -> ECPoint {
    let mut result = ec_zero();
    let mut power_of_2: felt252 = 1;

    let mut i: u32 = 0;
    loop {
        if i >= RANGE_BITS_32 {
            break;
        }

        let commitment = *commitments.at(i);
        let weighted = ec_mul(power_of_2, commitment);
        result = ec_add(result, weighted);

        // Double the power (2^i -> 2^(i+1))
        power_of_2 = add_mod_n(power_of_2, power_of_2);

        i += 1;
    };

    result
}

/// Get 2^i as felt252
fn pow2(i: u32) -> felt252 {
    let mut result: felt252 = 1;
    let mut j: u32 = 0;
    loop {
        if j >= i {
            break;
        }
        result = add_mod_n(result, result);
        j += 1;
    };
    result
}

// =============================================================================
// Proof Generation (for testing / off-chain use)
// =============================================================================

/// Create a bit proof for a commitment to bit value b
///
/// # Arguments
/// * `bit` - The bit value (0 or 1)
/// * `randomness` - The blinding factor r used in commitment
/// * `commitment` - The commitment V = b*G + r*H
/// * `challenge` - The overall challenge c
/// * `k_real` - Random value for real proof branch
/// * `c_sim` - Simulated challenge for fake branch (chosen by prover)
///
/// # Returns
/// * BitProof with both branches
pub fn create_bit_proof(
    bit: u8,
    randomness: felt252,
    commitment: ECPoint,
    challenge: felt252,
    k_real: felt252,
    c_sim: felt252,
) -> BitProof {
    let h = generator_h();
    let g = generator();

    // Compute the complementary challenge
    // c = c0 + c1, so if we pick c_sim, then c_real = c - c_sim
    let c_real = sub_mod_n(challenge, c_sim);

    if bit == 0 {
        // =====================================================================
        // Bit = 0: Branch 0 is real, Branch 1 is simulated
        // =====================================================================

        // Real proof for branch 0 (V = r*H)
        // A0 = k_real * H
        let a0 = ec_mul(k_real, h);
        // s0 = k_real + c0 * r
        let c0_r = mul_mod_n(c_real, randomness);
        let s0 = add_mod_n(k_real, c0_r);

        // Simulated proof for branch 1
        // We have c1 = c_sim, and need to find A1 such that verification passes
        // Verification: s1*H == A1 + c1*(V-G)
        // So: A1 = s1*H - c1*(V-G)
        // We can choose s1 arbitrarily, then compute A1
        let s1 = k_real; // Reuse k_real as s1 (arbitrary choice)
        let v_minus_g = ec_sub(commitment, g);
        let c1_v_minus_g = ec_mul(c_sim, v_minus_g);
        let s1_h = ec_mul(s1, h);
        let a1 = ec_sub(s1_h, c1_v_minus_g);

        BitProof {
            a0_x: a0.x, a0_y: a0.y,
            c0: c_real,
            s0,
            a1_x: a1.x, a1_y: a1.y,
            c1: c_sim,
            s1,
        }
    } else {
        // =====================================================================
        // Bit = 1: Branch 1 is real, Branch 0 is simulated
        // =====================================================================

        // Real proof for branch 1 (V - G = r*H)
        // A1 = k_real * H
        let a1 = ec_mul(k_real, h);
        // s1 = k_real + c1 * r
        let c1_r = mul_mod_n(c_real, randomness);
        let s1 = add_mod_n(k_real, c1_r);

        // Simulated proof for branch 0
        // Verification: s0*H == A0 + c0*V
        // So: A0 = s0*H - c0*V
        let s0 = k_real; // Arbitrary choice
        let c0_v = ec_mul(c_sim, commitment);
        let s0_h = ec_mul(s0, h);
        let a0 = ec_sub(s0_h, c0_v);

        BitProof {
            a0_x: a0.x, a0_y: a0.y,
            c0: c_sim,
            s0,
            a1_x: a1.x, a1_y: a1.y,
            c1: c_real,
            s1,
        }
    }
}

/// Create a bit commitment: V = b*G + r*H
pub fn create_bit_commitment(bit: u8, randomness: felt252) -> ECPoint {
    let g = generator();
    let h = generator_h();

    let r_h = ec_mul(randomness, h);

    if bit == 0 {
        r_h
    } else {
        ec_add(g, r_h)
    }
}

/// Create a full 32-bit range proof
///
/// IMPORTANT: The bit_blindings must satisfy the constraint:
///   Σ 2^i * bit_blindings[i] = blinding (mod n)
/// This ensures the weighted sum of bit commitments equals the value commitment.
///
/// For convenience, use create_range_proof_32_with_seed() which handles this automatically.
///
/// # Arguments
/// * `value` - The value to prove is in range (must be < 2^32)
/// * `blinding` - The blinding factor for the value commitment
/// * `bit_blindings` - 32 blinding factors that must sum correctly (see above)
/// * `k_values` - 32 random k values for proof generation
/// * `c_sim_values` - 32 simulated challenge values
///
/// # Returns
/// * (value_commitment, range_proof)
pub fn create_range_proof_32(
    value: u64,
    blinding: felt252,
    bit_blindings: Span<felt252>,
    k_values: Span<felt252>,
    c_sim_values: Span<felt252>,
) -> (ECPoint, RangeProof32) {
    assert!(bit_blindings.len() == RANGE_BITS_32.into(), "Need 32 bit blindings");
    assert!(k_values.len() == RANGE_BITS_32.into(), "Need 32 k values");
    assert!(c_sim_values.len() == RANGE_BITS_32.into(), "Need 32 c_sim values");

    let g = generator();
    let h = generator_h();

    // Create value commitment: V = value*G + blinding*H
    let value_felt: felt252 = value.into();
    let value_g = ec_mul(value_felt, g);
    let blinding_h = ec_mul(blinding, h);
    let value_commitment = ec_add(value_g, blinding_h);

    // Create bit commitments
    let mut bit_commitments: Array<ECPoint> = array![];
    let mut aggregate_blinding: felt252 = 0;
    let mut power_of_2: felt252 = 1;

    let mut i: u32 = 0;
    loop {
        if i >= RANGE_BITS_32 {
            break;
        }

        // Extract bit i from value
        let bit: u8 = ((value / pow2_u64(i)) % 2).try_into().unwrap();

        let bit_blinding = *bit_blindings.at(i);
        let bit_commitment = create_bit_commitment(bit, bit_blinding);
        bit_commitments.append(bit_commitment);

        // Accumulate weighted blinding: r = Σ 2^i * r_i
        let weighted_blinding = mul_mod_n(power_of_2, bit_blinding);
        aggregate_blinding = add_mod_n(aggregate_blinding, weighted_blinding);

        power_of_2 = add_mod_n(power_of_2, power_of_2);
        i += 1;
    };

    // Compute master challenge
    let master_challenge = compute_range_challenge(value_commitment, @bit_commitments);

    // Create bit proofs
    let mut bit_proofs: Array<BitProof> = array![];
    let mut j: u32 = 0;
    loop {
        if j >= RANGE_BITS_32 {
            break;
        }

        let bit: u8 = ((value / pow2_u64(j)) % 2).try_into().unwrap();
        let bit_challenge = derive_bit_challenge(master_challenge, j);
        let bit_blinding = *bit_blindings.at(j);
        let bit_commitment = *bit_commitments.at(j);
        let k = *k_values.at(j);
        let c_sim = *c_sim_values.at(j);

        let proof = create_bit_proof(
            bit,
            bit_blinding,
            bit_commitment,
            bit_challenge,
            k,
            c_sim
        );
        bit_proofs.append(proof);

        j += 1;
    };

    let range_proof = RangeProof32 {
        bit_commitments,
        bit_proofs,
        aggregate_blinding,
    };

    (value_commitment, range_proof)
}

/// Create a range proof with automatic blinding derivation
///
/// This is the recommended way to create range proofs. It derives all random
/// values from a seed, and computes the commitment blinding as the weighted sum
/// of the bit blindings (ensuring consistency).
///
/// # Arguments
/// * `value` - The value to prove is in range (must be < 2^32)
/// * `seed` - Random seed for deriving all random values
///
/// # Returns
/// * (value_commitment, range_proof, aggregate_blinding)
/// The aggregate_blinding can be used to create the commitment externally if needed.
pub fn create_range_proof_32_with_seed(
    value: u64,
    seed: felt252,
) -> (ECPoint, RangeProof32, felt252) {
    let g = generator();
    let h = generator_h();

    // Derive 32 random bit blindings from seed
    let mut bit_blindings: Array<felt252> = array![];
    let mut aggregate_blinding: felt252 = 0;
    let mut power_of_2: felt252 = 1;

    let mut i: u32 = 0;
    loop {
        if i >= 32 {
            break;
        }

        // Derive random blinding from seed
        let r_i = poseidon_hash_span(array![seed, 'bit_blind', i.into()].span());
        let r_i_reduced = reduce_mod_n(r_i);
        bit_blindings.append(r_i_reduced);

        // Accumulate: aggregate_blinding += 2^i * r_i
        let weighted = mul_mod_n(power_of_2, r_i_reduced);
        aggregate_blinding = add_mod_n(aggregate_blinding, weighted);

        power_of_2 = add_mod_n(power_of_2, power_of_2);
        i += 1;
    };

    // Create value commitment using computed aggregate_blinding
    // V = value*G + aggregate_blinding*H
    let value_felt: felt252 = value.into();
    let value_g = ec_mul(value_felt, g);
    let blinding_h = ec_mul(aggregate_blinding, h);
    let _value_commitment = ec_add(value_g, blinding_h);

    // Derive k values and c_sim values from seed
    let mut k_values: Array<felt252> = array![];
    let mut c_sim_values: Array<felt252> = array![];

    let mut j: u32 = 0;
    loop {
        if j >= 32 {
            break;
        }
        let k = reduce_mod_n(poseidon_hash_span(array![seed, 'k_val', j.into()].span()));
        let c_sim = reduce_mod_n(poseidon_hash_span(array![seed, 'c_sim', j.into()].span()));
        k_values.append(k);
        c_sim_values.append(c_sim);
        j += 1;
    };

    // Create the proof using the derived values
    let (commitment, proof) = create_range_proof_32(
        value,
        aggregate_blinding,
        bit_blindings.span(),
        k_values.span(),
        c_sim_values.span()
    );

    (commitment, proof, aggregate_blinding)
}

/// Helper to compute 2^i as u64
fn pow2_u64(i: u32) -> u64 {
    let mut result: u64 = 1;
    let mut j: u32 = 0;
    loop {
        if j >= i {
            break;
        }
        result = result * 2;
        j += 1;
    };
    result
}

// =============================================================================
// Serialization / Deserialization
// =============================================================================

/// Serialize a BitProof to an array of felt252
/// Format: [a0_x, a0_y, c0, s0, a1_x, a1_y, c1, s1]
pub fn serialize_bit_proof(proof: BitProof) -> Array<felt252> {
    array![
        proof.a0_x, proof.a0_y, proof.c0, proof.s0,
        proof.a1_x, proof.a1_y, proof.c1, proof.s1
    ]
}

/// Deserialize a BitProof from a span (consumes 8 elements)
pub fn deserialize_bit_proof(ref data: Span<felt252>) -> Option<BitProof> {
    let a0_x = *data.pop_front()?;
    let a0_y = *data.pop_front()?;
    let c0 = *data.pop_front()?;
    let s0 = *data.pop_front()?;
    let a1_x = *data.pop_front()?;
    let a1_y = *data.pop_front()?;
    let c1 = *data.pop_front()?;
    let s1 = *data.pop_front()?;

    Option::Some(BitProof { a0_x, a0_y, c0, s0, a1_x, a1_y, c1, s1 })
}

/// Serialize a RangeProof32 to an array of felt252
/// Format: [32 bit_commitments (x,y pairs), 32 bit_proofs (8 fields each), aggregate_blinding]
/// Total size: 64 + 256 + 1 = 321 felt252
pub fn serialize_range_proof_32(proof: @RangeProof32) -> Array<felt252> {
    let mut result: Array<felt252> = array![];

    // Serialize 32 bit commitments (64 felt252s)
    let mut i: u32 = 0;
    loop {
        if i >= RANGE_BITS_32 {
            break;
        }
        let commit = *proof.bit_commitments.at(i);
        result.append(commit.x);
        result.append(commit.y);
        i += 1;
    };

    // Serialize 32 bit proofs (256 felt252s)
    let mut j: u32 = 0;
    loop {
        if j >= RANGE_BITS_32 {
            break;
        }
        let bp = *proof.bit_proofs.at(j);
        result.append(bp.a0_x);
        result.append(bp.a0_y);
        result.append(bp.c0);
        result.append(bp.s0);
        result.append(bp.a1_x);
        result.append(bp.a1_y);
        result.append(bp.c1);
        result.append(bp.s1);
        j += 1;
    };

    // Serialize aggregate blinding (1 felt252)
    result.append(*proof.aggregate_blinding);

    result
}

/// Deserialize a RangeProof32 from a span
/// Expected size: 321 felt252
pub fn deserialize_range_proof_32(mut data: Span<felt252>) -> Option<RangeProof32> {
    // Minimum size check: 64 (commitments) + 256 (proofs) + 1 (blinding) = 321
    if data.len() < 321 {
        return Option::None;
    }

    // Deserialize 32 bit commitments
    let mut bit_commitments: Array<ECPoint> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= RANGE_BITS_32 {
            break;
        }
        let x = *data.pop_front()?;
        let y = *data.pop_front()?;
        bit_commitments.append(ECPoint { x, y });
        i += 1;
    };

    // Deserialize 32 bit proofs
    let mut bit_proofs: Array<BitProof> = array![];
    let mut j: u32 = 0;
    loop {
        if j >= RANGE_BITS_32 {
            break;
        }
        let bp = deserialize_bit_proof(ref data)?;
        bit_proofs.append(bp);
        j += 1;
    };

    // Deserialize aggregate blinding
    let aggregate_blinding = *data.pop_front()?;

    Option::Some(RangeProof32 {
        bit_commitments,
        bit_proofs,
        aggregate_blinding,
    })
}

/// Compute a compact hash of a RangeProof32 for storage
pub fn hash_range_proof_32(proof: @RangeProof32, commitment: ECPoint) -> CompactRangeProof32 {
    let serialized = serialize_range_proof_32(proof);
    let proof_hash = poseidon_hash_span(serialized.span());

    CompactRangeProof32 {
        proof_hash,
        commitment_x: commitment.x,
        commitment_y: commitment.y,
    }
}

/// Compute just the hash of a RangeProof32 (for audit trail storage)
pub fn compute_proof_hash_32(proof: @RangeProof32) -> felt252 {
    let serialized = serialize_range_proof_32(proof);
    poseidon_hash_span(serialized.span())
}

/// Serialize an array of RangeProof32 to felt252 array
/// Format: [count, proof1_data..., proof2_data..., ...]
/// Each proof is 321 felt252: 64 commitments (x,y pairs) + 256 bit proofs (8 fields each) + 1 blinding
pub fn serialize_range_proofs_32(proofs: Span<RangeProof32>) -> Array<felt252> {
    let mut result: Array<felt252> = array![];

    // Write count
    let count: felt252 = proofs.len().into();
    result.append(count);

    // Serialize each proof
    let mut i: u32 = 0;
    loop {
        if i >= proofs.len() {
            break;
        }
        let proof = proofs.at(i);
        let proof_data = serialize_range_proof_32(proof);

        // Append all elements from proof_data
        let proof_data_span = proof_data.span();
        let mut j: u32 = 0;
        loop {
            if j >= proof_data.len() {
                break;
            }
            result.append(*proof_data_span.at(j));
            j += 1;
        };

        i += 1;
    };

    result
}

/// Deserialize an array of RangeProof32 from felt252 span
/// Format: [count, proof1_data..., proof2_data..., ...]
pub fn deserialize_range_proofs_32(mut data: Span<felt252>) -> Option<Array<RangeProof32>> {
    // Read count
    let count_felt = data.pop_front()?;
    let count_u128: u128 = (*count_felt).try_into()?;
    let count: u32 = count_u128.try_into()?;

    // Each RangeProof32 is exactly 321 felt252
    const PROOF_SIZE: u32 = 321;

    // Check we have enough data
    let required_len: u32 = count * PROOF_SIZE;
    if data.len() < required_len.into() {
        return Option::None;
    }

    let mut proofs: Array<RangeProof32> = array![];
    let mut offset: u32 = 0;

    loop {
        if offset >= count * PROOF_SIZE {
            break;
        }

        // Create a slice for this proof starting at current offset
        let proof_slice = data.slice(offset.into(), PROOF_SIZE.into());
        let proof = deserialize_range_proof_32(proof_slice)?;
        proofs.append(proof);

        offset += PROOF_SIZE;
    };

    Option::Some(proofs)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test constants
    const TEST_VALUE: u64 = 12345;
    const TEST_BLINDING: felt252 = 0x1234567890abcdef;
    const TEST_K: felt252 = 0xfedcba0987654321;
    const TEST_C_SIM: felt252 = 0x1111111111111111;

    #[test]
    fn test_bit_commitment_zero() {
        let r: felt252 = 12345;
        let commitment = create_bit_commitment(0, r);

        // V = 0*G + r*H = r*H
        let h = generator_h();
        let expected = ec_mul(r, h);

        assert!(commitment.x == expected.x, "Bit 0 commitment x wrong");
        assert!(commitment.y == expected.y, "Bit 0 commitment y wrong");
    }

    #[test]
    fn test_bit_commitment_one() {
        let r: felt252 = 12345;
        let commitment = create_bit_commitment(1, r);

        // V = 1*G + r*H
        let g = generator();
        let h = generator_h();
        let r_h = ec_mul(r, h);
        let expected = ec_add(g, r_h);

        assert!(commitment.x == expected.x, "Bit 1 commitment x wrong");
        assert!(commitment.y == expected.y, "Bit 1 commitment y wrong");
    }

    #[test]
    fn test_bit_proof_zero_valid() {
        let bit: u8 = 0;
        let r: felt252 = 54321;
        let challenge: felt252 = 99999;
        let k: felt252 = 11111;
        let c_sim: felt252 = 44444;

        let commitment = create_bit_commitment(bit, r);
        let proof = create_bit_proof(bit, r, commitment, challenge, k, c_sim);

        let inputs = BitProofInputs { commitment, challenge };

        assert!(verify_bit_proof(inputs, proof), "Valid bit=0 proof failed");
    }

    #[test]
    fn test_bit_proof_one_valid() {
        let bit: u8 = 1;
        let r: felt252 = 54321;
        let challenge: felt252 = 99999;
        let k: felt252 = 11111;
        let c_sim: felt252 = 44444;

        let commitment = create_bit_commitment(bit, r);
        let proof = create_bit_proof(bit, r, commitment, challenge, k, c_sim);

        let inputs = BitProofInputs { commitment, challenge };

        assert!(verify_bit_proof(inputs, proof), "Valid bit=1 proof failed");
    }

    #[test]
    fn test_bit_proof_wrong_challenge_fails() {
        let bit: u8 = 1;
        let r: felt252 = 54321;
        let challenge: felt252 = 99999;
        let k: felt252 = 11111;
        let c_sim: felt252 = 44444;

        let commitment = create_bit_commitment(bit, r);
        let proof = create_bit_proof(bit, r, commitment, challenge, k, c_sim);

        // Use wrong challenge
        let wrong_inputs = BitProofInputs {
            commitment,
            challenge: challenge + 1
        };

        assert!(!verify_bit_proof(wrong_inputs, proof), "Wrong challenge accepted");
    }

    #[test]
    fn test_weighted_sum_simple() {
        // Create commitments for value 5 = 101 in binary (bits 0 and 2 are 1)
        let r0: felt252 = 100;
        let r1: felt252 = 200;
        let r2: felt252 = 300;

        let c0 = create_bit_commitment(1, r0); // bit 0 = 1
        let c1 = create_bit_commitment(0, r1); // bit 1 = 0
        let c2 = create_bit_commitment(1, r2); // bit 2 = 1

        let commits = array![c0, c1, c2];

        // Weighted sum should equal: 1*c0 + 2*c1 + 4*c2
        // = 1*(G + r0*H) + 2*(r1*H) + 4*(G + r2*H)
        // = (1 + 4)*G + (r0 + 2*r1 + 4*r2)*H
        // = 5*G + (100 + 400 + 1200)*H
        // = 5*G + 1700*H

        let g = generator();
        let h = generator_h();

        let five_g = ec_mul(5, g);
        let blinding: felt252 = 100 + 2 * 200 + 4 * 300; // = 1700
        let blinding_h = ec_mul(blinding, h);
        let expected = ec_add(five_g, blinding_h);

        // Compute weighted sum (only 3 bits for this test)
        let mut result = ec_zero();
        result = ec_add(result, ec_mul(1, c0));
        result = ec_add(result, ec_mul(2, c1));
        result = ec_add(result, ec_mul(4, c2));

        assert!(result.x == expected.x, "Weighted sum x wrong");
        assert!(result.y == expected.y, "Weighted sum y wrong");
    }

    #[test]
    fn test_pow2() {
        assert!(pow2(0) == 1, "2^0 wrong");
        assert!(pow2(1) == 2, "2^1 wrong");
        assert!(pow2(2) == 4, "2^2 wrong");
        assert!(pow2(3) == 8, "2^3 wrong");
        assert!(pow2(10) == 1024, "2^10 wrong");
    }

    #[test]
    fn test_domain_separators_unique() {
        assert!(BIT_PROOF_DOMAIN != RANGE_PROOF_DOMAIN, "Domains not unique");
    }

    // =========================================================================
    // Diagnostic tests to identify exactly where verification fails
    // =========================================================================

    #[test]
    fn test_challenge_constraint() {
        // Test that c0 + c1 = c (mod n) is properly computed
        let challenge: felt252 = 99999;
        let c_sim: felt252 = 44444;
        let c_real = sub_mod_n(challenge, c_sim);

        // c_real + c_sim should equal challenge
        let c_sum = add_mod_n(c_real, c_sim);
        assert!(c_sum == challenge, "Challenge constraint broken");
    }

    #[test]
    fn test_branch0_real_verification() {
        // Test branch 0 (bit=0) with real proof only
        let h = generator_h();
        let r: felt252 = 54321;
        let k: felt252 = 11111;
        let c0: felt252 = 55555;

        // Commitment for bit=0: V = r*H
        let v = ec_mul(r, h);

        // Real proof: A0 = k*H, s0 = k + c0*r
        let a0 = ec_mul(k, h);
        let c0_r = mul_mod_n(c0, r);
        let s0 = add_mod_n(k, c0_r);

        // Verify: s0*H == A0 + c0*V
        let lhs = ec_mul(s0, h);
        let c0_v = ec_mul(c0, v);
        let rhs = ec_add(a0, c0_v);

        assert!(lhs.x == rhs.x, "Branch 0 real verification x mismatch");
        assert!(lhs.y == rhs.y, "Branch 0 real verification y mismatch");
    }

    #[test]
    fn test_branch1_real_verification() {
        // Test branch 1 (bit=1) with real proof only
        let h = generator_h();
        let g = generator();
        let r: felt252 = 54321;
        let k: felt252 = 11111;
        let c1: felt252 = 55555;

        // Commitment for bit=1: V = G + r*H
        let r_h = ec_mul(r, h);
        let v = ec_add(g, r_h);

        // V - G = r*H
        let v_minus_g = ec_sub(v, g);

        // Real proof: A1 = k*H, s1 = k + c1*r
        let a1 = ec_mul(k, h);
        let c1_r = mul_mod_n(c1, r);
        let s1 = add_mod_n(k, c1_r);

        // Verify: s1*H == A1 + c1*(V-G)
        let lhs = ec_mul(s1, h);
        let c1_v_minus_g = ec_mul(c1, v_minus_g);
        let rhs = ec_add(a1, c1_v_minus_g);

        assert!(lhs.x == rhs.x, "Branch 1 real verification x mismatch");
        assert!(lhs.y == rhs.y, "Branch 1 real verification y mismatch");
    }

    #[test]
    fn test_branch0_simulated_verification() {
        // Test simulated branch 0 (when bit=1)
        let h = generator_h();
        let g = generator();
        let r: felt252 = 54321;
        let c0: felt252 = 44444;  // simulated challenge
        let s0: felt252 = 11111;  // arbitrary s0

        // Commitment for bit=1: V = G + r*H
        let r_h = ec_mul(r, h);
        let v = ec_add(g, r_h);

        // Simulated: A0 = s0*H - c0*V
        let s0_h = ec_mul(s0, h);
        let c0_v = ec_mul(c0, v);
        let a0 = ec_sub(s0_h, c0_v);

        // Verification should pass: s0*H == A0 + c0*V
        let lhs = s0_h;
        let rhs = ec_add(a0, c0_v);

        assert!(lhs.x == rhs.x, "Simulated branch 0 verification x mismatch");
        assert!(lhs.y == rhs.y, "Simulated branch 0 verification y mismatch");
    }

    #[test]
    fn test_branch1_simulated_verification() {
        // Test simulated branch 1 (when bit=0)
        let h = generator_h();
        let g = generator();
        let r: felt252 = 54321;
        let c1: felt252 = 44444;  // simulated challenge
        let s1: felt252 = 11111;  // arbitrary s1

        // Commitment for bit=0: V = r*H
        let v = ec_mul(r, h);

        // V - G for bit=0
        let v_minus_g = ec_sub(v, g);

        // Simulated: A1 = s1*H - c1*(V-G)
        let s1_h = ec_mul(s1, h);
        let c1_v_minus_g = ec_mul(c1, v_minus_g);
        let a1 = ec_sub(s1_h, c1_v_minus_g);

        // Verification should pass: s1*H == A1 + c1*(V-G)
        let lhs = s1_h;
        let rhs = ec_add(a1, c1_v_minus_g);

        assert!(lhs.x == rhs.x, "Simulated branch 1 verification x mismatch");
        assert!(lhs.y == rhs.y, "Simulated branch 1 verification y mismatch");
    }

    #[test]
    fn test_full_bit0_proof_step_by_step() {
        // Full bit=0 proof traced step by step
        let bit: u8 = 0;
        let r: felt252 = 54321;
        let challenge: felt252 = 99999;
        let k: felt252 = 11111;
        let c_sim: felt252 = 44444;

        let h = generator_h();
        let g = generator();

        // Test h directly
        assert!(h.x != 0, "Step-by-step: h.x is zero");
        assert!(h.y != 0, "Step-by-step: h.y is zero");

        // Test ec_mul with h directly
        let test_mul = ec_mul(k, h);
        assert!(!is_zero(test_mul), "Step-by-step: direct k*h is zero");

        // Create commitment
        let commitment = create_bit_commitment(bit, r);
        assert!(!is_zero(commitment), "Step-by-step: commitment is zero");

        // Create proof
        let proof = create_bit_proof(bit, r, commitment, challenge, k, c_sim);

        // Check challenge constraint
        let c_sum = add_mod_n(proof.c0, proof.c1);
        assert!(c_sum == challenge, "Step-by-step: challenge constraint failed");

        // Check A0, A1 are non-zero
        let a0 = ECPoint { x: proof.a0_x, y: proof.a0_y };
        let a1 = ECPoint { x: proof.a1_x, y: proof.a1_y };
        assert!(!is_zero(a0), "Step-by-step: A0 is zero");
        assert!(!is_zero(a1), "Step-by-step: A1 is zero");

        // Check s0, s1 are non-zero
        assert!(proof.s0 != 0, "Step-by-step: s0 is zero");
        assert!(proof.s1 != 0, "Step-by-step: s1 is zero");

        // Verify Branch 0 manually
        let s0_h = ec_mul(proof.s0, h);
        let c0_v = ec_mul(proof.c0, commitment);
        let rhs0 = ec_add(a0, c0_v);
        assert!(s0_h.x == rhs0.x, "Step-by-step: Branch 0 x mismatch");
        assert!(s0_h.y == rhs0.y, "Step-by-step: Branch 0 y mismatch");

        // Verify Branch 1 manually
        let v_minus_g = ec_sub(commitment, g);
        let s1_h = ec_mul(proof.s1, h);
        let c1_v_minus_g = ec_mul(proof.c1, v_minus_g);
        let rhs1 = ec_add(a1, c1_v_minus_g);
        assert!(s1_h.x == rhs1.x, "Step-by-step: Branch 1 x mismatch");
        assert!(s1_h.y == rhs1.y, "Step-by-step: Branch 1 y mismatch");
    }

    #[test]
    fn test_ec_mul_h_basic() {
        // Verify that ec_mul with generator_h works
        let h = generator_h();

        // First verify h is not zero
        assert!(h.x != 0, "h.x is zero");
        assert!(h.y != 0, "h.y is zero");

        // Test with same value as test_bit_commitment_zero (which passes)
        let k1: felt252 = 12345;
        let result1 = ec_mul(k1, h);
        assert!(!is_zero(result1), "ec_mul(12345, h) returned zero");

        // Test with different value
        let k2: felt252 = 11111;
        let result2 = ec_mul(k2, h);
        assert!(!is_zero(result2), "ec_mul(11111, h) returned zero");
    }

    #[test]
    fn test_generator_h_on_curve() {
        // Verify generator_h is actually on the STARK curve
        // If ec_mul(1, h) returns h, then h is on the curve
        // If it returns zero, then h is NOT on the curve
        let h = generator_h();

        // ec_mul with k=1 should return the same point if it's valid
        let result = ec_mul(1, h);
        assert!(result.x == h.x, "ec_mul(1, h) x mismatch - h not on curve?");
        assert!(result.y == h.y, "ec_mul(1, h) y mismatch - h not on curve?");
    }

    #[test]
    fn test_compute_2g() {
        // Verify generator_h returns correct 2*G
        let g = generator();
        let two_g = ec_add(g, g);

        assert!(!is_zero(two_g), "2*G is zero");

        // Verify ec_mul(2, g) gives same result
        let two_g_via_mul = ec_mul(2, g);
        assert!(!is_zero(two_g_via_mul), "ec_mul(2, g) is zero");
        assert!(two_g.x == two_g_via_mul.x, "2*G methods disagree on x");
        assert!(two_g.y == two_g_via_mul.y, "2*G methods disagree on y");

        // Verify generator_h matches computed 2*G
        let h = generator_h();
        assert!(h.x == two_g.x, "GEN_H_X is wrong");
        assert!(h.y == two_g.y, "GEN_H_Y is wrong");

        // NOTE: For production, update elgamal.cairo GEN_H constants to:
        // GEN_H_X = h.x (the computed value)
        // GEN_H_Y = h.y (the computed value)
        // Then revert generator_h() to use constants for gas efficiency
    }

    #[test]
    fn test_generator_g_works() {
        // Verify generator G works
        let g = generator();
        let k: felt252 = 12345;
        let result = ec_mul(k, g);
        assert!(!is_zero(result), "ec_mul(k, G) returned zero");
    }

    #[test]
    fn test_create_bit_proof_a0_directly() {
        // Test that create_bit_proof generates non-zero A0
        let bit: u8 = 0;
        let r: felt252 = 54321;
        let commitment = create_bit_commitment(bit, r);
        let challenge: felt252 = 99999;
        let k: felt252 = 11111;
        let c_sim: felt252 = 44444;

        let proof = create_bit_proof(bit, r, commitment, challenge, k, c_sim);

        // Check proof.a0_x and a0_y directly
        assert!(proof.a0_x != 0, "proof.a0_x is zero");
        assert!(proof.a0_y != 0, "proof.a0_y is zero");
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_bit_proof_serialization_roundtrip() {
        // Create a bit proof
        let bit: u8 = 1;
        let r: felt252 = 54321;
        let commitment = create_bit_commitment(bit, r);
        let challenge: felt252 = 99999;
        let k: felt252 = 11111;
        let c_sim: felt252 = 44444;

        let original = create_bit_proof(bit, r, commitment, challenge, k, c_sim);

        // Serialize
        let serialized = serialize_bit_proof(original);
        assert!(serialized.len() == 8, "BitProof should serialize to 8 elements");

        // Deserialize
        let mut span = serialized.span();
        let deserialized_opt = deserialize_bit_proof(ref span);
        assert!(deserialized_opt.is_some(), "Deserialization failed");

        let deserialized = deserialized_opt.unwrap();

        // Verify roundtrip
        assert!(deserialized.a0_x == original.a0_x, "a0_x mismatch");
        assert!(deserialized.a0_y == original.a0_y, "a0_y mismatch");
        assert!(deserialized.c0 == original.c0, "c0 mismatch");
        assert!(deserialized.s0 == original.s0, "s0 mismatch");
        assert!(deserialized.a1_x == original.a1_x, "a1_x mismatch");
        assert!(deserialized.a1_y == original.a1_y, "a1_y mismatch");
        assert!(deserialized.c1 == original.c1, "c1 mismatch");
        assert!(deserialized.s1 == original.s1, "s1 mismatch");
    }

    #[test]
    fn test_range_proof_32_serialization_size() {
        // Create a simple range proof for value 5 using seed-based function
        let value: u64 = 5;
        let seed: felt252 = 'size_test';

        let (_, proof, _) = create_range_proof_32_with_seed(value, seed);

        // Serialize
        let serialized = serialize_range_proof_32(@proof);

        // Verify size: 64 (commitments) + 256 (proofs) + 1 (blinding) = 321
        assert!(serialized.len() == 321, "RangeProof32 should serialize to 321 elements");
    }

    #[test]
    fn test_range_proof_32_serialization_roundtrip() {
        // Create a range proof using the seed-based function (ensures correct blinding sum)
        let value: u64 = 12345;
        let seed: felt252 = 'test_seed_123';

        let (value_commitment, original, _) = create_range_proof_32_with_seed(value, seed);

        // First verify the original proof works
        let original_valid = verify_range_proof_32(value_commitment, @original);
        assert!(original_valid, "Original proof should verify");

        // Serialize and deserialize
        let serialized = serialize_range_proof_32(@original);
        let deserialized_opt = deserialize_range_proof_32(serialized.span());
        assert!(deserialized_opt.is_some(), "Deserialization failed");

        let deserialized = deserialized_opt.unwrap();

        // Verify aggregate blinding matches
        assert!(
            deserialized.aggregate_blinding == original.aggregate_blinding,
            "Aggregate blinding mismatch"
        );

        // Verify first bit commitment matches
        let orig_bc0 = *original.bit_commitments.at(0);
        let deser_bc0 = *deserialized.bit_commitments.at(0);
        assert!(orig_bc0.x == deser_bc0.x, "First bit commitment x mismatch");
        assert!(orig_bc0.y == deser_bc0.y, "First bit commitment y mismatch");

        // Verify first bit proof matches
        let orig_bp0 = *original.bit_proofs.at(0);
        let deser_bp0 = *deserialized.bit_proofs.at(0);
        assert!(orig_bp0.a0_x == deser_bp0.a0_x, "First bit proof a0_x mismatch");
        assert!(orig_bp0.c0 == deser_bp0.c0, "First bit proof c0 mismatch");

        // Verify the deserialized proof verifies correctly
        let is_valid = verify_range_proof_32(value_commitment, @deserialized);
        assert!(is_valid, "Deserialized proof should verify");
    }

    #[test]
    fn test_deserialize_invalid_size_fails() {
        // Too small data should fail
        let small_data: Array<felt252> = array![1, 2, 3];
        let result = deserialize_range_proof_32(small_data.span());
        assert!(result.is_none(), "Should fail with too small data");
    }
}
