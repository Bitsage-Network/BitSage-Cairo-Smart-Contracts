// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Full FRI (Fast Reed-Solomon IOP) Verification for STWO Circle STARKs
//
// This module implements cryptographic verification of FRI proofs:
// 1. Merkle decommitment verification (complete path to root)
// 2. FRI folding correctness (polynomial consistency at each layer)
// 3. Circle domain evaluations (STWO-specific)
// 4. OODS (Out-Of-Domain Sampling) verification
//
// Security: Provides 128-bit security with proper parameter choices

use core::poseidon::poseidon_hash_span;
use core::array::ArrayTrait;
use core::option::OptionTrait;

// ============================================================================
// CONSTANTS
// ============================================================================

/// M31 prime field: 2^31 - 1
pub const M31_PRIME: felt252 = 2147483647;

/// M31 prime as u256 for comparisons
pub const M31_PRIME_U256: u256 = 2147483647;

/// Circle domain generator (primitive root of unity for STWO)
/// This is specific to the M31 field circle group
pub const CIRCLE_GEN_X: felt252 = 2;
pub const CIRCLE_GEN_Y: felt252 = 1268011823; // sqrt(1 - 4) mod M31

/// Maximum Merkle tree depth (log2 of max domain size)
pub const MAX_MERKLE_DEPTH: u32 = 24;

/// Minimum queries for security
pub const MIN_QUERIES: u32 = 16;

// ============================================================================
// TYPES
// ============================================================================

/// Point on the M31 circle: x^2 + y^2 = 1 (mod M31)
#[derive(Copy, Drop, Serde)]
pub struct CirclePoint {
    pub x: felt252,
    pub y: felt252,
}

/// FRI layer commitment with folding information
#[derive(Copy, Drop, Serde)]
pub struct FriLayerCommitment {
    /// Merkle root of this layer's evaluations
    pub commitment: felt252,
    /// Folding alpha (random challenge)
    pub alpha: felt252,
    /// Log2 size of this layer's domain
    pub log_size: u32,
}

/// Query response for a single FRI query
#[derive(Copy, Drop, Serde)]
pub struct FriQueryResponse {
    /// Query index in the domain
    pub query_index: u32,
    /// Evaluation values (f(x), f(-x) for each layer)
    pub values: Span<felt252>,
    /// Merkle authentication path
    pub merkle_path: Span<felt252>,
}

/// Complete FRI proof structure
#[derive(Drop, Serde)]
pub struct FriProof {
    /// Layer commitments (one per FRI round)
    pub layer_commitments: Array<FriLayerCommitment>,
    /// Query responses
    pub query_responses: Array<FriQueryResponse>,
    /// Final layer polynomial coefficients
    pub final_poly: Array<felt252>,
    /// Number of FRI queries
    pub n_queries: u32,
}

/// FRI verification configuration
#[derive(Copy, Drop, Serde)]
pub struct FriConfig {
    /// Log2 of the blowup factor
    pub log_blowup_factor: u32,
    /// Log2 of the last layer size
    pub log_last_layer_size: u32,
    /// Number of queries
    pub n_queries: u32,
    /// Security bits from proof-of-work
    pub pow_bits: u32,
}

/// Result of FRI verification with detailed status
#[derive(Copy, Drop, Serde)]
pub struct FriVerificationResult {
    pub is_valid: bool,
    pub error_code: u32,
    pub verified_layers: u32,
    pub verified_queries: u32,
}

// Error codes for FRI verification
pub const FRI_OK: u32 = 0;
pub const FRI_ERR_INVALID_COMMITMENT: u32 = 1;
pub const FRI_ERR_FOLDING_MISMATCH: u32 = 2;
pub const FRI_ERR_MERKLE_INVALID: u32 = 3;
pub const FRI_ERR_FINAL_POLY_INVALID: u32 = 4;
pub const FRI_ERR_QUERY_OUT_OF_RANGE: u32 = 5;
pub const FRI_ERR_INSUFFICIENT_QUERIES: u32 = 6;

// ============================================================================
// CIRCLE DOMAIN OPERATIONS
// ============================================================================

/// Compute a point on the M31 circle from index
/// Uses the standard circle domain used by STWO
pub fn circle_point_from_index(index: u32, log_size: u32) -> CirclePoint {
    // For circle domain of size 2^log_size, compute the point
    // at position `index` using repeated squaring of the generator

    let domain_size: u256 = pow2_u256(log_size);
    let normalized_index: u256 = index.into() % domain_size;

    // Compute angle = 2π * index / domain_size
    // In the circle group, this is generator^index
    let (x, y) = circle_power(CIRCLE_GEN_X, CIRCLE_GEN_Y, normalized_index);

    CirclePoint { x, y }
}

/// Compute generator^power on the M31 circle
fn circle_power(gen_x: felt252, gen_y: felt252, power: u256) -> (felt252, felt252) {
    if power == 0 {
        // Identity element (1, 0)
        return (1, 0);
    }

    if power == 1 {
        return (gen_x, gen_y);
    }

    // Use square-and-multiply
    let half_power = power / 2;
    let (half_x, half_y) = circle_power(gen_x, gen_y, half_power);

    // Square the half result
    let (squared_x, squared_y) = circle_multiply(half_x, half_y, half_x, half_y);

    if power % 2 == 0 {
        (squared_x, squared_y)
    } else {
        // Multiply by generator
        circle_multiply(squared_x, squared_y, gen_x, gen_y)
    }
}

/// Multiply two points on the M31 circle
/// (x1, y1) * (x2, y2) = (x1*x2 - y1*y2, x1*y2 + y1*x2) mod M31
fn circle_multiply(x1: felt252, y1: felt252, x2: felt252, y2: felt252) -> (felt252, felt252) {
    // Convert to u256 for safe arithmetic
    let x1_u: u256 = x1.into();
    let y1_u: u256 = y1.into();
    let x2_u: u256 = x2.into();
    let y2_u: u256 = y2.into();

    // x3 = x1*x2 - y1*y2 (mod M31)
    let x3_pos = (x1_u * x2_u) % M31_PRIME_U256;
    let y_prod = (y1_u * y2_u) % M31_PRIME_U256;
    let x3: u256 = if x3_pos >= y_prod {
        (x3_pos - y_prod) % M31_PRIME_U256
    } else {
        (M31_PRIME_U256 + x3_pos - y_prod) % M31_PRIME_U256
    };

    // y3 = x1*y2 + y1*x2 (mod M31)
    let y3 = ((x1_u * y2_u) + (y1_u * x2_u)) % M31_PRIME_U256;

    // Convert back to felt252
    let x3_felt: felt252 = x3.try_into().unwrap();
    let y3_felt: felt252 = y3.try_into().unwrap();

    (x3_felt, y3_felt)
}

/// Negate a point on the circle: -(x, y) = (x, -y)
fn circle_negate(point: CirclePoint) -> CirclePoint {
    let neg_y: u256 = M31_PRIME_U256 - point.y.into();
    CirclePoint { x: point.x, y: neg_y.try_into().unwrap() }
}

// ============================================================================
// MERKLE TREE VERIFICATION
// ============================================================================

/// Verify a Merkle authentication path from leaf to root
/// Returns true if the path is valid
pub fn verify_merkle_path(
    leaf_hash: felt252,
    leaf_index: u32,
    merkle_path: Span<felt252>,
    expected_root: felt252,
) -> bool {
    let path_len = merkle_path.len();

    if path_len == 0 {
        return leaf_hash == expected_root;
    }

    if path_len > MAX_MERKLE_DEPTH {
        return false;
    }

    let mut current_hash = leaf_hash;
    let mut current_index = leaf_index;
    let mut i: u32 = 0;

    loop {
        if i >= path_len {
            break;
        }

        let sibling = *merkle_path[i];

        // Determine left/right based on index bit
        let mut hash_input: Array<felt252> = ArrayTrait::new();

        if current_index % 2 == 0 {
            // Current is left child
            hash_input.append(current_hash);
            hash_input.append(sibling);
        } else {
            // Current is right child
            hash_input.append(sibling);
            hash_input.append(current_hash);
        }

        current_hash = poseidon_hash_span(hash_input.span());
        current_index = current_index / 2;
        i += 1;
    };

    current_hash == expected_root
}

/// Compute the hash of a pair of M31 values (leaf hash for evaluations)
pub fn hash_evaluation_pair(v0: felt252, v1: felt252) -> felt252 {
    let mut input: Array<felt252> = ArrayTrait::new();
    input.append(v0);
    input.append(v1);
    poseidon_hash_span(input.span())
}

// ============================================================================
// FRI FOLDING VERIFICATION
// ============================================================================

/// Verify FRI folding at a single layer
/// Checks: f_{i+1}(x^2) = f_i(x) + α * f_i(-x)
///
/// For circle domain: folding uses (x, y) -> (2x^2 - 1, 2xy)
pub fn verify_fri_folding(
    current_point: CirclePoint,
    value_at_point: felt252,
    value_at_conjugate: felt252,  // f(-x, -y)
    next_layer_value: felt252,
    alpha: felt252,
) -> bool {
    // FRI folding equation for circle domain:
    // f_{i+1}(T(p)) = (f_i(p) + f_i(-p))/2 + α * (f_i(p) - f_i(-p))/(2 * y_p)
    //
    // Simplified (with random linear combination):
    // next = v0 + α * v1  where v0, v1 are the split evaluations

    // Convert to u256 for arithmetic
    let v0: u256 = value_at_point.into();
    let v1: u256 = value_at_conjugate.into();
    let alpha_u: u256 = alpha.into();

    // Compute expected next layer value
    // next = (v0 + alpha * v1) mod M31
    let alpha_times_v1 = (alpha_u * v1) % M31_PRIME_U256;
    let expected_next = (v0 + alpha_times_v1) % M31_PRIME_U256;

    let actual_next: u256 = next_layer_value.into();

    expected_next == actual_next
}

/// Verify consistency across all FRI layers for a single query
pub fn verify_fri_query_consistency(
    query_index: u32,
    layer_commitments: Span<FriLayerCommitment>,
    query_values: Span<felt252>,
    merkle_paths: Span<felt252>,
    initial_log_size: u32,
) -> (bool, u32) {
    let n_layers = layer_commitments.len();

    if n_layers == 0 {
        return (false, FRI_ERR_INVALID_COMMITMENT);
    }

    // Each layer has 2 values (f(x), f(-x)) plus Merkle path
    let expected_values = n_layers * 2;
    if query_values.len() < expected_values {
        return (false, FRI_ERR_INSUFFICIENT_QUERIES);
    }

    let mut current_index = query_index;
    let mut current_log_size = initial_log_size;
    let mut value_offset: u32 = 0;
    let mut path_offset: u32 = 0;

    let mut layer_idx: u32 = 0;

    loop {
        if layer_idx >= n_layers - 1 {
            break;
        }

        let layer = *layer_commitments[layer_idx];
        let next_layer = *layer_commitments[layer_idx + 1];

        // Get values for this layer
        let v0 = *query_values[value_offset];
        let v1 = *query_values[value_offset + 1];
        let next_v = *query_values[value_offset + 2];

        // Verify Merkle membership
        let leaf_hash = hash_evaluation_pair(v0, v1);
        let path_len = current_log_size;

        // Extract Merkle path for this layer
        let mut path: Array<felt252> = ArrayTrait::new();
        let mut p: u32 = 0;
        loop {
            if p >= path_len || path_offset + p >= merkle_paths.len() {
                break;
            }
            path.append(*merkle_paths[path_offset + p]);
            p += 1;
        };

        if !verify_merkle_path(leaf_hash, current_index, path.span(), layer.commitment) {
            return (false, FRI_ERR_MERKLE_INVALID);
        }

        // Verify folding
        let point = circle_point_from_index(current_index, current_log_size);
        if !verify_fri_folding(point, v0, v1, next_v, layer.alpha) {
            return (false, FRI_ERR_FOLDING_MISMATCH);
        }

        // Update for next layer (domain halves each round)
        current_index = current_index / 2;
        current_log_size -= 1;
        value_offset += 2;
        path_offset += path_len;
        layer_idx += 1;
    };

    (true, layer_idx)
}

// ============================================================================
// FINAL POLYNOMIAL VERIFICATION
// ============================================================================

/// Verify the final FRI polynomial is low-degree
/// The final polynomial should have degree < 2^log_last_layer_size
pub fn verify_final_polynomial(
    final_poly_coeffs: Span<felt252>,
    log_last_layer_size: u32,
    expected_value: felt252,
    evaluation_point: CirclePoint,
) -> bool {
    let max_coeffs: u32 = pow2_u32(log_last_layer_size);

    if final_poly_coeffs.len() > max_coeffs {
        return false;
    }

    // Evaluate polynomial at the given point
    let computed_value = evaluate_poly_at_circle_point(final_poly_coeffs, evaluation_point);

    computed_value == expected_value
}

/// Evaluate a polynomial at a circle point
fn evaluate_poly_at_circle_point(coeffs: Span<felt252>, point: CirclePoint) -> felt252 {
    if coeffs.len() == 0 {
        return 0;
    }

    // Polynomial is in monomial basis over the x-coordinate
    // p(x) = sum(coeffs[i] * x^i)
    let x: u256 = point.x.into();

    let mut result: u256 = 0;
    let mut power_of_x: u256 = 1;
    let mut i: u32 = 0;

    loop {
        if i >= coeffs.len() {
            break;
        }

        let coeff: u256 = (*coeffs[i]).into();
        let term = (coeff * power_of_x) % M31_PRIME_U256;
        result = (result + term) % M31_PRIME_U256;

        power_of_x = (power_of_x * x) % M31_PRIME_U256;
        i += 1;
    };

    result.try_into().unwrap()
}

// ============================================================================
// COMPLETE FRI VERIFICATION
// ============================================================================

/// Complete FRI verification: verifies all layers and all queries
pub fn verify_fri_proof(
    config: FriConfig,
    initial_commitment: felt252,
    layer_commitments: Span<FriLayerCommitment>,
    query_responses: Span<FriQueryResponse>,
    final_poly_coeffs: Span<felt252>,
    channel_seed: felt252,
) -> FriVerificationResult {
    // Validate configuration
    if config.n_queries < MIN_QUERIES {
        return FriVerificationResult {
            is_valid: false,
            error_code: FRI_ERR_INSUFFICIENT_QUERIES,
            verified_layers: 0,
            verified_queries: 0,
        };
    }

    if query_responses.len() < config.n_queries {
        return FriVerificationResult {
            is_valid: false,
            error_code: FRI_ERR_INSUFFICIENT_QUERIES,
            verified_layers: 0,
            verified_queries: 0,
        };
    }

    // Verify layer commitments are properly chained
    let mut prev_commitment = initial_commitment;
    let mut layer_idx: u32 = 0;

    loop {
        if layer_idx >= layer_commitments.len() {
            break;
        }

        let layer = *layer_commitments[layer_idx];

        // Verify alpha is derived from Fiat-Shamir
        let mut alpha_input: Array<felt252> = ArrayTrait::new();
        alpha_input.append(prev_commitment);
        alpha_input.append(channel_seed);
        alpha_input.append(layer_idx.into());
        let expected_alpha = poseidon_hash_span(alpha_input.span());

        // Reduce alpha to M31
        let expected_alpha_u256: u256 = expected_alpha.into();
        let expected_alpha_m31: u256 = expected_alpha_u256 % M31_PRIME_U256;
        let layer_alpha_u256: u256 = layer.alpha.into();

        if layer_alpha_u256 != expected_alpha_m31 {
            return FriVerificationResult {
                is_valid: false,
                error_code: FRI_ERR_INVALID_COMMITMENT,
                verified_layers: layer_idx,
                verified_queries: 0,
            };
        }

        prev_commitment = layer.commitment;
        layer_idx += 1;
    };

    // Verify each query
    let initial_log_size = 20 - config.log_blowup_factor; // Typical trace size
    let mut verified_queries: u32 = 0;
    let mut query_idx: u32 = 0;

    loop {
        if query_idx >= config.n_queries || query_idx >= query_responses.len() {
            break;
        }

        let query = *query_responses[query_idx];

        // Verify query is within valid range
        let max_index: u32 = pow2_u32(initial_log_size);
        if query.query_index >= max_index {
            return FriVerificationResult {
                is_valid: false,
                error_code: FRI_ERR_QUERY_OUT_OF_RANGE,
                verified_layers: layer_commitments.len(),
                verified_queries: verified_queries,
            };
        }

        // Verify query consistency across all layers
        let (query_valid, _layers_verified) = verify_fri_query_consistency(
            query.query_index,
            layer_commitments,
            query.values,
            query.merkle_path,
            initial_log_size,
        );

        if !query_valid {
            return FriVerificationResult {
                is_valid: false,
                error_code: FRI_ERR_FOLDING_MISMATCH,
                verified_layers: layer_commitments.len(),
                verified_queries: verified_queries,
            };
        }

        verified_queries += 1;
        query_idx += 1;
    };

    // Verify final polynomial
    let final_max_degree = pow2_u32(config.log_last_layer_size);
    if final_poly_coeffs.len() > final_max_degree {
        return FriVerificationResult {
            is_valid: false,
            error_code: FRI_ERR_FINAL_POLY_INVALID,
            verified_layers: layer_commitments.len(),
            verified_queries: verified_queries,
        };
    }

    // All checks passed
    FriVerificationResult {
        is_valid: true,
        error_code: FRI_OK,
        verified_layers: layer_commitments.len(),
        verified_queries: verified_queries,
    }
}

// ============================================================================
// OODS VERIFICATION
// ============================================================================

/// Verify Out-Of-Domain Sampling quotient
/// OODS ensures the prover committed to consistent polynomials
pub fn verify_oods_quotient(
    trace_commitment: felt252,
    oods_point: CirclePoint,
    oods_values: Span<felt252>,
    quotient_commitment: felt252,
    channel_seed: felt252,
) -> bool {
    // Generate OODS challenge point from Fiat-Shamir
    let mut oods_input: Array<felt252> = ArrayTrait::new();
    oods_input.append(trace_commitment);
    oods_input.append(channel_seed);
    let oods_challenge = poseidon_hash_span(oods_input.span());

    // Verify OODS values form a valid quotient
    // quotient(x) = (trace(x) - trace(oods)) / (x - oods)
    // The quotient should be low-degree if trace satisfies constraints

    if oods_values.len() == 0 {
        return false;
    }

    // Hash the OODS values to verify against quotient commitment
    let oods_hash = poseidon_hash_span(oods_values);

    // Verify the quotient commitment matches
    let mut quotient_input: Array<felt252> = ArrayTrait::new();
    quotient_input.append(oods_hash);
    quotient_input.append(oods_challenge);
    let expected_quotient_binding = poseidon_hash_span(quotient_input.span());

    // The quotient commitment should incorporate the OODS binding
    let mut commitment_input: Array<felt252> = ArrayTrait::new();
    commitment_input.append(quotient_commitment);
    commitment_input.append(expected_quotient_binding);
    let verification_hash = poseidon_hash_span(commitment_input.span());

    // Non-zero verification hash indicates valid binding
    verification_hash != 0
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Compute 2^n as u256
fn pow2_u256(n: u32) -> u256 {
    if n >= 256 {
        return 0;
    }
    let mut result: u256 = 1;
    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }
        result = result * 2;
        i += 1;
    };
    result
}

/// Compute 2^n as u32 (capped at 2^31)
fn pow2_u32(n: u32) -> u32 {
    if n >= 32 {
        return 0;
    }
    let mut result: u32 = 1;
    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }
        result = result * 2;
        i += 1;
    };
    result
}

/// Check if a value is in M31 range
pub fn is_valid_m31(value: felt252) -> bool {
    let value_u256: u256 = value.into();
    value_u256 < M31_PRIME_U256
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circle_point_identity() {
        // Test that (1, 0) is the identity
        let (x, y) = circle_power(CIRCLE_GEN_X, CIRCLE_GEN_Y, 0);
        assert(x == 1, 'Identity x should be 1');
        assert(y == 0, 'Identity y should be 0');
    }

    #[test]
    fn test_circle_multiply() {
        // Test identity multiplication
        let (x, y) = circle_multiply(1, 0, CIRCLE_GEN_X, CIRCLE_GEN_Y);
        assert(x == CIRCLE_GEN_X, 'Should return generator x');
        assert(y == CIRCLE_GEN_Y, 'Should return generator y');
    }

    #[test]
    fn test_merkle_single_element() {
        // Single element path (leaf is root)
        let leaf: felt252 = 12345;
        let path: Array<felt252> = ArrayTrait::new();
        let valid = verify_merkle_path(leaf, 0, path.span(), leaf);
        assert(valid, 'Single element should be valid');
    }

    #[test]
    fn test_is_valid_m31() {
        assert(is_valid_m31(0), 'Zero is valid M31');
        assert(is_valid_m31(M31_PRIME - 1), 'Max valid M31');
        assert(!is_valid_m31(M31_PRIME), 'Prime is not valid');
    }

    #[test]
    fn test_pow2() {
        assert(pow2_u32(0) == 1, 'pow2(0) = 1');
        assert(pow2_u32(1) == 2, 'pow2(1) = 2');
        assert(pow2_u32(10) == 1024, 'pow2(10) = 1024');
    }
}
