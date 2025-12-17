//! Shared STWO Verification Utilities
//!
//! This module provides common verification functions used by both:
//! - `contracts/proof_verifier.cairo` (general proof verification)
//! - `obelysk/stwo_verifier.cairo` (STWO-specific with GPU-TEE support)
//!
//! Consolidating verification logic here ensures:
//! - Consistent security properties across verifiers
//! - Single point of maintenance for cryptographic operations
//! - Reduced code duplication

use core::poseidon::poseidon_hash_span;
use core::array::{Array, ArrayTrait, SpanTrait};

// =============================================================================
// Constants - STWO Circle STARK (M31 Field)
// =============================================================================

/// Mersenne-31 prime: 2^31 - 1
pub const M31_PRIME: felt252 = 2147483647;

/// Minimum proof elements for valid STWO STARK proof
pub const MIN_STARK_PROOF_ELEMENTS: u32 = 32;

/// Minimum FRI layers expected in a valid proof
pub const MIN_FRI_LAYERS: u32 = 4;

/// Expected commitment count (trace + composition)
pub const MIN_COMMITMENTS: u32 = 2;

/// Default PoW difficulty (leading zeros required)
pub const DEFAULT_POW_BITS: u32 = 16;

/// Maximum allowed PoW bits
pub const MAX_POW_BITS: u32 = 30;

/// Minimum allowed PoW bits
pub const MIN_POW_BITS: u32 = 12;

/// PCS config size (pow_bits, log_blowup, log_last_layer, n_queries)
pub const PCS_CONFIG_SIZE: u32 = 4;

// =============================================================================
// TEE Constants
// =============================================================================

/// Intel TDX attestation type
pub const TEE_TYPE_INTEL_TDX: u8 = 1;

/// AMD SEV-SNP attestation type
pub const TEE_TYPE_AMD_SEV_SNP: u8 = 2;

/// NVIDIA Confidential Computing attestation type
pub const TEE_TYPE_NVIDIA_CC: u8 = 3;

// =============================================================================
// Hash Functions
// =============================================================================

/// Compute cryptographically secure hash of proof data using Poseidon
///
/// # Arguments
/// * `proof_data` - The proof data elements to hash
///
/// # Returns
/// * `felt252` - The Poseidon hash of the proof data
pub fn compute_proof_hash(proof_data: Span<felt252>) -> felt252 {
    poseidon_hash_span(proof_data)
}

/// Compute hash for proof of work verification
///
/// # Arguments
/// * `commitment` - The commitment being verified
/// * `nonce` - The PoW nonce
///
/// # Returns
/// * `felt252` - The Poseidon hash of (commitment, nonce)
pub fn compute_pow_hash(commitment: felt252, nonce: felt252) -> felt252 {
    let mut hash_input: Array<felt252> = ArrayTrait::new();
    hash_input.append(commitment);
    hash_input.append(nonce);
    poseidon_hash_span(hash_input.span())
}

// =============================================================================
// M31 Field Validation
// =============================================================================

/// Check if a value is a valid M31 field element
/// M31 elements must be in range [0, 2^31 - 1)
///
/// # Arguments
/// * `value` - The value to check
///
/// # Returns
/// * `bool` - True if value is a valid M31 element
pub fn is_valid_m31(value: felt252) -> bool {
    let value_u256: u256 = value.into();
    let m31_prime_u256: u256 = M31_PRIME.into();
    value_u256 < m31_prime_u256
}

/// Validate all elements in proof data are valid M31 field elements
///
/// # Arguments
/// * `proof_data` - The proof data to validate
/// * `start_index` - Index to start validation from
///
/// # Returns
/// * `bool` - True if all elements are valid M31 elements
pub fn validate_m31_elements(proof_data: Span<felt252>, start_index: u32) -> bool {
    let proof_len = proof_data.len();
    let mut i = start_index;

    while i < proof_len {
        let element = *proof_data[i];
        if !is_valid_m31(element) {
            return false;
        }
        i += 1;
    };

    true
}

// =============================================================================
// Proof of Work Verification
// =============================================================================

/// Verify proof of work meets difficulty requirement
///
/// # Arguments
/// * `proof_hash` - Hash of the proof being verified
/// * `nonce` - The PoW nonce
/// * `required_bits` - Number of leading zeros required
///
/// # Returns
/// * `bool` - True if PoW is valid
pub fn verify_pow(proof_hash: felt252, nonce: felt252, required_bits: u32) -> bool {
    // Validate inputs
    if nonce == 0 {
        return false;
    }
    if required_bits < MIN_POW_BITS || required_bits > MAX_POW_BITS {
        return false;
    }

    // Compute hash of (proof_hash, nonce)
    let pow_hash = compute_pow_hash(proof_hash, nonce);

    // Check leading zeros
    check_leading_zeros(pow_hash, required_bits)
}

/// Check if a hash has the required number of leading zeros
///
/// # Arguments
/// * `hash` - The hash to check
/// * `required_zeros` - Number of leading zero bits required
///
/// # Returns
/// * `bool` - True if hash has enough leading zeros
pub fn check_leading_zeros(hash: felt252, required_zeros: u32) -> bool {
    let hash_u256: u256 = hash.into();

    // Calculate difficulty threshold
    // For required_zeros leading zeros, hash must be < 2^(252 - required_zeros)
    if required_zeros >= 252 {
        // Impossibly high difficulty
        return false;
    }

    let shift_amount = 252 - required_zeros;
    let difficulty_threshold: u256 = pow2_u256(shift_amount);

    hash_u256 < difficulty_threshold
}

/// Calculate 2^n for u256 (power of 2)
pub fn pow2_u256(n: u32) -> u256 {
    if n == 0 {
        return 1_u256;
    }
    if n >= 256 {
        return 0_u256; // Overflow protection
    }

    // Use iterative doubling for efficiency
    let mut result: u256 = 1;
    let mut i: u32 = 0;
    while i < n {
        result = result * 2;
        i += 1;
    };
    result
}

// =============================================================================
// PCS Config Extraction
// =============================================================================

/// Extract PCS configuration from proof data
///
/// # Arguments
/// * `proof_data` - The proof data containing PCS config
///
/// # Returns
/// * `Option<(u32, u32, u32, u32)>` - (pow_bits, log_blowup, log_last_layer, n_queries) or None
pub fn extract_pcs_config(proof_data: Span<felt252>) -> Option<(u32, u32, u32, u32)> {
    if proof_data.len() < PCS_CONFIG_SIZE {
        return Option::None;
    }

    // Try to convert each config element
    let pow_bits: u32 = match (*proof_data[0]).try_into() {
        Option::Some(v) => v,
        Option::None => { return Option::None; }
    };

    let log_blowup: u32 = match (*proof_data[1]).try_into() {
        Option::Some(v) => v,
        Option::None => { return Option::None; }
    };

    let log_last_layer: u32 = match (*proof_data[2]).try_into() {
        Option::Some(v) => v,
        Option::None => { return Option::None; }
    };

    let n_queries: u32 = match (*proof_data[3]).try_into() {
        Option::Some(v) => v,
        Option::None => { return Option::None; }
    };

    Option::Some((pow_bits, log_blowup, log_last_layer, n_queries))
}

/// Calculate security bits from PCS configuration
/// Security = log_blowup_factor * n_queries + pow_bits
///
/// # Arguments
/// * `pow_bits` - Proof of work bits
/// * `log_blowup` - Log of blowup factor
/// * `n_queries` - Number of FRI queries
///
/// # Returns
/// * `u32` - Total security bits
pub fn calculate_security_bits(pow_bits: u32, log_blowup: u32, n_queries: u32) -> u32 {
    // Check for potential overflow
    let query_security = log_blowup * n_queries;
    query_security + pow_bits
}

/// Validate PCS configuration values are within acceptable ranges
///
/// # Arguments
/// * `pow_bits` - Proof of work bits (expected: 12-30)
/// * `log_blowup` - Log of blowup factor (expected: 1-16)
/// * `log_last_layer` - Log of last layer degree (expected: 0-20)
/// * `n_queries` - Number of FRI queries (expected: 4-128)
///
/// # Returns
/// * `bool` - True if all values are within range
pub fn validate_pcs_config(pow_bits: u32, log_blowup: u32, log_last_layer: u32, n_queries: u32) -> bool {
    // Validate pow_bits
    if pow_bits < MIN_POW_BITS || pow_bits > MAX_POW_BITS {
        return false;
    }

    // Validate log_blowup (1 to 16)
    if log_blowup < 1 || log_blowup > 16 {
        return false;
    }

    // Validate log_last_layer (0 to 20)
    if log_last_layer > 20 {
        return false;
    }

    // Validate n_queries (4 to 128)
    if n_queries < 4 || n_queries > 128 {
        return false;
    }

    true
}

// =============================================================================
// Structural Validation
// =============================================================================

/// Validate basic proof structure
///
/// # Arguments
/// * `proof_data` - The proof data to validate
///
/// # Returns
/// * `bool` - True if proof has valid structure
pub fn validate_proof_structure(proof_data: Span<felt252>) -> bool {
    let proof_len = proof_data.len();

    // Check minimum length
    if proof_len < MIN_STARK_PROOF_ELEMENTS {
        return false;
    }

    // Validate commitments exist and are non-zero
    let commitments_start = PCS_CONFIG_SIZE;
    if proof_len <= commitments_start + 1 {
        return false;
    }

    let trace_commitment = *proof_data[commitments_start];
    let composition_commitment = *proof_data[commitments_start + 1];

    if trace_commitment == 0 || composition_commitment == 0 {
        return false;
    }

    // Validate FRI proof has minimum layers
    let fri_start = commitments_start + 2;
    let fri_elements = proof_len - fri_start;
    let expected_fri_min = MIN_FRI_LAYERS * 3; // commitment + alpha + evaluations per layer

    if fri_elements < expected_fri_min {
        return false;
    }

    true
}

/// Comprehensive proof validation combining all checks
///
/// # Arguments
/// * `proof_data` - The proof data to validate
/// * `expected_min_security` - Minimum security bits required
///
/// # Returns
/// * `(bool, felt252)` - (is_valid, proof_hash)
pub fn validate_proof_comprehensive(
    proof_data: Span<felt252>,
    expected_min_security: u32
) -> (bool, felt252) {
    // Step 1: Structure validation
    if !validate_proof_structure(proof_data) {
        return (false, 0);
    }

    // Step 2: Extract and validate PCS config
    let config = match extract_pcs_config(proof_data) {
        Option::Some(c) => c,
        Option::None => { return (false, 0); }
    };
    let (pow_bits, log_blowup, log_last_layer, n_queries) = config;

    if !validate_pcs_config(pow_bits, log_blowup, log_last_layer, n_queries) {
        return (false, 0);
    }

    // Step 3: Check security bits
    let security_bits = calculate_security_bits(pow_bits, log_blowup, n_queries);
    if security_bits < expected_min_security {
        return (false, 0);
    }

    // Step 4: Validate M31 field elements
    let m31_start = PCS_CONFIG_SIZE + 2; // After config and commitments
    if !validate_m31_elements(proof_data, m31_start) {
        return (false, 0);
    }

    // Step 5: Compute proof hash
    let proof_hash = compute_proof_hash(proof_data);

    // Step 6: Verify PoW
    let pow_nonce = *proof_data[proof_data.len() - 1];
    if !verify_pow(proof_hash, pow_nonce, pow_bits) {
        return (false, 0);
    }

    (true, proof_hash)
}

// =============================================================================
// TEE Attestation Helpers
// =============================================================================

/// Validate TEE type is supported
///
/// # Arguments
/// * `tee_type` - The TEE type identifier
///
/// # Returns
/// * `bool` - True if TEE type is valid
pub fn is_valid_tee_type(tee_type: u8) -> bool {
    tee_type == TEE_TYPE_INTEL_TDX
        || tee_type == TEE_TYPE_AMD_SEV_SNP
        || tee_type == TEE_TYPE_NVIDIA_CC
}

/// Get TEE type name for display
///
/// # Arguments
/// * `tee_type` - The TEE type identifier
///
/// # Returns
/// * `felt252` - Name as felt252
pub fn get_tee_type_name(tee_type: u8) -> felt252 {
    if tee_type == TEE_TYPE_INTEL_TDX {
        'INTEL_TDX'
    } else if tee_type == TEE_TYPE_AMD_SEV_SNP {
        'AMD_SEV_SNP'
    } else if tee_type == TEE_TYPE_NVIDIA_CC {
        'NVIDIA_CC'
    } else {
        'UNKNOWN'
    }
}
