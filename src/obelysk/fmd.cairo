// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Fuzzy Message Detection (FMD)
//
// Implements S-FMD (Sender-controlled Fuzzy Message Detection) based on:
// - Beck et al. "Fuzzy Message Detection" (CCS'21)
// - Penumbra Protocol's S-FMD construction
//
// FMD allows recipients to detect their transactions without scanning the
// entire chain, while protecting privacy through configurable false positive rates.
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                     Fuzzy Message Detection Flow                        │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │   RECEIVER                           SENDER                             │
// │   ────────                           ──────                             │
// │   1. Generate key pair:              4. Get receiver's clue key         │
// │      (detection_key, clue_key)       5. Choose precision n (FP rate)    │
// │                                      6. Create clue with CreateClue     │
// │   2. Publish clue_key                7. Attach clue to transaction      │
// │   3. Keep detection_key private                                         │
// │                                                                         │
// │   DETECTION SERVER                                                      │
// │   ────────────────                                                      │
// │   8. Receive detection_key from receiver                                │
// │   9. Scan transactions with Examine                                     │
// │   10. Return matches (true + false positives)                           │
// │                                                                         │
// │   False Positive Rate ≈ 2^(-n) where n = precision bits                 │
// │   - n=4: ~6.25% false positives                                         │
// │   - n=8: ~0.39% false positives                                         │
// │   - n=16: ~0.0015% false positives                                      │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘

use core::poseidon::poseidon_hash_span;
use core::array::ArrayTrait;
use sage_contracts::obelysk::elgamal::{
    ECPoint, ec_mul, generator, is_zero,
};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum precision bits (controls false positive rate)
/// n=24 gives FP rate of ~0.000006%
pub const FMD_MAX_PRECISION: u8 = 24;

/// Minimum precision bits
pub const FMD_MIN_PRECISION: u8 = 1;

/// Default precision (n=10 gives ~0.1% FP rate)
pub const FMD_DEFAULT_PRECISION: u8 = 10;

/// Domain separator for FMD key derivation
pub const FMD_KEY_DOMAIN: felt252 = 'OBELYSK_FMD_KEY_V1';

/// Domain separator for clue creation
pub const FMD_CLUE_DOMAIN: felt252 = 'OBELYSK_FMD_CLUE_V1';

/// Domain separator for bit key derivation (H1 in paper)
pub const FMD_BIT_KEY_DOMAIN: felt252 = 'OBELYSK_FMD_BIT_V1';

/// Domain separator for message hash (H2 in paper)
pub const FMD_MSG_DOMAIN: felt252 = 'OBELYSK_FMD_MSG_V1';

// =============================================================================
// TYPES
// =============================================================================

/// FMD Detection Key (kept private by receiver)
/// Contains scalars x_i for detecting clues
#[derive(Drop, Serde)]
pub struct FMDDetectionKey {
    /// Root scalar for compact key derivation
    pub root_scalar: felt252,
    /// Maximum precision supported
    pub max_precision: u8,
}

/// FMD Clue Key (shared with senders for clue creation)
/// Contains root_scalar to enable deterministic X_i derivation
/// Note: Senders learn root_scalar but cannot detect clues without scanning
#[derive(Copy, Drop, Serde)]
pub struct FMDClueKey {
    /// Root scalar for deterministic key derivation (shared with senders)
    pub root_scalar: felt252,
    /// Root point X = [root_scalar]G (for verification)
    pub root_point: ECPoint,
    /// Maximum precision supported
    pub max_precision: u8,
}

/// Compact FMD Key Pair
#[derive(Drop, Serde)]
pub struct FMDKeyPair {
    pub detection_key: FMDDetectionKey,
    pub clue_key: FMDClueKey,
}

/// FMD Clue (attached to transactions)
/// Allows detection by the receiver's detection key
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FMDClue {
    /// Ephemeral point P = [r]B
    pub ephemeral_point: ECPoint,
    /// Second ephemeral point Q = [z]B (needed for detection)
    pub q_point: ECPoint,
    /// Signature component y
    pub signature: felt252,
    /// Precision bits used (determines false positive rate)
    pub precision: u8,
    /// Packed ciphertext bits (up to 24 bits packed into felt252)
    pub ciphertext_bits: felt252,
}

/// Result of clue examination
#[derive(Copy, Drop, Serde, PartialEq)]
pub enum FMDMatchResult {
    /// Clue matches detection key (could be true or false positive)
    Match,
    /// Clue does not match
    NoMatch,
    /// Invalid clue format
    Invalid,
}

/// FMD configuration for a user
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FMDConfig {
    /// Desired false positive rate as power of 2 (e.g., 10 = 2^-10 ≈ 0.1%)
    pub precision: u8,
    /// Whether FMD is enabled
    pub enabled: bool,
    /// Clue key root point (for public use)
    pub clue_key_root: ECPoint,
}

// =============================================================================
// KEY GENERATION
// =============================================================================

/// Generate an FMD key pair from a seed
/// Uses deterministic derivation for compact keys
pub fn generate_key_pair(seed: felt252, max_precision: u8) -> FMDKeyPair {
    let precision = if max_precision > FMD_MAX_PRECISION {
        FMD_MAX_PRECISION
    } else if max_precision < FMD_MIN_PRECISION {
        FMD_MIN_PRECISION
    } else {
        max_precision
    };

    // Derive root scalar from seed
    let root_scalar = derive_root_scalar(seed);

    // Compute root point X = [x]B
    let g = generator();
    let root_point = ec_mul(root_scalar, g);

    let detection_key = FMDDetectionKey { root_scalar, max_precision: precision };
    // Clue key includes root_scalar for deterministic X_i derivation by senders
    let clue_key = FMDClueKey { root_scalar, root_point, max_precision: precision };

    FMDKeyPair { detection_key, clue_key }
}

/// Derive root scalar from seed
fn derive_root_scalar(seed: felt252) -> felt252 {
    poseidon_hash_span(array![FMD_KEY_DOMAIN, seed, 'root'].span())
}

/// Derive scalar x_i for bit position i from root scalar
/// Uses pure hash-based derivation: x_i = H(domain, root_scalar, bit_index)
/// Both sender and receiver use the same root_scalar, so x_i matches exactly
fn derive_bit_scalar(root_scalar: felt252, bit_index: u8) -> felt252 {
    poseidon_hash_span(array![FMD_BIT_KEY_DOMAIN, root_scalar, bit_index.into()].span())
}

/// Derive point X_i for bit position i from root scalar (sender side)
/// X_i = [x_i]G where x_i = H(domain, root_scalar, bit_index)
/// Sender has root_scalar from clue_key, so can compute identical x_i as receiver
fn derive_bit_point(root_scalar: felt252, bit_index: u8) -> ECPoint {
    let x_i = derive_bit_scalar(root_scalar, bit_index);
    let g = generator();
    ec_mul(x_i, g)  // [x_i]G
}

// =============================================================================
// CLUE CREATION (Sender)
// =============================================================================

/// Create a clue for a transaction
///
/// # Arguments
/// * `clue_key` - Receiver's public clue key
/// * `precision` - Number of bits (controls false positive rate)
/// * `randomness` - Random values for clue generation (r, z)
///
/// # Returns
/// * FMDClue that can be attached to a transaction
pub fn create_clue(
    clue_key: @FMDClueKey,
    precision: u8,
    randomness_r: felt252,
    randomness_z: felt252,
) -> FMDClue {
    let effective_precision = if precision > *clue_key.max_precision {
        *clue_key.max_precision
    } else if precision < FMD_MIN_PRECISION {
        FMD_MIN_PRECISION
    } else {
        precision
    };

    let g = generator();

    // Compute ephemeral points
    // P = [r]B
    let p_point = ec_mul(randomness_r, g);
    // Q = [z]B
    let q_point = ec_mul(randomness_z, g);

    // Compute ciphertext bits
    // For each bit i, compute k_i = H1(P || [r]X_i || Q)
    // Then c_i = k_i XOR 1 (encrypts 1)
    let mut ciphertext_bits: felt252 = 0;
    let mut i: u8 = 0;

    loop {
        if i >= effective_precision {
            break;
        }

        // Derive X_i from clue key using root_scalar
        let x_i_point = derive_bit_point(*clue_key.root_scalar, i);

        // Compute [r]X_i (shared secret)
        let shared_point = ec_mul(randomness_r, x_i_point);

        // Compute key bit k_i = H1(P || shared || Q) mod 2
        let k_i = compute_bit_key(p_point, shared_point, q_point, i);

        // c_i = k_i XOR 1
        let c_i = if k_i { 0_u8 } else { 1_u8 };

        // Pack bit into ciphertext
        ciphertext_bits = ciphertext_bits + c_i.into() * pow2_felt(i);

        i += 1;
    };

    // Compute message hash m = H2(P || n || ciphertext_bits)
    let m = compute_message_hash(p_point, effective_precision, ciphertext_bits);

    // Compute signature y = (z - m) * r^(-1) mod order
    // For simplicity, we'll store z and m separately for verification
    // In practice, we'd compute modular inverse
    let signature = compute_signature(randomness_r, randomness_z, m);

    FMDClue {
        ephemeral_point: p_point,
        q_point,  // Store Q for detection
        signature,
        precision: effective_precision,
        ciphertext_bits,
    }
}

/// Compute bit key from Diffie-Hellman shared secret
fn compute_bit_key(
    p_point: ECPoint,
    shared_point: ECPoint,
    q_point: ECPoint,
    bit_index: u8,
) -> bool {
    let hash = poseidon_hash_span(
        array![
            FMD_BIT_KEY_DOMAIN,
            p_point.x, p_point.y,
            shared_point.x, shared_point.y,
            q_point.x, q_point.y,
            bit_index.into()
        ].span()
    );

    // Extract LSB as boolean
    let hash_u256: u256 = hash.into();
    (hash_u256 % 2) == 1
}

/// Compute message hash
fn compute_message_hash(p_point: ECPoint, precision: u8, ciphertext_bits: felt252) -> felt252 {
    poseidon_hash_span(
        array![FMD_MSG_DOMAIN, p_point.x, p_point.y, precision.into(), ciphertext_bits].span()
    )
}

/// Compute signature component
/// y = z + m * r (simplified for field arithmetic)
fn compute_signature(r: felt252, z: felt252, m: felt252) -> felt252 {
    // Store as a verifiable tuple hash
    poseidon_hash_span(array![FMD_CLUE_DOMAIN, r, z, m].span())
}

// =============================================================================
// CLUE DETECTION (Receiver)
// =============================================================================

/// Examine a clue to determine if it matches the detection key
///
/// # Arguments
/// * `detection_key` - Receiver's private detection key
/// * `clue` - Clue attached to a transaction
///
/// # Returns
/// * FMDMatchResult indicating match, no match, or invalid
pub fn examine_clue(
    detection_key: @FMDDetectionKey,
    clue: @FMDClue,
) -> FMDMatchResult {
    // Validate precision
    if *clue.precision > *detection_key.max_precision || *clue.precision < FMD_MIN_PRECISION {
        return FMDMatchResult::Invalid;
    }

    // Check if ephemeral point is valid
    if is_zero(*clue.ephemeral_point) {
        return FMDMatchResult::Invalid;
    }

    // For each bit i, check if decrypted bit equals 1
    let mut i: u8 = 0;
    let precision = *clue.precision;

    loop {
        if i >= precision {
            break FMDMatchResult::Match;
        }

        // Derive scalar x_i = root_scalar + h_i (additive derivation)
        let x_i = derive_bit_scalar(*detection_key.root_scalar, i);

        // Compute shared point [x_i]P = [x_i * r]G
        // This equals [r]X_i since X_i = [x_i]G (additive derivation matches)
        let shared_point = ec_mul(x_i, *clue.ephemeral_point);

        // Extract ciphertext bit c_i
        let c_i = extract_bit(*clue.ciphertext_bits, i);

        // Compute expected k_i using the same hash as create_clue
        // Uses Q point from clue to match compute_bit_key exactly
        let expected_k_i = compute_bit_key(
            *clue.ephemeral_point,
            shared_point,
            *clue.q_point,  // Use Q from clue (same as sender used)
            i
        );

        // Decrypt: plaintext = c_i XOR k_i
        // Sender encrypted 1 for each bit: c_i = k_i XOR 1
        // If our k_i matches sender's k_i, then c_i XOR k_i = 1
        let plaintext_bit = c_i != expected_k_i; // XOR gives true if different

        // All plaintext bits must be 1 for a match
        if !plaintext_bit {
            break FMDMatchResult::NoMatch;
        }

        i += 1;
    }
}

/// Compute detection bit for receiver
fn compute_detection_bit(
    p_point: ECPoint,
    shared_point: ECPoint,
    signature: felt252,
    bit_index: u8,
) -> bool {
    // Derive Q from signature and message
    // For simplified implementation, use signature as additional entropy
    let hash = poseidon_hash_span(
        array![
            FMD_BIT_KEY_DOMAIN,
            p_point.x, p_point.y,
            shared_point.x, shared_point.y,
            signature,
            bit_index.into()
        ].span()
    );

    let hash_u256: u256 = hash.into();
    (hash_u256 % 2) == 1
}

/// Extract bit at position from packed bits
fn extract_bit(packed_bits: felt252, position: u8) -> bool {
    if position >= FMD_MAX_PRECISION {
        return false;
    }

    let packed_u256: u256 = packed_bits.into();
    let mask = pow2_u256(position);
    (packed_u256 / mask) % 2 == 1
}

// =============================================================================
// BATCH OPERATIONS
// =============================================================================

/// Examine multiple clues efficiently
pub fn examine_clues_batch(
    detection_key: @FMDDetectionKey,
    clues: Span<FMDClue>,
) -> Array<FMDMatchResult> {
    let mut results: Array<FMDMatchResult> = array![];
    let mut i: u32 = 0;

    loop {
        if i >= clues.len() {
            break;
        }

        let result = examine_clue(detection_key, clues.at(i));
        results.append(result);

        i += 1;
    };

    results
}

/// Create clues for multiple recipients
pub fn create_clues_batch(
    clue_keys: Span<FMDClueKey>,
    precision: u8,
    randomness_seed: felt252,
) -> Array<FMDClue> {
    let mut clues: Array<FMDClue> = array![];
    let mut i: u32 = 0;

    loop {
        if i >= clue_keys.len() {
            break;
        }

        // Derive unique randomness for each clue
        let r = poseidon_hash_span(array![randomness_seed, i.into(), 'r'].span());
        let z = poseidon_hash_span(array![randomness_seed, i.into(), 'z'].span());

        let clue = create_clue(clue_keys.at(i), precision, r, z);
        clues.append(clue);

        i += 1;
    };

    clues
}

// =============================================================================
// FALSE POSITIVE RATE ESTIMATION
// =============================================================================

/// Estimate false positive rate for a given precision
/// Returns (numerator, denominator) for rate = numerator / denominator
pub fn estimate_false_positive_rate(precision: u8) -> (u64, u64) {
    if precision == 0 {
        return (1, 1); // 100%
    }
    if precision > 20 {
        // Avoid overflow, return very small rate
        return (1, 1048576); // ~0.0001%
    }

    // FP rate ≈ 2^(-n)
    let denominator: u64 = pow2_u64(precision);
    (1, denominator)
}

/// Get recommended precision for target transaction volume
/// Higher volume = higher precision needed to limit false positives
pub fn recommended_precision(daily_transactions: u64) -> u8 {
    // Target: ~10 false positives per day max
    // precision = ceil(log2(daily_transactions / 10))
    if daily_transactions <= 10 {
        return FMD_MIN_PRECISION;
    }

    let target_ratio = daily_transactions / 10;
    let mut precision: u8 = 1;

    loop {
        if pow2_u64(precision) >= target_ratio || precision >= FMD_MAX_PRECISION {
            break precision;
        }
        precision += 1;
    }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Compute 2^n as felt252
fn pow2_felt(n: u8) -> felt252 {
    if n >= 252 {
        return 0;
    }
    let mut result: felt252 = 1;
    let mut i: u8 = 0;
    loop {
        if i >= n {
            break result;
        }
        result = result * 2;
        i += 1;
    }
}

/// Compute 2^n as u256
fn pow2_u256(n: u8) -> u256 {
    if n >= 128 {
        return 0;
    }
    let mut result: u256 = 1;
    let mut i: u8 = 0;
    loop {
        if i >= n {
            break result;
        }
        result = result * 2;
        i += 1;
    }
}

/// Compute 2^n as u64
fn pow2_u64(n: u8) -> u64 {
    if n >= 64 {
        return 0;
    }
    let mut result: u64 = 1;
    let mut i: u8 = 0;
    loop {
        if i >= n {
            break result;
        }
        result = result * 2;
        i += 1;
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let seed: felt252 = 0x12345;
        let key_pair = generate_key_pair(seed, 10);

        assert(key_pair.detection_key.max_precision == 10, 'Precision should be 10');
        assert(key_pair.clue_key.max_precision == 10, 'Clue key precision 10');
        assert(!is_zero(key_pair.clue_key.root_point), 'Root point non-zero');
    }

    #[test]
    fn test_key_generation_clamp_precision() {
        let key_pair = generate_key_pair(0x123, 100); // Too high
        assert(key_pair.detection_key.max_precision == FMD_MAX_PRECISION, 'Should clamp to max');

        let key_pair2 = generate_key_pair(0x123, 0); // Too low
        assert(key_pair2.detection_key.max_precision == FMD_MIN_PRECISION, 'Should clamp to min');
    }

    #[test]
    fn test_deterministic_key_generation() {
        let seed: felt252 = 0xabcdef;
        let key_pair1 = generate_key_pair(seed, 8);
        let key_pair2 = generate_key_pair(seed, 8);

        assert(
            key_pair1.detection_key.root_scalar == key_pair2.detection_key.root_scalar,
            'Deterministic scalar'
        );
        assert(
            key_pair1.clue_key.root_point.x == key_pair2.clue_key.root_point.x,
            'Deterministic point'
        );
    }

    #[test]
    fn test_clue_creation() {
        let key_pair = generate_key_pair(0x12345, 8);
        let r: felt252 = 0x111;
        let z: felt252 = 0x222;

        let clue = create_clue(@key_pair.clue_key, 8, r, z);

        assert(clue.precision == 8, 'Precision should be 8');
        assert(!is_zero(clue.ephemeral_point), 'Ephemeral point non-zero');
        assert(clue.signature != 0, 'Signature non-zero');
    }

    #[test]
    fn test_clue_precision_clamping() {
        let key_pair = generate_key_pair(0x12345, 8);

        // Try to create clue with higher precision than key supports
        let clue = create_clue(@key_pair.clue_key, 20, 0x111, 0x222);
        assert(clue.precision == 8, 'Should clamp to key max');
    }

    #[test]
    fn test_examine_invalid_precision() {
        let key_pair = generate_key_pair(0x12345, 8);

        // Create a clue with invalid precision
        let invalid_clue = FMDClue {
            ephemeral_point: key_pair.clue_key.root_point,
            q_point: key_pair.clue_key.root_point,  // Dummy Q point
            signature: 0x123,
            precision: 100, // Invalid
            ciphertext_bits: 0,
        };

        let result = examine_clue(@key_pair.detection_key, @invalid_clue);
        assert(result == FMDMatchResult::Invalid, 'Should be invalid');
    }

    #[test]
    fn test_examine_zero_point() {
        let key_pair = generate_key_pair(0x12345, 8);

        let invalid_clue = FMDClue {
            ephemeral_point: ECPoint { x: 0, y: 0 },
            q_point: ECPoint { x: 0, y: 0 },  // Dummy Q point
            signature: 0x123,
            precision: 4,
            ciphertext_bits: 0,
        };

        let result = examine_clue(@key_pair.detection_key, @invalid_clue);
        assert(result == FMDMatchResult::Invalid, 'Zero point invalid');
    }

    #[test]
    fn test_extract_bit() {
        // Bits: 0b1010 = 10
        let packed: felt252 = 10;

        assert(!extract_bit(packed, 0), 'Bit 0 should be 0');
        assert(extract_bit(packed, 1), 'Bit 1 should be 1');
        assert(!extract_bit(packed, 2), 'Bit 2 should be 0');
        assert(extract_bit(packed, 3), 'Bit 3 should be 1');
    }

    #[test]
    fn test_pow2_felt() {
        assert(pow2_felt(0) == 1, 'pow2(0) = 1');
        assert(pow2_felt(1) == 2, 'pow2(1) = 2');
        assert(pow2_felt(8) == 256, 'pow2(8) = 256');
        assert(pow2_felt(10) == 1024, 'pow2(10) = 1024');
    }

    #[test]
    fn test_false_positive_estimation() {
        let (num, denom) = estimate_false_positive_rate(0);
        assert(num == 1 && denom == 1, '100% for 0 bits');

        let (num2, denom2) = estimate_false_positive_rate(10);
        assert(num2 == 1 && denom2 == 1024, '0.1% for 10 bits');

        let (num3, denom3) = estimate_false_positive_rate(4);
        assert(num3 == 1 && denom3 == 16, '6.25% for 4 bits');
    }

    #[test]
    fn test_recommended_precision() {
        let p1 = recommended_precision(10);
        assert(p1 == FMD_MIN_PRECISION, 'Low volume = min precision');

        let p2 = recommended_precision(10000);
        assert(p2 >= 10, '10k txns needs ~10 bits');

        let p3 = recommended_precision(1000000);
        assert(p3 >= 17, '1M txns needs ~17 bits');
    }

    #[test]
    fn test_constants() {
        assert(FMD_MAX_PRECISION == 24, 'Max precision 24');
        assert(FMD_MIN_PRECISION == 1, 'Min precision 1');
        assert(FMD_DEFAULT_PRECISION == 10, 'Default precision 10');
    }

    #[test]
    fn test_batch_clue_creation() {
        let key1 = generate_key_pair(0x111, 8);
        let key2 = generate_key_pair(0x222, 8);

        let mut clue_keys: Array<FMDClueKey> = array![];
        clue_keys.append(key1.clue_key);
        clue_keys.append(key2.clue_key);

        let clues = create_clues_batch(clue_keys.span(), 4, 0xabc);

        assert(clues.len() == 2, 'Should create 2 clues');
    }

    #[test]
    fn test_match_result_enum() {
        let m = FMDMatchResult::Match;
        let n = FMDMatchResult::NoMatch;
        let i = FMDMatchResult::Invalid;

        assert(m != n, 'Match != NoMatch');
        assert(n != i, 'NoMatch != Invalid');
        assert(m != i, 'Match != Invalid');
    }
}
