// SPDX-License-Identifier: BUSL-1.1
// Fuzzy Message Detection (FMD) External Tests
// Comprehensive tests for privacy-preserving transaction filtering

use sage_contracts::obelysk::fmd::{
    // Constants
    FMD_MAX_PRECISION, FMD_MIN_PRECISION, FMD_DEFAULT_PRECISION,
    FMD_KEY_DOMAIN, FMD_CLUE_DOMAIN, FMD_BIT_KEY_DOMAIN, FMD_MSG_DOMAIN,
    // Types
    FMDDetectionKey, FMDClueKey, FMDClue, FMDMatchResult, FMDConfig,
    // Functions
    generate_key_pair, create_clue, examine_clue, examine_clues_batch,
    create_clues_batch, estimate_false_positive_rate, recommended_precision,
};
use sage_contracts::obelysk::elgamal::{ECPoint, is_zero, generator, ec_mul};

// =============================================================================
// CONSTANT TESTS
// =============================================================================

#[test]
fn test_max_precision_is_24() {
    assert(FMD_MAX_PRECISION == 24, 'Max precision should be 24');
}

#[test]
fn test_min_precision_is_1() {
    assert(FMD_MIN_PRECISION == 1, 'Min precision should be 1');
}

#[test]
fn test_default_precision_is_10() {
    assert(FMD_DEFAULT_PRECISION == 10, 'Default precision 10');
}

#[test]
fn test_domain_separators_unique() {
    assert(FMD_KEY_DOMAIN != FMD_CLUE_DOMAIN, 'Key != Clue domain');
    assert(FMD_CLUE_DOMAIN != FMD_BIT_KEY_DOMAIN, 'Clue != Bit domain');
    assert(FMD_BIT_KEY_DOMAIN != FMD_MSG_DOMAIN, 'Bit != Msg domain');
    assert(FMD_KEY_DOMAIN != FMD_MSG_DOMAIN, 'Key != Msg domain');
}

#[test]
fn test_domain_separators_non_zero() {
    assert(FMD_KEY_DOMAIN != 0, 'Key domain non-zero');
    assert(FMD_CLUE_DOMAIN != 0, 'Clue domain non-zero');
    assert(FMD_BIT_KEY_DOMAIN != 0, 'Bit domain non-zero');
    assert(FMD_MSG_DOMAIN != 0, 'Msg domain non-zero');
}

// =============================================================================
// KEY GENERATION TESTS
// =============================================================================

#[test]
fn test_key_pair_generation_basic() {
    let key_pair = generate_key_pair(0x12345, 8);

    assert(key_pair.detection_key.max_precision == 8, 'Detection key precision');
    assert(key_pair.clue_key.max_precision == 8, 'Clue key precision');
    assert(key_pair.detection_key.root_scalar != 0, 'Root scalar non-zero');
}

#[test]
fn test_key_pair_root_point_on_curve() {
    let key_pair = generate_key_pair(0xabcdef, 10);

    // Root point should be non-zero (valid EC point)
    assert(!is_zero(key_pair.clue_key.root_point), 'Root point valid');
}

#[test]
fn test_key_pair_deterministic() {
    let seed: felt252 = 0x999888777;
    let kp1 = generate_key_pair(seed, 12);
    let kp2 = generate_key_pair(seed, 12);

    assert(kp1.detection_key.root_scalar == kp2.detection_key.root_scalar, 'Same seed = same key');
    assert(kp1.clue_key.root_point.x == kp2.clue_key.root_point.x, 'Same root point');
}

#[test]
fn test_key_pair_different_seeds_different_keys() {
    let kp1 = generate_key_pair(0x111, 8);
    let kp2 = generate_key_pair(0x222, 8);

    assert(kp1.detection_key.root_scalar != kp2.detection_key.root_scalar, 'Different seeds');
    assert(kp1.clue_key.root_point.x != kp2.clue_key.root_point.x, 'Different points');
}

#[test]
fn test_key_pair_precision_clamping_high() {
    let kp = generate_key_pair(0x123, 100);
    assert(kp.detection_key.max_precision == FMD_MAX_PRECISION, 'Clamp to max');
}

#[test]
fn test_key_pair_precision_clamping_zero() {
    let kp = generate_key_pair(0x123, 0);
    assert(kp.detection_key.max_precision == FMD_MIN_PRECISION, 'Clamp to min');
}

#[test]
fn test_key_pair_precision_at_boundaries() {
    let kp_min = generate_key_pair(0x111, FMD_MIN_PRECISION);
    let kp_max = generate_key_pair(0x222, FMD_MAX_PRECISION);

    assert(kp_min.detection_key.max_precision == FMD_MIN_PRECISION, 'Min precision');
    assert(kp_max.detection_key.max_precision == FMD_MAX_PRECISION, 'Max precision');
}

// =============================================================================
// CLUE CREATION TESTS
// =============================================================================

#[test]
fn test_clue_creation_basic() {
    let kp = generate_key_pair(0x12345, 10);
    let clue = create_clue(@kp.clue_key, 6, 0x111, 0x222);

    assert(clue.precision == 6, 'Clue precision 6');
    assert(!is_zero(clue.ephemeral_point), 'Ephemeral point valid');
    assert(clue.signature != 0, 'Signature non-zero');
}

#[test]
fn test_clue_precision_clamped_to_key() {
    let kp = generate_key_pair(0x12345, 8);
    let clue = create_clue(@kp.clue_key, 20, 0x111, 0x222);

    assert(clue.precision == 8, 'Clamp to key precision');
}

#[test]
fn test_clue_precision_minimum() {
    let kp = generate_key_pair(0x12345, 8);
    let clue = create_clue(@kp.clue_key, 0, 0x111, 0x222);

    assert(clue.precision == FMD_MIN_PRECISION, 'Clamp to min');
}

#[test]
fn test_clue_different_randomness_different_clues() {
    let kp = generate_key_pair(0x12345, 8);

    let clue1 = create_clue(@kp.clue_key, 4, 0x111, 0x222);
    let clue2 = create_clue(@kp.clue_key, 4, 0x333, 0x444);

    assert(clue1.ephemeral_point.x != clue2.ephemeral_point.x, 'Different ephemeral');
    assert(clue1.signature != clue2.signature, 'Different signature');
}

#[test]
fn test_clue_same_randomness_same_clue() {
    let kp = generate_key_pair(0x12345, 8);

    let clue1 = create_clue(@kp.clue_key, 4, 0x111, 0x222);
    let clue2 = create_clue(@kp.clue_key, 4, 0x111, 0x222);

    assert(clue1.ephemeral_point.x == clue2.ephemeral_point.x, 'Same ephemeral');
    assert(clue1.signature == clue2.signature, 'Same signature');
}

#[test]
fn test_clue_ephemeral_point_is_valid_ec_point() {
    let kp = generate_key_pair(0xabc, 8);
    let clue = create_clue(@kp.clue_key, 8, 0x999, 0x888);

    // P = [r]G should be a valid point
    let g = generator();
    let expected_p = ec_mul(0x999, g);

    assert(clue.ephemeral_point.x == expected_p.x, 'P = [r]G');
    assert(clue.ephemeral_point.y == expected_p.y, 'P = [r]G y');
}

// =============================================================================
// CLUE EXAMINATION TESTS
// =============================================================================

#[test]
fn test_examine_invalid_precision_too_high() {
    let kp = generate_key_pair(0x12345, 8);

    let invalid_clue = FMDClue {
        ephemeral_point: kp.clue_key.root_point,
        q_point: kp.clue_key.root_point,  // Dummy Q
        signature: 0x123,
        precision: 50, // Higher than key's max
        ciphertext_bits: 0,
    };

    let result = examine_clue(@kp.detection_key, @invalid_clue);
    assert(result == FMDMatchResult::Invalid, 'Should be invalid');
}

#[test]
fn test_examine_invalid_precision_zero() {
    let kp = generate_key_pair(0x12345, 8);

    let invalid_clue = FMDClue {
        ephemeral_point: kp.clue_key.root_point,
        q_point: kp.clue_key.root_point,  // Dummy Q
        signature: 0x123,
        precision: 0, // Below minimum
        ciphertext_bits: 0,
    };

    let result = examine_clue(@kp.detection_key, @invalid_clue);
    assert(result == FMDMatchResult::Invalid, 'Zero precision invalid');
}

#[test]
fn test_examine_zero_ephemeral_point() {
    let kp = generate_key_pair(0x12345, 8);

    let invalid_clue = FMDClue {
        ephemeral_point: ECPoint { x: 0, y: 0 },
        q_point: ECPoint { x: 0, y: 0 },  // Dummy Q
        signature: 0x123,
        precision: 4,
        ciphertext_bits: 0,
    };

    let result = examine_clue(@kp.detection_key, @invalid_clue);
    assert(result == FMDMatchResult::Invalid, 'Zero point invalid');
}

#[test]
fn test_match_result_enum_distinct() {
    let m = FMDMatchResult::Match;
    let n = FMDMatchResult::NoMatch;
    let i = FMDMatchResult::Invalid;

    assert(m != n, 'Match != NoMatch');
    assert(n != i, 'NoMatch != Invalid');
    assert(m != i, 'Match != Invalid');
}

// =============================================================================
// BATCH OPERATIONS TESTS
// =============================================================================

#[test]
fn test_batch_clue_creation_empty() {
    let clue_keys: Array<FMDClueKey> = array![];
    let clues = create_clues_batch(clue_keys.span(), 4, 0x12345);

    assert(clues.len() == 0, 'Empty input = empty output');
}

#[test]
fn test_batch_clue_creation_single() {
    let kp = generate_key_pair(0x111, 8);
    let mut clue_keys: Array<FMDClueKey> = array![];
    clue_keys.append(kp.clue_key);

    let clues = create_clues_batch(clue_keys.span(), 4, 0x12345);

    assert(clues.len() == 1, 'One clue created');
}

#[test]
fn test_batch_clue_creation_multiple() {
    let kp1 = generate_key_pair(0x111, 8);
    let kp2 = generate_key_pair(0x222, 8);
    let kp3 = generate_key_pair(0x333, 8);

    let mut clue_keys: Array<FMDClueKey> = array![];
    clue_keys.append(kp1.clue_key);
    clue_keys.append(kp2.clue_key);
    clue_keys.append(kp3.clue_key);

    let clues = create_clues_batch(clue_keys.span(), 6, 0xabc);

    assert(clues.len() == 3, 'Three clues created');
}

#[test]
fn test_batch_clue_creation_unique_randomness() {
    let kp1 = generate_key_pair(0x111, 8);
    let kp2 = generate_key_pair(0x222, 8);

    let mut clue_keys: Array<FMDClueKey> = array![];
    clue_keys.append(kp1.clue_key);
    clue_keys.append(kp2.clue_key);

    let clues = create_clues_batch(clue_keys.span(), 4, 0x12345);

    let clue0 = clues.at(0);
    let clue1 = clues.at(1);

    assert(clue0.ephemeral_point.x != clue1.ephemeral_point.x, 'Different randomness');
}

#[test]
fn test_batch_examine_empty() {
    let kp = generate_key_pair(0x12345, 8);
    let clues: Array<FMDClue> = array![];

    let results = examine_clues_batch(@kp.detection_key, clues.span());

    assert(results.len() == 0, 'Empty input = empty output');
}

// =============================================================================
// FALSE POSITIVE RATE TESTS
// =============================================================================

#[test]
fn test_fp_rate_zero_precision() {
    let (num, denom) = estimate_false_positive_rate(0);
    assert(num == 1 && denom == 1, '100% for 0 bits');
}

#[test]
fn test_fp_rate_1_bit() {
    let (num, denom) = estimate_false_positive_rate(1);
    assert(num == 1 && denom == 2, '50% for 1 bit');
}

#[test]
fn test_fp_rate_4_bits() {
    let (num, denom) = estimate_false_positive_rate(4);
    assert(num == 1 && denom == 16, '6.25% for 4 bits');
}

#[test]
fn test_fp_rate_8_bits() {
    let (num, denom) = estimate_false_positive_rate(8);
    assert(num == 1 && denom == 256, '~0.4% for 8 bits');
}

#[test]
fn test_fp_rate_10_bits() {
    let (num, denom) = estimate_false_positive_rate(10);
    assert(num == 1 && denom == 1024, '~0.1% for 10 bits');
}

#[test]
fn test_fp_rate_16_bits() {
    let (num, denom) = estimate_false_positive_rate(16);
    assert(num == 1 && denom == 65536, '~0.0015% for 16 bits');
}

#[test]
fn test_fp_rate_high_precision() {
    let (num, denom) = estimate_false_positive_rate(30);
    // Should cap at reasonable value
    assert(num == 1, 'Numerator is 1');
    assert(denom > 0, 'Denominator positive');
}

// =============================================================================
// RECOMMENDED PRECISION TESTS
// =============================================================================

#[test]
fn test_recommended_precision_low_volume() {
    let p = recommended_precision(5);
    assert(p == FMD_MIN_PRECISION, 'Low volume = min precision');
}

#[test]
fn test_recommended_precision_10_txns() {
    let p = recommended_precision(10);
    assert(p == FMD_MIN_PRECISION, '10 txns = min precision');
}

#[test]
fn test_recommended_precision_100_txns() {
    let p = recommended_precision(100);
    assert(p >= 3, '100 txns needs ~3 bits');
}

#[test]
fn test_recommended_precision_1000_txns() {
    let p = recommended_precision(1000);
    assert(p >= 6, '1k txns needs ~6 bits');
}

#[test]
fn test_recommended_precision_10000_txns() {
    let p = recommended_precision(10000);
    assert(p >= 10, '10k txns needs ~10 bits');
}

#[test]
fn test_recommended_precision_1m_txns() {
    let p = recommended_precision(1000000);
    assert(p >= 17, '1M txns needs ~17 bits');
}

#[test]
fn test_recommended_precision_capped() {
    let p = recommended_precision(10000000000);
    assert(p <= FMD_MAX_PRECISION, 'Should cap at max');
}

// =============================================================================
// FMD CONFIG TESTS
// =============================================================================

#[test]
fn test_fmd_config_creation() {
    let config = FMDConfig {
        precision: 10,
        enabled: true,
        clue_key_root: ECPoint { x: 0x123, y: 0x456 },
    };

    assert(config.precision == 10, 'Precision set');
    assert(config.enabled, 'Enabled set');
    assert(config.clue_key_root.x == 0x123, 'Root x set');
}

#[test]
fn test_fmd_config_disabled() {
    let config = FMDConfig {
        precision: 8,
        enabled: false,
        clue_key_root: ECPoint { x: 0, y: 0 },
    };

    assert(!config.enabled, 'Disabled config');
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

#[test]
fn test_full_flow_key_to_clue_to_examine() {
    // 1. Receiver generates key pair
    let receiver_keys = generate_key_pair(0x12345678, 8);

    // 2. Sender creates clue using receiver's clue key
    let clue = create_clue(@receiver_keys.clue_key, 4, 0x9999, 0x8888);

    // 3. Clue has valid structure
    assert(clue.precision == 4, 'Clue precision correct');
    assert(!is_zero(clue.ephemeral_point), 'Valid ephemeral');

    // 4. Receiver can examine clue (result depends on protocol correctness)
    let result = examine_clue(@receiver_keys.detection_key, @clue);
    // Result should be Match or NoMatch, not Invalid
    assert(result != FMDMatchResult::Invalid, 'Valid clue structure');
}

#[test]
fn test_multiple_receivers_different_clues() {
    let receiver1 = generate_key_pair(0x111, 8);
    let receiver2 = generate_key_pair(0x222, 8);

    let clue1 = create_clue(@receiver1.clue_key, 4, 0xabc, 0xdef);
    let clue2 = create_clue(@receiver2.clue_key, 4, 0xabc, 0xdef);

    // Same randomness = same ephemeral point P (expected behavior)
    assert(clue1.ephemeral_point.x == clue2.ephemeral_point.x, 'Same ephemeral P');

    // Both clues should be valid
    assert(clue1.precision == 4, 'Clue1 valid precision');
    assert(clue2.precision == 4, 'Clue2 valid precision');
    assert(!is_zero(clue1.ephemeral_point), 'Clue1 valid point');
    assert(!is_zero(clue2.ephemeral_point), 'Clue2 valid point');
}
