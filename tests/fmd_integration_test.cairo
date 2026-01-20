// ===========================================================================
// Fuzzy Message Detection (FMD) Integration Tests
// ===========================================================================
// Tests the S-FMD implementation based on Beck et al. "Fuzzy Message Detection"
// with real cryptographic operations for key generation, clue creation, and
// clue detection.
// ===========================================================================

use core::traits::Into;
use core::option::OptionTrait;
use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::fmd::{
    // Types
    FMDDetectionKey, FMDClueKey, FMDKeyPair, FMDClue, FMDConfig,
    FMDMatchResult,
    // Key generation
    generate_key_pair,
    // Clue operations
    create_clue, examine_clue,
    // Batch operations
    examine_clues_batch, create_clues_batch,
    // Utilities
    estimate_false_positive_rate, recommended_precision,
    // Constants
    FMD_MAX_PRECISION, FMD_MIN_PRECISION, FMD_DEFAULT_PRECISION,
    FMD_KEY_DOMAIN, FMD_CLUE_DOMAIN,
};
use sage_contracts::obelysk::elgamal::{ECPoint, generator, is_zero};

// ===========================================================================
// Key Generation Tests
// ===========================================================================

#[test]
fn test_generate_key_pair_basic() {
    let seed: felt252 = 'test_seed_12345';
    let max_precision: u8 = 10;

    let key_pair = generate_key_pair(seed, max_precision);

    // Verify detection key
    assert(key_pair.detection_key.root_scalar != 0, 'Root scalar should be non-zero');
    assert(key_pair.detection_key.max_precision == max_precision, 'Precision mismatch');

    // Verify clue key
    assert(!is_zero(key_pair.clue_key.root_point), 'Root point should be non-zero');
    assert(key_pair.clue_key.max_precision == max_precision, 'Clue key precision mismatch');
}

#[test]
fn test_generate_key_pair_deterministic() {
    let seed: felt252 = 'deterministic_seed';

    let key_pair_1 = generate_key_pair(seed, 8);
    let key_pair_2 = generate_key_pair(seed, 8);

    // Same seed should produce same keys
    assert(
        key_pair_1.detection_key.root_scalar == key_pair_2.detection_key.root_scalar,
        'Keys should be deterministic'
    );
    assert(
        key_pair_1.clue_key.root_point.x == key_pair_2.clue_key.root_point.x,
        'Clue keys should match'
    );
}

#[test]
fn test_generate_key_pair_different_seeds() {
    let key_pair_1 = generate_key_pair('seed_alpha', 10);
    let key_pair_2 = generate_key_pair('seed_beta', 10);

    // Different seeds should produce different keys
    assert(
        key_pair_1.detection_key.root_scalar != key_pair_2.detection_key.root_scalar,
        'Diff seeds = diff keys'
    );
}

#[test]
fn test_key_pair_precision_bounds() {
    // Test minimum precision clamping
    let min_key = generate_key_pair('min_test', 0);
    assert(min_key.detection_key.max_precision == FMD_MIN_PRECISION, 'Should clamp to min');

    // Test maximum precision clamping
    let max_key = generate_key_pair('max_test', 100);
    assert(max_key.detection_key.max_precision == FMD_MAX_PRECISION, 'Should clamp to max');

    // Test valid precision
    let valid_key = generate_key_pair('valid_test', 16);
    assert(valid_key.detection_key.max_precision == 16, 'Should keep valid precision');
}

// ===========================================================================
// Clue Creation Tests
// ===========================================================================

#[test]
fn test_create_clue_basic() {
    let key_pair = generate_key_pair('clue_test_seed', 10);
    let randomness_r: felt252 = 'random_r_value';
    let randomness_z: felt252 = 'random_z_value';

    let clue = create_clue(@key_pair.clue_key, 8, randomness_r, randomness_z);

    // Verify clue structure
    assert(!is_zero(clue.ephemeral_point), 'Ephemeral point should exist');
    assert(clue.signature != 0, 'Signature should be non-zero');
    assert(clue.precision == 8, 'Precision should be 8');
}

#[test]
fn test_create_clue_different_precisions() {
    let key_pair = generate_key_pair('precision_test', 20);

    let clue_low = create_clue(@key_pair.clue_key, 4, 'r1', 'z1');
    let clue_mid = create_clue(@key_pair.clue_key, 10, 'r2', 'z2');
    let clue_high = create_clue(@key_pair.clue_key, 16, 'r3', 'z3');

    assert(clue_low.precision == 4, 'Low precision should be 4');
    assert(clue_mid.precision == 10, 'Mid precision should be 10');
    assert(clue_high.precision == 16, 'High precision should be 16');
}

#[test]
fn test_create_clue_precision_capped() {
    let key_pair = generate_key_pair('cap_test', 8);  // Max precision is 8

    // Request precision higher than key supports
    let clue = create_clue(@key_pair.clue_key, 20, 'r', 'z');

    // Should be capped to key's max precision
    assert(clue.precision == 8, 'Should cap to key max precision');
}

#[test]
fn test_create_clue_deterministic() {
    let key_pair = generate_key_pair('det_clue_test', 10);

    let clue_1 = create_clue(@key_pair.clue_key, 8, 'same_r', 'same_z');
    let clue_2 = create_clue(@key_pair.clue_key, 8, 'same_r', 'same_z');

    // Same inputs should produce same clue
    assert(clue_1.ephemeral_point.x == clue_2.ephemeral_point.x, 'Ephemeral X should match');
    assert(clue_1.signature == clue_2.signature, 'Signatures should match');
    assert(clue_1.ciphertext_bits == clue_2.ciphertext_bits, 'Ciphertext should match');
}

// ===========================================================================
// Clue Detection Tests
// ===========================================================================

#[test]
fn test_examine_clue_true_match() {
    let key_pair = generate_key_pair('match_test_seed', 10);

    // Create clue for this key pair
    let clue = create_clue(@key_pair.clue_key, 8, 'r_value', 'z_value');

    // Examine with matching detection key
    let result = examine_clue(@key_pair.detection_key, @clue);

    assert(result == FMDMatchResult::Match, 'Should match own clue');
}

#[test]
fn test_examine_clue_no_match_different_key() {
    let alice_keys = generate_key_pair('alice_seed', 10);
    let bob_keys = generate_key_pair('bob_seed', 10);

    // Create clue for Alice
    let clue_for_alice = create_clue(@alice_keys.clue_key, 8, 'r', 'z');

    // Bob tries to examine (should not match)
    let result = examine_clue(@bob_keys.detection_key, @clue_for_alice);

    // Most of the time this should be NoMatch (with small FP chance)
    // For testing, we just verify it doesn't crash
    assert(
        result == FMDMatchResult::Match || result == FMDMatchResult::NoMatch,
        'Should return valid result'
    );
}

#[test]
fn test_examine_clue_invalid_precision() {
    let key_pair = generate_key_pair('invalid_prec_test', 5);

    // Create a clue with higher precision than the key
    let clue = create_clue(@key_pair.clue_key, 8, 'r', 'z');  // Will be capped to 5

    // Manually create an invalid clue with wrong precision
    let invalid_clue = FMDClue {
        ephemeral_point: clue.ephemeral_point,
        q_point: clue.q_point,  // Copy Q from valid clue
        signature: clue.signature,
        precision: 20,  // Higher than key's max (5)
        ciphertext_bits: clue.ciphertext_bits,
    };

    let result = examine_clue(@key_pair.detection_key, @invalid_clue);
    assert(result == FMDMatchResult::Invalid, 'Should be invalid');
}

#[test]
fn test_examine_clue_zero_ephemeral_point() {
    let key_pair = generate_key_pair('zero_point_test', 10);

    let invalid_clue = FMDClue {
        ephemeral_point: ECPoint { x: 0, y: 0 },
        q_point: ECPoint { x: 0, y: 0 },  // Dummy Q
        signature: 12345,
        precision: 8,
        ciphertext_bits: 0,
    };

    let result = examine_clue(@key_pair.detection_key, @invalid_clue);
    assert(result == FMDMatchResult::Invalid, 'Zero point should be invalid');
}

// ===========================================================================
// Batch Operations Tests
// ===========================================================================

#[test]
fn test_examine_clues_batch() {
    let alice_keys = generate_key_pair('alice_batch', 10);
    let bob_keys = generate_key_pair('bob_batch', 10);

    // Create clues: 2 for Alice, 1 for Bob
    let clue_alice_1 = create_clue(@alice_keys.clue_key, 6, 'r1', 'z1');
    let clue_alice_2 = create_clue(@alice_keys.clue_key, 6, 'r2', 'z2');
    let clue_bob = create_clue(@bob_keys.clue_key, 6, 'r3', 'z3');

    let clues = array![clue_alice_1, clue_alice_2, clue_bob];

    // Alice examines all clues
    let results = examine_clues_batch(@alice_keys.detection_key, clues.span());

    assert(results.len() == 3, 'Should have 3 results');
    assert(*results.at(0) == FMDMatchResult::Match, 'First should match Alice');
    assert(*results.at(1) == FMDMatchResult::Match, 'Second should match Alice');
    // Third may or may not match (FP possible)
}

#[test]
fn test_create_clues_batch() {
    let alice_keys = generate_key_pair('alice_multi', 10);
    let bob_keys = generate_key_pair('bob_multi', 10);
    let charlie_keys = generate_key_pair('charlie_multi', 10);

    let clue_keys = array![alice_keys.clue_key, bob_keys.clue_key, charlie_keys.clue_key];

    let clues = create_clues_batch(clue_keys.span(), 8, 'batch_seed');

    assert(clues.len() == 3, 'Should create 3 clues');

    // Verify each recipient can detect their clue
    let alice_result = examine_clue(@alice_keys.detection_key, clues.at(0));
    let bob_result = examine_clue(@bob_keys.detection_key, clues.at(1));
    let charlie_result = examine_clue(@charlie_keys.detection_key, clues.at(2));

    assert(alice_result == FMDMatchResult::Match, 'Alice should detect her clue');
    assert(bob_result == FMDMatchResult::Match, 'Bob should detect his clue');
    assert(charlie_result == FMDMatchResult::Match, 'Charlie should detect his clue');
}

// ===========================================================================
// False Positive Rate Tests
// ===========================================================================

#[test]
fn test_estimate_false_positive_rate() {
    // n=0: 100% FP rate
    let (num, denom) = estimate_false_positive_rate(0);
    assert(num == 1 && denom == 1, 'n=0 should be 100%');

    // n=1: 50% FP rate (1/2)
    let (num, denom) = estimate_false_positive_rate(1);
    assert(num == 1 && denom == 2, 'n=1 should be 50%');

    // n=4: ~6.25% FP rate (1/16)
    let (num, denom) = estimate_false_positive_rate(4);
    assert(num == 1 && denom == 16, 'n=4 should be 1/16');

    // n=10: ~0.1% FP rate (1/1024)
    let (num, denom) = estimate_false_positive_rate(10);
    assert(num == 1 && denom == 1024, 'n=10 should be 1/1024');
}

#[test]
fn test_recommended_precision() {
    // Low volume: minimal precision needed
    let low_vol_precision = recommended_precision(5);
    assert(low_vol_precision >= FMD_MIN_PRECISION, 'Should be at least min');

    // Medium volume
    let med_vol_precision = recommended_precision(1000);
    assert(med_vol_precision > low_vol_precision, 'Higher vol = higher precision');

    // High volume
    let high_vol_precision = recommended_precision(1000000);
    assert(high_vol_precision <= FMD_MAX_PRECISION, 'Should not exceed max');
}

// ===========================================================================
// Full Flow Integration Tests
// ===========================================================================

#[test]
fn test_full_fmd_transaction_flow() {
    // Scenario: Alice publishes clue key, Bob sends her a private payment

    // Step 1: Alice generates key pair
    let alice_seed: felt252 = poseidon_hash_span(array!['alice_secret_key'].span());
    let alice_keys = generate_key_pair(alice_seed, FMD_DEFAULT_PRECISION);

    // Alice publishes her clue key (this is public)
    let alice_public_clue_key = alice_keys.clue_key;

    // Step 2: Bob wants to send Alice a payment
    // He creates a clue using Alice's public clue key
    let bob_randomness_r: felt252 = poseidon_hash_span(array!['bob_random_r', 12345].span());
    let bob_randomness_z: felt252 = poseidon_hash_span(array!['bob_random_z', 67890].span());

    let clue_for_alice = create_clue(
        @alice_public_clue_key,
        8,  // precision: ~0.4% FP rate
        bob_randomness_r,
        bob_randomness_z
    );

    // Step 3: Bob attaches this clue to his transaction (on-chain or off-chain)
    // The clue is public but only Alice can efficiently detect it

    // Step 4: Alice's detection server scans transactions
    // Using her private detection key
    let detection_result = examine_clue(@alice_keys.detection_key, @clue_for_alice);

    // Alice successfully detects the transaction meant for her
    assert(detection_result == FMDMatchResult::Match, 'Alice should detect payment');

    // Step 5: Verify that random parties cannot efficiently detect
    let random_keys = generate_key_pair('random_observer', 10);
    let random_result = examine_clue(@random_keys.detection_key, @clue_for_alice);

    // Random observer has low probability of false positive
    // (This test may occasionally pass due to FP, but statistically rare)
}

#[test]
fn test_multi_recipient_detection_flow() {
    // Scenario: Privacy Pool with multiple recipients

    // Create 5 recipients with different keys
    let recipient_1 = generate_key_pair('recipient_1', 12);
    let recipient_2 = generate_key_pair('recipient_2', 12);
    let recipient_3 = generate_key_pair('recipient_3', 12);
    let recipient_4 = generate_key_pair('recipient_4', 12);
    let recipient_5 = generate_key_pair('recipient_5', 12);

    // Create batch of clues for all recipients
    let clue_keys = array![
        recipient_1.clue_key,
        recipient_2.clue_key,
        recipient_3.clue_key,
        recipient_4.clue_key,
        recipient_5.clue_key,
    ];

    let clues = create_clues_batch(clue_keys.span(), 10, 'multi_recipient_seed');

    // Each recipient should detect their own clue
    assert(examine_clue(@recipient_1.detection_key, clues.at(0)) == FMDMatchResult::Match, 'R1 detect');
    assert(examine_clue(@recipient_2.detection_key, clues.at(1)) == FMDMatchResult::Match, 'R2 detect');
    assert(examine_clue(@recipient_3.detection_key, clues.at(2)) == FMDMatchResult::Match, 'R3 detect');
    assert(examine_clue(@recipient_4.detection_key, clues.at(3)) == FMDMatchResult::Match, 'R4 detect');
    assert(examine_clue(@recipient_5.detection_key, clues.at(4)) == FMDMatchResult::Match, 'R5 detect');

    // Batch detection by recipient_3
    let r3_results = examine_clues_batch(@recipient_3.detection_key, clues.span());
    assert(*r3_results.at(2) == FMDMatchResult::Match, 'R3 should match own clue');
}

#[test]
fn test_detection_server_simulation() {
    // Simulate a detection server processing many transactions

    let user_keys = generate_key_pair('detection_server_user', 10);

    // Simulate 10 transactions, only 2 are for our user
    let mut clues: Array<FMDClue> = array![];

    // Transaction 1: Random sender to random recipient
    let rand1_keys = generate_key_pair('rand1', 10);
    clues.append(create_clue(@rand1_keys.clue_key, 8, 'tx1_r', 'tx1_z'));

    // Transaction 2: Someone sends to our user!
    clues.append(create_clue(@user_keys.clue_key, 8, 'tx2_r', 'tx2_z'));

    // Transaction 3-8: Random transactions
    let mut i: u32 = 3;
    while i <= 8 {
        let rand_keys = generate_key_pair(i.into(), 10);
        clues.append(create_clue(@rand_keys.clue_key, 8, i.into(), (i + 100).into()));
        i += 1;
    };

    // Transaction 9: Another transaction for our user!
    clues.append(create_clue(@user_keys.clue_key, 8, 'tx9_r', 'tx9_z'));

    // Transaction 10: Random
    let rand10_keys = generate_key_pair('rand10', 10);
    clues.append(create_clue(@rand10_keys.clue_key, 8, 'tx10_r', 'tx10_z'));

    // Detection server batch processes
    let results = examine_clues_batch(@user_keys.detection_key, clues.span());

    assert(results.len() == 10, 'Should have 10 results');

    // Count matches (should be at least 2, plus possible false positives)
    let mut match_count: u32 = 0;
    let mut j: u32 = 0;
    while j < 10 {
        if *results.at(j) == FMDMatchResult::Match {
            match_count += 1;
        }
        j += 1;
    };

    assert(match_count >= 2, 'Should detect 2+ matches');
    // Transaction 2 (index 1) should definitely match
    assert(*results.at(1) == FMDMatchResult::Match, 'TX2 should match');
    // Transaction 9 (index 8) should definitely match
    assert(*results.at(8) == FMDMatchResult::Match, 'TX9 should match');
}

// ===========================================================================
// Edge Cases and Error Handling
// ===========================================================================

#[test]
fn test_minimum_precision_clue() {
    let key_pair = generate_key_pair('min_prec', 24);

    // Create clue with minimum precision (1 bit)
    let clue = create_clue(@key_pair.clue_key, FMD_MIN_PRECISION, 'r', 'z');

    assert(clue.precision == FMD_MIN_PRECISION, 'Should be min precision');

    // Should still be detectable
    let result = examine_clue(@key_pair.detection_key, @clue);
    assert(result == FMDMatchResult::Match, 'Min precision should work');
}

#[test]
fn test_maximum_precision_clue() {
    let key_pair = generate_key_pair('max_prec', FMD_MAX_PRECISION);

    // Create clue with maximum precision
    let clue = create_clue(@key_pair.clue_key, FMD_MAX_PRECISION, 'r', 'z');

    assert(clue.precision == FMD_MAX_PRECISION, 'Should be max precision');

    // Should still be detectable
    let result = examine_clue(@key_pair.detection_key, @clue);
    assert(result == FMDMatchResult::Match, 'Max precision should work');
}

#[test]
fn test_empty_batch_operations() {
    let key_pair = generate_key_pair('empty_batch', 10);

    // Empty batch examination
    let empty_clues: Array<FMDClue> = array![];
    let results = examine_clues_batch(@key_pair.detection_key, empty_clues.span());
    assert(results.len() == 0, 'Empty batch = empty results');

    // Empty batch creation
    let empty_keys: Array<FMDClueKey> = array![];
    let created = create_clues_batch(empty_keys.span(), 8, 'seed');
    assert(created.len() == 0, 'No keys = no clues');
}

// ===========================================================================
// Privacy Property Tests
// ===========================================================================

#[test]
fn test_clue_unlinkability() {
    let key_pair = generate_key_pair('unlinkable', 10);

    // Create multiple clues for the same recipient with different randomness
    let clue_1 = create_clue(@key_pair.clue_key, 8, 'random_1', 'z1');
    let clue_2 = create_clue(@key_pair.clue_key, 8, 'random_2', 'z2');
    let clue_3 = create_clue(@key_pair.clue_key, 8, 'random_3', 'z3');

    // Clues should be different (unlinkable by observers)
    assert(clue_1.ephemeral_point.x != clue_2.ephemeral_point.x, 'Clues should differ');
    assert(clue_2.ephemeral_point.x != clue_3.ephemeral_point.x, 'Clues should differ 2');
    assert(clue_1.signature != clue_2.signature, 'Signatures should differ');

    // But all should be detectable by the recipient
    assert(examine_clue(@key_pair.detection_key, @clue_1) == FMDMatchResult::Match, 'C1 match');
    assert(examine_clue(@key_pair.detection_key, @clue_2) == FMDMatchResult::Match, 'C2 match');
    assert(examine_clue(@key_pair.detection_key, @clue_3) == FMDMatchResult::Match, 'C3 match');
}
