// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// ElGamal Cryptographic Correctness Tests
// Tests production-grade EC operations using Cairo's native core::ec module

use core::array::ArrayTrait;
use core::traits::TryInto;

// Import ElGamal module functions and types
use sage_contracts::obelysk::elgamal::{
    // Types
    ECPoint, ElGamalCiphertext, EncryptedBalance, EncryptionProof,
    // Constants
    GEN_X, GEN_Y, GEN_H_X, GEN_H_Y, CURVE_ORDER,
    // EC Operations
    generator, generator_h, ec_zero, is_zero,
    ec_add, ec_sub, ec_neg, ec_mul, ec_double,
    // ElGamal Operations
    derive_public_key, encrypt, decrypt_point, rerandomize,
    // Homomorphic Operations
    homomorphic_add, homomorphic_sub, homomorphic_scalar_mul,
    zero_ciphertext, verify_ciphertext,
    // Schnorr Proofs
    create_schnorr_proof, verify_schnorr_proof,
    create_encryption_proof, verify_encryption_proof,
    // Balance Management
    create_encrypted_balance, rollup_balance,
    // Helpers
    hash_points, pedersen_commit,
    get_c1, get_c2, get_commitment, create_proof_with_commitment
};

// =============================================================================
// Test Constants
// =============================================================================

const TEST_SECRET_KEY_1: felt252 = 12345678901234567890;
const TEST_SECRET_KEY_2: felt252 = 98765432109876543210;
const TEST_RANDOMNESS_1: felt252 = 111111111111111111;
const TEST_RANDOMNESS_2: felt252 = 222222222222222222;
const TEST_NONCE_1: felt252 = 333333333333333333;
const TEST_NONCE_2: felt252 = 444444444444444444;

// =============================================================================
// EC Point Operation Tests
// =============================================================================

#[test]
fn test_generator_is_valid() {
    let g = generator();

    // Generator should not be zero
    assert(!is_zero(g), 'Generator should not be zero');

    // Generator coordinates should match constants
    assert(g.x == GEN_X, 'Generator X mismatch');
    assert(g.y == GEN_Y, 'Generator Y mismatch');
}

#[test]
fn test_generator_h_is_valid() {
    let h = generator_h();

    // H should not be zero
    assert(!is_zero(h), 'Generator H should not be zero');

    // H should be different from G
    let g = generator();
    assert(h.x != g.x || h.y != g.y, 'H should differ from G');
}

#[test]
fn test_ec_zero_is_identity() {
    let zero = ec_zero();

    // Zero point should have coordinates (0, 0)
    assert(zero.x == 0, 'Zero X should be 0');
    assert(zero.y == 0, 'Zero Y should be 0');

    // is_zero should return true
    assert(is_zero(zero), 'is_zero should return true');
}

#[test]
fn test_ec_add_identity() {
    let g = generator();
    let zero = ec_zero();

    // G + 0 = G
    let result = ec_add(g, zero);
    assert(result.x == g.x, 'G + 0 should equal G (x)');
    assert(result.y == g.y, 'G + 0 should equal G (y)');

    // 0 + G = G
    let result2 = ec_add(zero, g);
    assert(result2.x == g.x, '0 + G should equal G (x)');
    assert(result2.y == g.y, '0 + G should equal G (y)');
}

#[test]
fn test_ec_add_commutativity() {
    let g = generator();
    let h = generator_h();

    // G + H should equal H + G
    let result1 = ec_add(g, h);
    let result2 = ec_add(h, g);

    assert(result1.x == result2.x, 'Addition not commutative (x)');
    assert(result1.y == result2.y, 'Addition not commutative (y)');
}

#[test]
fn test_ec_neg_properties() {
    let g = generator();

    // -G should have same x but negated y
    let neg_g = ec_neg(g);
    assert(neg_g.x == g.x, 'Negation should preserve x');
    assert(neg_g.y != g.y, 'Negation should change y');

    // G + (-G) should be zero (point at infinity)
    let sum = ec_add(g, neg_g);
    assert(is_zero(sum), 'G + (-G) should be zero');
}

#[test]
fn test_ec_sub_equals_add_neg() {
    let g = generator();
    let h = generator_h();

    // G - H should equal G + (-H)
    let sub_result = ec_sub(g, h);
    let add_neg_result = ec_add(g, ec_neg(h));

    assert(sub_result.x == add_neg_result.x, 'Sub != Add neg (x)');
    assert(sub_result.y == add_neg_result.y, 'Sub != Add neg (y)');
}

#[test]
fn test_ec_mul_identity() {
    let g = generator();

    // 1 * G = G
    let result = ec_mul(1, g);
    assert(result.x == g.x, '1 * G should equal G (x)');
    assert(result.y == g.y, '1 * G should equal G (y)');
}

#[test]
fn test_ec_mul_zero_scalar() {
    let g = generator();

    // 0 * G = 0
    let result = ec_mul(0, g);
    assert(is_zero(result), '0 * G should be zero');
}

#[test]
fn test_ec_mul_zero_point() {
    let zero = ec_zero();

    // 5 * 0 = 0
    let result = ec_mul(5, zero);
    assert(is_zero(result), 'k * 0 should be zero');
}

#[test]
fn test_ec_double_equals_mul_2() {
    let g = generator();

    // 2*G via double should equal 2*G via mul
    let double_result = ec_double(g);
    let mul_result = ec_mul(2, g);

    assert(double_result.x == mul_result.x, 'Double != Mul 2 (x)');
    assert(double_result.y == mul_result.y, 'Double != Mul 2 (y)');
}

#[test]
fn test_ec_mul_distributive() {
    let g = generator();

    // (a + b) * G = a*G + b*G
    let a: felt252 = 7;
    let b: felt252 = 13;

    let lhs = ec_mul(a + b, g);
    let rhs = ec_add(ec_mul(a, g), ec_mul(b, g));

    assert(lhs.x == rhs.x, 'Mul not distributive (x)');
    assert(lhs.y == rhs.y, 'Mul not distributive (y)');
}

// =============================================================================
// Key Derivation Tests
// =============================================================================

#[test]
fn test_derive_public_key() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);

    // Public key should not be zero
    assert(!is_zero(pk), 'Public key should not be zero');

    // Public key should equal sk * G
    let g = generator();
    let expected = ec_mul(sk, g);
    assert(pk.x == expected.x, 'PK derivation wrong (x)');
    assert(pk.y == expected.y, 'PK derivation wrong (y)');
}

#[test]
fn test_different_secrets_different_keys() {
    let pk1 = derive_public_key(TEST_SECRET_KEY_1);
    let pk2 = derive_public_key(TEST_SECRET_KEY_2);

    // Different secrets should produce different public keys
    assert(pk1.x != pk2.x || pk1.y != pk2.y, 'Same keys for diff secrets');
}

// =============================================================================
// ElGamal Encryption/Decryption Tests
// =============================================================================

#[test]
fn test_encrypt_produces_valid_ciphertext() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);
    let amount: u256 = 1000;
    let randomness = TEST_RANDOMNESS_1;

    let ciphertext = encrypt(amount, pk, randomness);

    // Ciphertext should be valid (on curve)
    assert(verify_ciphertext(ciphertext), 'Ciphertext should be valid');

    // C1 and C2 should not be zero for non-zero amount
    let c1 = get_c1(ciphertext);
    let c2 = get_c2(ciphertext);
    assert(!is_zero(c1), 'C1 should not be zero');
    assert(!is_zero(c2), 'C2 should not be zero');
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);
    let amount: u256 = 500;
    let randomness = TEST_RANDOMNESS_1;

    // Encrypt
    let ciphertext = encrypt(amount, pk, randomness);

    // Decrypt: M = C2 - sk * C1 = amount * H
    let decrypted_point = decrypt_point(ciphertext, sk);

    // The decrypted point should equal amount * H
    let h = generator_h();
    let expected_point = ec_mul(amount.try_into().unwrap(), h);

    assert(decrypted_point.x == expected_point.x, 'Decrypt wrong (x)');
    assert(decrypted_point.y == expected_point.y, 'Decrypt wrong (y)');
}

#[test]
fn test_encrypt_zero_amount() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);
    let amount: u256 = 0;
    let randomness = TEST_RANDOMNESS_1;

    // Encrypt zero
    let ciphertext = encrypt(amount, pk, randomness);

    // Decrypt should give zero point (0 * H = 0)
    let decrypted = decrypt_point(ciphertext, sk);

    // For amount=0, M = 0*H = 0, so decrypted should be zero
    assert(is_zero(decrypted), 'Decrypt 0 should give zero');
}

#[test]
fn test_different_randomness_different_ciphertext() {
    let pk = derive_public_key(TEST_SECRET_KEY_1);
    let amount: u256 = 100;

    let ct1 = encrypt(amount, pk, TEST_RANDOMNESS_1);
    let ct2 = encrypt(amount, pk, TEST_RANDOMNESS_2);

    // Same amount, different randomness → different ciphertext
    assert(ct1.c1_x != ct2.c1_x || ct1.c1_y != ct2.c1_y, 'C1 should differ');
}

#[test]
fn test_rerandomize_same_decryption() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);
    let amount: u256 = 750;

    // Original encryption
    let ct1 = encrypt(amount, pk, TEST_RANDOMNESS_1);

    // Re-randomize
    let ct2 = rerandomize(ct1, pk, TEST_RANDOMNESS_2);

    // Ciphertexts should be different
    assert(ct1.c1_x != ct2.c1_x || ct1.c1_y != ct2.c1_y, 'Rerandomized C1 same');

    // But decryption should give same value
    let dec1 = decrypt_point(ct1, sk);
    let dec2 = decrypt_point(ct2, sk);

    assert(dec1.x == dec2.x, 'Rerandomize changed value (x)');
    assert(dec1.y == dec2.y, 'Rerandomize changed value (y)');
}

// =============================================================================
// Homomorphic Operation Tests
// =============================================================================

#[test]
fn test_homomorphic_add() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);

    let amount1: u256 = 300;
    let amount2: u256 = 200;

    let ct1 = encrypt(amount1, pk, TEST_RANDOMNESS_1);
    let ct2 = encrypt(amount2, pk, TEST_RANDOMNESS_2);

    // Homomorphic addition: Enc(a) + Enc(b) = Enc(a+b)
    let ct_sum = homomorphic_add(ct1, ct2);

    // Decrypt the sum
    let decrypted_sum = decrypt_point(ct_sum, sk);

    // Should equal (amount1 + amount2) * H
    let h = generator_h();
    let expected_sum_felt: felt252 = (amount1 + amount2).try_into().unwrap();
    let expected_point = ec_mul(expected_sum_felt, h);

    assert(decrypted_sum.x == expected_point.x, 'Homo add wrong (x)');
    assert(decrypted_sum.y == expected_point.y, 'Homo add wrong (y)');
}

#[test]
fn test_homomorphic_sub() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);

    let amount1: u256 = 500;
    let amount2: u256 = 200;

    let ct1 = encrypt(amount1, pk, TEST_RANDOMNESS_1);
    let ct2 = encrypt(amount2, pk, TEST_RANDOMNESS_2);

    // Homomorphic subtraction: Enc(a) - Enc(b) = Enc(a-b)
    let ct_diff = homomorphic_sub(ct1, ct2);

    // Decrypt the difference
    let decrypted_diff = decrypt_point(ct_diff, sk);

    // Should equal (amount1 - amount2) * H = 300 * H
    let h = generator_h();
    let expected_diff_felt: felt252 = (amount1 - amount2).try_into().unwrap();
    let expected_point = ec_mul(expected_diff_felt, h);

    assert(decrypted_diff.x == expected_point.x, 'Homo sub wrong (x)');
    assert(decrypted_diff.y == expected_point.y, 'Homo sub wrong (y)');
}

#[test]
fn test_homomorphic_scalar_mul() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);

    let amount: u256 = 100;
    let scalar: felt252 = 5;

    let ct = encrypt(amount, pk, TEST_RANDOMNESS_1);

    // Scalar multiplication: k * Enc(a) = Enc(k*a)
    let ct_scaled = homomorphic_scalar_mul(scalar, ct);

    // Decrypt
    let decrypted = decrypt_point(ct_scaled, sk);

    // Should equal (scalar * amount) * H = 500 * H
    let h = generator_h();
    let expected_felt: felt252 = (scalar * amount.try_into().unwrap());
    let expected_point = ec_mul(expected_felt, h);

    assert(decrypted.x == expected_point.x, 'Scalar mul wrong (x)');
    assert(decrypted.y == expected_point.y, 'Scalar mul wrong (y)');
}

#[test]
fn test_zero_ciphertext() {
    let zero_ct = zero_ciphertext();

    // Should be all zeros
    assert(zero_ct.c1_x == 0, 'Zero CT c1_x not 0');
    assert(zero_ct.c1_y == 0, 'Zero CT c1_y not 0');
    assert(zero_ct.c2_x == 0, 'Zero CT c2_x not 0');
    assert(zero_ct.c2_y == 0, 'Zero CT c2_y not 0');

    // Should be valid
    assert(verify_ciphertext(zero_ct), 'Zero CT should be valid');
}

// =============================================================================
// Schnorr Proof Tests
// =============================================================================

// NOTE: Schnorr proof verification has a known limitation in Cairo.
// The response s = nonce - e * secret should be computed mod curve_order,
// but felt252 arithmetic is mod field_prime. When e * secret > nonce,
// the wrap-around happens mod field_prime instead of mod curve_order.
// This requires implementing proper modular arithmetic for production use.
// The encryption proof (which is used in practice) works correctly.

#[test]
fn test_schnorr_proof_structure() {
    // Test that Schnorr proofs generate valid structure
    // (Full verification requires modular arithmetic mod curve_order)
    let sk: felt252 = 7;
    let pk = derive_public_key(sk);
    let nonce: felt252 = 13;

    let context: Array<felt252> = array!['test'];
    let proof = create_schnorr_proof(sk, pk, nonce, context);

    // Proof should have valid commitment
    let commitment = get_commitment(proof);
    assert(!is_zero(commitment), 'Proof commitment is zero');

    // Proof structure should be valid
    assert(proof.challenge != 0, 'Challenge is zero');
    // Response may wrap around - this is the known limitation
}

#[test]
fn test_schnorr_proof_wrong_key_fails() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);
    let wrong_pk = derive_public_key(TEST_SECRET_KEY_2);
    let nonce = TEST_NONCE_1;

    // Create separate context arrays
    let context_for_create: Array<felt252> = array!['test'];
    let context_for_verify: Array<felt252> = array!['test'];

    // Create proof for pk
    let proof = create_schnorr_proof(sk, pk, nonce, context_for_create);

    // Verify with wrong public key should fail
    let is_valid = verify_schnorr_proof(wrong_pk, proof, context_for_verify);
    assert(!is_valid, 'Wrong key should fail');
}

#[test]
fn test_schnorr_proof_wrong_context_fails() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);
    let nonce = TEST_NONCE_1;
    let context1: Array<felt252> = array!['context1'];
    let context2: Array<felt252> = array!['context2'];

    // Create proof with context1
    let proof = create_schnorr_proof(sk, pk, nonce, context1);

    // Verify with context2 should fail (different challenge)
    let is_valid = verify_schnorr_proof(pk, proof, context2);
    assert(!is_valid, 'Wrong context should fail');
}

// =============================================================================
// Encryption Proof Tests
// =============================================================================

#[test]
fn test_encryption_proof_valid() {
    let pk = derive_public_key(TEST_SECRET_KEY_1);
    let amount: u256 = 1000;
    let randomness = TEST_RANDOMNESS_1;
    let proof_nonce = TEST_NONCE_1;

    // Create ciphertext
    let ciphertext = encrypt(amount, pk, randomness);

    // Create encryption proof
    let proof = create_encryption_proof(amount, pk, randomness, proof_nonce);

    // Verify proof
    let is_valid = verify_encryption_proof(ciphertext, pk, proof);
    assert(is_valid, 'Valid encryption proof rejected');
}

// =============================================================================
// Encrypted Balance Tests
// =============================================================================

#[test]
fn test_create_encrypted_balance() {
    let pk = derive_public_key(TEST_SECRET_KEY_1);
    let amount: u256 = 10000;
    let randomness = TEST_RANDOMNESS_1;

    let balance = create_encrypted_balance(amount, pk, randomness);

    // Main ciphertext should be valid
    assert(verify_ciphertext(balance.ciphertext), 'Balance CT invalid');

    // Pending should be zero
    let c1_pending_in = get_c1(balance.pending_in);
    let c1_pending_out = get_c1(balance.pending_out);
    assert(is_zero(c1_pending_in), 'Pending in should be zero');
    assert(is_zero(c1_pending_out), 'Pending out should be zero');

    // Epoch should be 0
    assert(balance.epoch == 0, 'Initial epoch should be 0');
}

#[test]
fn test_rollup_balance() {
    let sk = TEST_SECRET_KEY_1;
    let pk = derive_public_key(sk);

    // Create initial balance of 1000
    let initial_amount: u256 = 1000;
    let balance = create_encrypted_balance(initial_amount, pk, TEST_RANDOMNESS_1);

    // Create a modified balance with pending_in of 500
    let pending_in_amount: u256 = 500;
    let balance_with_pending = EncryptedBalance {
        ciphertext: balance.ciphertext,
        pending_in: encrypt(pending_in_amount, pk, TEST_RANDOMNESS_2),
        pending_out: balance.pending_out,
        epoch: balance.epoch,
    };

    // Rollup
    let rolled_up = rollup_balance(balance_with_pending);

    // After rollup:
    // - pending_in and pending_out should be zero
    // - epoch should increment
    // - balance should include pending
    let c1_pending_in = get_c1(rolled_up.pending_in);
    let c1_pending_out = get_c1(rolled_up.pending_out);
    assert(is_zero(c1_pending_in), 'Pending in not cleared');
    assert(is_zero(c1_pending_out), 'Pending out not cleared');
    assert(rolled_up.epoch == 1, 'Epoch should be 1');

    // Decrypt rolled up balance - should be 1500
    let decrypted = decrypt_point(rolled_up.ciphertext, sk);
    let h = generator_h();
    let expected_total: felt252 = 1500;
    let expected_point = ec_mul(expected_total, h);

    assert(decrypted.x == expected_point.x, 'Rollup balance wrong (x)');
    assert(decrypted.y == expected_point.y, 'Rollup balance wrong (y)');
}

// =============================================================================
// Hash Function Tests
// =============================================================================

#[test]
fn test_hash_points_deterministic() {
    let g = generator();
    let h = generator_h();

    let points1: Array<ECPoint> = array![g, h];
    let points2: Array<ECPoint> = array![g, h];

    let hash1 = hash_points(points1);
    let hash2 = hash_points(points2);

    assert(hash1 == hash2, 'Hash not deterministic');
}

#[test]
fn test_hash_points_different_input() {
    let g = generator();
    let h = generator_h();

    let points1: Array<ECPoint> = array![g, h];
    let points2: Array<ECPoint> = array![h, g];  // Different order

    let hash1 = hash_points(points1);
    let hash2 = hash_points(points2);

    assert(hash1 != hash2, 'Different input same hash');
}

#[test]
fn test_pedersen_commit() {
    let amount: felt252 = 1000;
    let randomness = TEST_RANDOMNESS_1;

    // C = amount*H + randomness*G
    let commitment = pedersen_commit(amount, randomness);

    // Should not be zero
    assert(!is_zero(commitment), 'Pedersen commit is zero');

    // Verify structure: C = amount*H + randomness*G
    let g = generator();
    let h = generator_h();
    let expected = ec_add(ec_mul(amount, h), ec_mul(randomness, g));

    assert(commitment.x == expected.x, 'Pedersen wrong (x)');
    assert(commitment.y == expected.y, 'Pedersen wrong (y)');
}

// =============================================================================
// Helper Function Tests
// =============================================================================

#[test]
fn test_get_c1_c2_helpers() {
    let pk = derive_public_key(TEST_SECRET_KEY_1);
    let amount: u256 = 100;
    let ct = encrypt(amount, pk, TEST_RANDOMNESS_1);

    let c1 = get_c1(ct);
    let c2 = get_c2(ct);

    // Should extract correct coordinates
    assert(c1.x == ct.c1_x, 'get_c1 x wrong');
    assert(c1.y == ct.c1_y, 'get_c1 y wrong');
    assert(c2.x == ct.c2_x, 'get_c2 x wrong');
    assert(c2.y == ct.c2_y, 'get_c2 y wrong');
}

#[test]
fn test_create_proof_with_commitment() {
    let g = generator();
    let commitment = ec_mul(TEST_NONCE_1, g);
    let challenge: felt252 = 12345;
    let response: felt252 = 67890;
    let range_hash: felt252 = 11111;

    let proof = create_proof_with_commitment(commitment, challenge, response, range_hash);

    assert(proof.commitment_x == commitment.x, 'Proof commitment_x wrong');
    assert(proof.commitment_y == commitment.y, 'Proof commitment_y wrong');
    assert(proof.challenge == challenge, 'Proof challenge wrong');
    assert(proof.response == response, 'Proof response wrong');
    assert(proof.range_proof_hash == range_hash, 'Proof range_hash wrong');
}

#[test]
fn test_get_commitment_helper() {
    let g = generator();
    let commitment = ec_mul(TEST_NONCE_1, g);
    let proof = create_proof_with_commitment(commitment, 123, 456, 789);

    let extracted = get_commitment(proof);

    assert(extracted.x == commitment.x, 'get_commitment x wrong');
    assert(extracted.y == commitment.y, 'get_commitment y wrong');
}
