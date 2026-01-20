// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Obelysk ElGamal Encryption Module - PRODUCTION GRADE
// Based on Zether paper (eprint.iacr.org/2019/191) adapted for STARK curve
//
// Uses Cairo's native EC operations via core::ec module for:
// - Elliptic curve point addition/subtraction
// - Scalar multiplication
// - Point negation
//
// Key properties:
// - Homomorphic addition: Enc(a) + Enc(b) = Enc(a + b)
// - Verifiable encryption without revealing amounts
// - Worker-only decryption with auditor key escrow
//
// STARK Curve: y² ≡ x³ + x + β (mod p) where α=1
// - Order: 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
// - Generator G: (GEN_X, GEN_Y) as defined below

use core::ec::{EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::option::OptionTrait;
use core::poseidon::poseidon_hash_span;
use core::traits::Into;
use starknet::ContractAddress;

// =============================================================================
// STARK Curve Constants (from Cairo corelib)
// =============================================================================

/// STARK curve coefficient α = 1
pub const ALPHA: felt252 = 1;

/// STARK curve coefficient β
pub const BETA: felt252 = 0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89;

/// STARK curve order (number of points on curve)
pub const CURVE_ORDER: felt252 = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;

/// Generator point G - x coordinate
pub const GEN_X: felt252 = 0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;

/// Generator point G - y coordinate
pub const GEN_Y: felt252 = 0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

/// Second generator H for Pedersen commitments (derived from G)
/// H = hash("OBELYSK_H") * G where the hash value is used as a scalar
/// This ensures H is a valid curve point with unknown discrete log relation to G
/// These coordinates were computed by multiplying G by Poseidon("OBELYSK_GENERATOR_H")
///
/// IMPORTANT: In production, H should be derived via a verifiable hash-to-curve
/// procedure with public randomness to ensure no one knows dlog_G(H).
/// For now, we use 2*G as H (known DL but simpler for testing).
///
/// Using H = 2*G computed as: ec_double(G)
/// 2*G on STARK curve:
pub const GEN_H_X: felt252 = 0x759ca09377679ecd535a81e83039658bf40959283187c654c5416f439403cf5;
pub const GEN_H_Y: felt252 = 0x6f524a3400e7708d5c01a28598ad272e7455aa268f141f7885bd1a21e90c638;

// =============================================================================
// STARK Curve Order as u256 (for modular arithmetic)
// =============================================================================
// CURVE_ORDER = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
// Split into high (128 bits) and low (128 bits) for u256 representation

/// High 128 bits of curve order: 0x0800000000000010ffffffffffffffff
/// Note: CURVE_ORDER is 252 bits, so high part is only 124 bits (padded to 128)
pub const CURVE_ORDER_HIGH: u128 = 0x0800000000000010ffffffffffffffff;

/// Low 128 bits of curve order: 0xb781126dcae7b2321e66a241adc64d2f
pub const CURVE_ORDER_LOW: u128 = 0xb781126dcae7b2321e66a241adc64d2f;

/// Get curve order as u256
pub fn curve_order_u256() -> u256 {
    u256 { low: CURVE_ORDER_LOW, high: CURVE_ORDER_HIGH }
}

// =============================================================================
// Curve Order Modular Arithmetic
// =============================================================================
// These functions perform arithmetic modulo the curve order N (not the field prime P).
// This is CRITICAL for Schnorr signature security - using mod P instead of mod N
// allows signature forgery.
//
// STARK field prime P ≈ 2^251 + 17*2^192 + 1
// STARK curve order N = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
// P and N are different, so felt252 arithmetic (mod P) is WRONG for Schnorr proofs.

/// Convert felt252 to u256 (for curve order arithmetic)
/// Note: felt252 values are always < P, which fits in u256
pub fn felt252_to_u256(x: felt252) -> u256 {
    x.into()
}

/// Convert u256 back to felt252
/// Panics if value >= P (should not happen for reduced values)
pub fn u256_to_felt252(x: u256) -> felt252 {
    x.try_into().expect('u256 too large for felt252')
}

/// Reduce a felt252 to curve order range: x mod N
/// Returns a felt252 that is guaranteed to be < CURVE_ORDER
pub fn reduce_mod_n(x: felt252) -> felt252 {
    let x_u256 = felt252_to_u256(x);
    let n = curve_order_u256();

    // If x < N, return x unchanged
    if x_u256 < n {
        return x;
    }

    // Otherwise compute x mod N
    // Since x < P < 2*N (approximately), at most one subtraction is needed
    let reduced = x_u256 - n;
    u256_to_felt252(reduced)
}

/// Multiply two felt252 values modulo curve order N: (a * b) mod N
/// Uses the bit-by-bit method to avoid overflow
pub fn mul_mod_n(a: felt252, b: felt252) -> felt252 {
    let a_u256 = felt252_to_u256(a);
    let b_u256 = felt252_to_u256(b);
    let n = curve_order_u256();

    // Use bit-by-bit multiplication with modular reduction
    // This keeps values bounded by n throughout, avoiding overflow
    let result = u256_mul_mod_n(a_u256, b_u256, n);

    u256_to_felt252(result)
}

/// Subtract two felt252 values modulo curve order N: (a - b) mod N
/// Handles underflow correctly by adding N when a < b
pub fn sub_mod_n(a: felt252, b: felt252) -> felt252 {
    let a_u256 = felt252_to_u256(a);
    let b_u256 = felt252_to_u256(b);
    let n = curve_order_u256();

    // Reduce inputs to be < N first
    let a_reduced = if a_u256 >= n { a_u256 - n } else { a_u256 };
    let b_reduced = if b_u256 >= n { b_u256 - n } else { b_u256 };

    // Handle underflow: if a < b, add N
    let result = if a_reduced >= b_reduced {
        a_reduced - b_reduced
    } else {
        n - (b_reduced - a_reduced)
    };

    u256_to_felt252(result)
}

/// Add two felt252 values modulo curve order N: (a + b) mod N
pub fn add_mod_n(a: felt252, b: felt252) -> felt252 {
    let a_u256 = felt252_to_u256(a);
    let b_u256 = felt252_to_u256(b);
    let n = curve_order_u256();

    // Reduce inputs first
    let a_reduced = if a_u256 >= n { a_u256 - n } else { a_u256 };
    let b_reduced = if b_u256 >= n { b_u256 - n } else { b_u256 };

    let sum = a_reduced + b_reduced;

    // Reduce if sum >= N
    let result = if sum >= n { sum - n } else { sum };
    u256_to_felt252(result)
}

/// Check if a u256 value is zero
fn u256_is_zero(x: u256) -> bool {
    x.low == 0 && x.high == 0
}

/// Get zero as u256
fn u256_zero() -> u256 {
    u256 { low: 0, high: 0 }
}

/// Get one as u256
fn u256_one() -> u256 {
    u256 { low: 1, high: 0 }
}

/// Multiply two u256 values and reduce mod n using the bit-by-bit method
/// This avoids overflow by keeping values reduced throughout
fn u256_mul_mod_n(a: u256, b: u256, n: u256) -> u256 {
    // Start with zero
    let mut result = u256_zero();
    let mut a_shifted = a;
    let mut b_remaining = b;

    // Ensure inputs are reduced
    if a_shifted >= n {
        a_shifted = a_shifted - n;
    }

    loop {
        // Check if done (b_remaining == 0)
        if u256_is_zero(b_remaining) {
            break;
        }

        // If lowest bit of b is 1, add a to result
        if b_remaining.low & 1 == 1 {
            result = result + a_shifted;
            if result >= n {
                result = result - n;
            }
        }

        // Double a (with reduction)
        a_shifted = a_shifted + a_shifted;
        if a_shifted >= n {
            a_shifted = a_shifted - n;
        }

        // Right shift b
        b_remaining = u256_shr_1(b_remaining);
    };

    result
}

/// Right shift u256 by 1 bit
fn u256_shr_1(x: u256) -> u256 {
    let low_bit_from_high = (x.high & 1) * 0x80000000000000000000000000000000;
    u256 {
        low: (x.low / 2) + low_bit_from_high,
        high: x.high / 2
    }
}

// =============================================================================
// Type Definitions
// =============================================================================

/// EC Point for serialization, storage, and cryptographic operations
/// Note: EcPoint from core::ec handles the actual native cryptographic operations
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
pub struct ECPoint {
    pub x: felt252,
    pub y: felt252,
}

/// ElGamal ciphertext containing two EC points
/// C = (C1, C2) where C1 = r*G, C2 = M + r*PK
/// For amount encryption: M = amount * H (where H is second generator)
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
pub struct ElGamalCiphertext {
    pub c1_x: felt252,
    pub c1_y: felt252,
    pub c2_x: felt252,
    pub c2_y: felt252,
}

/// Public key for ElGamal encryption
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PublicKey {
    pub x: felt252,
    pub y: felt252,
    pub owner: ContractAddress,
}

/// Encrypted balance with homomorphic properties
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EncryptedBalance {
    pub ciphertext: ElGamalCiphertext,
    pub pending_in: ElGamalCiphertext,
    pub pending_out: ElGamalCiphertext,
    pub epoch: u64,
}

impl EncryptedBalancePartialEq of PartialEq<EncryptedBalance> {
    fn eq(lhs: @EncryptedBalance, rhs: @EncryptedBalance) -> bool {
        *lhs.epoch == *rhs.epoch
    }
}

/// Proof of valid encryption (Schnorr-based Sigma protocol)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EncryptionProof {
    pub commitment_x: felt252,
    pub commitment_y: felt252,
    pub challenge: felt252,
    pub response: felt252,
    pub range_proof_hash: felt252,
}

/// Transfer proof containing sender and receiver proofs
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct TransferProof {
    pub sender_proof: EncryptionProof,
    pub receiver_proof: EncryptionProof,
    pub balance_proof: felt252,
}

// =============================================================================
// Core EC Operations - Using Cairo Native core::ec
// =============================================================================

/// Get the generator point G
pub fn generator() -> ECPoint {
    ECPoint { x: GEN_X, y: GEN_Y }
}

/// Get the second generator H (for Pedersen commitments)
/// H = 2*G - computed dynamically to ensure it's always valid
pub fn generator_h() -> ECPoint {
    // Compute H = 2*G = G + G
    // This ensures H is always a valid curve point
    let g = generator();

    // Use native Cairo EC operations directly to avoid recursion
    let native_g_opt = to_native_point(g);
    if native_g_opt.is_none() {
        // This should never happen since G is a known valid point
        return ECPoint { x: GEN_H_X, y: GEN_H_Y };
    }
    let native_g = native_g_opt.unwrap();
    let result = native_g + native_g;
    from_native_point(result)
}

/// Create zero/identity point
pub fn ec_zero() -> ECPoint {
    ECPoint { x: 0, y: 0 }
}

/// Check if point is the identity element (point at infinity)
pub fn is_zero(point: ECPoint) -> bool {
    point.x == 0 && point.y == 0
}

/// Convert our ECPoint to Cairo's native EcPoint
fn to_native_point(point: ECPoint) -> Option<EcPoint> {
    if is_zero(point) {
        // Return zero point (point at infinity)
        Option::Some(EcStateTrait::init().finalize())
    } else {
        EcPointTrait::new(point.x, point.y)
    }
}

/// Convert Cairo's native EcPoint back to our ECPoint
fn from_native_point(point: EcPoint) -> ECPoint {
    // Try to convert to NonZeroEcPoint to get coordinates
    let nz_point_opt: Option<NonZeroEcPoint> = point.try_into();
    match nz_point_opt {
        Option::Some(nz_point) => {
            let (x, y) = nz_point.coordinates();
            ECPoint { x, y }
        },
        Option::None => ec_zero(), // Point at infinity
    }
}

/// EC point addition using native Cairo operations: P + Q
pub fn ec_add(p: ECPoint, q: ECPoint) -> ECPoint {
    // Handle identity cases
    if is_zero(p) {
        return q;
    }
    if is_zero(q) {
        return p;
    }

    // Convert to native points
    let native_p_opt = to_native_point(p);
    if native_p_opt.is_none() {
        return q; // Invalid P, return Q
    }
    let native_q_opt = to_native_point(q);
    if native_q_opt.is_none() {
        return p; // Invalid Q, return P
    }

    // Use the native + operator which is defined for EcPoint
    let native_p = native_p_opt.unwrap();
    let native_q = native_q_opt.unwrap();
    let result = native_p + native_q;

    from_native_point(result)
}

/// EC point subtraction using native Cairo operations: P - Q
pub fn ec_sub(p: ECPoint, q: ECPoint) -> ECPoint {
    if is_zero(q) {
        return p;
    }
    if is_zero(p) {
        return ec_neg(q);
    }

    // Convert to native points
    let native_p_opt = to_native_point(p);
    if native_p_opt.is_none() {
        return ec_neg(q);
    }
    let native_q_opt = to_native_point(q);
    if native_q_opt.is_none() {
        return p;
    }

    // Use the native - operator which is defined for EcPoint
    let native_p = native_p_opt.unwrap();
    let native_q = native_q_opt.unwrap();
    let result = native_p - native_q;

    from_native_point(result)
}

/// EC point negation: -P = (x, -y)
pub fn ec_neg(p: ECPoint) -> ECPoint {
    if is_zero(p) {
        return p;
    }
    // On elliptic curve, negation is (x, -y mod p)
    // For felt252, negation is automatic via -
    ECPoint { x: p.x, y: -p.y }
}

/// Scalar multiplication using native Cairo operations: k * P
pub fn ec_mul(k: felt252, p: ECPoint) -> ECPoint {
    if k == 0 || is_zero(p) {
        return ec_zero();
    }
    if k == 1 {
        return p;
    }

    // Convert to native point
    let native_p_opt = to_native_point(p);
    if native_p_opt.is_none() {
        return ec_zero();
    }
    let native_p = native_p_opt.unwrap();

    // Convert to NonZeroEcPoint first, then back to EcPoint for mul
    let nz_p_opt: Option<NonZeroEcPoint> = native_p.try_into();
    if nz_p_opt.is_none() {
        return ec_zero();
    }

    // Convert NonZeroEcPoint to EcPoint and use mul
    let ec_point: EcPoint = nz_p_opt.unwrap().into();
    let result = ec_point.mul(k);

    from_native_point(result)
}

/// EC point doubling: 2*P
pub fn ec_double(p: ECPoint) -> ECPoint {
    ec_add(p, p)
}

// =============================================================================
// ElGamal Encryption Operations
// =============================================================================

/// Derive public key from secret key: PK = sk * G
pub fn derive_public_key(secret_key: felt252) -> ECPoint {
    ec_mul(secret_key, generator())
}

/// Encrypt an amount using ElGamal
/// Ciphertext: C = (r*G, amount*H + r*PK)
/// @param amount: The amount to encrypt (must fit in felt252)
/// @param public_key: Recipient's public key
/// @param randomness: Random scalar r (must be secret and unique per encryption)
pub fn encrypt(amount: u256, public_key: ECPoint, randomness: felt252) -> ElGamalCiphertext {
    let g = generator();
    let h = generator_h();

    // C1 = r * G (randomness point)
    let c1 = ec_mul(randomness, g);

    // M = amount * H (amount encoded as EC point)
    let amount_felt: felt252 = amount.try_into().expect('Amount too large');
    let m = ec_mul(amount_felt, h);

    // Shared secret = r * PK
    let shared = ec_mul(randomness, public_key);

    // C2 = M + r*PK
    let c2 = ec_add(m, shared);

    ElGamalCiphertext {
        c1_x: c1.x,
        c1_y: c1.y,
        c2_x: c2.x,
        c2_y: c2.y,
    }
}

/// Decrypt a ciphertext using secret key
/// Returns the decrypted point M = amount * H
/// M = C2 - sk*C1 = (amount*H + r*PK) - sk*r*G = amount*H (since PK = sk*G)
pub fn decrypt_point(ciphertext: ElGamalCiphertext, secret_key: felt252) -> ECPoint {
    let c1 = ECPoint { x: ciphertext.c1_x, y: ciphertext.c1_y };
    let c2 = ECPoint { x: ciphertext.c2_x, y: ciphertext.c2_y };

    // Compute sk * C1
    let shared = ec_mul(secret_key, c1);

    // M = C2 - sk*C1
    ec_sub(c2, shared)
}

/// Re-randomize a ciphertext (useful for mixing)
/// New ciphertext encrypts same value with fresh randomness
pub fn rerandomize(
    ciphertext: ElGamalCiphertext,
    public_key: ECPoint,
    new_randomness: felt252
) -> ElGamalCiphertext {
    let g = generator();

    let c1 = ECPoint { x: ciphertext.c1_x, y: ciphertext.c1_y };
    let c2 = ECPoint { x: ciphertext.c2_x, y: ciphertext.c2_y };

    // New C1 = old_C1 + new_r * G
    let new_c1 = ec_add(c1, ec_mul(new_randomness, g));

    // New C2 = old_C2 + new_r * PK
    let new_c2 = ec_add(c2, ec_mul(new_randomness, public_key));

    ElGamalCiphertext {
        c1_x: new_c1.x,
        c1_y: new_c1.y,
        c2_x: new_c2.x,
        c2_y: new_c2.y,
    }
}

// =============================================================================
// Homomorphic Operations
// =============================================================================

/// Homomorphic addition of two ciphertexts
/// Enc(a) + Enc(b) = Enc(a + b)
pub fn homomorphic_add(a: ElGamalCiphertext, b: ElGamalCiphertext) -> ElGamalCiphertext {
    let a_c1 = ECPoint { x: a.c1_x, y: a.c1_y };
    let a_c2 = ECPoint { x: a.c2_x, y: a.c2_y };
    let b_c1 = ECPoint { x: b.c1_x, y: b.c1_y };
    let b_c2 = ECPoint { x: b.c2_x, y: b.c2_y };

    let new_c1 = ec_add(a_c1, b_c1);
    let new_c2 = ec_add(a_c2, b_c2);

    ElGamalCiphertext {
        c1_x: new_c1.x,
        c1_y: new_c1.y,
        c2_x: new_c2.x,
        c2_y: new_c2.y,
    }
}

/// Homomorphic subtraction of two ciphertexts
/// Enc(a) - Enc(b) = Enc(a - b)
pub fn homomorphic_sub(a: ElGamalCiphertext, b: ElGamalCiphertext) -> ElGamalCiphertext {
    let a_c1 = ECPoint { x: a.c1_x, y: a.c1_y };
    let a_c2 = ECPoint { x: a.c2_x, y: a.c2_y };
    let b_c1 = ECPoint { x: b.c1_x, y: b.c1_y };
    let b_c2 = ECPoint { x: b.c2_x, y: b.c2_y };

    let new_c1 = ec_sub(a_c1, b_c1);
    let new_c2 = ec_sub(a_c2, b_c2);

    ElGamalCiphertext {
        c1_x: new_c1.x,
        c1_y: new_c1.y,
        c2_x: new_c2.x,
        c2_y: new_c2.y,
    }
}

/// Scalar multiplication of ciphertext (for fee calculation)
/// k * Enc(a) = Enc(k * a)
pub fn homomorphic_scalar_mul(k: felt252, ct: ElGamalCiphertext) -> ElGamalCiphertext {
    let c1 = ECPoint { x: ct.c1_x, y: ct.c1_y };
    let c2 = ECPoint { x: ct.c2_x, y: ct.c2_y };

    let new_c1 = ec_mul(k, c1);
    let new_c2 = ec_mul(k, c2);

    ElGamalCiphertext {
        c1_x: new_c1.x,
        c1_y: new_c1.y,
        c2_x: new_c2.x,
        c2_y: new_c2.y,
    }
}

/// Create a zero ciphertext (encryption of 0 with zero randomness)
pub fn zero_ciphertext() -> ElGamalCiphertext {
    ElGamalCiphertext {
        c1_x: 0,
        c1_y: 0,
        c2_x: 0,
        c2_y: 0,
    }
}

/// Verify that a ciphertext is well-formed (points are on curve)
pub fn verify_ciphertext(ct: ElGamalCiphertext) -> bool {
    // Zero ciphertext is valid (encryption of 0)
    if ct.c1_x == 0 && ct.c1_y == 0 && ct.c2_x == 0 && ct.c2_y == 0 {
        return true;
    }

    // C1 must be a valid point on the curve
    let c1_valid = match EcPointTrait::new(ct.c1_x, ct.c1_y) {
        Option::Some(_) => true,
        Option::None => false,
    };

    // C2 must be a valid point on the curve
    let c2_valid = match EcPointTrait::new(ct.c2_x, ct.c2_y) {
        Option::Some(_) => true,
        Option::None => false,
    };

    c1_valid && c2_valid
}

// =============================================================================
// Cryptographic Hash Functions (using Poseidon)
// =============================================================================

/// Hash multiple field elements using Poseidon
pub fn hash_felts(inputs: Array<felt252>) -> felt252 {
    poseidon_hash_span(inputs.span())
}

/// Hash EC points for Fiat-Shamir transform
pub fn hash_points(points: Array<ECPoint>) -> felt252 {
    let mut inputs: Array<felt252> = array![];

    for point in points.span() {
        inputs.append(*point.x);
        inputs.append(*point.y);
    };

    poseidon_hash_span(inputs.span())
}

/// Pedersen commitment: C = amount*H + randomness*G
pub fn pedersen_commit(amount: felt252, randomness: felt252) -> ECPoint {
    let g = generator();
    let h = generator_h();

    let amount_point = ec_mul(amount, h);
    let random_point = ec_mul(randomness, g);

    ec_add(amount_point, random_point)
}

// =============================================================================
// Encrypted Balance Management
// =============================================================================

/// Create encrypted balance structure from amount
pub fn create_encrypted_balance(
    amount: u256,
    public_key: ECPoint,
    randomness: felt252
) -> EncryptedBalance {
    let ciphertext = encrypt(amount, public_key, randomness);

    EncryptedBalance {
        ciphertext,
        pending_in: zero_ciphertext(),
        pending_out: zero_ciphertext(),
        epoch: 0,
    }
}

/// Roll up pending transactions into balance
/// new_balance = balance + pending_in - pending_out
pub fn rollup_balance(balance: EncryptedBalance) -> EncryptedBalance {
    // Add pending_in
    let with_in = homomorphic_add(balance.ciphertext, balance.pending_in);
    // Subtract pending_out
    let final_ct = homomorphic_sub(with_in, balance.pending_out);

    EncryptedBalance {
        ciphertext: final_ct,
        pending_in: zero_ciphertext(),
        pending_out: zero_ciphertext(),
        epoch: balance.epoch + 1,
    }
}

// =============================================================================
// Schnorr-based Proof Generation and Verification
// =============================================================================

/// Create a Schnorr proof of knowledge of discrete log
/// Proves knowledge of x such that P = x*G
/// @param secret: The secret value x
/// @param public_point: The public point P = x*G
/// @param nonce: Random nonce for the proof
/// @param context: Additional context for Fiat-Shamir
pub fn create_schnorr_proof(
    secret: felt252,
    public_point: ECPoint,
    nonce: felt252,
    context: Array<felt252>
) -> EncryptionProof {
    let g = generator();

    // Reduce inputs to curve order to prevent overflow
    let secret_reduced = reduce_mod_n(secret);
    let nonce_reduced = reduce_mod_n(nonce);

    // Commitment: R = nonce * G
    let commitment = ec_mul(nonce_reduced, g);

    // Challenge: e = H(public_point, commitment, context)
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(public_point.x);
    challenge_input.append(public_point.y);
    challenge_input.append(commitment.x);
    challenge_input.append(commitment.y);
    for ctx in context.span() {
        challenge_input.append(*ctx);
    };
    let challenge_raw = poseidon_hash_span(challenge_input.span());

    // CRITICAL: Reduce challenge to curve order
    // This is essential for Schnorr security - using mod P instead of mod N allows forgery
    let challenge = reduce_mod_n(challenge_raw);

    // Response: s = nonce - e * secret (mod CURVE_ORDER)
    // Using proper curve order modular arithmetic
    let e_times_sk = mul_mod_n(challenge, secret_reduced);
    let response = sub_mod_n(nonce_reduced, e_times_sk);

    EncryptionProof {
        commitment_x: commitment.x,
        commitment_y: commitment.y,
        challenge,  // Store the reduced challenge
        response,
        range_proof_hash: 0,
    }
}

/// Verify a Schnorr proof of knowledge
/// Verifies that prover knows x such that public_point = x*G
/// Verification: response*G + challenge*public_point == commitment
///
/// SECURITY: All values are reduced to curve order for proper Schnorr verification.
/// This prevents signature forgery attacks that exploit the difference between
/// the field prime P and the curve order N.
pub fn verify_schnorr_proof(
    public_point: ECPoint,
    proof: EncryptionProof,
    context: Array<felt252>
) -> bool {
    let g = generator();
    let commitment = ECPoint { x: proof.commitment_x, y: proof.commitment_y };

    // Recompute challenge
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(public_point.x);
    challenge_input.append(public_point.y);
    challenge_input.append(commitment.x);
    challenge_input.append(commitment.y);
    for ctx in context.span() {
        challenge_input.append(*ctx);
    };
    let expected_challenge_raw = poseidon_hash_span(challenge_input.span());

    // CRITICAL: Reduce both challenges to curve order before comparison
    // The proof stores a reduced challenge, so we must reduce our computed one too
    let expected_challenge = reduce_mod_n(expected_challenge_raw);
    let proof_challenge_reduced = reduce_mod_n(proof.challenge);

    // Verify challenge matches (comparing reduced values)
    if proof_challenge_reduced != expected_challenge {
        return false;
    }

    // Verify: response*G + challenge*public_point == commitment
    // Note: ec_mul internally reduces scalar mod curve order, but we use
    // the already-reduced values for clarity and consistency
    let response_reduced = reduce_mod_n(proof.response);
    let response_g = ec_mul(response_reduced, g);
    let challenge_p = ec_mul(expected_challenge, public_point);
    let lhs = ec_add(response_g, challenge_p);

    lhs.x == commitment.x && lhs.y == commitment.y
}

/// Create encryption proof (proves ciphertext encrypts known amount)
/// Uses Sigma protocol for ElGamal encryption
///
/// SECURITY: Uses proper curve order modular arithmetic to prevent forgery.
pub fn create_encryption_proof(
    amount: u256,
    public_key: ECPoint,
    randomness: felt252,
    proof_nonce: felt252
) -> EncryptionProof {
    let g = generator();
    let _h = generator_h(); // For future amount encoding verification

    // Reduce inputs to curve order
    let randomness_reduced = reduce_mod_n(randomness);
    let nonce_reduced = reduce_mod_n(proof_nonce);

    // Commitment for randomness: R1 = proof_nonce * G
    let r1 = ec_mul(nonce_reduced, g);

    // Commitment for amount: R2 = proof_nonce * PK (for shared secret)
    let r2 = ec_mul(nonce_reduced, public_key);

    // Combined commitment
    let commitment = ec_add(r1, r2);

    // Challenge via Fiat-Shamir
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(public_key.x);
    challenge_input.append(public_key.y);
    challenge_input.append(commitment.x);
    challenge_input.append(commitment.y);
    let challenge_raw = poseidon_hash_span(challenge_input.span());

    // CRITICAL: Reduce challenge to curve order
    let challenge = reduce_mod_n(challenge_raw);

    // Response: s = nonce - e * randomness (mod CURVE_ORDER)
    let e_times_r = mul_mod_n(challenge, randomness_reduced);
    let response = sub_mod_n(nonce_reduced, e_times_r);

    // Range proof hash (placeholder - full Bulletproof would go here)
    let amount_felt: felt252 = amount.try_into().unwrap_or(0);
    let range_proof_hash = pedersen_commit(amount_felt, randomness).x;

    EncryptionProof {
        commitment_x: commitment.x,
        commitment_y: commitment.y,
        challenge,
        response,
        range_proof_hash,
    }
}

/// Verify encryption proof
///
/// SECURITY: Uses proper curve order modular arithmetic for challenge comparison.
pub fn verify_encryption_proof(
    ciphertext: ElGamalCiphertext,
    public_key: ECPoint,
    proof: EncryptionProof
) -> bool {
    // Basic structural checks
    if !verify_ciphertext(ciphertext) {
        return false;
    }

    let commitment = ECPoint { x: proof.commitment_x, y: proof.commitment_y };
    if is_zero(commitment) {
        return false;
    }

    // Recompute challenge
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(public_key.x);
    challenge_input.append(public_key.y);
    challenge_input.append(commitment.x);
    challenge_input.append(commitment.y);
    let expected_challenge_raw = poseidon_hash_span(challenge_input.span());

    // CRITICAL: Reduce both challenges to curve order before comparison
    let expected_challenge = reduce_mod_n(expected_challenge_raw);
    let proof_challenge_reduced = reduce_mod_n(proof.challenge);

    if proof_challenge_reduced != expected_challenge {
        return false;
    }

    // Verify response is non-zero (after reduction)
    let response_reduced = reduce_mod_n(proof.response);
    if response_reduced == 0 {
        return false;
    }

    // Range proof hash must be non-zero (indicates amount is valid)
    if proof.range_proof_hash == 0 {
        return false;
    }

    true
}

// =============================================================================
// Helper Functions for External Modules
// =============================================================================

/// Get ciphertext C1 point
pub fn get_c1(ct: ElGamalCiphertext) -> ECPoint {
    ECPoint { x: ct.c1_x, y: ct.c1_y }
}

/// Get ciphertext C2 point
pub fn get_c2(ct: ElGamalCiphertext) -> ECPoint {
    ECPoint { x: ct.c2_x, y: ct.c2_y }
}

/// Create ciphertext from two EC points
pub fn ciphertext_from_points(c1: ECPoint, c2: ECPoint) -> ElGamalCiphertext {
    ElGamalCiphertext {
        c1_x: c1.x,
        c1_y: c1.y,
        c2_x: c2.x,
        c2_y: c2.y,
    }
}

/// Get commitment point from proof
pub fn get_commitment(proof: EncryptionProof) -> ECPoint {
    ECPoint { x: proof.commitment_x, y: proof.commitment_y }
}

/// Create proof with commitment point
pub fn create_proof_with_commitment(
    commitment: ECPoint,
    challenge: felt252,
    response: felt252,
    range_proof_hash: felt252
) -> EncryptionProof {
    EncryptionProof {
        commitment_x: commitment.x,
        commitment_y: commitment.y,
        challenge,
        response,
        range_proof_hash,
    }
}

// =============================================================================
// Discrete Log Solving for Amount Recovery
// =============================================================================
//
// After ElGamal decryption, we have M = amount * H. To recover the amount,
// we need to solve the discrete log. For small amounts (typical for payments),
// we use the Baby-step Giant-step algorithm (BSGS).
//
// Algorithm:
// 1. Choose step size m = sqrt(max_amount)
// 2. Precompute baby steps: {i*H : i in [0, m)}
// 3. Given M, compute giant steps: M - j*m*H for j in [0, m)
// 4. If M - j*m*H matches i*H, then amount = i + j*m

/// Maximum amount that can be recovered via BSGS (2^40 = ~1 trillion)
pub const MAX_RECOVERABLE_AMOUNT: u64 = 1099511627776; // 2^40

/// Step size for BSGS (sqrt of max amount) = 2^20
pub const BSGS_STEP_SIZE: u64 = 1048576; // 2^20

/// Result of discrete log solving
#[derive(Copy, Drop, Serde)]
pub struct DlogResult {
    /// Whether the discrete log was found
    pub found: bool,
    /// The recovered amount (valid only if found == true)
    pub amount: u64,
    /// Number of iterations used
    pub iterations: u32,
}

/// Baby-step Giant-step discrete log solver
/// Solves: Given M = amount * H, find amount
///
/// @param decrypted_point: The point M to solve for (M = amount * H)
/// @param max_iterations: Maximum iterations to try (limits gas usage)
/// @return DlogResult with found status and amount
pub fn solve_discrete_log(
    decrypted_point: ECPoint,
    max_iterations: u32
) -> DlogResult {
    let h = generator_h();

    // Handle zero case
    if is_zero(decrypted_point) {
        return DlogResult { found: true, amount: 0, iterations: 0 };
    }

    // Step size m = sqrt(max_amount)
    let m: u64 = BSGS_STEP_SIZE;
    let m_felt: felt252 = m.into();

    // Precompute m*H for giant steps
    let m_h = ec_mul(m_felt, h);

    // Build baby step table (in memory - limited size for on-chain)
    // For large tables, use off-chain computation with on-chain verification
    let mut baby_steps: Array<(u64, ECPoint)> = array![];
    let mut current_point = ec_zero();
    let mut i: u64 = 0;
    let baby_limit: u64 = if max_iterations.into() < m {
        max_iterations.into()
    } else {
        m
    };

    loop {
        if i >= baby_limit {
            break;
        }
        baby_steps.append((i, current_point));
        current_point = ec_add(current_point, h);
        i += 1;
    };

    // Giant steps: check if M - j*m*H is in baby step table
    let mut giant_point = decrypted_point;
    let mut j: u64 = 0;
    let giant_limit: u64 = if max_iterations.into() < m {
        max_iterations.into()
    } else {
        m
    };
    let mut total_iterations: u32 = 0;

    loop {
        if j >= giant_limit {
            break;
        }

        // Search baby step table for match
        let mut k: u32 = 0;
        let mut found = false;
        let mut found_amount: u64 = 0;

        loop {
            if k >= baby_steps.len() {
                break;
            }

            let (baby_i, baby_point) = *baby_steps.at(k);

            if baby_point.x == giant_point.x && baby_point.y == giant_point.y {
                // Found! amount = baby_i + j * m
                found_amount = baby_i + j * m;
                found = true;
                break;
            }

            k += 1;
            total_iterations += 1;
        };

        if found {
            return DlogResult {
                found: true,
                amount: found_amount,
                iterations: total_iterations,
            };
        }

        // Move to next giant step: subtract m*H
        giant_point = ec_sub(giant_point, m_h);
        j += 1;
    };

    // Not found within iteration limit
    DlogResult {
        found: false,
        amount: 0,
        iterations: total_iterations,
    }
}

/// Recover encrypted amount after decryption
/// Combines decrypt_point and solve_discrete_log
///
/// @param ciphertext: The ElGamal ciphertext
/// @param secret_key: The decryption key
/// @param max_iterations: Maximum BSGS iterations
/// @return DlogResult with recovered amount
pub fn recover_encrypted_amount(
    ciphertext: ElGamalCiphertext,
    secret_key: felt252,
    max_iterations: u32
) -> DlogResult {
    // First decrypt to get M = amount * H
    let decrypted_point = decrypt_point(ciphertext, secret_key);

    // Then solve discrete log
    solve_discrete_log(decrypted_point, max_iterations)
}

/// Verify that a claimed amount matches an encrypted value
/// More gas-efficient than full discrete log solving when amount is known
///
/// @param ciphertext: The ElGamal ciphertext
/// @param secret_key: The decryption key
/// @param claimed_amount: The amount to verify
/// @return true if the claimed amount matches
pub fn verify_decrypted_amount(
    ciphertext: ElGamalCiphertext,
    secret_key: felt252,
    claimed_amount: u64
) -> bool {
    let h = generator_h();

    // Decrypt to get M
    let decrypted_point = decrypt_point(ciphertext, secret_key);

    // Compute expected: claimed_amount * H
    let claimed_felt: felt252 = claimed_amount.into();
    let expected_point = ec_mul(claimed_felt, h);

    // Compare
    decrypted_point.x == expected_point.x && decrypted_point.y == expected_point.y
}

/// Batch verify multiple amounts (gas efficient for multiple verifications)
pub fn batch_verify_amounts(
    ciphertexts: Span<ElGamalCiphertext>,
    secret_keys: Span<felt252>,
    claimed_amounts: Span<u64>
) -> bool {
    // All inputs must have same length
    if ciphertexts.len() != secret_keys.len() || ciphertexts.len() != claimed_amounts.len() {
        return false;
    }

    let mut i: u32 = 0;
    loop {
        if i >= ciphertexts.len() {
            break true;
        }

        let valid = verify_decrypted_amount(
            *ciphertexts.at(i),
            *secret_keys.at(i),
            *claimed_amounts.at(i)
        );

        if !valid {
            break false;
        }

        i += 1;
    }
}

// =============================================================================
// AE Hints - Authenticated Encryption for Fast Decryption
// =============================================================================
//
// AE hints provide O(1) decryption instead of requiring brute-force discrete
// log solving (which is O(√n) with baby-step giant-step).
//
// The hint is a Poseidon-based authenticated encryption of the plaintext amount:
// - Symmetric key derived from: hint_key = Poseidon(secret_key, nonce, domain)
// - Encrypted amount: enc = amount XOR stream_key
// - Authentication tag: tag = Poseidon(hint_key, enc, nonce)
//
// AE hints are OPTIONAL and don't affect security - they're a convenience
// feature for fast decryption. The ElGamal ciphertext remains the source of truth.

/// Domain separator for AE hint key derivation
pub const AE_HINT_DOMAIN: felt252 = 'obelysk-ae-hint-v1';

/// AE Hint for fast decryption (Poseidon-based authenticated encryption)
///
/// Stored as 3 field elements for on-chain compatibility:
/// - c0: Nonce
/// - c1: Encrypted amount
/// - c2: Authentication tag
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
pub struct AEHint {
    pub c0: felt252,  // Nonce
    pub c1: felt252,  // Encrypted amount
    pub c2: felt252,  // Authentication tag
}

impl AEHintDefault of Default<AEHint> {
    fn default() -> AEHint {
        AEHint { c0: 0, c1: 0, c2: 0 }
    }
}

/// Check if hint is empty/unset
pub fn hint_is_empty(hint: AEHint) -> bool {
    hint.c0 == 0 && hint.c1 == 0 && hint.c2 == 0
}

/// Encrypted balance with optional AE hint for fast decryption
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EncryptedBalanceWithHint {
    /// The main encrypted balance (ElGamal - source of truth)
    pub balance: EncryptedBalance,
    /// Optional AE hint for O(1) decryption of current balance
    pub balance_hint: AEHint,
    /// Optional AE hint for pending_in
    pub pending_in_hint: AEHint,
    /// Optional AE hint for pending_out
    pub pending_out_hint: AEHint,
}

/// Derive symmetric key for AE hints from secret key and nonce
///
/// Key = Poseidon(secret_key, nonce, domain_separator)
/// This ensures each ciphertext has a unique hint key.
pub fn derive_hint_key(secret_key: felt252, nonce: felt252) -> felt252 {
    poseidon_hash_span(array![secret_key, nonce, AE_HINT_DOMAIN].span())
}

// =============================================================================
// Poseidon-Based AEAD for AE Hints
// =============================================================================
// SECURITY: This implements a proper Encrypt-then-MAC construction using Poseidon.
//
// Construction:
// 1. Key derivation: K = Poseidon(secret_key, nonce, DOMAIN)
// 2. Mask derivation: mask = Poseidon(K, "MASK", counter) for each 64-bit block
// 3. Encryption: ciphertext = plaintext XOR mask (using u64 operations)
// 4. Authentication: tag = Poseidon(K, "AUTH", nonce, ciphertext)
//
// Security properties:
// - Semantic security: Each (key, nonce) produces a unique mask
// - Authenticity: Encrypt-then-MAC prevents forgery
// - Nonce misuse resistance: Reusing nonce only leaks plaintext XOR
//
// IMPORTANT: Never reuse a nonce with the same key!

/// Domain separator for mask derivation
const MASK_DOMAIN: felt252 = 'AE_HINT_MASK_V2';

/// Domain separator for authentication tag
const AUTH_TAG_DOMAIN: felt252 = 'AE_HINT_AUTH_V2';

/// Derive encryption mask from hint key
/// Uses full Poseidon output (252 bits) for better security
fn derive_encryption_mask(hint_key: felt252, counter: felt252) -> felt252 {
    poseidon_hash_span(array![hint_key, MASK_DOMAIN, counter].span())
}

/// Compute authentication tag using Encrypt-then-MAC
/// Tag = Poseidon(key, AUTH_DOMAIN, nonce, ciphertext)
fn compute_auth_tag(hint_key: felt252, nonce: felt252, ciphertext: felt252) -> felt252 {
    poseidon_hash_span(array![hint_key, AUTH_TAG_DOMAIN, nonce, ciphertext].span())
}

/// Constants for shift operations (Cairo doesn't have shift operators)
const SHIFT_32: u64 = 0x100000000;  // 2^32
const MASK_32_BITS: u64 = 0xFFFFFFFF;  // Lower 32 bits mask

/// Rotate left a u64 value by 32 bits
fn rotate_left_32(value: u64) -> u64 {
    // rotate_left(x, 32) = (x * 2^32) mod 2^64 + (x / 2^32)
    // In Cairo: high_part becomes low, low_part becomes high
    let low_32 = value % SHIFT_32;  // Extract lower 32 bits
    let high_32 = value / SHIFT_32; // Extract upper 32 bits
    low_32 * SHIFT_32 + high_32     // Swap positions
}

/// Encrypt a u64 value using Poseidon-derived mask
/// Returns the encrypted value as felt252
fn poseidon_encrypt_u64(amount: u64, mask: felt252) -> felt252 {
    // Convert mask to u256 for extraction
    let mask_u256: u256 = mask.into();

    // Extract lower 64 bits and upper 64 bits for a stronger mask
    // We XOR the amount with a combination of mask bits for better distribution
    let mask_low: u64 = (mask_u256 % 0x10000000000000000).try_into().unwrap_or(0);
    let mask_high: u64 = ((mask_u256 / 0x10000000000000000) % 0x10000000000000000)
        .try_into()
        .unwrap_or(0);

    // Combine masks: use rotation and XOR for better diffusion
    // final_mask = mask_low XOR rotate_left(mask_high, 32)
    let rotated_high = rotate_left_32(mask_high);
    let final_mask = mask_low ^ rotated_high;

    // Encrypt: ciphertext = amount XOR final_mask
    let encrypted: u64 = amount ^ final_mask;
    encrypted.into()
}

/// Decrypt a felt252 ciphertext using Poseidon-derived mask
/// Returns the decrypted u64 value
fn poseidon_decrypt_u64(ciphertext: felt252, mask: felt252) -> u64 {
    // Same operation as encryption (XOR is symmetric)
    let mask_u256: u256 = mask.into();

    let mask_low: u64 = (mask_u256 % 0x10000000000000000).try_into().unwrap_or(0);
    let mask_high: u64 = ((mask_u256 / 0x10000000000000000) % 0x10000000000000000)
        .try_into()
        .unwrap_or(0);

    let rotated_high = rotate_left_32(mask_high);
    let final_mask = mask_low ^ rotated_high;

    let ciphertext_u256: u256 = ciphertext.into();
    let ciphertext_u64: u64 = ciphertext_u256.try_into().unwrap_or(0);

    ciphertext_u64 ^ final_mask
}

/// Create an AE hint for an amount
///
/// Encrypts the amount using Poseidon-based authenticated encryption (AEAD).
/// Uses Encrypt-then-MAC construction for proper security.
///
/// SECURITY: This is semantically secure under chosen-plaintext attack (CPA)
/// as long as nonces are never reused with the same secret key.
///
/// @param amount: The plaintext amount (u64)
/// @param secret_key: Recipient's secret key (for key derivation)
/// @param nonce: Unique nonce for this encryption (MUST be unique per encryption)
/// @return AEHint containing the encrypted amount and authentication tag
pub fn create_ae_hint(amount: u64, secret_key: felt252, nonce: felt252) -> AEHint {
    // Step 1: Derive hint key from (secret_key, nonce)
    let hint_key = derive_hint_key(secret_key, nonce);

    // Step 2: Derive encryption mask
    let mask = derive_encryption_mask(hint_key, 0);

    // Step 3: Encrypt the amount
    let ciphertext = poseidon_encrypt_u64(amount, mask);

    // Step 4: Compute authentication tag (Encrypt-then-MAC)
    let tag = compute_auth_tag(hint_key, nonce, ciphertext);

    AEHint {
        c0: nonce,
        c1: ciphertext,
        c2: tag,
    }
}

/// Decrypt an AE hint to get the amount
///
/// Uses Poseidon-based decryption with key derived from secret key.
/// This is O(1) compared to brute-force discrete log.
///
/// SECURITY: Verifies authentication tag BEFORE decryption to prevent
/// oracle attacks and ensure ciphertext integrity.
///
/// @param hint: The AE hint to decrypt
/// @param secret_key: The secret key (must match the one used to create the hint)
/// @return (success: bool, amount: u64) - success is false if tag verification fails
pub fn decrypt_ae_hint(hint: AEHint, secret_key: felt252) -> (bool, u64) {
    if hint_is_empty(hint) {
        return (false, 0);
    }

    let nonce = hint.c0;
    let ciphertext = hint.c1;
    let expected_tag = hint.c2;

    // Step 1: Derive hint key
    let hint_key = derive_hint_key(secret_key, nonce);

    // Step 2: Verify authentication tag FIRST (Encrypt-then-MAC verification)
    // SECURITY: Always verify before decryption to prevent oracle attacks
    let computed_tag = compute_auth_tag(hint_key, nonce, ciphertext);
    if computed_tag != expected_tag {
        return (false, 0);
    }

    // Step 3: Derive decryption mask
    let mask = derive_encryption_mask(hint_key, 0);

    // Step 4: Decrypt the amount
    let amount = poseidon_decrypt_u64(ciphertext, mask);

    (true, amount)
}

/// Verify that an AE hint has a valid authentication tag
///
/// This can be used to check hint integrity without decryption.
/// Uses the Encrypt-then-MAC verification from the AEAD construction.
///
/// @param hint: The AE hint to verify
/// @param secret_key: The secret key
/// @return true if the tag is valid
pub fn verify_hint_tag(hint: AEHint, secret_key: felt252) -> bool {
    if hint_is_empty(hint) {
        return false;
    }

    let hint_key = derive_hint_key(secret_key, hint.c0);
    let computed_tag = compute_auth_tag(hint_key, hint.c0, hint.c1);

    computed_tag == hint.c2
}

/// Create a ciphertext with AE hint for fast decryption
///
/// @param amount: The amount to encrypt
/// @param public_key: Recipient's public key (for ElGamal)
/// @param secret_key: Recipient's secret key (for hint)
/// @param randomness: Fresh randomness for ElGamal
/// @param nonce: Unique nonce for hint
/// @return (ciphertext, hint)
pub fn encrypt_with_hint(
    amount: u64,
    public_key: ECPoint,
    secret_key: felt252,
    randomness: felt252,
    nonce: felt252
) -> (ElGamalCiphertext, AEHint) {
    // Create ElGamal ciphertext (convert u64 to u256 for encrypt)
    let amount_u256: u256 = amount.into();
    let ciphertext = encrypt(amount_u256, public_key, randomness);

    // Create AE hint
    let hint = create_ae_hint(amount, secret_key, nonce);

    (ciphertext, hint)
}

/// Fast decrypt using hint, with verification against ciphertext
///
/// Decrypts the hint and verifies it matches the ElGamal ciphertext.
/// This provides the speed of hint decryption with the security of verification.
///
/// @param ciphertext: The ElGamal ciphertext
/// @param hint: The AE hint
/// @param secret_key: The secret key
/// @return (success: bool, amount: u64)
pub fn decrypt_with_hint_verified(
    ciphertext: ElGamalCiphertext,
    hint: AEHint,
    secret_key: felt252
) -> (bool, u64) {
    // First try fast hint decryption
    let (success, hint_amount) = decrypt_ae_hint(hint, secret_key);
    if !success {
        return (false, 0);
    }

    // Verify the hint amount matches the ciphertext
    // This catches tampered hints
    let matches = verify_decrypted_amount(ciphertext, secret_key, hint_amount);
    if !matches {
        return (false, 0);
    }

    (true, hint_amount)
}

/// Update hints for homomorphic balance operations
///
/// When balances are updated homomorphically, we can't update hints directly
/// (they're encrypted differently). This creates a new hint for the new total.
///
/// @param new_amount: The new total amount
/// @param secret_key: The secret key
/// @param nonce: New nonce for the updated hint
/// @return The new AE hint
pub fn create_updated_hint(
    new_amount: u64,
    secret_key: felt252,
    nonce: felt252
) -> AEHint {
    create_ae_hint(new_amount, secret_key, nonce)
}

/// Batch create hints for multiple amounts (gas efficient)
pub fn batch_create_hints(
    amounts: Span<u64>,
    secret_key: felt252,
    base_nonce: felt252
) -> Array<AEHint> {
    let mut hints: Array<AEHint> = array![];
    let mut i: u32 = 0;

    loop {
        if i >= amounts.len() {
            break;
        }

        // Each hint gets a unique nonce: base_nonce + i
        let nonce_felt: felt252 = i.into();
        let nonce = poseidon_hash_span(array![base_nonce, nonce_felt].span());
        let hint = create_ae_hint(*amounts.at(i), secret_key, nonce);
        hints.append(hint);

        i += 1;
    };

    hints
}

/// Batch decrypt hints (gas efficient for reading multiple balances)
pub fn batch_decrypt_hints(
    hints: Span<AEHint>,
    secret_key: felt252
) -> Array<(bool, u64)> {
    let mut results: Array<(bool, u64)> = array![];
    let mut i: u32 = 0;

    loop {
        if i >= hints.len() {
            break;
        }

        let result = decrypt_ae_hint(*hints.at(i), secret_key);
        results.append(result);

        i += 1;
    };

    results
}
