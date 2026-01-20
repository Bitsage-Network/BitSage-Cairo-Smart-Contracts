// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Same Encryption Proofs - Prove Multiple Ciphertexts Encrypt Same Value
//
// Based on Tongo's SHE library (same-encryption.md)
//
// This module provides cryptographic proofs that two or more ElGamal ciphertexts
// encrypt the same value under different public keys. This is critical for:
//
// 1. Transfer integrity: Prove sender/receiver/auditor ciphertexts match
// 2. Multi-party encryption: Prove viewing keys encrypt correct amount
// 3. Compliance: Prove auditor ciphertext matches transfer amount
//
// KEY INSIGHT: Both proofs share the same sb response, which proves
// the same message b is encrypted without revealing b.
//
// Protocol (2-party):
//   Statement: Prove (L1, R1) and (L2, R2) encrypt same message b
//              for public keys y1 and y2
//
//   Prover (knows b, r1, r2):
//     1. Choose random kb, kr1, kr2
//     2. Compute AL1 = g^kb * y1^kr1, AR1 = g^kr1
//     3. Compute AL2 = g^kb * y2^kr2, AR2 = g^kr2
//     4. Challenge c = Hash(domain, AL1, AR1, AL2, AR2, L1, R1, L2, R2)
//     5. Responses: sb = kb + c*b (SHARED!), sr1 = kr1 + c*r1, sr2 = kr2 + c*r2
//
//   Verifier:
//     1. Recompute c
//     2. Check: g^sb * y1^sr1 == AL1 * L1^c AND g^sr1 == AR1 * R1^c
//     3. Check: g^sb * y2^sr2 == AL2 * L2^c AND g^sr2 == AR2 * R2^c
//     4. Same sb in both checks proves same message!

use core::poseidon::poseidon_hash_span;
use super::elgamal::{
    ECPoint, ElGamalCiphertext,
    ec_add, ec_mul, is_zero,
    generator, generator_h,
    reduce_mod_n, mul_mod_n, add_mod_n,
};

// =============================================================================
// Domain Separators
// =============================================================================

/// Domain separator for 2-party same encryption proofs
pub const SAME_ENC_2_DOMAIN: felt252 = 'obelysk-same-enc-2-v1';

/// Domain separator for 3-party same encryption proofs (sender/receiver/auditor)
pub const SAME_ENC_3_DOMAIN: felt252 = 'obelysk-same-enc-3-v1';

// =============================================================================
// Proof Structures
// =============================================================================

/// Proof that two ElGamal ciphertexts encrypt the same value
///
/// Used to prove sender and receiver (or any two parties) receive
/// encryptions of the same amount.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SameEncryptionProof {
    // Commitment for first ciphertext (AL1 = g^kb * y1^kr1)
    pub al1_x: felt252,
    pub al1_y: felt252,
    // Commitment for R1 (AR1 = g^kr1)
    pub ar1_x: felt252,
    pub ar1_y: felt252,
    // Commitment for second ciphertext (AL2 = g^kb * y2^kr2)
    pub al2_x: felt252,
    pub al2_y: felt252,
    // Commitment for R2 (AR2 = g^kr2)
    pub ar2_x: felt252,
    pub ar2_y: felt252,
    /// CRITICAL: Shared message response - proves same amount!
    /// sb = kb + c * b (mod n)
    pub sb: felt252,
    /// Randomness response for first ciphertext
    /// sr1 = kr1 + c * r1 (mod n)
    pub sr1: felt252,
    /// Randomness response for second ciphertext
    /// sr2 = kr2 + c * r2 (mod n)
    pub sr2: felt252,
}

/// Proof that THREE ElGamal ciphertexts encrypt the same value
///
/// Used for transfers where sender, receiver, AND auditor all receive
/// encryptions of the same amount.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SameEncryption3Proof {
    // Commitments for sender (party 1)
    pub al1_x: felt252,
    pub al1_y: felt252,
    pub ar1_x: felt252,
    pub ar1_y: felt252,
    // Commitments for receiver (party 2)
    pub al2_x: felt252,
    pub al2_y: felt252,
    pub ar2_x: felt252,
    pub ar2_y: felt252,
    // Commitments for auditor (party 3)
    pub al3_x: felt252,
    pub al3_y: felt252,
    pub ar3_x: felt252,
    pub ar3_y: felt252,
    /// CRITICAL: Shared message response - proves ALL THREE encrypt same amount!
    pub sb: felt252,
    /// Randomness responses for each party
    pub sr1: felt252,
    pub sr2: felt252,
    pub sr3: felt252,
}

/// Inputs for same encryption verification
#[derive(Copy, Drop, Serde)]
pub struct SameEncryptionInputs {
    /// First ciphertext (L1 = g^b * y1^r1, R1 = g^r1)
    pub ct1: ElGamalCiphertext,
    /// Second ciphertext (L2 = g^b * y2^r2, R2 = g^r2)
    pub ct2: ElGamalCiphertext,
    /// First public key
    pub pk1: ECPoint,
    /// Second public key
    pub pk2: ECPoint,
}

/// Inputs for 3-party same encryption verification
#[derive(Copy, Drop, Serde)]
pub struct SameEncryption3Inputs {
    /// Sender ciphertext
    pub ct_sender: ElGamalCiphertext,
    /// Receiver ciphertext
    pub ct_receiver: ElGamalCiphertext,
    /// Auditor ciphertext
    pub ct_auditor: ElGamalCiphertext,
    /// Sender public key
    pub pk_sender: ECPoint,
    /// Receiver public key
    pub pk_receiver: ECPoint,
    /// Auditor public key
    pub pk_auditor: ECPoint,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Extract L (first component) from ciphertext as ECPoint
#[inline(always)]
fn get_L(ct: ElGamalCiphertext) -> ECPoint {
    ECPoint { x: ct.c2_x, y: ct.c2_y }  // L is in c2 (M + r*PK)
}

/// Extract R (second component) from ciphertext as ECPoint
#[inline(always)]
fn get_R(ct: ElGamalCiphertext) -> ECPoint {
    ECPoint { x: ct.c1_x, y: ct.c1_y }  // R is in c1 (r*G)
}

/// Compute challenge hash for 2-party proof
fn compute_challenge_2(
    al1: ECPoint,
    ar1: ECPoint,
    al2: ECPoint,
    ar2: ECPoint,
    ct1: ElGamalCiphertext,
    ct2: ElGamalCiphertext,
    pk1: ECPoint,
    pk2: ECPoint,
) -> felt252 {
    let mut hash_input: Array<felt252> = array![];

    // Domain separator
    hash_input.append(SAME_ENC_2_DOMAIN);

    // Commitments
    hash_input.append(al1.x);
    hash_input.append(al1.y);
    hash_input.append(ar1.x);
    hash_input.append(ar1.y);
    hash_input.append(al2.x);
    hash_input.append(al2.y);
    hash_input.append(ar2.x);
    hash_input.append(ar2.y);

    // Ciphertexts
    hash_input.append(ct1.c1_x);
    hash_input.append(ct1.c1_y);
    hash_input.append(ct1.c2_x);
    hash_input.append(ct1.c2_y);
    hash_input.append(ct2.c1_x);
    hash_input.append(ct2.c1_y);
    hash_input.append(ct2.c2_x);
    hash_input.append(ct2.c2_y);

    // Public keys
    hash_input.append(pk1.x);
    hash_input.append(pk1.y);
    hash_input.append(pk2.x);
    hash_input.append(pk2.y);

    // Reduce to curve order for security
    reduce_mod_n(poseidon_hash_span(hash_input.span()))
}

/// Compute challenge hash for 3-party proof
fn compute_challenge_3(
    al1: ECPoint, ar1: ECPoint,
    al2: ECPoint, ar2: ECPoint,
    al3: ECPoint, ar3: ECPoint,
    ct1: ElGamalCiphertext,
    ct2: ElGamalCiphertext,
    ct3: ElGamalCiphertext,
    pk1: ECPoint,
    pk2: ECPoint,
    pk3: ECPoint,
) -> felt252 {
    let mut hash_input: Array<felt252> = array![];

    // Domain separator
    hash_input.append(SAME_ENC_3_DOMAIN);

    // All commitments
    hash_input.append(al1.x);
    hash_input.append(al1.y);
    hash_input.append(ar1.x);
    hash_input.append(ar1.y);
    hash_input.append(al2.x);
    hash_input.append(al2.y);
    hash_input.append(ar2.x);
    hash_input.append(ar2.y);
    hash_input.append(al3.x);
    hash_input.append(al3.y);
    hash_input.append(ar3.x);
    hash_input.append(ar3.y);

    // All ciphertexts
    hash_input.append(ct1.c1_x);
    hash_input.append(ct1.c1_y);
    hash_input.append(ct1.c2_x);
    hash_input.append(ct1.c2_y);
    hash_input.append(ct2.c1_x);
    hash_input.append(ct2.c1_y);
    hash_input.append(ct2.c2_x);
    hash_input.append(ct2.c2_y);
    hash_input.append(ct3.c1_x);
    hash_input.append(ct3.c1_y);
    hash_input.append(ct3.c2_x);
    hash_input.append(ct3.c2_y);

    // All public keys
    hash_input.append(pk1.x);
    hash_input.append(pk1.y);
    hash_input.append(pk2.x);
    hash_input.append(pk2.y);
    hash_input.append(pk3.x);
    hash_input.append(pk3.y);

    reduce_mod_n(poseidon_hash_span(hash_input.span()))
}

// =============================================================================
// Verification Functions
// =============================================================================

/// Verify that two ciphertexts encrypt the same value
///
/// This is the core verification that proves ct1 and ct2 both encrypt
/// the same message b, even though they use different public keys
/// and different randomness.
///
/// The magic is in the SHARED sb response - if sb works for both
/// verification equations, then the message must be the same.
///
/// # Arguments
/// * `inputs` - The two ciphertexts and their public keys
/// * `proof` - The same encryption proof
///
/// # Returns
/// * `true` if proof is valid (same message encrypted)
/// * `false` otherwise
pub fn verify_same_encryption(
    inputs: SameEncryptionInputs,
    proof: SameEncryptionProof
) -> bool {
    let g = generator();

    // Extract proof commitments
    let al1 = ECPoint { x: proof.al1_x, y: proof.al1_y };
    let ar1 = ECPoint { x: proof.ar1_x, y: proof.ar1_y };
    let al2 = ECPoint { x: proof.al2_x, y: proof.al2_y };
    let ar2 = ECPoint { x: proof.ar2_x, y: proof.ar2_y };

    // Basic validity checks
    if is_zero(al1) || is_zero(ar1) || is_zero(al2) || is_zero(ar2) {
        return false;
    }
    if proof.sb == 0 || proof.sr1 == 0 || proof.sr2 == 0 {
        return false;
    }

    // Recompute challenge
    let c = compute_challenge_2(
        al1, ar1, al2, ar2,
        inputs.ct1, inputs.ct2,
        inputs.pk1, inputs.pk2
    );

    // Extract ciphertext components
    let L1 = get_L(inputs.ct1);
    let R1 = get_R(inputs.ct1);
    let L2 = get_L(inputs.ct2);
    let R2 = get_R(inputs.ct2);

    // =========================================================================
    // Verify first ElGamal proof (for ct1)
    // Check: g^sb * pk1^sr1 == AL1 * L1^c
    // Check: g^sr1 == AR1 * R1^c
    // =========================================================================

    // LHS1: g^sb * pk1^sr1
    let g_sb = ec_mul(proof.sb, g);
    let pk1_sr1 = ec_mul(proof.sr1, inputs.pk1);
    let lhs1_L = ec_add(g_sb, pk1_sr1);

    // RHS1: AL1 * L1^c
    let L1_c = ec_mul(c, L1);
    let rhs1_L = ec_add(al1, L1_c);

    if lhs1_L.x != rhs1_L.x || lhs1_L.y != rhs1_L.y {
        return false;
    }

    // LHS1_R: g^sr1
    let lhs1_R = ec_mul(proof.sr1, g);

    // RHS1_R: AR1 * R1^c
    let R1_c = ec_mul(c, R1);
    let rhs1_R = ec_add(ar1, R1_c);

    if lhs1_R.x != rhs1_R.x || lhs1_R.y != rhs1_R.y {
        return false;
    }

    // =========================================================================
    // Verify second ElGamal proof (for ct2) - SAME sb proves same message!
    // Check: g^sb * pk2^sr2 == AL2 * L2^c
    // Check: g^sr2 == AR2 * R2^c
    // =========================================================================

    // LHS2: g^sb * pk2^sr2 (NOTE: same sb as above!)
    let pk2_sr2 = ec_mul(proof.sr2, inputs.pk2);
    let lhs2_L = ec_add(g_sb, pk2_sr2);  // Reusing g_sb!

    // RHS2: AL2 * L2^c
    let L2_c = ec_mul(c, L2);
    let rhs2_L = ec_add(al2, L2_c);

    if lhs2_L.x != rhs2_L.x || lhs2_L.y != rhs2_L.y {
        return false;
    }

    // LHS2_R: g^sr2
    let lhs2_R = ec_mul(proof.sr2, g);

    // RHS2_R: AR2 * R2^c
    let R2_c = ec_mul(c, R2);
    let rhs2_R = ec_add(ar2, R2_c);

    if lhs2_R.x != rhs2_R.x || lhs2_R.y != rhs2_R.y {
        return false;
    }

    // All checks passed - same message encrypted in both ciphertexts!
    true
}

/// Verify that THREE ciphertexts encrypt the same value
///
/// Used for transfer verification where:
/// - ct_sender: Amount encrypted for sender (to subtract from balance)
/// - ct_receiver: Amount encrypted for receiver (to add to pending)
/// - ct_auditor: Amount encrypted for auditor (compliance trail)
///
/// All three MUST encrypt the same amount b.
pub fn verify_same_encryption_3(
    inputs: SameEncryption3Inputs,
    proof: SameEncryption3Proof
) -> bool {
    let g = generator();

    // Extract proof commitments
    let al1 = ECPoint { x: proof.al1_x, y: proof.al1_y };
    let ar1 = ECPoint { x: proof.ar1_x, y: proof.ar1_y };
    let al2 = ECPoint { x: proof.al2_x, y: proof.al2_y };
    let ar2 = ECPoint { x: proof.ar2_x, y: proof.ar2_y };
    let al3 = ECPoint { x: proof.al3_x, y: proof.al3_y };
    let ar3 = ECPoint { x: proof.ar3_x, y: proof.ar3_y };

    // Basic validity checks
    if is_zero(al1) || is_zero(ar1) || is_zero(al2) || is_zero(ar2)
       || is_zero(al3) || is_zero(ar3) {
        return false;
    }
    if proof.sb == 0 || proof.sr1 == 0 || proof.sr2 == 0 || proof.sr3 == 0 {
        return false;
    }

    // Recompute challenge
    let c = compute_challenge_3(
        al1, ar1, al2, ar2, al3, ar3,
        inputs.ct_sender, inputs.ct_receiver, inputs.ct_auditor,
        inputs.pk_sender, inputs.pk_receiver, inputs.pk_auditor
    );

    // Extract ciphertext components
    let L1 = get_L(inputs.ct_sender);
    let R1 = get_R(inputs.ct_sender);
    let L2 = get_L(inputs.ct_receiver);
    let R2 = get_R(inputs.ct_receiver);
    let L3 = get_L(inputs.ct_auditor);
    let R3 = get_R(inputs.ct_auditor);

    // Compute g^sb ONCE (shared across all verifications)
    let g_sb = ec_mul(proof.sb, g);

    // =========================================================================
    // Verify sender proof (party 1)
    // =========================================================================
    let pk1_sr1 = ec_mul(proof.sr1, inputs.pk_sender);
    let lhs1_L = ec_add(g_sb, pk1_sr1);
    let L1_c = ec_mul(c, L1);
    let rhs1_L = ec_add(al1, L1_c);
    if lhs1_L.x != rhs1_L.x || lhs1_L.y != rhs1_L.y {
        return false;
    }

    let lhs1_R = ec_mul(proof.sr1, g);
    let R1_c = ec_mul(c, R1);
    let rhs1_R = ec_add(ar1, R1_c);
    if lhs1_R.x != rhs1_R.x || lhs1_R.y != rhs1_R.y {
        return false;
    }

    // =========================================================================
    // Verify receiver proof (party 2) - SAME sb!
    // =========================================================================
    let pk2_sr2 = ec_mul(proof.sr2, inputs.pk_receiver);
    let lhs2_L = ec_add(g_sb, pk2_sr2);
    let L2_c = ec_mul(c, L2);
    let rhs2_L = ec_add(al2, L2_c);
    if lhs2_L.x != rhs2_L.x || lhs2_L.y != rhs2_L.y {
        return false;
    }

    let lhs2_R = ec_mul(proof.sr2, g);
    let R2_c = ec_mul(c, R2);
    let rhs2_R = ec_add(ar2, R2_c);
    if lhs2_R.x != rhs2_R.x || lhs2_R.y != rhs2_R.y {
        return false;
    }

    // =========================================================================
    // Verify auditor proof (party 3) - SAME sb!
    // =========================================================================
    let pk3_sr3 = ec_mul(proof.sr3, inputs.pk_auditor);
    let lhs3_L = ec_add(g_sb, pk3_sr3);
    let L3_c = ec_mul(c, L3);
    let rhs3_L = ec_add(al3, L3_c);
    if lhs3_L.x != rhs3_L.x || lhs3_L.y != rhs3_L.y {
        return false;
    }

    let lhs3_R = ec_mul(proof.sr3, g);
    let R3_c = ec_mul(c, R3);
    let rhs3_R = ec_add(ar3, R3_c);
    if lhs3_R.x != rhs3_R.x || lhs3_R.y != rhs3_R.y {
        return false;
    }

    // All checks passed - all three ciphertexts encrypt the same amount!
    true
}

// =============================================================================
// Proof Generation (for off-chain use / testing)
// =============================================================================

/// Generate a same encryption proof (2-party)
///
/// This function is primarily for testing and off-chain proof generation.
/// In production, proofs would be generated by the client.
///
/// # Arguments
/// * `message` - The amount being encrypted (as felt252)
/// * `r1` - Randomness used for first encryption
/// * `r2` - Randomness used for second encryption
/// * `pk1` - First public key
/// * `pk2` - Second public key
/// * `kb` - Random commitment for message
/// * `kr1` - Random commitment for r1
/// * `kr2` - Random commitment for r2
///
/// # Returns
/// * Tuple of (ciphertext1, ciphertext2, proof)
pub fn create_same_encryption_proof(
    message: felt252,
    r1: felt252,
    r2: felt252,
    pk1: ECPoint,
    pk2: ECPoint,
    kb: felt252,
    kr1: felt252,
    kr2: felt252,
) -> (ElGamalCiphertext, ElGamalCiphertext, SameEncryptionProof) {
    let g = generator();
    let _h = generator_h();

    // Create ciphertexts
    // ct = (R, L) = (g^r, g^b * pk^r) where b is encoded as b*H
    // For simplicity, we use direct encoding: L = g^b * pk^r

    // Ciphertext 1: Enc[pk1](message, r1)
    let R1 = ec_mul(r1, g);
    let g_m = ec_mul(message, g);
    let pk1_r1 = ec_mul(r1, pk1);
    let L1 = ec_add(g_m, pk1_r1);
    let ct1 = ElGamalCiphertext {
        c1_x: R1.x, c1_y: R1.y,
        c2_x: L1.x, c2_y: L1.y,
    };

    // Ciphertext 2: Enc[pk2](message, r2)
    let R2 = ec_mul(r2, g);
    let pk2_r2 = ec_mul(r2, pk2);
    let L2 = ec_add(g_m, pk2_r2);
    let ct2 = ElGamalCiphertext {
        c1_x: R2.x, c1_y: R2.y,
        c2_x: L2.x, c2_y: L2.y,
    };

    // Compute commitments
    // AL1 = g^kb * pk1^kr1
    let g_kb = ec_mul(kb, g);
    let pk1_kr1 = ec_mul(kr1, pk1);
    let AL1 = ec_add(g_kb, pk1_kr1);

    // AR1 = g^kr1
    let AR1 = ec_mul(kr1, g);

    // AL2 = g^kb * pk2^kr2 (same kb!)
    let pk2_kr2 = ec_mul(kr2, pk2);
    let AL2 = ec_add(g_kb, pk2_kr2);

    // AR2 = g^kr2
    let AR2 = ec_mul(kr2, g);

    // Compute challenge
    let c = compute_challenge_2(AL1, AR1, AL2, AR2, ct1, ct2, pk1, pk2);

    // Compute responses (all mod curve order)
    // sb = kb + c * message
    let c_m = mul_mod_n(c, message);
    let sb = add_mod_n(kb, c_m);

    // sr1 = kr1 + c * r1
    let c_r1 = mul_mod_n(c, r1);
    let sr1 = add_mod_n(kr1, c_r1);

    // sr2 = kr2 + c * r2
    let c_r2 = mul_mod_n(c, r2);
    let sr2 = add_mod_n(kr2, c_r2);

    let proof = SameEncryptionProof {
        al1_x: AL1.x, al1_y: AL1.y,
        ar1_x: AR1.x, ar1_y: AR1.y,
        al2_x: AL2.x, al2_y: AL2.y,
        ar2_x: AR2.x, ar2_y: AR2.y,
        sb,
        sr1,
        sr2,
    };

    (ct1, ct2, proof)
}

/// Generate a 3-party same encryption proof
///
/// Creates proof that sender, receiver, and auditor ciphertexts
/// all encrypt the same amount.
pub fn create_same_encryption_3_proof(
    message: felt252,
    r1: felt252,  // sender randomness
    r2: felt252,  // receiver randomness
    r3: felt252,  // auditor randomness
    pk1: ECPoint, // sender pk
    pk2: ECPoint, // receiver pk
    pk3: ECPoint, // auditor pk
    kb: felt252,  // commitment randomness for message
    kr1: felt252,
    kr2: felt252,
    kr3: felt252,
) -> (ElGamalCiphertext, ElGamalCiphertext, ElGamalCiphertext, SameEncryption3Proof) {
    let g = generator();

    // Create all three ciphertexts
    let g_m = ec_mul(message, g);

    // Sender ciphertext
    let R1 = ec_mul(r1, g);
    let pk1_r1 = ec_mul(r1, pk1);
    let L1 = ec_add(g_m, pk1_r1);
    let ct1 = ElGamalCiphertext {
        c1_x: R1.x, c1_y: R1.y,
        c2_x: L1.x, c2_y: L1.y,
    };

    // Receiver ciphertext
    let R2 = ec_mul(r2, g);
    let pk2_r2 = ec_mul(r2, pk2);
    let L2 = ec_add(g_m, pk2_r2);
    let ct2 = ElGamalCiphertext {
        c1_x: R2.x, c1_y: R2.y,
        c2_x: L2.x, c2_y: L2.y,
    };

    // Auditor ciphertext
    let R3 = ec_mul(r3, g);
    let pk3_r3 = ec_mul(r3, pk3);
    let L3 = ec_add(g_m, pk3_r3);
    let ct3 = ElGamalCiphertext {
        c1_x: R3.x, c1_y: R3.y,
        c2_x: L3.x, c2_y: L3.y,
    };

    // Compute commitments (all use same kb for message!)
    let g_kb = ec_mul(kb, g);

    let pk1_kr1 = ec_mul(kr1, pk1);
    let AL1 = ec_add(g_kb, pk1_kr1);
    let AR1 = ec_mul(kr1, g);

    let pk2_kr2 = ec_mul(kr2, pk2);
    let AL2 = ec_add(g_kb, pk2_kr2);
    let AR2 = ec_mul(kr2, g);

    let pk3_kr3 = ec_mul(kr3, pk3);
    let AL3 = ec_add(g_kb, pk3_kr3);
    let AR3 = ec_mul(kr3, g);

    // Compute challenge
    let c = compute_challenge_3(
        AL1, AR1, AL2, AR2, AL3, AR3,
        ct1, ct2, ct3,
        pk1, pk2, pk3
    );

    // Compute responses
    let c_m = mul_mod_n(c, message);
    let sb = add_mod_n(kb, c_m);

    let c_r1 = mul_mod_n(c, r1);
    let sr1 = add_mod_n(kr1, c_r1);

    let c_r2 = mul_mod_n(c, r2);
    let sr2 = add_mod_n(kr2, c_r2);

    let c_r3 = mul_mod_n(c, r3);
    let sr3 = add_mod_n(kr3, c_r3);

    let proof = SameEncryption3Proof {
        al1_x: AL1.x, al1_y: AL1.y,
        ar1_x: AR1.x, ar1_y: AR1.y,
        al2_x: AL2.x, al2_y: AL2.y,
        ar2_x: AR2.x, ar2_y: AR2.y,
        al3_x: AL3.x, al3_y: AL3.y,
        ar3_x: AR3.x, ar3_y: AR3.y,
        sb,
        sr1, sr2, sr3,
    };

    (ct1, ct2, ct3, proof)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MESSAGE: felt252 = 1000;
    const TEST_R1: felt252 = 12345;
    const TEST_R2: felt252 = 67890;
    const TEST_R3: felt252 = 11111;
    const TEST_KB: felt252 = 22222;
    const TEST_KR1: felt252 = 33333;
    const TEST_KR2: felt252 = 44444;
    const TEST_KR3: felt252 = 55555;
    const TEST_SK1: felt252 = 111111;
    const TEST_SK2: felt252 = 222222;
    const TEST_SK3: felt252 = 333333;

    fn get_test_keys() -> (ECPoint, ECPoint, ECPoint) {
        let g = generator();
        let pk1 = ec_mul(TEST_SK1, g);
        let pk2 = ec_mul(TEST_SK2, g);
        let pk3 = ec_mul(TEST_SK3, g);
        (pk1, pk2, pk3)
    }

    #[test]
    fn test_same_encryption_2_party_valid() {
        let (pk1, pk2, _) = get_test_keys();

        let (ct1, ct2, proof) = create_same_encryption_proof(
            TEST_MESSAGE,
            TEST_R1,
            TEST_R2,
            pk1,
            pk2,
            TEST_KB,
            TEST_KR1,
            TEST_KR2
        );

        let inputs = SameEncryptionInputs { ct1, ct2, pk1, pk2 };

        assert!(verify_same_encryption(inputs, proof), "Valid proof rejected");
    }

    #[test]
    fn test_same_encryption_3_party_valid() {
        let (pk1, pk2, pk3) = get_test_keys();

        let (ct1, ct2, ct3, proof) = create_same_encryption_3_proof(
            TEST_MESSAGE,
            TEST_R1, TEST_R2, TEST_R3,
            pk1, pk2, pk3,
            TEST_KB,
            TEST_KR1, TEST_KR2, TEST_KR3
        );

        let inputs = SameEncryption3Inputs {
            ct_sender: ct1,
            ct_receiver: ct2,
            ct_auditor: ct3,
            pk_sender: pk1,
            pk_receiver: pk2,
            pk_auditor: pk3,
        };

        assert!(verify_same_encryption_3(inputs, proof), "Valid 3-party proof rejected");
    }

    #[test]
    fn test_same_encryption_wrong_pk_fails() {
        let (pk1, pk2, pk3) = get_test_keys();

        let (ct1, ct2, proof) = create_same_encryption_proof(
            TEST_MESSAGE,
            TEST_R1,
            TEST_R2,
            pk1,
            pk2,
            TEST_KB,
            TEST_KR1,
            TEST_KR2
        );

        // Try to verify with wrong public key
        let inputs = SameEncryptionInputs { ct1, ct2, pk1, pk2: pk3 };

        assert!(!verify_same_encryption(inputs, proof), "Wrong pk accepted");
    }

    #[test]
    fn test_same_encryption_tampered_sb_fails() {
        let (pk1, pk2, _) = get_test_keys();

        let (ct1, ct2, mut proof) = create_same_encryption_proof(
            TEST_MESSAGE,
            TEST_R1,
            TEST_R2,
            pk1,
            pk2,
            TEST_KB,
            TEST_KR1,
            TEST_KR2
        );

        // Tamper with shared sb
        proof.sb = proof.sb + 1;

        let inputs = SameEncryptionInputs { ct1, ct2, pk1, pk2 };

        assert!(!verify_same_encryption(inputs, proof), "Tampered sb accepted");
    }

    #[test]
    fn test_domain_separators_unique() {
        assert!(SAME_ENC_2_DOMAIN != SAME_ENC_3_DOMAIN, "Domains not unique");
    }
}
