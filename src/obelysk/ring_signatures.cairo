// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Ring Signatures for Sender Anonymity
//
// Implements Linkable Spontaneous Anonymous Group (LSAG) signatures
// Based on: "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups"
//
// Properties:
// - Anonymity: Verifier cannot determine which ring member signed
// - Linkability: Can detect if same key signs twice (prevents double-spend)
// - Spontaneous: No group manager or setup required
//
// Ring size determines anonymity set - larger rings = more privacy

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::{
    ECPoint, ec_mul, ec_add, generator
};

// ============================================================================
// RING SIGNATURE STRUCTURES
// ============================================================================

/// A ring signature proving membership in a group without revealing identity
#[derive(Drop, Serde)]
pub struct RingSignature {
    /// The ring of public keys (anonymity set)
    pub ring: Array<ECPoint>,
    /// Key image (for linkability detection)
    pub key_image: ECPoint,
    /// Challenge seed
    pub c0: felt252,
    /// Response values (one per ring member)
    pub responses: Array<felt252>,
}

/// Compact ring signature for on-chain storage
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CompactRingSignature {
    /// Key image for linkability
    pub key_image_x: felt252,
    pub key_image_y: felt252,
    /// Ring size
    pub ring_size: u8,
    /// Challenge seed
    pub c0: felt252,
    /// Hash of the full signature data (for verification)
    pub signature_hash: felt252,
}

/// Ring member public key with index
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RingMember {
    pub pubkey: ECPoint,
    pub index: u32,
}

/// Parameters for ring signature generation
#[derive(Drop, Serde)]
pub struct RingSignParams {
    /// Message to sign
    pub message: felt252,
    /// Signer's secret key
    pub secret_key: felt252,
    /// Signer's index in the ring
    pub signer_index: u32,
    /// Ring of public keys
    pub ring: Array<ECPoint>,
    /// Random nonces (one per ring member except signer)
    pub nonces: Array<felt252>,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Minimum ring size for adequate anonymity
const MIN_RING_SIZE: u32 = 4;

/// Maximum ring size (gas limit consideration)
const MAX_RING_SIZE: u32 = 16;

/// Domain separator for key image derivation
const KEY_IMAGE_DOMAIN: felt252 = 'LSAG_KEY_IMAGE';

/// Domain separator for challenge computation
const CHALLENGE_DOMAIN: felt252 = 'LSAG_CHALLENGE';

// ============================================================================
// RING SIGNATURE GENERATION
// ============================================================================

/// Generate a ring signature using LSAG (Linkable Spontaneous Anonymous Group)
/// @param params: Signing parameters including secret key and ring
/// @return Ring signature
pub fn sign_ring(params: RingSignParams) -> RingSignature {
    let g = generator();
    let n = params.ring.len();
    let s = params.signer_index;

    assert!(n >= MIN_RING_SIZE, "Ring too small");
    assert!(n <= MAX_RING_SIZE, "Ring too large");
    assert!(s < n, "Invalid signer index");

    // Step 1: Compute key image I = x * H(P_s)
    let p_s = *params.ring.at(s);
    let hp_s = hash_to_point(p_s);
    let key_image = ec_mul(params.secret_key, hp_s);

    // Step 2: Choose random k and compute initial L, R
    let k = generate_random_scalar(params.message, params.secret_key);
    let l_init = ec_mul(k, g);         // k * G
    let r_init = ec_mul(k, hp_s);      // k * H(P_s)

    // Step 3: c_{s+1} = H(m, L, R)
    let c_splus1 = compute_challenge(params.message, l_init, r_init);

    // Step 4: We'll collect responses in order [r_0, r_1, ..., r_{n-1}]
    // and track challenges as we go around the ring

    // First pass: go from s+1 around to s, computing challenges
    // Store the challenges we compute at each position
    let mut challenges_at: Array<felt252> = array![];
    let mut nonce_mapping: Array<u32> = array![];  // Which nonce index for each position

    // Initialize challenges array with placeholders
    let mut init_j: u32 = 0;
    loop {
        if init_j >= n {
            break;
        }
        challenges_at.append(0);
        nonce_mapping.append(0);
        init_j += 1;
    };

    // Compute the chain of challenges
    let mut c_current = c_splus1;
    let mut pos = (s + 1) % n;
    let mut nonce_used: u32 = 0;

    loop {
        if pos == s {
            break;
        }

        // Get response for this position (random nonce)
        let r_i = *params.nonces.at(nonce_used);

        // Compute L_i = r_i*G + c*P_i
        let p_i = *params.ring.at(pos);
        let r_g = ec_mul(r_i, g);
        let c_p = ec_mul(c_current, p_i);
        let l_i = ec_add(r_g, c_p);

        // Compute R_i = r_i*H(P_i) + c*I
        let hp_i = hash_to_point(p_i);
        let r_hp = ec_mul(r_i, hp_i);
        let c_i = ec_mul(c_current, key_image);
        let r_i_pt = ec_add(r_hp, c_i);

        // Compute next challenge
        c_current = compute_challenge(params.message, l_i, r_i_pt);

        nonce_used += 1;
        pos = (pos + 1) % n;
    };

    // Now c_current = c_s (the challenge for the signer)
    let c_s = c_current;

    // Step 5: Compute signer's response: r_s = k - c_s * x
    let r_s = k - c_s * params.secret_key;

    // Step 6: Build responses array in order [r_0, r_1, ..., r_{n-1}]
    let mut responses: Array<felt252> = array![];
    let mut build_pos: u32 = 0;

    loop {
        if build_pos >= n {
            break;
        }

        if build_pos == s {
            // Signer's response
            responses.append(r_s);
        } else {
            // Calculate which nonce was used for this position
            // Nonces are used in order: position (s+1), (s+2), ..., (s-1) mod n
            // So for position p, nonce index = distance from (s+1) to p (wrapping)
            let distance = if build_pos > s {
                build_pos - s - 1
            } else {
                // build_pos < s (can't be equal, we handled that)
                // distance = positions from s+1 to n-1, then 0 to build_pos
                (n - s - 1) + build_pos
            };
            responses.append(*params.nonces.at(distance));
        }

        build_pos += 1;
    };

    // Step 7: Compute c_0
    // c_0 is the challenge at position 0. We need to trace from c_{s+1} to find it.
    // If s = n-1, then c_{s+1} = c_0
    // Otherwise, c_0 is computed after processing position n-1 (if s < n-1)
    // Actually, c_0 is what the challenge is when we arrive at position 0

    // For verification starting at position 0 with c_0:
    // - Process position 0 with c_0 -> get c_1
    // - Process position 1 with c_1 -> get c_2
    // - ...
    // - Process position n-1 with c_{n-1} -> get c_n = c_0 (ring closes)

    // In signing, we computed c_{s+1} and traced around.
    // c_0 is the challenge we have when we arrive at position 0 during the trace.

    // Trace again to find c_0
    let c0 = if s == n - 1 {
        // Signer is last position, so c_{s+1} = c_0
        c_splus1
    } else {
        // Need to trace from c_{s+1} until we reach position 0
        let mut trace_c = c_splus1;
        let mut trace_pos = (s + 1) % n;
        let mut trace_nonce: u32 = 0;

        loop {
            if trace_pos == 0 {
                break trace_c;
            }

            // We need the response for this position
            let r_i = *params.nonces.at(trace_nonce);
            let p_i = *params.ring.at(trace_pos);

            let r_g = ec_mul(r_i, g);
            let c_p = ec_mul(trace_c, p_i);
            let l_i = ec_add(r_g, c_p);

            let hp_i = hash_to_point(p_i);
            let r_hp = ec_mul(r_i, hp_i);
            let c_img = ec_mul(trace_c, key_image);
            let r_i_pt = ec_add(r_hp, c_img);

            trace_c = compute_challenge(params.message, l_i, r_i_pt);
            trace_nonce += 1;
            trace_pos = (trace_pos + 1) % n;
        }
    };

    RingSignature {
        ring: params.ring,
        key_image,
        c0,
        responses,
    }
}

// ============================================================================
// RING SIGNATURE VERIFICATION
// ============================================================================

/// Verify a ring signature
/// @param signature: The ring signature to verify
/// @param message: The message that was signed
/// @return true if signature is valid
pub fn verify_ring_signature(
    signature: @RingSignature,
    message: felt252
) -> bool {
    let g = generator();
    let ring_size = signature.ring.len();

    // Validate ring size
    if ring_size < MIN_RING_SIZE || ring_size > MAX_RING_SIZE {
        return false;
    }

    if signature.responses.len() != ring_size {
        return false;
    }

    // Verify the ring of challenges closes
    let mut current_c = *signature.c0;
    let mut i: u32 = 0;

    loop {
        if i >= ring_size {
            break;
        }

        let p_i = signature.ring.at(i);
        let r_i = *signature.responses.at(i);

        // Compute L_i = r_i*G + c_i*P_i
        let r_g = ec_mul(r_i, g);
        let c_p = ec_mul(current_c, *p_i);
        let l_i = ec_add(r_g, c_p);

        // Compute R_i = r_i*H(P_i) + c_i*I
        let hp_i = hash_to_point(*p_i);
        let r_hp = ec_mul(r_i, hp_i);
        let c_i = ec_mul(current_c, *signature.key_image);
        let r_i_point = ec_add(r_hp, c_i);

        // Compute c_{i+1}
        current_c = compute_challenge(message, l_i, r_i_point);

        i += 1;
    };

    // The ring closes if we return to c0
    current_c == *signature.c0
}

/// Check if a key image has been used before (linkability)
/// @param key_image: The key image to check
/// @param used_images: Array of previously used key images
/// @return true if this key image was used before
pub fn is_key_image_used(
    key_image: ECPoint,
    used_images: Span<ECPoint>
) -> bool {
    let mut i: u32 = 0;
    loop {
        if i >= used_images.len() {
            break false;
        }

        let used = *used_images.at(i);
        if key_image.x == used.x && key_image.y == used.y {
            break true;
        }

        i += 1;
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Hash a point to another point on the curve (for key image)
fn hash_to_point(point: ECPoint) -> ECPoint {
    let mut input: Array<felt252> = array![];
    input.append(KEY_IMAGE_DOMAIN);
    input.append(point.x);
    input.append(point.y);

    let hash = poseidon_hash_span(input.span());

    // Use hash as scalar to get a point
    // In production, use a proper hash-to-curve algorithm
    let g = generator();
    ec_mul(hash, g)
}

/// Compute challenge for ring signature
fn compute_challenge(message: felt252, l: ECPoint, r: ECPoint) -> felt252 {
    let mut input: Array<felt252> = array![];
    input.append(CHALLENGE_DOMAIN);
    input.append(message);
    input.append(l.x);
    input.append(l.y);
    input.append(r.x);
    input.append(r.y);

    poseidon_hash_span(input.span())
}

/// Generate a deterministic random scalar from message and key
fn generate_random_scalar(message: felt252, key: felt252) -> felt252 {
    let mut input: Array<felt252> = array![];
    input.append('RANDOM_SCALAR');
    input.append(message);
    input.append(key);

    poseidon_hash_span(input.span())
}

/// Compact a ring signature for storage
pub fn compact_ring_signature(sig: @RingSignature) -> CompactRingSignature {
    // Hash the full signature for integrity
    let mut sig_data: Array<felt252> = array![];
    sig_data.append((*sig.key_image).x);
    sig_data.append((*sig.key_image).y);
    sig_data.append(*sig.c0);

    let mut i: u32 = 0;
    loop {
        if i >= sig.responses.len() {
            break;
        }
        sig_data.append(*sig.responses.at(i));
        i += 1;
    };

    let signature_hash = poseidon_hash_span(sig_data.span());

    CompactRingSignature {
        key_image_x: (*sig.key_image).x,
        key_image_y: (*sig.key_image).y,
        ring_size: sig.ring.len().try_into().unwrap(),
        c0: *sig.c0,
        signature_hash,
    }
}

// ============================================================================
// RING SELECTION HELPERS
// ============================================================================

/// Parameters for selecting decoy ring members
#[derive(Drop, Serde)]
pub struct RingSelectionParams {
    /// Real sender's public key
    pub real_sender: ECPoint,
    /// Desired ring size
    pub ring_size: u32,
    /// Random seed for selection
    pub seed: felt252,
}

/// Result of ring selection
#[derive(Drop, Serde)]
pub struct SelectedRing {
    /// The full ring (decoys + real sender)
    pub ring: Array<ECPoint>,
    /// Index of real sender in the ring
    pub sender_index: u32,
}

/// Select decoys from a pool to form a ring
/// In production, this would use a more sophisticated selection algorithm
/// that considers output age, amount similarity, etc.
pub fn select_ring_members(
    params: RingSelectionParams,
    decoy_pool: Span<ECPoint>
) -> SelectedRing {
    assert!(decoy_pool.len() >= params.ring_size - 1, "Insufficient decoys");
    assert!(params.ring_size >= MIN_RING_SIZE, "Ring too small");
    assert!(params.ring_size <= MAX_RING_SIZE, "Ring too large");

    let mut ring: Array<ECPoint> = array![];
    let mut _used: Array<u32> = array![];

    // Determine sender's position using seed
    let sender_index_felt = poseidon_hash_span(array![params.seed, 'SENDER_POS'].span());
    let sender_index_u256: u256 = sender_index_felt.into();
    let sender_index: u32 = (sender_index_u256 % params.ring_size.into()).try_into().unwrap();

    // Select decoys
    let mut current_seed = params.seed;
    let mut decoy_count: u32 = 0;
    let mut ring_pos: u32 = 0;

    loop {
        if ring_pos >= params.ring_size {
            break;
        }

        if ring_pos == sender_index {
            // Insert real sender
            ring.append(params.real_sender);
        } else {
            // Select a decoy
            let decoy_hash = poseidon_hash_span(array![current_seed, decoy_count.into()].span());
            let decoy_hash_u256: u256 = decoy_hash.into();
            let decoy_idx: u32 = (decoy_hash_u256 % decoy_pool.len().into()).try_into().unwrap();

            ring.append(*decoy_pool.at(decoy_idx));
            current_seed = decoy_hash;
            decoy_count += 1;
        }

        ring_pos += 1;
    };

    SelectedRing {
        ring,
        sender_index,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::{
        RingSignature, CompactRingSignature, RingSignParams, RingSelectionParams,
        sign_ring, verify_ring_signature, is_key_image_used, compact_ring_signature,
        select_ring_members, hash_to_point, compute_challenge, generate_random_scalar,
        MIN_RING_SIZE, MAX_RING_SIZE,
    };
    use sage_contracts::obelysk::elgamal::{ECPoint, ec_mul, generator};

    /// Generate a test keypair
    fn generate_test_keypair(seed: felt252) -> (felt252, ECPoint) {
        let secret_key = seed;
        let public_key = ec_mul(secret_key, generator());
        (secret_key, public_key)
    }

    /// Generate a ring of test public keys
    fn generate_test_ring(size: u32, real_index: u32, real_pubkey: ECPoint) -> Array<ECPoint> {
        let mut ring: Array<ECPoint> = array![];
        let mut i: u32 = 0;

        loop {
            if i >= size {
                break;
            }

            if i == real_index {
                ring.append(real_pubkey);
            } else {
                // Generate deterministic decoy keys
                let decoy_secret: felt252 = (i + 100).into();
                let decoy_pubkey = ec_mul(decoy_secret, generator());
                ring.append(decoy_pubkey);
            }

            i += 1;
        };

        ring
    }

    /// Generate random nonces for ring signature
    fn generate_test_nonces(count: u32, seed: felt252) -> Array<felt252> {
        let mut nonces: Array<felt252> = array![];
        let mut i: u32 = 0;

        loop {
            if i >= count {
                break;
            }

            let nonce = generate_random_scalar(seed, (i + 1).into());
            nonces.append(nonce);

            i += 1;
        };

        nonces
    }

    #[test]
    fn test_hash_to_point() {
        let g = generator();
        let point = hash_to_point(g);

        // Should produce a valid point
        assert!(point.x != 0, "Hash to point should produce non-zero x");
        assert!(point.y != 0, "Hash to point should produce non-zero y");

        // Same input should produce same output
        let point2 = hash_to_point(g);
        assert!(point.x == point2.x && point.y == point2.y, "Hash to point should be deterministic");
    }

    #[test]
    fn test_compute_challenge() {
        let g = generator();
        let l = ec_mul(123, g);
        let r = ec_mul(456, g);
        let message: felt252 = 'test_message';

        let challenge1 = compute_challenge(message, l, r);
        let challenge2 = compute_challenge(message, l, r);

        // Same inputs should produce same challenge
        assert!(challenge1 == challenge2, "Challenge should be deterministic");

        // Different message should produce different challenge
        let challenge3 = compute_challenge('other_message', l, r);
        assert!(challenge1 != challenge3, "Different messages should produce different challenges");
    }

    #[test]
    fn test_ring_signature_basic() {
        // Generate signer's keypair
        let (secret_key, public_key) = generate_test_keypair(42);

        // Create a ring of size 4 with signer at LAST position (simplest case)
        let signer_index: u32 = 3;
        let ring = generate_test_ring(4, signer_index, public_key);

        // Generate nonces for non-signer positions (3 nonces needed)
        let nonces = generate_test_nonces(3, 12345);

        let message: felt252 = 'test_payment';

        // Create ring signature
        let params = RingSignParams {
            message,
            secret_key,
            signer_index,
            ring: ring.clone(),
            nonces,
        };

        let signature = sign_ring(params);

        // Verify the signature
        let is_valid = verify_ring_signature(@signature, message);
        assert!(is_valid, "Ring signature should be valid");
    }

    #[test]
    fn test_ring_signature_wrong_message() {
        // Generate signer's keypair
        let (secret_key, public_key) = generate_test_keypair(42);

        // Create a ring of size 4
        let signer_index: u32 = 2;
        let ring = generate_test_ring(4, signer_index, public_key);
        let nonces = generate_test_nonces(3, 12345);

        let message: felt252 = 'real_message';

        let params = RingSignParams {
            message,
            secret_key,
            signer_index,
            ring: ring.clone(),
            nonces,
        };

        let signature = sign_ring(params);

        // Verify with wrong message should fail
        let is_valid = verify_ring_signature(@signature, 'wrong_message');
        assert!(!is_valid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_key_image_linkability() {
        // Generate signer's keypair
        let (secret_key, public_key) = generate_test_keypair(42);

        // Sign two different messages with the same key
        let ring1 = generate_test_ring(4, 0, public_key);
        let ring2 = generate_test_ring(4, 2, public_key);

        let nonces1 = generate_test_nonces(3, 111);
        let nonces2 = generate_test_nonces(3, 222);

        let sig1 = sign_ring(RingSignParams {
            message: 'message1',
            secret_key,
            signer_index: 0,
            ring: ring1,
            nonces: nonces1,
        });

        let sig2 = sign_ring(RingSignParams {
            message: 'message2',
            secret_key,
            signer_index: 2,
            ring: ring2,
            nonces: nonces2,
        });

        // Key images should be the same (linkable)
        assert!(
            sig1.key_image.x == sig2.key_image.x && sig1.key_image.y == sig2.key_image.y,
            "Same signer should produce same key image (linkability)"
        );
    }

    #[test]
    fn test_different_signers_different_key_images() {
        // Two different signers
        let (secret_key1, public_key1) = generate_test_keypair(42);
        let (secret_key2, public_key2) = generate_test_keypair(99);

        let ring1 = generate_test_ring(4, 0, public_key1);
        let ring2 = generate_test_ring(4, 0, public_key2);

        let nonces = generate_test_nonces(3, 111);

        let sig1 = sign_ring(RingSignParams {
            message: 'message',
            secret_key: secret_key1,
            signer_index: 0,
            ring: ring1,
            nonces: nonces.clone(),
        });

        let sig2 = sign_ring(RingSignParams {
            message: 'message',
            secret_key: secret_key2,
            signer_index: 0,
            ring: ring2,
            nonces,
        });

        // Key images should be different
        assert!(
            sig1.key_image.x != sig2.key_image.x || sig1.key_image.y != sig2.key_image.y,
            "Different signers should produce different key images"
        );
    }

    #[test]
    fn test_is_key_image_used() {
        let (secret_key, public_key) = generate_test_keypair(42);
        let ring = generate_test_ring(4, 1, public_key);
        let nonces = generate_test_nonces(3, 111);

        let signature = sign_ring(RingSignParams {
            message: 'test',
            secret_key,
            signer_index: 1,
            ring,
            nonces,
        });

        // Empty used list
        let empty_used: Array<ECPoint> = array![];
        assert!(!is_key_image_used(signature.key_image, empty_used.span()), "Should not be used");

        // Add key image to used list
        let mut used: Array<ECPoint> = array![];
        used.append(signature.key_image);
        assert!(is_key_image_used(signature.key_image, used.span()), "Should be detected as used");
    }

    #[test]
    fn test_compact_ring_signature() {
        let (secret_key, public_key) = generate_test_keypair(42);
        let ring = generate_test_ring(4, 0, public_key);
        let nonces = generate_test_nonces(3, 111);

        let signature = sign_ring(RingSignParams {
            message: 'test',
            secret_key,
            signer_index: 0,
            ring,
            nonces,
        });

        let compact = compact_ring_signature(@signature);

        // Verify compact signature has correct data
        assert!(compact.key_image_x == signature.key_image.x, "Key image x should match");
        assert!(compact.key_image_y == signature.key_image.y, "Key image y should match");
        assert!(compact.ring_size == 4, "Ring size should be 4");
        assert!(compact.c0 == signature.c0, "c0 should match");
        assert!(compact.signature_hash != 0, "Signature hash should be non-zero");
    }

    #[test]
    fn test_ring_selection() {
        let (_, public_key) = generate_test_keypair(42);

        // Create a pool of decoys
        let mut decoy_pool: Array<ECPoint> = array![];
        let mut i: u32 = 0;
        loop {
            if i >= 20 {
                break;
            }
            let decoy_secret: felt252 = (i + 200).into();
            decoy_pool.append(ec_mul(decoy_secret, generator()));
            i += 1;
        };

        let params = RingSelectionParams {
            real_sender: public_key,
            ring_size: 8,
            seed: 'random_seed',
        };

        let selected = select_ring_members(params, decoy_pool.span());

        // Verify ring size
        assert!(selected.ring.len() == 8, "Ring should have 8 members");

        // Verify sender is in the ring
        let sender_in_ring = *selected.ring.at(selected.sender_index);
        assert!(
            sender_in_ring.x == public_key.x && sender_in_ring.y == public_key.y,
            "Sender should be in the ring at sender_index"
        );
    }

    #[test]
    fn test_max_ring_size() {
        let (secret_key, public_key) = generate_test_keypair(42);

        // Create a ring of maximum size with signer at LAST position
        let signer_idx = MAX_RING_SIZE - 1;
        let ring = generate_test_ring(MAX_RING_SIZE, signer_idx, public_key);
        let nonces = generate_test_nonces(MAX_RING_SIZE - 1, 111);

        let signature = sign_ring(RingSignParams {
            message: 'max_ring_test',
            secret_key,
            signer_index: signer_idx,
            ring: ring.clone(),
            nonces,
        });

        let is_valid = verify_ring_signature(@signature, 'max_ring_test');
        assert!(is_valid, "Max ring size signature should be valid");
    }
}
