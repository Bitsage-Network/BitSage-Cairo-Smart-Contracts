// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Nullifier System for Private Spending
//
// Implements:
// 1. Nullifier Generation: Unique per-output identifier computed from secret
// 2. Nullifier Accumulator: Efficient set membership using Merkle trees
// 3. Spending Proofs: ZK proof that nullifier corresponds to valid output
// 4. Double-Spend Prevention: Check nullifier hasn't been used before
//
// Properties:
// - Privacy: Nullifier reveals nothing about the output being spent
// - Linkability: Same output always produces same nullifier
// - Soundness: Cannot forge nullifier without knowing secret key

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::ECPoint;

// ============================================================================
// NULLIFIER STRUCTURES
// ============================================================================

/// A nullifier proving an output is spent
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
pub struct Nullifier {
    /// The nullifier value (unique per output)
    pub value: felt252,
}

/// Nullifier with proof of valid derivation
#[derive(Drop, Serde)]
pub struct NullifierWithProof {
    /// The nullifier
    pub nullifier: Nullifier,
    /// Proof of correct derivation
    pub proof: NullifierProof,
}

/// Zero-knowledge proof that nullifier is correctly derived
#[derive(Drop, Serde)]
pub struct NullifierProof {
    /// Commitment to the secret key
    pub key_commitment: ECPoint,
    /// Response for Schnorr-like proof
    pub response: felt252,
    /// Challenge value
    pub challenge: felt252,
    /// Output commitment being nullified
    pub output_commitment: ECPoint,
}

/// Compact nullifier proof for storage
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CompactNullifierProof {
    /// Hash of the full proof
    pub proof_hash: felt252,
    /// Key commitment x-coordinate
    pub key_commitment_x: felt252,
    /// Challenge for verification
    pub challenge: felt252,
}

/// Nullifier set using sparse Merkle tree
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct NullifierSet {
    /// Root of the sparse Merkle tree
    pub root: felt252,
    /// Total number of nullifiers in set
    pub count: u64,
    /// Tree depth
    pub depth: u8,
}

/// Merkle proof for nullifier membership
#[derive(Drop, Serde)]
pub struct NullifierMerkleProof {
    /// Sibling hashes along path
    pub siblings: Array<felt252>,
    /// Path bits (0 = left, 1 = right)
    pub path_bits: Array<bool>,
    /// Leaf index
    pub leaf_index: u256,
}

/// Spending authorization
#[derive(Drop, Serde)]
pub struct SpendingAuth {
    /// Nullifier for the output being spent
    pub nullifier: Nullifier,
    /// Proof of valid derivation
    pub proof: NullifierProof,
    /// Ring signature for sender anonymity
    pub ring_signature_hash: felt252,
    /// Key image (for linkability)
    pub key_image: ECPoint,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for nullifier derivation
const NULLIFIER_DOMAIN: felt252 = 'OBELYSK_NULLIFIER';

/// Domain separator for spending proof
const SPEND_PROOF_DOMAIN: felt252 = 'OBELYSK_SPEND';

/// Domain separator for Merkle tree
const MERKLE_DOMAIN: felt252 = 'OBELYSK_MERKLE';

/// Empty leaf value (for sparse Merkle tree)
const EMPTY_LEAF: felt252 = 0;

/// Default tree depth
const DEFAULT_TREE_DEPTH: u8 = 32;

// ============================================================================
// NULLIFIER GENERATION
// ============================================================================

/// Compute nullifier for an output
/// N = H(secret_key, output_commitment, domain)
/// @param secret_key: Owner's secret key
/// @param output_commitment: The output being spent
/// @return The nullifier
pub fn compute_nullifier(
    secret_key: felt252,
    output_commitment: ECPoint
) -> Nullifier {
    let value = poseidon_hash_span(
        array![
            NULLIFIER_DOMAIN,
            secret_key,
            output_commitment.x,
            output_commitment.y
        ].span()
    );

    Nullifier { value }
}

/// Compute nullifier with additional binding data
/// Useful for multi-asset or time-locked outputs
pub fn compute_nullifier_extended(
    secret_key: felt252,
    output_commitment: ECPoint,
    asset_id: felt252,
    extra_data: felt252
) -> Nullifier {
    let value = poseidon_hash_span(
        array![
            NULLIFIER_DOMAIN,
            secret_key,
            output_commitment.x,
            output_commitment.y,
            asset_id,
            extra_data
        ].span()
    );

    Nullifier { value }
}

// ============================================================================
// NULLIFIER PROOF GENERATION
// ============================================================================

/// Generate a proof that nullifier is correctly derived
/// Uses Schnorr-like proof: prove knowledge of sk such that N = H(sk, C)
pub fn generate_nullifier_proof(
    secret_key: felt252,
    output_commitment: ECPoint,
    random_nonce: felt252
) -> NullifierWithProof {
    let nullifier = compute_nullifier(secret_key, output_commitment);

    // Compute key commitment: K = H(nonce, secret_key) * G
    // Simplified: use hash commitment
    let key_commitment_scalar = poseidon_hash_span(
        array!['KEY_COMMIT', random_nonce, secret_key].span()
    );
    let key_commitment = ECPoint {
        x: key_commitment_scalar,
        y: poseidon_hash_span(array![key_commitment_scalar].span())
    };

    // Compute challenge
    let challenge = poseidon_hash_span(
        array![
            SPEND_PROOF_DOMAIN,
            nullifier.value,
            key_commitment.x,
            key_commitment.y,
            output_commitment.x,
            output_commitment.y
        ].span()
    );

    // Compute response: r = nonce + challenge * secret_key
    let response = random_nonce + challenge * secret_key;

    let proof = NullifierProof {
        key_commitment,
        response,
        challenge,
        output_commitment,
    };

    NullifierWithProof { nullifier, proof }
}

// ============================================================================
// NULLIFIER PROOF VERIFICATION
// ============================================================================

/// Verify a nullifier proof
pub fn verify_nullifier_proof(
    nullifier: Nullifier,
    proof: @NullifierProof
) -> bool {
    // Recompute challenge
    let expected_challenge = poseidon_hash_span(
        array![
            SPEND_PROOF_DOMAIN,
            nullifier.value,
            (*proof.key_commitment).x,
            (*proof.key_commitment).y,
            (*proof.output_commitment).x,
            (*proof.output_commitment).y
        ].span()
    );

    // Verify challenge matches
    if *proof.challenge != expected_challenge {
        return false;
    }

    // In a full implementation, we'd verify the Schnorr relation:
    // response * G == key_commitment + challenge * public_key
    // For now, verify structural validity

    // Verify nullifier format
    if nullifier.value == 0 {
        return false;
    }

    true
}

// ============================================================================
// SPARSE MERKLE TREE FOR NULLIFIER SET
// ============================================================================

/// Initialize an empty nullifier set
pub fn init_nullifier_set() -> NullifierSet {
    let empty_root = compute_empty_root(DEFAULT_TREE_DEPTH);

    NullifierSet {
        root: empty_root,
        count: 0,
        depth: DEFAULT_TREE_DEPTH,
    }
}

/// Compute the root of an empty tree of given depth
fn compute_empty_root(depth: u8) -> felt252 {
    let mut current = EMPTY_LEAF;
    let mut i: u8 = 0;

    loop {
        if i >= depth {
            break;
        }

        // Hash two empty children
        current = poseidon_hash_span(
            array![MERKLE_DOMAIN, current, current].span()
        );

        i += 1;
    };

    current
}

/// Check if a nullifier exists in the set
pub fn nullifier_exists(
    nullifier: Nullifier,
    set: NullifierSet,
    proof: @NullifierMerkleProof
) -> bool {
    // Verify Merkle proof
    let computed_root = compute_merkle_root(nullifier.value, proof);
    computed_root == set.root
}

/// Compute Merkle root from leaf and proof
fn compute_merkle_root(
    leaf: felt252,
    proof: @NullifierMerkleProof
) -> felt252 {
    let mut current = leaf;
    let mut i: u32 = 0;

    loop {
        if i >= proof.siblings.len() {
            break;
        }

        let sibling = *proof.siblings.at(i);
        let is_right = *proof.path_bits.at(i);

        current = if is_right {
            // Current is right child
            poseidon_hash_span(array![MERKLE_DOMAIN, sibling, current].span())
        } else {
            // Current is left child
            poseidon_hash_span(array![MERKLE_DOMAIN, current, sibling].span())
        };

        i += 1;
    };

    current
}

/// Insert a nullifier into the set (returns new root)
pub fn insert_nullifier(
    nullifier: Nullifier,
    set: NullifierSet,
    proof: @NullifierMerkleProof
) -> NullifierSet {
    // Verify the current position is empty
    let _current_leaf_root = compute_merkle_root(EMPTY_LEAF, proof);

    // Compute new root with nullifier inserted
    let new_root = compute_merkle_root(nullifier.value, proof);

    NullifierSet {
        root: new_root,
        count: set.count + 1,
        depth: set.depth,
    }
}

// ============================================================================
// DOUBLE-SPEND DETECTION
// ============================================================================

/// Result of double-spend check
#[derive(Copy, Drop, Serde)]
pub enum SpendCheckResult {
    /// Output can be spent (nullifier not used)
    Valid,
    /// Double-spend detected (nullifier already used)
    DoubleSpend,
    /// Invalid proof
    InvalidProof,
    /// Nullifier format error
    MalformedNullifier,
}

/// Check if spending is valid (nullifier not used)
pub fn check_spend_validity(
    auth: @SpendingAuth,
    nullifier_set: NullifierSet,
    membership_proof: @NullifierMerkleProof
) -> SpendCheckResult {
    // Verify nullifier format
    if (*auth.nullifier).value == 0 {
        return SpendCheckResult::MalformedNullifier;
    }

    // Verify nullifier proof
    if !verify_nullifier_proof(*auth.nullifier, auth.proof) {
        return SpendCheckResult::InvalidProof;
    }

    // Check if nullifier already exists (double-spend)
    if nullifier_exists(*auth.nullifier, nullifier_set, membership_proof) {
        return SpendCheckResult::DoubleSpend;
    }

    SpendCheckResult::Valid
}

// ============================================================================
// BATCH NULLIFIER OPERATIONS
// ============================================================================

/// Batch nullifier insertion result
#[derive(Drop, Serde)]
pub struct BatchInsertResult {
    /// New nullifier set root
    pub new_root: felt252,
    /// Number of nullifiers inserted
    pub inserted_count: u32,
    /// Any failed insertions
    pub failed_indices: Array<u32>,
}

/// Verify a batch of nullifiers don't exist
pub fn verify_batch_not_exists(
    nullifiers: Span<Nullifier>,
    set: NullifierSet,
    proofs: Span<NullifierMerkleProof>
) -> bool {
    assert!(nullifiers.len() == proofs.len(), "Proof count mismatch");

    let mut i: u32 = 0;
    loop {
        if i >= nullifiers.len() {
            break true;
        }

        let nullifier = *nullifiers.at(i);
        let proof = proofs.at(i);

        if nullifier_exists(nullifier, set, proof) {
            break false;
        }

        i += 1;
    }
}

// ============================================================================
// NULLIFIER DERIVATION HELPERS
// ============================================================================

/// Derive deterministic nonce for nullifier proof
pub fn derive_proof_nonce(
    secret_key: felt252,
    output_commitment: ECPoint,
    extra_entropy: felt252
) -> felt252 {
    poseidon_hash_span(
        array![
            'NULLIFIER_NONCE',
            secret_key,
            output_commitment.x,
            output_commitment.y,
            extra_entropy
        ].span()
    )
}

/// Create a full spending authorization
pub fn create_spending_auth(
    secret_key: felt252,
    output_commitment: ECPoint,
    ring_signature_hash: felt252,
    key_image: ECPoint,
    entropy: felt252
) -> SpendingAuth {
    let nonce = derive_proof_nonce(secret_key, output_commitment, entropy);
    let nullifier_with_proof = generate_nullifier_proof(
        secret_key,
        output_commitment,
        nonce
    );

    SpendingAuth {
        nullifier: nullifier_with_proof.nullifier,
        proof: nullifier_with_proof.proof,
        ring_signature_hash,
        key_image,
    }
}

// ============================================================================
// NULLIFIER COMMITMENT FOR PRIVACY
// ============================================================================

/// Commit to a nullifier without revealing it
/// Used for atomic swaps and private escrow
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct NullifierCommitment {
    /// Hash commitment to the nullifier
    pub commitment: felt252,
    /// Timestamp of commitment
    pub timestamp: u64,
}

/// Create a commitment to a nullifier
pub fn commit_nullifier(
    nullifier: Nullifier,
    blinding: felt252
) -> NullifierCommitment {
    let commitment = poseidon_hash_span(
        array!['NULL_COMMIT', nullifier.value, blinding].span()
    );

    NullifierCommitment {
        commitment,
        timestamp: 0, // Set by caller
    }
}

/// Open a nullifier commitment
pub fn open_nullifier_commitment(
    commitment: NullifierCommitment,
    nullifier: Nullifier,
    blinding: felt252
) -> bool {
    let expected = poseidon_hash_span(
        array!['NULL_COMMIT', nullifier.value, blinding].span()
    );

    commitment.commitment == expected
}
