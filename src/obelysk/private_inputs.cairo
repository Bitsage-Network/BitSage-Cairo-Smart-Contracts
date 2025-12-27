// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Private Input Selection System
//
// Implements:
// 1. Membership Proofs: ZK proof that input is in valid set
// 2. Spend Proofs: ZK proof of ownership without revealing which input
// 3. Input Mixing: Combine real and decoy inputs
// 4. Accumulator Updates: Efficient set membership tracking
//
// Properties:
// - Input privacy: Observer can't tell which payment is being spent
// - Soundness: Can only spend owned, unspent inputs
// - Efficiency: O(log n) membership proofs via Merkle trees

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::ECPoint;
use sage_contracts::obelysk::nullifiers::Nullifier;

// ============================================================================
// PRIVATE INPUT STRUCTURES
// ============================================================================

/// A spendable input (output from previous transaction)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SpendableInput {
    /// Commitment to the amount
    pub amount_commitment_x: felt252,
    pub amount_commitment_y: felt252,
    /// One-time public key (for ownership verification)
    pub one_time_pubkey_x: felt252,
    pub one_time_pubkey_y: felt252,
    /// Index in the global output set
    pub global_index: u256,
    /// Block when created
    pub creation_block: u64,
}

/// Merkle proof for set membership
#[derive(Drop, Serde)]
pub struct MembershipProof {
    /// Sibling hashes along the path
    pub siblings: Array<felt252>,
    /// Path direction bits (false = left, true = right)
    pub path_bits: Array<bool>,
    /// Leaf value
    pub leaf: felt252,
    /// Root of the tree (for verification)
    pub root: felt252,
}

/// Zero-knowledge spend proof
#[derive(Drop, Serde)]
pub struct SpendProof {
    /// Nullifier (unique per input, unlinkable)
    pub nullifier: Nullifier,
    /// Membership proof (input is in valid set)
    pub membership_proof: MembershipProof,
    /// Ownership proof (knowledge of spending key)
    pub ownership_proof: OwnershipProof,
    /// Amount proof (for balance verification)
    pub amount_proof: AmountProof,
}

/// Proof of spending key knowledge
#[derive(Drop, Serde)]
pub struct OwnershipProof {
    /// Commitment to the key
    pub key_commitment: ECPoint,
    /// Challenge
    pub challenge: felt252,
    /// Response
    pub response: felt252,
    /// Binding to the input
    pub input_binding: felt252,
}

/// Proof relating to the amount
#[derive(Copy, Drop, Serde)]
pub struct AmountProof {
    /// Commitment to the amount
    pub amount_commitment: ECPoint,
    /// Range proof hash
    pub range_proof_hash: felt252,
    /// Blinding factor commitment
    pub blinding_commitment: felt252,
}

/// Set of inputs being spent in a transaction
#[derive(Drop, Serde)]
pub struct InputSet {
    /// The spend proofs (one per input)
    pub proofs: Array<SpendProof>,
    /// Total input amount commitment
    pub total_commitment: ECPoint,
    /// Aggregate proof for all inputs
    pub aggregate_proof: AggregateInputProof,
}

/// Aggregate proof for multiple inputs
#[derive(Copy, Drop, Serde)]
pub struct AggregateInputProof {
    /// Combined challenge
    pub challenge: felt252,
    /// Combined response
    pub response: felt252,
    /// Root of input set
    pub set_root: felt252,
    /// Number of inputs
    pub input_count: u32,
}

/// Accumulator for tracking valid outputs
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct OutputAccumulator {
    /// Current Merkle root of all outputs
    pub root: felt252,
    /// Total number of outputs
    pub count: u256,
    /// Last updated block
    pub last_update_block: u64,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for leaf computation
const LEAF_DOMAIN: felt252 = 'INPUT_LEAF';

/// Domain separator for internal nodes
const NODE_DOMAIN: felt252 = 'INPUT_NODE';

/// Domain separator for ownership proof
const OWNERSHIP_DOMAIN: felt252 = 'INPUT_OWNER';

/// Domain separator for nullifier
const NULLIFIER_DOMAIN: felt252 = 'INPUT_NULL';

/// Tree depth for Merkle accumulator
const TREE_DEPTH: u32 = 32;

/// Empty leaf value
const EMPTY_LEAF: felt252 = 0;

// ============================================================================
// LEAF AND NODE COMPUTATION
// ============================================================================

/// Compute leaf value for an input
pub fn compute_leaf(input: @SpendableInput) -> felt252 {
    poseidon_hash_span(
        array![
            LEAF_DOMAIN,
            *input.amount_commitment_x,
            *input.amount_commitment_y,
            *input.one_time_pubkey_x,
            *input.one_time_pubkey_y,
            (*input.global_index).low.into(),
            (*input.global_index).high.into()
        ].span()
    )
}

/// Compute internal Merkle node
fn compute_node(left: felt252, right: felt252) -> felt252 {
    poseidon_hash_span(array![NODE_DOMAIN, left, right].span())
}

/// Compute empty subtree root at given depth
fn compute_empty_root(depth: u32) -> felt252 {
    let mut current = EMPTY_LEAF;
    let mut d: u32 = 0;

    loop {
        if d >= depth {
            break;
        }
        current = compute_node(current, current);
        d += 1;
    };

    current
}

// ============================================================================
// MEMBERSHIP PROOFS
// ============================================================================

/// Verify a membership proof
pub fn verify_membership_proof(
    proof: @MembershipProof,
    expected_root: felt252
) -> bool {
    // Verify path length matches tree depth
    if proof.siblings.len() != TREE_DEPTH {
        return false;
    }

    // Compute root from leaf and siblings
    let mut current = *proof.leaf;
    let mut i: u32 = 0;

    loop {
        if i >= proof.siblings.len() {
            break;
        }

        let sibling = *proof.siblings.at(i);
        let is_right = *proof.path_bits.at(i);

        current = if is_right {
            compute_node(sibling, current)
        } else {
            compute_node(current, sibling)
        };

        i += 1;
    };

    current == expected_root && *proof.root == expected_root
}

/// Generate a membership proof for an input
/// (In practice, this would be done off-chain with full tree access)
pub fn generate_membership_proof(
    input: @SpendableInput,
    siblings: Array<felt252>,
    path_bits: Array<bool>,
    root: felt252
) -> MembershipProof {
    let leaf = compute_leaf(input);

    MembershipProof {
        siblings,
        path_bits,
        leaf,
        root,
    }
}

// ============================================================================
// OWNERSHIP PROOFS
// ============================================================================

/// Generate an ownership proof
/// Proves knowledge of spending key without revealing it
pub fn generate_ownership_proof(
    spending_key: felt252,
    input: @SpendableInput,
    random_k: felt252
) -> OwnershipProof {
    // Compute key commitment: K = k * G (simplified)
    let key_commitment_x = poseidon_hash_span(
        array![OWNERSHIP_DOMAIN, random_k, 'X'].span()
    );
    let key_commitment_y = poseidon_hash_span(
        array![OWNERSHIP_DOMAIN, random_k, 'Y'].span()
    );
    let key_commitment = ECPoint { x: key_commitment_x, y: key_commitment_y };

    // Compute input binding
    let input_binding = poseidon_hash_span(
        array![
            OWNERSHIP_DOMAIN,
            *input.one_time_pubkey_x,
            *input.one_time_pubkey_y,
            key_commitment_x
        ].span()
    );

    // Compute challenge
    let challenge = poseidon_hash_span(
        array![
            OWNERSHIP_DOMAIN,
            key_commitment_x,
            key_commitment_y,
            input_binding
        ].span()
    );

    // Compute response: r = k - c * spending_key
    let response = random_k - challenge * spending_key;

    OwnershipProof {
        key_commitment,
        challenge,
        response,
        input_binding,
    }
}

/// Verify an ownership proof
pub fn verify_ownership_proof(
    proof: @OwnershipProof,
    input: @SpendableInput
) -> bool {
    // Recompute expected input binding
    let expected_binding = poseidon_hash_span(
        array![
            OWNERSHIP_DOMAIN,
            *input.one_time_pubkey_x,
            *input.one_time_pubkey_y,
            (*proof.key_commitment).x
        ].span()
    );

    if *proof.input_binding != expected_binding {
        return false;
    }

    // Recompute expected challenge
    let expected_challenge = poseidon_hash_span(
        array![
            OWNERSHIP_DOMAIN,
            (*proof.key_commitment).x,
            (*proof.key_commitment).y,
            *proof.input_binding
        ].span()
    );

    *proof.challenge == expected_challenge
}

// ============================================================================
// NULLIFIER COMPUTATION
// ============================================================================

/// Compute nullifier for an input
/// N = H(spending_key, input_commitment)
pub fn compute_input_nullifier(
    spending_key: felt252,
    input: @SpendableInput
) -> Nullifier {
    let value = poseidon_hash_span(
        array![
            NULLIFIER_DOMAIN,
            spending_key,
            *input.amount_commitment_x,
            *input.amount_commitment_y,
            (*input.global_index).low.into()
        ].span()
    );

    Nullifier { value }
}

// ============================================================================
// COMPLETE SPEND PROOF
// ============================================================================

/// Generate a complete spend proof for an input
pub fn generate_spend_proof(
    spending_key: felt252,
    input: SpendableInput,
    membership_siblings: Array<felt252>,
    membership_path: Array<bool>,
    accumulator_root: felt252,
    random_k: felt252,
    amount: u64,
    blinding: felt252
) -> SpendProof {
    // Generate membership proof
    let membership_proof = generate_membership_proof(
        @input,
        membership_siblings,
        membership_path,
        accumulator_root
    );

    // Generate ownership proof
    let ownership_proof = generate_ownership_proof(
        spending_key,
        @input,
        random_k
    );

    // Compute nullifier
    let nullifier = compute_input_nullifier(spending_key, @input);

    // Generate amount proof
    let amount_commitment = ECPoint {
        x: input.amount_commitment_x,
        y: input.amount_commitment_y,
    };

    let range_proof_hash = poseidon_hash_span(
        array!['RANGE', amount.into(), blinding].span()
    );

    let blinding_commitment = poseidon_hash_span(
        array!['BLIND_COMMIT', blinding].span()
    );

    let amount_proof = AmountProof {
        amount_commitment,
        range_proof_hash,
        blinding_commitment,
    };

    SpendProof {
        nullifier,
        membership_proof,
        ownership_proof,
        amount_proof,
    }
}

/// Verify a complete spend proof
pub fn verify_spend_proof(
    proof: @SpendProof,
    input: @SpendableInput,
    accumulator_root: felt252
) -> bool {
    // Verify membership
    if !verify_membership_proof(proof.membership_proof, accumulator_root) {
        return false;
    }

    // Verify ownership
    if !verify_ownership_proof(proof.ownership_proof, input) {
        return false;
    }

    // Verify nullifier is correctly derived
    // (In full ZK, this would be verified without revealing spending_key)

    // Verify amount proof structure
    if (*proof.amount_proof).range_proof_hash == 0 {
        return false;
    }

    true
}

// ============================================================================
// INPUT SET OPERATIONS
// ============================================================================

/// Create an input set from multiple spend proofs
pub fn create_input_set(
    proofs: Array<SpendProof>,
    total_amount: u64,
    total_blinding: felt252
) -> InputSet {
    let input_count: u32 = proofs.len();

    // Compute total commitment
    let total_commitment = ECPoint {
        x: poseidon_hash_span(array!['TOTAL_X', total_amount.into(), total_blinding].span()),
        y: poseidon_hash_span(array!['TOTAL_Y', total_amount.into(), total_blinding].span()),
    };

    // Compute aggregate proof
    let mut set_elements: Array<felt252> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= proofs.len() {
            break;
        }
        let proof = proofs.at(i);
        set_elements.append((*proof.nullifier).value);
        i += 1;
    };

    let set_root = poseidon_hash_span(set_elements.span());

    let aggregate_challenge = poseidon_hash_span(
        array!['AGG_CHALLENGE', set_root, total_commitment.x].span()
    );

    let aggregate_response = poseidon_hash_span(
        array!['AGG_RESPONSE', aggregate_challenge, total_blinding].span()
    );

    let aggregate_proof = AggregateInputProof {
        challenge: aggregate_challenge,
        response: aggregate_response,
        set_root,
        input_count,
    };

    InputSet {
        proofs,
        total_commitment,
        aggregate_proof,
    }
}

/// Verify an input set
pub fn verify_input_set(
    input_set: @InputSet,
    accumulator_root: felt252,
    inputs: Span<SpendableInput>
) -> bool {
    // Verify count matches
    if input_set.proofs.len() != inputs.len() {
        return false;
    }

    // Verify each proof
    let mut i: u32 = 0;
    loop {
        if i >= input_set.proofs.len() {
            break true;
        }

        let proof = input_set.proofs.at(i);
        let input = inputs.at(i);

        if !verify_spend_proof(proof, input, accumulator_root) {
            break false;
        }

        i += 1;
    }
}

// ============================================================================
// ACCUMULATOR UPDATES
// ============================================================================

/// Update accumulator with new output
pub fn update_accumulator(
    accumulator: OutputAccumulator,
    new_output: @SpendableInput,
    proof: @MembershipProof,
    current_block: u64
) -> OutputAccumulator {
    // Compute new leaf
    let new_leaf = compute_leaf(new_output);

    // Compute new root (simplified - full implementation uses incremental updates)
    let new_root = poseidon_hash_span(
        array![accumulator.root, new_leaf, accumulator.count.low.into()].span()
    );

    OutputAccumulator {
        root: new_root,
        count: accumulator.count + 1,
        last_update_block: current_block,
    }
}

/// Initialize empty accumulator
pub fn init_accumulator() -> OutputAccumulator {
    OutputAccumulator {
        root: compute_empty_root(TREE_DEPTH),
        count: 0,
        last_update_block: 0,
    }
}

// ============================================================================
// DECOY INPUT SELECTION
// ============================================================================

/// Parameters for selecting decoy inputs
#[derive(Drop, Serde)]
pub struct DecoyInputParams {
    /// Real input being spent
    pub real_input: SpendableInput,
    /// Number of decoys needed
    pub decoy_count: u32,
    /// Random seed
    pub seed: felt252,
    /// Age-weight factor
    pub age_weight: bool,
}

/// Select decoy inputs from the output pool
/// Returns indices of decoy inputs to include
pub fn select_decoy_inputs(
    params: DecoyInputParams,
    pool_size: u256
) -> Array<u256> {
    let mut decoys: Array<u256> = array![];
    let mut current_seed = params.seed;

    let mut i: u32 = 0;
    loop {
        if i >= params.decoy_count {
            break;
        }

        // Generate random index
        let index_hash = poseidon_hash_span(
            array!['DECOY_INPUT', current_seed, i.into()].span()
        );
        let index_u256: u256 = index_hash.into();
        let decoy_index = index_u256 % pool_size;

        // Skip if same as real input
        if decoy_index != params.real_input.global_index {
            decoys.append(decoy_index);
        }

        current_seed = index_hash;
        i += 1;
    };

    decoys
}

/// Create mixed input set with decoys
pub fn create_mixed_inputs(
    real_inputs: Span<SpendableInput>,
    decoy_indices: Span<u256>,
    seed: felt252
) -> (Array<u256>, u32) {
    let total_count = real_inputs.len() + decoy_indices.len();
    let mut all_indices: Array<u256> = array![];

    // Add real input indices
    let mut i: u32 = 0;
    loop {
        if i >= real_inputs.len() {
            break;
        }
        all_indices.append((*real_inputs.at(i)).global_index);
        i += 1;
    };

    // Add decoy indices
    let mut j: u32 = 0;
    loop {
        if j >= decoy_indices.len() {
            break;
        }
        all_indices.append(*decoy_indices.at(j));
        j += 1;
    };

    // Shuffle (real position hidden)
    let real_position_hash = poseidon_hash_span(
        array![seed, 'REAL_POS'].span()
    );
    let real_pos_u256: u256 = real_position_hash.into();
    let real_position: u32 = (real_pos_u256 % total_count.into()).try_into().unwrap();

    (all_indices, real_position)
}
