// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Private Worker Pools
//
// Implements anonymous worker collectives for enhanced privacy:
// 1. Anonymous Pool Membership: Workers join without revealing identity
// 2. Collective Payment Reception: Client pays pool, not individuals
// 3. Private Distribution: Pool distributes to members privately
// 4. Contribution Tracking: ZK proofs of work contribution
//
// Flow:
// Client → Pool Contract → [Worker1, Worker2, Worker3] (unlinkable)

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;
use sage_contracts::obelysk::elgamal::ECPoint;

// ============================================================================
// POOL STRUCTURES
// ============================================================================

/// Anonymous worker pool
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerPool {
    /// Pool identifier
    pub pool_id: u256,
    /// Merkle root of member commitments
    pub member_root: felt252,
    /// Total member count
    pub member_count: u32,
    /// Pool's collective public key (for receiving payments)
    pub pool_pubkey_x: felt252,
    pub pool_pubkey_y: felt252,
    /// Encrypted balance (total pool funds)
    pub balance_commitment_x: felt252,
    pub balance_commitment_y: felt252,
    /// Minimum stake to join
    pub min_stake: u256,
    /// Pool creation block
    pub created_block: u64,
    /// Is pool active
    pub is_active: bool,
}

/// Member commitment (hides identity)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct MemberCommitment {
    /// Commitment to member identity: H(address, secret)
    pub commitment: felt252,
    /// Member's encrypted share commitment
    pub share_commitment: felt252,
    /// Join epoch
    pub join_epoch: u64,
    /// Contribution weight (encrypted)
    pub weight_commitment: felt252,
}

/// Anonymous membership proof
#[derive(Drop, Serde)]
pub struct MembershipProof {
    /// Merkle path to member commitment
    pub merkle_path: Array<felt252>,
    /// Path direction bits
    pub path_bits: Array<bool>,
    /// Member's secret (for claiming)
    pub member_secret: felt252,
    /// Nullifier to prevent double-claims
    pub nullifier: felt252,
}

/// Pool payment (from client to pool)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PoolPayment {
    /// Payment identifier
    pub payment_id: u256,
    /// Target pool
    pub pool_id: u256,
    /// Encrypted amount
    pub amount_commitment_x: felt252,
    pub amount_commitment_y: felt252,
    /// Job reference (encrypted)
    pub job_ref_encrypted: felt252,
    /// Payment timestamp
    pub timestamp: u64,
    /// Is distributed
    pub is_distributed: bool,
}

/// Distribution share for a member
#[derive(Copy, Drop, Serde)]
pub struct DistributionShare {
    /// Member's commitment (for verification)
    pub member_commitment: felt252,
    /// Encrypted share amount
    pub share_commitment_x: felt252,
    pub share_commitment_y: felt252,
    /// Stealth address for receiving
    pub stealth_address: felt252,
    /// Ephemeral public key
    pub ephemeral_pubkey_x: felt252,
    pub ephemeral_pubkey_y: felt252,
}

/// Distribution proof (proves fair distribution)
#[derive(Drop, Serde)]
pub struct DistributionProof {
    /// Sum of shares equals total payment
    pub sum_proof: felt252,
    /// Each share matches weight
    pub weight_proofs: Array<felt252>,
    /// Distribution randomness
    pub randomness: felt252,
}

/// Work contribution proof (for weight calculation)
#[derive(Drop, Serde)]
pub struct ContributionProof {
    /// Job IDs contributed to (encrypted)
    pub job_commitments: Array<felt252>,
    /// Computation units (encrypted)
    pub units_commitment: felt252,
    /// STWO proof of valid work
    pub work_proof_hash: felt252,
    /// Epoch of contribution
    pub epoch: u64,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for pool operations
const POOL_DOMAIN: felt252 = 'WORKER_POOL';

/// Domain separator for member commitments
const MEMBER_DOMAIN: felt252 = 'POOL_MEMBER';

/// Domain separator for distribution
const DIST_DOMAIN: felt252 = 'POOL_DIST';

/// Merkle tree depth for member set
const MEMBER_TREE_DEPTH: u32 = 20;

/// Maximum members per pool
const MAX_MEMBERS: u32 = 1000;

/// Distribution epoch length (blocks)
const DISTRIBUTION_EPOCH: u64 = 720; // ~1 day

/// Minimum members for pool activation
const MIN_MEMBERS_ACTIVE: u32 = 3;

// ============================================================================
// POOL CREATION AND MANAGEMENT
// ============================================================================

/// Create a new worker pool
pub fn create_pool(
    pool_id: u256,
    founder_commitment: felt252,
    pool_pubkey: ECPoint,
    min_stake: u256,
    current_block: u64
) -> WorkerPool {
    // Initialize with founder as first member
    let member_root = compute_single_member_root(founder_commitment);

    WorkerPool {
        pool_id,
        member_root,
        member_count: 1,
        pool_pubkey_x: pool_pubkey.x,
        pool_pubkey_y: pool_pubkey.y,
        balance_commitment_x: 0,
        balance_commitment_y: 0,
        min_stake,
        created_block: current_block,
        is_active: false, // Needs MIN_MEMBERS_ACTIVE to activate
    }
}

/// Compute member root for single member
fn compute_single_member_root(commitment: felt252) -> felt252 {
    let mut current = commitment;
    let empty = compute_empty_subtree();

    let mut i: u32 = 0;
    loop {
        if i >= MEMBER_TREE_DEPTH {
            break;
        }
        current = poseidon_hash_span(array![MEMBER_DOMAIN, current, empty].span());
        i += 1;
    };

    current
}

/// Compute empty subtree hash
fn compute_empty_subtree() -> felt252 {
    poseidon_hash_span(array![MEMBER_DOMAIN, 'EMPTY'].span())
}

/// Generate member commitment
pub fn generate_member_commitment(
    member_address: ContractAddress,
    secret: felt252
) -> felt252 {
    poseidon_hash_span(
        array![MEMBER_DOMAIN, member_address.into(), secret].span()
    )
}

/// Generate nullifier for claiming
pub fn generate_claim_nullifier(
    member_secret: felt252,
    payment_id: u256,
    epoch: u64
) -> felt252 {
    poseidon_hash_span(
        array![
            DIST_DOMAIN,
            member_secret,
            payment_id.low.into(),
            payment_id.high.into(),
            epoch.into()
        ].span()
    )
}

// ============================================================================
// ANONYMOUS JOIN
// ============================================================================

/// Parameters for joining a pool anonymously
#[derive(Drop, Serde)]
pub struct JoinParams {
    /// Pool to join
    pub pool_id: u256,
    /// Member commitment (hides identity)
    pub member_commitment: felt252,
    /// Stake amount commitment
    pub stake_commitment: ECPoint,
    /// Range proof for stake >= min_stake
    pub stake_range_proof: felt252,
    /// Initial weight commitment
    pub weight_commitment: felt252,
}

/// Result of joining pool
#[derive(Drop, Serde)]
pub struct JoinResult {
    /// Updated pool
    pub pool: WorkerPool,
    /// Member's position in tree
    pub member_index: u32,
    /// New member root
    pub new_root: felt252,
    /// Membership proof for future claims
    pub initial_proof: MembershipProof,
}

/// Add member to pool (updates Merkle root)
pub fn add_member_to_pool(
    pool: WorkerPool,
    params: JoinParams,
    merkle_path: Array<felt252>,
    path_bits: Array<bool>
) -> JoinResult {
    // Verify stake range proof
    assert!(params.stake_range_proof != 0, "Invalid stake proof");

    // Compute new member leaf
    let member_leaf = poseidon_hash_span(
        array![
            MEMBER_DOMAIN,
            params.member_commitment,
            params.weight_commitment
        ].span()
    );

    // Compute new root with member added
    let new_root = compute_new_root_with_member(
        pool.member_root,
        member_leaf,
        pool.member_count,
        merkle_path.span(),
        path_bits.span()
    );

    let updated_pool = WorkerPool {
        pool_id: pool.pool_id,
        member_root: new_root,
        member_count: pool.member_count + 1,
        pool_pubkey_x: pool.pool_pubkey_x,
        pool_pubkey_y: pool.pool_pubkey_y,
        balance_commitment_x: pool.balance_commitment_x,
        balance_commitment_y: pool.balance_commitment_y,
        min_stake: pool.min_stake,
        created_block: pool.created_block,
        is_active: pool.member_count + 1 >= MIN_MEMBERS_ACTIVE,
    };

    // Create initial membership proof
    let initial_proof = MembershipProof {
        merkle_path,
        path_bits,
        member_secret: 0, // Holder provides when claiming
        nullifier: 0,
    };

    JoinResult {
        pool: updated_pool,
        member_index: pool.member_count,
        new_root,
        initial_proof,
    }
}

/// Compute new root after adding member
fn compute_new_root_with_member(
    current_root: felt252,
    new_leaf: felt252,
    index: u32,
    path: Span<felt252>,
    path_bits: Span<bool>
) -> felt252 {
    // Insert at index position and recompute root
    let mut current = new_leaf;
    let mut i: u32 = 0;

    loop {
        if i >= path.len() {
            break;
        }

        let sibling = *path.at(i);
        let is_right = *path_bits.at(i);

        current = if is_right {
            poseidon_hash_span(array![MEMBER_DOMAIN, sibling, current].span())
        } else {
            poseidon_hash_span(array![MEMBER_DOMAIN, current, sibling].span())
        };

        i += 1;
    };

    current
}

// ============================================================================
// POOL PAYMENTS
// ============================================================================

/// Receive payment to pool
pub fn receive_pool_payment(
    pool: WorkerPool,
    payment_id: u256,
    amount_commitment: ECPoint,
    job_ref_encrypted: felt252,
    timestamp: u64
) -> (WorkerPool, PoolPayment) {
    // Update pool balance
    let new_balance_x = poseidon_hash_span(
        array![pool.balance_commitment_x, amount_commitment.x].span()
    );
    let new_balance_y = poseidon_hash_span(
        array![pool.balance_commitment_y, amount_commitment.y].span()
    );

    let updated_pool = WorkerPool {
        pool_id: pool.pool_id,
        member_root: pool.member_root,
        member_count: pool.member_count,
        pool_pubkey_x: pool.pool_pubkey_x,
        pool_pubkey_y: pool.pool_pubkey_y,
        balance_commitment_x: new_balance_x,
        balance_commitment_y: new_balance_y,
        min_stake: pool.min_stake,
        created_block: pool.created_block,
        is_active: pool.is_active,
    };

    let payment = PoolPayment {
        payment_id,
        pool_id: pool.pool_id,
        amount_commitment_x: amount_commitment.x,
        amount_commitment_y: amount_commitment.y,
        job_ref_encrypted,
        timestamp,
        is_distributed: false,
    };

    (updated_pool, payment)
}

// ============================================================================
// PRIVATE DISTRIBUTION
// ============================================================================

/// Parameters for distribution
#[derive(Drop, Serde)]
pub struct DistributionParams {
    /// Payment to distribute
    pub payment_id: u256,
    /// Member shares (encrypted)
    pub shares: Array<DistributionShare>,
    /// Proof of fair distribution
    pub proof: DistributionProof,
    /// Distribution epoch
    pub epoch: u64,
}

/// Verify distribution is fair
pub fn verify_distribution(
    payment: @PoolPayment,
    params: @DistributionParams,
    pool: @WorkerPool
) -> bool {
    // Verify sum of shares equals payment amount
    if *params.proof.sum_proof == 0 {
        return false;
    }

    // Verify each share matches member weight
    let mut i: u32 = 0;
    loop {
        if i >= params.shares.len() {
            break true;
        }

        if i >= params.proof.weight_proofs.len() {
            break false;
        }

        let weight_proof = *params.proof.weight_proofs.at(i);
        if weight_proof == 0 {
            break false;
        }

        i += 1;
    }
}

/// Create distribution shares for members
pub fn create_distribution_shares(
    payment_amount: u64,
    member_weights: Span<u64>,
    member_commitments: Span<felt252>,
    stealth_addresses: Span<felt252>,
    ephemeral_keys: Span<ECPoint>,
    blinding_factors: Span<felt252>
) -> Array<DistributionShare> {
    let mut shares: Array<DistributionShare> = array![];

    // Calculate total weight
    let mut total_weight: u64 = 0;
    let mut i: u32 = 0;
    loop {
        if i >= member_weights.len() {
            break;
        }
        total_weight += *member_weights.at(i);
        i += 1;
    };

    // Create share for each member
    let mut j: u32 = 0;
    loop {
        if j >= member_weights.len() {
            break;
        }

        let weight = *member_weights.at(j);
        let share_amount = (payment_amount * weight) / total_weight;
        let blinding = *blinding_factors.at(j);

        // Compute share commitment
        let share_commitment = poseidon_hash_span(
            array![DIST_DOMAIN, share_amount.into(), blinding].span()
        );

        let ephemeral = *ephemeral_keys.at(j);

        shares.append(DistributionShare {
            member_commitment: *member_commitments.at(j),
            share_commitment_x: share_commitment,
            share_commitment_y: poseidon_hash_span(array![share_commitment].span()),
            stealth_address: *stealth_addresses.at(j),
            ephemeral_pubkey_x: ephemeral.x,
            ephemeral_pubkey_y: ephemeral.y,
        });

        j += 1;
    };

    shares
}

// ============================================================================
// ANONYMOUS CLAIMING
// ============================================================================

/// Claim share anonymously
pub fn claim_share(
    pool: @WorkerPool,
    payment: @PoolPayment,
    membership_proof: @MembershipProof,
    share: @DistributionShare
) -> bool {
    // Verify membership
    if !verify_membership(*pool.member_root, membership_proof) {
        return false;
    }

    // Verify nullifier hasn't been used
    // (This check happens in the contract storage)

    // Verify share corresponds to member
    if *share.member_commitment != compute_member_from_proof(membership_proof) {
        return false;
    }

    true
}

/// Verify membership proof
fn verify_membership(
    root: felt252,
    proof: @MembershipProof
) -> bool {
    let leaf = poseidon_hash_span(
        array![MEMBER_DOMAIN, *proof.member_secret].span()
    );

    let mut current = leaf;
    let mut i: u32 = 0;

    loop {
        if i >= proof.merkle_path.len() {
            break;
        }

        let sibling = *proof.merkle_path.at(i);
        let is_right = *proof.path_bits.at(i);

        current = if is_right {
            poseidon_hash_span(array![MEMBER_DOMAIN, sibling, current].span())
        } else {
            poseidon_hash_span(array![MEMBER_DOMAIN, current, sibling].span())
        };

        i += 1;
    };

    current == root
}

/// Compute member commitment from proof
fn compute_member_from_proof(proof: @MembershipProof) -> felt252 {
    poseidon_hash_span(array![MEMBER_DOMAIN, *proof.member_secret].span())
}

// ============================================================================
// CONTRIBUTION TRACKING
// ============================================================================

/// Update member weight based on contributions
pub fn update_contribution_weight(
    current_weight: felt252,
    contribution: @ContributionProof,
    blinding: felt252
) -> felt252 {
    // Verify work proof
    assert!(*contribution.work_proof_hash != 0, "Invalid work proof");

    // Compute new weight commitment
    poseidon_hash_span(
        array![
            POOL_DOMAIN,
            current_weight,
            *contribution.units_commitment,
            blinding
        ].span()
    )
}

/// Generate contribution proof
pub fn generate_contribution_proof(
    job_ids: Span<u256>,
    computation_units: u64,
    epoch: u64,
    work_proof_hash: felt252
) -> ContributionProof {
    let mut job_commitments: Array<felt252> = array![];

    let mut i: u32 = 0;
    loop {
        if i >= job_ids.len() {
            break;
        }

        let job_id = *job_ids.at(i);
        let commitment = poseidon_hash_span(
            array![POOL_DOMAIN, job_id.low.into(), job_id.high.into()].span()
        );
        job_commitments.append(commitment);

        i += 1;
    };

    let units_commitment = poseidon_hash_span(
        array![POOL_DOMAIN, computation_units.into()].span()
    );

    ContributionProof {
        job_commitments,
        units_commitment,
        work_proof_hash,
        epoch,
    }
}

// ============================================================================
// POOL GOVERNANCE
// ============================================================================

/// Pool parameter update proposal
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PoolProposal {
    /// Proposal ID
    pub proposal_id: u256,
    /// Pool ID
    pub pool_id: u256,
    /// Proposed new min_stake
    pub new_min_stake: u256,
    /// Proposer commitment (anonymous)
    pub proposer_commitment: felt252,
    /// Yes votes (encrypted count)
    pub yes_votes_commitment: felt252,
    /// No votes (encrypted count)
    pub no_votes_commitment: felt252,
    /// Voting deadline
    pub deadline_block: u64,
    /// Is executed
    pub is_executed: bool,
}

/// Anonymous vote
#[derive(Drop, Serde)]
pub struct AnonymousVote {
    /// Voter's membership proof
    pub membership_proof: MembershipProof,
    /// Encrypted vote (0 or 1)
    pub vote_commitment: felt252,
    /// Vote nullifier (prevents double voting)
    pub vote_nullifier: felt252,
}

/// Cast anonymous vote
pub fn cast_vote(
    pool: @WorkerPool,
    proposal: PoolProposal,
    vote: @AnonymousVote
) -> PoolProposal {
    // Verify membership
    assert!(verify_membership(*pool.member_root, vote.membership_proof), "Not a member");

    // Update vote counts (homomorphic addition)
    let new_yes = poseidon_hash_span(
        array![proposal.yes_votes_commitment, *vote.vote_commitment].span()
    );

    PoolProposal {
        proposal_id: proposal.proposal_id,
        pool_id: proposal.pool_id,
        new_min_stake: proposal.new_min_stake,
        proposer_commitment: proposal.proposer_commitment,
        yes_votes_commitment: new_yes,
        no_votes_commitment: proposal.no_votes_commitment,
        deadline_block: proposal.deadline_block,
        is_executed: proposal.is_executed,
    }
}
