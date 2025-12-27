// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Delayed Claims System for Timing Privacy
//
// Implements:
// 1. Scheduled Claims: Set future claim time with randomization
// 2. Claim Pools: Batch claims together to hide individual timing
// 3. Decoy Scheduling: Add fake scheduled claims as cover traffic
// 4. Commit-Reveal Claims: Two-phase claiming for enhanced privacy
//
// Properties:
// - Prevents timing correlation between payment and claim
// - Claim pools provide k-anonymity for claim timing
// - Decoy traffic obscures real claim patterns

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;

// ============================================================================
// DELAYED CLAIM STRUCTURES
// ============================================================================

/// A scheduled claim commitment
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ScheduledClaim {
    /// Commitment to claim parameters (hides actual claim until execution)
    pub commitment: felt252,
    /// Earliest block when claim can be executed
    pub min_block: u64,
    /// Latest block when claim can be executed (expiry)
    pub max_block: u64,
    /// Whether this claim has been executed
    pub is_executed: bool,
    /// Whether this is a decoy (only known to creator)
    /// Note: Stored as part of commitment, not directly
    pub scheduling_timestamp: u64,
}

/// Claim commitment opening
#[derive(Drop, Serde)]
pub struct ClaimOpening {
    /// The announcement index being claimed
    pub announcement_index: u256,
    /// The recipient's address
    pub recipient: ContractAddress,
    /// Spending proof
    pub spending_proof_hash: felt252,
    /// Random nonce used in commitment
    pub nonce: felt252,
}

/// Claim pool entry
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ClaimPoolEntry {
    /// Pool identifier
    pub pool_id: u64,
    /// Claim commitment
    pub commitment: felt252,
    /// Position in pool
    pub position: u32,
    /// Block when added to pool
    pub join_block: u64,
}

/// Claim pool configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ClaimPool {
    /// Pool identifier
    pub pool_id: u64,
    /// Minimum participants before execution
    pub min_participants: u32,
    /// Current participant count
    pub current_participants: u32,
    /// Execution block (when pool executes)
    pub execution_block: u64,
    /// Whether pool has executed
    pub is_executed: bool,
    /// Pool type (0 = time-based, 1 = count-based)
    pub pool_type: u8,
}

/// Timing randomization parameters
#[derive(Copy, Drop, Serde)]
pub struct TimingParams {
    /// Minimum delay in blocks
    pub min_delay: u64,
    /// Maximum delay in blocks
    pub max_delay: u64,
    /// Random seed for delay calculation
    pub seed: felt252,
    /// Use gamma distribution for more realistic timing
    pub use_gamma_distribution: bool,
}

/// Decoy claim configuration
#[derive(Copy, Drop, Serde)]
pub struct DecoyClaimParams {
    /// Number of decoy claims to schedule
    pub decoy_count: u32,
    /// Timing spread for decoys
    pub timing_spread: u64,
    /// Random seed
    pub seed: felt252,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for claim commitments
const CLAIM_COMMIT_DOMAIN: felt252 = 'DELAYED_CLAIM';

/// Domain separator for timing
const TIMING_DOMAIN: felt252 = 'CLAIM_TIMING';

/// Domain separator for pools
const POOL_DOMAIN: felt252 = 'CLAIM_POOL';

/// Minimum delay (prevent instant claims that leak timing)
const MIN_DELAY_BLOCKS: u64 = 10; // ~20 minutes

/// Maximum delay (reasonable upper bound)
const MAX_DELAY_BLOCKS: u64 = 4320; // ~6 days

/// Default pool size for k-anonymity
const DEFAULT_POOL_SIZE: u32 = 10;

/// Pool execution timeout (blocks after target)
const POOL_TIMEOUT_BLOCKS: u64 = 100;

// ============================================================================
// COMMITMENT FUNCTIONS
// ============================================================================

/// Create a commitment to a future claim
pub fn create_claim_commitment(
    announcement_index: u256,
    recipient: ContractAddress,
    spending_proof_hash: felt252,
    nonce: felt252
) -> felt252 {
    poseidon_hash_span(
        array![
            CLAIM_COMMIT_DOMAIN,
            announcement_index.low.into(),
            announcement_index.high.into(),
            recipient.into(),
            spending_proof_hash,
            nonce
        ].span()
    )
}

/// Verify a claim commitment opening
pub fn verify_claim_opening(
    commitment: felt252,
    opening: @ClaimOpening
) -> bool {
    let expected = create_claim_commitment(
        *opening.announcement_index,
        *opening.recipient,
        *opening.spending_proof_hash,
        *opening.nonce
    );

    commitment == expected
}

// ============================================================================
// TIMING RANDOMIZATION
// ============================================================================

/// Calculate randomized delay using configurable distribution
pub fn calculate_random_delay(
    params: TimingParams,
    current_block: u64
) -> (u64, u64) {
    // Ensure bounds are valid
    let min = if params.min_delay < MIN_DELAY_BLOCKS {
        MIN_DELAY_BLOCKS
    } else {
        params.min_delay
    };

    let max = if params.max_delay > MAX_DELAY_BLOCKS {
        MAX_DELAY_BLOCKS
    } else if params.max_delay < min {
        min + 100
    } else {
        params.max_delay
    };

    // Generate random delay
    let delay = if params.use_gamma_distribution {
        calculate_gamma_delay(params.seed, min, max)
    } else {
        calculate_uniform_delay(params.seed, min, max)
    };

    let min_block = current_block + delay;
    let max_block = min_block + POOL_TIMEOUT_BLOCKS;

    (min_block, max_block)
}

/// Uniform random delay between min and max
fn calculate_uniform_delay(seed: felt252, min: u64, max: u64) -> u64 {
    let hash = poseidon_hash_span(array![TIMING_DOMAIN, seed, 'UNIFORM'].span());
    let hash_u256: u256 = hash.into();

    let range = max - min;
    let delay: u64 = (hash_u256 % range.into()).try_into().unwrap();

    min + delay
}

/// Gamma-distributed delay (models real user behavior better)
/// Most users claim relatively quickly, with long tail
fn calculate_gamma_delay(seed: felt252, min: u64, max: u64) -> u64 {
    // Simplified gamma approximation using multiple uniform samples
    let hash1 = poseidon_hash_span(array![TIMING_DOMAIN, seed, 'G1'].span());
    let hash2 = poseidon_hash_span(array![TIMING_DOMAIN, seed, 'G2'].span());
    let hash3 = poseidon_hash_span(array![TIMING_DOMAIN, seed, 'G3'].span());

    let h1_u256: u256 = hash1.into();
    let h2_u256: u256 = hash2.into();
    let h3_u256: u256 = hash3.into();

    let range = max - min;

    // Sum of uniform samples approximates gamma
    let s1: u64 = (h1_u256 % range.into()).try_into().unwrap();
    let s2: u64 = (h2_u256 % range.into()).try_into().unwrap();
    let s3: u64 = (h3_u256 % range.into()).try_into().unwrap();

    // Average and scale to range
    let avg = (s1 + s2 + s3) / 3;
    let scaled = avg / 2; // Bias toward shorter delays

    min + scaled
}

// ============================================================================
// SCHEDULED CLAIM MANAGEMENT
// ============================================================================

/// Schedule a claim for future execution
pub fn schedule_claim(
    announcement_index: u256,
    recipient: ContractAddress,
    spending_proof_hash: felt252,
    timing: TimingParams,
    current_block: u64,
    current_timestamp: u64
) -> (ScheduledClaim, felt252) {
    // Generate random nonce
    let nonce = poseidon_hash_span(
        array![timing.seed, current_block.into(), recipient.into()].span()
    );

    // Create commitment
    let commitment = create_claim_commitment(
        announcement_index,
        recipient,
        spending_proof_hash,
        nonce
    );

    // Calculate execution window
    let (min_block, max_block) = calculate_random_delay(timing, current_block);

    let scheduled = ScheduledClaim {
        commitment,
        min_block,
        max_block,
        is_executed: false,
        scheduling_timestamp: current_timestamp,
    };

    (scheduled, nonce)
}

/// Check if a scheduled claim can be executed now
pub fn can_execute_claim(
    claim: @ScheduledClaim,
    current_block: u64
) -> bool {
    if *claim.is_executed {
        return false;
    }

    current_block >= *claim.min_block && current_block <= *claim.max_block
}

/// Check if a scheduled claim has expired
pub fn is_claim_expired(
    claim: @ScheduledClaim,
    current_block: u64
) -> bool {
    current_block > *claim.max_block && !*claim.is_executed
}

// ============================================================================
// CLAIM POOLS
// ============================================================================

/// Create a new claim pool
pub fn create_claim_pool(
    pool_id: u64,
    min_participants: u32,
    execution_block: u64,
    pool_type: u8
) -> ClaimPool {
    ClaimPool {
        pool_id,
        min_participants,
        current_participants: 0,
        execution_block,
        is_executed: false,
        pool_type,
    }
}

/// Join a claim pool
pub fn join_claim_pool(
    pool: ClaimPool,
    commitment: felt252,
    current_block: u64
) -> (ClaimPool, ClaimPoolEntry) {
    let entry = ClaimPoolEntry {
        pool_id: pool.pool_id,
        commitment,
        position: pool.current_participants,
        join_block: current_block,
    };

    let updated_pool = ClaimPool {
        pool_id: pool.pool_id,
        min_participants: pool.min_participants,
        current_participants: pool.current_participants + 1,
        execution_block: pool.execution_block,
        is_executed: pool.is_executed,
        pool_type: pool.pool_type,
    };

    (updated_pool, entry)
}

/// Check if pool is ready to execute
pub fn is_pool_ready(
    pool: @ClaimPool,
    current_block: u64
) -> bool {
    if *pool.is_executed {
        return false;
    }

    // Time-based pool
    if *pool.pool_type == 0 {
        return current_block >= *pool.execution_block;
    }

    // Count-based pool
    if *pool.pool_type == 1 {
        return *pool.current_participants >= *pool.min_participants;
    }

    false
}

/// Get anonymity set size for a pool
pub fn get_pool_anonymity_set(pool: @ClaimPool) -> u32 {
    *pool.current_participants
}

// ============================================================================
// DECOY CLAIMS
// ============================================================================

/// Generate decoy claim schedules
/// These look like real claims but don't correspond to actual payments
pub fn generate_decoy_claims(
    params: DecoyClaimParams,
    current_block: u64,
    current_timestamp: u64
) -> Array<ScheduledClaim> {
    let mut decoys: Array<ScheduledClaim> = array![];
    let mut current_seed = params.seed;

    let mut i: u32 = 0;
    loop {
        if i >= params.decoy_count {
            break;
        }

        // Generate fake commitment
        let fake_commitment = poseidon_hash_span(
            array!['DECOY', current_seed, i.into()].span()
        );

        // Random timing within spread
        let delay_hash = poseidon_hash_span(
            array![TIMING_DOMAIN, current_seed, 'DECOY_DELAY'].span()
        );
        let delay_u256: u256 = delay_hash.into();
        let delay: u64 = (delay_u256 % params.timing_spread.into()).try_into().unwrap();

        let decoy = ScheduledClaim {
            commitment: fake_commitment,
            min_block: current_block + delay + MIN_DELAY_BLOCKS,
            max_block: current_block + delay + MIN_DELAY_BLOCKS + POOL_TIMEOUT_BLOCKS,
            is_executed: false,
            scheduling_timestamp: current_timestamp,
        };

        decoys.append(decoy);
        current_seed = delay_hash;
        i += 1;
    };

    decoys
}

/// Check if a claim is a decoy (for internal use)
/// Note: From external perspective, decoys are indistinguishable
fn is_decoy_claim(commitment: felt252, decoy_marker: felt252) -> bool {
    // Decoys have a specific structure in their commitment
    let marker_check = poseidon_hash_span(
        array!['DECOY_CHECK', commitment, decoy_marker].span()
    );
    marker_check == commitment
}

// ============================================================================
// COMMIT-REVEAL SCHEME
// ============================================================================

/// Phase 1: Commit to claiming (hides which payment)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ClaimCommitPhase {
    /// Commitment hash
    pub commitment: felt252,
    /// Block when committed
    pub commit_block: u64,
    /// Minimum blocks before reveal
    pub reveal_delay: u64,
    /// Maximum blocks before expiry
    pub expiry_blocks: u64,
}

/// Phase 2: Reveal opening to execute claim
#[derive(Drop, Serde)]
pub struct ClaimRevealPhase {
    /// The commitment being revealed
    pub commitment: felt252,
    /// Full opening data
    pub opening: ClaimOpening,
    /// Block when revealed
    pub reveal_block: u64,
}

/// Create commit phase
pub fn create_commit_phase(
    commitment: felt252,
    current_block: u64,
    reveal_delay: u64,
    expiry_blocks: u64
) -> ClaimCommitPhase {
    ClaimCommitPhase {
        commitment,
        commit_block: current_block,
        reveal_delay,
        expiry_blocks,
    }
}

/// Check if reveal is allowed
pub fn can_reveal(
    commit: @ClaimCommitPhase,
    current_block: u64
) -> bool {
    let reveal_block = *commit.commit_block + *commit.reveal_delay;
    let expiry_block = *commit.commit_block + *commit.expiry_blocks;

    current_block >= reveal_block && current_block <= expiry_block
}

/// Verify reveal against commitment
pub fn verify_reveal(
    commit: @ClaimCommitPhase,
    reveal: @ClaimRevealPhase
) -> bool {
    *commit.commitment == *reveal.commitment
        && verify_claim_opening(*commit.commitment, reveal.opening)
}

// ============================================================================
// TIMING ANALYSIS RESISTANCE
// ============================================================================

/// Statistics about claim timing (for analysis)
#[derive(Copy, Drop, Serde)]
pub struct ClaimTimingStats {
    /// Average delay from payment to claim
    pub avg_delay_blocks: u64,
    /// Standard deviation of delays
    pub std_dev_blocks: u64,
    /// Minimum observed delay
    pub min_delay_blocks: u64,
    /// Maximum observed delay
    pub max_delay_blocks: u64,
    /// Number of claims analyzed
    pub sample_count: u64,
}

/// Calculate recommended timing params based on current network activity
pub fn calculate_recommended_timing(
    stats: ClaimTimingStats
) -> TimingParams {
    // Use 1-2 standard deviations for blending
    let min = stats.avg_delay_blocks - stats.std_dev_blocks;
    let max = stats.avg_delay_blocks + (stats.std_dev_blocks * 2);

    TimingParams {
        min_delay: if min < MIN_DELAY_BLOCKS { MIN_DELAY_BLOCKS } else { min },
        max_delay: if max > MAX_DELAY_BLOCKS { MAX_DELAY_BLOCKS } else { max },
        seed: 0, // Should be set by caller
        use_gamma_distribution: true,
    }
}

/// Calculate entropy of claim timing (higher = more private)
pub fn calculate_timing_entropy(
    claims: Span<ScheduledClaim>,
    bucket_size: u64
) -> u64 {
    // Simple entropy calculation based on timing distribution
    // Full implementation would use Shannon entropy
    if claims.len() == 0 {
        return 0;
    }

    // Count claims per time bucket
    let mut _bucket_counts: Array<u32> = array![];
    let mut _total_buckets: u32 = 0;

    // For now, return simple diversity metric
    let mut unique_times: u32 = 0;
    let mut i: u32 = 0;
    let mut prev_bucket: u64 = 0;

    loop {
        if i >= claims.len() {
            break;
        }

        let claim = *claims.at(i);
        let bucket = claim.min_block / bucket_size;

        if bucket != prev_bucket || i == 0 {
            unique_times += 1;
            prev_bucket = bucket;
        }

        i += 1;
    };

    // Normalize to 0-100 scale
    let diversity = (unique_times * 100) / claims.len();
    diversity.into()
}
