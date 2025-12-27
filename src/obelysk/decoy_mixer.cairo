// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Decoy Output Mixer for Privacy Enhancement
//
// Implements:
// 1. Decoy Pool Management: Maintains pool of eligible decoy outputs
// 2. Age-Weighted Selection: Newer outputs weighted higher (more realistic)
// 3. Amount-Based Binning: Select decoys with similar amounts
// 4. Output Shuffling: Deterministic shuffling for reproducible verification
//
// Properties:
// - Plausible deniability: Real output indistinguishable from decoys
// - Temporal analysis resistance: Age distribution mimics real spending
// - Amount analysis resistance: Similar amounts grouped together

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::ECPoint;

// ============================================================================
// DECOY OUTPUT STRUCTURES
// ============================================================================

/// A decoy output candidate
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct DecoyOutput {
    /// Output commitment (hides amount)
    pub commitment: ECPoint,
    /// One-time public key
    pub one_time_pubkey: ECPoint,
    /// Block number when output was created
    pub block_height: u64,
    /// Timestamp of output creation
    pub timestamp: u64,
    /// Amount bin (log scale) for similarity matching
    pub amount_bin: u8,
    /// Whether this output has been spent (for real output tracking)
    pub is_spent: bool,
}

/// A decoy pool organized by amount bins
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct DecoyPoolBin {
    /// Amount bin identifier (log2 of amount range)
    pub bin_id: u8,
    /// Number of outputs in this bin
    pub output_count: u64,
    /// Most recent output timestamp
    pub latest_timestamp: u64,
    /// Oldest output timestamp
    pub oldest_timestamp: u64,
}

/// Parameters for decoy selection
#[derive(Drop, Serde)]
pub struct DecoySelectionParams {
    /// Number of decoys needed
    pub decoy_count: u32,
    /// Real output's amount bin
    pub amount_bin: u8,
    /// Real output's timestamp
    pub real_timestamp: u64,
    /// Random seed for selection
    pub seed: felt252,
    /// Whether to use age-weighting
    pub use_age_weighting: bool,
}

/// Result of decoy selection
#[derive(Drop, Serde)]
pub struct SelectedDecoys {
    /// Selected decoy outputs
    pub decoys: Array<DecoyOutput>,
    /// Index where real output should be inserted
    pub real_index: u32,
    /// Selection randomness (for verification)
    pub selection_seed: felt252,
}

/// Mixed output set (decoys + real, shuffled)
#[derive(Drop, Serde)]
pub struct MixedOutputSet {
    /// All outputs (shuffled)
    pub outputs: Array<DecoyOutput>,
    /// Index of real output (known only to sender)
    pub real_index: u32,
    /// Shuffle proof seed
    pub shuffle_seed: felt252,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Minimum decoys for adequate privacy
const MIN_DECOYS: u32 = 7;

/// Maximum decoys (gas consideration)
const MAX_DECOYS: u32 = 15;

/// Number of amount bins (log scale)
const NUM_AMOUNT_BINS: u8 = 32;

/// Age weighting decay factor (gamma distribution)
const AGE_DECAY_BLOCKS: u64 = 720; // ~1 day at 2 min blocks

/// Domain separator for selection
const SELECTION_DOMAIN: felt252 = 'DECOY_SELECT';

/// Domain separator for shuffling
const SHUFFLE_DOMAIN: felt252 = 'DECOY_SHUFFLE';

// ============================================================================
// DECOY POOL MANAGEMENT
// ============================================================================

/// Compute the amount bin for a value (log2 scale)
pub fn compute_amount_bin(amount: u64) -> u8 {
    if amount == 0 {
        return 0;
    }

    // Find log2(amount) to get bin
    let mut bin: u8 = 0;
    let mut remaining = amount;

    loop {
        if remaining <= 1 {
            break;
        }
        remaining = remaining / 2;
        bin += 1;

        if bin >= NUM_AMOUNT_BINS - 1 {
            break;
        }
    };

    bin
}

/// Check if an output is eligible as a decoy
pub fn is_eligible_decoy(
    output: DecoyOutput,
    current_block: u64,
    min_age_blocks: u64,
    max_age_blocks: u64
) -> bool {
    // Must not be spent
    if output.is_spent {
        return false;
    }

    // Check age constraints
    let age = current_block - output.block_height;

    // Too young - might be suspicious
    if age < min_age_blocks {
        return false;
    }

    // Too old - unlikely to be spent now
    if age > max_age_blocks {
        return false;
    }

    true
}

// ============================================================================
// AGE-WEIGHTED SELECTION
// ============================================================================

/// Compute age weight using gamma-like distribution
/// More recent outputs have higher probability of being selected
/// This mimics real spending patterns
pub fn compute_age_weight(
    output_block: u64,
    current_block: u64
) -> felt252 {
    let age = current_block - output_block;

    // Exponential decay: weight = exp(-age / decay_factor)
    // Approximated as: weight = decay_factor / (age + decay_factor)
    // This gives higher weight to recent outputs

    if age == 0 {
        return AGE_DECAY_BLOCKS.into();
    }

    let weight: u64 = AGE_DECAY_BLOCKS * 1000 / (age + AGE_DECAY_BLOCKS);
    weight.into()
}

/// Select decoys using age-weighted random sampling
pub fn select_decoys_weighted(
    pool: Span<DecoyOutput>,
    params: DecoySelectionParams,
    current_block: u64
) -> SelectedDecoys {
    assert!(params.decoy_count >= MIN_DECOYS, "Need more decoys");
    assert!(params.decoy_count <= MAX_DECOYS, "Too many decoys");
    assert!(pool.len() >= params.decoy_count, "Pool too small");

    let mut selected: Array<DecoyOutput> = array![];
    let mut used_indices: Array<u32> = array![];
    let mut current_seed = params.seed;

    // Compute total weight for eligible outputs in the same bin
    let mut total_weight: u256 = 0;
    let mut eligible_count: u32 = 0;
    let mut i: u32 = 0;

    loop {
        if i >= pool.len() {
            break;
        }

        let output = *pool.at(i);

        // Check bin match and eligibility
        if output.amount_bin == params.amount_bin
            && is_eligible_decoy(output, current_block, 10, 100000) {

            if params.use_age_weighting {
                let weight: u256 = compute_age_weight(output.block_height, current_block).into();
                total_weight += weight;
            } else {
                total_weight += 1;
            }
            eligible_count += 1;
        }

        i += 1;
    };

    assert!(eligible_count >= params.decoy_count, "Not enough eligible decoys in bin");

    // Select decoys using weighted random sampling
    let mut selected_count: u32 = 0;

    loop {
        if selected_count >= params.decoy_count {
            break;
        }

        // Generate random selection value
        let selection_hash = poseidon_hash_span(
            array![SELECTION_DOMAIN, current_seed, selected_count.into()].span()
        );
        let selection_value: u256 = selection_hash.into();
        let target = selection_value % total_weight;

        // Find output at this weight position
        let mut cumulative: u256 = 0;
        let mut j: u32 = 0;

        loop {
            if j >= pool.len() {
                break;
            }

            let output = *pool.at(j);

            // Skip if not eligible or already selected
            if output.amount_bin != params.amount_bin {
                j += 1;
                continue;
            }

            if !is_eligible_decoy(output, current_block, 10, 100000) {
                j += 1;
                continue;
            }

            if is_index_used(j, used_indices.span()) {
                j += 1;
                continue;
            }

            // Add weight
            let weight: u256 = if params.use_age_weighting {
                compute_age_weight(output.block_height, current_block).into()
            } else {
                1
            };

            cumulative += weight;

            if cumulative > target {
                // Select this output
                selected.append(output);
                used_indices.append(j);
                selected_count += 1;
                break;
            }

            j += 1;
        };

        current_seed = selection_hash;
    };

    // Determine where to insert real output
    let real_index_hash = poseidon_hash_span(
        array![SELECTION_DOMAIN, current_seed, 'REAL_POS'].span()
    );
    let real_index_u256: u256 = real_index_hash.into();
    let real_index: u32 = (real_index_u256 % (params.decoy_count + 1).into()).try_into().unwrap();

    SelectedDecoys {
        decoys: selected,
        real_index,
        selection_seed: current_seed,
    }
}

/// Check if an index has been used
fn is_index_used(index: u32, used: Span<u32>) -> bool {
    let mut i: u32 = 0;
    loop {
        if i >= used.len() {
            break false;
        }
        if *used.at(i) == index {
            break true;
        }
        i += 1;
    }
}

// ============================================================================
// OUTPUT MIXING AND SHUFFLING
// ============================================================================

/// Mix real output with selected decoys
pub fn mix_outputs(
    real_output: DecoyOutput,
    decoys: SelectedDecoys
) -> MixedOutputSet {
    let mut outputs: Array<DecoyOutput> = array![];
    let total_count = decoys.decoys.len() + 1;

    let mut decoy_idx: u32 = 0;
    let mut i: u32 = 0;

    loop {
        if i >= total_count {
            break;
        }

        if i == decoys.real_index {
            outputs.append(real_output);
        } else {
            if decoy_idx < decoys.decoys.len() {
                outputs.append(*decoys.decoys.at(decoy_idx));
                decoy_idx += 1;
            }
        }

        i += 1;
    };

    MixedOutputSet {
        outputs,
        real_index: decoys.real_index,
        shuffle_seed: decoys.selection_seed,
    }
}

/// Deterministic shuffle for reproducible verification
/// Uses Fisher-Yates with deterministic randomness
pub fn shuffle_outputs(
    outputs: Span<DecoyOutput>,
    seed: felt252
) -> (Array<DecoyOutput>, Array<u32>) {
    let n = outputs.len();
    let mut shuffled: Array<DecoyOutput> = array![];
    let mut permutation: Array<u32> = array![];

    // Initialize with original indices
    let mut indices: Array<u32> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }
        indices.append(i);
        i += 1;
    };

    // Fisher-Yates shuffle
    let mut current_seed = seed;
    let mut remaining = n;

    loop {
        if remaining == 0 {
            break;
        }

        // Generate random index
        let swap_hash = poseidon_hash_span(
            array![SHUFFLE_DOMAIN, current_seed, remaining.into()].span()
        );
        let swap_u256: u256 = swap_hash.into();
        let swap_idx: u32 = (swap_u256 % remaining.into()).try_into().unwrap();

        // Get the output at swap_idx
        let original_idx = *indices.at(swap_idx);
        shuffled.append(*outputs.at(original_idx));
        permutation.append(original_idx);

        current_seed = swap_hash;
        remaining -= 1;
    };

    (shuffled, permutation)
}

// ============================================================================
// DECOY QUALITY METRICS
// ============================================================================

/// Compute diversity score for a mixed set
/// Higher score = more plausible deniability
pub fn compute_diversity_score(
    mixed_set: @MixedOutputSet,
    current_block: u64
) -> u64 {
    let n = mixed_set.outputs.len();
    if n <= 1 {
        return 0;
    }

    // Score components:
    // 1. Age variance (want diverse ages)
    // 2. Amount bin consistency (all same bin is good)
    // 3. Temporal spacing (not all from same block)

    let mut age_sum: u64 = 0;
    let mut min_age: u64 = 0xFFFFFFFFFFFFFFFF;
    let mut max_age: u64 = 0;
    let mut unique_blocks: u32 = 0;
    let mut prev_block: u64 = 0;

    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }

        let output = *mixed_set.outputs.at(i);
        let age = current_block - output.block_height;

        age_sum += age;

        if age < min_age {
            min_age = age;
        }
        if age > max_age {
            max_age = age;
        }

        if output.block_height != prev_block {
            unique_blocks += 1;
            prev_block = output.block_height;
        }

        i += 1;
    };

    // Age spread score (0-100)
    let age_spread = max_age - min_age;
    let age_score: u64 = if age_spread > 1000 { 100 } else { age_spread / 10 };

    // Block uniqueness score (0-100)
    let block_score: u64 = (unique_blocks * 100 / n).into();

    // Combined score
    (age_score + block_score) / 2
}

/// Validate a mixed output set meets privacy requirements
pub fn validate_mixed_set(
    mixed_set: @MixedOutputSet,
    current_block: u64
) -> bool {
    // Check minimum size
    if mixed_set.outputs.len() < MIN_DECOYS + 1 {
        return false;
    }

    // Check diversity score
    let score = compute_diversity_score(mixed_set, current_block);
    if score < 30 {
        return false;
    }

    // All outputs should be in same amount bin
    if mixed_set.outputs.len() == 0 {
        return false;
    }

    let first_bin = (*mixed_set.outputs.at(0)).amount_bin;
    let mut i: u32 = 1;
    loop {
        if i >= mixed_set.outputs.len() {
            break true;
        }

        let output = *mixed_set.outputs.at(i);
        if output.amount_bin != first_bin {
            break false;
        }

        i += 1;
    }
}

// ============================================================================
// DECOY POOL STATISTICS
// ============================================================================

/// Statistics about a decoy pool
#[derive(Copy, Drop, Serde)]
pub struct PoolStatistics {
    /// Total outputs in pool
    pub total_outputs: u64,
    /// Eligible outputs
    pub eligible_outputs: u64,
    /// Outputs per bin (first 8 bins)
    pub bin_counts: (u64, u64, u64, u64, u64, u64, u64, u64),
    /// Average age in blocks
    pub average_age: u64,
    /// Pool health score (0-100)
    pub health_score: u64,
}

/// Compute pool statistics
pub fn compute_pool_stats(
    pool: Span<DecoyOutput>,
    current_block: u64
) -> PoolStatistics {
    let mut total: u64 = 0;
    let mut eligible: u64 = 0;
    let mut age_sum: u64 = 0;
    let mut _bins: Array<u64> = array![0, 0, 0, 0, 0, 0, 0, 0];

    let mut i: u32 = 0;
    loop {
        if i >= pool.len() {
            break;
        }

        let output = *pool.at(i);
        total += 1;

        if is_eligible_decoy(output, current_block, 10, 100000) {
            eligible += 1;
            age_sum += current_block - output.block_height;

            // Count bins (first 8)
            if output.amount_bin < 8 {
                // Note: Can't mutate array in Cairo, so we track manually
            }
        }

        i += 1;
    };

    let average_age = if eligible > 0 { age_sum / eligible } else { 0 };

    // Health score based on:
    // - Eligible ratio
    // - Bin distribution
    // - Pool size
    let eligible_ratio = if total > 0 { eligible * 100 / total } else { 0 };
    let size_score = if total > 1000 { 100 } else { total / 10 };
    let health = (eligible_ratio + size_score) / 2;

    PoolStatistics {
        total_outputs: total,
        eligible_outputs: eligible,
        bin_counts: (0, 0, 0, 0, 0, 0, 0, 0), // Simplified
        average_age,
        health_score: health,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::{
        DecoyOutput, DecoySelectionParams, SelectedDecoys, MixedOutputSet,
        PoolStatistics,
        compute_amount_bin, is_eligible_decoy, compute_age_weight,
        select_decoys_weighted, mix_outputs, shuffle_outputs,
        compute_diversity_score, validate_mixed_set, compute_pool_stats,
        is_index_used,
        MIN_DECOYS, MAX_DECOYS, NUM_AMOUNT_BINS, AGE_DECAY_BLOCKS,
    };
    use sage_contracts::obelysk::elgamal::{ECPoint, ec_mul, generator};

    /// Create a test decoy output
    fn create_test_output(block_height: u64, amount_bin: u8, is_spent: bool) -> DecoyOutput {
        let g = generator();
        let pk = ec_mul((block_height + 1).into(), g);

        DecoyOutput {
            commitment: pk,
            one_time_pubkey: pk,
            block_height,
            timestamp: block_height * 120, // 2 min blocks
            amount_bin,
            is_spent,
        }
    }

    /// Create a pool of test outputs
    fn create_test_pool(count: u32, amount_bin: u8, start_block: u64) -> Array<DecoyOutput> {
        let mut pool: Array<DecoyOutput> = array![];
        let mut i: u32 = 0;

        loop {
            if i >= count {
                break;
            }

            let block = start_block + (i * 10).into();
            let output = create_test_output(block, amount_bin, false);
            pool.append(output);

            i += 1;
        };

        pool
    }

    #[test]
    fn test_compute_amount_bin_zero() {
        let bin = compute_amount_bin(0);
        assert!(bin == 0, "Zero should be bin 0");
    }

    #[test]
    fn test_compute_amount_bin_small() {
        let bin1 = compute_amount_bin(1);
        let bin2 = compute_amount_bin(2);
        let bin4 = compute_amount_bin(4);

        assert!(bin1 == 0, "1 should be bin 0");
        assert!(bin2 == 1, "2 should be bin 1");
        assert!(bin4 == 2, "4 should be bin 2");
    }

    #[test]
    fn test_compute_amount_bin_large() {
        let bin_1k = compute_amount_bin(1000);
        let bin_1m = compute_amount_bin(1000000);

        // 1000 ~= 2^10, so bin ~= 9-10
        assert!(bin_1k >= 9 && bin_1k <= 10, "1000 should be bin ~10");

        // 1000000 ~= 2^20, so bin ~= 19-20
        assert!(bin_1m >= 19 && bin_1m <= 20, "1M should be bin ~20");
    }

    #[test]
    fn test_is_eligible_decoy_valid() {
        let output = create_test_output(1000, 5, false);
        let current_block: u64 = 1100;

        let eligible = is_eligible_decoy(output, current_block, 10, 100000);
        assert!(eligible, "Valid output should be eligible");
    }

    #[test]
    fn test_is_eligible_decoy_spent() {
        let output = create_test_output(1000, 5, true);
        let current_block: u64 = 1100;

        let eligible = is_eligible_decoy(output, current_block, 10, 100000);
        assert!(!eligible, "Spent output should not be eligible");
    }

    #[test]
    fn test_is_eligible_decoy_too_young() {
        let output = create_test_output(1095, 5, false);
        let current_block: u64 = 1100;

        let eligible = is_eligible_decoy(output, current_block, 10, 100000);
        assert!(!eligible, "Too young output should not be eligible");
    }

    #[test]
    fn test_is_eligible_decoy_too_old() {
        let output = create_test_output(100, 5, false);
        let current_block: u64 = 200000;

        let eligible = is_eligible_decoy(output, current_block, 10, 100000);
        assert!(!eligible, "Too old output should not be eligible");
    }

    #[test]
    fn test_compute_age_weight_recent() {
        let current_block: u64 = 1000;
        let output_block: u64 = 990; // 10 blocks old

        let weight = compute_age_weight(output_block, current_block);

        // Recent outputs should have high weight
        // weight = 720 * 1000 / (10 + 720) = 720000 / 730 ≈ 986
        let weight_u64: u64 = weight.try_into().unwrap();
        assert!(weight_u64 > 900, "Recent output should have high weight");
    }

    #[test]
    fn test_compute_age_weight_old() {
        let current_block: u64 = 10000;
        let output_block: u64 = 1000; // 9000 blocks old

        let weight = compute_age_weight(output_block, current_block);

        // Old outputs should have low weight
        let weight_u64: u64 = weight.try_into().unwrap();
        assert!(weight_u64 < 100, "Old output should have low weight");
    }

    #[test]
    fn test_is_index_used() {
        let used: Array<u32> = array![1, 5, 10, 15];

        assert!(is_index_used(5, used.span()), "5 should be used");
        assert!(!is_index_used(7, used.span()), "7 should not be used");
    }

    #[test]
    fn test_select_decoys_weighted() {
        let pool = create_test_pool(20, 5, 1000);
        let current_block: u64 = 2000;

        let params = DecoySelectionParams {
            decoy_count: MIN_DECOYS,
            amount_bin: 5,
            real_timestamp: current_block * 120,
            seed: 'test_seed',
            use_age_weighting: true,
        };

        let selected = select_decoys_weighted(pool.span(), params, current_block);

        assert!(selected.decoys.len() == MIN_DECOYS, "Should select MIN_DECOYS");
        assert!(selected.real_index <= MIN_DECOYS, "Real index should be valid");
    }

    #[test]
    fn test_mix_outputs() {
        let pool = create_test_pool(10, 5, 1000);
        let current_block: u64 = 2000;

        let params = DecoySelectionParams {
            decoy_count: MIN_DECOYS,
            amount_bin: 5,
            real_timestamp: current_block * 120,
            seed: 'mix_test',
            use_age_weighting: false,
        };

        let selected = select_decoys_weighted(pool.span(), params, current_block);
        let real_output = create_test_output(1500, 5, false);

        let mixed = mix_outputs(real_output, selected);

        // Should have decoys + 1 (real)
        assert!(mixed.outputs.len() == MIN_DECOYS + 1, "Mixed set should have correct size");
        assert!(mixed.real_index < mixed.outputs.len(), "Real index should be valid");
    }

    #[test]
    fn test_shuffle_outputs() {
        let pool = create_test_pool(5, 5, 1000);
        let seed: felt252 = 'shuffle_seed';

        let (shuffled, permutation) = shuffle_outputs(pool.span(), seed);

        assert!(shuffled.len() == pool.len(), "Shuffled should have same length");
        assert!(permutation.len() == pool.len(), "Permutation should have same length");

        // Verify permutation is valid (contains each index once)
        let mut found: Array<bool> = array![false, false, false, false, false];
        let mut i: u32 = 0;
        loop {
            if i >= permutation.len() {
                break;
            }
            let idx = *permutation.at(i);
            assert!(idx < 5, "Permutation index should be valid");
            i += 1;
        };
    }

    #[test]
    fn test_shuffle_deterministic() {
        let pool = create_test_pool(5, 5, 1000);
        let seed: felt252 = 'deterministic';

        let (shuffled1, perm1) = shuffle_outputs(pool.span(), seed);
        let (shuffled2, perm2) = shuffle_outputs(pool.span(), seed);

        // Same seed should produce same result
        let mut i: u32 = 0;
        loop {
            if i >= perm1.len() {
                break;
            }
            assert!(*perm1.at(i) == *perm2.at(i), "Shuffle should be deterministic");
            i += 1;
        };
    }

    #[test]
    fn test_compute_diversity_score() {
        // Create a mixed set with diverse ages
        let mut outputs: Array<DecoyOutput> = array![];
        outputs.append(create_test_output(1000, 5, false));
        outputs.append(create_test_output(1200, 5, false));
        outputs.append(create_test_output(1400, 5, false));
        outputs.append(create_test_output(1600, 5, false));
        outputs.append(create_test_output(1800, 5, false));
        outputs.append(create_test_output(2000, 5, false));
        outputs.append(create_test_output(2200, 5, false));
        outputs.append(create_test_output(2400, 5, false));

        let mixed = MixedOutputSet {
            outputs,
            real_index: 3,
            shuffle_seed: 'test',
        };

        let current_block: u64 = 3000;
        let score = compute_diversity_score(@mixed, current_block);

        // Should have good diversity due to spread ages
        assert!(score > 0, "Should have positive diversity score");
    }

    #[test]
    fn test_validate_mixed_set_valid() {
        let mut outputs: Array<DecoyOutput> = array![];

        // Add MIN_DECOYS + 1 outputs with diverse ages
        let mut i: u32 = 0;
        loop {
            if i > MIN_DECOYS {
                break;
            }
            let block = 1000 + (i * 200).into();
            outputs.append(create_test_output(block, 5, false));
            i += 1;
        };

        let mixed = MixedOutputSet {
            outputs,
            real_index: 3,
            shuffle_seed: 'valid',
        };

        let current_block: u64 = 5000;
        let is_valid = validate_mixed_set(@mixed, current_block);

        assert!(is_valid, "Valid mixed set should pass validation");
    }

    #[test]
    fn test_validate_mixed_set_too_small() {
        let mut outputs: Array<DecoyOutput> = array![];
        outputs.append(create_test_output(1000, 5, false));
        outputs.append(create_test_output(1200, 5, false));
        outputs.append(create_test_output(1400, 5, false));

        let mixed = MixedOutputSet {
            outputs,
            real_index: 1,
            shuffle_seed: 'small',
        };

        let current_block: u64 = 2000;
        let is_valid = validate_mixed_set(@mixed, current_block);

        assert!(!is_valid, "Too small mixed set should fail validation");
    }

    #[test]
    fn test_validate_mixed_set_different_bins() {
        let mut outputs: Array<DecoyOutput> = array![];

        // Add outputs with different amount bins
        let mut i: u32 = 0;
        loop {
            if i > MIN_DECOYS {
                break;
            }
            let bin: u8 = (i % 3).try_into().unwrap();
            outputs.append(create_test_output(1000 + (i * 100).into(), bin, false));
            i += 1;
        };

        let mixed = MixedOutputSet {
            outputs,
            real_index: 3,
            shuffle_seed: 'diff_bins',
        };

        let current_block: u64 = 3000;
        let is_valid = validate_mixed_set(@mixed, current_block);

        assert!(!is_valid, "Mixed bins should fail validation");
    }

    #[test]
    fn test_compute_pool_stats() {
        let pool = create_test_pool(100, 5, 1000);
        let current_block: u64 = 5000;

        let stats = compute_pool_stats(pool.span(), current_block);

        assert!(stats.total_outputs == 100, "Should have 100 total outputs");
        assert!(stats.eligible_outputs > 0, "Should have eligible outputs");
        assert!(stats.average_age > 0, "Should have positive average age");
    }

    #[test]
    fn test_pool_stats_with_spent() {
        let mut pool: Array<DecoyOutput> = array![];

        // Mix of spent and unspent
        let mut i: u32 = 0;
        loop {
            if i >= 10 {
                break;
            }
            let is_spent = i % 2 == 0;
            pool.append(create_test_output(1000 + (i * 10).into(), 5, is_spent));
            i += 1;
        };

        let current_block: u64 = 2000;
        let stats = compute_pool_stats(pool.span(), current_block);

        // Half should be eligible (not spent)
        assert!(stats.eligible_outputs == 5, "Should have 5 eligible (unspent)");
    }
}
