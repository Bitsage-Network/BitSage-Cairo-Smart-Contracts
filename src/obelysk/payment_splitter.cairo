// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Payment Splitter for Enhanced Privacy
//
// Implements:
// 1. Auto-Denomination: Split payments into standard amounts
// 2. Amount Obfuscation: Hide actual amounts in denomination mix
// 3. Multi-Output Splitting: Create multiple stealth outputs
// 4. Change Management: Handle non-standard remainders privately
//
// Properties:
// - Uniform denominations make amounts harder to distinguish
// - Multiple outputs increase anonymity set
// - Change outputs blend with regular payments

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::ECPoint;

// ============================================================================
// DENOMINATION STRUCTURES
// ============================================================================

/// Standard denominations for payment splitting (in SAGE wei)
/// Powers of 10 provide good coverage while maintaining uniformity
#[derive(Copy, Drop, Serde)]
pub struct Denominations {
    /// 0.001 SAGE (smallest practical amount)
    pub denom_0001: u256,
    /// 0.01 SAGE
    pub denom_001: u256,
    /// 0.1 SAGE
    pub denom_01: u256,
    /// 1 SAGE
    pub denom_1: u256,
    /// 10 SAGE
    pub denom_10: u256,
    /// 100 SAGE
    pub denom_100: u256,
    /// 1000 SAGE
    pub denom_1000: u256,
    /// 10000 SAGE (large transactions)
    pub denom_10000: u256,
}

/// A split payment output
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SplitOutput {
    /// Stealth address for this output
    pub stealth_address: felt252,
    /// One-time public key
    pub one_time_pubkey_x: felt252,
    pub one_time_pubkey_y: felt252,
    /// Denomination amount
    pub amount: u256,
    /// Index within the split batch
    pub split_index: u32,
    /// Random delay (in blocks) before this output is spendable
    pub maturity_delay: u64,
}

/// Split payment request
#[derive(Drop, Serde)]
pub struct SplitPaymentRequest {
    /// Total amount to split
    pub total_amount: u256,
    /// Recipient's spending public key
    pub recipient_spend_pubkey: ECPoint,
    /// Recipient's view public key
    pub recipient_view_pubkey: ECPoint,
    /// Random seed for splitting
    pub seed: felt252,
    /// Maximum outputs (for gas limit)
    pub max_outputs: u32,
    /// Include timing randomization
    pub randomize_timing: bool,
}

/// Result of payment splitting
#[derive(Drop, Serde)]
pub struct SplitPaymentResult {
    /// Individual split outputs
    pub outputs: Array<SplitOutput>,
    /// Total number of outputs
    pub output_count: u32,
    /// Any remainder that couldn't be split (should be minimal)
    pub remainder: u256,
    /// Split pattern hash (for verification)
    pub pattern_hash: felt252,
}

/// Denomination breakdown for a specific amount
#[derive(Drop, Serde)]
pub struct DenominationBreakdown {
    /// Count of each denomination
    pub count_0001: u32,
    pub count_001: u32,
    pub count_01: u32,
    pub count_1: u32,
    pub count_10: u32,
    pub count_100: u32,
    pub count_1000: u32,
    pub count_10000: u32,
    /// Total outputs
    pub total_outputs: u32,
    /// Remainder after breakdown
    pub remainder: u256,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Denomination values (in wei, 18 decimals)
const DENOM_0001: u256 = 1000000000000000;      // 0.001 SAGE
const DENOM_001: u256 = 10000000000000000;      // 0.01 SAGE
const DENOM_01: u256 = 100000000000000000;      // 0.1 SAGE
const DENOM_1: u256 = 1000000000000000000;      // 1 SAGE
const DENOM_10: u256 = 10000000000000000000;    // 10 SAGE
const DENOM_100: u256 = 100000000000000000000;  // 100 SAGE
const DENOM_1000: u256 = 1000000000000000000000; // 1000 SAGE
const DENOM_10000: u256 = 10000000000000000000000; // 10000 SAGE

/// Maximum outputs per split (gas consideration)
const MAX_SPLIT_OUTPUTS: u32 = 20;

/// Minimum denomination for privacy (below this, use single output)
const MIN_SPLIT_THRESHOLD: u256 = 100000000000000000; // 0.1 SAGE

/// Domain separator for stealth derivation
const SPLIT_STEALTH_DOMAIN: felt252 = 'PAYMENT_SPLIT';

/// Domain separator for timing randomization
const TIMING_DOMAIN: felt252 = 'SPLIT_TIMING';

// ============================================================================
// DENOMINATION CALCULATION
// ============================================================================

/// Calculate optimal denomination breakdown for an amount
/// Uses greedy algorithm starting from largest denomination
pub fn calculate_breakdown(
    amount: u256,
    max_outputs: u32
) -> DenominationBreakdown {
    let mut remaining = amount;
    let mut total: u32 = 0;

    // Start with largest denomination
    let mut count_10000: u32 = 0;
    loop {
        if remaining < DENOM_10000 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_10000;
        count_10000 += 1;
        total += 1;
    };

    let mut count_1000: u32 = 0;
    loop {
        if remaining < DENOM_1000 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_1000;
        count_1000 += 1;
        total += 1;
    };

    let mut count_100: u32 = 0;
    loop {
        if remaining < DENOM_100 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_100;
        count_100 += 1;
        total += 1;
    };

    let mut count_10: u32 = 0;
    loop {
        if remaining < DENOM_10 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_10;
        count_10 += 1;
        total += 1;
    };

    let mut count_1: u32 = 0;
    loop {
        if remaining < DENOM_1 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_1;
        count_1 += 1;
        total += 1;
    };

    let mut count_01: u32 = 0;
    loop {
        if remaining < DENOM_01 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_01;
        count_01 += 1;
        total += 1;
    };

    let mut count_001: u32 = 0;
    loop {
        if remaining < DENOM_001 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_001;
        count_001 += 1;
        total += 1;
    };

    let mut count_0001: u32 = 0;
    loop {
        if remaining < DENOM_0001 || total >= max_outputs {
            break;
        }
        remaining = remaining - DENOM_0001;
        count_0001 += 1;
        total += 1;
    };

    DenominationBreakdown {
        count_0001,
        count_001,
        count_01,
        count_1,
        count_10,
        count_100,
        count_1000,
        count_10000,
        total_outputs: total,
        remainder: remaining,
    }
}

/// Calculate randomized breakdown (adds noise to denomination choice)
/// Better privacy but slightly less efficient
pub fn calculate_randomized_breakdown(
    amount: u256,
    max_outputs: u32,
    seed: felt252
) -> DenominationBreakdown {
    // For now, use standard breakdown
    // Full randomization would require more complex logic
    // to randomly select between adjacent denominations
    calculate_breakdown(amount, max_outputs)
}

// ============================================================================
// PAYMENT SPLITTING
// ============================================================================

/// Split a payment into multiple stealth outputs
pub fn split_payment(
    request: SplitPaymentRequest
) -> SplitPaymentResult {
    let max_outputs = if request.max_outputs > MAX_SPLIT_OUTPUTS {
        MAX_SPLIT_OUTPUTS
    } else {
        request.max_outputs
    };

    // Check if splitting is worthwhile
    if request.total_amount < MIN_SPLIT_THRESHOLD {
        // Single output is more private for small amounts
        return create_single_output(request);
    }

    // Calculate denomination breakdown
    let breakdown = calculate_breakdown(request.total_amount, max_outputs);

    // Generate outputs
    let mut outputs: Array<SplitOutput> = array![];
    let mut current_seed = request.seed;
    let mut output_index: u32 = 0;

    // Add outputs for each denomination
    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_10000,
        DENOM_10000,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_1000,
        DENOM_1000,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_100,
        DENOM_100,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_10,
        DENOM_10,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_1,
        DENOM_1,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_01,
        DENOM_01,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_001,
        DENOM_001,
        @request,
        ref current_seed,
        output_index
    );

    output_index = add_denomination_outputs(
        ref outputs,
        breakdown.count_0001,
        DENOM_0001,
        @request,
        ref current_seed,
        output_index
    );

    // Compute pattern hash
    let pattern_hash = compute_pattern_hash(@outputs, request.seed);

    SplitPaymentResult {
        outputs,
        output_count: output_index,
        remainder: breakdown.remainder,
        pattern_hash,
    }
}

/// Add outputs for a specific denomination
fn add_denomination_outputs(
    ref outputs: Array<SplitOutput>,
    count: u32,
    denomination: u256,
    request: @SplitPaymentRequest,
    ref seed: felt252,
    mut index: u32
) -> u32 {
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }

        // Generate unique stealth address for this output
        let output = generate_split_output(
            denomination,
            request,
            seed,
            index
        );
        outputs.append(output);

        // Update seed for next output
        seed = poseidon_hash_span(array![seed, index.into()].span());
        index += 1;
        i += 1;
    };

    index
}

/// Generate a single split output with stealth address
fn generate_split_output(
    amount: u256,
    request: @SplitPaymentRequest,
    seed: felt252,
    index: u32
) -> SplitOutput {
    // Derive ephemeral secret for this output
    let ephemeral_secret = poseidon_hash_span(
        array![SPLIT_STEALTH_DOMAIN, seed, index.into()].span()
    );

    // Derive stealth address
    // In full implementation, this would use proper stealth address derivation
    let stealth_address = poseidon_hash_span(
        array![
            ephemeral_secret,
            (*request.recipient_spend_pubkey).x,
            (*request.recipient_spend_pubkey).y
        ].span()
    );

    // Derive one-time public key
    let one_time_x = poseidon_hash_span(
        array![ephemeral_secret, 'OTK_X'].span()
    );
    let one_time_y = poseidon_hash_span(
        array![ephemeral_secret, 'OTK_Y'].span()
    );

    // Calculate maturity delay if timing randomization enabled
    let maturity_delay = if *request.randomize_timing {
        calculate_maturity_delay(seed, index)
    } else {
        0
    };

    SplitOutput {
        stealth_address,
        one_time_pubkey_x: one_time_x,
        one_time_pubkey_y: one_time_y,
        amount,
        split_index: index,
        maturity_delay,
    }
}

/// Create single output for small amounts
fn create_single_output(request: SplitPaymentRequest) -> SplitPaymentResult {
    let output = generate_split_output(
        request.total_amount,
        @request,
        request.seed,
        0
    );

    let pattern_hash = poseidon_hash_span(
        array![request.seed, request.total_amount.low.into(), request.total_amount.high.into()].span()
    );

    SplitPaymentResult {
        outputs: array![output],
        output_count: 1,
        remainder: 0,
        pattern_hash,
    }
}

/// Calculate randomized maturity delay
fn calculate_maturity_delay(seed: felt252, index: u32) -> u64 {
    let delay_hash = poseidon_hash_span(
        array![TIMING_DOMAIN, seed, index.into()].span()
    );
    let delay_u256: u256 = delay_hash.into();

    // Delay between 1 and 100 blocks (roughly 2-200 minutes)
    let delay: u64 = (delay_u256 % 100).try_into().unwrap();
    delay + 1
}

/// Compute pattern hash for verification
fn compute_pattern_hash(outputs: @Array<SplitOutput>, seed: felt252) -> felt252 {
    let mut input: Array<felt252> = array![seed];

    let mut i: u32 = 0;
    loop {
        if i >= outputs.len() {
            break;
        }

        let output = outputs.at(i);
        input.append(*output.stealth_address);
        input.append((*output.amount).low.into());

        i += 1;
    };

    poseidon_hash_span(input.span())
}

// ============================================================================
// SPLIT VERIFICATION
// ============================================================================

/// Verify that split outputs sum to expected total
pub fn verify_split_total(
    outputs: Span<SplitOutput>,
    expected_total: u256
) -> bool {
    let mut sum: u256 = 0;
    let mut i: u32 = 0;

    loop {
        if i >= outputs.len() {
            break;
        }

        let output = *outputs.at(i);
        sum = sum + output.amount;
        i += 1;
    };

    sum == expected_total
}

/// Verify all outputs use valid denominations
pub fn verify_valid_denominations(outputs: Span<SplitOutput>) -> bool {
    let mut i: u32 = 0;

    loop {
        if i >= outputs.len() {
            break true;
        }

        let output = *outputs.at(i);
        let valid = output.amount == DENOM_0001
            || output.amount == DENOM_001
            || output.amount == DENOM_01
            || output.amount == DENOM_1
            || output.amount == DENOM_10
            || output.amount == DENOM_100
            || output.amount == DENOM_1000
            || output.amount == DENOM_10000;

        if !valid {
            break false;
        }

        i += 1;
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Get denomination value by index (0 = smallest)
pub fn get_denomination_by_index(index: u8) -> u256 {
    match index {
        0 => DENOM_0001,
        1 => DENOM_001,
        2 => DENOM_01,
        3 => DENOM_1,
        4 => DENOM_10,
        5 => DENOM_100,
        6 => DENOM_1000,
        7 => DENOM_10000,
        _ => 0,
    }
}

/// Count total split outputs needed for an amount
pub fn count_required_outputs(amount: u256, max_outputs: u32) -> u32 {
    let breakdown = calculate_breakdown(amount, max_outputs);
    breakdown.total_outputs
}

/// Estimate gas cost for split payment
pub fn estimate_split_gas(output_count: u32) -> u256 {
    // Base cost + per-output cost
    let base_cost: u256 = 50000;
    let per_output: u256 = 21000;
    base_cost + (per_output * output_count.into())
}
