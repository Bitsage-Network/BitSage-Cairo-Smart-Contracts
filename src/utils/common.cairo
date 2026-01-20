//! Common Utilities for SAGE Network Contracts
//! Cairo 2.12.0 Code Deduplication Optimizations
//! 
//! This module contains shared functions used across multiple contracts
//! to reduce code duplication and leverage Cairo 2.12.0's optimization features

use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
use core::num::traits::Zero;

/// Common validation functions to reduce duplicate code
pub mod validation {
    use super::*;

    /// Validate that the caller is the contract admin
    #[inline(always)]
    pub fn ensure_admin(admin: ContractAddress) {
        let caller = get_caller_address();
        assert!(caller == admin, "Not authorized");
    }

    /// Validate that the contract is not paused
    #[inline(always)]
    pub fn ensure_not_paused(paused: bool) {
        assert!(!paused, "Contract is paused");
    }

    /// Validate that an address is not zero
    #[inline(always)]
    pub fn ensure_non_zero_address(address: ContractAddress) {
        assert!(!address.is_zero(), "Zero address not allowed");
    }

    /// Validate that an amount is greater than zero
    #[inline(always)]
    pub fn ensure_non_zero_amount(amount: u256) {
        assert!(amount > 0, "Amount must be greater than zero");
    }

    /// Validate that a deadline is in the future
    #[inline(always)]
    pub fn ensure_future_deadline(deadline: u64) {
        let current_time = get_block_timestamp();
        assert!(deadline > current_time, "Deadline must be in the future");
    }
}

/// Common mathematical operations to reduce duplicate calculations
pub mod math {
    /// Calculate percentage of an amount (with basis points precision)
    #[inline(always)]
    pub fn calculate_percentage(amount: u256, percentage_bps: u16) -> u256 {
        (amount * percentage_bps.into()) / 10000
    }

    /// Calculate weighted average of two values
    #[inline(always)]
    pub fn weighted_average(value1: u256, weight1: u256, value2: u256, weight2: u256) -> u256 {
        (value1 * weight1 + value2 * weight2) / (weight1 + weight2)
    }

    /// Safe division that returns 0 if divisor is 0
    #[inline(always)]
    pub fn safe_div(dividend: u256, divisor: u256) -> u256 {
        if divisor == 0 {
            0
        } else {
            dividend / divisor
        }
    }
}

/// Common type conversion utilities
pub mod conversions {
    use super::*;

    /// Convert u256 to felt252 with panic on overflow
    #[inline(always)]
    pub fn u256_to_felt252(value: u256) -> felt252 {
        let Some(result) = value.try_into() else {
            panic!("Value too large for felt252 conversion");
        };
        result
    }

    /// Convert JobId to storage key
    #[inline(always)]
    pub fn job_id_to_key(job_id: u256) -> felt252 {
        u256_to_felt252(job_id)
    }

    /// Convert WorkerId to storage key  
    #[inline(always)]
    pub fn worker_id_to_key(worker_id: felt252) -> felt252 {
        worker_id
    }
}

/// Common event emission patterns
pub mod events {
    use super::*;

    /// Standard event data validation
    #[inline(always)]
    pub fn validate_event_data(
        address: ContractAddress,
        amount: u256,
        timestamp: u64
    ) {
        validation::ensure_non_zero_address(address);
        validation::ensure_non_zero_amount(amount);
        assert!(timestamp > 0, "Invalid timestamp");
    }
}

/// Common storage patterns
pub mod storage {
    use super::*;

    /// Update counter with overflow protection
    #[inline(always)]
    pub fn safe_increment_counter(current: u64) -> u64 {
        let max_value: u64 = 0xFFFFFFFFFFFFFFFF;  // u64::MAX
        if current >= max_value - 1 {
            panic!("Counter overflow");
        }
        current + 1
    }

    /// Update counter with underflow protection
    #[inline(always)]
    pub fn safe_decrement_counter(current: u64) -> u64 {
        if current == 0 {
            panic!("Counter underflow");
        }
        current - 1
    }
}

// =============================================================================
// MULTI-ASSET DECIMAL HANDLING
// =============================================================================

/// Asset decimal constants and conversion utilities for multi-asset privacy payments
///
/// Supported Assets:
/// - SAGE: 18 decimals (network native token)
/// - USDC: 6 decimals (native USDC on Starknet)
/// - STRK: 18 decimals (Starknet native token)
/// - BTC: 8 decimals (native BTC via BTCFi bridge)
/// - ETH: 18 decimals
pub mod decimals {
    /// Asset IDs (must match privacy_router::AssetIds)
    pub mod AssetId {
        pub const SAGE: u64 = 0;
        pub const USDC: u64 = 1;
        pub const STRK: u64 = 2;
        pub const BTC: u64 = 3;
        pub const ETH: u64 = 4;
    }

    /// Decimal places for each asset
    pub mod AssetDecimals {
        pub const SAGE: u8 = 18;
        pub const USDC: u8 = 6;
        pub const STRK: u8 = 18;
        pub const BTC: u8 = 8;
        pub const ETH: u8 = 18;
    }

    /// Standard decimal precision (18 decimals) used as normalization base
    pub const STANDARD_DECIMALS: u8 = 18;

    /// Power of 10 lookup table for efficient conversions
    pub mod Pow10 {
        pub const POW10_0: u256 = 1;
        pub const POW10_1: u256 = 10;
        pub const POW10_2: u256 = 100;
        pub const POW10_3: u256 = 1000;
        pub const POW10_4: u256 = 10000;
        pub const POW10_5: u256 = 100000;
        pub const POW10_6: u256 = 1000000;
        pub const POW10_7: u256 = 10000000;
        pub const POW10_8: u256 = 100000000;
        pub const POW10_9: u256 = 1000000000;
        pub const POW10_10: u256 = 10000000000;
        pub const POW10_11: u256 = 100000000000;
        pub const POW10_12: u256 = 1000000000000;
        pub const POW10_13: u256 = 10000000000000;
        pub const POW10_14: u256 = 100000000000000;
        pub const POW10_15: u256 = 1000000000000000;
        pub const POW10_16: u256 = 10000000000000000;
        pub const POW10_17: u256 = 100000000000000000;
        pub const POW10_18: u256 = 1000000000000000000;
    }

    /// Get decimal places for an asset ID
    /// @param asset_id: The asset identifier
    /// @return Number of decimal places (0 if unknown asset)
    #[inline(always)]
    pub fn get_decimals(asset_id: u64) -> u8 {
        if asset_id == AssetId::SAGE {
            AssetDecimals::SAGE
        } else if asset_id == AssetId::USDC {
            AssetDecimals::USDC
        } else if asset_id == AssetId::STRK {
            AssetDecimals::STRK
        } else if asset_id == AssetId::BTC {
            AssetDecimals::BTC
        } else if asset_id == AssetId::ETH {
            AssetDecimals::ETH
        } else {
            0 // Unknown asset
        }
    }

    /// Get power of 10 for given exponent (0-18)
    /// @param exp: The exponent (0-18)
    /// @return 10^exp
    #[inline(always)]
    pub fn pow10(exp: u8) -> u256 {
        if exp == 0 { Pow10::POW10_0 }
        else if exp == 1 { Pow10::POW10_1 }
        else if exp == 2 { Pow10::POW10_2 }
        else if exp == 3 { Pow10::POW10_3 }
        else if exp == 4 { Pow10::POW10_4 }
        else if exp == 5 { Pow10::POW10_5 }
        else if exp == 6 { Pow10::POW10_6 }
        else if exp == 7 { Pow10::POW10_7 }
        else if exp == 8 { Pow10::POW10_8 }
        else if exp == 9 { Pow10::POW10_9 }
        else if exp == 10 { Pow10::POW10_10 }
        else if exp == 11 { Pow10::POW10_11 }
        else if exp == 12 { Pow10::POW10_12 }
        else if exp == 13 { Pow10::POW10_13 }
        else if exp == 14 { Pow10::POW10_14 }
        else if exp == 15 { Pow10::POW10_15 }
        else if exp == 16 { Pow10::POW10_16 }
        else if exp == 17 { Pow10::POW10_17 }
        else if exp == 18 { Pow10::POW10_18 }
        else { panic!("Exponent too large (max 18)") }
    }

    /// Normalize an amount to 18 decimals (standard precision)
    /// @param amount: The amount in asset's native decimals
    /// @param asset_id: The asset identifier
    /// @return Amount normalized to 18 decimals
    ///
    /// Example:
    /// - 1 USDC (1_000_000 in 6 decimals) -> 1_000_000_000_000_000_000 (18 decimals)
    /// - 1 BTC (100_000_000 in 8 decimals) -> 1_000_000_000_000_000_000 (18 decimals)
    #[inline(always)]
    pub fn normalize_to_18(amount: u256, asset_id: u64) -> u256 {
        let decimals = get_decimals(asset_id);
        if decimals == 0 {
            panic!("Unknown asset");
        }
        if decimals == STANDARD_DECIMALS {
            amount
        } else if decimals < STANDARD_DECIMALS {
            // Scale up: multiply by 10^(18 - decimals)
            let scale = pow10(STANDARD_DECIMALS - decimals);
            amount * scale
        } else {
            // Scale down: divide by 10^(decimals - 18)
            // This case shouldn't happen with current assets, but handle it anyway
            let scale = pow10(decimals - STANDARD_DECIMALS);
            amount / scale
        }
    }

    /// Convert from 18 decimals to asset's native decimals
    /// @param amount_18: The amount in 18 decimals
    /// @param asset_id: The target asset identifier
    /// @return Amount in asset's native decimals
    ///
    /// Example:
    /// - 1_000_000_000_000_000_000 (1.0 in 18 decimals) -> 1_000_000 (1.0 USDC)
    /// - 1_000_000_000_000_000_000 (1.0 in 18 decimals) -> 100_000_000 (1.0 BTC)
    #[inline(always)]
    pub fn scale_to_asset(amount_18: u256, asset_id: u64) -> u256 {
        let decimals = get_decimals(asset_id);
        if decimals == 0 {
            panic!("Unknown asset");
        }
        if decimals == STANDARD_DECIMALS {
            amount_18
        } else if decimals < STANDARD_DECIMALS {
            // Scale down: divide by 10^(18 - decimals)
            let scale = pow10(STANDARD_DECIMALS - decimals);
            amount_18 / scale
        } else {
            // Scale up: multiply by 10^(decimals - 18)
            let scale = pow10(decimals - STANDARD_DECIMALS);
            amount_18 * scale
        }
    }

    /// Convert amount between any two assets
    /// @param amount: Amount in source asset's decimals
    /// @param from_asset: Source asset ID
    /// @param to_asset: Target asset ID
    /// @return Amount in target asset's decimals
    ///
    /// Note: This is a decimal conversion only, NOT a price conversion.
    /// For price conversion, use the oracle module.
    #[inline(always)]
    pub fn convert_decimals(amount: u256, from_asset: u64, to_asset: u64) -> u256 {
        if from_asset == to_asset {
            amount
        } else {
            // Normalize to 18 decimals, then scale to target
            let normalized = normalize_to_18(amount, from_asset);
            scale_to_asset(normalized, to_asset)
        }
    }

    /// Check if an amount is within the valid range for an asset
    /// Prevents overflow when converting between decimals
    /// @param amount: Amount to check
    /// @param asset_id: Asset identifier
    /// @return true if amount is valid
    pub fn is_valid_amount(amount: u256, asset_id: u64) -> bool {
        let decimals = get_decimals(asset_id);
        if decimals == 0 {
            return false;
        }
        // Check that normalizing won't overflow
        // Max safe value depends on target decimals
        if decimals < STANDARD_DECIMALS {
            let scale = pow10(STANDARD_DECIMALS - decimals);
            // Check for overflow: amount * scale must fit in u256
            let max_safe = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256 / scale;
            amount <= max_safe
        } else {
            true // Scaling down never overflows
        }
    }

    /// Format amount for display (returns whole units and fractional part)
    /// @param amount: Amount in asset's native decimals
    /// @param asset_id: Asset identifier
    /// @return (whole_units, fractional_part, decimals)
    pub fn split_amount(amount: u256, asset_id: u64) -> (u256, u256, u8) {
        let decimals = get_decimals(asset_id);
        if decimals == 0 {
            return (0, 0, 0);
        }
        let divisor = pow10(decimals);
        let whole = amount / divisor;
        let fractional = amount % divisor;
        (whole, fractional, decimals)
    }
}