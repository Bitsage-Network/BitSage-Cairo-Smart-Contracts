//! Common Utilities for CIRO Network Contracts
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