// SAGE Network Security Utilities
// Simple utility functions for security checks and monitoring

use starknet::ContractAddress;

/// Essential security structures
#[derive(Drop, Serde, starknet::Store)]
pub struct RateLimitState {
    pub current_count: u32,
    pub window_start: u64,
    pub window_duration: u64,
    pub max_requests: u32,
}

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct SecurityMetrics {
    pub failed_attempts: u32,
    pub last_failure_time: u64,
    pub security_level: u8,
    pub alert_threshold: u32,
}

/// Security Events
#[derive(Drop, starknet::Event)]
pub struct SecurityAlert {
    pub alert_type: felt252,
    pub severity: u8,
    pub timestamp: u64,
    pub source: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct RateLimitExceeded {
    pub source: ContractAddress,
    pub timestamp: u64,
    pub attempt_count: u32,
}

/// Utility functions for security
pub fn validate_address(address: ContractAddress) -> bool {
    let zero_address: ContractAddress = 0.try_into().unwrap();
    address != zero_address
}

pub fn calculate_time_window(window_type: u8) -> u64 {
    if window_type == 1 {
        300    // 5 minutes
    } else if window_type == 2 {
        3600   // 1 hour  
    } else if window_type == 3 {
        86400  // 1 day
    } else {
        3600   // Default 1 hour
    }
}

pub fn get_security_level_name(level: u8) -> felt252 {
    if level == 1 {
        'normal'
    } else if level == 2 {
        'elevated'
    } else if level == 3 {
        'high'
    } else if level == 4 {
        'critical'
    } else {
        'unknown'
    }
}

pub fn is_rate_limit_exceeded(
    current_count: u32,
    max_requests: u32,
    window_start: u64,
    window_duration: u64,
    current_time: u64
) -> bool {
    // Check if window has expired
    if current_time >= window_start + window_duration {
        return false; // Window reset, not exceeded
    }
    
    // Check if current requests exceed limit
    current_count >= max_requests
}

pub fn calculate_security_score(
    failed_attempts: u32,
    alert_threshold: u32,
    time_since_last_failure: u64
) -> u8 {
    if failed_attempts == 0 {
        return 100; // Perfect score
    }
    
    let failure_ratio = (failed_attempts * 100) / alert_threshold;
    let time_bonus = if time_since_last_failure > 86400 { 20 } else { 0 }; // 1 day bonus
    
    let base_score = if failure_ratio > 100 { 0 } else { 100 - failure_ratio };
    let final_score = base_score + time_bonus;
    
    if final_score > 100 { 100 } else { final_score.try_into().unwrap() }
}

pub fn is_suspicious_activity(
    request_frequency: u32,
    normal_threshold: u32,
    time_pattern_anomaly: bool
) -> bool {
    request_frequency > (normal_threshold * 3) || time_pattern_anomaly
}

pub fn format_security_message(prefix: felt252, code: u32) -> felt252 {
    // Simple message formatting
    prefix + code.into()
}

// =============================================================================
// Two-Step Ownership Transfer Pattern
// =============================================================================
// Prevents accidental ownership transfers by requiring the new owner to accept.
// Usage:
// 1. Current owner calls transfer_ownership(new_owner)
// 2. New owner calls accept_ownership()
// 3. Only then is ownership transferred

/// Ownership state for two-step transfer
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct OwnableState {
    pub owner: ContractAddress,
    pub pending_owner: ContractAddress,
}

/// Events for ownership changes
#[derive(Drop, starknet::Event)]
pub struct OwnershipTransferStarted {
    #[key]
    pub previous_owner: ContractAddress,
    #[key]
    pub new_owner: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct OwnershipTransferred {
    #[key]
    pub previous_owner: ContractAddress,
    #[key]
    pub new_owner: ContractAddress,
}

/// Initialize ownership state
pub fn init_ownership(owner: ContractAddress) -> OwnableState {
    let zero: ContractAddress = 0.try_into().unwrap();
    OwnableState {
        owner,
        pending_owner: zero,
    }
}

/// Start ownership transfer (called by current owner)
/// Returns the updated state
pub fn start_ownership_transfer(
    state: OwnableState,
    caller: ContractAddress,
    new_owner: ContractAddress
) -> OwnableState {
    assert!(caller == state.owner, "Ownable: caller is not the owner");
    assert!(validate_address(new_owner), "Ownable: new owner is zero address");

    OwnableState {
        owner: state.owner,
        pending_owner: new_owner,
    }
}

/// Accept ownership (called by pending owner)
/// Returns the updated state
pub fn accept_ownership(
    state: OwnableState,
    caller: ContractAddress
) -> OwnableState {
    let zero: ContractAddress = 0.try_into().unwrap();
    assert!(caller == state.pending_owner, "Ownable: caller is not pending owner");

    OwnableState {
        owner: caller,
        pending_owner: zero,
    }
}

/// Cancel pending ownership transfer (called by current owner)
pub fn cancel_ownership_transfer(
    state: OwnableState,
    caller: ContractAddress
) -> OwnableState {
    let zero: ContractAddress = 0.try_into().unwrap();
    assert!(caller == state.owner, "Ownable: caller is not the owner");

    OwnableState {
        owner: state.owner,
        pending_owner: zero,
    }
}

/// Check if caller is owner
pub fn only_owner(state: @OwnableState, caller: ContractAddress) {
    assert!(caller == *state.owner, "Ownable: caller is not the owner");
}

// =============================================================================
// Pausable Pattern
// =============================================================================
// Allows contracts to be paused in case of emergency

/// Pausable state
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct PausableState {
    pub paused: bool,
}

/// Events for pause state changes
#[derive(Drop, starknet::Event)]
pub struct Paused {
    pub account: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct Unpaused {
    pub account: ContractAddress,
}

/// Check if not paused (revert if paused)
pub fn when_not_paused(state: @PausableState) {
    assert!(!*state.paused, "Pausable: paused");
}

/// Check if paused (revert if not paused)
pub fn when_paused(state: @PausableState) {
    assert!(*state.paused, "Pausable: not paused");
}

/// Pause the contract
pub fn pause(state: PausableState) -> PausableState {
    assert!(!state.paused, "Pausable: already paused");
    PausableState { paused: true }
}

/// Unpause the contract
pub fn unpause(state: PausableState) -> PausableState {
    assert!(state.paused, "Pausable: not paused");
    PausableState { paused: false }
} 