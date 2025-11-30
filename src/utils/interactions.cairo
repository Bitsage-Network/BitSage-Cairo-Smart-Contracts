// CIRO Network Contract Interactions Utilities
// Simple utility functions for contract interactions and validation

use starknet::ContractAddress;

/// Contract registry structures
#[derive(Drop, Serde, starknet::Store)]
pub struct ContractInfo {
    pub address: ContractAddress,
    pub version: felt252,
    pub active: bool,
    pub registered_at: u64,
}

/// Events
#[derive(Drop, starknet::Event)]
pub struct ContractRegistered {
    pub name: felt252,
    pub address: ContractAddress,
    pub version: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct ContractUpdated {
    pub name: felt252,
    pub old_address: ContractAddress,
    pub new_address: ContractAddress,
}

/// Utility functions for contract interactions
pub fn validate_contract_address(address: ContractAddress) -> bool {
    let zero_address: ContractAddress = 0.try_into().unwrap();
    address != zero_address
}

pub fn format_contract_name(prefix: felt252, suffix: felt252) -> felt252 {
    // Simple name formatting - in practice would combine prefix and suffix
    prefix + suffix
}

pub fn is_contract_active(info: ContractInfo) -> bool {
    info.active && validate_contract_address(info.address)
}

pub fn calculate_contract_age(registered_at: u64, current_time: u64) -> u64 {
    if current_time >= registered_at {
        current_time - registered_at
    } else {
        0
    }
}

pub fn is_version_newer(current_version: felt252, new_version: felt252) -> bool {
    // Simple version comparison - check if versions are different
    new_version != current_version
}

pub fn get_contract_status_code(info: ContractInfo) -> u8 {
    if !validate_contract_address(info.address) {
        0 // Invalid address
    } else if !info.active {
        1 // Inactive
    } else {
        2 // Active
    }
}

pub fn format_version_string(major: u8, minor: u8, patch: u8) -> felt252 {
    // Simple version formatting: major.minor.patch -> felt252
    let version_num = (major.into() * 10000) + (minor.into() * 100) + patch.into();
    version_num.try_into().unwrap()
}

pub fn validate_upgrade_path(current_version: felt252, target_version: felt252) -> bool {
    // Simple upgrade validation - target must be different from current
    target_version != current_version
}

pub fn calculate_downtime(last_active: u64, current_time: u64) -> u64 {
    if current_time > last_active {
        current_time - last_active
    } else {
        0
    }
}

pub fn is_maintenance_window(current_time: u64, maintenance_start: u64, maintenance_duration: u64) -> bool {
    current_time >= maintenance_start && current_time <= (maintenance_start + maintenance_duration)
} 