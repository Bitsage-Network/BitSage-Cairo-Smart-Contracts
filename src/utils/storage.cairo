// CIRO Network Storage Utilities
// Optimized storage patterns for gas efficiency and functionality

use starknet::ContractAddress;
use super::constants::*;

/// Iterable mapping pattern for efficient enumeration
/// Maintains both a mapping and an array for iteration
pub trait IterableMapping<K, V> {
    /// Get the count of items in the mapping
    fn count() -> u32;
    
    /// Get item by key
    fn get(key: K) -> V;
    
    /// Set item by key
    fn set(key: K, value: V);
    
    /// Get key by index for iteration
    fn get_key_by_index(index: u32) -> K;
    
    /// Get value by index for iteration
    fn get_value_by_index(index: u32) -> V;
    
    /// Remove item by key
    fn remove(key: K);
    
    /// Check if key exists
    fn contains(key: K) -> bool;
}

/// Dynamic array pattern for efficient storage
/// Maintains length and indexed access
pub trait DynamicArray<T> {
    /// Get the length of the array
    fn length() -> u32;
    
    /// Get item at index
    fn get(index: u32) -> T;
    
    /// Set item at index
    fn set(index: u32, value: T);
    
    /// Push item to end of array
    fn push(value: T);
    
    /// Pop item from end of array
    fn pop() -> T;
    
    /// Remove item at index (swap with last)
    fn remove(index: u32);
    
    /// Clear all items
    fn clear();
}

/// Packed flags utility for efficient boolean storage
/// Uses bit manipulation for multiple flags in a single storage slot
pub trait PackedFlags {
    /// Set a flag to true
    fn set_flag(flags: u64, flag: u64) -> u64;
    
    /// Set a flag to false
    fn clear_flag(flags: u64, flag: u64) -> u64;
    
    /// Check if a flag is set
    fn has_flag(flags: u64, flag: u64) -> bool;
    
    /// Toggle a flag
    fn toggle_flag(flags: u64, flag: u64) -> u64;
    
    /// Count number of set flags
    fn count_flags(flags: u64) -> u8;
}

/// Implementation of PackedFlags trait
impl PackedFlagsImpl of PackedFlags {
    fn set_flag(flags: u64, flag: u64) -> u64 {
        flags | flag
    }
    
    fn clear_flag(flags: u64, flag: u64) -> u64 {
        flags & (~flag)
    }
    
    fn has_flag(flags: u64, flag: u64) -> bool {
        (flags & flag) != 0
    }
    
    fn toggle_flag(flags: u64, flag: u64) -> u64 {
        flags ^ flag
    }
    
    fn count_flags(flags: u64) -> u8 {
        let mut count = 0;
        let mut temp = flags;
        
        while temp > 0 {
            if temp & 1 == 1 {
                count += 1;
            }
            temp = temp / 2;
        }
        
        count
    }
}

/// Storage layout patterns for different data structures

/// Job storage layout - optimized for job management
pub mod job_storage {
    use starknet::ContractAddress;
    use super::super::types::JobData;
    
    /// Total number of jobs
    #[storage_var]
    fn jobs_count() -> u32 {}
    
    /// Job data by ID
    #[storage_var]
    fn job_data(job_id: felt252) -> JobData {}
    
    /// Job ID by index (for iteration)
    #[storage_var]
    fn job_by_index(index: u32) -> felt252 {}
    
    /// Job index by ID (for removal)
    #[storage_var]
    fn job_index(job_id: felt252) -> u32 {}
    
    /// Jobs by requester
    #[storage_var]
    fn requester_jobs_count(requester: ContractAddress) -> u32 {}
    
    #[storage_var]
    fn requester_job_by_index(requester: ContractAddress, index: u32) -> felt252 {}
    
    /// Active jobs by worker
    #[storage_var]
    fn worker_active_jobs_count(worker_id: felt252) -> u32 {}
    
    #[storage_var]
    fn worker_active_job_by_index(worker_id: felt252, index: u32) -> felt252 {}
    
    /// Jobs by status (for efficient filtering)
    #[storage_var]
    fn status_jobs_count(status: u8) -> u32 {}
    
    #[storage_var]
    fn status_job_by_index(status: u8, index: u32) -> felt252 {}
}

/// Worker storage layout - optimized for worker management
pub mod worker_storage {
    use starknet::ContractAddress;
    use super::super::types::{WorkerProfile, PerformanceMetrics, StakeInfo};
    
    /// Total number of workers
    #[storage_var]
    fn workers_count() -> u32 {}
    
    /// Worker profile by ID
    #[storage_var]
    fn worker_profile(worker_id: felt252) -> WorkerProfile {}
    
    /// Worker ID by index (for iteration)
    #[storage_var]
    fn worker_by_index(index: u32) -> felt252 {}
    
    /// Worker index by ID (for removal)
    #[storage_var]
    fn worker_index(worker_id: felt252) -> u32 {}
    
    /// Worker ID by address
    #[storage_var]
    fn address_to_worker_id(address: ContractAddress) -> felt252 {}
    
    /// Worker address by ID
    #[storage_var]
    fn worker_address(worker_id: felt252) -> ContractAddress {}
    
    /// Performance metrics by worker
    #[storage_var]
    fn worker_metrics(worker_id: felt252) -> PerformanceMetrics {}
    
    /// Stake information by worker
    #[storage_var]
    fn worker_stake(worker_id: felt252) -> StakeInfo {}
    
    /// Workers by capability (for efficient matching)
    #[storage_var]
    fn capability_workers_count(capability: u64) -> u32 {}
    
    #[storage_var]
    fn capability_worker_by_index(capability: u64, index: u32) -> felt252 {}
    
    /// Active workers count (cached for efficiency)
    #[storage_var]
    fn active_workers_count() -> u32 {}
}

/// Attestation storage layout - optimized for result verification
pub mod attestation_storage {
    use super::super::types::ResultAttestation;
    
    /// Attestation by job ID
    #[storage_var]
    fn job_attestation(job_id: felt252) -> ResultAttestation {}
    
    /// Attestation count by worker
    #[storage_var]
    fn worker_attestation_count(worker_id: felt252) -> u32 {}
    
    /// Attestation job ID by worker and index
    #[storage_var]
    fn worker_attestation_by_index(worker_id: felt252, index: u32) -> felt252 {}
    
    /// Disputed attestations count
    #[storage_var]
    fn disputed_attestations_count() -> u32 {}
    
    /// Disputed attestation by index
    #[storage_var]
    fn disputed_attestation_by_index(index: u32) -> felt252 {}
}

/// Payment storage layout - optimized for payment management
pub mod payment_storage {
    use starknet::ContractAddress;
    use super::super::types::{PaymentChannel, Subscription};
    
    /// Payment channel by ID
    #[storage_var]
    fn payment_channel(channel_id: felt252) -> PaymentChannel {}
    
    /// Channels count by sender
    #[storage_var]
    fn sender_channels_count(sender: ContractAddress) -> u32 {}
    
    /// Channel ID by sender and index
    #[storage_var]
    fn sender_channel_by_index(sender: ContractAddress, index: u32) -> felt252 {}
    
    /// Subscription by address
    #[storage_var]
    fn user_subscription(user: ContractAddress) -> Subscription {}
    
    /// Sponsored transactions count by user
    #[storage_var]
    fn sponsored_tx_count(user: ContractAddress) -> u32 {}
    
    /// Gas allowance by user
    #[storage_var]
    fn gas_allowance(user: ContractAddress) -> u256 {}
    
    /// Daily gas used by user
    #[storage_var]
    fn daily_gas_used(user: ContractAddress) -> u256 {}
}

/// Dispute storage layout - optimized for dispute resolution
pub mod dispute_storage {
    use super::super::types::{DisputeInfo, SlashRecord};
    
    /// Dispute by ID
    #[storage_var]
    fn dispute_info(dispute_id: felt252) -> DisputeInfo {}
    
    /// Active disputes count
    #[storage_var]
    fn active_disputes_count() -> u32 {}
    
    /// Active dispute by index
    #[storage_var]
    fn active_dispute_by_index(index: u32) -> felt252 {}
    
    /// Disputes by job
    #[storage_var]
    fn job_dispute_count(job_id: felt252) -> u32 {}
    
    #[storage_var]
    fn job_dispute_by_index(job_id: felt252, index: u32) -> felt252 {}
    
    /// Slash records count
    #[storage_var]
    fn slash_records_count() -> u32 {}
    
    /// Slash record by index
    #[storage_var]
    fn slash_record_by_index(index: u32) -> SlashRecord {}
    
    /// Slash records by worker
    #[storage_var]
    fn worker_slash_count(worker_id: felt252) -> u32 {}
    
    #[storage_var]
    fn worker_slash_by_index(worker_id: felt252, index: u32) -> felt252 {}
}

/// Utility functions for storage operations

/// Batch operations for gas efficiency
pub mod batch_operations {
    use super::super::constants::BATCH_SIZE_LIMIT;
    use super::super::types::BatchResult;
    
    /// Execute batch job updates
    fn batch_update_jobs(job_ids: Array<felt252>, updates: Array<u8>) -> BatchResult {
        let mut result = BatchResult {
            total_operations: job_ids.len(),
            successful_operations: 0,
            failed_operations: 0,
            first_failure_index: 0xFFFFFFFF, // u32::MAX
            gas_used: 0,
        };
        
        // Implementation would go here
        // This is a placeholder structure
        
        result
    }
    
    /// Execute batch worker updates
    fn batch_update_workers(worker_ids: Array<felt252>, updates: Array<u8>) -> BatchResult {
        let mut result = BatchResult {
            total_operations: worker_ids.len(),
            successful_operations: 0,
            failed_operations: 0,
            first_failure_index: 0xFFFFFFFF,
            gas_used: 0,
        };
        
        // Implementation would go here
        
        result
    }
}

/// Pagination utilities for efficient querying
pub mod pagination {
    use super::super::constants::PAGINATION_LIMIT;
    use super::super::types::PaginationInfo;
    
    /// Create pagination info
    fn create_pagination(offset: u32, limit: u32, total: u32) -> PaginationInfo {
        let safe_limit = if limit > PAGINATION_LIMIT { PAGINATION_LIMIT } else { limit };
        let has_more = offset + safe_limit < total;
        
        PaginationInfo {
            offset,
            limit: safe_limit,
            total_count: total,
            has_more,
        }
    }
    
    /// Validate pagination parameters
    fn validate_pagination(offset: u32, limit: u32) -> (u32, u32) {
        let safe_limit = if limit > PAGINATION_LIMIT { PAGINATION_LIMIT } else { limit };
        let safe_offset = if offset > 1000000 { 0 } else { offset }; // Prevent overflow
        
        (safe_offset, safe_limit)
    }
} 