//! Reputation Manager Interface for SAGE Network
//! Central reputation management system for worker ranking and job allocation

/// Reputation score with detailed tracking
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ReputationScore {
    pub score: u32,              // Current reputation score (0-1000)
    pub level: u8,               // Reputation level (1-5)
    pub last_updated: u64,       // Timestamp of last update
    pub total_jobs_completed: u32, // Total jobs completed
    pub successful_jobs: u32,    // Successfully completed jobs
    pub failed_jobs: u32,        // Failed jobs
    pub dispute_count: u32,      // Number of disputes
    pub slash_count: u32,        // Number of times slashed
}

/// Reputation event for history tracking
#[derive(Drop, Serde, starknet::Store)]
pub struct ReputationEvent {
    pub timestamp: u64,          // When the event occurred
    pub score_delta: i32,        // Change in score (+/-)
    pub reason: felt252,         // Reason for the change
    pub job_id: Option<u256>,    // Associated job if applicable
    pub old_score: u32,          // Score before change
    pub new_score: u32,          // Score after change
}

/// Worker ranking information
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerRank {
    pub worker_id: felt252,      // Worker identifier
    pub score: u32,              // Current reputation score
    pub level: u8,               // Reputation level
    pub rank: u32,               // Ranking position
}

/// Reputation update reasons
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum ReputationReason {
    JobCompleted,       // Successful job completion
    JobFailed,          // Job failed or timed out
    WorkerSlashed,      // Worker was slashed
    DisputeLost,        // Lost a dispute
    DisputeWon,         // Won a dispute
    InactivityDecay,    // Reputation decay from inactivity
    AdminAdjustment,    // Admin manual adjustment
}

/// Reputation threshold requirements
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ReputationThreshold {
    pub job_type: felt252,       // Type of job
    pub min_score: u32,          // Minimum reputation score required
    pub min_level: u8,           // Minimum reputation level required
    pub max_failures: u32,       // Maximum allowed recent failures
}

#[starknet::interface]
pub trait IReputationManager<TContractState> {
    /// Initialize reputation for a new worker
    /// @param worker_id: Worker to initialize
    /// @return: Success status
    fn initialize_reputation(ref self: TContractState, worker_id: felt252) -> bool;
    
    /// Update worker reputation based on performance
    /// @param worker_id: Worker to update
    /// @param score_delta: Change in reputation score
    /// @param reason: Reason for the update
    /// @param job_id: Associated job ID (optional)
    /// @return: Success status
    fn update_reputation(
        ref self: TContractState, 
        worker_id: felt252, 
        score_delta: i32, 
        reason: ReputationReason,
        job_id: Option<u256>
    ) -> bool;
    
    /// Get current reputation score for a worker
    /// @param worker_id: Worker to query
    /// @return: Current reputation score
    fn get_reputation(self: @TContractState, worker_id: felt252) -> ReputationScore;
    
    /// Get reputation history for a worker
    /// @param worker_id: Worker to query
    /// @param limit: Maximum number of events to return
    /// @return: Array of reputation events
    fn get_reputation_history(
        self: @TContractState, 
        worker_id: felt252, 
        limit: u32
    ) -> Array<ReputationEvent>;
    
    /// Check if worker meets reputation threshold
    /// @param worker_id: Worker to check
    /// @param threshold: Threshold requirements
    /// @return: Whether threshold is met
    fn check_reputation_threshold(
        self: @TContractState, 
        worker_id: felt252, 
        threshold: ReputationThreshold
    ) -> bool;
    
    /// Get worker's current rank among all workers
    /// @param worker_id: Worker to rank
    /// @return: Current rank (1-based)
    fn get_worker_rank(self: @TContractState, worker_id: felt252) -> u32;
    
    /// Get top N workers by reputation
    /// @param count: Number of workers to return
    /// @return: Array of top workers
    fn get_top_workers(self: @TContractState, count: u32) -> Array<WorkerRank>;

    /// Get workers within a reputation level
    /// @param level: Reputation level (1-5)
    /// @return: Array of workers in that level
    fn get_workers_by_level(self: @TContractState, level: u8) -> Array<WorkerRank>;

    // ============================================================================
    // Phase 2.1: Paginated Query Functions
    // ============================================================================

    /// Get top workers with pagination support
    /// @param offset: Starting index (0-based)
    /// @param limit: Maximum number of workers to return
    /// @return: Array of top workers in the specified range
    fn get_top_workers_paginated(
        self: @TContractState,
        offset: u32,
        limit: u32
    ) -> Array<WorkerRank>;

    /// Get workers by level with pagination support
    /// @param level: Reputation level (1-5)
    /// @param offset: Starting index (0-based)
    /// @param limit: Maximum number of workers to return
    /// @return: Array of workers in the specified level and range
    fn get_workers_by_level_paginated(
        self: @TContractState,
        level: u8,
        offset: u32,
        limit: u32
    ) -> Array<WorkerRank>;

    /// Get total count of workers at a specific level (useful for pagination)
    /// @param level: Reputation level (1-5)
    /// @return: Total count of workers at that level
    fn get_workers_count_by_level(self: @TContractState, level: u8) -> u32;
    
    /// Apply reputation decay for inactive workers (batch processing)
    /// @param cutoff_timestamp: Workers inactive since this time will have decay applied
    /// @return: Number of workers affected
    fn apply_inactivity_decay(ref self: TContractState, cutoff_timestamp: u64) -> u32;

    /// Apply inactivity decay in batches for gas efficiency (admin only)
    /// @param level: Reputation level to process
    /// @param start_index: Starting index in the level's worker list
    /// @param batch_size: Number of workers to process in this batch
    /// @return: (workers_processed, workers_decayed)
    fn apply_decay_batch(
        ref self: TContractState,
        level: u8,
        start_index: u32,
        batch_size: u32
    ) -> (u32, u32);

    /// Get reputation with lazy decay applied (view function)
    /// @param worker_id: Worker to query
    /// @return: Reputation score with any pending decay applied
    fn get_reputation_with_decay(self: @TContractState, worker_id: felt252) -> ReputationScore;

    /// Set decay configuration (admin only)
    /// @param decay_period_secs: Inactivity period before decay starts (seconds)
    /// @param decay_points_per_period: Points to deduct per decay period
    fn set_decay_config(
        ref self: TContractState,
        decay_period_secs: u64,
        decay_points_per_period: u32
    );
    
    /// Set reputation threshold for job types (admin only)
    /// @param job_type: Type of job
    /// @param threshold: New threshold requirements
    fn set_reputation_threshold(
        ref self: TContractState, 
        job_type: felt252, 
        threshold: ReputationThreshold
    );
    
    /// Admin function to manually adjust reputation
    /// @param worker_id: Worker to adjust
    /// @param new_score: New reputation score
    /// @param reason: Reason for adjustment
    fn admin_adjust_reputation(
        ref self: TContractState, 
        worker_id: felt252, 
        new_score: u32, 
        reason: felt252
    );
    
    /// Get reputation statistics for the network
    /// @return: Network-wide reputation statistics
    fn get_network_stats(self: @TContractState) -> (u32, u32, u32, u32); // (total_workers, avg_score, highest_score, lowest_score)

    // =========================================================================
    // Two-Step Admin Transfer
    // =========================================================================

    /// Start admin transfer (current admin only)
    fn transfer_admin(ref self: TContractState, new_admin: starknet::ContractAddress);

    /// Accept admin role (pending admin only)
    fn accept_admin(ref self: TContractState);

    /// Get current admin
    fn admin(self: @TContractState) -> starknet::ContractAddress;

    /// Get pending admin
    fn pending_admin(self: @TContractState) -> starknet::ContractAddress;

    // =========================================================================
    // Pausable
    // =========================================================================

    /// Pause the contract (admin only)
    fn pause(ref self: TContractState);

    /// Unpause the contract (admin only)
    fn unpause(ref self: TContractState);

    /// Check if contract is paused
    fn is_paused(self: @TContractState) -> bool;
} 