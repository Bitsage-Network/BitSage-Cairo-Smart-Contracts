use starknet::ContractAddress;
use super::job_manager::{JobId, WorkerId, ModelRequirements};

/// Worker capability flags (bitfield)
/// Each bit represents a specific capability
pub const CAPABILITY_CUDA: u64 = 1;           // CUDA support
pub const CAPABILITY_OPENCL: u64 = 2;         // OpenCL support  
pub const CAPABILITY_FP16: u64 = 4;           // Half precision support
pub const CAPABILITY_INT8: u64 = 8;           // INT8 quantization
pub const CAPABILITY_NVLINK: u64 = 16;        // NVLink support
pub const CAPABILITY_INFINIBAND: u64 = 32;    // InfiniBand networking
pub const CAPABILITY_TENSOR_CORES: u64 = 64;  // Tensor core support
pub const CAPABILITY_MULTI_GPU: u64 = 128;    // Multi-GPU support

/// Worker status enumeration
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum WorkerStatus {
    Active,      // Available for job assignments
    Inactive,    // Temporarily unavailable
    Slashed,     // Penalized for misconduct
    Exiting,     // In the process of leaving the network
    Banned,      // Permanently excluded from the network
}

/// Worker hardware specifications
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerCapabilities {
    pub gpu_memory: u64,           // GPU memory in GB
    pub cpu_cores: u8,             // Number of CPU cores
    pub ram: u64,                  // System RAM in GB
    pub storage: u64,              // Available storage in GB
    pub bandwidth: u32,            // Network bandwidth in Mbps
    pub capability_flags: u64,     // Bitfield of capabilities
    pub gpu_model: felt252,        // GPU model identifier
    pub cpu_model: felt252,        // CPU model identifier
}

/// Worker profile structure
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerProfile {
    pub worker_id: WorkerId,
    pub owner: ContractAddress,
    pub capabilities: WorkerCapabilities,
    pub status: WorkerStatus,
    pub registered_at: u64,        // Registration timestamp
    pub last_heartbeat: u64,       // Last activity timestamp
    pub stake_amount: u256,        // Current stake amount
    pub reputation_score: u64,     // Reputation score (0-1000)
    pub jobs_completed: u32,       // Total jobs completed
    pub jobs_failed: u32,          // Total jobs failed
    pub total_earnings: u256,      // Total earnings in wei
    pub location_hash: felt252,    // Hashed location for privacy
}

/// Performance metrics for workers
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PerformanceMetrics {
    pub avg_response_time: u64,    // Average response time in seconds
    pub completion_rate: u8,       // Completion rate percentage (0-100)
    pub quality_score: u8,         // Average quality score (0-100)
    pub uptime_percentage: u8,     // Uptime percentage (0-100)
    pub last_updated: u64,         // Last metrics update timestamp
}

/// Slashing record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SlashRecord {
    pub worker: ContractAddress,
    pub reason: SlashReason,
    pub amount: u256,
    pub timestamp: u64,
    pub evidence_hash: felt252,
}

/// Worker Staking Tier Enumeration (v3.1 - Realistic Capital Deployment)
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum WorkerTier {
    Basic,          // $100 - entry level
    Premium,        // $500 - serious commitment  
    Enterprise,     // $2,500 - business tier
    Infrastructure, // $10,000 - data center tier
    Fleet,          // $50,000 - small fleet operators
    Datacenter,     // $100,000 - major operators
    Hyperscale,     // $250,000 - hyperscale operators
    Institutional,  // $500,000 - institutional grade
}

/// Large Holder Tier Enumeration (CIRO-Fixed with USD floors) 
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum HolderTier {
    Regular,        // < 5M CIRO
    Whale,          // 5M+ CIRO + $2M+ USD value
    Institution,    // 25M+ CIRO + $10M+ USD value
    HyperWhale,     // 100M+ CIRO + $50M+ USD value
}

/// Worker Tier Benefits
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerTierBenefits {
    pub tier: WorkerTier,
    pub usd_requirement: u256,           // USD requirement in cents
    pub allocation_priority: u256,       // Job allocation priority multiplier
    pub performance_bonus_bps: u256,     // Performance bonus in basis points
    pub min_reputation_required: u64,    // Minimum reputation to achieve this tier
}

/// Enhanced Stake Info with Tiers
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct StakeInfo {
    pub amount: u256,           // CIRO tokens staked
    pub usd_value: u256,        // Current USD value in cents
    pub tier: WorkerTier,       // Current staking tier
    pub locked_until: u64,      // Lock expiration timestamp
    pub last_adjustment: u64,   // Last tier requirement adjustment
    pub last_reward_block: u64, // Last reward calculation block
    pub delegated_amount: u256, // Amount delegated to this worker
    pub performance_score: u64, // Performance-based score
}

/// Unstaking request
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct UnstakeRequest {
    pub worker: ContractAddress,
    pub amount: u256,
    pub unlock_time: u64,
    pub is_complete_exit: bool,
}

/// Slashing reasons
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum SlashReason {
    Malicious,          // Intentionally incorrect results
    Unavailable,        // Failed to respond to assignments
    PoorPerformance,    // Consistently poor performance
    ProtocolViolation,  // Violated network protocol
    Fraud,              // Fraudulent behavior
}

/// Add Into<u8> implementation for SlashReason
impl SlashReasonIntoU8 of Into<SlashReason, u8> {
    fn into(self: SlashReason) -> u8 {
        match self {
            SlashReason::Malicious => 0,
            SlashReason::Unavailable => 1, 
            SlashReason::PoorPerformance => 2,
            SlashReason::ProtocolViolation => 3,
            SlashReason::Fraud => 4,
        }
    }
}

/// Add Into<felt252> implementation for SlashReason
impl SlashReasonIntoFelt252 of Into<SlashReason, felt252> {
    fn into(self: SlashReason) -> felt252 {
        match self {
            SlashReason::Malicious => 'malicious',
            SlashReason::Unavailable => 'unavailable',
            SlashReason::PoorPerformance => 'poor_performance',
            SlashReason::ProtocolViolation => 'protocol_violation',
            SlashReason::Fraud => 'fraud',
        }
    }
}

/// Add Into<u8> implementation for WorkerStatus
impl WorkerStatusIntoU8 of Into<WorkerStatus, u8> {
    fn into(self: WorkerStatus) -> u8 {
        match self {
            WorkerStatus::Active => 1,
            WorkerStatus::Inactive => 2,
            WorkerStatus::Slashed => 4,
            WorkerStatus::Exiting => 8,
            WorkerStatus::Banned => 16,
        }
    }
}

/// Job allocation result
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AllocationResult {
    pub worker: ContractAddress,
    pub confidence_score: u8,      // Confidence in allocation (0-100)
    pub estimated_completion: u64, // Estimated completion time
}

/// Main CDC Pool interface
#[starknet::interface]
pub trait ICDCPool<TContractState> {
    /// Worker Registration Functions
    
    /// Register a new worker with capabilities and initial stake
    /// @param capabilities: Worker's hardware capabilities
    /// @param proof_of_resources: Cryptographic proof of claimed resources
    /// @param location_hash: Hashed location for privacy-preserving matching
    /// @return worker_id: Unique identifier for the registered worker
    fn register_worker(
        ref self: TContractState,
        capabilities: WorkerCapabilities,
        proof_of_resources: Array<felt252>,
        location_hash: felt252
    ) -> WorkerId;
    
    /// Update worker capabilities (requires re-verification)
    /// @param worker_id: Worker to update
    /// @param new_capabilities: Updated capabilities
    /// @param proof_of_resources: Proof of new capabilities
    fn update_worker_capabilities(
        ref self: TContractState,
        worker_id: WorkerId,
        new_capabilities: WorkerCapabilities,
        proof_of_resources: Array<felt252>
    );
    
    /// Deactivate worker (temporarily unavailable)
    /// @param worker_id: Worker to deactivate
    /// @param reason: Reason for deactivation
    fn deactivate_worker(ref self: TContractState, worker_id: WorkerId, reason: felt252);
    
    /// Reactivate worker (return to active status)
    /// @param worker_id: Worker to reactivate
    fn reactivate_worker(ref self: TContractState, worker_id: WorkerId);
    
    /// Submit heartbeat to maintain active status
    /// @param worker_id: Worker submitting heartbeat
    /// @param performance_data: Current performance metrics
    fn submit_heartbeat(
        ref self: TContractState,
        worker_id: WorkerId,
        performance_data: PerformanceMetrics
    );
    
    /// Staking Functions
    
    /// Stake tokens to participate in the network
    /// @param amount: Amount to stake
    /// @param lock_period: Optional lock period for higher rewards
    fn stake(ref self: TContractState, amount: u256, lock_period: u64);
    
    /// Request unstaking (with time delay)
    /// @param amount: Amount to unstake
    /// @return unlock_time: When funds will be available
    fn request_unstake(ref self: TContractState, amount: u256) -> u64;
    
    /// Execute unstaking after delay period
    /// @param worker: Worker to unstake for
    fn execute_unstake(ref self: TContractState, worker: ContractAddress);
    
    /// Complete unstaking after delay period (caller-based)
    fn complete_unstake(ref self: TContractState);
    
    /// Increase stake amount
    /// @param additional_amount: Additional amount to stake
    fn increase_stake(ref self: TContractState, additional_amount: u256);
    
    /// Delegate stake to another worker
    /// @param worker: Worker to delegate to
    /// @param amount: Amount to delegate
    fn delegate_stake(ref self: TContractState, worker: ContractAddress, amount: u256);
    
    /// Job Allocation Functions
    
    /// Allocate a job to the best available worker
    /// @param job_id: Job to allocate
    /// @param requirements: Job requirements
    /// @param priority: Job priority (0-255)
    /// @param max_latency: Maximum acceptable latency
    /// @return allocation: Allocation result with worker and confidence
    fn allocate_job(
        ref self: TContractState,
        job_id: JobId,
        requirements: ModelRequirements,
        priority: u8,
        max_latency: u64
    ) -> AllocationResult;
    
    /// Get eligible workers for a job
    /// @param requirements: Job requirements
    /// @param max_results: Maximum number of results
    /// @return workers: Array of eligible worker IDs
    fn get_eligible_workers(
        self: @TContractState,
        requirements: ModelRequirements,
        max_results: u32
    ) -> Array<WorkerId>;
    
    /// Reserve worker for a job (temporary allocation)
    /// @param worker_id: Worker to reserve
    /// @param job_id: Job to reserve for
    /// @param duration: Reservation duration in seconds
    fn reserve_worker(
        ref self: TContractState,
        worker_id: WorkerId,
        job_id: JobId,
        duration: u64
    );
    
    /// Release worker reservation
    /// @param worker_id: Worker to release
    /// @param job_id: Job to release for
    fn release_worker(ref self: TContractState, worker_id: WorkerId, job_id: JobId);
    
    /// Reputation and Performance Functions
    
    /// Update worker reputation based on job performance
    /// @param worker_id: Worker to update
    /// @param job_id: Completed job
    /// @param performance_score: Performance score (0-100)
    /// @param response_time: Response time in seconds
    /// @param quality_score: Quality score (0-100)
    fn update_reputation(
        ref self: TContractState,
        worker_id: WorkerId,
        job_id: JobId,
        performance_score: u8,
        response_time: u64,
        quality_score: u8
    );
    
    /// Record job completion
    /// @param worker_id: Worker who completed the job
    /// @param job_id: Completed job
    /// @param success: Whether job was successful
    /// @param execution_time: Time taken to complete
    fn record_job_completion(
        ref self: TContractState,
        worker_id: WorkerId,
        job_id: JobId,
        success: bool,
        execution_time: u64
    );
    
    /// Get worker performance metrics
    /// @param worker_id: Worker to query
    /// @return metrics: Current performance metrics
    fn get_performance_metrics(
        self: @TContractState,
        worker_id: WorkerId
    ) -> PerformanceMetrics;
    
    /// Get worker metrics (alternative name)
    /// @param worker_id: Worker to query
    /// @return metrics: Current performance metrics
    fn get_worker_metrics(
        self: @TContractState,
        worker_id: WorkerId
    ) -> PerformanceMetrics;
    
    /// Slashing Functions
    
    /// Slash worker for misconduct
    /// @param worker_id: Worker to slash
    /// @param reason: Reason for slashing
    /// @param evidence: Evidence of misconduct
    /// @return slashed_amount: Amount slashed
    fn slash_worker(
        ref self: TContractState,
        worker_id: WorkerId,
        reason: SlashReason,
        evidence: Array<felt252>
    ) -> u256;
    
    /// Challenge a slashing decision
    /// @param worker_id: Worker challenging the slash
    /// @param evidence: Counter-evidence
    fn challenge_slash(
        ref self: TContractState,
        worker_id: WorkerId,
        evidence: Array<felt252>
    );
    
    /// Resolve slashing challenge
    /// @param worker_id: Worker being challenged
    /// @param upheld: Whether slashing is upheld
    fn resolve_slash_challenge(
        ref self: TContractState,
        worker_id: WorkerId,
        upheld: bool
    );
    
    /// Reward Distribution Functions
    
    /// Distribute rewards to workers
    /// @param worker_id: Worker to reward
    /// @param job_id: Job that earned the reward
    /// @param base_reward: Base reward amount
    /// @param performance_bonus: Performance-based bonus
    fn distribute_rewards(
        ref self: TContractState,
        worker_id: WorkerId,
        job_id: JobId,
        base_reward: u256,
        performance_bonus: u256
    );
    
    /// Distribute reward to worker (singular variant)
    /// @param worker_id: Worker to reward
    /// @param base_reward: Base reward amount
    /// @param performance_bonus: Performance-based bonus
    fn distribute_reward(
        ref self: TContractState,
        worker_id: WorkerId,
        base_reward: u256,
        performance_bonus: u256
    );
    
    /// Claim accumulated rewards
    /// @param worker_id: Worker claiming rewards
    /// @return amount: Amount claimed
    fn claim_rewards(ref self: TContractState, worker_id: WorkerId) -> u256;
    
    /// Calculate pending rewards
    /// @param worker_id: Worker to calculate for
    /// @return pending: Pending reward amount
    fn calculate_pending_rewards(self: @TContractState, worker_id: WorkerId) -> u256;
    
    /// Query Functions
    
    /// Get worker profile
    /// @param worker_id: Worker to query
    /// @return profile: Worker profile
    fn get_worker_profile(self: @TContractState, worker_id: WorkerId) -> WorkerProfile;
    
    /// Get worker capabilities
    /// @param worker_id: Worker to query
    /// @return capabilities: Worker capabilities
    fn get_worker_capabilities(self: @TContractState, worker_id: WorkerId) -> WorkerCapabilities;
    
    /// Get worker by owner address
    /// @param owner: Owner address
    /// @return worker_id: Worker ID (if exists)
    fn get_worker_by_owner(self: @TContractState, owner: ContractAddress) -> Option<WorkerId>;
    
    /// Get active workers count
    /// @return count: Number of active workers
    fn get_active_workers_count(self: @TContractState) -> u32;
    
    /// Get workers by capability
    /// @param capability_flags: Required capabilities
    /// @param min_reputation: Minimum reputation score
    /// @param max_results: Maximum results to return
    /// @return workers: Array of matching worker IDs
    fn get_workers_by_capability(
        self: @TContractState,
        capability_flags: u64,
        min_reputation: u64,
        max_results: u32
    ) -> Array<WorkerId>;
    
    /// Get network statistics
    /// @return total_workers: Total registered workers
    /// @return active_workers: Currently active workers
    /// @return total_stake: Total staked amount
    /// @return total_jobs: Total jobs processed
    fn get_network_stats(self: @TContractState) -> (u32, u32, u256, u32);
    
    /// Get worker leaderboard
    /// @param metric: Metric to sort by ('reputation', 'earnings', 'jobs')
    /// @param limit: Maximum results
    /// @return workers: Sorted array of worker IDs
    fn get_leaderboard(
        self: @TContractState,
        metric: felt252,
        limit: u32
    ) -> Array<WorkerId>;
    
    /// Get stake information
    /// @param worker: Worker to query
    /// @return stake_info: Staking information
    fn get_stake_info(self: @TContractState, worker: ContractAddress) -> StakeInfo;
    
    /// Get unstaking requests
    /// @param worker: Worker to query
    /// @return requests: Array of unstaking requests
    fn get_unstaking_requests(
        self: @TContractState,
        worker: ContractAddress
    ) -> Array<UnstakeRequest>;
    
    /// Get unstake requests (paginated)
    /// @param offset: Starting offset for pagination
    /// @param limit: Maximum number of results
    /// @return requests: Array of unstaking requests
    fn get_unstake_requests(
        self: @TContractState,
        offset: u32,
        limit: u32
    ) -> Array<UnstakeRequest>;
    
    /// Worker Tier Functions (v3.0 Tokenomics)
    
    /// Get current worker tier for a worker
    /// @param worker: Worker to query
    /// @return tier: Current worker tier
    fn get_worker_tier(self: @TContractState, worker: ContractAddress) -> WorkerTier;
    
    /// Get worker tier benefits
    /// @param tier: Worker tier to query
    /// @return benefits: Tier benefits structure
    fn get_worker_tier_benefits(self: @TContractState, tier: WorkerTier) -> WorkerTierBenefits;
    
    /// Get USD value of staked amount
    /// @param worker: Worker to query
    /// @return usd_value: USD value in cents
    fn get_stake_usd_value(self: @TContractState, worker: ContractAddress) -> u256;
    
    /// Get CIRO token requirement for a tier
    /// @param tier: Worker tier to query
    /// @return requirement: CIRO tokens required
    fn get_tier_ciro_requirement(self: @TContractState, tier: WorkerTier) -> u256;
    
    /// Update CIRO price (oracle function)
    /// @param new_price: New CIRO price in USD cents
    fn update_ciro_price(ref self: TContractState, new_price: u256);
    
    /// Check if worker meets tier requirements
    /// @param worker: Worker to check
    /// @param tier: Target tier
    /// @return meets_requirements: True if worker meets requirements
    fn meets_tier_requirements(self: @TContractState, worker: ContractAddress, tier: WorkerTier) -> bool;
    
    /// Get holder tier for governance
    /// @param holder: Token holder address
    /// @return tier: Holder tier (Regular, Whale, Institution)
    fn get_holder_tier(self: @TContractState, holder: ContractAddress) -> HolderTier;
    
    /// Get tier-based allocation score for job assignment
    /// @param worker: Worker to evaluate
    /// @param requirements: Job requirements
    /// @return score: Allocation score (higher = better priority)
    fn get_tier_allocation_score(
        self: @TContractState,
        worker: ContractAddress,
        requirements: ModelRequirements
    ) -> u256;
    
    /// Administrative Functions
    
    /// Update minimum stake requirement
    /// @param new_min_stake: New minimum stake amount
    fn update_min_stake(ref self: TContractState, new_min_stake: u256);
    
    /// Update slashing parameters
    /// @param reason: Slashing reason
    /// @param percentage: Slashing percentage
    fn update_slash_percentage(
        ref self: TContractState,
        reason: SlashReason,
        percentage: u8
    );
    
    /// Update reward parameters
    /// @param base_rate: Base reward rate
    /// @param performance_multiplier: Performance bonus multiplier
    fn update_reward_parameters(
        ref self: TContractState,
        base_rate: u256,
        performance_multiplier: u8
    );
    
    /// Pause contract operations
    fn pause_contract(ref self: TContractState);
    
    /// Resume contract operations
    fn resume_contract(ref self: TContractState);
    
    /// Emergency worker removal
    /// @param worker_id: Worker to remove
    /// @param reason: Reason for emergency removal
    fn emergency_remove_worker(
        ref self: TContractState,
        worker_id: WorkerId,
        reason: felt252
    );
}

/// Events emitted by the CDC Pool contract
#[derive(Drop, starknet::Event)]
pub struct WorkerRegistered {
    #[key]
    pub worker_id: WorkerId,
    #[key]
    pub owner: ContractAddress,
    pub capabilities: WorkerCapabilities,
    pub stake_amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct WorkerDeactivated {
    #[key]
    pub worker_id: WorkerId,
    pub reason: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct WorkerReactivated {
    #[key]
    pub worker_id: WorkerId,
}

#[derive(Drop, starknet::Event)]
pub struct StakeAdded {
    #[key]
    pub worker: ContractAddress,
    pub amount: u256,
    pub total_stake: u256,
}

#[derive(Drop, starknet::Event)]
pub struct UnstakeRequested {
    #[key]
    pub worker: ContractAddress,
    pub amount: u256,
    pub unlock_time: u64,
}

#[derive(Drop, starknet::Event)]
pub struct UnstakeExecuted {
    #[key]
    pub worker: ContractAddress,
    pub amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct JobAllocated {
    #[key]
    pub job_id: JobId,
    #[key]
    pub worker_id: WorkerId,
    pub confidence_score: u8,
    pub estimated_completion: u64,
}

#[derive(Drop, starknet::Event)]
pub struct WorkerReserved {
    #[key]
    pub worker_id: WorkerId,
    #[key]
    pub job_id: JobId,
    pub duration: u64,
}

#[derive(Drop, starknet::Event)]
pub struct WorkerReleased {
    #[key]
    pub worker_id: WorkerId,
    #[key]
    pub job_id: JobId,
}

#[derive(Drop, starknet::Event)]
pub struct ReputationUpdated {
    #[key]
    pub worker_id: WorkerId,
    pub old_score: u64,
    pub new_score: u64,
    pub job_id: JobId,
}

#[derive(Drop, starknet::Event)]
pub struct WorkerSlashed {
    #[key]
    pub worker_id: WorkerId,
    pub reason: SlashReason,
    pub amount: u256,
    pub evidence_hash: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct SlashChallenged {
    #[key]
    pub worker_id: WorkerId,
    pub challenger: ContractAddress,
    pub evidence_hash: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct RewardsDistributed {
    #[key]
    pub worker_id: WorkerId,
    #[key]
    pub job_id: JobId,
    pub base_reward: u256,
    pub performance_bonus: u256,
    pub total_reward: u256,
}

#[derive(Drop, starknet::Event)]
pub struct RewardsClaimed {
    #[key]
    pub worker_id: WorkerId,
    pub amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct HeartbeatSubmitted {
    #[key]
    pub worker_id: WorkerId,
    pub timestamp: u64,
    pub performance_data: PerformanceMetrics,
}

#[derive(Drop, starknet::Event)]
pub struct ParameterUpdated {
    pub parameter: felt252,
    pub old_value: u256,
    pub new_value: u256,
} 