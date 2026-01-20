//! Enhanced Job Manager Interface for SAGE Network
//! Supports both AI computation and ZK proof generation workloads
//! 
//! Strategic Vision: SAGE as permissionless GPU "power plant" serving:
//! 1. AI/ML training & inference (market-based $/GPU-hour)
//! 2. ZK proof generation for Starknet (deterministic $/batch)

use starknet::{ContractAddress, ClassHash};
use core::array::Array;

// Enhanced Job ID system supporting multiple job types
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct JobId {
    pub value: u256
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerId {
    pub value: felt252
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ModelId {
    pub value: u256
}

// Dispute evidence structure - Remove Store trait due to Array field
#[derive(Drop, Serde)]
pub struct DisputeEvidence {
    pub evidence_type: felt252,
    pub data: Array<felt252>, // Arrays can't be stored directly
    pub timestamp: u64,
    pub submitter: ContractAddress
}

// Job specification for AI workloads - Remove Store trait due to Array fields
#[derive(Drop, Serde)]
pub struct JobSpec {
    pub job_type: JobType,
    pub model_id: ModelId,
    pub input_data_hash: felt252,
    pub expected_output_format: felt252,
    pub verification_method: VerificationMethod,
    pub max_reward: u256,
    pub sla_deadline: u64,
    pub compute_requirements: Array<felt252>, // Arrays can't be stored directly
    pub metadata: Array<felt252> // Arrays can't be stored directly
}

// Result submission from workers - Remove Store trait due to Array field
#[derive(Drop, Serde)]
pub struct JobResult {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub output_data_hash: felt252,
    pub computation_proof: Array<felt252>, // Arrays can't be stored directly
    pub tee_quote: Array<felt252>, // TEE Attestation Quote
    pub gas_used: u256,
    pub execution_time: u64
}

// Job type enumeration
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum JobType {
    AIInference,
    AITraining,
    ProofGeneration,
    ProofVerification,
    DataPipeline,
    ConfidentialVM
}

// Verification method enumeration  
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum VerificationMethod {
    None,
    StatisticalSampling,
    ZeroKnowledgeProof,
    ConsensusValidation
}

// Job state enumeration
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum JobState {
    Queued,
    Processing,
    Completed,
    Paid,       // SECURITY: Added to prevent double-distribution of rewards
    Failed,
    Cancelled
}

// Model requirements - Remove Store trait due to Array field
#[derive(Drop, Serde)]
pub struct ModelRequirements {
    pub min_memory_gb: u32,
    pub min_compute_units: u32,
    pub required_gpu_type: felt252,
    pub framework_dependencies: Array<felt252> // Arrays can't be stored directly
}

// Proof job specific data - Remove Store trait due to Array field
#[derive(Drop, Serde)]
pub struct ProveJobData {
    pub circuit_id: felt252,
    pub public_inputs: Array<felt252>, // Arrays can't be stored directly
    pub private_inputs_hash: felt252,
    pub expected_proof_size: u32
}

// Job details for queries - simplified to avoid Array issues
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct JobDetails {
    pub job_id: JobId,
    pub job_type: JobType,
    pub client: ContractAddress,
    pub worker: ContractAddress,
    pub state: JobState,
    pub payment_amount: u256,
    pub created_at: u64,
    pub assigned_at: u64,
    pub completed_at: u64,
    pub result_hash: felt252
}

// Worker statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerStats {
    pub total_jobs_completed: u64,
    pub success_rate: u8, // Percentage
    pub average_completion_time: u64,
    pub reputation_score: u256,
    pub total_earnings: u256
}

/// Main Job Manager Interface
#[starknet::interface]
pub trait IJobManager<TContractState> {
    /// Submit a new AI inference/training job
    fn submit_ai_job(
        ref self: TContractState,
        job_spec: JobSpec,
        payment: u256,
        client: ContractAddress
    ) -> JobId;

    /// Submit a new proof generation job  
    fn submit_prove_job(
        ref self: TContractState,
        prove_job_data: ProveJobData,
        payment: u256,
        client: ContractAddress
    ) -> JobId;

    /// Assign a job to a specific worker (admin only)
    fn assign_job_to_worker(
        ref self: TContractState,
        job_id: JobId,
        worker_id: WorkerId
    );

    /// Claim a job directly (decentralized - any registered worker can claim)
    /// Workers call this to claim available jobs without coordinator
    fn claim_job(
        ref self: TContractState,
        job_id: JobId
    );

    /// Get list of pending job IDs (for workers to find available work)
    fn get_pending_jobs(self: @TContractState, offset: u64, limit: u64) -> Array<JobId>;

    /// Get count of pending jobs
    fn get_pending_job_count(self: @TContractState) -> u64;

    /// Submit job execution results
    fn submit_job_result(
        ref self: TContractState,
        job_id: JobId,
        result: JobResult
    );

    /// Distribute rewards after job completion and verification
    fn distribute_rewards(ref self: TContractState, job_id: JobId);

    /// Register a new model for job execution
    fn register_model(
        ref self: TContractState,
        model_hash: felt252,
        requirements: ModelRequirements,
        pricing: u256
    ) -> ModelId;

    /// Get detailed information about a job
    fn get_job_details(self: @TContractState, job_id: JobId) -> JobDetails;

    /// Get current state of a job
    fn get_job_state(self: @TContractState, job_id: JobId) -> JobState;

    /// Get worker statistics
    fn get_worker_stats(self: @TContractState, worker_id: WorkerId) -> WorkerStats;

    /// Admin: Update configuration parameters
    fn update_config(ref self: TContractState, config_key: felt252, config_value: felt252);

    /// Admin: Pause the contract
    fn pause(ref self: TContractState);

    /// Admin: Unpause the contract  
    fn unpause(ref self: TContractState);

    /// Admin: Emergency withdraw
    fn emergency_withdraw(ref self: TContractState, token: ContractAddress, amount: u256);

    /// Register a worker with their address
    fn register_worker(ref self: TContractState, worker_id: WorkerId, worker_address: ContractAddress);

    // Cairo 2.12.0: Gas Reserve Functions for Compute Job Optimization
    
    /// Estimate gas requirement for a job based on job specification
    fn estimate_job_gas_requirement(self: @TContractState, job_spec: JobSpec) -> u256;

    /// Reserve gas for job execution to prevent failures
    fn reserve_gas_for_job(ref self: TContractState, job_id: JobId, estimated_gas: u256);

    /// Optimize gas allocation based on worker efficiency
    fn optimize_worker_gas_allocation(
        self: @TContractState, 
        worker_id: WorkerId, 
        job_type: JobType
    ) -> u256;

    /// Update base gas cost for a specific model
    fn update_model_gas_cost(
        ref self: TContractState, 
        model_id: ModelId, 
        base_gas_cost: u256
    );

    /// Get gas efficiency metrics for a job (estimated, reserved, actual)
    fn get_job_gas_efficiency(self: @TContractState, job_id: JobId) -> (u256, u256, u256);

    // ============================================================================
    // PHASE 2: Additional View Functions
    // ============================================================================

    /// Get total number of jobs submitted
    fn get_total_jobs(self: @TContractState) -> u64;

    /// Get number of currently active (in-progress) jobs
    fn get_active_jobs(self: @TContractState) -> u64;

    /// Get number of completed jobs
    fn get_completed_jobs(self: @TContractState) -> u64;

    /// Get worker address from worker ID
    fn get_worker_address(self: @TContractState, worker_id: WorkerId) -> ContractAddress;

    /// Get worker ID from address (reverse lookup)
    fn get_worker_id_by_address(self: @TContractState, worker_address: ContractAddress) -> WorkerId;

    /// Get total registered worker count
    fn get_worker_count(self: @TContractState) -> u64;

    /// Check if a worker is active
    fn is_worker_active(self: @TContractState, worker_id: WorkerId) -> bool;

    /// Check if contract is paused
    fn is_paused(self: @TContractState) -> bool;

    /// Get platform configuration values
    fn get_platform_config(self: @TContractState) -> (u16, u256, u64, u256); // (fee_bps, min_payment, max_duration, dispute_fee)

    // ============================================================================
    // PHASE 3: Proof-Gated Payment Integration
    // ============================================================================

    /// Admin: Set ProofGatedPayment contract address for proof-based payment release
    fn set_proof_gated_payment(ref self: TContractState, payment: ContractAddress);

    /// Check if proof is verified and payment is ready for a job
    fn is_proof_payment_ready(self: @TContractState, job_id: JobId) -> bool;

    // ============================================================================
    // Contract Integration Setup Functions
    // ============================================================================

    /// Admin: Set ReputationManager contract address
    /// @param reputation_manager: The ReputationManager contract address (cannot be zero)
    fn set_reputation_manager(ref self: TContractState, reputation_manager: ContractAddress);

    /// Admin: Set CDC Pool contract address
    /// @param cdc_pool: The CDC Pool contract address (cannot be zero)
    fn set_cdc_pool_contract(ref self: TContractState, cdc_pool: ContractAddress);

    /// Get integration contract addresses
    /// @return (reputation_manager, cdc_pool, proof_gated_payment)
    fn get_integration_contracts(self: @TContractState) -> (ContractAddress, ContractAddress, ContractAddress);

    // ============================================================================
    // Circuit Breaker Functions
    // ============================================================================

    /// Admin: Enable circuit breaker to skip CDC Pool calls (for emergency use)
    /// @param duration: How long to keep circuit breaker active (in seconds)
    fn enable_cdc_pool_circuit_breaker(ref self: TContractState, duration: u64);

    /// Admin: Disable circuit breaker to resume CDC Pool calls
    fn disable_cdc_pool_circuit_breaker(ref self: TContractState);

    /// Check if circuit breaker is currently active
    /// @return (is_active, expires_at)
    fn get_circuit_breaker_status(self: @TContractState) -> (bool, u64);

    // ============================================================================
    // Upgrade Functions
    // ============================================================================

    /// Schedule a contract upgrade with timelock
    /// @param new_class_hash: The new class hash to upgrade to
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);

    /// Execute a scheduled upgrade after timelock expires
    fn execute_upgrade(ref self: TContractState);

    /// Cancel a pending upgrade
    fn cancel_upgrade(ref self: TContractState);

    /// Get upgrade information (pending_class_hash, scheduled_at, delay)
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);

    /// Set the upgrade timelock delay
    /// @param delay: New delay in seconds (must be between 1 and 30 days)
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
} 