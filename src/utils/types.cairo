/// System-wide utility types for CIRO Network contracts

/// Job type enumeration
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum JobType {
    AIInference,
    AITraining,
    ComputerVision,
    NLP,
    AudioProcessing,
    TimeSeriesAnalysis,
    MultimodalAI,
    ReinforcementLearning,
    SpecializedAI,
    ProofGeneration,
    ProofVerification,
    DataProcessing,
    Custom
}

/// Job state enumeration (external facing)
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum JobState {
    Queued,
    Processing,
    Completed,
    Failed,
    Cancelled
}

/// Verification method enumeration
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum VerificationMethod {
    None,
    StatisticalSampling,
    ZeroKnowledgeProof,
    MultiPartyComputation,
    ConsensusValidation
}

/// Model ID wrapper
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ModelId {
    pub value: u256
}

/// Worker ID wrapper  
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerId {
    pub value: felt252
}

/// Job ID wrapper
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct JobId {
    pub value: u256
}

/// Model requirements - Remove Copy and Store traits due to Array field
#[derive(Drop, Serde)]
pub struct ModelRequirements {
    pub min_memory_gb: u32,
    pub min_compute_units: u32,
    pub required_gpu_type: felt252,
    pub framework_dependencies: Array<felt252> // Arrays cannot be Copy or Store
}

/// Job result structure - Remove Copy and Store traits due to Array field
#[derive(Drop, Serde)]  
pub struct JobResult {
    pub job_id: JobId,
    pub worker_id: WorkerId,
    pub output_data_hash: felt252,
    pub computation_proof: Array<felt252>, // Arrays cannot be Copy or Store
    pub gas_used: u256,
    pub execution_time: u64
}

/// Priority levels for jobs
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum JobPriority {
    Low,
    Normal,
    High,
    Critical
}

/// Worker reputation tiers
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum WorkerTier {
    Bronze,
    Silver,
    Gold,
    Platinum,
    Diamond
}

/// Allocation status for workers
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum AllocationStatus {
    Available,
    Reserved,
    Busy,
    Offline,
    Slashed
}

/// Network phases for governance
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum NetworkPhase {
    Bootstrap,
    Growth,
    Maturity,
    Decline
}

/// Simple percentage type (0-100)
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum Percentage {
    Value: u8 // 0-100
}

/// Reputation score (0-1000)
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum ReputationScore {
    Score: u16 // 0-1000
} 