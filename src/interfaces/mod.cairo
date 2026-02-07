// SAGE Network Contract Interfaces
// This module contains all the interfaces for SAGE Network smart contracts

pub mod job_manager;
pub mod cdc_pool;
pub mod paymaster;
pub mod sage_token;
pub mod reputation_manager;
pub mod proof_verifier;
pub mod proof_router;

// Re-export commonly used types from job_manager
pub use job_manager::{IJobManager, JobId, ModelId, WorkerId, JobStatus, JobSpec, JobResult, ModelRequirements};

// Re-export commonly used types from cdc_pool
pub use cdc_pool::{
    ICDCPool, WorkerStatus, WorkerCapabilities, WorkerProfile, PerformanceMetrics,
    StakeInfo, UnstakeRequest, SlashReason, SlashRecord, AllocationResult
};

// Re-export commonly used types from paymaster
pub use paymaster::{
    IPaymaster, SubscriptionTier, PaymentChannel, Subscription, SponsorshipRequest, RateLimit
};

// Re-export commonly used types from sage_token
pub use sage_token::{
    ISAGEToken, IERC20CamelOnly, GovernanceProposal, BurnEvent, SecurityBudget
};

// Re-export commonly used types from reputation_manager
pub use reputation_manager::{
    IReputationManager, ReputationScore, ReputationEvent, ReputationReason, ReputationThreshold, WorkerRank
}; 