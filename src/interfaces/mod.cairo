// CIRO Network Contract Interfaces
// This module contains all the interfaces for CIRO Network smart contracts

pub mod job_manager;
pub mod cdc_pool;
pub mod paymaster;
pub mod ciro_token;
pub mod reputation_manager;

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

// Re-export commonly used types from ciro_token
pub use ciro_token::{
    ICIROToken, GovernanceProposal, BurnEvent, SecurityBudget
};

// Re-export commonly used types from reputation_manager
pub use reputation_manager::{
    IReputationManager, ReputationScore, ReputationEvent, ReputationReason, ReputationThreshold
}; 