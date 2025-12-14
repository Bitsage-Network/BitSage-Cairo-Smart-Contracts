//! ZK Proof Verifier Interface for SAGE Network
//! Handles proof generation jobs for Starknet and other ZK rollups
//! Critical component for positioning SAGE as blockchain scaling infrastructure

use core::array::Array;
use core::serde::Serde;
pub use super::job_manager::{WorkerId};

// ZK Proof specific identifiers
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofJobId {
    pub value: u256
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct BatchHash {
    pub value: felt252
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofHash {
    pub value: felt252
}

// ZK Proof job types
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum ProofType {
    StarknetBatch,
    RecursiveProof,
    ZKMLInference,
    CrossChainBridge,
    ApplicationSpecific
}

// Priority levels
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum ProofPriority {
    Standard,
    High,
    Critical,
    Emergency
}

// Proof job specification
// NOTE: Array<felt252> cannot be stored in Cairo 2.x storage directly.
// We store the hash of the input.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofJobSpec {
    pub job_id: ProofJobId,
    pub proof_type: ProofType,
    pub batch_hash: BatchHash,
    pub public_input_hash: felt252,
    pub priority: ProofPriority,
    pub reward_usdc: u256,
    pub bonus_ciro: u256,
    pub deadline_timestamp: u64,
    pub required_attestations: u8,
    pub min_stake_requirement: u256
}

// Proof submission
#[derive(Drop, Serde)]
pub struct ProofSubmission {
    pub job_id: ProofJobId,
    pub worker_id: WorkerId,
    pub proof_data: Array<felt252>,
    pub proof_hash: ProofHash,
    pub computation_time_ms: u64,
    pub gas_used: u64,
    pub attestation_signature: Array<felt252>
}

// Proof status
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum ProofStatus {
    Pending,
    InProgress,
    Verified,
    Failed,
    Expired,
    Disputed
}

// Metrics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProverMetrics {
    pub worker_id: WorkerId,
    pub proofs_completed: u64,
    pub success_rate: u16,
    pub average_completion_time: u64,
    pub stake_amount: u256,
    pub total_rewards_earned: u256,
    pub reputation_score: u16
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofEconomics {
    pub proof_type: ProofType,
    pub base_reward_usdc: u256,
    pub congestion_multiplier: u16,
    pub size_multiplier: u16
}

#[starknet::interface]
pub trait IProofVerifier<TContractState> {
    fn submit_proof_job(ref self: TContractState, spec: ProofJobSpec) -> ProofJobId;
    fn get_proof_job(self: @TContractState, job_id: ProofJobId) -> ProofJobSpec;
    fn get_pending_jobs(self: @TContractState, proof_type: ProofType, max_count: u32) -> Array<ProofJobId>;
    fn cancel_proof_job(ref self: TContractState, job_id: ProofJobId);
    fn submit_proof(ref self: TContractState, submission: ProofSubmission) -> bool;
    fn verify_proof(ref self: TContractState, job_id: ProofJobId, proof_data: Array<felt252>) -> bool;
    fn get_proof_status(self: @TContractState, job_id: ProofJobId) -> ProofStatus;
    fn resolve_dispute(ref self: TContractState, job_id: ProofJobId, canonical_proof: Array<felt252>);
    fn register_as_prover(
        ref self: TContractState, 
        worker_id: WorkerId, 
        stake_amount: u256, 
        supported_proof_types: Array<ProofType>
    );
    fn claim_proof_job(ref self: TContractState, job_id: ProofJobId, worker_id: WorkerId) -> bool;
    fn get_prover_metrics(self: @TContractState, worker_id: WorkerId) -> ProverMetrics;
    fn update_economics(ref self: TContractState, economics: ProofEconomics);
    fn withdraw_stake(ref self: TContractState, amount: u256);
    fn is_enclave_whitelisted(self: @TContractState, enclave_measurement: felt252) -> bool;
    fn whitelist_enclave(ref self: TContractState, enclave_measurement: felt252, valid: bool);
}
