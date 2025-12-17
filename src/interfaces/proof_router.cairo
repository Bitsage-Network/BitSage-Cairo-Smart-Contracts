//! Proof Router Interface
//!
//! Provides a unified entry point for proof verification that routes
//! proofs to the appropriate verifier based on proof type and source.
//!
//! Flow:
//! 1. Client submits proof with type/source metadata
//! 2. Router selects appropriate verifier (STWO GPU-TEE vs Standard)
//! 3. Router delegates verification and returns result
//! 4. Router triggers economics (rewards/slashing) based on result

use starknet::ContractAddress;

/// Proof source indicating where/how the proof was generated
#[derive(Copy, Drop, Serde, PartialEq)]
pub enum ProofSource {
    /// Standard STWO proof generated on CPU (SIMD backend)
    StandardSTWO,
    /// GPU-accelerated STWO proof with TEE attestation
    GpuTeeSTWO,
    /// External/third-party prover
    External,
}

/// Proof type indicating what kind of computation was proven
#[derive(Copy, Drop, Serde, PartialEq)]
pub enum ProofType {
    /// Starknet transaction batch execution
    StarknetBatch,
    /// Recursive proof aggregation
    RecursiveProof,
    /// ZKML inference computation
    ZKMLInference,
    /// Cross-chain bridge verification
    CrossChainBridge,
    /// Generic computation proof
    GenericComputation,
}

/// Economics action to take after verification
#[derive(Copy, Drop, Serde, PartialEq)]
pub enum EconomicsAction {
    /// No economic action needed
    None,
    /// Distribute rewards to prover
    DistributeReward,
    /// Slash prover collateral (fraud detected)
    SlashCollateral,
    /// Refund job submitter (proof failed)
    RefundSubmitter,
}

/// Verification result with economics metadata
#[derive(Copy, Drop, Serde)]
pub struct VerificationResult {
    /// Whether the proof was verified successfully
    pub is_valid: bool,
    /// Hash of the verified proof
    pub proof_hash: felt252,
    /// Security bits achieved
    pub security_bits: u32,
    /// Economics action to take
    pub economics_action: EconomicsAction,
    /// Reward amount (if applicable)
    pub reward_amount: u256,
    /// Slash amount (if applicable)
    pub slash_amount: u256,
}

/// Proof submission request
#[derive(Drop, Serde)]
pub struct ProofRequest {
    /// Unique job ID
    pub job_id: u256,
    /// Proof data
    pub proof_data: Array<felt252>,
    /// Hash of public inputs
    pub public_input_hash: felt252,
    /// Proof type
    pub proof_type: ProofType,
    /// Proof source
    pub proof_source: ProofSource,
    /// Prover address
    pub prover: ContractAddress,
    /// TEE attestation (for GPU-TEE proofs)
    pub tee_attestation: Option<TeeAttestationData>,
}

/// TEE attestation data for GPU-TEE proofs
#[derive(Copy, Drop, Serde)]
pub struct TeeAttestationData {
    /// TEE type (1=TDX, 2=SEV-SNP, 3=NVIDIA CC)
    pub tee_type: u8,
    /// Enclave measurement hash
    pub enclave_measurement: felt252,
    /// Quote hash
    pub quote_hash: felt252,
    /// Attestation timestamp
    pub attestation_timestamp: u64,
}

#[starknet::interface]
pub trait IProofRouter<TContractState> {
    /// Submit and verify a proof, routing to appropriate verifier
    /// Returns verification result with economics action
    fn verify_and_route(
        ref self: TContractState,
        request: ProofRequest,
    ) -> VerificationResult;

    /// Get recommended verifier for a proof type/source combination
    fn get_verifier_for(
        self: @TContractState,
        proof_type: ProofType,
        proof_source: ProofSource,
    ) -> ContractAddress;

    /// Set verifier address for a proof type/source combination (admin only)
    fn set_verifier(
        ref self: TContractState,
        proof_type: ProofType,
        proof_source: ProofSource,
        verifier: ContractAddress,
    );

    /// Set economics contracts (admin only)
    fn set_economics_contracts(
        ref self: TContractState,
        collateral_manager: ContractAddress,
        fee_manager: ContractAddress,
        reward_distributor: ContractAddress,
    );

    /// Get minimum security bits for a proof type
    fn get_min_security_bits(
        self: @TContractState,
        proof_type: ProofType,
    ) -> u32;

    /// Set minimum security bits for a proof type (admin only)
    fn set_min_security_bits(
        ref self: TContractState,
        proof_type: ProofType,
        min_bits: u32,
    );

    /// Execute economics action based on verification result (internal)
    fn execute_economics(
        ref self: TContractState,
        result: VerificationResult,
        prover: ContractAddress,
        job_id: u256,
    );

    /// Pause/unpause the router (admin only)
    fn set_paused(ref self: TContractState, paused: bool);

    /// Check if router is paused
    fn is_paused(self: @TContractState) -> bool;
}

/// Events emitted by the proof router
#[derive(Drop, starknet::Event)]
pub struct ProofRouted {
    #[key]
    pub job_id: u256,
    pub proof_type: ProofType,
    pub proof_source: ProofSource,
    pub verifier: ContractAddress,
    pub is_valid: bool,
    pub economics_action: EconomicsAction,
}

#[derive(Drop, starknet::Event)]
pub struct VerifierUpdated {
    pub proof_type: ProofType,
    pub proof_source: ProofSource,
    pub verifier: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct EconomicsExecuted {
    #[key]
    pub job_id: u256,
    pub action: EconomicsAction,
    pub amount: u256,
    pub recipient: ContractAddress,
}
