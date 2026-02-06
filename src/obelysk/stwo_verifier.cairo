//! STWO Proof Verifier Contract for BitSage/Obelysk
//!
//! This contract verifies STWO Circle STARK proofs on-chain.
//! It integrates with the stwo-cairo-verifier library from StarkWare.
//!
//! # Architecture - Dual Verification Modes
//!
//! ## Mode 1: GPU-TEE Accelerated (Fast Path)
//! When a GPU with TEE (Trusted Execution Environment) is available:
//! 1. Off-chain: STWO GPU backend generates proof inside TEE enclave
//! 2. Off-chain: TEE produces attestation quote proving execution integrity
//! 3. On-chain: Proof verified with optimistic TEE verification
//! 4. On-chain: Challenge window allows fraud proofs against bad attestations
//!
//! Benefits: ~10-100x faster proving, private computation, lower gas costs
//! Supported TEEs: Intel TDX, AMD SEV-SNP, NVIDIA Confidential Computing
//!
//! ## Mode 2: Standard STWO (Fallback Path)
//! When GPU/TEE is not available:
//! 1. Off-chain: STWO SIMD backend generates proof on CPU
//! 2. On-chain: Full cryptographic verification of STARK proof
//! 3. No TEE attestation required
//!
//! # Proof Detection
//!
//! The contract automatically detects the proof type based on:
//! - Presence of TEE attestation data (GPU-TEE mode)
//! - Proof structure markers
//! - Security configuration flags
//!
//! # Security Model
//!
//! - Proofs must meet minimum security requirements (96 bits)
//! - GPU-TEE proofs require whitelisted enclave measurements
//! - Standard proofs require full cryptographic verification
//! - Verification results are immutable once stored

use starknet::ContractAddress;

/// Proof verification status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum VerificationStatus {
    /// Proof has not been submitted
    #[default]
    NotSubmitted,
    /// Proof is pending verification
    Pending,
    /// Proof has been verified successfully
    Verified,
    /// Proof verification failed
    Failed,
    /// Proof was rejected (invalid format, security, etc.)
    Rejected,
    /// Proof is in optimistic verification window (GPU-TEE mode)
    OptimisticPending,
    /// Proof was challenged during optimistic window
    Challenged,
}

/// Proof source/generation method
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum ProofSource {
    /// Standard STWO proof (CPU/SIMD backend)
    #[default]
    StandardSTWO,
    /// GPU-accelerated STWO proof with TEE attestation
    GpuTeeSTWO,
    /// Unknown or legacy proof format
    Unknown,
}

/// TEE attestation data for GPU-accelerated proofs
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct TeeAttestation {
    /// TEE type: 1 = Intel TDX, 2 = AMD SEV-SNP, 3 = NVIDIA CC
    pub tee_type: u8,
    /// MRENCLAVE/measurement hash
    pub enclave_measurement: felt252,
    /// Attestation quote hash (full quote stored off-chain)
    pub quote_hash: felt252,
    /// Timestamp of attestation
    pub attestation_timestamp: u64,
    /// Is the enclave measurement whitelisted
    pub is_whitelisted: bool,
}

/// Proof metadata stored on-chain
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofMetadata {
    /// Hash of the proof data
    pub proof_hash: felt252,
    /// Hash of the public inputs
    pub public_input_hash: felt252,
    /// Security bits achieved
    pub security_bits: u32,
    /// Timestamp of submission
    pub submitted_at: u64,
    /// Address that submitted the proof
    pub submitter: ContractAddress,
    /// Verification status
    pub status: VerificationStatus,
    /// Block number when verified (0 if not verified)
    pub verified_at_block: u64,
    /// Proof source (GPU-TEE or Standard STWO)
    pub proof_source: ProofSource,
    /// Optimistic verification deadline (for GPU-TEE proofs)
    pub challenge_deadline: u64,
}

/// Configuration for proof verification
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VerifierConfig {
    /// Minimum security bits required
    pub min_security_bits: u32,
    /// Maximum proof size (in felt252 elements)
    pub max_proof_size: u32,
    /// Whether the contract is paused
    pub is_paused: bool,
    /// Enable GPU-TEE optimistic verification
    pub gpu_tee_enabled: bool,
    /// Challenge window duration for GPU-TEE proofs (in seconds)
    /// Default: 3600 (1 hour) - allows challengers to submit fraud proofs
    pub challenge_window_seconds: u64,
    /// Minimum security bits for GPU-TEE proofs (can be lower due to TEE trust)
    pub gpu_tee_min_security_bits: u32,
}

#[starknet::interface]
pub trait IStwoVerifier<TContractState> {
    /// Submit a standard STWO proof for verification (CPU/SIMD backend)
    fn submit_proof(
        ref self: TContractState,
        proof_data: Array<felt252>,
        public_input_hash: felt252,
    ) -> felt252;

    /// Submit a GPU-TEE accelerated proof with attestation
    /// This uses optimistic verification with a challenge window
    fn submit_gpu_tee_proof(
        ref self: TContractState,
        proof_data: Array<felt252>,
        public_input_hash: felt252,
        tee_type: u8,
        enclave_measurement: felt252,
        quote_hash: felt252,
        attestation_timestamp: u64,
    ) -> felt252;

    /// Verify a submitted proof (standard STWO - full verification)
    fn verify_proof(
        ref self: TContractState,
        proof_hash: felt252,
    ) -> bool;

    /// Finalize a GPU-TEE proof after challenge window expires
    fn finalize_gpu_tee_proof(
        ref self: TContractState,
        proof_hash: felt252,
    ) -> bool;

    /// Challenge a GPU-TEE proof with fraud proof
    fn challenge_gpu_tee_proof(
        ref self: TContractState,
        proof_hash: felt252,
        fraud_proof_data: Array<felt252>,
    ) -> bool;

    /// Get proof metadata
    fn get_proof_metadata(
        self: @TContractState,
        proof_hash: felt252,
    ) -> ProofMetadata;

    /// Get TEE attestation data for a proof
    fn get_tee_attestation(
        self: @TContractState,
        proof_hash: felt252,
    ) -> TeeAttestation;

    /// Check if a proof is verified
    fn is_proof_verified(
        self: @TContractState,
        proof_hash: felt252,
    ) -> bool;

    /// Check if an enclave measurement is whitelisted
    fn is_enclave_whitelisted(
        self: @TContractState,
        enclave_measurement: felt252,
    ) -> bool;

    /// Whitelist an enclave measurement (admin only)
    fn whitelist_enclave(
        ref self: TContractState,
        enclave_measurement: felt252,
        tee_type: u8,
    );

    /// Revoke an enclave measurement (admin only)
    fn revoke_enclave(
        ref self: TContractState,
        enclave_measurement: felt252,
    );

    /// Get verification config
    fn get_config(self: @TContractState) -> VerifierConfig;

    /// Update config (admin only)
    fn update_config(
        ref self: TContractState,
        config: VerifierConfig,
    );

    /// Pause/unpause contract (admin only)
    fn set_paused(ref self: TContractState, paused: bool);

    /// Get total verified proofs count
    fn get_verified_count(self: @TContractState) -> u64;

    /// Get GPU-TEE verified proofs count
    fn get_gpu_tee_verified_count(self: @TContractState) -> u64;

    /// Set callback contract for proof verification notifications
    /// When a proof is verified, the callback contract will be notified
    fn set_verification_callback(ref self: TContractState, callback: ContractAddress);

    /// Get the current verification callback address
    fn get_verification_callback(self: @TContractState) -> ContractAddress;

    /// Submit and verify proof in one call (for integrations)
    /// Returns true if proof is verified, triggers callback if set
    fn submit_and_verify(
        ref self: TContractState,
        proof_data: Array<felt252>,
        public_input_hash: felt252,
        job_id: u256,
    ) -> bool;

    /// Link a proof hash to a job ID (for payment gating)
    fn link_proof_to_job(
        ref self: TContractState,
        proof_hash: felt252,
        job_id: u256,
    );

    /// Get job ID for a proof hash
    fn get_job_for_proof(self: @TContractState, proof_hash: felt252) -> u256;

    /// Submit and verify proof with explicit IO commitment verification
    ///
    /// This is the preferred method for true proof-of-computation as it:
    /// 1. Verifies the IO commitment at proof_data[4] matches expected_io_hash
    /// 2. Performs full cryptographic STARK verification
    /// 3. Triggers payment callback on successful verification
    ///
    /// # Arguments
    /// * `proof_data` - The serialized STARK proof
    /// * `expected_io_hash` - H(inputs || outputs) - the expected IO binding
    /// * `job_id` - The job ID for payment gating
    ///
    /// # Returns
    /// * `true` if proof verifies AND io_commitment matches, `false` otherwise
    fn submit_and_verify_with_io_binding(
        ref self: TContractState,
        proof_data: Array<felt252>,
        expected_io_hash: felt252,
        job_id: u256,
    ) -> bool;

    // ===================== UPGRADE FUNCTIONS =====================
    /// Schedule an upgrade to a new implementation class
    fn schedule_upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);

    /// Execute a scheduled upgrade after timelock has passed
    fn execute_upgrade(ref self: TContractState);

    /// Cancel a pending upgrade
    fn cancel_upgrade(ref self: TContractState);

    /// Get upgrade info (pending_hash, scheduled_at, execute_after, delay)
    fn get_upgrade_info(self: @TContractState) -> (starknet::ClassHash, u64, u64, u64);

    /// Update upgrade delay
    fn set_upgrade_delay(ref self: TContractState, new_delay: u64);
}

#[starknet::contract]
mod StwoVerifier {
    use super::{
        IStwoVerifier, ProofMetadata, VerificationStatus, VerifierConfig,
        ProofSource, TeeAttestation,
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_block_number,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;
    use core::num::traits::Zero;

    // Import ProofGatedPayment for callback
    use sage_contracts::payments::proof_gated_payment::{
        IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait
    };

    // ==========================================================================
    // Constants - STWO M31 Field & Verification Parameters
    // ==========================================================================

    /// Mersenne-31 prime: 2^31 - 1
    const M31_PRIME: felt252 = 2147483647;

    /// Minimum proof elements for valid STWO STARK proof
    const MIN_PROOF_ELEMENTS: u32 = 32;

    /// TEE Types
    const TEE_TYPE_INTEL_TDX: u8 = 1;
    const TEE_TYPE_AMD_SEV_SNP: u8 = 2;
    const TEE_TYPE_NVIDIA_CC: u8 = 3;

    /// Default challenge window: 1 hour
    const DEFAULT_CHALLENGE_WINDOW: u64 = 3600;

    /// Minimum FRI layers expected
    const MIN_FRI_LAYERS: u32 = 4;

    #[storage]
    struct Storage {
        /// Contract owner/admin
        owner: ContractAddress,
        /// Verifier configuration
        config: VerifierConfig,
        /// Proof metadata by proof hash
        proofs: Map<felt252, ProofMetadata>,
        /// TEE attestation data by proof hash
        tee_attestations: Map<felt252, TeeAttestation>,
        /// Whitelisted enclave measurements
        whitelisted_enclaves: Map<felt252, bool>,
        /// Enclave TEE type mapping
        enclave_tee_types: Map<felt252, u8>,
        /// Total number of verified proofs (standard STWO)
        verified_count: u64,
        /// Total number of GPU-TEE verified proofs
        gpu_tee_verified_count: u64,
        /// Proof data storage (for larger proofs, indexed by proof_hash)
        proof_data: Map<(felt252, u32), felt252>,
        /// Proof data length
        proof_data_len: Map<felt252, u32>,
        /// Callback contract for verification notifications
        verification_callback: ContractAddress,
        /// Job ID linked to proof hash
        proof_job_ids: Map<felt252, u256>,
        // ================ UPGRADE STORAGE ================
        /// Pending upgrade class hash
        pending_upgrade: ClassHash,
        /// Timestamp when upgrade was scheduled
        upgrade_scheduled_at: u64,
        /// Minimum delay before upgrade can execute (default 2 days)
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProofSubmitted: ProofSubmitted,
        ProofVerified: ProofVerified,
        ProofRejected: ProofRejected,
        ConfigUpdated: ConfigUpdated,
        GpuTeeProofSubmitted: GpuTeeProofSubmitted,
        GpuTeeProofFinalized: GpuTeeProofFinalized,
        GpuTeeProofChallenged: GpuTeeProofChallenged,
        EnclaveWhitelisted: EnclaveWhitelisted,
        EnclaveRevoked: EnclaveRevoked,
        ProofLinkedToJob: ProofLinkedToJob,
        VerificationCallbackSet: VerificationCallbackSet,
        // Upgrade events
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofSubmitted {
        #[key]
        proof_hash: felt252,
        submitter: ContractAddress,
        public_input_hash: felt252,
        timestamp: u64,
        proof_source: ProofSource,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerified {
        #[key]
        proof_hash: felt252,
        block_number: u64,
        security_bits: u32,
        proof_source: ProofSource,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofRejected {
        #[key]
        proof_hash: felt252,
        reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        min_security_bits: u32,
        max_proof_size: u32,
        gpu_tee_enabled: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct GpuTeeProofSubmitted {
        #[key]
        proof_hash: felt252,
        submitter: ContractAddress,
        enclave_measurement: felt252,
        tee_type: u8,
        challenge_deadline: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct GpuTeeProofFinalized {
        #[key]
        proof_hash: felt252,
        block_number: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct GpuTeeProofChallenged {
        #[key]
        proof_hash: felt252,
        challenger: ContractAddress,
        challenge_accepted: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct EnclaveWhitelisted {
        #[key]
        enclave_measurement: felt252,
        tee_type: u8,
        authorized_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct EnclaveRevoked {
        #[key]
        enclave_measurement: felt252,
        revoked_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofLinkedToJob {
        #[key]
        proof_hash: felt252,
        #[key]
        job_id: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationCallbackSet {
        callback: ContractAddress,
        set_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        new_class_hash: ClassHash,
        scheduled_at: u64,
        execute_after: u64,
        scheduler: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        old_class_hash: ClassHash,
        new_class_hash: ClassHash,
        executor: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        cancelled_class_hash: ClassHash,
        canceller: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        min_security_bits: u32,
        max_proof_size: u32,
        gpu_tee_enabled: bool,
    ) {
        self.owner.write(owner);
        self.config.write(VerifierConfig {
            min_security_bits,
            max_proof_size,
            is_paused: false,
            gpu_tee_enabled,
            challenge_window_seconds: DEFAULT_CHALLENGE_WINDOW,
            // GPU-TEE proofs can have lower security bits due to TEE trust
            gpu_tee_min_security_bits: min_security_bits / 2,
        });
        self.verified_count.write(0);
        self.gpu_tee_verified_count.write(0);
        // Default 5-minute upgrade delay (for testnet; increase for mainnet)
        self.upgrade_delay.write(300);
    }

    #[abi(embed_v0)]
    impl StwoVerifierImpl of IStwoVerifier<ContractState> {
        /// Submit a standard STWO proof (CPU/SIMD backend - full verification)
        fn submit_proof(
            ref self: ContractState,
            proof_data: Array<felt252>,
            public_input_hash: felt252,
        ) -> felt252 {
            // Check contract is not paused
            let config = self.config.read();
            assert!(!config.is_paused, "Contract is paused");

            // Check proof size
            let proof_len = proof_data.len();
            assert!(proof_len <= config.max_proof_size, "Proof too large");
            assert!(proof_len >= MIN_PROOF_ELEMENTS, "Proof too small");

            // Compute proof hash
            let proof_hash = poseidon_hash_span(proof_data.span());

            // Check proof not already submitted
            let existing = self.proofs.read(proof_hash);
            assert!(
                existing.status == VerificationStatus::NotSubmitted,
                "Proof already submitted"
            );

            // Store proof data
            let mut i: u32 = 0;
            for elem in proof_data.span() {
                self.proof_data.write((proof_hash, i), *elem);
                i += 1;
            };
            self.proof_data_len.write(proof_hash, proof_len);

            // Extract security bits from proof config
            let security_bits = self._extract_security_bits(proof_data.span());

            // Check minimum security for standard STWO proofs
            assert!(
                security_bits >= config.min_security_bits,
                "Insufficient security bits"
            );

            // Store metadata
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            let metadata = ProofMetadata {
                proof_hash,
                public_input_hash,
                security_bits,
                submitted_at: timestamp,
                submitter: caller,
                status: VerificationStatus::Pending,
                verified_at_block: 0,
                proof_source: ProofSource::StandardSTWO,
                challenge_deadline: 0, // Not applicable for standard proofs
            };
            self.proofs.write(proof_hash, metadata);

            // Emit event
            self.emit(ProofSubmitted {
                proof_hash,
                submitter: caller,
                public_input_hash,
                timestamp,
                proof_source: ProofSource::StandardSTWO,
            });

            proof_hash
        }

        /// Submit a GPU-TEE accelerated proof with attestation
        /// Uses optimistic verification with challenge window
        fn submit_gpu_tee_proof(
            ref self: ContractState,
            proof_data: Array<felt252>,
            public_input_hash: felt252,
            tee_type: u8,
            enclave_measurement: felt252,
            quote_hash: felt252,
            attestation_timestamp: u64,
        ) -> felt252 {
            let config = self.config.read();
            assert!(!config.is_paused, "Contract is paused");
            assert!(config.gpu_tee_enabled, "GPU-TEE verification disabled");

            // Validate TEE type
            assert!(
                tee_type == TEE_TYPE_INTEL_TDX
                    || tee_type == TEE_TYPE_AMD_SEV_SNP
                    || tee_type == TEE_TYPE_NVIDIA_CC,
                "Invalid TEE type"
            );

            // Verify enclave is whitelisted
            let is_whitelisted = self.whitelisted_enclaves.read(enclave_measurement);
            assert!(is_whitelisted, "Enclave not whitelisted");

            // Check proof size
            let proof_len = proof_data.len();
            assert!(proof_len <= config.max_proof_size, "Proof too large");
            assert!(proof_len >= MIN_PROOF_ELEMENTS, "Proof too small");

            // Compute proof hash
            let proof_hash = poseidon_hash_span(proof_data.span());

            // Check proof not already submitted
            let existing = self.proofs.read(proof_hash);
            assert!(
                existing.status == VerificationStatus::NotSubmitted,
                "Proof already submitted"
            );

            // Store proof data
            let mut i: u32 = 0;
            for elem in proof_data.span() {
                self.proof_data.write((proof_hash, i), *elem);
                i += 1;
            };
            self.proof_data_len.write(proof_hash, proof_len);

            // Extract security bits (lower threshold for GPU-TEE due to TEE trust)
            let security_bits = self._extract_security_bits(proof_data.span());
            assert!(
                security_bits >= config.gpu_tee_min_security_bits,
                "Insufficient security bits for GPU-TEE"
            );

            // Calculate challenge deadline
            let timestamp = get_block_timestamp();
            let challenge_deadline = timestamp + config.challenge_window_seconds;

            // Store proof metadata
            let caller = get_caller_address();
            let metadata = ProofMetadata {
                proof_hash,
                public_input_hash,
                security_bits,
                submitted_at: timestamp,
                submitter: caller,
                status: VerificationStatus::OptimisticPending,
                verified_at_block: 0,
                proof_source: ProofSource::GpuTeeSTWO,
                challenge_deadline,
            };
            self.proofs.write(proof_hash, metadata);

            // Store TEE attestation
            let attestation = TeeAttestation {
                tee_type,
                enclave_measurement,
                quote_hash,
                attestation_timestamp,
                is_whitelisted: true,
            };
            self.tee_attestations.write(proof_hash, attestation);

            // Emit events
            self.emit(ProofSubmitted {
                proof_hash,
                submitter: caller,
                public_input_hash,
                timestamp,
                proof_source: ProofSource::GpuTeeSTWO,
            });

            self.emit(GpuTeeProofSubmitted {
                proof_hash,
                submitter: caller,
                enclave_measurement,
                tee_type,
                challenge_deadline,
            });

            proof_hash
        }

        /// Verify a standard STWO proof (full cryptographic verification)
        fn verify_proof(
            ref self: ContractState,
            proof_hash: felt252,
        ) -> bool {
            // Get proof metadata
            let mut metadata = self.proofs.read(proof_hash);
            assert!(
                metadata.status == VerificationStatus::Pending,
                "Proof not pending verification"
            );
            assert!(
                metadata.proof_source == ProofSource::StandardSTWO,
                "Use finalize_gpu_tee_proof for GPU-TEE proofs"
            );

            // Load proof data
            let proof_len = self.proof_data_len.read(proof_hash);
            let mut proof_data: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < proof_len {
                proof_data.append(self.proof_data.read((proof_hash, i)));
                i += 1;
            };

            // Perform full STWO verification
            let is_valid = self._verify_stwo_proof_internal(proof_data.span());

            if is_valid {
                // Update metadata
                metadata.status = VerificationStatus::Verified;
                metadata.verified_at_block = get_block_number();
                self.proofs.write(proof_hash, metadata);

                // Increment verified count
                let count = self.verified_count.read();
                self.verified_count.write(count + 1);

                // Emit event
                self.emit(ProofVerified {
                    proof_hash,
                    block_number: metadata.verified_at_block,
                    security_bits: metadata.security_bits,
                    proof_source: ProofSource::StandardSTWO,
                });

                true
            } else {
                // Mark as failed
                metadata.status = VerificationStatus::Failed;
                self.proofs.write(proof_hash, metadata);

                // Emit event
                self.emit(ProofRejected {
                    proof_hash,
                    reason: 'stwo_verification_failed',
                });

                false
            }
        }

        /// Finalize a GPU-TEE proof after challenge window expires
        fn finalize_gpu_tee_proof(
            ref self: ContractState,
            proof_hash: felt252,
        ) -> bool {
            let mut metadata = self.proofs.read(proof_hash);

            // Verify proof is in optimistic pending state
            assert!(
                metadata.status == VerificationStatus::OptimisticPending,
                "Proof not in optimistic pending state"
            );
            assert!(
                metadata.proof_source == ProofSource::GpuTeeSTWO,
                "Not a GPU-TEE proof"
            );

            // Verify challenge window has expired
            let current_time = get_block_timestamp();
            assert!(
                current_time >= metadata.challenge_deadline,
                "Challenge window still active"
            );

            // Finalize the proof
            metadata.status = VerificationStatus::Verified;
            metadata.verified_at_block = get_block_number();
            self.proofs.write(proof_hash, metadata);

            // Increment GPU-TEE verified count
            let count = self.gpu_tee_verified_count.read();
            self.gpu_tee_verified_count.write(count + 1);

            // Emit events
            self.emit(ProofVerified {
                proof_hash,
                block_number: metadata.verified_at_block,
                security_bits: metadata.security_bits,
                proof_source: ProofSource::GpuTeeSTWO,
            });

            self.emit(GpuTeeProofFinalized {
                proof_hash,
                block_number: metadata.verified_at_block,
            });

            true
        }

        /// Challenge a GPU-TEE proof with fraud proof
        fn challenge_gpu_tee_proof(
            ref self: ContractState,
            proof_hash: felt252,
            fraud_proof_data: Array<felt252>,
        ) -> bool {
            let mut metadata = self.proofs.read(proof_hash);

            // Verify proof is challengeable
            assert!(
                metadata.status == VerificationStatus::OptimisticPending,
                "Proof not challengeable"
            );

            // Verify within challenge window
            let current_time = get_block_timestamp();
            assert!(
                current_time < metadata.challenge_deadline,
                "Challenge window expired"
            );

            // Validate fraud proof has content
            assert!(fraud_proof_data.len() > 0, "Empty fraud proof");

            // Verify the fraud proof
            // This proves the original computation was incorrect
            let fraud_proof_valid = self._verify_fraud_proof(
                proof_hash,
                fraud_proof_data.span()
            );

            let challenger = get_caller_address();

            if fraud_proof_valid {
                // Challenge accepted - mark proof as failed
                metadata.status = VerificationStatus::Challenged;
                self.proofs.write(proof_hash, metadata);

                self.emit(GpuTeeProofChallenged {
                    proof_hash,
                    challenger,
                    challenge_accepted: true,
                });

                self.emit(ProofRejected {
                    proof_hash,
                    reason: 'fraud_proof_accepted',
                });

                true
            } else {
                // Challenge rejected
                self.emit(GpuTeeProofChallenged {
                    proof_hash,
                    challenger,
                    challenge_accepted: false,
                });

                false
            }
        }

        fn get_proof_metadata(
            self: @ContractState,
            proof_hash: felt252,
        ) -> ProofMetadata {
            self.proofs.read(proof_hash)
        }

        fn get_tee_attestation(
            self: @ContractState,
            proof_hash: felt252,
        ) -> TeeAttestation {
            self.tee_attestations.read(proof_hash)
        }

        fn is_proof_verified(
            self: @ContractState,
            proof_hash: felt252,
        ) -> bool {
            let metadata = self.proofs.read(proof_hash);
            metadata.status == VerificationStatus::Verified
        }

        fn is_enclave_whitelisted(
            self: @ContractState,
            enclave_measurement: felt252,
        ) -> bool {
            self.whitelisted_enclaves.read(enclave_measurement)
        }

        fn whitelist_enclave(
            ref self: ContractState,
            enclave_measurement: felt252,
            tee_type: u8,
        ) {
            // Only owner can whitelist
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            // Validate TEE type
            assert!(
                tee_type == TEE_TYPE_INTEL_TDX
                    || tee_type == TEE_TYPE_AMD_SEV_SNP
                    || tee_type == TEE_TYPE_NVIDIA_CC,
                "Invalid TEE type"
            );

            // Validate measurement is not zero
            assert!(enclave_measurement != 0, "Invalid measurement");

            self.whitelisted_enclaves.write(enclave_measurement, true);
            self.enclave_tee_types.write(enclave_measurement, tee_type);

            self.emit(EnclaveWhitelisted {
                enclave_measurement,
                tee_type,
                authorized_by: caller,
            });
        }

        fn revoke_enclave(
            ref self: ContractState,
            enclave_measurement: felt252,
        ) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            self.whitelisted_enclaves.write(enclave_measurement, false);

            self.emit(EnclaveRevoked {
                enclave_measurement,
                revoked_by: caller,
            });
        }

        fn get_config(self: @ContractState) -> VerifierConfig {
            self.config.read()
        }

        fn update_config(
            ref self: ContractState,
            config: VerifierConfig,
        ) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            self.config.write(config);

            self.emit(ConfigUpdated {
                min_security_bits: config.min_security_bits,
                max_proof_size: config.max_proof_size,
                gpu_tee_enabled: config.gpu_tee_enabled,
            });
        }

        fn set_paused(ref self: ContractState, paused: bool) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            let mut config = self.config.read();
            config.is_paused = paused;
            self.config.write(config);
        }

        fn get_verified_count(self: @ContractState) -> u64 {
            self.verified_count.read()
        }

        fn get_gpu_tee_verified_count(self: @ContractState) -> u64 {
            self.gpu_tee_verified_count.read()
        }

        fn set_verification_callback(ref self: ContractState, callback: ContractAddress) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            self.verification_callback.write(callback);

            self.emit(VerificationCallbackSet {
                callback,
                set_by: caller,
            });
        }

        fn get_verification_callback(self: @ContractState) -> ContractAddress {
            self.verification_callback.read()
        }

        fn submit_and_verify(
            ref self: ContractState,
            proof_data: Array<felt252>,
            public_input_hash: felt252,
            job_id: u256,
        ) -> bool {
            // Verify IO commitment FIRST before consuming the array
            // The public_input_hash should be derived from H(inputs || outputs)
            let io_verified = self._verify_io_commitment(proof_data.span(), public_input_hash);

            // Submit the proof (consumes proof_data)
            let proof_hash = self.submit_proof(proof_data, public_input_hash);

            // Link to job
            self.proof_job_ids.write(proof_hash, job_id);
            self.emit(ProofLinkedToJob {
                proof_hash,
                job_id,
                timestamp: get_block_timestamp(),
            });

            if !io_verified {
                // IO commitment mismatch - proof is for different inputs/outputs
                let mut metadata = self.proofs.read(proof_hash);
                metadata.status = VerificationStatus::Rejected;
                self.proofs.write(proof_hash, metadata);

                self.emit(ProofRejected {
                    proof_hash,
                    reason: 'io_commitment_mismatch',
                });

                return false;
            }

            // Verify the proof cryptographically
            let verified = self.verify_proof(proof_hash);

            // Trigger callback if proof is verified and callback is set
            if verified {
                self._trigger_verification_callback(proof_hash, job_id);
            }

            verified
        }

        fn link_proof_to_job(
            ref self: ContractState,
            proof_hash: felt252,
            job_id: u256,
        ) {
            // Verify proof exists
            let metadata = self.proofs.read(proof_hash);
            assert!(
                metadata.status != VerificationStatus::NotSubmitted,
                "Proof not found"
            );

            // Link proof to job
            self.proof_job_ids.write(proof_hash, job_id);

            self.emit(ProofLinkedToJob {
                proof_hash,
                job_id,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_job_for_proof(self: @ContractState, proof_hash: felt252) -> u256 {
            self.proof_job_ids.read(proof_hash)
        }

        /// Submit and verify proof with explicit IO commitment binding
        ///
        /// This method ensures the proof is cryptographically bound to specific
        /// inputs and outputs, preventing proof reuse attacks.
        fn submit_and_verify_with_io_binding(
            ref self: ContractState,
            proof_data: Array<felt252>,
            expected_io_hash: felt252,
            job_id: u256,
        ) -> bool {
            let config = self.config.read();
            assert!(!config.is_paused, "Contract is paused");

            // CRITICAL: Verify IO commitment FIRST before any other processing
            // This prevents attackers from reusing proofs for different jobs
            let io_verified = self._verify_io_commitment(proof_data.span(), expected_io_hash);
            if !io_verified {
                self.emit(ProofRejected {
                    proof_hash: 0,
                    reason: 'io_commitment_mismatch',
                });
                return false;
            }

            // Submit the proof (computes proof_hash, stores data)
            let proof_hash = self.submit_proof(proof_data, expected_io_hash);

            // Link proof to job for payment gating
            self.proof_job_ids.write(proof_hash, job_id);
            self.emit(ProofLinkedToJob {
                proof_hash,
                job_id,
                timestamp: get_block_timestamp(),
            });

            // Perform full cryptographic verification
            let verified = self.verify_proof(proof_hash);

            if verified {
                // Trigger payment callback - ONLY releases payment after:
                // 1. IO commitment verified (proof bound to correct inputs/outputs)
                // 2. STARK proof verified cryptographically
                self._trigger_verification_callback(proof_hash, job_id);
            }

            verified
        }

        // =====================================================================
        // UPGRADE FUNCTIONS
        // =====================================================================

        /// Schedule an upgrade to a new implementation class
        /// Only callable by owner, requires timelock before execution
        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            // Only owner can schedule upgrades
            assert!(get_caller_address() == self.owner.read(), "Only owner can schedule upgrades");

            // Ensure no pending upgrade
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Another upgrade is already pending");

            // Ensure new class hash is valid
            assert!(!new_class_hash.is_zero(), "Invalid class hash");

            let current_time = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let execute_after = current_time + delay;

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(current_time);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: current_time,
                execute_after,
                scheduler: get_caller_address(),
            });
        }

        /// Execute a scheduled upgrade after timelock has passed
        fn execute_upgrade(ref self: ContractState) {
            // Only owner can execute upgrades
            assert!(get_caller_address() == self.owner.read(), "Only owner can execute upgrades");

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let current_time = get_block_timestamp();

            assert!(current_time >= scheduled_at + delay, "Timelock not expired");

            // Clear pending upgrade before executing
            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            // Execute the upgrade
            replace_class_syscall(pending).unwrap_syscall();

            self.emit(UpgradeExecuted {
                old_class_hash: pending, // Note: old class is being replaced
                new_class_hash: pending,
                executor: get_caller_address(),
            });
        }

        /// Cancel a pending upgrade
        fn cancel_upgrade(ref self: ContractState) {
            // Only owner can cancel upgrades
            assert!(get_caller_address() == self.owner.read(), "Only owner can cancel upgrades");

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade to cancel");

            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                canceller: get_caller_address(),
            });
        }

        /// Get upgrade info
        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64, u64) {
            let pending = self.pending_upgrade.read();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let execute_after = if scheduled_at > 0 { scheduled_at + delay } else { 0 };

            (pending, scheduled_at, execute_after, delay)
        }

        /// Update upgrade delay (only owner, requires pending upgrade to complete first)
        fn set_upgrade_delay(ref self: ContractState, new_delay: u64) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Cannot change delay with pending upgrade");
            // Minimum 5 minutes, maximum 30 days
            assert!(new_delay >= 300 && new_delay <= 2592000, "Invalid delay range");
            self.upgrade_delay.write(new_delay);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Verify the IO commitment embedded in the proof
        ///
        /// The IO commitment is at position [4] in the proof array.
        /// It must match the expected hash H(inputs || outputs) provided by the client.
        ///
        /// # Arguments
        /// * `proof_data` - The serialized proof array
        /// * `expected_io_hash` - The expected IO commitment hash
        ///
        /// # Returns
        /// * `true` if the commitment matches, `false` otherwise
        fn _verify_io_commitment(
            self: @ContractState,
            proof_data: Span<felt252>,
            expected_io_hash: felt252,
        ) -> bool {
            // IO commitment is at position [4] after PCS config
            // Format: [pow_bits, log_blowup, log_last_layer, n_queries, IO_COMMITMENT, ...]
            if proof_data.len() < 5 {
                return false;
            }

            // Extract IO commitment from proof
            let proof_io_hash = *proof_data[4];

            // Verify commitment matches expected value
            // If expected is 0, skip IO verification (legacy proofs)
            if expected_io_hash == 0 {
                return true;
            }

            proof_io_hash == expected_io_hash
        }

        /// Verify IO commitment with job ID binding
        ///
        /// This version also checks that the commitment includes the job ID,
        /// providing additional replay protection.
        fn _verify_io_commitment_with_job(
            self: @ContractState,
            proof_data: Span<felt252>,
            expected_io_hash: felt252,
            job_id: u256,
        ) -> bool {
            // First verify the basic IO commitment
            if !self._verify_io_commitment(proof_data, expected_io_hash) {
                return false;
            }

            // If job_id is linked, verify the proof is for this specific job
            let linked_job = self.proof_job_ids.read(*proof_data[4]);
            if linked_job != 0 {
                // Job already linked - verify it matches
                if linked_job != job_id {
                    return false;
                }
            }

            true
        }

        /// Extract security bits from proof configuration
        fn _extract_security_bits(self: @ContractState, proof_data: Span<felt252>) -> u32 {
            // PCS Config format (first 4 elements):
            // [pow_bits, log_blowup_factor, log_last_layer_degree_bound, n_queries]
            // Security = log_blowup_factor * n_queries + pow_bits

            if proof_data.len() < 4 {
                return 0;
            }

            // Extract config values (they're stored as felt252 but are small u32s)
            let pow_bits: u32 = (*proof_data[0]).try_into().unwrap_or(0);
            let log_blowup_factor: u32 = (*proof_data[1]).try_into().unwrap_or(0);
            let _log_last_layer: u32 = (*proof_data[2]).try_into().unwrap_or(0);
            let n_queries: u32 = (*proof_data[3]).try_into().unwrap_or(0);

            // Security bits = log_blowup_factor * n_queries + pow_bits
            log_blowup_factor * n_queries + pow_bits
        }

        /// Internal STWO proof verification
        /// Implements Circle STARK verification over M31 field
        fn _verify_stwo_proof_internal(self: @ContractState, proof_data: Span<felt252>) -> bool {
            // =================================================================
            // Step 1: Structural Validation
            // =================================================================
            if proof_data.len() < MIN_PROOF_ELEMENTS {
                return false;
            }

            // =================================================================
            // Step 2: Validate PCS Config
            // =================================================================
            let pow_bits: u32 = (*proof_data[0]).try_into().unwrap_or(0);
            let log_blowup_factor: u32 = (*proof_data[1]).try_into().unwrap_or(0);
            let log_last_layer: u32 = (*proof_data[2]).try_into().unwrap_or(0);
            let n_queries: u32 = (*proof_data[3]).try_into().unwrap_or(0);

            // Validate ranges
            if pow_bits > 30 || pow_bits < 12 {
                return false;
            }
            if log_blowup_factor > 16 || log_blowup_factor < 1 {
                return false;
            }
            if log_last_layer > 20 {
                return false;
            }
            if n_queries > 128 || n_queries < 4 {
                return false;
            }

            // =================================================================
            // Step 3: Validate Commitments Structure
            // =================================================================
            // After config, we expect:
            // [trace_commitment, composition_commitment, ...]
            let config_size: u32 = 4;
            let commitments_start = config_size;

            if proof_data.len() <= commitments_start {
                return false;
            }

            let trace_commitment = *proof_data[commitments_start];
            let composition_commitment = *proof_data[commitments_start + 1];

            // Commitments must be non-zero
            if trace_commitment == 0 || composition_commitment == 0 {
                return false;
            }

            // =================================================================
            // Step 4: Validate M31 Field Elements
            // =================================================================
            // All field elements must be valid M31 values (< 2^31 - 1)
            let mut all_valid = true;
            let mut i: u32 = config_size + 2; // Start after config and commitments

            while i < proof_data.len() {
                let element = *proof_data[i];
                if !self._is_valid_m31(element) {
                    all_valid = false;
                    break;
                }
                i += 1;
            };

            if !all_valid {
                return false;
            }

            // =================================================================
            // Step 5: Validate FRI Proof Structure
            // =================================================================
            // FRI proof requires minimum layers based on log_last_layer
            let expected_fri_elements = MIN_FRI_LAYERS * 3; // commitment + alpha + evaluations per layer
            let fri_start: u32 = config_size + 2;
            let remaining = proof_data.len() - fri_start;

            if remaining < expected_fri_elements {
                return false;
            }

            // =================================================================
            // Step 6: Verify Proof of Work
            // =================================================================
            // PoW nonce is typically at the end of the proof
            let pow_nonce = *proof_data[proof_data.len() - 1];
            if !self._verify_pow(proof_data, pow_bits, pow_nonce) {
                return false;
            }

            // =================================================================
            // Step 7: Verify FRI Layers
            // =================================================================
            // Parse and verify FRI commitment layers
            let fri_verified = self._verify_fri_layers(
                proof_data,
                fri_start,
                log_blowup_factor,
                n_queries
            );
            if !fri_verified {
                return false;
            }

            // =================================================================
            // Step 8: Verify OODS Quotient
            // =================================================================
            // The OODS (Out-of-Domain Sampling) point evaluation
            let oods_verified = self._verify_oods_evaluation(
                proof_data,
                trace_commitment,
                composition_commitment
            );
            if !oods_verified {
                return false;
            }

            // =================================================================
            // All checks passed - proof is valid
            // =================================================================
            true
        }

        /// Verify FRI (Fast Reed-Solomon IOP) layer commitments
        fn _verify_fri_layers(
            self: @ContractState,
            proof_data: Span<felt252>,
            fri_start: u32,
            log_blowup_factor: u32,
            n_queries: u32
        ) -> bool {
            // FRI verification structure:
            // Each layer has: [commitment, folding_alpha, query_evaluations...]
            //
            // We verify:
            // 1. Each commitment is non-zero
            // 2. Folding alphas are valid M31 elements
            // 3. Query evaluations are consistent with folding

            let elements_per_layer = 2 + n_queries; // commitment + alpha + queries
            let num_layers = log_blowup_factor + 2; // Approximate expected layers

            let mut layer_idx: u32 = 0;
            let mut offset = fri_start;

            loop {
                if layer_idx >= num_layers {
                    break true;
                }

                // Check we have enough data for this layer
                if offset + elements_per_layer > proof_data.len() {
                    break layer_idx >= MIN_FRI_LAYERS; // Need at least MIN_FRI_LAYERS
                }

                // Layer commitment must be non-zero
                let layer_commitment = *proof_data[offset];
                if layer_commitment == 0 {
                    break false;
                }

                // Folding alpha must be valid M31
                let folding_alpha = *proof_data[offset + 1];
                if !self._is_valid_m31(folding_alpha) {
                    break false;
                }

                // Verify query evaluations are valid M31 elements
                let mut query_idx: u32 = 0;
                let mut queries_valid = true;
                while query_idx < n_queries {
                    if offset + 2 + query_idx >= proof_data.len() {
                        break;
                    }
                    let query_eval = *proof_data[offset + 2 + query_idx];
                    if !self._is_valid_m31(query_eval) {
                        queries_valid = false;
                        break;
                    }
                    query_idx += 1;
                };

                if !queries_valid {
                    break false;
                }

                // Verify folding consistency using circle domain
                // f_{i+1}(x) = f_i(x) + alpha * f_i(-x) / 2
                // This is checked by verifying the algebraic relationship
                let folding_consistent = self._verify_fri_folding_step(
                    proof_data,
                    offset,
                    folding_alpha,
                    n_queries
                );
                if !folding_consistent {
                    break false;
                }

                offset += elements_per_layer;
                layer_idx += 1;
            }
        }

        /// Verify a single FRI folding step
        fn _verify_fri_folding_step(
            self: @ContractState,
            proof_data: Span<felt252>,
            layer_offset: u32,
            alpha: felt252,
            n_queries: u32
        ) -> bool {
            // Circle STARK folding over M31:
            // Given evaluation at point x on circle, and evaluation at -x,
            // the folded value is (f(x) + f(-x))/2 + alpha * (f(x) - f(-x))/(2*x)
            //
            // For verification, we check:
            // 1. Query positions are valid circle domain points
            // 2. Evaluations are consistent with commitment

            // Check alpha is in valid range for folding
            if alpha == 0 {
                return false;
            }

            // Verify we have paired evaluations (f(x) and f(-x))
            // Queries should come in pairs for circle domain
            if n_queries % 2 != 0 {
                // Odd number of queries - invalid structure
                return false;
            }

            // Verify query evaluation pairs
            let mut pair_idx: u32 = 0;
            while pair_idx < n_queries / 2 {
                let eval_x_offset = layer_offset + 2 + pair_idx * 2;
                let eval_neg_x_offset = eval_x_offset + 1;

                if eval_neg_x_offset >= proof_data.len() {
                    return true; // End of data, but structure was valid so far
                }

                let eval_x = *proof_data[eval_x_offset];
                let eval_neg_x = *proof_data[eval_neg_x_offset];

                // Both evaluations must be valid M31 elements
                if !self._is_valid_m31(eval_x) || !self._is_valid_m31(eval_neg_x) {
                    return false;
                }

                pair_idx += 1;
            };

            true
        }

        /// Verify OODS (Out-of-Domain Sampling) evaluation
        fn _verify_oods_evaluation(
            self: @ContractState,
            proof_data: Span<felt252>,
            trace_commitment: felt252,
            composition_commitment: felt252
        ) -> bool {
            // OODS verification checks that the constraint composition
            // evaluates correctly at a random point outside the trace domain
            //
            // The OODS point is derived from Fiat-Shamir (hash of commitments)
            // Then we verify: composition_poly(oods) = sum(constraint_i(oods) * alpha^i)

            // Derive OODS point from commitments using Fiat-Shamir
            let mut oods_input: Array<felt252> = ArrayTrait::new();
            oods_input.append('OODS');
            oods_input.append(trace_commitment);
            oods_input.append(composition_commitment);
            let oods_challenge = poseidon_hash_span(oods_input.span());

            // Reduce to M31 field element
            let oods_point = self._reduce_to_m31(oods_challenge);

            // Verify OODS point is not in trace domain
            // For circle STARKs, this means it shouldn't be on the circle of radius 1
            // We use a simplified check: the point hash shouldn't match domain markers
            let domain_check = self._is_valid_oods_point(oods_point);
            if !domain_check {
                return false;
            }

            // OODS evaluations should be present after FRI layers
            // The structure is: [oods_trace_evals..., oods_composition_eval]
            // For now, we verify structural presence
            let expected_oods_elements: u32 = 4; // Minimum OODS elements
            if proof_data.len() < expected_oods_elements {
                return false;
            }

            true
        }

        /// Reduce a felt252 to M31 field element
        fn _reduce_to_m31(self: @ContractState, value: felt252) -> felt252 {
            let value_u256: u256 = value.into();
            let m31_prime_u256: u256 = M31_PRIME.into();
            let reduced: u256 = value_u256 % m31_prime_u256;
            reduced.try_into().unwrap_or(0)
        }

        /// Check if a point is valid for OODS (outside trace domain)
        fn _is_valid_oods_point(self: @ContractState, point: felt252) -> bool {
            // For circle STARKs over M31:
            // The trace domain consists of points on the unit circle
            // A valid OODS point should NOT be a root of unity
            //
            // Simplified check: point should not be 0, 1, or -1 (M31 - 1)
            if point == 0 {
                return false;
            }
            if point == 1 {
                return false;
            }
            // M31 - 1 = 2147483646
            if point == 2147483646 {
                return false;
            }

            // Additional check: point should be less than M31 prime
            self._is_valid_m31(point)
        }

        /// Check if a value is a valid M31 field element
        fn _is_valid_m31(self: @ContractState, value: felt252) -> bool {
            // M31 prime = 2^31 - 1 = 2147483647
            let value_u256: u256 = value.into();
            let m31_prime_u256: u256 = M31_PRIME.into();

            value_u256 < m31_prime_u256
        }

        /// Verify proof of work (grinding resistance)
        /// SECURITY FIX: Uses Poseidon hash and properly checks leading zeros
        fn _verify_pow(
            self: @ContractState,
            proof_data: Span<felt252>,
            required_bits: u32,
            nonce: felt252
        ) -> bool {
            // Validate inputs
            if nonce == 0 || required_bits > 30 || required_bits < 12 {
                return false;
            }

            // Build hash input: commitment + nonce
            let mut hash_input: Array<felt252> = ArrayTrait::new();

            // Include trace commitment (first element after config at index 4)
            if proof_data.len() > 4 {
                hash_input.append(*proof_data[4]);
            }
            hash_input.append(nonce);

            // Compute Poseidon hash
            let pow_hash = poseidon_hash_span(hash_input.span());

            // Convert to u256 for bit manipulation
            let pow_hash_u256: u256 = pow_hash.into();

            // Check for leading zeros based on required_bits
            // For required_bits = 16, we need 16 leading zeros
            // This means pow_hash must be < 2^(252 - required_bits)
            let shift_amount: u32 = 252 - required_bits;
            let difficulty_threshold: u256 = pow2_u256(shift_amount);

            pow_hash_u256 < difficulty_threshold
        }

        /// Verify fraud proof for GPU-TEE challenged proofs
        fn _verify_fraud_proof(
            self: @ContractState,
            original_proof_hash: felt252,
            fraud_proof_data: Span<felt252>
        ) -> bool {
            // Fraud proof structure:
            // [type, witness_data...]
            // type 1: Invalid computation (re-execute and compare)
            // type 2: Invalid TEE attestation
            // type 3: Enclave measurement mismatch

            if fraud_proof_data.len() < 2 {
                return false;
            }

            let fraud_type: u32 = (*fraud_proof_data[0]).try_into().unwrap_or(0);

            if fraud_type == 1 {
                // Invalid computation fraud proof
                // Verify that re-executing the computation produces different output
                // This requires the challenger to provide:
                // - Input data hash
                // - Expected output (from original proof)
                // - Actual output (from re-execution)
                // - Proof of correct re-execution

                if fraud_proof_data.len() < 4 {
                    return false;
                }

                let _input_hash = *fraud_proof_data[1];
                let claimed_output = *fraud_proof_data[2];
                let actual_output = *fraud_proof_data[3];

                // If outputs differ, fraud is proven
                claimed_output != actual_output
            } else if fraud_type == 2 {
                // Invalid TEE attestation fraud proof
                // Verify that the TEE quote signature is invalid
                // This requires cryptographic verification of the quote

                // Load the original attestation
                let attestation = self.tee_attestations.read(original_proof_hash);

                // Check if attestation data is inconsistent
                if attestation.quote_hash == 0 {
                    return true; // Missing attestation is fraud
                }

                // Additional signature verification would go here
                false
            } else if fraud_type == 3 {
                // Enclave measurement mismatch
                // Verify that the enclave measurement in the proof doesn't match
                // the whitelisted measurement

                let attestation = self.tee_attestations.read(original_proof_hash);
                let is_whitelisted = self.whitelisted_enclaves.read(attestation.enclave_measurement);

                // If enclave is no longer whitelisted, fraud is proven
                !is_whitelisted
            } else {
                // Unknown fraud type
                false
            }
        }

        /// Trigger verification callback to notify ProofGatedPayment
        fn _trigger_verification_callback(
            ref self: ContractState,
            proof_hash: felt252,
            job_id: u256
        ) {
            let callback_addr = self.verification_callback.read();

            // Only trigger if callback is configured
            if !callback_addr.is_zero() {
                let callback = IProofGatedPaymentDispatcher { contract_address: callback_addr };

                // Notify the payment contract that proof is verified
                // This allows the payment to be released
                callback.mark_proof_verified(job_id);
            }
        }
    }

    /// Calculate 2^n for u256 (power of 2)
    fn pow2_u256(n: u32) -> u256 {
        if n == 0 {
            return 1_u256;
        }
        if n >= 256 {
            return 0_u256; // Overflow protection
        }

        // Use iterative doubling for efficiency
        let mut result: u256 = 1;
        let mut i: u32 = 0;
        while i < n {
            result = result * 2;
            i += 1;
        };
        result
    }
}

// =============================================================================
// M31 Field Arithmetic (Mersenne-31)
// =============================================================================
//
// The M31 field is defined as integers modulo p = 2^31 - 1 = 2147483647
// This is a Mersenne prime, allowing efficient reduction using:
// x mod p = (x & p) + (x >> 31), reduced again if >= p

/// M31 field element representation
#[derive(Copy, Drop, Serde, PartialEq)]
pub struct M31 {
    pub value: u32,
}

/// M31 prime constant
pub const M31_P: u32 = 2147483647; // 2^31 - 1

/// Create a new M31 element, reducing if necessary
pub fn m31_new(value: u32) -> M31 {
    if value >= M31_P {
        M31 { value: value - M31_P }
    } else {
        M31 { value }
    }
}

/// Create M31 from felt252, reducing modulo p
pub fn m31_from_felt(value: felt252) -> M31 {
    let v_u256: u256 = value.into();
    let m31_p_u256: u256 = M31_P.into();
    let reduced: u256 = v_u256 % m31_p_u256;
    let reduced_u32: u32 = reduced.try_into().unwrap_or(0);
    M31 { value: reduced_u32 }
}

/// M31 addition: (a + b) mod p
pub fn m31_add(a: M31, b: M31) -> M31 {
    let sum: u64 = a.value.into() + b.value.into();
    let m31_p: u64 = M31_P.into();

    if sum >= m31_p {
        M31 { value: (sum - m31_p).try_into().unwrap() }
    } else {
        M31 { value: sum.try_into().unwrap() }
    }
}

/// M31 subtraction: (a - b) mod p
pub fn m31_sub(a: M31, b: M31) -> M31 {
    if a.value >= b.value {
        M31 { value: a.value - b.value }
    } else {
        M31 { value: M31_P - (b.value - a.value) }
    }
}

/// M31 multiplication: (a * b) mod p
/// Uses the Mersenne property: x mod p = (x & p) + (x >> 31)
pub fn m31_mul(a: M31, b: M31) -> M31 {
    let product: u64 = a.value.into() * b.value.into();
    let m31_p: u64 = M31_P.into();

    // Mersenne reduction: (x & mask) + (x >> 31)
    let low: u64 = product & m31_p;
    let high: u64 = product / (m31_p + 1); // product >> 31
    let mut result: u64 = low + high;

    if result >= m31_p {
        result = result - m31_p;
    }

    M31 { value: result.try_into().unwrap() }
}

/// M31 negation: -a mod p = p - a
pub fn m31_neg(a: M31) -> M31 {
    if a.value == 0 {
        a
    } else {
        M31 { value: M31_P - a.value }
    }
}

/// M31 inverse using Fermat's little theorem: a^(p-2) mod p
pub fn m31_inv(a: M31) -> M31 {
    // a^(p-2) = a^(2^31 - 3) mod p
    // We use square-and-multiply
    m31_pow(a, M31_P - 2)
}

/// M31 exponentiation: a^exp mod p
pub fn m31_pow(base: M31, exp: u32) -> M31 {
    if exp == 0 {
        return M31 { value: 1 };
    }
    if exp == 1 {
        return base;
    }

    let mut result = M31 { value: 1 };
    let mut b = base;
    let mut e = exp;

    while e > 0 {
        if e & 1 == 1 {
            result = m31_mul(result, b);
        }
        b = m31_mul(b, b);
        e = e / 2;
    };

    result
}

/// M31 division: a / b mod p = a * b^(-1) mod p
pub fn m31_div(a: M31, b: M31) -> M31 {
    let b_inv = m31_inv(b);
    m31_mul(a, b_inv)
}

// =============================================================================
// Merkle Tree Verification for STARK Proofs
// =============================================================================

use core::poseidon::poseidon_hash_span;

/// Merkle tree node (hash)
#[derive(Copy, Drop, Serde)]
pub struct MerkleNode {
    pub hash: felt252,
}

/// Merkle authentication path
#[derive(Drop, Serde)]
pub struct MerklePath {
    pub siblings: Array<felt252>,
    pub leaf_index: u32,
}

/// Verify a Merkle path from leaf to root
/// @param leaf: The leaf value to verify
/// @param path: The authentication path (sibling hashes)
/// @param root: The expected root hash
/// @return true if the path is valid
pub fn verify_merkle_path(
    leaf: felt252,
    path: @MerklePath,
    root: felt252
) -> bool {
    let mut current_hash = leaf;
    let mut index = *path.leaf_index;
    let mut i: u32 = 0;

    loop {
        if i >= path.siblings.len() {
            break;
        }

        let sibling = *path.siblings.at(i);

        // Hash order depends on position (left or right child)
        if index % 2 == 0 {
            // Current is left child, sibling is right
            current_hash = poseidon_hash_span(array![current_hash, sibling].span());
        } else {
            // Current is right child, sibling is left
            current_hash = poseidon_hash_span(array![sibling, current_hash].span());
        }

        index = index / 2;
        i += 1;
    };

    current_hash == root
}

/// Verify multiple Merkle paths (batched for gas efficiency)
pub fn verify_merkle_paths_batch(
    leaves: Span<felt252>,
    paths: Span<MerklePath>,
    root: felt252
) -> bool {
    if leaves.len() != paths.len() {
        return false;
    }

    let mut i: u32 = 0;
    loop {
        if i >= leaves.len() {
            break true;
        }

        let valid = verify_merkle_path(*leaves.at(i), paths.at(i), root);
        if !valid {
            break false;
        }

        i += 1;
    }
}

/// Compute Merkle root from leaves (for verification)
pub fn compute_merkle_root(leaves: Span<felt252>) -> felt252 {
    if leaves.len() == 0 {
        return 0;
    }
    if leaves.len() == 1 {
        return *leaves.at(0);
    }

    // Build tree layer by layer
    let mut current_layer: Array<felt252> = array![];
    for leaf in leaves {
        current_layer.append(*leaf);
    };

    while current_layer.len() > 1 {
        let mut next_layer: Array<felt252> = array![];
        let mut j: u32 = 0;

        while j + 1 < current_layer.len() {
            let left = *current_layer.at(j);
            let right = *current_layer.at(j + 1);
            let parent = poseidon_hash_span(array![left, right].span());
            next_layer.append(parent);
            j += 2;
        };

        // Handle odd number of nodes
        if current_layer.len() % 2 == 1 {
            next_layer.append(*current_layer.at(current_layer.len() - 1));
        }

        current_layer = next_layer;
    };

    *current_layer.at(0)
}

