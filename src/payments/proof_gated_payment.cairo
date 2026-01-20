// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Proof-Gated Payment System
// Connects ProofVerifier → PaymentRouter
// Payments only flow after proof verification (STWO or TEE)

use starknet::{ContractAddress, ClassHash};

/// Payment verification source
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum VerificationSource {
    STWOProof,      // Full STWO Circle STARK proof verified
    TEEOptimistic,  // TEE result finalized after challenge period
    TEEChallenged,  // TEE result + ZK proof after challenge
}

/// Job payment status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum PaymentStatus {
    Pending,         // Awaiting proof verification
    ProofVerified,   // Proof verified, ready for payment
    PaymentReleased, // Payment sent to worker
    Disputed,        // Under dispute
    Cancelled,       // Job cancelled, no payment
}

/// Job payment record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct JobPaymentRecord {
    pub job_id: u256,
    pub worker: ContractAddress,
    pub client: ContractAddress,
    pub sage_amount: u256,
    pub usd_value: u256,
    pub verification_source: VerificationSource,
    pub status: PaymentStatus,
    pub proof_verified_at: u64,
    pub payment_released_at: u64,
    pub privacy_enabled: bool,
}

/// Checkpoint for metered billing (hourly proofs)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ComputeCheckpoint {
    pub checkpoint_id: u256,
    pub job_id: u256,
    pub hour_number: u32,           // Which hour (1, 2, 3, ...)
    pub proof_hash: felt252,        // Proof for this hour's computation
    pub verified: bool,             // Whether proof is verified
    pub sage_amount: u256,          // Payment for this checkpoint
    pub timestamp: u64,
}

#[starknet::interface]
pub trait IProofGatedPayment<TContractState> {
    /// Register a job for proof-gated payment
    fn register_job_payment(
        ref self: TContractState,
        job_id: u256,
        worker: ContractAddress,
        client: ContractAddress,
        sage_amount: u256,
        usd_value: u256,
        privacy_enabled: bool
    );

    /// Called when STWO proof is verified - triggers payment release
    fn on_proof_verified(
        ref self: TContractState,
        job_id: u256,
        proof_hash: felt252
    );

    /// Called when TEE result is finalized - triggers payment release
    fn on_tee_finalized(
        ref self: TContractState,
        job_id: u256
    );

    /// Called when TEE challenge is resolved with ZK proof
    fn on_challenge_resolved(
        ref self: TContractState,
        job_id: u256,
        challenger_wins: bool
    );

    /// Release payment for verified job (internal, called after verification)
    fn release_payment(
        ref self: TContractState,
        job_id: u256
    );

    /// Submit hourly checkpoint for metered billing
    fn submit_checkpoint(
        ref self: TContractState,
        job_id: u256,
        hour_number: u32,
        proof_data: Array<felt252>,
        proof_hash: felt252
    );

    /// Verify and pay for a checkpoint
    fn verify_and_pay_checkpoint(
        ref self: TContractState,
        checkpoint_id: u256
    );

    /// Get job payment status
    fn get_job_payment(self: @TContractState, job_id: u256) -> JobPaymentRecord;

    /// Get checkpoint details
    fn get_checkpoint(self: @TContractState, checkpoint_id: u256) -> ComputeCheckpoint;

    /// Get total checkpoints for a job
    fn get_job_checkpoints(self: @TContractState, job_id: u256) -> u32;

    /// Check if job is ready for payment
    fn is_payment_ready(self: @TContractState, job_id: u256) -> bool;

    // === Configuration Functions (Production-grade initialization) ===

    /// Configure all circular dependencies at once. Can only be called before finalize().
    /// This is the production-grade pattern to avoid deploying with placeholder addresses.
    fn configure(
        ref self: TContractState,
        payment_router: ContractAddress,
        optimistic_tee: ContractAddress,
        job_manager: ContractAddress,
        stwo_verifier: ContractAddress
    );

    /// Finalize configuration - locks all dependency addresses permanently.
    /// After calling this, configure() and individual setters will revert.
    fn finalize(ref self: TContractState);

    /// Check if contract is configured
    fn is_configured(self: @TContractState) -> bool;

    /// Check if contract is finalized (configuration locked)
    fn is_finalized(self: @TContractState) -> bool;

    // === Legacy Admin Setters (work only before finalize) ===

    /// Admin: Set payment router address (deprecated, use configure())
    fn set_payment_router(ref self: TContractState, router: ContractAddress);

    /// Admin: Set proof verifier address
    fn set_proof_verifier(ref self: TContractState, verifier: ContractAddress);

    /// Admin: Set optimistic TEE address (deprecated, use configure())
    fn set_optimistic_tee(ref self: TContractState, tee: ContractAddress);

    /// Admin: Set hourly rate in SAGE
    fn set_hourly_rate(ref self: TContractState, rate: u256);

    /// Admin: Set JobManager address (deprecated, use configure())
    fn set_job_manager(ref self: TContractState, job_manager: ContractAddress);

    /// Admin: Set STWO verifier address (deprecated, use configure())
    fn set_stwo_verifier(ref self: TContractState, stwo_verifier: ContractAddress);

    /// Called by STWO verifier when proof is verified - marks job ready for payment
    /// This is the callback entry point from StwoVerifier.submit_and_verify()
    fn mark_proof_verified(ref self: TContractState, job_id: u256);

    // === Upgrade Functions ===
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[starknet::contract]
mod ProofGatedPayment {
    use super::{
        IProofGatedPayment, VerificationSource, PaymentStatus,
        JobPaymentRecord, ComputeCheckpoint
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;

    // Import interfaces for cross-contract calls
    use sage_contracts::interfaces::proof_verifier::{
        IProofVerifierDispatcher, IProofVerifierDispatcherTrait,
        ProofJobId,
    };
    use sage_contracts::payments::payment_router::{
        IPaymentRouterDispatcher, IPaymentRouterDispatcherTrait
    };

    const BPS_DENOMINATOR: u256 = 10000;
    // Default hourly rate: 10 SAGE per hour (10 * 10^18)
    const DEFAULT_HOURLY_RATE: u256 = 10000000000000000000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        proof_verifier: ContractAddress,

        // Configuration state - production-grade initialization pattern
        // These are set via configure() and locked via finalize()
        payment_router: ContractAddress,
        optimistic_tee: ContractAddress,
        job_manager: ContractAddress,
        stwo_verifier: ContractAddress,
        configured: bool,   // True once configure() is called with all deps
        finalized: bool,    // True once finalize() is called - locks configuration forever

        // Job payment tracking
        job_payments: Map<u256, JobPaymentRecord>,
        job_registered: Map<u256, bool>,

        // Metered billing checkpoints
        checkpoints: Map<u256, ComputeCheckpoint>,
        checkpoint_counter: u256,
        job_checkpoint_count: Map<u256, u32>,
        job_checkpoints: Map<(u256, u32), u256>, // (job_id, index) -> checkpoint_id

        // Hourly rate for metered billing
        hourly_rate_sage: u256,

        // Stats
        total_payments_released: u256,
        total_checkpoints_verified: u64,
        total_sage_distributed: u256,

        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        JobPaymentRegistered: JobPaymentRegistered,
        ProofVerifiedPaymentReady: ProofVerifiedPaymentReady,
        TEEFinalizedPaymentReady: TEEFinalizedPaymentReady,
        PaymentReleased: PaymentReleased,
        CheckpointSubmitted: CheckpointSubmitted,
        CheckpointVerified: CheckpointVerified,
        CheckpointPaid: CheckpointPaid,
        DisputeResolved: DisputeResolved,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct JobPaymentRegistered {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        sage_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerifiedPaymentReady {
        #[key]
        job_id: u256,
        proof_hash: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct TEEFinalizedPaymentReady {
        #[key]
        job_id: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentReleased {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        sage_amount: u256,
        verification_source: felt252,
        privacy_enabled: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CheckpointSubmitted {
        #[key]
        checkpoint_id: u256,
        #[key]
        job_id: u256,
        hour_number: u32,
        proof_hash: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CheckpointVerified {
        #[key]
        checkpoint_id: u256,
        verified: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CheckpointPaid {
        #[key]
        checkpoint_id: u256,
        #[key]
        job_id: u256,
        sage_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct DisputeResolved {
        #[key]
        job_id: u256,
        challenger_wins: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        #[key]
        new_class_hash: ClassHash,
        scheduled_at: u64,
        execute_after: u64,
        scheduled_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        #[key]
        new_class_hash: ClassHash,
        executed_at: u64,
        executed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        #[key]
        cancelled_class_hash: ClassHash,
        cancelled_at: u64,
        cancelled_by: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        proof_verifier: ContractAddress
    ) {
        // Production-grade: Only immutable dependencies in constructor
        // Circular dependencies set via configure() after deployment
        assert!(!owner.is_zero(), "Invalid owner address");
        assert!(!proof_verifier.is_zero(), "Invalid proof verifier address");

        self.owner.write(owner);
        self.proof_verifier.write(proof_verifier);
        self.hourly_rate_sage.write(DEFAULT_HOURLY_RATE);
        self.checkpoint_counter.write(0);
        self.upgrade_delay.write(172800); // 2 days
        self.configured.write(false);
        self.finalized.write(false);
    }

    #[abi(embed_v0)]
    impl ProofGatedPaymentImpl of IProofGatedPayment<ContractState> {
        /// Register a job for proof-gated payment
        fn register_job_payment(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            client: ContractAddress,
            sage_amount: u256,
            usd_value: u256,
            privacy_enabled: bool
        ) {
            // Only owner or authorized contracts can register
            self._only_authorized();

            assert(!self.job_registered.read(job_id), 'Job already registered');
            assert(!worker.is_zero(), 'Invalid worker');
            assert(sage_amount > 0, 'Invalid amount');

            let record = JobPaymentRecord {
                job_id,
                worker,
                client,
                sage_amount,
                usd_value,
                verification_source: VerificationSource::STWOProof, // Default, updated on verification
                status: PaymentStatus::Pending,
                proof_verified_at: 0,
                payment_released_at: 0,
                privacy_enabled,
            };

            self.job_payments.write(job_id, record);
            self.job_registered.write(job_id, true);

            self.emit(JobPaymentRegistered {
                job_id,
                worker,
                sage_amount,
                timestamp: get_block_timestamp(),
            });
        }

        /// Called when STWO proof is verified - triggers payment release
        fn on_proof_verified(
            ref self: ContractState,
            job_id: u256,
            proof_hash: felt252
        ) {
            // Only ProofVerifier can call this
            let caller = get_caller_address();
            assert(caller == self.proof_verifier.read(), 'Only ProofVerifier');

            assert(self.job_registered.read(job_id), 'Job not registered');

            let mut record = self.job_payments.read(job_id);
            assert(record.status == PaymentStatus::Pending, 'Invalid status');

            // Update status to verified
            record.status = PaymentStatus::ProofVerified;
            record.verification_source = VerificationSource::STWOProof;
            record.proof_verified_at = get_block_timestamp();
            self.job_payments.write(job_id, record);

            self.emit(ProofVerifiedPaymentReady {
                job_id,
                proof_hash,
                timestamp: get_block_timestamp(),
            });

            // Auto-release payment after verification
            self._execute_payment(job_id);
        }

        /// Called when TEE result is finalized - triggers payment release
        fn on_tee_finalized(
            ref self: ContractState,
            job_id: u256
        ) {
            // Only OptimisticTEE can call this
            let caller = get_caller_address();
            assert(caller == self.optimistic_tee.read(), 'Only OptimisticTEE');

            assert(self.job_registered.read(job_id), 'Job not registered');

            let mut record = self.job_payments.read(job_id);
            assert(record.status == PaymentStatus::Pending, 'Invalid status');

            // Update status to verified via TEE
            record.status = PaymentStatus::ProofVerified;
            record.verification_source = VerificationSource::TEEOptimistic;
            record.proof_verified_at = get_block_timestamp();
            self.job_payments.write(job_id, record);

            self.emit(TEEFinalizedPaymentReady {
                job_id,
                timestamp: get_block_timestamp(),
            });

            // Auto-release payment after finalization
            self._execute_payment(job_id);
        }

        /// Called when TEE challenge is resolved with ZK proof
        fn on_challenge_resolved(
            ref self: ContractState,
            job_id: u256,
            challenger_wins: bool
        ) {
            // Only OptimisticTEE can call this
            let caller = get_caller_address();
            assert(caller == self.optimistic_tee.read(), 'Only OptimisticTEE');

            assert(self.job_registered.read(job_id), 'Job not registered');

            let mut record = self.job_payments.read(job_id);

            if challenger_wins {
                // Worker fraud detected - no payment, mark cancelled
                record.status = PaymentStatus::Cancelled;
                self.job_payments.write(job_id, record);

                // In production: slash worker stake, reward challenger
            } else {
                // Worker was honest - release payment
                record.status = PaymentStatus::ProofVerified;
                record.verification_source = VerificationSource::TEEChallenged;
                record.proof_verified_at = get_block_timestamp();
                self.job_payments.write(job_id, record);

                self._execute_payment(job_id);
            }

            self.emit(DisputeResolved {
                job_id,
                challenger_wins,
                timestamp: get_block_timestamp(),
            });
        }

        /// Release payment for verified job (can be called manually if auto-release fails)
        fn release_payment(
            ref self: ContractState,
            job_id: u256
        ) {
            assert(self.job_registered.read(job_id), 'Job not registered');

            let record = self.job_payments.read(job_id);
            assert(record.status == PaymentStatus::ProofVerified, 'Not verified');

            self._execute_payment(job_id);
        }

        /// Submit hourly checkpoint for metered billing
        fn submit_checkpoint(
            ref self: ContractState,
            job_id: u256,
            hour_number: u32,
            proof_data: Array<felt252>,
            proof_hash: felt252
        ) {
            assert(self.job_registered.read(job_id), 'Job not registered');
            assert(proof_data.len() >= 32, 'Invalid proof data');

            let checkpoint_id = self.checkpoint_counter.read() + 1;
            self.checkpoint_counter.write(checkpoint_id);

            let hourly_rate = self.hourly_rate_sage.read();

            let checkpoint = ComputeCheckpoint {
                checkpoint_id,
                job_id,
                hour_number,
                proof_hash,
                verified: false,
                sage_amount: hourly_rate,
                timestamp: get_block_timestamp(),
            };

            self.checkpoints.write(checkpoint_id, checkpoint);

            // Track checkpoint for this job
            let current_count = self.job_checkpoint_count.read(job_id);
            self.job_checkpoints.write((job_id, current_count), checkpoint_id);
            self.job_checkpoint_count.write(job_id, current_count + 1);

            // Submit proof to ProofVerifier
            let verifier = IProofVerifierDispatcher {
                contract_address: self.proof_verifier.read()
            };

            let proof_job_id = ProofJobId { value: checkpoint_id };
            let verified = verifier.verify_proof(proof_job_id, proof_data);

            if verified {
                // Mark checkpoint as verified
                let mut cp = self.checkpoints.read(checkpoint_id);
                cp.verified = true;
                self.checkpoints.write(checkpoint_id, cp);

                let verified_count = self.total_checkpoints_verified.read();
                self.total_checkpoints_verified.write(verified_count + 1);

                self.emit(CheckpointVerified {
                    checkpoint_id,
                    verified: true,
                    timestamp: get_block_timestamp(),
                });

                // Auto-pay for verified checkpoint
                self._pay_checkpoint(checkpoint_id);
            }

            self.emit(CheckpointSubmitted {
                checkpoint_id,
                job_id,
                hour_number,
                proof_hash,
                timestamp: get_block_timestamp(),
            });
        }

        /// Verify and pay for a checkpoint (manual trigger)
        fn verify_and_pay_checkpoint(
            ref self: ContractState,
            checkpoint_id: u256
        ) {
            let checkpoint = self.checkpoints.read(checkpoint_id);
            assert(checkpoint.verified, 'Checkpoint not verified');

            self._pay_checkpoint(checkpoint_id);
        }

        fn get_job_payment(self: @ContractState, job_id: u256) -> JobPaymentRecord {
            self.job_payments.read(job_id)
        }

        fn get_checkpoint(self: @ContractState, checkpoint_id: u256) -> ComputeCheckpoint {
            self.checkpoints.read(checkpoint_id)
        }

        fn get_job_checkpoints(self: @ContractState, job_id: u256) -> u32 {
            self.job_checkpoint_count.read(job_id)
        }

        fn is_payment_ready(self: @ContractState, job_id: u256) -> bool {
            if !self.job_registered.read(job_id) {
                return false;
            }
            let record = self.job_payments.read(job_id);
            record.status == PaymentStatus::ProofVerified
        }

        // === Production-grade Configuration Functions ===

        fn configure(
            ref self: ContractState,
            payment_router: ContractAddress,
            optimistic_tee: ContractAddress,
            job_manager: ContractAddress,
            stwo_verifier: ContractAddress
        ) {
            self._only_owner();
            assert!(!self.finalized.read(), "Contract is finalized");

            // Validate all addresses
            assert!(!payment_router.is_zero(), "Invalid payment router");
            assert!(!optimistic_tee.is_zero(), "Invalid optimistic TEE");
            assert!(!job_manager.is_zero(), "Invalid job manager");
            assert!(!stwo_verifier.is_zero(), "Invalid STWO verifier");

            // Set all circular dependencies at once
            self.payment_router.write(payment_router);
            self.optimistic_tee.write(optimistic_tee);
            self.job_manager.write(job_manager);
            self.stwo_verifier.write(stwo_verifier);
            self.configured.write(true);
        }

        fn finalize(ref self: ContractState) {
            self._only_owner();
            assert!(self.configured.read(), "Contract not configured");
            assert!(!self.finalized.read(), "Already finalized");

            // Permanently lock configuration
            self.finalized.write(true);
        }

        fn is_configured(self: @ContractState) -> bool {
            self.configured.read()
        }

        fn is_finalized(self: @ContractState) -> bool {
            self.finalized.read()
        }

        // === Legacy Setters (deprecated, work only before finalize) ===

        fn set_payment_router(ref self: ContractState, router: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Contract is finalized");
            assert!(!router.is_zero(), "Invalid payment router address");
            self.payment_router.write(router);
        }

        fn set_proof_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Contract is finalized");
            assert!(!verifier.is_zero(), "Invalid proof verifier address");
            self.proof_verifier.write(verifier);
        }

        fn set_optimistic_tee(ref self: ContractState, tee: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Contract is finalized");
            assert!(!tee.is_zero(), "Invalid optimistic TEE address");
            self.optimistic_tee.write(tee);
        }

        fn set_hourly_rate(ref self: ContractState, rate: u256) {
            self._only_owner();
            assert!(rate > 0, "Hourly rate must be positive");
            self.hourly_rate_sage.write(rate);
        }

        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Contract is finalized");
            assert!(!job_manager.is_zero(), "Invalid job manager address");
            self.job_manager.write(job_manager);
        }

        fn set_stwo_verifier(ref self: ContractState, stwo_verifier: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Contract is finalized");
            assert!(!stwo_verifier.is_zero(), "Invalid STWO verifier address");
            self.stwo_verifier.write(stwo_verifier);
        }

        fn mark_proof_verified(ref self: ContractState, job_id: u256) {
            // Only STWO verifier can call this callback
            let caller = get_caller_address();
            let stwo_verifier = self.stwo_verifier.read();
            assert!(!stwo_verifier.is_zero(), "STWO verifier not configured");
            assert!(caller == stwo_verifier, "Only STWO verifier");

            assert!(self.job_registered.read(job_id), "Job not registered");

            let mut record = self.job_payments.read(job_id);
            assert!(record.status == PaymentStatus::Pending, "Invalid status");

            // Update status to verified
            record.status = PaymentStatus::ProofVerified;
            record.verification_source = VerificationSource::STWOProof;
            record.proof_verified_at = get_block_timestamp();
            self.job_payments.write(job_id, record);

            self.emit(ProofVerifiedPaymentReady {
                job_id,
                proof_hash: 0,  // Proof hash not passed in this callback
                timestamp: get_block_timestamp(),
            });

            // Auto-release payment after verification
            self._execute_payment(job_id);
        }

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();

            let pending = self.pending_upgrade.read();
            let zero_hash: ClassHash = 0.try_into().unwrap();
            assert(pending == zero_hash, 'Upgrade already pending');

            let now = get_block_timestamp();
            let delay = self.upgrade_delay.read();

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(now);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: now,
                execute_after: now + delay,
                scheduled_by: get_caller_address(),
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            self._only_owner();

            let pending = self.pending_upgrade.read();
            let zero_hash: ClassHash = 0.try_into().unwrap();
            assert(pending != zero_hash, 'No pending upgrade');

            let now = get_block_timestamp();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            assert(now >= scheduled_at + delay, 'Timelock not expired');

            self.pending_upgrade.write(zero_hash);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: now,
                executed_by: get_caller_address(),
            });

            replace_class_syscall(pending).unwrap_syscall();
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();

            let pending = self.pending_upgrade.read();
            let zero_hash: ClassHash = 0.try_into().unwrap();
            assert(pending != zero_hash, 'No pending upgrade');

            self.pending_upgrade.write(zero_hash);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_at: get_block_timestamp(),
                cancelled_by: get_caller_address(),
            });
        }

        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64) {
            let pending = self.pending_upgrade.read();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let execute_after = if scheduled_at > 0 { scheduled_at + delay } else { 0 };
            (pending, scheduled_at, execute_after)
        }

        fn set_upgrade_delay(ref self: ContractState, delay: u64) {
            self._only_owner();
            self.upgrade_delay.write(delay);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }

        fn _only_authorized(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            let proof_verifier = self.proof_verifier.read();
            let optimistic_tee = self.optimistic_tee.read();
            let job_manager = self.job_manager.read();

            assert(
                caller == owner
                    || caller == proof_verifier
                    || caller == optimistic_tee
                    || caller == job_manager,
                'Not authorized'
            );
        }

        /// Execute payment through PaymentRouter
        fn _execute_payment(ref self: ContractState, job_id: u256) {
            let mut record = self.job_payments.read(job_id);
            assert(record.status == PaymentStatus::ProofVerified, 'Not verified');

            // Register job in PaymentRouter for proper fee distribution
            let router = IPaymentRouterDispatcher {
                contract_address: self.payment_router.read()
            };

            // Register the job with worker and privacy setting
            router.register_job(job_id, record.worker, record.privacy_enabled);

            // Payment is handled by PaymentRouter's fee distribution
            // 80% to worker, 20% protocol fee (70% burn, 20% treasury, 10% stakers)

            // Update status
            record.status = PaymentStatus::PaymentReleased;
            record.payment_released_at = get_block_timestamp();
            self.job_payments.write(job_id, record);

            // Update stats
            let total = self.total_payments_released.read();
            self.total_payments_released.write(total + 1);

            let total_sage = self.total_sage_distributed.read();
            self.total_sage_distributed.write(total_sage + record.sage_amount);

            self.emit(PaymentReleased {
                job_id,
                worker: record.worker,
                sage_amount: record.sage_amount,
                verification_source: self._source_to_felt(record.verification_source),
                privacy_enabled: record.privacy_enabled,
                timestamp: get_block_timestamp(),
            });
        }

        /// Pay for a verified checkpoint
        fn _pay_checkpoint(ref self: ContractState, checkpoint_id: u256) {
            let checkpoint = self.checkpoints.read(checkpoint_id);
            let job_record = self.job_payments.read(checkpoint.job_id);

            // Register checkpoint payment in PaymentRouter
            let router = IPaymentRouterDispatcher {
                contract_address: self.payment_router.read()
            };

            // Use checkpoint_id as the "job_id" for this micro-payment
            router.register_job(checkpoint_id, job_record.worker, job_record.privacy_enabled);

            // Update stats
            let total_sage = self.total_sage_distributed.read();
            self.total_sage_distributed.write(total_sage + checkpoint.sage_amount);

            self.emit(CheckpointPaid {
                checkpoint_id,
                job_id: checkpoint.job_id,
                sage_amount: checkpoint.sage_amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn _source_to_felt(self: @ContractState, source: VerificationSource) -> felt252 {
            match source {
                VerificationSource::STWOProof => 'STWO_PROOF',
                VerificationSource::TEEOptimistic => 'TEE_OPTIMISTIC',
                VerificationSource::TEEChallenged => 'TEE_CHALLENGED',
            }
        }
    }
}
