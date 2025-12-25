// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Metered Billing - Hourly GPU Compute Tracking with Proof Attestation
// Each hour of compute generates a proof checkpoint for billing
// Supports both STWO proofs and TEE attestations

use starknet::ContractAddress;

/// GPU tier classification
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum GPUTier {
    H100,       // NVIDIA H100 - Premium tier
    A100,       // NVIDIA A100 - High tier
    RTX4090,    // Consumer high-end
    RTX3090,    // Consumer tier
    Other,      // Other GPUs
}

/// Checkpoint verification method
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum VerificationMethod {
    STWOProof,      // Full STWO Circle STARK proof
    TEEAttestation, // TEE quote (optimistic)
    Hybrid,         // TEE + periodic STWO proofs
}

/// Metered job configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct MeteredJob {
    pub job_id: u256,
    pub client: ContractAddress,
    pub worker: ContractAddress,
    pub gpu_tier: GPUTier,
    pub hourly_rate_sage: u256,       // SAGE per hour for this GPU tier
    pub max_hours: u32,                // Maximum hours budgeted
    pub verification_method: VerificationMethod,
    pub checkpoint_interval: u64,      // Seconds between checkpoints (default 3600)
    pub started_at: u64,
    pub ended_at: u64,
    pub is_active: bool,
    pub privacy_enabled: bool,
}

/// Hourly checkpoint record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct HourlyCheckpoint {
    pub checkpoint_id: u256,
    pub job_id: u256,
    pub hour_number: u32,
    pub gpu_utilization: u8,           // 0-100% average GPU utilization
    pub memory_used_gb: u32,           // Peak memory usage in GB
    pub compute_hash: felt252,         // Hash of compute trace for this hour
    pub proof_hash: felt252,           // Proof hash (STWO or TEE quote)
    pub verification_method: VerificationMethod,
    pub verified: bool,
    pub paid: bool,
    pub sage_amount: u256,
    pub submitted_at: u64,
    pub verified_at: u64,
}

/// Worker GPU registration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct WorkerGPU {
    pub worker: ContractAddress,
    pub gpu_tier: GPUTier,
    pub gpu_count: u8,
    pub total_memory_gb: u32,
    pub tee_enabled: bool,
    pub enclave_measurement: felt252,
    pub registered_at: u64,
    pub total_hours_worked: u256,
    pub total_sage_earned: u256,
}

#[starknet::interface]
pub trait IMeteredBilling<TContractState> {
    // === Job Lifecycle ===

    /// Start a metered GPU compute job
    fn start_metered_job(
        ref self: TContractState,
        job_id: u256,
        worker: ContractAddress,
        gpu_tier: GPUTier,
        max_hours: u32,
        verification_method: VerificationMethod,
        privacy_enabled: bool
    );

    /// End a metered job (stops billing)
    fn end_metered_job(ref self: TContractState, job_id: u256);

    /// Submit hourly checkpoint with proof
    fn submit_hourly_checkpoint(
        ref self: TContractState,
        job_id: u256,
        hour_number: u32,
        gpu_utilization: u8,
        memory_used_gb: u32,
        compute_hash: felt252,
        proof_data: Array<felt252>,
        proof_hash: felt252
    );

    /// Submit TEE attestation checkpoint (optimistic path)
    fn submit_tee_checkpoint(
        ref self: TContractState,
        job_id: u256,
        hour_number: u32,
        gpu_utilization: u8,
        memory_used_gb: u32,
        compute_hash: felt252,
        tee_quote: Array<felt252>,
        enclave_measurement: felt252
    );

    /// Verify and pay a checkpoint
    fn verify_checkpoint(ref self: TContractState, checkpoint_id: u256);

    /// Batch verify multiple checkpoints
    fn batch_verify_checkpoints(ref self: TContractState, checkpoint_ids: Array<u256>);

    // === Worker Management ===

    /// Register worker GPU capabilities
    fn register_worker_gpu(
        ref self: TContractState,
        gpu_tier: GPUTier,
        gpu_count: u8,
        total_memory_gb: u32,
        tee_enabled: bool,
        enclave_measurement: felt252
    );

    /// Update worker GPU info
    fn update_worker_gpu(
        ref self: TContractState,
        gpu_tier: GPUTier,
        gpu_count: u8,
        total_memory_gb: u32
    );

    // === View Functions ===

    /// Get job details
    fn get_metered_job(self: @TContractState, job_id: u256) -> MeteredJob;

    /// Get checkpoint details
    fn get_checkpoint(self: @TContractState, checkpoint_id: u256) -> HourlyCheckpoint;

    /// Get worker GPU info
    fn get_worker_gpu(self: @TContractState, worker: ContractAddress) -> WorkerGPU;

    /// Get hourly rate for GPU tier
    fn get_hourly_rate(self: @TContractState, gpu_tier: GPUTier) -> u256;

    /// Get total checkpoints for job
    fn get_job_checkpoint_count(self: @TContractState, job_id: u256) -> u32;

    /// Get verified hours for job
    fn get_verified_hours(self: @TContractState, job_id: u256) -> u32;

    /// Get total SAGE paid for job
    fn get_job_total_paid(self: @TContractState, job_id: u256) -> u256;

    /// Calculate current bill for active job
    fn calculate_current_bill(self: @TContractState, job_id: u256) -> u256;

    // === Admin Functions ===

    /// Set hourly rate for GPU tier
    fn set_hourly_rate(ref self: TContractState, gpu_tier: GPUTier, rate: u256);

    /// Set payment contracts
    fn set_proof_gated_payment(ref self: TContractState, payment: ContractAddress);
    fn set_proof_verifier(ref self: TContractState, verifier: ContractAddress);
    fn set_optimistic_tee(ref self: TContractState, tee: ContractAddress);
}

#[starknet::contract]
mod MeteredBilling {
    use super::{
        IMeteredBilling, GPUTier, VerificationMethod, MeteredJob,
        HourlyCheckpoint, WorkerGPU
    };
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;

    use sage_contracts::interfaces::proof_verifier::{
        IProofVerifierDispatcher, IProofVerifierDispatcherTrait,
        ProofJobId, ProofStatus
    };
    use sage_contracts::payments::proof_gated_payment::{
        IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait
    };

    // Default hourly rates in SAGE (18 decimals)
    // H100: $3/hour → 30 SAGE at $0.10
    const RATE_H100: u256 = 30000000000000000000;
    // A100: $2/hour → 20 SAGE
    const RATE_A100: u256 = 20000000000000000000;
    // RTX 4090: $1/hour → 10 SAGE
    const RATE_RTX4090: u256 = 10000000000000000000;
    // RTX 3090: $0.50/hour → 5 SAGE
    const RATE_RTX3090: u256 = 5000000000000000000;
    // Other: $0.25/hour → 2.5 SAGE
    const RATE_OTHER: u256 = 2500000000000000000;

    const SECONDS_PER_HOUR: u64 = 3600;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        proof_verifier: ContractAddress,
        proof_gated_payment: ContractAddress,
        optimistic_tee: ContractAddress,

        // GPU tier rates (can be updated by admin)
        hourly_rates: Map<u8, u256>,  // GPUTier as u8 -> rate

        // Job tracking
        metered_jobs: Map<u256, MeteredJob>,
        job_exists: Map<u256, bool>,

        // Checkpoint tracking
        checkpoints: Map<u256, HourlyCheckpoint>,
        checkpoint_counter: u256,
        job_checkpoint_count: Map<u256, u32>,
        job_checkpoints: Map<(u256, u32), u256>, // (job_id, index) -> checkpoint_id
        job_verified_hours: Map<u256, u32>,
        job_total_paid: Map<u256, u256>,

        // Worker tracking
        worker_gpus: Map<ContractAddress, WorkerGPU>,
        worker_registered: Map<ContractAddress, bool>,

        // SECURITY: Track which hours have been checkpointed (prevents duplicate billing)
        job_hour_checkpointed: Map<(u256, u32), bool>,  // (job_id, hour_number) -> checkpointed

        // Stats
        total_metered_jobs: u64,
        total_compute_hours: u256,
        total_sage_distributed: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        MeteredJobStarted: MeteredJobStarted,
        MeteredJobEnded: MeteredJobEnded,
        CheckpointSubmitted: CheckpointSubmitted,
        CheckpointVerified: CheckpointVerified,
        CheckpointPaid: CheckpointPaid,
        WorkerGPURegistered: WorkerGPURegistered,
        HourlyRateUpdated: HourlyRateUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct MeteredJobStarted {
        #[key]
        job_id: u256,
        #[key]
        client: ContractAddress,
        #[key]
        worker: ContractAddress,
        gpu_tier: u8,
        hourly_rate: u256,
        max_hours: u32,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MeteredJobEnded {
        #[key]
        job_id: u256,
        total_hours: u32,
        total_paid: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CheckpointSubmitted {
        #[key]
        checkpoint_id: u256,
        #[key]
        job_id: u256,
        hour_number: u32,
        gpu_utilization: u8,
        proof_hash: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CheckpointVerified {
        #[key]
        checkpoint_id: u256,
        #[key]
        job_id: u256,
        verified: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CheckpointPaid {
        #[key]
        checkpoint_id: u256,
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        sage_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerGPURegistered {
        #[key]
        worker: ContractAddress,
        gpu_tier: u8,
        gpu_count: u8,
        tee_enabled: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct HourlyRateUpdated {
        gpu_tier: u8,
        old_rate: u256,
        new_rate: u256,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        proof_verifier: ContractAddress,
        proof_gated_payment: ContractAddress,
        optimistic_tee: ContractAddress
    ) {
        self.owner.write(owner);
        self.proof_verifier.write(proof_verifier);
        self.proof_gated_payment.write(proof_gated_payment);
        self.optimistic_tee.write(optimistic_tee);

        // Initialize default hourly rates
        self.hourly_rates.write(0, RATE_H100);      // GPUTier::H100
        self.hourly_rates.write(1, RATE_A100);      // GPUTier::A100
        self.hourly_rates.write(2, RATE_RTX4090);   // GPUTier::RTX4090
        self.hourly_rates.write(3, RATE_RTX3090);   // GPUTier::RTX3090
        self.hourly_rates.write(4, RATE_OTHER);     // GPUTier::Other

        self.checkpoint_counter.write(0);
    }

    #[abi(embed_v0)]
    impl MeteredBillingImpl of IMeteredBilling<ContractState> {
        fn start_metered_job(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            gpu_tier: GPUTier,
            max_hours: u32,
            verification_method: VerificationMethod,
            privacy_enabled: bool
        ) {
            let client = get_caller_address();
            assert(!self.job_exists.read(job_id), 'Job already exists');
            assert(!worker.is_zero(), 'Invalid worker');
            assert(max_hours > 0, 'Invalid max hours');

            // Get hourly rate for this GPU tier
            let hourly_rate = self._get_rate_for_tier(gpu_tier);

            let job = MeteredJob {
                job_id,
                client,
                worker,
                gpu_tier,
                hourly_rate_sage: hourly_rate,
                max_hours,
                verification_method,
                checkpoint_interval: SECONDS_PER_HOUR,
                started_at: get_block_timestamp(),
                ended_at: 0,
                is_active: true,
                privacy_enabled,
            };

            self.metered_jobs.write(job_id, job);
            self.job_exists.write(job_id, true);

            // Update stats
            let total = self.total_metered_jobs.read();
            self.total_metered_jobs.write(total + 1);

            self.emit(MeteredJobStarted {
                job_id,
                client,
                worker,
                gpu_tier: self._tier_to_u8(gpu_tier),
                hourly_rate,
                max_hours,
                timestamp: get_block_timestamp(),
            });
        }

        fn end_metered_job(ref self: ContractState, job_id: u256) {
            assert(self.job_exists.read(job_id), 'Job not found');

            let mut job = self.metered_jobs.read(job_id);
            let caller = get_caller_address();

            // Only client or worker can end job
            assert(caller == job.client || caller == job.worker, 'Not authorized');
            assert(job.is_active, 'Job not active');

            job.is_active = false;
            job.ended_at = get_block_timestamp();
            self.metered_jobs.write(job_id, job);

            let total_hours = self.job_verified_hours.read(job_id);
            let total_paid = self.job_total_paid.read(job_id);

            self.emit(MeteredJobEnded {
                job_id,
                total_hours,
                total_paid,
                timestamp: get_block_timestamp(),
            });
        }

        fn submit_hourly_checkpoint(
            ref self: ContractState,
            job_id: u256,
            hour_number: u32,
            gpu_utilization: u8,
            memory_used_gb: u32,
            compute_hash: felt252,
            proof_data: Array<felt252>,
            proof_hash: felt252
        ) {
            assert(self.job_exists.read(job_id), 'Job not found');

            let job = self.metered_jobs.read(job_id);
            let caller = get_caller_address();

            assert(caller == job.worker, 'Only worker');
            assert(job.is_active, 'Job not active');
            assert(hour_number <= job.max_hours, 'Exceeds max hours');
            assert(gpu_utilization <= 100, 'Invalid utilization');

            // SECURITY: Prevent duplicate billing for same hour
            assert!(!self.job_hour_checkpointed.read((job_id, hour_number)), "Hour already checkpointed");

            // Mark hour as checkpointed BEFORE creating checkpoint (CEI pattern)
            self.job_hour_checkpointed.write((job_id, hour_number), true);

            // Create checkpoint
            let checkpoint_id = self.checkpoint_counter.read() + 1;
            self.checkpoint_counter.write(checkpoint_id);

            let checkpoint = HourlyCheckpoint {
                checkpoint_id,
                job_id,
                hour_number,
                gpu_utilization,
                memory_used_gb,
                compute_hash,
                proof_hash,
                verification_method: VerificationMethod::STWOProof,
                verified: false,
                paid: false,
                sage_amount: job.hourly_rate_sage,
                submitted_at: get_block_timestamp(),
                verified_at: 0,
            };

            self.checkpoints.write(checkpoint_id, checkpoint);

            // Track checkpoint for job
            let count = self.job_checkpoint_count.read(job_id);
            self.job_checkpoints.write((job_id, count), checkpoint_id);
            self.job_checkpoint_count.write(job_id, count + 1);

            // Submit proof to ProofVerifier
            let verifier = IProofVerifierDispatcher {
                contract_address: self.proof_verifier.read()
            };

            let proof_job_id = ProofJobId { value: checkpoint_id };
            let verified = verifier.verify_proof(proof_job_id, proof_data);

            if verified {
                self._mark_checkpoint_verified(checkpoint_id);
                self._pay_checkpoint(checkpoint_id);
            }

            self.emit(CheckpointSubmitted {
                checkpoint_id,
                job_id,
                hour_number,
                gpu_utilization,
                proof_hash,
                timestamp: get_block_timestamp(),
            });
        }

        fn submit_tee_checkpoint(
            ref self: ContractState,
            job_id: u256,
            hour_number: u32,
            gpu_utilization: u8,
            memory_used_gb: u32,
            compute_hash: felt252,
            tee_quote: Array<felt252>,
            enclave_measurement: felt252
        ) {
            assert(self.job_exists.read(job_id), 'Job not found');

            let job = self.metered_jobs.read(job_id);
            let caller = get_caller_address();

            assert(caller == job.worker, 'Only worker');
            assert(job.is_active, 'Job not active');
            assert(hour_number <= job.max_hours, 'Exceeds max hours');

            // SECURITY: Prevent duplicate billing for same hour
            assert!(!self.job_hour_checkpointed.read((job_id, hour_number)), "Hour already checkpointed");

            // Mark hour as checkpointed BEFORE creating checkpoint (CEI pattern)
            self.job_hour_checkpointed.write((job_id, hour_number), true);

            // Verify enclave is whitelisted
            let verifier = IProofVerifierDispatcher {
                contract_address: self.proof_verifier.read()
            };
            assert(verifier.is_enclave_whitelisted(enclave_measurement), 'Invalid enclave');

            // Create checkpoint with TEE attestation
            let checkpoint_id = self.checkpoint_counter.read() + 1;
            self.checkpoint_counter.write(checkpoint_id);

            // Compute proof hash from TEE quote
            let proof_hash = poseidon_hash_span(tee_quote.span());

            let checkpoint = HourlyCheckpoint {
                checkpoint_id,
                job_id,
                hour_number,
                gpu_utilization,
                memory_used_gb,
                compute_hash,
                proof_hash,
                verification_method: VerificationMethod::TEEAttestation,
                verified: true,  // TEE attestation is trusted immediately
                paid: false,
                sage_amount: job.hourly_rate_sage,
                submitted_at: get_block_timestamp(),
                verified_at: get_block_timestamp(),
            };

            self.checkpoints.write(checkpoint_id, checkpoint);

            // Track checkpoint
            let count = self.job_checkpoint_count.read(job_id);
            self.job_checkpoints.write((job_id, count), checkpoint_id);
            self.job_checkpoint_count.write(job_id, count + 1);

            // TEE attestation is optimistically trusted - pay immediately
            self._pay_checkpoint(checkpoint_id);

            self.emit(CheckpointSubmitted {
                checkpoint_id,
                job_id,
                hour_number,
                gpu_utilization,
                proof_hash,
                timestamp: get_block_timestamp(),
            });
        }

        fn verify_checkpoint(ref self: ContractState, checkpoint_id: u256) {
            let checkpoint = self.checkpoints.read(checkpoint_id);
            assert(!checkpoint.verified, 'Already verified');

            // Check proof status
            let verifier = IProofVerifierDispatcher {
                contract_address: self.proof_verifier.read()
            };

            let proof_job_id = ProofJobId { value: checkpoint_id };
            let status = verifier.get_proof_status(proof_job_id);

            match status {
                ProofStatus::Verified => {
                    self._mark_checkpoint_verified(checkpoint_id);
                    self._pay_checkpoint(checkpoint_id);
                },
                _ => {
                    assert(false, 'Proof not verified');
                }
            }
        }

        fn batch_verify_checkpoints(ref self: ContractState, checkpoint_ids: Array<u256>) {
            let mut i: u32 = 0;
            let len = checkpoint_ids.len();
            while i < len {
                let checkpoint_id = *checkpoint_ids.at(i);
                let checkpoint = self.checkpoints.read(checkpoint_id);
                if !checkpoint.verified {
                    // Try to verify
                    let verifier = IProofVerifierDispatcher {
                        contract_address: self.proof_verifier.read()
                    };
                    let proof_job_id = ProofJobId { value: checkpoint_id };
                    let status = verifier.get_proof_status(proof_job_id);

                    match status {
                        ProofStatus::Verified => {
                            self._mark_checkpoint_verified(checkpoint_id);
                            self._pay_checkpoint(checkpoint_id);
                        },
                        _ => {}
                    }
                }
                i += 1;
            };
        }

        fn register_worker_gpu(
            ref self: ContractState,
            gpu_tier: GPUTier,
            gpu_count: u8,
            total_memory_gb: u32,
            tee_enabled: bool,
            enclave_measurement: felt252
        ) {
            let worker = get_caller_address();

            let gpu = WorkerGPU {
                worker,
                gpu_tier,
                gpu_count,
                total_memory_gb,
                tee_enabled,
                enclave_measurement,
                registered_at: get_block_timestamp(),
                total_hours_worked: 0,
                total_sage_earned: 0,
            };

            self.worker_gpus.write(worker, gpu);
            self.worker_registered.write(worker, true);

            self.emit(WorkerGPURegistered {
                worker,
                gpu_tier: self._tier_to_u8(gpu_tier),
                gpu_count,
                tee_enabled,
                timestamp: get_block_timestamp(),
            });
        }

        fn update_worker_gpu(
            ref self: ContractState,
            gpu_tier: GPUTier,
            gpu_count: u8,
            total_memory_gb: u32
        ) {
            let worker = get_caller_address();
            assert(self.worker_registered.read(worker), 'Not registered');

            let mut gpu = self.worker_gpus.read(worker);
            gpu.gpu_tier = gpu_tier;
            gpu.gpu_count = gpu_count;
            gpu.total_memory_gb = total_memory_gb;
            self.worker_gpus.write(worker, gpu);
        }

        fn get_metered_job(self: @ContractState, job_id: u256) -> MeteredJob {
            self.metered_jobs.read(job_id)
        }

        fn get_checkpoint(self: @ContractState, checkpoint_id: u256) -> HourlyCheckpoint {
            self.checkpoints.read(checkpoint_id)
        }

        fn get_worker_gpu(self: @ContractState, worker: ContractAddress) -> WorkerGPU {
            self.worker_gpus.read(worker)
        }

        fn get_hourly_rate(self: @ContractState, gpu_tier: GPUTier) -> u256 {
            self._get_rate_for_tier(gpu_tier)
        }

        fn get_job_checkpoint_count(self: @ContractState, job_id: u256) -> u32 {
            self.job_checkpoint_count.read(job_id)
        }

        fn get_verified_hours(self: @ContractState, job_id: u256) -> u32 {
            self.job_verified_hours.read(job_id)
        }

        fn get_job_total_paid(self: @ContractState, job_id: u256) -> u256 {
            self.job_total_paid.read(job_id)
        }

        fn calculate_current_bill(self: @ContractState, job_id: u256) -> u256 {
            let job = self.metered_jobs.read(job_id);
            if !job.is_active {
                return self.job_total_paid.read(job_id);
            }

            let elapsed = get_block_timestamp() - job.started_at;
            let hours_elapsed: u256 = (elapsed / SECONDS_PER_HOUR).into();
            let verified_hours: u256 = self.job_verified_hours.read(job_id).into();

            // Current bill = verified hours + pending hours
            let pending_hours = if hours_elapsed > verified_hours {
                hours_elapsed - verified_hours
            } else {
                0
            };

            self.job_total_paid.read(job_id) + (pending_hours * job.hourly_rate_sage)
        }

        fn set_hourly_rate(ref self: ContractState, gpu_tier: GPUTier, rate: u256) {
            self._only_owner();

            let tier_u8 = self._tier_to_u8(gpu_tier);
            let old_rate = self.hourly_rates.read(tier_u8);
            self.hourly_rates.write(tier_u8, rate);

            self.emit(HourlyRateUpdated {
                gpu_tier: tier_u8,
                old_rate,
                new_rate: rate,
                timestamp: get_block_timestamp(),
            });
        }

        fn set_proof_gated_payment(ref self: ContractState, payment: ContractAddress) {
            self._only_owner();
            // SECURITY: Zero address validation
            assert!(!payment.is_zero(), "Payment contract cannot be zero address");
            self.proof_gated_payment.write(payment);
        }

        fn set_proof_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._only_owner();
            // SECURITY: Zero address validation
            assert!(!verifier.is_zero(), "Verifier cannot be zero address");
            self.proof_verifier.write(verifier);
        }

        fn set_optimistic_tee(ref self: ContractState, tee: ContractAddress) {
            self._only_owner();
            // SECURITY: Zero address validation
            assert!(!tee.is_zero(), "TEE contract cannot be zero address");
            self.optimistic_tee.write(tee);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }

        fn _tier_to_u8(self: @ContractState, tier: GPUTier) -> u8 {
            match tier {
                GPUTier::H100 => 0,
                GPUTier::A100 => 1,
                GPUTier::RTX4090 => 2,
                GPUTier::RTX3090 => 3,
                GPUTier::Other => 4,
            }
        }

        fn _get_rate_for_tier(self: @ContractState, tier: GPUTier) -> u256 {
            let tier_u8 = self._tier_to_u8(tier);
            self.hourly_rates.read(tier_u8)
        }

        fn _mark_checkpoint_verified(ref self: ContractState, checkpoint_id: u256) {
            let mut checkpoint = self.checkpoints.read(checkpoint_id);
            checkpoint.verified = true;
            checkpoint.verified_at = get_block_timestamp();
            self.checkpoints.write(checkpoint_id, checkpoint);

            // Update job verified hours
            let verified = self.job_verified_hours.read(checkpoint.job_id);
            self.job_verified_hours.write(checkpoint.job_id, verified + 1);

            // Update global stats
            let total_hours = self.total_compute_hours.read();
            self.total_compute_hours.write(total_hours + 1);

            self.emit(CheckpointVerified {
                checkpoint_id,
                job_id: checkpoint.job_id,
                verified: true,
                timestamp: get_block_timestamp(),
            });
        }

        fn _pay_checkpoint(ref self: ContractState, checkpoint_id: u256) {
            let mut checkpoint = self.checkpoints.read(checkpoint_id);
            assert(checkpoint.verified, 'Not verified');
            assert(!checkpoint.paid, 'Already paid');

            let job = self.metered_jobs.read(checkpoint.job_id);

            // Register payment in ProofGatedPayment for proper fee distribution
            let payment = IProofGatedPaymentDispatcher {
                contract_address: self.proof_gated_payment.read()
            };

            // Use checkpoint_id as job_id for micro-payment
            payment.register_job_payment(
                checkpoint_id,
                job.worker,
                job.client,
                checkpoint.sage_amount,
                0, // USD value calculated from SAGE
                job.privacy_enabled
            );

            // Mark as paid
            checkpoint.paid = true;
            self.checkpoints.write(checkpoint_id, checkpoint);

            // Update job total paid
            let total = self.job_total_paid.read(checkpoint.job_id);
            self.job_total_paid.write(checkpoint.job_id, total + checkpoint.sage_amount);

            // Update worker stats
            let mut worker_gpu = self.worker_gpus.read(job.worker);
            worker_gpu.total_hours_worked = worker_gpu.total_hours_worked + 1;
            worker_gpu.total_sage_earned = worker_gpu.total_sage_earned + checkpoint.sage_amount;
            self.worker_gpus.write(job.worker, worker_gpu);

            // Update global stats
            let total_sage = self.total_sage_distributed.read();
            self.total_sage_distributed.write(total_sage + checkpoint.sage_amount);

            self.emit(CheckpointPaid {
                checkpoint_id,
                job_id: checkpoint.job_id,
                worker: job.worker,
                sage_amount: checkpoint.sage_amount,
                timestamp: get_block_timestamp(),
            });
        }
    }
}
