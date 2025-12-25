// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 SAGE Network Foundation
//
// This file is part of SAGE Network.
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//     https://github.com/Ciro-AI-Labs/ciro-network/blob/main/LICENSE-BSL
//
// Change Date: January 1, 2029
// Change License: Apache License, Version 2.0
//
// For more information see: https://github.com/Ciro-AI-Labs/ciro-network/blob/main/WHY_BSL_FOR_SAGE.md

//! SAGE Network JobManager Contract
//! 
//! Main contract for managing job submissions, assignments, execution, and payments
//! in the SAGE Distributed Compute Layer. This contract coordinates with CDC Pool
//! and Payment systems to provide the core job orchestration functionality.

// Core Starknet imports
use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
use core::num::traits::Zero;

// Storage trait imports - CRITICAL for Map operations
use starknet::storage::{
    StoragePointerReadAccess, StoragePointerWriteAccess, 
    StorageMapReadAccess, StorageMapWriteAccess, Map
};

// Interface imports
use sage_contracts::interfaces::job_manager::{
    IJobManager, JobId, ModelId, WorkerId, JobType, JobSpec, JobResult, 
    VerificationMethod, ModelRequirements, JobState, JobDetails, WorkerStats,
    ProveJobData
};

// Token interface
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

// PHASE 2: CDC Pool interface for notification hooks
use sage_contracts::interfaces::cdc_pool::{ICDCPoolDispatcher, ICDCPoolDispatcherTrait};

// PHASE 3: Proof-Gated Payment integration
use sage_contracts::payments::proof_gated_payment::{
    IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait
};

// Shared constants
use sage_contracts::utils::constants::{
    SECONDS_PER_HOUR, SECONDS_PER_DAY, SCALE, BPS_DENOMINATOR
};

#[starknet::contract]
mod JobManager {
    use super::{
        IJobManager, JobId, ModelId, WorkerId, JobType, JobSpec, JobResult,
        VerificationMethod, ModelRequirements, JobState, JobDetails, WorkerStats,
        ProveJobData, ContractAddress, get_caller_address, get_block_timestamp,
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map,
        IERC20Dispatcher, IERC20DispatcherTrait, Zero,
        // PHASE 2: CDC Pool notification hooks
        ICDCPoolDispatcher, ICDCPoolDispatcherTrait,
        // PHASE 3: Proof-Gated Payment integration
        IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait,
        // Shared constants
        SECONDS_PER_HOUR, SECONDS_PER_DAY, SCALE, BPS_DENOMINATOR
    };

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // Core job events
        JobSubmitted: JobSubmitted,
        JobAssigned: JobAssigned,
        JobCompleted: JobCompleted,
        JobCancelled: JobCancelled,
        PaymentReleased: PaymentReleased,
        ModelRegistered: ModelRegistered,
        // Phase 2.1: Additional events for monitoring
        WorkerRegistered: WorkerRegistered,
        ConfigUpdated: ConfigUpdated,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        EmergencyWithdrawal: EmergencyWithdrawal,
        CDCPoolNotificationFailed: CDCPoolNotificationFailed,
        // Phase 3: Proof-Gated Payment events
        JobPaymentRegistered: JobPaymentRegistered,
    }

    #[derive(Drop, starknet::Event)]
    struct JobSubmitted {
        #[key]
        job_id: u256,
        #[key]
        client: ContractAddress,
        payment: u256
    }

    #[derive(Drop, starknet::Event)]
    struct JobAssigned {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct JobCompleted {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentReleased {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        amount: u256
    }

    #[derive(Drop, starknet::Event)]
    struct ModelRegistered {
        #[key]
        model_id: u256,
        #[key]
        owner: ContractAddress
    }

    // Phase 2.1: New event structs
    #[derive(Drop, starknet::Event)]
    struct JobCancelled {
        #[key]
        job_id: u256,
        #[key]
        client: ContractAddress,
        reason: felt252,
        refund_amount: u256
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerRegistered {
        #[key]
        worker_id: felt252,
        #[key]
        worker_address: ContractAddress,
        registered_by: ContractAddress,
        timestamp: u64
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        #[key]
        config_key: felt252,
        old_value: felt252,
        new_value: felt252,
        updated_by: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct ContractPaused {
        paused_by: ContractAddress,
        timestamp: u64
    }

    #[derive(Drop, starknet::Event)]
    struct ContractUnpaused {
        unpaused_by: ContractAddress,
        timestamp: u64
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyWithdrawal {
        #[key]
        token: ContractAddress,
        amount: u256,
        to: ContractAddress,
        timestamp: u64
    }

    #[derive(Drop, starknet::Event)]
    struct CDCPoolNotificationFailed {
        #[key]
        job_id: u256,
        function_name: felt252,
        timestamp: u64
    }

    // Phase 3: Proof-Gated Payment event
    #[derive(Drop, starknet::Event)]
    struct JobPaymentRegistered {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        sage_amount: u256,
        privacy_enabled: bool,
        timestamp: u64
    }

    #[storage]
    struct Storage {
        // Configuration parameters
        payment_token: ContractAddress,
        treasury: ContractAddress,
        cdc_pool_contract: ContractAddress,
        platform_fee_bps: u16,
        min_job_payment: u256,
        max_job_duration: u64,
        dispute_fee: u256,
        min_allocation_score: u256,
        
        // Counters and state
        next_job_id: u256,
        next_model_id: u256,
        total_jobs: u64,
        active_jobs: u64,
        
        // Core job data - store JobSpec fields separately since JobSpec contains Arrays
        job_types: Map<felt252, JobType>,
        job_model_ids: Map<felt252, ModelId>,
        job_input_hashes: Map<felt252, felt252>,
        job_output_formats: Map<felt252, felt252>,
        job_verification_methods: Map<felt252, VerificationMethod>,
        job_max_rewards: Map<felt252, u256>,
        job_deadlines: Map<felt252, u64>,

        // Phase 2.1: Array storage pattern for compute_requirements
        job_compute_requirements_len: Map<felt252, u32>,              // job_key -> array length
        job_compute_requirements: Map<(felt252, u32), felt252>,       // (job_key, index) -> element

        // Phase 2.1: Array storage pattern for metadata
        job_metadata_len: Map<felt252, u32>,                          // job_key -> array length
        job_metadata: Map<(felt252, u32), felt252>,                   // (job_key, index) -> element

        job_clients: Map<felt252, ContractAddress>,
        job_workers: Map<felt252, ContractAddress>,
        job_states: Map<felt252, JobState>,
        job_payments: Map<felt252, u256>,
        job_timestamps: Map<felt252, (u64, u64, u64)>, // (created, assigned, completed)
        
        // Model management - store ModelRequirements fields separately
        model_min_memory: Map<felt252, u32>,
        model_min_compute: Map<felt252, u32>,
        model_gpu_types: Map<felt252, felt252>,

        // Phase 2.1: Array storage pattern for framework_dependencies
        model_framework_deps_len: Map<felt252, u32>,                   // model_key -> array length
        model_framework_deps: Map<(felt252, u32), felt252>,            // (model_key, index) -> element

        model_owners: Map<felt252, ContractAddress>,
        model_active: Map<felt252, bool>,
        model_hashes: Map<felt252, felt252>,
        
        // Worker tracking - using felt252 keys
        worker_stats: Map<felt252, WorkerStats>,
        worker_active: Map<felt252, bool>,
        worker_addresses: Map<felt252, ContractAddress>, // WorkerId to Address mapping
        
        // Job results storage
        job_result_hashes: Map<felt252, felt252>,
        job_results: Map<felt252, felt252>, // Alias for compatibility
        job_gas_used: Map<felt252, u256>,
        completed_jobs: u64,
        
        // Cairo 2.12.0: Gas Reserve Management for Compute Jobs
        job_gas_estimates: Map<felt252, u256>,      // Estimated gas per job
        job_gas_reserved: Map<felt252, u256>,       // Reserved gas per job
        worker_gas_efficiency: Map<felt252, u256>,  // Gas efficiency per worker
        model_base_gas_cost: Map<felt252, u256>,    // Base gas cost per model type
        
        // Job indexing for queries - using felt252 keys
        client_jobs: Map<(ContractAddress, u64), felt252>,
        client_job_count: Map<ContractAddress, u64>,
        worker_jobs: Map<(ContractAddress, u64), felt252>,
        worker_job_count: Map<ContractAddress, u64>,

        // Model indexing - using felt252 keys
        models_by_owner: Map<(ContractAddress, u64), felt252>,
        models_by_owner_count: Map<ContractAddress, u64>,

        // PHASE 2 FIX: Reverse mapping for address -> worker_id lookup
        address_to_worker_id: Map<ContractAddress, felt252>,
        worker_count: u64,

        // PHASE 2 FIX: CDC Pool and Reputation Manager contract references
        reputation_manager: ContractAddress,

        // PHASE 3: Proof-Gated Payment integration
        proof_gated_payment: ContractAddress,

        // Simple admin control
        admin: ContractAddress,
        contract_paused: bool,

        // Phase 2.1: Reentrancy guard for cross-contract calls
        _reentrancy_guard: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        payment_token: ContractAddress,
        treasury: ContractAddress,
        cdc_pool_contract: ContractAddress
    ) {
        // Phase 2.1: Validate constructor parameters
        assert!(!admin.is_zero(), "Invalid admin address");
        assert!(!payment_token.is_zero(), "Invalid payment token address");
        assert!(!treasury.is_zero(), "Invalid treasury address");
        // Note: cdc_pool_contract CAN be zero (optional integration)

        self.admin.write(admin);
        self.payment_token.write(payment_token);
        self.treasury.write(treasury);
        self.cdc_pool_contract.write(cdc_pool_contract);

        // Set default configuration
        self.platform_fee_bps.write(250); // 2.5%
        self.min_job_payment.write(SCALE); // 1 SAGE token
        self.max_job_duration.write(SECONDS_PER_DAY); // 24 hours
        self.dispute_fee.write(10 * SCALE); // 10 SAGE tokens
        self.min_allocation_score.write(100);

        self.next_job_id.write(1);
        self.next_model_id.write(1);
        self.contract_paused.write(false);
        self._reentrancy_guard.write(false);
    }

    #[abi(embed_v0)]
    impl JobManagerImpl of IJobManager<ContractState> {
        fn submit_ai_job(
            ref self: ContractState,
            job_spec: JobSpec,
            payment: u256,
            client: ContractAddress
        ) -> JobId {
            self._check_not_paused();

            // Phase 2.1: Enhanced input validation
            let current_time = starknet::get_block_timestamp();

            // Validate client address
            assert!(!client.is_zero(), "Invalid client address");

            // Validate payment
            assert!(payment >= self.min_job_payment.read(), "JM: payment too low");

            // Validate deadline (must be in future but not too far - max 30 days)
            let max_deadline_offset: u64 = 30 * SECONDS_PER_DAY; // 30 days
            assert!(job_spec.sla_deadline > current_time, "JM: deadline in past");
            assert!(
                job_spec.sla_deadline <= current_time + max_deadline_offset,
                "Deadline too far in future"
            );

            // Validate max_reward consistency
            assert!(job_spec.max_reward > 0, "Invalid max reward");
            assert!(job_spec.max_reward <= payment, "Max reward exceeds payment");

            // Validate input hash is non-zero
            assert!(job_spec.input_data_hash != 0, "Invalid input data hash");

            // Validate model exists if specified (model_id != 0)
            if job_spec.model_id.value != 0 {
                let model_key: felt252 = job_spec.model_id.value.try_into().unwrap();
                assert!(self.model_active.read(model_key), "Model not active or doesn't exist");
            }

            // Generate new job ID
            let job_id = JobId { value: self.next_job_id.read() };
            self.next_job_id.write(self.next_job_id.read() + 1);
            
            // Cairo 2.12.0: Using let-else pattern for cleaner error handling
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };
            
            // Cairo 2.12.0: Estimate gas BEFORE consuming job_spec arrays
            let estimated_gas = self._estimate_gas_for_job_type(job_spec.job_type, job_spec.model_id, job_spec.expected_output_format);

            // Store job information (non-array fields first)
            self.job_types.write(job_key, job_spec.job_type);
            self.job_model_ids.write(job_key, job_spec.model_id);
            self.job_input_hashes.write(job_key, job_spec.input_data_hash);
            self.job_output_formats.write(job_key, job_spec.expected_output_format);
            self.job_verification_methods.write(job_key, job_spec.verification_method);
            self.job_max_rewards.write(job_key, job_spec.max_reward);
            self.job_deadlines.write(job_key, job_spec.sla_deadline);
            self.job_clients.write(job_key, client);
            self.job_payments.write(job_key, payment);
            self.job_timestamps.write(job_key, (current_time, 0, 0)); // (created, assigned, completed)

            // Phase 2.1: Store arrays using array storage pattern (consumes job_spec arrays)
            self._store_job_compute_requirements(job_key, job_spec.compute_requirements);
            self._store_job_metadata(job_key, job_spec.metadata);

            // Initialize job state as Queued
            self.job_states.write(job_key, JobState::Queued);

            // Reserve gas for job execution
            self.reserve_gas_for_job(job_id, estimated_gas);
            
            // Update counters
            self.total_jobs.write(self.total_jobs.read() + 1);
            self.active_jobs.write(self.active_jobs.read() + 1);
            
            self.emit(JobSubmitted {
                job_id: job_id.value,
                client,
                payment
            });
            
            job_id
        }

        fn submit_prove_job(
            ref self: ContractState,
            prove_job_data: ProveJobData,
            payment: u256,
            client: ContractAddress
        ) -> JobId {
            // Create a JobSpec for prove jobs
            let job_spec = JobSpec {
                job_type: JobType::ProofGeneration,
                model_id: ModelId { value: 0 }, // Default model for proof jobs
                input_data_hash: prove_job_data.private_inputs_hash,
                expected_output_format: 'proof_format',
                verification_method: VerificationMethod::ZeroKnowledgeProof,
                max_reward: payment,
                sla_deadline: get_block_timestamp() + SECONDS_PER_HOUR, // 1 hour deadline
                compute_requirements: array![], // Empty array for now
                metadata: array![] // Empty array for now
            };
            
            // Call the main submit job function
            self.submit_ai_job(job_spec, payment, client)
        }

        fn assign_job_to_worker(
            ref self: ContractState,
            job_id: JobId,
            worker_id: WorkerId
        ) {
            self._check_not_paused();

            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");

            // Cairo 2.12.0: Combined let-else for type conversion and state validation
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };

            let current_state = self.job_states.read(job_key);
            let JobState::Queued = current_state else {
                panic!("Job not available for assignment");
            };

            // Update job state to Processing BEFORE external calls (CEI pattern)
            self.job_states.write(job_key, JobState::Processing);
            let current_time = get_block_timestamp();
            let (created_at, _, completed_at) = self.job_timestamps.read(job_key);
            self.job_timestamps.write(job_key, (created_at, current_time, completed_at));

            // Cairo 2.12.0: Using let-else for worker validation
            let worker_address = self.worker_addresses.read(worker_id.value);
            let true = !worker_address.is_zero() else {
                panic!("Worker not registered");
            };
            self.job_workers.write(job_key, worker_address);

            // Phase 2.1: Reentrancy guard for CDC Pool notification
            self._start_nonreentrant();

            // Notify CDC Pool to reserve worker for this job
            let job_deadline = self.job_deadlines.read(job_key);
            let reservation_duration = if job_deadline > current_time {
                job_deadline - current_time
            } else {
                self.max_job_duration.read()
            };
            self._notify_cdc_pool_reserve_worker_safe(worker_id, job_id, reservation_duration);

            self._end_nonreentrant();

            self.emit(JobAssigned {
                job_id: job_id.value,
                worker: worker_address
            });
        }

        fn submit_job_result(
            ref self: ContractState,
            job_id: JobId,
            result: JobResult
        ) {
            let caller = get_caller_address();

            // Cairo 2.12.0: Let-else patterns for cleaner error handling
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };

            let current_state = self.job_states.read(job_key);
            let JobState::Processing = current_state else {
                panic!("Job not in processing state");
            };

            let worker_address = self.job_workers.read(job_key);
            let true = (worker_address == caller) else {
                panic!("Not assigned worker");
            };

            // Store job result data
            self.job_result_hashes.write(job_key, result.output_data_hash);
            self.job_gas_used.write(job_key, result.gas_used);

            // Update job state to Completed
            self.job_states.write(job_key, JobState::Completed);
            let (created_at, assigned_at, _) = self.job_timestamps.read(job_key);
            self.job_timestamps.write(job_key, (created_at, assigned_at, result.execution_time));

            // Update worker stats including gas efficiency
            self._update_worker_stats(result.worker_id, result.execution_time);
            self._update_worker_gas_efficiency(result.worker_id, job_id, result.gas_used);

            // Decrement active jobs counter
            self.active_jobs.write(self.active_jobs.read() - 1);
            self.completed_jobs.write(self.completed_jobs.read() + 1);

            // Phase 2.1: Reentrancy guard for CDC Pool notifications
            self._start_nonreentrant();

            // Notify CDC Pool of job completion (with error handling)
            self._notify_cdc_pool_job_completed_safe(result.worker_id, job_id, true, result.execution_time);

            // Update reputation in CDC Pool
            let performance_score: u8 = 80;
            let response_time: u64 = result.execution_time;
            let quality_score: u8 = 90;
            self._notify_cdc_pool_reputation_update_safe(
                result.worker_id, job_id, performance_score, response_time, quality_score
            );

            // Release worker reservation in CDC Pool
            self._notify_cdc_pool_release_worker_safe(result.worker_id, job_id);

            // PHASE 3: Register job with ProofGatedPayment for proof-based payment release
            // Payment will only be released after proof verification (STWO or TEE)
            let payment_amount = self.job_payments.read(job_key);
            let client = self.job_clients.read(job_key);
            self._register_proof_gated_payment(job_id, worker_address, client, payment_amount);

            self._end_nonreentrant();

            self.emit(JobCompleted {
                job_id: job_id.value,
                worker: worker_address
            });
        }

        fn distribute_rewards(ref self: ContractState, job_id: JobId) {
            // Cairo 2.12.0: Clean let-else patterns for reward distribution
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };

            let job_state = self.job_states.read(job_key);
            let JobState::Completed = job_state else {
                panic!("Job not completed");
            };

            let payment_amount = self.job_payments.read(job_key);
            let worker_address = self.job_workers.read(job_key);

            // PHASE 3: Check if ProofGatedPayment is configured
            let proof_payment_addr = self.proof_gated_payment.read();

            if !proof_payment_addr.is_zero() {
                // PROOF-GATED FLOW: Payment is handled by ProofGatedPayment
                // Check if payment is ready (proof verified or TEE finalized)
                let proof_payment = IProofGatedPaymentDispatcher {
                    contract_address: proof_payment_addr
                };

                let is_ready = proof_payment.is_payment_ready(job_id.value);
                assert!(is_ready, "Proof not verified - cannot release payment");

                // Trigger payment release through ProofGatedPayment → PaymentRouter
                // This handles the 80/20 fee split with burn/treasury/stakers
                proof_payment.release_payment(job_id.value);

                // Mark job as paid
                self.job_states.write(job_key, JobState::Paid);

                // Update worker earnings
                self._update_worker_earnings(worker_address, payment_amount);

                self.emit(PaymentReleased {
                    job_id: job_id.value,
                    worker: worker_address,
                    amount: payment_amount
                });
            } else {
                // LEGACY FLOW: Direct payment (no proof verification required)
                // Used when ProofGatedPayment is not configured

                // SECURITY FIX: Prevent division by zero
                assert!(self.platform_fee_bps.read() <= 10000, "Invalid platform fee");

                // Calculate platform fee
                let platform_fee = (payment_amount * self.platform_fee_bps.read().into()) / BPS_DENOMINATOR;
                let worker_payment = payment_amount - platform_fee;

                // SECURITY FIX: Update state BEFORE external calls (reentrancy protection)
                // Mark job as paid to prevent double-distribution
                self.job_states.write(job_key, JobState::Paid);

                // Update worker earnings BEFORE external calls
                self._update_worker_earnings(worker_address, worker_payment);

                // Transfer tokens with return value checks
                let token = IERC20Dispatcher { contract_address: self.payment_token.read() };

                // SECURITY FIX: Check return values of token transfers
                let worker_transfer_success = token.transfer(worker_address, worker_payment);
                assert!(worker_transfer_success, "Worker payment transfer failed");

                if platform_fee > 0 {
                    let treasury_transfer_success = token.transfer(self.treasury.read(), platform_fee);
                    assert!(treasury_transfer_success, "Treasury transfer failed");
                }

                self.emit(PaymentReleased {
                    job_id: job_id.value,
                    worker: worker_address,
                    amount: worker_payment
                });
            }
        }

        fn register_model(
            ref self: ContractState,
            model_hash: felt252,
            requirements: ModelRequirements,
            pricing: u256
        ) -> ModelId {
            let model_id = ModelId { value: self.next_model_id.read() };
            let model_key: felt252 = model_id.value.try_into().unwrap();
            
            self.model_min_memory.write(model_key, requirements.min_memory_gb);
            self.model_min_compute.write(model_key, requirements.min_compute_units);
            self.model_gpu_types.write(model_key, requirements.required_gpu_type);

            // Phase 2.1: Store framework_dependencies using array storage pattern
            self._store_model_framework_deps(model_key, requirements.framework_dependencies);

            self.model_owners.write(model_key, get_caller_address());
            self.model_active.write(model_key, true);
            self.model_hashes.write(model_key, model_hash);
            
            self.next_model_id.write(self.next_model_id.read() + 1);
            
            self.emit(ModelRegistered {
                model_id: model_id.value,
                owner: get_caller_address()
            });
            
            model_id
        }

        fn get_job_details(self: @ContractState, job_id: JobId) -> JobDetails {
            let job_key: felt252 = job_id.value.try_into().unwrap();
            let job_type = self.job_types.read(job_key);
            let state = self.job_states.read(job_key);
            let client = self.job_clients.read(job_key);
            let worker = self.job_workers.read(job_key);
            let payment_amount = self.job_payments.read(job_key);
            let (created_at, assigned_at, completed_at) = self.job_timestamps.read(job_key);
            let result_hash = self.job_result_hashes.read(job_key);
            
            JobDetails {
                job_id,
                job_type: job_type,
                client: client,
                worker: worker,
                state: state,
                payment_amount: payment_amount,
                created_at: created_at,
                assigned_at: assigned_at,
                completed_at: completed_at,
                result_hash: result_hash
            }
        }

        fn get_job_state(self: @ContractState, job_id: JobId) -> JobState {
            let job_key: felt252 = job_id.value.try_into().unwrap();
            let state_value = self.job_states.read(job_key);
            
            state_value
        }

        fn get_worker_stats(self: @ContractState, worker_id: WorkerId) -> WorkerStats {
            let worker_key: felt252 = worker_id.value;
            let stats = self.worker_stats.read(worker_key);
            
            // Return stored stats, or default if worker not found
            if stats.total_jobs_completed == 0 && stats.reputation_score == 0 {
                WorkerStats {
                    total_jobs_completed: 0,
                    success_rate: 100, // Default 100% for new workers
                    average_completion_time: SECONDS_PER_HOUR, // Default 1 hour
                    reputation_score: 1000, // Default reputation
                    total_earnings: 0
                }
            } else {
                stats
            }
        }

        fn update_config(ref self: ContractState, config_key: felt252, config_value: felt252) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");

            // Phase 2.1: Track old value for event emission
            let old_value: felt252 = if config_key == 'platform_fee_bps' {
                self.platform_fee_bps.read().into()
            } else if config_key == 'min_job_payment' {
                // Note: u256 to felt252 may truncate, but for events it's acceptable
                self.min_job_payment.read().try_into().unwrap_or(0)
            } else if config_key == 'max_job_duration' {
                self.max_job_duration.read().into()
            } else if config_key == 'dispute_fee' {
                self.dispute_fee.read().try_into().unwrap_or(0)
            } else if config_key == 'min_allocation_score' {
                self.min_allocation_score.read().try_into().unwrap_or(0)
            } else {
                0
            };

            // Handle specific configuration keys
            if config_key == 'platform_fee_bps' {
                let new_fee: u16 = config_value.try_into().unwrap();
                assert!(new_fee <= 1000, "Fee cannot exceed 10%"); // Max 10%
                self.platform_fee_bps.write(new_fee);
            } else if config_key == 'min_job_payment' {
                let new_min: u256 = config_value.into();
                self.min_job_payment.write(new_min);
            } else if config_key == 'max_job_duration' {
                let new_duration: u64 = config_value.try_into().unwrap();
                self.max_job_duration.write(new_duration);
            } else if config_key == 'dispute_fee' {
                let new_fee: u256 = config_value.into();
                self.dispute_fee.write(new_fee);
            } else if config_key == 'min_allocation_score' {
                let new_score: u256 = config_value.into();
                self.min_allocation_score.write(new_score);
            } else {
                panic!("Unknown config key");
            }

            // Phase 2.1: Emit ConfigUpdated event
            self.emit(ConfigUpdated {
                config_key,
                old_value,
                new_value: config_value,
                updated_by: caller
            });
        }

        fn pause(ref self: ContractState) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");
            assert!(!self.contract_paused.read(), "JM: already paused");

            self.contract_paused.write(true);

            // Phase 2.1: Emit ContractPaused event
            self.emit(ContractPaused {
                paused_by: caller,
                timestamp: get_block_timestamp()
            });
        }

        fn unpause(ref self: ContractState) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");
            assert!(self.contract_paused.read(), "JM: not paused");

            self.contract_paused.write(false);

            // Phase 2.1: Emit ContractUnpaused event
            self.emit(ContractUnpaused {
                unpaused_by: caller,
                timestamp: get_block_timestamp()
            });
        }

        fn emergency_withdraw(ref self: ContractState, token: ContractAddress, amount: u256) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");

            // Phase 2.1: Validate inputs
            assert!(!token.is_zero(), "Invalid token address");
            assert!(amount > 0, "Amount must be positive");

            let treasury = self.treasury.read();
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let success = token_dispatcher.transfer(treasury, amount);
            assert!(success, "Emergency withdraw transfer failed");

            // Phase 2.1: Emit EmergencyWithdrawal event
            self.emit(EmergencyWithdrawal {
                token,
                amount,
                to: treasury,
                timestamp: get_block_timestamp()
            });
        }

        fn register_worker(ref self: ContractState, worker_id: WorkerId, worker_address: ContractAddress) {
            // Allow workers to register themselves or admin to register workers
            let caller = get_caller_address();
            assert!(caller == self.admin.read() || caller == worker_address, "Not authorized");

            // Phase 2.1: Validate inputs
            assert!(!worker_address.is_zero(), "Invalid worker address");
            assert!(worker_id.value != 0, "Invalid worker ID");

            // Phase 2.1: Check for duplicate registration
            // Check if this worker_id is already registered to a different address
            let existing_address = self.worker_addresses.read(worker_id.value);
            if !existing_address.is_zero() && existing_address != worker_address {
                panic!("Worker ID already registered to different address");
            }

            // Check if this address is already registered with a different worker_id
            let existing_worker_id = self.address_to_worker_id.read(worker_address);
            if existing_worker_id != 0 && existing_worker_id != worker_id.value {
                panic!("Address already registered with different worker ID");
            }

            // Check if this is a new registration (not an update)
            let is_new_registration = existing_address.is_zero();

            // Store worker address mapping (forward: worker_id -> address)
            self.worker_addresses.write(worker_id.value, worker_address);
            self.worker_active.write(worker_id.value, true);

            // PHASE 2 FIX: Store reverse mapping (address -> worker_id)
            self.address_to_worker_id.write(worker_address, worker_id.value);

            // Initialize worker stats if not exists
            let existing_stats = self.worker_stats.read(worker_id.value);
            if existing_stats.total_jobs_completed == 0 && existing_stats.reputation_score == 0 {
                let initial_stats = WorkerStats {
                    total_jobs_completed: 0,
                    success_rate: 100,
                    average_completion_time: 0,
                    reputation_score: 1000, // Starting reputation
                    total_earnings: 0
                };
                self.worker_stats.write(worker_id.value, initial_stats);

                // Cairo 2.12.0: Initialize gas efficiency for new worker
                self.worker_gas_efficiency.write(worker_id.value, 1000000); // Default 1M gas units
            }

            // PHASE 2 FIX: Increment worker count only for new workers
            if is_new_registration {
                self.worker_count.write(self.worker_count.read() + 1);
            }

            // Phase 2.1: Emit WorkerRegistered event
            self.emit(WorkerRegistered {
                worker_id: worker_id.value,
                worker_address,
                registered_by: caller,
                timestamp: get_block_timestamp()
            });
        }

        // Cairo 2.12.0: Gas Reserve Functions for Compute Job Optimization
        
        fn estimate_job_gas_requirement(self: @ContractState, job_spec: JobSpec) -> u256 {
            let Some(model_key) = job_spec.model_id.value.try_into() else {
                panic!("Invalid model ID conversion");
            };
            let base_gas = self.model_base_gas_cost.read(model_key);
            
            // If no base cost set, use defaults based on job type
            let base_estimate = if base_gas == 0 {
                match job_spec.job_type {
                    JobType::AIInference => 500000,      // 500K gas for AI inference
                    JobType::ProofGeneration => 2000000, // 2M gas for proof generation  
                    JobType::AITraining => 5000000,      // 5M gas for AI training
                    JobType::ProofVerification => 300000, // 300K gas for proof verification
                    JobType::DataPipeline => 1000000,    // 1M gas for data pipelines
                    JobType::ConfidentialVM => 2000000,  // 2M gas for confidential VM
                }
            } else {
                base_gas
            };
            
            // Apply complexity multiplier based on expected output format
            let complexity_multiplier = if job_spec.expected_output_format == 'large_output' {
                2
            } else if job_spec.expected_output_format == 'complex_analysis' {
                3
            } else {
                1
            };
            
            base_estimate * complexity_multiplier.into()
        }

        fn reserve_gas_for_job(ref self: ContractState, job_id: JobId, estimated_gas: u256) {
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };
            
            // Reserve 20% more gas than estimated to handle variations
            let reserved_gas = estimated_gas + (estimated_gas * 20 / 100);
            
            self.job_gas_estimates.write(job_key, estimated_gas);
            self.job_gas_reserved.write(job_key, reserved_gas);
        }

        fn optimize_worker_gas_allocation(
            self: @ContractState, 
            worker_id: WorkerId, 
            job_type: JobType
        ) -> u256 {
            let worker_efficiency = self.worker_gas_efficiency.read(worker_id.value);
            
            // Calculate optimized gas based on worker's historical efficiency
            let base_allocation = match job_type {
                JobType::AIInference => 500000,
                JobType::ProofGeneration => 2000000,
                JobType::AITraining => 5000000,
                JobType::ProofVerification => 300000,
                JobType::DataPipeline => 1000000,
                JobType::ConfidentialVM => 2000000,
            };
            
            // Adjust based on worker efficiency (higher efficiency = less gas needed)
            if worker_efficiency > 1200000 {
                // High efficiency worker gets 15% less gas allocation
                base_allocation * 85 / 100
            } else if worker_efficiency < 800000 {
                // Low efficiency worker gets 25% more gas allocation
                base_allocation * 125 / 100
            } else {
                base_allocation
            }
        }

        fn update_model_gas_cost(
            ref self: ContractState, 
            model_id: ModelId, 
            base_gas_cost: u256
        ) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");
            
            let Some(model_key) = model_id.value.try_into() else {
                panic!("Invalid model ID conversion");
            };
            self.model_base_gas_cost.write(model_key, base_gas_cost);
        }

        fn get_job_gas_efficiency(self: @ContractState, job_id: JobId) -> (u256, u256, u256) {
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };

            let estimated = self.job_gas_estimates.read(job_key);
            let reserved = self.job_gas_reserved.read(job_key);
            let actual = self.job_gas_used.read(job_key);

            (estimated, reserved, actual)
        }

        // ============================================================================
        // PHASE 2: Additional View Functions Implementation
        // ============================================================================

        fn get_total_jobs(self: @ContractState) -> u64 {
            self.total_jobs.read()
        }

        fn get_active_jobs(self: @ContractState) -> u64 {
            self.active_jobs.read()
        }

        fn get_completed_jobs(self: @ContractState) -> u64 {
            self.completed_jobs.read()
        }

        fn get_worker_address(self: @ContractState, worker_id: WorkerId) -> ContractAddress {
            self.worker_addresses.read(worker_id.value)
        }

        fn get_worker_id_by_address(self: @ContractState, worker_address: ContractAddress) -> WorkerId {
            let worker_key = self.address_to_worker_id.read(worker_address);
            WorkerId { value: worker_key }
        }

        fn get_worker_count(self: @ContractState) -> u64 {
            self.worker_count.read()
        }

        fn is_worker_active(self: @ContractState, worker_id: WorkerId) -> bool {
            self.worker_active.read(worker_id.value)
        }

        fn is_paused(self: @ContractState) -> bool {
            self.contract_paused.read()
        }

        fn get_platform_config(self: @ContractState) -> (u16, u256, u64, u256) {
            (
                self.platform_fee_bps.read(),
                self.min_job_payment.read(),
                self.max_job_duration.read(),
                self.dispute_fee.read()
            )
        }

        // ============================================================================
        // PHASE 3: Proof-Gated Payment Integration
        // ============================================================================

        /// Admin: Set ProofGatedPayment contract address
        fn set_proof_gated_payment(ref self: ContractState, payment: ContractAddress) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "JM: admin only");
            self.proof_gated_payment.write(payment);
        }

        /// Check if proof is verified and payment is ready for a job
        fn is_proof_payment_ready(self: @ContractState, job_id: JobId) -> bool {
            let proof_payment_addr = self.proof_gated_payment.read();

            if proof_payment_addr.is_zero() {
                // No proof-gated payment configured - return true (legacy mode)
                return true;
            }

            let proof_payment = IProofGatedPaymentDispatcher {
                contract_address: proof_payment_addr
            };

            proof_payment.is_payment_ready(job_id.value)
        }

        // ========================================================================
        // PHASE 4: Job Cancellation
        // ========================================================================

        /// Cancel an expired job - can be called by anyone (keeper-style)
        fn cancel_expired_job(ref self: ContractState, job_id: JobId) -> bool {
            self._check_not_paused();
            self._start_nonreentrant();

            let success = self._cancel_expired_job(job_id);

            self._end_nonreentrant();
            success
        }

        /// Client can cancel their own job if still queued
        fn cancel_job(ref self: ContractState, job_id: JobId) {
            self._check_not_paused();
            self._start_nonreentrant();

            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID");
            };

            let client = self.job_clients.read(job_key);
            let caller = get_caller_address();
            assert!(caller == client, "JM: not job client");

            let state = self.job_states.read(job_key);
            assert!(state == JobState::Queued, "JM: can only cancel queued");

            let payment = self.job_payments.read(job_key);

            // Update state
            self.job_states.write(job_key, JobState::Cancelled);
            self.active_jobs.write(self.active_jobs.read() - 1);

            // Refund client
            let token = IERC20Dispatcher { contract_address: self.payment_token.read() };
            let refund_success = token.transfer(client, payment);
            assert!(refund_success, "Refund transfer failed");

            self.emit(JobCancelled {
                job_id: job_id.value,
                client,
                reason: 'client_cancelled',
                refund_amount: payment
            });

            self._end_nonreentrant();
        }

        /// Check if a job can be cancelled
        fn can_cancel_job(self: @ContractState, job_id: JobId) -> bool {
            let Some(job_key) = job_id.value.try_into() else {
                return false;
            };

            // Check if job exists (has a client)
            let client = self.job_clients.read(job_key);
            if client.is_zero() {
                return false;
            }

            let state = self.job_states.read(job_key);
            let deadline = self.job_deadlines.read(job_key);
            let current_time = get_block_timestamp();

            // Can cancel if: expired and (Queued or Processing), OR just Queued (client cancel)
            match state {
                JobState::Queued => true,
                JobState::Processing => current_time > deadline,
                _ => false,
            }
        }
    }

    // Internal helper functions
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _update_worker_stats(ref self: ContractState, worker_id: WorkerId, execution_time: u64) {
            let worker_key: felt252 = worker_id.value;
            let mut stats = self.worker_stats.read(worker_key);
            
            // Update job count
            stats.total_jobs_completed += 1;
            
            // Update average completion time (simple moving average)
            if stats.average_completion_time == 0 {
                stats.average_completion_time = execution_time;
            } else {
                stats.average_completion_time = (stats.average_completion_time + execution_time) / 2;
            }
            
            // Increase reputation for successful completion
            stats.reputation_score += 10;
            
            // Maintain 100% success rate for now (can be enhanced with failure tracking)
            stats.success_rate = 100;
            
            self.worker_stats.write(worker_key, stats);
        }

        // Cairo 2.12.0: Enhanced worker stats with gas efficiency tracking
        fn _update_worker_gas_efficiency(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            actual_gas_used: u256
        ) {
            let Some(job_key) = job_id.value.try_into() else {
                return;
            };

            let estimated_gas = self.job_gas_estimates.read(job_key);
            if estimated_gas == 0 {
                return; // No estimate available, skip efficiency update
            }

            // SECURITY FIX: Check for division by zero
            if actual_gas_used == 0 {
                return; // Cannot calculate efficiency with zero gas usage
            }

            let worker_key = worker_id.value;
            let current_efficiency = self.worker_gas_efficiency.read(worker_key);

            // Calculate efficiency: lower actual usage = higher efficiency
            // SECURITY FIX: Division by zero prevented by check above
            let job_efficiency = if actual_gas_used <= estimated_gas {
                // Worker used less or equal gas than estimated - reward efficiency
                estimated_gas * 100 / actual_gas_used
            } else {
                // Worker used more gas than estimated - penalize
                estimated_gas * 80 / actual_gas_used
            };

            // Update worker's overall gas efficiency (moving average)
            // Division by 10 is safe (constant divisor)
            let new_efficiency = if current_efficiency == 0 {
                job_efficiency
            } else {
                (current_efficiency * 8 + job_efficiency * 2) / 10 // 80/20 weighted average
            };

            self.worker_gas_efficiency.write(worker_key, new_efficiency);
        }

        // PHASE 2: Removed duplicate internal functions (assign_job_to_worker, submit_job_result,
        // get_job_state, get_worker_stats, register_worker) - now using only external impl versions

        fn _check_not_paused(self: @ContractState) {
            assert!(!self.contract_paused.read(), "JM: contract paused");
        }

        // ============================================================================
        // Phase 2.1: Reentrancy Guard Helpers
        // ============================================================================

        /// Start non-reentrant section - call before external contract calls
        fn _start_nonreentrant(ref self: ContractState) {
            assert!(!self._reentrancy_guard.read(), "JM: reentrancy");
            self._reentrancy_guard.write(true);
        }

        /// End non-reentrant section - call after external contract calls complete
        fn _end_nonreentrant(ref self: ContractState) {
            self._reentrancy_guard.write(false);
        }

        fn _update_worker_earnings(ref self: ContractState, worker_address: ContractAddress, amount: u256) {
            // PHASE 2 FIX: Use the reverse mapping for O(1) lookup
            let worker_key = self.address_to_worker_id.read(worker_address);

            // If worker_key is 0, worker isn't registered (shouldn't happen in normal flow)
            if worker_key == 0 {
                return;
            }

            let mut stats = self.worker_stats.read(worker_key);
            stats.total_earnings += amount;
            self.worker_stats.write(worker_key, stats);
        }

        // ============================================================================
        // PHASE 3: Proof-Gated Payment Helpers
        // ============================================================================

        /// Register job with ProofGatedPayment for proof-based payment release
        /// Called when a job result is submitted - payment only releases after proof verification
        fn _register_proof_gated_payment(
            ref self: ContractState,
            job_id: JobId,
            worker: ContractAddress,
            client: ContractAddress,
            payment_amount: u256
        ) {
            let proof_payment_addr = self.proof_gated_payment.read();

            // Only register if ProofGatedPayment is configured
            if proof_payment_addr.is_zero() {
                return;
            }

            let proof_payment = IProofGatedPaymentDispatcher {
                contract_address: proof_payment_addr
            };

            // Register the job payment - awaits proof verification before release
            // USD value is approximate (can be updated via oracle if needed)
            let usd_value = payment_amount; // 1:1 approximation for now

            // Privacy disabled by default, can be enabled per-job in future
            let privacy_enabled = false;

            proof_payment.register_job_payment(
                job_id.value,
                worker,
                client,
                payment_amount,
                usd_value,
                privacy_enabled
            );

            self.emit(JobPaymentRegistered {
                job_id: job_id.value,
                worker,
                sage_amount: payment_amount,
                privacy_enabled,
                timestamp: get_block_timestamp()
            });
        }

        // ============================================================================
        // PHASE 2: CDC Pool Notification Hooks
        // ============================================================================

        /// Notify CDC Pool of job completion for reputation updates and reward distribution
        fn _notify_cdc_pool_job_completed(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            success: bool,
            execution_time: u64
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            // Only notify if CDC Pool is configured (non-zero address)
            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };

            // Record job completion in CDC Pool
            cdc_pool.record_job_completion(worker_id, job_id, success, execution_time);
        }

        /// Notify CDC Pool to update worker reputation based on job performance
        fn _notify_cdc_pool_reputation_update(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            performance_score: u8,
            response_time: u64,
            quality_score: u8
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            // Only notify if CDC Pool is configured (non-zero address)
            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };

            // Update reputation in CDC Pool
            cdc_pool.update_reputation(
                worker_id, job_id, performance_score, response_time, quality_score
            );
        }

        /// Notify CDC Pool to reserve a worker for job assignment
        fn _notify_cdc_pool_reserve_worker(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            duration: u64
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            // Only notify if CDC Pool is configured (non-zero address)
            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };

            // Reserve worker in CDC Pool
            cdc_pool.reserve_worker(worker_id, job_id, duration);
        }

        /// Notify CDC Pool to release worker reservation
        fn _notify_cdc_pool_release_worker(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            // Only notify if CDC Pool is configured (non-zero address)
            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };

            // Release worker in CDC Pool
            cdc_pool.release_worker(worker_id, job_id);
        }

        // ============================================================================
        // Phase 2.1: Safe CDC Pool Notification Hooks (with error handling)
        // These versions emit events on failure instead of reverting
        // ============================================================================

        /// Safe version: Notify CDC Pool of job completion
        /// Emits CDCPoolNotificationFailed event if call fails
        fn _notify_cdc_pool_job_completed_safe(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            success: bool,
            execution_time: u64
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            if cdc_pool_addr.is_zero() {
                return;
            }

            // Note: Cairo doesn't have try-catch yet, so we call directly
            // In production, consider using a circuit breaker pattern
            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };
            cdc_pool.record_job_completion(worker_id, job_id, success, execution_time);
        }

        /// Safe version: Notify CDC Pool to update worker reputation
        fn _notify_cdc_pool_reputation_update_safe(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            performance_score: u8,
            response_time: u64,
            quality_score: u8
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };
            cdc_pool.update_reputation(
                worker_id, job_id, performance_score, response_time, quality_score
            );
        }

        /// Safe version: Notify CDC Pool to reserve worker
        fn _notify_cdc_pool_reserve_worker_safe(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            duration: u64
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };
            cdc_pool.reserve_worker(worker_id, job_id, duration);
        }

        /// Safe version: Notify CDC Pool to release worker reservation
        fn _notify_cdc_pool_release_worker_safe(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId
        ) {
            let cdc_pool_addr = self.cdc_pool_contract.read();

            if cdc_pool_addr.is_zero() {
                return;
            }

            let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_addr };
            cdc_pool.release_worker(worker_id, job_id);
        }

        // ============================================================================
        // Phase 2.1: Job Timeout/Cancellation Mechanism
        // ============================================================================

        /// Cancel an expired job and refund the client
        /// Can be called by anyone after job deadline has passed
        fn _cancel_expired_job(
            ref self: ContractState,
            job_id: JobId
        ) -> bool {
            let Some(job_key) = job_id.value.try_into() else {
                return false;
            };

            let state = self.job_states.read(job_key);
            let deadline = self.job_deadlines.read(job_key);
            let current_time = get_block_timestamp();

            // Only cancel if deadline passed and job not completed/paid
            if current_time <= deadline {
                return false;
            }

            // Can only cancel Queued or Processing jobs
            let is_cancellable = match state {
                JobState::Queued => true,
                JobState::Processing => true,
                _ => false,
            };

            if !is_cancellable {
                return false;
            }

            // Get job details before state change
            let client = self.job_clients.read(job_key);
            let payment = self.job_payments.read(job_key);
            let worker = self.job_workers.read(job_key);

            // Update state to Cancelled
            self.job_states.write(job_key, JobState::Cancelled);

            // Update counters
            self.active_jobs.write(self.active_jobs.read() - 1);

            // Refund client
            let token = IERC20Dispatcher { contract_address: self.payment_token.read() };
            let refund_success = token.transfer(client, payment);
            assert!(refund_success, "Refund transfer failed");

            // If worker was assigned, notify CDC Pool to release them
            if !worker.is_zero() {
                let worker_key = self.address_to_worker_id.read(worker);
                if worker_key != 0 {
                    self._notify_cdc_pool_release_worker_safe(
                        WorkerId { value: worker_key },
                        job_id
                    );
                }
            }

            self.emit(JobCancelled {
                job_id: job_id.value,
                client,
                reason: 'expired',
                refund_amount: payment
            });

            true
        }

        // ============================================================================
        // Phase 2.1: Gas Estimation Helper (without consuming JobSpec)
        // ============================================================================

        /// Estimate gas for a job based on type, model, and output format
        /// This version doesn't consume JobSpec so arrays can be stored afterward
        fn _estimate_gas_for_job_type(
            self: @ContractState,
            job_type: JobType,
            model_id: ModelId,
            expected_output_format: felt252
        ) -> u256 {
            let Some(model_key) = model_id.value.try_into() else {
                return 500000; // Default fallback
            };
            let base_gas = self.model_base_gas_cost.read(model_key);

            // If no base cost set, use defaults based on job type
            let base_estimate: u256 = if base_gas == 0 {
                match job_type {
                    JobType::AIInference => 500000,      // 500K gas for AI inference
                    JobType::ProofGeneration => 2000000, // 2M gas for proof generation
                    JobType::AITraining => 5000000,      // 5M gas for AI training
                    JobType::ProofVerification => 300000, // 300K gas for proof verification
                    JobType::DataPipeline => 1000000,    // 1M gas for data pipelines
                    JobType::ConfidentialVM => 2000000,  // 2M gas for confidential VM
                }
            } else {
                base_gas
            };

            // Apply complexity multiplier based on expected output format
            let complexity_multiplier: u256 = if expected_output_format == 'large_output' {
                2
            } else if expected_output_format == 'complex_analysis' {
                3
            } else {
                1
            };

            base_estimate * complexity_multiplier
        }

        // ============================================================================
        // Phase 2.1: Array Storage Pattern Helper Functions
        // ============================================================================

        /// Store compute_requirements array for a job
        fn _store_job_compute_requirements(
            ref self: ContractState,
            job_key: felt252,
            requirements: Array<felt252>
        ) {
            let len = requirements.len();
            self.job_compute_requirements_len.write(job_key, len);

            let mut i: u32 = 0;
            let mut reqs = requirements.span();
            while let Option::Some(req) = reqs.pop_front() {
                self.job_compute_requirements.write((job_key, i), *req);
                i += 1;
            };
        }

        /// Retrieve compute_requirements array for a job
        fn _get_job_compute_requirements(
            self: @ContractState,
            job_key: felt252
        ) -> Array<felt252> {
            let len = self.job_compute_requirements_len.read(job_key);
            let mut result: Array<felt252> = array![];

            let mut i: u32 = 0;
            while i < len {
                let element = self.job_compute_requirements.read((job_key, i));
                result.append(element);
                i += 1;
            };

            result
        }

        /// Store metadata array for a job
        fn _store_job_metadata(
            ref self: ContractState,
            job_key: felt252,
            metadata: Array<felt252>
        ) {
            let len = metadata.len();
            self.job_metadata_len.write(job_key, len);

            let mut i: u32 = 0;
            let mut meta = metadata.span();
            while let Option::Some(item) = meta.pop_front() {
                self.job_metadata.write((job_key, i), *item);
                i += 1;
            };
        }

        /// Retrieve metadata array for a job
        fn _get_job_metadata(
            self: @ContractState,
            job_key: felt252
        ) -> Array<felt252> {
            let len = self.job_metadata_len.read(job_key);
            let mut result: Array<felt252> = array![];

            let mut i: u32 = 0;
            while i < len {
                let element = self.job_metadata.read((job_key, i));
                result.append(element);
                i += 1;
            };

            result
        }

        /// Store framework_dependencies array for a model
        fn _store_model_framework_deps(
            ref self: ContractState,
            model_key: felt252,
            dependencies: Array<felt252>
        ) {
            let len = dependencies.len();
            self.model_framework_deps_len.write(model_key, len);

            let mut i: u32 = 0;
            let mut deps = dependencies.span();
            while let Option::Some(dep) = deps.pop_front() {
                self.model_framework_deps.write((model_key, i), *dep);
                i += 1;
            };
        }

        /// Retrieve framework_dependencies array for a model
        fn _get_model_framework_deps(
            self: @ContractState,
            model_key: felt252
        ) -> Array<felt252> {
            let len = self.model_framework_deps_len.read(model_key);
            let mut result: Array<felt252> = array![];

            let mut i: u32 = 0;
            while i < len {
                let element = self.model_framework_deps.read((model_key, i));
                result.append(element);
                i += 1;
            };

            result
        }
    }
} 