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

#[starknet::contract]
mod JobManager {
    use super::{
        IJobManager, JobId, ModelId, WorkerId, JobType, JobSpec, JobResult, 
        VerificationMethod, ModelRequirements, JobState, JobDetails, WorkerStats,
        ProveJobData, ContractAddress, get_caller_address, get_block_timestamp,
        StoragePointerReadAccess, StoragePointerWriteAccess, 
        StorageMapReadAccess, StorageMapWriteAccess, Map,
        IERC20Dispatcher, IERC20DispatcherTrait, Zero
    };

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        // Custom contract events
        JobSubmitted: JobSubmitted,
        JobAssigned: JobAssigned,
        JobCompleted: JobCompleted,
        PaymentReleased: PaymentReleased,
        ModelRegistered: ModelRegistered
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
        // Note: compute_requirements and metadata arrays would need special handling
        
        job_clients: Map<felt252, ContractAddress>,
        job_workers: Map<felt252, ContractAddress>,
        job_states: Map<felt252, JobState>,
        job_payments: Map<felt252, u256>,
        job_timestamps: Map<felt252, (u64, u64, u64)>, // (created, assigned, completed)
        
        // Model management - store ModelRequirements fields separately  
        model_min_memory: Map<felt252, u32>,
        model_min_compute: Map<felt252, u32>,
        model_gpu_types: Map<felt252, felt252>,
        // Note: framework_dependencies array would need special handling
        
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
        
        // Simple admin control
        admin: ContractAddress,
        contract_paused: bool,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        payment_token: ContractAddress,
        treasury: ContractAddress,
        cdc_pool_contract: ContractAddress
    ) {
        self.admin.write(admin);
        
        self.payment_token.write(payment_token);
        self.treasury.write(treasury);
        self.cdc_pool_contract.write(cdc_pool_contract);
        
        // Set default configuration
        self.platform_fee_bps.write(250); // 2.5%
        self.min_job_payment.write(1000000000000000000); // 1 SAGE token
        self.max_job_duration.write(86400); // 24 hours
        self.dispute_fee.write(10000000000000000000); // 10 SAGE tokens
        self.min_allocation_score.write(100);
        
        self.next_job_id.write(1);
        self.next_model_id.write(1);
        self.contract_paused.write(false);
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
            
            // Validate inputs
            let current_time = starknet::get_block_timestamp();
            assert!(payment >= self.min_job_payment.read(), "Payment too low");
            assert!(job_spec.sla_deadline > current_time, "Invalid deadline");
            assert!(job_spec.max_reward > 0, "Invalid max reward");
            
            // Generate new job ID
            let job_id = JobId { value: self.next_job_id.read() };
            self.next_job_id.write(self.next_job_id.read() + 1);
            
            // Cairo 2.12.0: Using let-else pattern for cleaner error handling
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };
            
                    // Store job information
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
        
                    // Initialize job state as Queued
            self.job_states.write(job_key, JobState::Queued);
            
            // Cairo 2.12.0: Estimate and reserve gas for job execution
            let estimated_gas = self.estimate_job_gas_requirement(job_spec);
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
                sla_deadline: get_block_timestamp() + 3600, // 1 hour deadline
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
            assert!(caller == self.admin.read(), "Not authorized");
            
            // Cairo 2.12.0: Combined let-else for type conversion and state validation
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID conversion");
            };
            
            let current_state = self.job_states.read(job_key);
            let JobState::Queued = current_state else {
                panic!("Job not available for assignment");
            };
            
            // Update job state to Processing
            self.job_states.write(job_key, JobState::Processing);
            let (created_at, _, completed_at) = self.job_timestamps.read(job_key);
            self.job_timestamps.write(job_key, (created_at, get_block_timestamp(), completed_at));
            
            // Cairo 2.12.0: Using let-else for worker validation
            let worker_address = self.worker_addresses.read(worker_id.value);
            let true = !worker_address.is_zero() else {
                panic!("Worker not registered");
            };
            self.job_workers.write(job_key, worker_address);
            
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
            
            // Calculate platform fee
            let platform_fee = (payment_amount * self.platform_fee_bps.read().into()) / 10000;
            let worker_payment = payment_amount - platform_fee;
            
            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.payment_token.read() };
            token.transfer(worker_address, worker_payment);
            if platform_fee > 0 {
                token.transfer(self.treasury.read(), platform_fee);
            }
            
            // Update worker earnings - need to find worker_id from address
            self._update_worker_earnings(worker_address, worker_payment);
            
            self.emit(PaymentReleased {
                job_id: job_id.value,
                worker: worker_address,
                amount: worker_payment
            });
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
            // Note: framework_dependencies array would need special handling
            
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
            let _job_model_id = self.job_model_ids.read(job_key);
            let _job_input_hash = self.job_input_hashes.read(job_key);
            let _job_output_format = self.job_output_formats.read(job_key);
            let _job_verification_method = self.job_verification_methods.read(job_key);
            let _job_max_reward = self.job_max_rewards.read(job_key);
            let _job_deadline = self.job_deadlines.read(job_key);
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
                    average_completion_time: 3600, // Default 1 hour
                    reputation_score: 1000, // Default reputation
                    total_earnings: 0
                }
            } else {
                stats
            }
        }

        fn update_config(ref self: ContractState, config_key: felt252, config_value: felt252) {
            assert!(get_caller_address() == self.admin.read(), "Not authorized");
            
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
        }

        fn pause(ref self: ContractState) {
            assert!(get_caller_address() == self.admin.read(), "Not authorized");
            self.contract_paused.write(true);
        }

        fn unpause(ref self: ContractState) {
            assert!(get_caller_address() == self.admin.read(), "Not authorized");
            self.contract_paused.write(false);
        }

        fn emergency_withdraw(ref self: ContractState, token: ContractAddress, amount: u256) {
            assert!(get_caller_address() == self.admin.read(), "Not authorized");
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer(self.treasury.read(), amount);
        }

        fn register_worker(ref self: ContractState, worker_id: WorkerId, worker_address: ContractAddress) {
            // Allow workers to register themselves or admin to register workers
            let caller = get_caller_address();
            assert!(caller == self.admin.read() || caller == worker_address, "Not authorized");
            
            // Store worker address mapping
            self.worker_addresses.write(worker_id.value, worker_address);
            self.worker_active.write(worker_id.value, true);
            
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
            assert!(caller == self.admin.read(), "Not authorized");
            
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
            
            let worker_key = worker_id.value;
            let current_efficiency = self.worker_gas_efficiency.read(worker_key);
            
            // Calculate efficiency: lower actual usage = higher efficiency
            let job_efficiency = if actual_gas_used <= estimated_gas {
                // Worker used less or equal gas than estimated - reward efficiency
                estimated_gas * 100 / actual_gas_used
            } else {
                // Worker used more gas than estimated - penalize
                estimated_gas * 80 / actual_gas_used
            };
            
            // Update worker's overall gas efficiency (moving average)
            let new_efficiency = if current_efficiency == 0 {
                job_efficiency
            } else {
                (current_efficiency * 8 + job_efficiency * 2) / 10 // 80/20 weighted average
            };
            
            self.worker_gas_efficiency.write(worker_key, new_efficiency);
        }
        
        /// Assign a job to a specific worker
        fn assign_job_to_worker(
            ref self: ContractState,
            job_id: JobId,
            worker_id: WorkerId,
            worker_address: ContractAddress
        ) {
            self._check_not_paused();
            
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID");
            };
            
            // Verify job is in Queued state
            let current_state = self.job_states.read(job_key);
            assert!(current_state == JobState::Queued, "Job not available for assignment");
            
            // Update job assignment
            self.job_workers.write(job_key, worker_address);
            self.job_states.write(job_key, JobState::Processing);
            
            // Update timestamps
            let (created, _, completed) = self.job_timestamps.read(job_key);
            self.job_timestamps.write(job_key, (created, get_block_timestamp(), completed));
            
            // Emit event
            self.emit(JobAssigned {
                job_id: job_id.value,
                worker: worker_address
            });
        }

        /// Submit job result from worker
        fn submit_job_result(
            ref self: ContractState,
            job_id: JobId,
            result: JobResult
        ) {
            self._check_not_paused();
            
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID");
            };
            
            // Verify job is in Processing state
            let current_state = self.job_states.read(job_key);
            assert!(current_state == JobState::Processing, "Job not in processing state");
            
            // Verify caller is the assigned worker
            let assigned_worker = self.job_workers.read(job_key);
            assert!(get_caller_address() == assigned_worker, "Only assigned worker can submit result");
            
            // Store result
            self.job_results.write(job_key, result.output_data_hash);
            self.job_states.write(job_key, JobState::Completed);
            
            // Update timestamps
            let (created, assigned, _) = self.job_timestamps.read(job_key);
            self.job_timestamps.write(job_key, (created, assigned, get_block_timestamp()));
            
            // Update counters
            self.active_jobs.write(self.active_jobs.read() - 1);
            self.completed_jobs.write(self.completed_jobs.read() + 1);
            
            // Update worker stats
            let Some(worker_key) = result.worker_id.value.try_into() else {
                panic!("Invalid worker ID");
            };
            
            let mut stats = self.worker_stats.read(worker_key);
            stats.total_jobs_completed += 1;
            
            // Calculate execution time
            let execution_time = get_block_timestamp() - assigned;
            let new_avg = if stats.total_jobs_completed == 1 {
                execution_time
            } else {
                (stats.average_completion_time * (stats.total_jobs_completed - 1) + execution_time) / stats.total_jobs_completed
            };
            stats.average_completion_time = new_avg;
            
            // Update success rate (simplified - assuming all completed jobs are successful for now)
            stats.success_rate = 100; // Will be refined with dispute system
            
            self.worker_stats.write(worker_key, stats);
            
            // Emit event
            self.emit(JobCompleted {
                job_id: job_id.value,
                worker: assigned_worker
            });
        }

        /// Get job state
        fn get_job_state(self: @ContractState, job_id: JobId) -> JobState {
            let Some(job_key) = job_id.value.try_into() else {
                panic!("Invalid job ID");
            };
            self.job_states.read(job_key)
        }

        /// Get worker statistics
        fn get_worker_stats(self: @ContractState, worker_id: WorkerId) -> WorkerStats {
            let Some(worker_key) = worker_id.value.try_into() else {
                panic!("Invalid worker ID");
            };
            self.worker_stats.read(worker_key)
        }

        /// Register a new worker
        fn register_worker(
            ref self: ContractState,
            worker_id: WorkerId,
            worker_address: ContractAddress
        ) {
            self._check_not_paused();
            
            let Some(worker_key) = worker_id.value.try_into() else {
                panic!("Invalid worker ID");
            };
            
            // Initialize worker stats
            let stats = WorkerStats {
                total_jobs_completed: 0,
                success_rate: 100, // Start with perfect score
                average_completion_time: 0,
                reputation_score: 100, // Starting reputation
                total_earnings: 0
            };
            
            self.worker_stats.write(worker_key, stats);
            self.worker_addresses.write(worker_key, worker_address);
            
            // Optionally emit an event for worker registration
            // (You'd need to add WorkerRegistered to the Event enum)
        }

        fn _check_not_paused(self: @ContractState) {
            assert!(!self.contract_paused.read(), "Contract is paused");
        }
        
        fn _update_worker_earnings(ref self: ContractState, worker_address: ContractAddress, amount: u256) {
            // This is a simplified approach - in a full implementation, you'd want a reverse lookup
            // For now, we'll need to track worker_id -> address mapping more efficiently
            // This is a placeholder that demonstrates the concept
            let mut found = false;
            let mut worker_key: felt252 = 0;
            
            // In a real implementation, you'd maintain a reverse mapping or emit events to track this
            // For now, we'll just update the first worker we find with this address (not ideal)
            // A better approach would be to pass worker_id to distribute_rewards function
            
            if found {
                let mut stats = self.worker_stats.read(worker_key);
                stats.total_earnings += amount;
                self.worker_stats.write(worker_key, stats);
            }
        }
    }
} 