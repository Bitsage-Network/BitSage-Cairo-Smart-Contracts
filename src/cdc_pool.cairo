// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 CIRO Network Foundation
//
// This file is part of CIRO Network.
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//     https://github.com/Ciro-AI-Labs/ciro-network/blob/main/LICENSE-BSL
//
// Change Date: January 1, 2029
// Change License: Apache License, Version 2.0
//
// For more information see: https://github.com/Ciro-AI-Labs/ciro-network/blob/main/WHY_BSL_FOR_CIRO.md

//! CIRO Distributed Compute (CDC) Pool Contract
//! 
//! Manages worker registration, staking, reputation, and job allocation
//! for the CIRO Network compute infrastructure.

use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
use starknet::storage::{
    StoragePointerReadAccess, StoragePointerWriteAccess, 
    StorageMapReadAccess, StorageMapWriteAccess, Map
};

// Cairo 2.12.0 Optimization Features
// Using improved storage patterns and validation functions

// Interface imports
use ciro_contracts::interfaces::cdc_pool::{
    ICDCPool, WorkerCapabilities, WorkerProfile, WorkerStatus, PerformanceMetrics,
    StakeInfo, UnstakeRequest, AllocationResult, SlashRecord, SlashReason, WorkerTier,
    WorkerTierBenefits, HolderTier, WorkerRegistered, WorkerDeactivated, WorkerReactivated,
    StakeAdded, UnstakeRequested, UnstakeExecuted, JobAllocated, WorkerReserved, WorkerReleased
};
use ciro_contracts::interfaces::job_manager::{JobId, ModelRequirements, WorkerId};

// Token interface for CIRO token operations
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

#[starknet::contract]
mod CDCPool {
    use super::{
        ICDCPool, WorkerCapabilities, WorkerProfile, WorkerStatus, PerformanceMetrics,
        StakeInfo, UnstakeRequest, AllocationResult, SlashRecord, SlashReason, WorkerTier,
        WorkerTierBenefits, HolderTier, ContractAddress, get_caller_address, get_block_timestamp,
        StoragePointerReadAccess, StoragePointerWriteAccess, 
        StorageMapReadAccess, StorageMapWriteAccess, Map,
        JobId, ModelRequirements, WorkerId, IERC20Dispatcher, IERC20DispatcherTrait,
        WorkerRegistered, WorkerDeactivated, WorkerReactivated, StakeAdded, UnstakeRequested,
        UnstakeExecuted, JobAllocated, WorkerReserved, WorkerReleased
    };

    // Helper constants
    const ZERO_ADDRESS: felt252 = 0;

    #[storage]
    struct Storage {
        // Core contract state
        admin: ContractAddress,
        ciro_token: ContractAddress,
        paused: bool,
        
        // Worker management
        next_worker_id: felt252,
        total_workers: u32,
        active_workers: u32,
        
        // Worker data storage - using felt252 keys for all maps
        worker_profiles: Map<felt252, WorkerProfile>,
        worker_owners: Map<felt252, ContractAddress>,
        owner_to_worker: Map<ContractAddress, felt252>,
        worker_capabilities: Map<felt252, WorkerCapabilities>,
        worker_status: Map<felt252, WorkerStatus>,
        worker_performance: Map<felt252, PerformanceMetrics>,
        
        // Staking data
        stakes: Map<ContractAddress, StakeInfo>,
        unstake_requests: Map<felt252, UnstakeRequest>, // Using counter as key
        next_unstake_id: felt252,
        total_staked: u256,
        min_stake: u256,
        
        // Reputation and performance tracking
        worker_reputation: Map<felt252, u64>,
        worker_jobs_completed: Map<felt252, u32>,
        worker_jobs_failed: Map<felt252, u32>,
        worker_total_earnings: Map<felt252, u256>,
        
        // Job allocation
        reserved_workers: Map<(felt252, felt252), u64>, // (worker_id, job_id) -> end_time
        job_allocations: Map<felt252, felt252>, // job_id -> worker_id
        
        // Slash records
        slash_records: Map<felt252, SlashRecord>,
        next_slash_id: felt252,
        slash_percentages: Map<u8, u8>, // reason -> percentage
        
        // Rewards
        pending_rewards: Map<felt252, u256>,
        base_reward_rate: u256,
        performance_multiplier: u8,
        
        // Tier system
        ciro_price_usd_cents: u256, // CIRO price in USD cents
        tier_usd_requirements: Map<u8, u256>, // tier -> USD requirement in cents
        tier_allocation_bonuses: Map<u8, u256>, // tier -> allocation priority bonus
        
        // Network stats
        total_jobs_processed: u32,
        last_heartbeat: Map<felt252, u64>, // worker_id -> timestamp
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        WorkerRegistered: WorkerRegistered,
        WorkerDeactivated: WorkerDeactivated,
        WorkerReactivated: WorkerReactivated,
        StakeAdded: StakeAdded,
        UnstakeRequested: UnstakeRequested,
        UnstakeExecuted: UnstakeExecuted,
        JobAllocated: JobAllocated,
        WorkerReserved: WorkerReserved,
        WorkerReleased: WorkerReleased,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        ciro_token: ContractAddress,
        min_stake: u256
    ) {
        self.admin.write(admin);
        self.ciro_token.write(ciro_token);
        self.min_stake.write(min_stake);
        self.next_worker_id.write(1);
        self.next_unstake_id.write(1);
        self.next_slash_id.write(1);
        self.base_reward_rate.write(1000000000000000000); // 1 CIRO base rate
        self.performance_multiplier.write(50); // 50% bonus
        self.ciro_price_usd_cents.write(100); // $1.00 initial price
        
        // Initialize tier requirements (in USD cents)
        self.tier_usd_requirements.write(0, 10000); // Basic: $100
        self.tier_usd_requirements.write(1, 50000); // Premium: $500
        self.tier_usd_requirements.write(2, 250000); // Enterprise: $2,500
        self.tier_usd_requirements.write(3, 1000000); // Infrastructure: $10,000
        self.tier_usd_requirements.write(4, 5000000); // Fleet: $50,000
        self.tier_usd_requirements.write(5, 10000000); // Datacenter: $100,000
        self.tier_usd_requirements.write(6, 25000000); // Hyperscale: $250,000
        self.tier_usd_requirements.write(7, 50000000); // Institutional: $500,000
        
        // Initialize slash percentages
        self.slash_percentages.write(0, 50); // Malicious: 50%
        self.slash_percentages.write(1, 10); // Unavailable: 10%
        self.slash_percentages.write(2, 20); // Poor Performance: 20%
        self.slash_percentages.write(3, 30); // Protocol Violation: 30%
        self.slash_percentages.write(4, 100); // Fraud: 100%
    }

    #[abi(embed_v0)]
    impl CDCPoolImpl of ICDCPool<ContractState> {
        
        // Worker Registration Functions
        
        fn register_worker(
            ref self: ContractState,
            capabilities: WorkerCapabilities,
            proof_of_resources: Array<felt252>,
            location_hash: felt252
        ) -> WorkerId {
            // Cairo 2.12.0: Improved error diagnostics for validation
            assert!(!self.paused.read(), "Contract is paused");
            let caller = get_caller_address();
            
            // Check if worker already exists
            let existing_worker = self.owner_to_worker.read(caller);
            assert!(existing_worker == 0, "Worker already registered");
            
            // Generate new worker ID
            let worker_id_felt = self.next_worker_id.read();
            let worker_id = WorkerId { value: worker_id_felt };
            self.next_worker_id.write(worker_id_felt + 1);
            
            // Create worker profile
            let profile = WorkerProfile {
                worker_id,
                owner: caller,
                capabilities,
                status: WorkerStatus::Active,
                registered_at: get_block_timestamp(),
                last_heartbeat: get_block_timestamp(),
                stake_amount: 0,
                reputation_score: 500, // Start with middle reputation
                jobs_completed: 0,
                jobs_failed: 0,
                total_earnings: 0,
                location_hash,
            };
            
            // Store worker data
            self.worker_profiles.write(worker_id_felt, profile);
            self.worker_owners.write(worker_id_felt, caller);
            self.owner_to_worker.write(caller, worker_id_felt);
            self.worker_capabilities.write(worker_id_felt, capabilities);
            self.worker_status.write(worker_id_felt, WorkerStatus::Active);
            self.worker_reputation.write(worker_id_felt, 500);
            
            // Update counters
            self.total_workers.write(self.total_workers.read() + 1);
            self.active_workers.write(self.active_workers.read() + 1);
            
            // Emit event
            self.emit(Event::WorkerRegistered(WorkerRegistered {
                worker_id,
                owner: caller,
                capabilities,
                stake_amount: 0,
            }));
            
            worker_id
        }

        fn update_worker_capabilities(
            ref self: ContractState,
            worker_id: WorkerId,
            new_capabilities: WorkerCapabilities,
            proof_of_resources: Array<felt252>
        ) {
            let caller = get_caller_address();
            let worker_key = worker_id.value;
            // Cairo 2.12.0: More descriptive error messages
            let owner = self.worker_owners.read(worker_key);
            assert!(owner == caller, "Not worker owner");
            
            self.worker_capabilities.write(worker_key, new_capabilities);
            
            // Update profile capabilities
            let mut profile = self.worker_profiles.read(worker_key);
            profile.capabilities = new_capabilities;
            self.worker_profiles.write(worker_key, profile);
        }

        fn deactivate_worker(ref self: ContractState, worker_id: WorkerId, reason: felt252) {
            let caller = get_caller_address();
            let worker_key = worker_id.value;
            // Cairo 2.12.0: Enhanced validation with better error context
            let owner = self.worker_owners.read(worker_key);
            assert!(owner == caller, "Not worker owner");
            
            let current_status = self.worker_status.read(worker_key);
            if current_status == WorkerStatus::Active {
                self.active_workers.write(self.active_workers.read() - 1);
            }
            
            self.worker_status.write(worker_key, WorkerStatus::Inactive);
            
            self.emit(Event::WorkerDeactivated(WorkerDeactivated {
                worker_id,
                reason,
            }));
        }

        fn reactivate_worker(ref self: ContractState, worker_id: WorkerId) {
            let caller = get_caller_address();
            let worker_key = worker_id.value;
            let owner = self.worker_owners.read(worker_key);
            assert!(owner == caller, "Not worker owner");
            
            let current_status = self.worker_status.read(worker_key);
            assert!(current_status == WorkerStatus::Inactive, "Worker not inactive");
            
            self.worker_status.write(worker_key, WorkerStatus::Active);
            self.active_workers.write(self.active_workers.read() + 1);
            
            self.emit(Event::WorkerReactivated(WorkerReactivated {
                worker_id,
            }));
        }

        fn submit_heartbeat(
            ref self: ContractState,
            worker_id: WorkerId,
            performance_data: PerformanceMetrics
        ) {
            let caller = get_caller_address();
            let worker_key = worker_id.value;
            let owner = self.worker_owners.read(worker_key);
            assert!(owner == caller, "Not worker owner");
            
            self.last_heartbeat.write(worker_key, get_block_timestamp());
            self.worker_performance.write(worker_key, performance_data);
        }

        // Staking Functions

        fn stake(ref self: ContractState, amount: u256, lock_period: u64) {
            assert!(!self.paused.read(), "Contract is paused");
            assert!(amount >= self.min_stake.read(), "Amount below minimum stake");
            
            let caller = get_caller_address();
            let ciro_token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            
            // Transfer tokens from caller
            ciro_token.transfer_from(caller, starknet::get_contract_address(), amount);
            
            // Update stake info
            let mut stake_info = self.stakes.read(caller);
            stake_info.amount += amount;
            stake_info.locked_until = get_block_timestamp() + lock_period;
            stake_info.last_adjustment = get_block_timestamp();
            self.stakes.write(caller, stake_info);
            
            self.total_staked.write(self.total_staked.read() + amount);
            
            self.emit(Event::StakeAdded(StakeAdded {
                worker: caller,
                amount,
                total_stake: stake_info.amount,
            }));
        }

        fn request_unstake(ref self: ContractState, amount: u256) -> u64 {
            let caller = get_caller_address();
            let stake_info = self.stakes.read(caller);
            // Cairo 2.12.0: Better stake validation with clear error messages
            assert!(stake_info.amount >= amount, "Insufficient stake");
            
            let unlock_time = get_block_timestamp() + 604800; // 7 days
            let unstake_id = self.next_unstake_id.read();
            
            let request = UnstakeRequest {
                worker: caller,
                amount,
                unlock_time,
                is_complete_exit: stake_info.amount == amount,
            };
            
            self.unstake_requests.write(unstake_id, request);
            self.next_unstake_id.write(unstake_id + 1);
            
            self.emit(Event::UnstakeRequested(UnstakeRequested {
                worker: caller,
                amount,
                unlock_time,
            }));
            
            unlock_time
        }

        fn execute_unstake(ref self: ContractState, worker: ContractAddress) {
            // Implementation for executing unstake for a specific worker
            // For now, just call complete_unstake logic
            self.complete_unstake();
        }

        fn complete_unstake(ref self: ContractState) {
            let caller = get_caller_address();
            // Find and process unstake request for caller
            // Simplified implementation - in reality would need to track individual requests
            let stake_info = self.stakes.read(caller);
            
            if stake_info.locked_until <= get_block_timestamp() {
                let ciro_token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
                ciro_token.transfer(caller, stake_info.amount);
                
                let empty_stake = StakeInfo {
                    amount: 0,
                    usd_value: 0,
                    tier: WorkerTier::Basic,
                    locked_until: 0,
                    last_adjustment: 0,
                    last_reward_block: 0,
                    delegated_amount: 0,
                    performance_score: 0,
                };
                self.stakes.write(caller, empty_stake);
                
                self.emit(Event::UnstakeExecuted(UnstakeExecuted {
                    worker: caller,
                    amount: stake_info.amount,
                }));
            }
        }

        fn increase_stake(ref self: ContractState, additional_amount: u256) {
            self.stake(additional_amount, 0);
        }

        fn delegate_stake(ref self: ContractState, worker: ContractAddress, amount: u256) {
            let caller = get_caller_address();
            let mut stake_info = self.stakes.read(caller);
            // Cairo 2.12.0: Improved delegation validation
            assert!(stake_info.amount >= amount, "Insufficient stake");
            
            stake_info.delegated_amount += amount;
            self.stakes.write(caller, stake_info);
            
            // Add to delegated worker's stake
            let mut worker_stake = self.stakes.read(worker);
            worker_stake.delegated_amount += amount;
            self.stakes.write(worker, worker_stake);
        }

        // Job Allocation Functions

        fn allocate_job(
            ref self: ContractState,
            job_id: JobId,
            requirements: ModelRequirements,
            priority: u8,
            max_latency: u64
        ) -> AllocationResult {
            // Simplified allocation algorithm - find first available worker
            let zero_address: ContractAddress = 0.try_into().unwrap();
            let mut best_worker = zero_address;
            let mut best_score = 0;
            let mut worker_id_u256: u256 = 1;
            let max_worker_id: u256 = self.next_worker_id.read().into();
            
            // In a real implementation, this would be more sophisticated
            while worker_id_u256 != max_worker_id {
                let worker_id_felt: felt252 = worker_id_u256.try_into().unwrap();
                let status = self.worker_status.read(worker_id_felt);
                if status == WorkerStatus::Active {
                    let capabilities = self.worker_capabilities.read(worker_id_felt);
                    if capabilities.gpu_memory >= requirements.min_memory_gb.into() {
                        best_worker = self.worker_owners.read(worker_id_felt);
                        best_score = 90; // High confidence
                        break;
                    }
                }
                worker_id_u256 += 1;
            };
            
            if best_worker != zero_address {
                let job_key: felt252 = job_id.value.try_into().unwrap();
                let worker_id_felt: felt252 = worker_id_u256.try_into().unwrap();
                self.job_allocations.write(job_key, worker_id_felt);
                
                let allocation = AllocationResult {
                    worker: best_worker,
                    confidence_score: best_score,
                    estimated_completion: get_block_timestamp() + 3600, // 1 hour
                };
                
                self.emit(Event::JobAllocated(JobAllocated {
                    job_id,
                    worker_id: WorkerId { value: worker_id_felt },
                    confidence_score: best_score,
                    estimated_completion: allocation.estimated_completion,
                }));
                
                allocation
            } else {
                // No worker found
                AllocationResult {
                    worker: zero_address,
                    confidence_score: 0,
                    estimated_completion: 0,
                }
            }
        }

        fn get_eligible_workers(
            self: @ContractState,
            requirements: ModelRequirements,
            max_results: u32
        ) -> Array<WorkerId> {
            let mut workers = array![];
            let mut found = 0;
            let mut worker_id_u256: u256 = 1;
            let max_worker_id: u256 = self.next_worker_id.read().into();
            
            while worker_id_u256 != max_worker_id && found != max_results {
                let worker_id_felt: felt252 = worker_id_u256.try_into().unwrap();
                let status = self.worker_status.read(worker_id_felt);
                if status == WorkerStatus::Active {
                    let capabilities = self.worker_capabilities.read(worker_id_felt);
                    if capabilities.gpu_memory >= requirements.min_memory_gb.into() {
                        workers.append(WorkerId { value: worker_id_felt });
                        found += 1;
                    }
                }
                worker_id_u256 += 1;
            };
            
            workers
        }

        fn reserve_worker(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            duration: u64
        ) {
            let end_time = get_block_timestamp() + duration;
            let job_key: felt252 = job_id.value.try_into().unwrap();
            self.reserved_workers.write((worker_id.value, job_key), end_time);
            
            self.emit(Event::WorkerReserved(WorkerReserved {
                worker_id,
                job_id,
                duration,
            }));
        }

        fn release_worker(ref self: ContractState, worker_id: WorkerId, job_id: JobId) {
            let job_key: felt252 = job_id.value.try_into().unwrap();
            self.reserved_workers.write((worker_id.value, job_key), 0);
            
            self.emit(Event::WorkerReleased(WorkerReleased {
                worker_id,
                job_id: job_id,
            }));
        }

        // Reputation and Performance Functions

        fn update_reputation(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            performance_score: u8,
            response_time: u64,
            quality_score: u8
        ) {
            let worker_key = worker_id.value;
            let current_reputation = self.worker_reputation.read(worker_key);
            
            // Simple reputation update algorithm
            let score_impact: u64 = (performance_score.into() + quality_score.into()) / 2;
            let new_reputation = if score_impact > 50 {
                current_reputation + 1
            } else if current_reputation > 0 { 
                current_reputation - 1 
            } else { 
                0 
            };
            
            self.worker_reputation.write(worker_key, new_reputation);
        }

        fn record_job_completion(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            success: bool,
            execution_time: u64
        ) {
            let worker_key = worker_id.value;
            
            if success {
                let completed = self.worker_jobs_completed.read(worker_key);
                self.worker_jobs_completed.write(worker_key, completed + 1);
            } else {
                let failed = self.worker_jobs_failed.read(worker_key);
                self.worker_jobs_failed.write(worker_key, failed + 1);
            }
            
            self.total_jobs_processed.write(self.total_jobs_processed.read() + 1);
        }

        fn get_performance_metrics(
            self: @ContractState,
            worker_id: WorkerId
        ) -> PerformanceMetrics {
            self.worker_performance.read(worker_id.value)
        }

        fn get_worker_metrics(
            self: @ContractState,
            worker_id: WorkerId
        ) -> PerformanceMetrics {
            self.get_performance_metrics(worker_id)
        }

        // Slashing Functions

        fn slash_worker(
            ref self: ContractState,
            worker_id: WorkerId,
            reason: SlashReason,
            evidence: Array<felt252>
        ) -> u256 {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin can slash");
            
            let worker_key = worker_id.value;
            let worker_owner = self.worker_owners.read(worker_key);
            let stake_info = self.stakes.read(worker_owner);
            
            let reason_u8: u8 = reason.into();
            let slash_percentage = self.slash_percentages.read(reason_u8);
            let slash_amount = (stake_info.amount * slash_percentage.into()) / 100;
            
            // Record slash
            let slash_id = self.next_slash_id.read();
            let slash_record = SlashRecord {
                worker: worker_owner,
                reason,
                amount: slash_amount,
                timestamp: get_block_timestamp(),
                evidence_hash: if evidence.len() > 0 { *evidence.at(0) } else { 0 },
            };
            self.slash_records.write(slash_id, slash_record);
            self.next_slash_id.write(slash_id + 1);
            
            // Update worker status and stake
            self.worker_status.write(worker_key, WorkerStatus::Slashed);
            let mut updated_stake = stake_info;
            updated_stake.amount -= slash_amount;
            self.stakes.write(worker_owner, updated_stake);
            
            slash_amount
        }

        fn challenge_slash(
            ref self: ContractState,
            worker_id: WorkerId,
            evidence: Array<felt252>
        ) {
            // Simplified implementation - in reality would start dispute process
            let caller = get_caller_address();
            let worker_key = worker_id.value;
            let owner = self.worker_owners.read(worker_key);
            assert!(owner == caller, "Not worker owner");
        }

        fn resolve_slash_challenge(
            ref self: ContractState,
            worker_id: WorkerId,
            upheld: bool
        ) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin can resolve");
            
            if !upheld {
                // Restore worker status
                let worker_key = worker_id.value;
                self.worker_status.write(worker_key, WorkerStatus::Active);
            }
        }

        // Reward Distribution Functions

        fn distribute_rewards(
            ref self: ContractState,
            worker_id: WorkerId,
            job_id: JobId,
            base_reward: u256,
            performance_bonus: u256
        ) {
            let worker_key = worker_id.value;
            let current_pending = self.pending_rewards.read(worker_key);
            self.pending_rewards.write(worker_key, current_pending + base_reward + performance_bonus);
            
            // Update worker total earnings
            let current_earnings = self.worker_total_earnings.read(worker_key);
            self.worker_total_earnings.write(worker_key, current_earnings + base_reward + performance_bonus);
        }

        fn distribute_reward(
            ref self: ContractState,
            worker_id: WorkerId,
            base_reward: u256,
            performance_bonus: u256
        ) {
            let worker_key = worker_id.value;
            let current_pending = self.pending_rewards.read(worker_key);
            self.pending_rewards.write(worker_key, current_pending + base_reward + performance_bonus);
        }

        fn claim_rewards(ref self: ContractState, worker_id: WorkerId) -> u256 {
            let caller = get_caller_address();
            let worker_key = worker_id.value;
            let owner = self.worker_owners.read(worker_key);
            assert!(owner == caller, "Not worker owner");
            
            let pending = self.pending_rewards.read(worker_key);
            if pending > 0 {
                self.pending_rewards.write(worker_key, 0);
                
                let ciro_token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
                ciro_token.transfer(caller, pending);
            }
            
            pending
        }

        fn calculate_pending_rewards(self: @ContractState, worker_id: WorkerId) -> u256 {
            self.pending_rewards.read(worker_id.value)
        }

        // Query Functions

        fn get_worker_profile(self: @ContractState, worker_id: WorkerId) -> WorkerProfile {
            self.worker_profiles.read(worker_id.value)
        }

        fn get_worker_capabilities(self: @ContractState, worker_id: WorkerId) -> WorkerCapabilities {
            self.worker_capabilities.read(worker_id.value)
        }

        fn get_worker_by_owner(self: @ContractState, owner: ContractAddress) -> Option<WorkerId> {
            let worker_key = self.owner_to_worker.read(owner);
            if worker_key == 0 {
                Option::None
            } else {
                Option::Some(WorkerId { value: worker_key })
            }
        }

        fn get_active_workers_count(self: @ContractState) -> u32 {
            self.active_workers.read()
        }

        fn get_workers_by_capability(
            self: @ContractState,
            capability_flags: u64,
            min_reputation: u64,
            max_results: u32
        ) -> Array<WorkerId> {
            let mut workers = array![];
            let mut found = 0;
            let mut worker_id_u256: u256 = 1;
            let max_worker_id: u256 = self.next_worker_id.read().into();
            
            while worker_id_u256 != max_worker_id && found != max_results {
                let worker_id_felt: felt252 = worker_id_u256.try_into().unwrap();
                let status = self.worker_status.read(worker_id_felt);
                let reputation = self.worker_reputation.read(worker_id_felt);
                let capabilities = self.worker_capabilities.read(worker_id_felt);
                
                if status == WorkerStatus::Active 
                    && reputation >= min_reputation 
                    && (capabilities.capability_flags & capability_flags) == capability_flags {
                    workers.append(WorkerId { value: worker_id_felt });
                    found += 1;
                }
                worker_id_u256 += 1;
            };
            
            workers
        }

        fn get_network_stats(self: @ContractState) -> (u32, u32, u256, u32) {
            (
                self.total_workers.read(),
                self.active_workers.read(),
                self.total_staked.read(),
                self.total_jobs_processed.read()
            )
        }

        fn get_leaderboard(
            self: @ContractState,
            metric: felt252,
            limit: u32
        ) -> Array<WorkerId> {
            // Simplified leaderboard - in reality would need sorting
            let mut workers = array![];
            let mut found = 0;
            let mut worker_id_u256: u256 = 1;
            let max_worker_id: u256 = self.next_worker_id.read().into();
            
            while worker_id_u256 != max_worker_id && found != limit {
                let worker_id_felt: felt252 = worker_id_u256.try_into().unwrap();
                let status = self.worker_status.read(worker_id_felt);
                if status == WorkerStatus::Active {
                    workers.append(WorkerId { value: worker_id_felt });
                    found += 1;
                }
                worker_id_u256 += 1;
            };
            
            workers
        }

        fn get_stake_info(self: @ContractState, worker: ContractAddress) -> StakeInfo {
            self.stakes.read(worker)
        }

        fn get_unstaking_requests(
            self: @ContractState,
            worker: ContractAddress
        ) -> Array<UnstakeRequest> {
            // Simplified - would need to track per-worker requests
            array![]
        }

        fn get_unstake_requests(
            self: @ContractState,
            offset: u32,
            limit: u32
        ) -> Array<UnstakeRequest> {
            // Simplified implementation
            array![]
        }

        // Worker Tier Functions

        fn get_worker_tier(self: @ContractState, worker: ContractAddress) -> WorkerTier {
            let stake_info = self.stakes.read(worker);
            let usd_value = (stake_info.amount * self.ciro_price_usd_cents.read()) / 1000000000000000000; // Convert from wei
            
            if usd_value >= self.tier_usd_requirements.read(7) {
                WorkerTier::Institutional
            } else if usd_value >= self.tier_usd_requirements.read(6) {
                WorkerTier::Hyperscale
            } else if usd_value >= self.tier_usd_requirements.read(5) {
                WorkerTier::Datacenter
            } else if usd_value >= self.tier_usd_requirements.read(4) {
                WorkerTier::Fleet
            } else if usd_value >= self.tier_usd_requirements.read(3) {
                WorkerTier::Infrastructure
            } else if usd_value >= self.tier_usd_requirements.read(2) {
                WorkerTier::Enterprise
            } else if usd_value >= self.tier_usd_requirements.read(1) {
                WorkerTier::Premium
            } else {
                WorkerTier::Basic
            }
        }

        fn get_worker_tier_benefits(self: @ContractState, tier: WorkerTier) -> WorkerTierBenefits {
            let tier_u8: u8 = match tier {
                WorkerTier::Basic => 0,
                WorkerTier::Premium => 1,
                WorkerTier::Enterprise => 2,
                WorkerTier::Infrastructure => 3,
                WorkerTier::Fleet => 4,
                WorkerTier::Datacenter => 5,
                WorkerTier::Hyperscale => 6,
                WorkerTier::Institutional => 7,
            };
            
            WorkerTierBenefits {
                tier,
                usd_requirement: self.tier_usd_requirements.read(tier_u8),
                allocation_priority: 100 + (tier_u8.into() * 10), // Base 100 + tier bonus
                performance_bonus_bps: 50 + (tier_u8.into() * 25), // 0.5% + tier bonus
                min_reputation_required: 500 + (tier_u8.into() * 50),
            }
        }

        fn get_stake_usd_value(self: @ContractState, worker: ContractAddress) -> u256 {
            let stake_info = self.stakes.read(worker);
            (stake_info.amount * self.ciro_price_usd_cents.read()) / 1000000000000000000 // Convert from wei
        }

        fn get_tier_ciro_requirement(self: @ContractState, tier: WorkerTier) -> u256 {
            let tier_u8: u8 = match tier {
                WorkerTier::Basic => 0,
                WorkerTier::Premium => 1,
                WorkerTier::Enterprise => 2,
                WorkerTier::Infrastructure => 3,
                WorkerTier::Fleet => 4,
                WorkerTier::Datacenter => 5,
                WorkerTier::Hyperscale => 6,
                WorkerTier::Institutional => 7,
            };
            
            let usd_requirement = self.tier_usd_requirements.read(tier_u8);
            let ciro_price = self.ciro_price_usd_cents.read();
            
            // Calculate CIRO tokens needed (in wei)
            (usd_requirement * 1000000000000000000) / ciro_price
        }

        fn update_ciro_price(ref self: ContractState, new_price: u256) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin can update price");
            self.ciro_price_usd_cents.write(new_price);
        }

        fn meets_tier_requirements(self: @ContractState, worker: ContractAddress, tier: WorkerTier) -> bool {
            let current_tier = self.get_worker_tier(worker);
            let current_tier_u8: u8 = match current_tier {
                WorkerTier::Basic => 0,
                WorkerTier::Premium => 1,
                WorkerTier::Enterprise => 2,
                WorkerTier::Infrastructure => 3,
                WorkerTier::Fleet => 4,
                WorkerTier::Datacenter => 5,
                WorkerTier::Hyperscale => 6,
                WorkerTier::Institutional => 7,
            };
            
            let target_tier_u8: u8 = match tier {
                WorkerTier::Basic => 0,
                WorkerTier::Premium => 1,
                WorkerTier::Enterprise => 2,
                WorkerTier::Infrastructure => 3,
                WorkerTier::Fleet => 4,
                WorkerTier::Datacenter => 5,
                WorkerTier::Hyperscale => 6,
                WorkerTier::Institutional => 7,
            };
            
            current_tier_u8 >= target_tier_u8
        }

        fn get_holder_tier(self: @ContractState, holder: ContractAddress) -> HolderTier {
            let ciro_token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            let balance = ciro_token.balance_of(holder);
            let usd_value = (balance * self.ciro_price_usd_cents.read()) / 1000000000000000000;
            
            if balance >= 100000000000000000000000000 && usd_value >= 5000000 { // 100M CIRO + $50M
                HolderTier::HyperWhale
            } else if balance >= 25000000000000000000000000 && usd_value >= 1000000 { // 25M CIRO + $10M
                HolderTier::Institution
            } else if balance >= 5000000000000000000000000 && usd_value >= 200000 { // 5M CIRO + $2M
                HolderTier::Whale
            } else {
                HolderTier::Regular
            }
        }

        fn get_tier_allocation_score(
            self: @ContractState,
            worker: ContractAddress,
            requirements: ModelRequirements
        ) -> u256 {
            let tier = self.get_worker_tier(worker);
            let base_score = 100;
            
            let tier_bonus = match tier {
                WorkerTier::Basic => 0,
                WorkerTier::Premium => 10,
                WorkerTier::Enterprise => 25,
                WorkerTier::Infrastructure => 50,
                WorkerTier::Fleet => 100,
                WorkerTier::Datacenter => 200,
                WorkerTier::Hyperscale => 350,
                WorkerTier::Institutional => 500,
            };
            
            base_score + tier_bonus
        }

        // Administrative Functions

        fn update_min_stake(ref self: ContractState, new_min_stake: u256) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            self.min_stake.write(new_min_stake);
        }

        fn update_slash_percentage(
            ref self: ContractState,
            reason: SlashReason,
            percentage: u8
        ) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            let reason_u8: u8 = reason.into();
            self.slash_percentages.write(reason_u8, percentage);
        }

        fn update_reward_parameters(
            ref self: ContractState,
            base_rate: u256,
            performance_multiplier: u8
        ) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            self.base_reward_rate.write(base_rate);
            self.performance_multiplier.write(performance_multiplier);
        }

        fn pause_contract(ref self: ContractState) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            self.paused.write(true);
        }

        fn resume_contract(ref self: ContractState) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            self.paused.write(false);
        }

        fn emergency_remove_worker(
            ref self: ContractState,
            worker_id: WorkerId,
            reason: felt252
        ) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            
            let worker_key = worker_id.value;
            self.worker_status.write(worker_key, WorkerStatus::Banned);
            
            let current_status = self.worker_status.read(worker_key);
            if current_status == WorkerStatus::Active {
                self.active_workers.write(self.active_workers.read() - 1);
            }
        }
    }
}
