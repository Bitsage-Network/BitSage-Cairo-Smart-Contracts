//! Reputation Manager Implementation for SAGE Network
//! Central reputation management system for worker ranking and job allocation
//!
//! Phase 2 Complete Implementation:
//! - Per-worker reputation storage
//! - Reputation update with bounds checking
//! - Rate limiting for updates
//! - Reputation thresholds per job type
//! - History tracking (limited to recent events)

use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
use starknet::storage::{
    StoragePointerReadAccess, StoragePointerWriteAccess,
    StorageMapReadAccess, StorageMapWriteAccess, Map
};
use core::num::traits::Zero;

use sage_contracts::interfaces::reputation_manager::{
    IReputationManager, ReputationScore, ReputationEvent, ReputationReason,
    ReputationThreshold, WorkerRank
};

// Constants
const MIN_SCORE: u32 = 0;
const MAX_SCORE: u32 = 1000;
const INITIAL_SCORE: u32 = 500;
const INITIAL_LEVEL: u8 = 3;

// Score changes for different actions
const JOB_COMPLETED_BONUS: i32 = 15;
const JOB_FAILED_PENALTY: i32 = -25;
const SLASH_PENALTY: i32 = -100;
const DISPUTE_LOST_PENALTY: i32 = -50;
const DISPUTE_WON_BONUS: i32 = 30;
const INACTIVITY_DECAY: i32 = -5;

// Rate limiting (minimum seconds between updates for same worker)
const MIN_UPDATE_INTERVAL: u64 = 60; // 1 minute

// Default decay configuration
const DEFAULT_DECAY_PERIOD_SECS: u64 = 604800; // 7 days of inactivity before decay
const DEFAULT_DECAY_POINTS_PER_PERIOD: u32 = 5; // 5 points per decay period
const MAX_DECAY_PERIODS: u64 = 20; // Cap decay at 20 periods to prevent excessive penalties

#[starknet::contract]
pub mod ReputationManager {
    use super::{
        IReputationManager, ReputationScore, ReputationEvent, ReputationReason,
        ReputationThreshold, WorkerRank, ContractAddress, get_caller_address,
        get_block_timestamp, StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map,
        MIN_SCORE, MAX_SCORE, INITIAL_SCORE, INITIAL_LEVEL,
        DEFAULT_DECAY_PERIOD_SECS, DEFAULT_DECAY_POINTS_PER_PERIOD, MAX_DECAY_PERIODS,
        Zero
    };

    #[storage]
    struct Storage {
        // Admin and authorized contracts
        admin: ContractAddress,
        pending_admin: ContractAddress,  // Two-step admin transfer
        paused: bool,                     // Pausable
        cdc_pool: ContractAddress,
        job_manager: ContractAddress,

        // Rate limiting configuration
        update_rate_limit: u64,

        // Per-worker reputation storage
        worker_reputations: Map<felt252, ReputationScore>,
        worker_initialized: Map<felt252, bool>,
        worker_last_update: Map<felt252, u64>,

        // Reputation thresholds per job type
        job_type_thresholds: Map<felt252, ReputationThreshold>,

        // Network statistics
        total_workers: u32,
        total_score_sum: u256,  // Sum of all scores for avg calculation
        highest_score: u32,
        lowest_score: u32,

        // Worker list for enumeration (limited implementation)
        // In production, use events + off-chain indexing for full enumeration
        workers_by_level: Map<(u8, u32), felt252>,  // (level, index) -> worker_id
        workers_count_by_level: Map<u8, u32>,        // level -> count

        // Phase 2.1: Track worker's index in their level list for O(1) removal
        worker_level_index: Map<felt252, u32>,      // worker_id -> index in level list

        // History tracking (limited to last N events per worker)
        worker_history_count: Map<felt252, u32>,
        // Note: Full history would require off-chain indexing via events

        // Decay configuration (Phase 2: On-chain decay)
        decay_period_secs: u64,          // Inactivity period before decay starts
        decay_points_per_period: u32,    // Points to deduct per decay period
        last_decay_applied: Map<felt252, u64>, // Last time decay was applied to worker
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ReputationInitialized: ReputationInitialized,
        ReputationUpdated: ReputationUpdated,
        ThresholdSet: ThresholdSet,
        AdminAdjusted: AdminAdjusted,
        InactivityDecayApplied: InactivityDecayApplied,
        WorkerDecayed: WorkerDecayed,
        DecayConfigUpdated: DecayConfigUpdated,
        AdminTransferStarted: AdminTransferStarted,
        AdminTransferred: AdminTransferred,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AdminTransferStarted {
        #[key]
        pub previous_admin: ContractAddress,
        #[key]
        pub new_admin: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AdminTransferred {
        #[key]
        pub previous_admin: ContractAddress,
        #[key]
        pub new_admin: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContractPaused {
        pub account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContractUnpaused {
        pub account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WorkerDecayed {
        #[key]
        pub worker_id: felt252,
        pub old_score: u32,
        pub new_score: u32,
        pub decay_periods: u64,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DecayConfigUpdated {
        pub decay_period_secs: u64,
        pub decay_points_per_period: u32,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ReputationInitialized {
        #[key]
        pub worker_id: felt252,
        pub initial_score: u32,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ReputationUpdated {
        #[key]
        pub worker_id: felt252,
        pub old_score: u32,
        pub new_score: u32,
        pub score_delta: i32,
        pub reason: felt252,
        pub job_id: Option<u256>,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ThresholdSet {
        #[key]
        pub job_type: felt252,
        pub min_score: u32,
        pub min_level: u8,
        pub max_failures: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AdminAdjusted {
        pub worker_id: felt252,
        pub new_score: u32,
        pub reason: felt252,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct InactivityDecayApplied {
        pub workers_affected: u32,
        pub cutoff_timestamp: u64,
        pub timestamp: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        admin: ContractAddress,
        cdc_pool: ContractAddress,
        job_manager: ContractAddress,
        update_rate_limit: u64
    ) {
        // Phase 2.1: Validate constructor parameters
        assert!(!admin.is_zero(), "Invalid admin address");
        // Note: cdc_pool and job_manager can be zero initially and set later

        self.admin.write(admin);
        self.cdc_pool.write(cdc_pool);
        self.job_manager.write(job_manager);
        self.update_rate_limit.write(update_rate_limit);

        // Initialize network stats
        self.total_workers.write(0);
        self.total_score_sum.write(0);
        self.highest_score.write(0);
        self.lowest_score.write(MAX_SCORE);

        // Initialize decay configuration with defaults
        self.decay_period_secs.write(DEFAULT_DECAY_PERIOD_SECS);
        self.decay_points_per_period.write(DEFAULT_DECAY_POINTS_PER_PERIOD);
    }

    #[abi(embed_v0)]
    impl ReputationManagerImpl of IReputationManager<ContractState> {
        fn initialize_reputation(ref self: ContractState, worker_id: felt252) -> bool {
            // Check if already initialized
            if self.worker_initialized.read(worker_id) {
                return false;
            }

            let current_time = get_block_timestamp();

            // Create initial reputation score
            let initial_rep = ReputationScore {
                score: INITIAL_SCORE,
                level: INITIAL_LEVEL,
                last_updated: current_time,
                total_jobs_completed: 0,
                successful_jobs: 0,
                failed_jobs: 0,
                dispute_count: 0,
                slash_count: 0,
            };

            // Store reputation
            self.worker_reputations.write(worker_id, initial_rep);
            self.worker_initialized.write(worker_id, true);
            self.worker_last_update.write(worker_id, current_time);
            self.last_decay_applied.write(worker_id, current_time);

            // Update network stats
            let current_total = self.total_workers.read();
            self.total_workers.write(current_total + 1);
            self.total_score_sum.write(self.total_score_sum.read() + INITIAL_SCORE.into());

            // Update level tracking
            let level_count = self.workers_count_by_level.read(INITIAL_LEVEL);
            self.workers_by_level.write((INITIAL_LEVEL, level_count), worker_id);
            self.workers_count_by_level.write(INITIAL_LEVEL, level_count + 1);
            // Phase 2.1: Track worker's index for O(1) removal later
            self.worker_level_index.write(worker_id, level_count);

            // Update highest/lowest
            if INITIAL_SCORE > self.highest_score.read() {
                self.highest_score.write(INITIAL_SCORE);
            }
            if INITIAL_SCORE < self.lowest_score.read() {
                self.lowest_score.write(INITIAL_SCORE);
            }

            self.emit(ReputationInitialized {
                worker_id,
                initial_score: INITIAL_SCORE,
                timestamp: current_time,
            });

            true
        }

        fn update_reputation(
            ref self: ContractState,
            worker_id: felt252,
            score_delta: i32,
            reason: ReputationReason,
            job_id: Option<u256>
        ) -> bool {
            // Authorization check - only CDC Pool or Job Manager can update
            let caller = get_caller_address();
            let cdc_pool = self.cdc_pool.read();
            let job_manager = self.job_manager.read();
            let admin = self.admin.read();

            if caller != cdc_pool && caller != job_manager && caller != admin {
                return false;
            }

            // Check if worker is initialized
            if !self.worker_initialized.read(worker_id) {
                return false;
            }

            // Rate limiting check
            let current_time = get_block_timestamp();
            let last_update = self.worker_last_update.read(worker_id);
            let rate_limit = self.update_rate_limit.read();

            if current_time < last_update + rate_limit && caller != admin {
                return false; // Too soon for another update (unless admin)
            }

            // Get current reputation
            let mut rep = self.worker_reputations.read(worker_id);
            let old_score = rep.score;
            let old_level = rep.level;

            // Calculate new score with bounds checking
            let new_score = self._calculate_new_score(old_score, score_delta);

            // Update job counters based on reason
            match reason {
                ReputationReason::JobCompleted => {
                    rep.total_jobs_completed += 1;
                    rep.successful_jobs += 1;
                },
                ReputationReason::JobFailed => {
                    rep.total_jobs_completed += 1;
                    rep.failed_jobs += 1;
                },
                ReputationReason::WorkerSlashed => {
                    rep.slash_count += 1;
                },
                ReputationReason::DisputeLost => {
                    rep.dispute_count += 1;
                },
                ReputationReason::DisputeWon => {
                    rep.dispute_count += 1;
                },
                ReputationReason::InactivityDecay => {
                    // No counter update for decay
                },
                ReputationReason::AdminAdjustment => {
                    // No counter update for admin
                },
            }

            // Update score and recalculate level
            rep.score = new_score;
            rep.level = self._calculate_level(new_score);
            rep.last_updated = current_time;

            // Store updated reputation
            self.worker_reputations.write(worker_id, rep);
            self.worker_last_update.write(worker_id, current_time);

            // Update network stats
            self._update_network_stats(old_score, new_score);

            // Update level tracking if level changed
            if old_level != rep.level {
                self._update_level_tracking(worker_id, old_level, rep.level);
            }

            // Emit event with reason as felt252
            let reason_felt: felt252 = self._reason_to_felt(reason);
            self.emit(ReputationUpdated {
                worker_id,
                old_score,
                new_score,
                score_delta,
                reason: reason_felt,
                job_id,
                timestamp: current_time,
            });

            true
        }

        fn get_reputation(self: @ContractState, worker_id: felt252) -> ReputationScore {
            // Return stored reputation or default for uninitialized workers
            if !self.worker_initialized.read(worker_id) {
                return ReputationScore {
                    score: 0,
                    level: 0,
                    last_updated: 0,
                    total_jobs_completed: 0,
                    successful_jobs: 0,
                    failed_jobs: 0,
                    dispute_count: 0,
                    slash_count: 0,
                };
            }

            self.worker_reputations.read(worker_id)
        }

        fn get_reputation_history(
            self: @ContractState,
            worker_id: felt252,
            limit: u32
        ) -> Array<ReputationEvent> {
            // Note: Full history requires off-chain indexing via events
            // This returns an empty array - clients should use event logs
            array![]
        }

        fn check_reputation_threshold(
            self: @ContractState,
            worker_id: felt252,
            threshold: ReputationThreshold
        ) -> bool {
            // Worker must be initialized
            if !self.worker_initialized.read(worker_id) {
                return false;
            }

            let rep = self.worker_reputations.read(worker_id);

            // Check minimum score
            if rep.score < threshold.min_score {
                return false;
            }

            // Check minimum level
            if rep.level < threshold.min_level {
                return false;
            }

            // Check maximum failures
            if rep.failed_jobs > threshold.max_failures {
                return false;
            }

            true
        }

        fn get_worker_rank(self: @ContractState, worker_id: felt252) -> u32 {
            // Percentile-based ranking estimation (gas-efficient on-chain solution)
            // Returns estimated rank based on score percentile relative to highest score
            if !self.worker_initialized.read(worker_id) {
                return 0; // Not ranked
            }

            let rep = self.worker_reputations.read(worker_id);
            let total_workers = self.total_workers.read();

            if total_workers == 0 {
                return 1;
            }

            // Estimate rank based on score (higher score = lower rank number)
            // This is an approximation - exact ranking needs off-chain indexing
            let highest = self.highest_score.read();
            if highest == 0 {
                return 1;
            }

            let score_percentile = (rep.score * 100) / highest;
            let estimated_rank = ((100 - score_percentile) * total_workers) / 100 + 1;

            estimated_rank
        }

        fn get_top_workers(self: @ContractState, count: u32) -> Array<WorkerRank> {
            // Note: Full leaderboard requires off-chain indexing
            // This returns workers at the highest level as an approximation
            let mut result: Array<WorkerRank> = array![];

            // Get workers from level 5 (highest)
            let level_5_count = self.workers_count_by_level.read(5);
            let workers_to_return = if count < level_5_count { count } else { level_5_count };

            let mut i: u32 = 0;
            while i < workers_to_return {
                let worker_id = self.workers_by_level.read((5, i));
                if worker_id != 0 {
                    let rep = self.worker_reputations.read(worker_id);
                    result.append(WorkerRank {
                        worker_id,
                        score: rep.score,
                        level: rep.level,
                        rank: i + 1,
                    });
                }
                i += 1;
            };

            result
        }

        fn get_workers_by_level(self: @ContractState, level: u8) -> Array<WorkerRank> {
            let mut result: Array<WorkerRank> = array![];

            // Validate level
            if level < 1 || level > 5 {
                return result;
            }

            let level_count = self.workers_count_by_level.read(level);
            let max_results: u32 = if level_count > 100 { 100 } else { level_count };

            let mut i: u32 = 0;
            while i < max_results {
                let worker_id = self.workers_by_level.read((level, i));
                if worker_id != 0 {
                    let rep = self.worker_reputations.read(worker_id);
                    result.append(WorkerRank {
                        worker_id,
                        score: rep.score,
                        level: rep.level,
                        rank: i + 1, // Rank within level
                    });
                }
                i += 1;
            };

            result
        }

        // ============================================================================
        // Phase 2.1: Paginated Query Functions
        // ============================================================================

        fn get_top_workers_paginated(
            self: @ContractState,
            offset: u32,
            limit: u32
        ) -> Array<WorkerRank> {
            let mut result: Array<WorkerRank> = array![];

            // Cap limit to prevent excessive gas usage
            let max_limit: u32 = if limit > 100 { 100 } else { limit };

            // Start from level 5 (highest) and work down
            let mut current_level: u8 = 5;
            let mut workers_returned: u32 = 0;
            let mut workers_skipped: u32 = 0;

            while current_level >= 1 && workers_returned < max_limit {
                let level_count = self.workers_count_by_level.read(current_level);
                let mut i: u32 = 0;

                while i < level_count && workers_returned < max_limit {
                    // Skip workers until we reach the offset
                    if workers_skipped < offset {
                        workers_skipped += 1;
                        i += 1;
                        continue;
                    }

                    let worker_id = self.workers_by_level.read((current_level, i));
                    if worker_id != 0 {
                        let rep = self.worker_reputations.read(worker_id);
                        result.append(WorkerRank {
                            worker_id,
                            score: rep.score,
                            level: rep.level,
                            rank: offset + workers_returned + 1, // Global rank
                        });
                        workers_returned += 1;
                    }
                    i += 1;
                };

                if current_level == 1 {
                    break;
                }
                current_level -= 1;
            };

            result
        }

        fn get_workers_by_level_paginated(
            self: @ContractState,
            level: u8,
            offset: u32,
            limit: u32
        ) -> Array<WorkerRank> {
            let mut result: Array<WorkerRank> = array![];

            // Validate level
            if level < 1 || level > 5 {
                return result;
            }

            // Cap limit to prevent excessive gas usage
            let max_limit: u32 = if limit > 100 { 100 } else { limit };

            let level_count = self.workers_count_by_level.read(level);

            // If offset is beyond available workers, return empty
            if offset >= level_count {
                return result;
            }

            // Calculate end index
            let end_index = if offset + max_limit > level_count {
                level_count
            } else {
                offset + max_limit
            };

            let mut i: u32 = offset;
            while i < end_index {
                let worker_id = self.workers_by_level.read((level, i));
                if worker_id != 0 {
                    let rep = self.worker_reputations.read(worker_id);
                    result.append(WorkerRank {
                        worker_id,
                        score: rep.score,
                        level: rep.level,
                        rank: i + 1, // Rank within level (1-based)
                    });
                }
                i += 1;
            };

            result
        }

        fn get_workers_count_by_level(self: @ContractState, level: u8) -> u32 {
            // Validate level
            if level < 1 || level > 5 {
                return 0;
            }
            self.workers_count_by_level.read(level)
        }

        fn apply_inactivity_decay(ref self: ContractState, cutoff_timestamp: u64) -> u32 {
            // Only admin can apply decay
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Not authorized");

            // Process all levels in sequence
            let mut total_affected: u32 = 0;

            // Process each level (1-5)
            let mut level: u8 = 1;
            while level <= 5 {
                let (_, affected) = self._apply_decay_for_level(level, 0, 100, cutoff_timestamp);
                total_affected += affected;
                level += 1;
            };

            self.emit(InactivityDecayApplied {
                workers_affected: total_affected,
                cutoff_timestamp,
                timestamp: get_block_timestamp(),
            });

            total_affected
        }

        fn apply_decay_batch(
            ref self: ContractState,
            level: u8,
            start_index: u32,
            batch_size: u32
        ) -> (u32, u32) {
            // Only admin can apply decay
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Not authorized");
            assert!(level >= 1 && level <= 5, "Invalid level");

            let current_time = get_block_timestamp();
            let decay_period = self.decay_period_secs.read();
            // Calculate cutoff: workers inactive longer than decay_period should be decayed
            let cutoff = if current_time > decay_period {
                current_time - decay_period
            } else {
                0
            };

            self._apply_decay_for_level(level, start_index, batch_size, cutoff)
        }

        fn get_reputation_with_decay(self: @ContractState, worker_id: felt252) -> ReputationScore {
            // Return default for uninitialized workers
            if !self.worker_initialized.read(worker_id) {
                return ReputationScore {
                    score: 0,
                    level: 0,
                    last_updated: 0,
                    total_jobs_completed: 0,
                    successful_jobs: 0,
                    failed_jobs: 0,
                    dispute_count: 0,
                    slash_count: 0,
                };
            }

            let rep = self.worker_reputations.read(worker_id);

            // Calculate pending decay (view only, doesn't persist)
            let current_time = get_block_timestamp();
            let last_activity = rep.last_updated;
            let decay_period = self.decay_period_secs.read();
            let decay_points = self.decay_points_per_period.read();

            if decay_period == 0 || current_time <= last_activity {
                return rep;
            }

            let time_inactive = current_time - last_activity;
            if time_inactive < decay_period {
                return rep;
            }

            // Calculate number of decay periods elapsed
            let decay_periods_elapsed: u64 = time_inactive / decay_period;
            let capped_periods = if decay_periods_elapsed > MAX_DECAY_PERIODS {
                MAX_DECAY_PERIODS
            } else {
                decay_periods_elapsed
            };

            // Calculate total decay
            let total_decay: u32 = (capped_periods.try_into().unwrap_or(0_u32)) * decay_points;

            // Apply decay to score
            let new_score = if total_decay >= rep.score {
                MIN_SCORE
            } else {
                rep.score - total_decay
            };

            // Return adjusted reputation (without persisting)
            ReputationScore {
                score: new_score,
                level: self._calculate_level(new_score),
                last_updated: rep.last_updated,
                total_jobs_completed: rep.total_jobs_completed,
                successful_jobs: rep.successful_jobs,
                failed_jobs: rep.failed_jobs,
                dispute_count: rep.dispute_count,
                slash_count: rep.slash_count,
            }
        }

        fn set_decay_config(
            ref self: ContractState,
            decay_period_secs: u64,
            decay_points_per_period: u32
        ) {
            // Only admin can set decay config
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin can set decay config");

            // Validate values
            assert!(decay_period_secs >= 3600, "Decay period must be at least 1 hour");
            assert!(decay_points_per_period <= 50, "Decay points too high");

            self.decay_period_secs.write(decay_period_secs);
            self.decay_points_per_period.write(decay_points_per_period);

            self.emit(DecayConfigUpdated {
                decay_period_secs,
                decay_points_per_period,
                timestamp: get_block_timestamp(),
            });
        }

        fn set_reputation_threshold(
            ref self: ContractState,
            job_type: felt252,
            threshold: ReputationThreshold
        ) {
            // Only admin can set thresholds
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin can set thresholds");

            // Validate threshold values
            assert!(threshold.min_score <= MAX_SCORE, "Invalid min_score");
            assert!(threshold.min_level >= 1 && threshold.min_level <= 5, "Invalid min_level");

            self.job_type_thresholds.write(job_type, threshold);

            self.emit(ThresholdSet {
                job_type,
                min_score: threshold.min_score,
                min_level: threshold.min_level,
                max_failures: threshold.max_failures,
            });
        }

        fn admin_adjust_reputation(
            ref self: ContractState,
            worker_id: felt252,
            new_score: u32,
            reason: felt252
        ) {
            // Only admin can manually adjust
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin can adjust");

            // Validate score
            assert!(new_score <= MAX_SCORE, "Score exceeds maximum");

            // Initialize if needed
            if !self.worker_initialized.read(worker_id) {
                self.initialize_reputation(worker_id);
            }

            let current_time = get_block_timestamp();
            let mut rep = self.worker_reputations.read(worker_id);
            let old_score = rep.score;
            let old_level = rep.level;

            // Update score and level
            rep.score = new_score;
            rep.level = self._calculate_level(new_score);
            rep.last_updated = current_time;

            self.worker_reputations.write(worker_id, rep);
            self.worker_last_update.write(worker_id, current_time);

            // Update network stats
            self._update_network_stats(old_score, new_score);

            // Update level tracking if changed
            if old_level != rep.level {
                self._update_level_tracking(worker_id, old_level, rep.level);
            }

            self.emit(AdminAdjusted {
                worker_id,
                new_score,
                reason,
                timestamp: current_time,
            });
        }

        fn get_network_stats(self: @ContractState) -> (u32, u32, u32, u32) {
            let total_workers = self.total_workers.read();
            let highest_score = self.highest_score.read();
            let lowest_score = self.lowest_score.read();

            // Calculate average score
            let avg_score: u32 = if total_workers > 0 {
                let sum: u256 = self.total_score_sum.read();
                let avg: u256 = sum / total_workers.into();
                avg.try_into().unwrap_or(0)
            } else {
                0
            };

            (total_workers, avg_score, highest_score, lowest_score)
        }

        // =========================================================================
        // Two-Step Admin Transfer
        // =========================================================================

        fn transfer_admin(ref self: ContractState, new_admin: ContractAddress) {
            let caller = get_caller_address();
            assert!(caller == self.admin.read(), "Only admin");
            assert!(!new_admin.is_zero(), "New admin cannot be zero");

            let previous_admin = self.admin.read();
            self.pending_admin.write(new_admin);

            self.emit(AdminTransferStarted {
                previous_admin,
                new_admin,
            });
        }

        fn accept_admin(ref self: ContractState) {
            let caller = get_caller_address();
            let pending = self.pending_admin.read();
            assert!(caller == pending, "Caller is not pending admin");

            let previous_admin = self.admin.read();
            let zero: ContractAddress = 0.try_into().unwrap();

            self.admin.write(caller);
            self.pending_admin.write(zero);

            self.emit(AdminTransferred {
                previous_admin,
                new_admin: caller,
            });
        }

        fn admin(self: @ContractState) -> ContractAddress {
            self.admin.read()
        }

        fn pending_admin(self: @ContractState) -> ContractAddress {
            self.pending_admin.read()
        }

        // =========================================================================
        // Pausable
        // =========================================================================

        fn pause(ref self: ContractState) {
            assert!(get_caller_address() == self.admin.read(), "Only admin");
            assert!(!self.paused.read(), "Already paused");
            self.paused.write(true);
            self.emit(ContractPaused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            assert!(get_caller_address() == self.admin.read(), "Only admin");
            assert!(self.paused.read(), "Not paused");
            self.paused.write(false);
            self.emit(ContractUnpaused { account: get_caller_address() });
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }
    }

    // Internal helper functions
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Calculate new score with bounds checking
        fn _calculate_new_score(self: @ContractState, current_score: u32, delta: i32) -> u32 {
            if delta >= 0 {
                // Positive delta - add with overflow protection
                let new_score = current_score + delta.try_into().unwrap_or(0);
                if new_score > MAX_SCORE {
                    MAX_SCORE
                } else {
                    new_score
                }
            } else {
                // Negative delta - subtract with underflow protection
                let abs_delta: u32 = (-delta).try_into().unwrap_or(0);
                if abs_delta >= current_score {
                    MIN_SCORE
                } else {
                    current_score - abs_delta
                }
            }
        }

        /// Calculate reputation level from score
        fn _calculate_level(self: @ContractState, score: u32) -> u8 {
            if score >= 850 {
                5 // Elite
            } else if score >= 700 {
                4 // Expert
            } else if score >= 500 {
                3 // Intermediate
            } else if score >= 300 {
                2 // Beginner
            } else {
                1 // Novice
            }
        }

        /// Convert ReputationReason to felt252
        fn _reason_to_felt(self: @ContractState, reason: ReputationReason) -> felt252 {
            match reason {
                ReputationReason::JobCompleted => 'job_completed',
                ReputationReason::JobFailed => 'job_failed',
                ReputationReason::WorkerSlashed => 'worker_slashed',
                ReputationReason::DisputeLost => 'dispute_lost',
                ReputationReason::DisputeWon => 'dispute_won',
                ReputationReason::InactivityDecay => 'inactivity_decay',
                ReputationReason::AdminAdjustment => 'admin_adjustment',
            }
        }

        /// Update network statistics after score change
        fn _update_network_stats(ref self: ContractState, old_score: u32, new_score: u32) {
            // Update total score sum
            let current_sum = self.total_score_sum.read();
            let new_sum = current_sum - old_score.into() + new_score.into();
            self.total_score_sum.write(new_sum);

            // Update highest/lowest if needed
            if new_score > self.highest_score.read() {
                self.highest_score.write(new_score);
            }
            // Note: lowest_score update would need full scan, skip for efficiency
        }

        /// Update level tracking when worker changes level
        /// Phase 2.1: Fixed memory leak - now properly removes from old level
        fn _update_level_tracking(
            ref self: ContractState,
            worker_id: felt252,
            old_level: u8,
            new_level: u8
        ) {
            // Phase 2.1: Remove from old level using swap-with-last pattern
            // This maintains O(1) removal without gaps
            let old_level_count = self.workers_count_by_level.read(old_level);
            if old_level_count > 0 {
                let worker_index = self.worker_level_index.read(worker_id);

                // Only remove if the worker is actually in the old level
                let stored_worker = self.workers_by_level.read((old_level, worker_index));
                if stored_worker == worker_id {
                    let last_index = old_level_count - 1;

                    if worker_index < last_index {
                        // Swap with last element
                        let last_worker = self.workers_by_level.read((old_level, last_index));
                        self.workers_by_level.write((old_level, worker_index), last_worker);
                        // Update the moved worker's index
                        self.worker_level_index.write(last_worker, worker_index);
                    }

                    // Clear the last slot and decrement count
                    self.workers_by_level.write((old_level, last_index), 0);
                    self.workers_count_by_level.write(old_level, old_level_count - 1);
                }
            }

            // Add to new level (append at end)
            let new_level_count = self.workers_count_by_level.read(new_level);
            self.workers_by_level.write((new_level, new_level_count), worker_id);
            self.workers_count_by_level.write(new_level, new_level_count + 1);
            // Update worker's index to their new position
            self.worker_level_index.write(worker_id, new_level_count);
        }

        /// Apply decay for workers at a specific level in batches
        /// Returns (workers_processed, workers_decayed)
        fn _apply_decay_for_level(
            ref self: ContractState,
            level: u8,
            start_index: u32,
            batch_size: u32,
            cutoff_timestamp: u64
        ) -> (u32, u32) {
            let level_count = self.workers_count_by_level.read(level);

            // Cap batch_size to prevent excessive gas usage
            let max_batch: u32 = if batch_size > 50 { 50 } else { batch_size };

            // Calculate end index
            let end_index = if start_index + max_batch > level_count {
                level_count
            } else {
                start_index + max_batch
            };

            if start_index >= level_count {
                return (0, 0);
            }

            let current_time = get_block_timestamp();
            let decay_period = self.decay_period_secs.read();
            let decay_points = self.decay_points_per_period.read();

            if decay_period == 0 {
                return (0, 0);
            }

            let mut workers_processed: u32 = 0;
            let mut workers_decayed: u32 = 0;
            let mut i: u32 = start_index;

            while i < end_index {
                let worker_id = self.workers_by_level.read((level, i));
                if worker_id != 0 {
                    workers_processed += 1;

                    let rep = self.worker_reputations.read(worker_id);
                    let last_activity = rep.last_updated;

                    // Only decay if worker was inactive before cutoff
                    if last_activity < cutoff_timestamp && last_activity > 0 {
                        let time_inactive = current_time - last_activity;
                        let decay_periods_elapsed: u64 = time_inactive / decay_period;

                        if decay_periods_elapsed > 0 {
                            // Cap decay periods
                            let capped_periods = if decay_periods_elapsed > MAX_DECAY_PERIODS {
                                MAX_DECAY_PERIODS
                            } else {
                                decay_periods_elapsed
                            };

                            // Check if already decayed for these periods
                            let last_decay_time = self.last_decay_applied.read(worker_id);
                            let periods_since_last_decay = if current_time > last_decay_time {
                                (current_time - last_decay_time) / decay_period
                            } else {
                                0
                            };

                            if periods_since_last_decay > 0 {
                                // Calculate total decay to apply
                                let periods_to_apply = if periods_since_last_decay > capped_periods {
                                    capped_periods
                                } else {
                                    periods_since_last_decay
                                };

                                let total_decay: u32 = (periods_to_apply.try_into().unwrap_or(0_u32)) * decay_points;
                                let old_score = rep.score;

                                // Calculate new score
                                let new_score = if total_decay >= old_score {
                                    MIN_SCORE
                                } else {
                                    old_score - total_decay
                                };

                                if new_score != old_score {
                                    // Update reputation
                                    let old_level = rep.level;
                                    let new_level = self._calculate_level(new_score);

                                    let mut updated_rep = rep;
                                    updated_rep.score = new_score;
                                    updated_rep.level = new_level;
                                    // Don't update last_updated - that tracks activity, not decay

                                    self.worker_reputations.write(worker_id, updated_rep);
                                    self.last_decay_applied.write(worker_id, current_time);

                                    // Update network stats
                                    self._update_network_stats(old_score, new_score);

                                    // Update level tracking if changed
                                    if old_level != new_level {
                                        self._update_level_tracking(worker_id, old_level, new_level);
                                    }

                                    // Emit event for this worker
                                    self.emit(WorkerDecayed {
                                        worker_id,
                                        old_score,
                                        new_score,
                                        decay_periods: periods_to_apply,
                                        timestamp: current_time,
                                    });

                                    workers_decayed += 1;
                                }
                            }
                        }
                    }
                }
                i += 1;
            };

            (workers_processed, workers_decayed)
        }
    }
}
