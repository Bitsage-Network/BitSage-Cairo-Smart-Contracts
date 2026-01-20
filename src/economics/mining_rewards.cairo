//! Mining Rewards Contract
//!
//! Implements per-job mining rewards with daily caps to prevent early validator capture.
//! Based on BitSage Work-First Model with optional staking for increased caps.
//!
//! # Reward Structure
//!
//! - **Base Reward**: 2 SAGE per valid proof (Year 1)
//! - **Halvening**: Rewards decrease yearly (2.0 -> 1.5 -> 1.0 -> 0.75 -> 0.5)
//! - **GPU Multipliers**: Higher-tier GPUs earn more per job
//! - **Daily Caps**: Based on staking tier to prevent monopolization
//!
//! # Daily Caps by Stake Tier
//!
//! - No Stake: 100 SAGE/day
//! - Bronze (1K+ SAGE): 150 SAGE/day
//! - Silver (10K+ SAGE): 200 SAGE/day
//! - Gold (50K+ SAGE): 300 SAGE/day
//! - Platinum (200K+ SAGE): 500 SAGE/day
//!
//! # Mining Pool
//!
//! Total allocation: 300M SAGE
//! Distributed through job completions over ~5+ years

use starknet::{ContractAddress, ClassHash};
use super::super::staking::prover_staking::GpuTier;

/// Staking tier for daily caps
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum StakeTier {
    /// No stake - 100 SAGE/day cap
    #[default]
    None,
    /// 1,000+ SAGE staked - 150 SAGE/day cap
    Bronze,
    /// 10,000+ SAGE staked - 200 SAGE/day cap
    Silver,
    /// 50,000+ SAGE staked - 300 SAGE/day cap
    Gold,
    /// 200,000+ SAGE staked - 500 SAGE/day cap
    Platinum,
}

/// Daily mining statistics for a worker
#[derive(Copy, Drop, Serde, starknet::Store, Default)]
pub struct DailyStats {
    /// Day number (timestamp / 86400)
    pub day: u64,
    /// Jobs completed today
    pub jobs_completed: u32,
    /// SAGE earned today (in wei)
    pub earned_today: u256,
}

/// Worker mining statistics
#[derive(Copy, Drop, Serde, starknet::Store, Default)]
pub struct WorkerMiningStats {
    /// Total jobs completed all time
    pub total_jobs: u64,
    /// Total SAGE earned all time (in wei)
    pub total_earned: u256,
    /// Current day stats
    pub daily_stats: DailyStats,
    /// First job timestamp
    pub first_job_at: u64,
    /// Last job timestamp
    pub last_job_at: u64,
}

/// Mining rewards configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct MiningConfig {
    /// Base reward per job in wei (2 SAGE = 2_000000000000000000)
    pub base_reward_wei: u256,
    /// Contract start timestamp for halvening calculation
    pub start_timestamp: u64,
    /// Seconds per halvening period (1 year = 31536000)
    pub halvening_period_secs: u64,
    /// Daily cap for no stake (100 SAGE)
    pub cap_no_stake_wei: u256,
    /// Daily cap for bronze tier (150 SAGE)
    pub cap_bronze_wei: u256,
    /// Daily cap for silver tier (200 SAGE)
    pub cap_silver_wei: u256,
    /// Daily cap for gold tier (300 SAGE)
    pub cap_gold_wei: u256,
    /// Daily cap for platinum tier (500 SAGE)
    pub cap_platinum_wei: u256,
    /// Stake threshold for bronze tier (1,000 SAGE)
    pub threshold_bronze_wei: u256,
    /// Stake threshold for silver tier (10,000 SAGE)
    pub threshold_silver_wei: u256,
    /// Stake threshold for gold tier (50,000 SAGE)
    pub threshold_gold_wei: u256,
    /// Stake threshold for platinum tier (200,000 SAGE)
    pub threshold_platinum_wei: u256,
    /// Whether mining is paused
    pub paused: bool,
}

/// Result of a reward calculation
#[derive(Copy, Drop, Serde)]
pub struct RewardResult {
    /// Reward amount in wei (0 if capped)
    pub amount: u256,
    /// Whether worker hit daily cap
    pub capped: bool,
    /// Remaining cap for today in wei
    pub remaining_cap: u256,
    /// Worker's stake tier
    pub stake_tier: StakeTier,
}

#[starknet::interface]
pub trait IMiningRewards<TContractState> {
    /// Record a completed job and distribute mining reward
    /// Returns the reward amount (may be 0 if capped)
    fn record_job_completion(
        ref self: TContractState,
        worker: ContractAddress,
        job_id: felt252,
        gpu_tier: GpuTier,
    ) -> u256;

    /// Calculate potential reward without recording (for estimation)
    fn calculate_reward(
        self: @TContractState,
        worker: ContractAddress,
        gpu_tier: GpuTier,
    ) -> RewardResult;

    /// Get worker's mining statistics
    fn get_worker_stats(self: @TContractState, worker: ContractAddress) -> WorkerMiningStats;

    /// Get worker's remaining daily cap
    fn get_remaining_cap(self: @TContractState, worker: ContractAddress) -> u256;

    /// Get worker's stake tier based on staking contract
    fn get_stake_tier(self: @TContractState, worker: ContractAddress) -> StakeTier;

    /// Get current base reward (with halvening applied)
    fn get_current_base_reward(self: @TContractState) -> u256;

    /// Get GPU multiplier in basis points (10000 = 1.0x)
    fn get_gpu_multiplier(self: @TContractState, gpu_tier: GpuTier) -> u16;

    /// Get daily cap for a stake tier
    fn get_daily_cap(self: @TContractState, tier: StakeTier) -> u256;

    /// Get total distributed from mining pool
    fn total_distributed(self: @TContractState) -> u256;

    /// Get remaining in mining pool
    fn remaining_pool(self: @TContractState) -> u256;

    /// Get mining configuration
    fn get_config(self: @TContractState) -> MiningConfig;

    /// Update mining configuration (admin only)
    fn update_config(ref self: TContractState, config: MiningConfig);

    /// Set staking contract address (admin only)
    fn set_staking_contract(ref self: TContractState, staking: ContractAddress);

    /// Set job manager contract address (admin only)
    fn set_job_manager(ref self: TContractState, job_manager: ContractAddress);

    /// Pause/unpause mining (admin only)
    fn set_paused(ref self: TContractState, paused: bool);

    /// Emergency withdraw remaining pool (admin only, requires timelock)
    fn emergency_withdraw(ref self: TContractState, amount: u256, recipient: ContractAddress);
}

#[starknet::contract]
mod MiningRewards {
    use super::{
        IMiningRewards, StakeTier, DailyStats, WorkerMiningStats, MiningConfig, RewardResult,
        GpuTier,
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        get_contract_address,
    };
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // Import staking interface for stake queries
    use super::super::super::staking::prover_staking::{
        IProverStakingDispatcher, IProverStakingDispatcherTrait,
    };

    /// Total mining pool allocation: 300M SAGE
    const MINING_POOL_TOTAL: u256 = 300_000_000_000000000000000000; // 300M * 10^18

    /// Seconds in a day
    const SECONDS_PER_DAY: u64 = 86400;

    /// GPU multipliers in basis points (10000 = 1.0x)
    const GPU_MULTIPLIER_CONSUMER: u16 = 10000;      // 1.0x
    const GPU_MULTIPLIER_WORKSTATION: u16 = 12500;   // 1.25x
    const GPU_MULTIPLIER_DATACENTER: u16 = 15000;    // 1.5x
    const GPU_MULTIPLIER_ENTERPRISE: u16 = 20000;    // 2.0x
    const GPU_MULTIPLIER_FRONTIER: u16 = 25000;      // 2.5x

    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// SAGE token address
        sage_token: ContractAddress,
        /// Staking contract for stake queries
        staking_contract: ContractAddress,
        /// Job manager contract (can call record_job_completion)
        job_manager: ContractAddress,
        /// Treasury address (holds mining pool)
        treasury: ContractAddress,
        /// Mining configuration
        config: MiningConfig,
        /// Worker mining stats
        worker_stats: Map<ContractAddress, WorkerMiningStats>,
        /// Total distributed from pool
        total_distributed: u256,
        /// Emergency withdraw timelock
        emergency_unlock_time: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        RewardDistributed: RewardDistributed,
        DailyCapReached: DailyCapReached,
        ConfigUpdated: ConfigUpdated,
        PoolDepleted: PoolDepleted,
        EmergencyWithdraw: EmergencyWithdraw,
    }

    #[derive(Drop, starknet::Event)]
    struct RewardDistributed {
        #[key]
        worker: ContractAddress,
        #[key]
        job_id: felt252,
        amount: u256,
        gpu_tier: GpuTier,
        stake_tier: StakeTier,
    }

    #[derive(Drop, starknet::Event)]
    struct DailyCapReached {
        #[key]
        worker: ContractAddress,
        stake_tier: StakeTier,
        cap: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        base_reward_wei: u256,
        paused: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct PoolDepleted {
        total_distributed: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyWithdraw {
        amount: u256,
        recipient: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        staking_contract: ContractAddress,
        treasury: ContractAddress,
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.staking_contract.write(staking_contract);
        self.treasury.write(treasury);

        let now = get_block_timestamp();

        // Default configuration
        self.config.write(MiningConfig {
            base_reward_wei: 2_000000000000000000,     // 2 SAGE
            start_timestamp: now,
            halvening_period_secs: 31536000,           // 1 year
            cap_no_stake_wei: 100_000000000000000000,  // 100 SAGE
            cap_bronze_wei: 150_000000000000000000,    // 150 SAGE
            cap_silver_wei: 200_000000000000000000,    // 200 SAGE
            cap_gold_wei: 300_000000000000000000,      // 300 SAGE
            cap_platinum_wei: 500_000000000000000000,  // 500 SAGE
            threshold_bronze_wei: 1_000_000000000000000000,    // 1,000 SAGE
            threshold_silver_wei: 10_000_000000000000000000,   // 10,000 SAGE
            threshold_gold_wei: 50_000_000000000000000000,     // 50,000 SAGE
            threshold_platinum_wei: 200_000_000000000000000000, // 200,000 SAGE
            paused: false,
        });

        self.total_distributed.write(0);
        self.emergency_unlock_time.write(0);
    }

    #[abi(embed_v0)]
    impl MiningRewardsImpl of IMiningRewards<ContractState> {
        fn record_job_completion(
            ref self: ContractState,
            worker: ContractAddress,
            job_id: felt252,
            gpu_tier: GpuTier,
        ) -> u256 {
            let config = self.config.read();
            assert!(!config.paused, "Mining is paused");

            // Only job manager can record completions
            let caller = get_caller_address();
            assert!(
                caller == self.job_manager.read() || caller == self.owner.read(),
                "Unauthorized: only job manager"
            );

            // Check pool not depleted
            let distributed = self.total_distributed.read();
            let remaining = MINING_POOL_TOTAL - distributed;
            if remaining == 0 {
                self.emit(PoolDepleted { total_distributed: distributed });
                return 0;
            }

            // Calculate reward
            let reward_result = self._calculate_reward_internal(worker, gpu_tier);

            if reward_result.amount == 0 {
                // Worker hit daily cap
                self.emit(DailyCapReached {
                    worker,
                    stake_tier: reward_result.stake_tier,
                    cap: self._get_daily_cap_internal(reward_result.stake_tier),
                });
                return 0;
            }

            // Cap to remaining pool
            let actual_reward = if reward_result.amount > remaining {
                remaining
            } else {
                reward_result.amount
            };

            // Update worker stats
            let now = get_block_timestamp();
            let current_day = now / SECONDS_PER_DAY;
            let mut stats = self.worker_stats.read(worker);

            // Reset daily stats if new day
            if stats.daily_stats.day != current_day {
                stats.daily_stats = DailyStats {
                    day: current_day,
                    jobs_completed: 0,
                    earned_today: 0,
                };
            }

            stats.total_jobs += 1;
            stats.total_earned += actual_reward;
            stats.daily_stats.jobs_completed += 1;
            stats.daily_stats.earned_today += actual_reward;
            stats.last_job_at = now;
            if stats.first_job_at == 0 {
                stats.first_job_at = now;
            }

            self.worker_stats.write(worker, stats);

            // Update total distributed
            self.total_distributed.write(distributed + actual_reward);

            // Transfer reward from treasury to worker
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(self.treasury.read(), worker, actual_reward);

            self.emit(RewardDistributed {
                worker,
                job_id,
                amount: actual_reward,
                gpu_tier,
                stake_tier: reward_result.stake_tier,
            });

            actual_reward
        }

        fn calculate_reward(
            self: @ContractState,
            worker: ContractAddress,
            gpu_tier: GpuTier,
        ) -> RewardResult {
            self._calculate_reward_internal(worker, gpu_tier)
        }

        fn get_worker_stats(self: @ContractState, worker: ContractAddress) -> WorkerMiningStats {
            self.worker_stats.read(worker)
        }

        fn get_remaining_cap(self: @ContractState, worker: ContractAddress) -> u256 {
            let stake_tier = self._get_stake_tier_internal(worker);
            let daily_cap = self._get_daily_cap_internal(stake_tier);

            let now = get_block_timestamp();
            let current_day = now / SECONDS_PER_DAY;
            let stats = self.worker_stats.read(worker);

            if stats.daily_stats.day != current_day {
                // New day, full cap available
                daily_cap
            } else if stats.daily_stats.earned_today >= daily_cap {
                0
            } else {
                daily_cap - stats.daily_stats.earned_today
            }
        }

        fn get_stake_tier(self: @ContractState, worker: ContractAddress) -> StakeTier {
            self._get_stake_tier_internal(worker)
        }

        fn get_current_base_reward(self: @ContractState) -> u256 {
            let config = self.config.read();
            self._get_halvened_reward(config)
        }

        fn get_gpu_multiplier(self: @ContractState, gpu_tier: GpuTier) -> u16 {
            match gpu_tier {
                GpuTier::Consumer => GPU_MULTIPLIER_CONSUMER,
                GpuTier::Workstation => GPU_MULTIPLIER_WORKSTATION,
                GpuTier::DataCenter => GPU_MULTIPLIER_DATACENTER,
                GpuTier::Enterprise => GPU_MULTIPLIER_ENTERPRISE,
                GpuTier::Frontier => GPU_MULTIPLIER_FRONTIER,
            }
        }

        fn get_daily_cap(self: @ContractState, tier: StakeTier) -> u256 {
            self._get_daily_cap_internal(tier)
        }

        fn total_distributed(self: @ContractState) -> u256 {
            self.total_distributed.read()
        }

        fn remaining_pool(self: @ContractState) -> u256 {
            MINING_POOL_TOTAL - self.total_distributed.read()
        }

        fn get_config(self: @ContractState) -> MiningConfig {
            self.config.read()
        }

        fn update_config(ref self: ContractState, config: MiningConfig) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.config.write(config);

            self.emit(ConfigUpdated {
                base_reward_wei: config.base_reward_wei,
                paused: config.paused,
            });
        }

        fn set_staking_contract(ref self: ContractState, staking: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.staking_contract.write(staking);
        }

        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.job_manager.write(job_manager);
        }

        fn set_paused(ref self: ContractState, paused: bool) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            let mut config = self.config.read();
            config.paused = paused;
            self.config.write(config);
        }

        fn emergency_withdraw(ref self: ContractState, amount: u256, recipient: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");

            // Require 7-day timelock
            let unlock_time = self.emergency_unlock_time.read();
            let now = get_block_timestamp();

            if unlock_time == 0 {
                // Start timelock
                self.emergency_unlock_time.write(now + 604800); // 7 days
                return;
            }

            assert!(now >= unlock_time, "Timelock not expired");

            // Reset timelock
            self.emergency_unlock_time.write(0);

            // Transfer
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(self.treasury.read(), recipient, amount);

            self.emit(EmergencyWithdraw { amount, recipient });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Calculate reward with halvening, GPU multiplier, and daily cap
        fn _calculate_reward_internal(
            self: @ContractState,
            worker: ContractAddress,
            gpu_tier: GpuTier,
        ) -> RewardResult {
            let config = self.config.read();

            // Get stake tier
            let stake_tier = self._get_stake_tier_internal(worker);
            let daily_cap = self._get_daily_cap_internal(stake_tier);

            // Check current day's earnings
            let now = get_block_timestamp();
            let current_day = now / SECONDS_PER_DAY;
            let stats = self.worker_stats.read(worker);

            let earned_today = if stats.daily_stats.day == current_day {
                stats.daily_stats.earned_today
            } else {
                0
            };

            let remaining_cap = if earned_today >= daily_cap {
                0
            } else {
                daily_cap - earned_today
            };

            if remaining_cap == 0 {
                return RewardResult {
                    amount: 0,
                    capped: true,
                    remaining_cap: 0,
                    stake_tier,
                };
            }

            // Calculate base reward with halvening
            let base_reward = self._get_halvened_reward(config);

            // Apply GPU multiplier
            let multiplier: u256 = self._get_gpu_multiplier_internal(gpu_tier).into();
            let reward = (base_reward * multiplier) / 10000;

            // Cap to remaining daily limit
            let final_reward = if reward > remaining_cap {
                remaining_cap
            } else {
                reward
            };

            let new_remaining = remaining_cap - final_reward;

            RewardResult {
                amount: final_reward,
                capped: new_remaining == 0,
                remaining_cap: new_remaining,
                stake_tier,
            }
        }

        /// Get stake tier from staking contract
        fn _get_stake_tier_internal(self: @ContractState, worker: ContractAddress) -> StakeTier {
            let staking_addr = self.staking_contract.read();

            if staking_addr.is_zero() {
                return StakeTier::None;
            }

            let staking = IProverStakingDispatcher { contract_address: staking_addr };
            let stake = staking.get_stake(worker);
            let config = self.config.read();

            if stake.amount >= config.threshold_platinum_wei {
                StakeTier::Platinum
            } else if stake.amount >= config.threshold_gold_wei {
                StakeTier::Gold
            } else if stake.amount >= config.threshold_silver_wei {
                StakeTier::Silver
            } else if stake.amount >= config.threshold_bronze_wei {
                StakeTier::Bronze
            } else {
                StakeTier::None
            }
        }

        /// Get daily cap for stake tier
        fn _get_daily_cap_internal(self: @ContractState, tier: StakeTier) -> u256 {
            let config = self.config.read();
            match tier {
                StakeTier::None => config.cap_no_stake_wei,
                StakeTier::Bronze => config.cap_bronze_wei,
                StakeTier::Silver => config.cap_silver_wei,
                StakeTier::Gold => config.cap_gold_wei,
                StakeTier::Platinum => config.cap_platinum_wei,
            }
        }

        /// Get GPU multiplier
        fn _get_gpu_multiplier_internal(self: @ContractState, gpu_tier: GpuTier) -> u16 {
            match gpu_tier {
                GpuTier::Consumer => GPU_MULTIPLIER_CONSUMER,
                GpuTier::Workstation => GPU_MULTIPLIER_WORKSTATION,
                GpuTier::DataCenter => GPU_MULTIPLIER_DATACENTER,
                GpuTier::Enterprise => GPU_MULTIPLIER_ENTERPRISE,
                GpuTier::Frontier => GPU_MULTIPLIER_FRONTIER,
            }
        }

        /// Calculate halvened reward based on time since contract start
        /// Year 1: 2.0 SAGE, Year 2: 1.5 SAGE, Year 3: 1.0 SAGE, Year 4: 0.75 SAGE, Year 5+: 0.5 SAGE
        fn _get_halvened_reward(self: @ContractState, config: MiningConfig) -> u256 {
            let now = get_block_timestamp();
            let elapsed = now - config.start_timestamp;
            let year = elapsed / config.halvening_period_secs;

            // Halvening schedule (values in wei)
            // Year 0: 2.0 SAGE = 2_000000000000000000
            // Year 1: 1.5 SAGE = 1_500000000000000000
            // Year 2: 1.0 SAGE = 1_000000000000000000
            // Year 3: 0.75 SAGE = 750000000000000000
            // Year 4+: 0.5 SAGE = 500000000000000000

            if year == 0 {
                config.base_reward_wei  // 2.0 SAGE
            } else if year == 1 {
                (config.base_reward_wei * 75) / 100  // 1.5 SAGE (75% of 2)
            } else if year == 2 {
                config.base_reward_wei / 2  // 1.0 SAGE (50% of 2)
            } else if year == 3 {
                (config.base_reward_wei * 375) / 1000  // 0.75 SAGE (37.5% of 2)
            } else {
                config.base_reward_wei / 4  // 0.5 SAGE (25% of 2)
            }
        }
    }
}
