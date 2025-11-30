// SPDX-License-Identifier: MIT
// BitSage Network - Gamification & Reputation System

#[starknet::contract]
mod Gamification {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, 
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use ciro_contracts::contracts::staking::{IWorkerStakingDispatcher, IWorkerStakingDispatcherTrait};

    // Worker levels
    #[derive(Drop, Serde, Copy, PartialEq)]
    enum WorkerLevel {
        Apprentice,   // 0 XP
        Journeyman,   // 1,000 XP
        Expert,       // 5,000 XP
        Master,       // 15,000 XP
        Legend,       // 50,000 XP
    }

    // Achievement types
    #[derive(Drop, Serde, Copy, PartialEq)]
    enum AchievementType {
        FirstJob,           // Complete 1 job
        Dedicated,          // 30 days uptime
        SpeedDemon,         // Top 1% speed
        ConfidentialExpert, // 100 TEE jobs
        NetworkGuardian,    // Submit valid fraud proof
        Century,            // 100 perfect jobs
        LegendStatus,       // Reach Legend level
    }

    // Worker profile
    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct WorkerProfile {
        worker_id: felt252,
        xp: u64,
        level: u8,
        reputation: u64,
        total_jobs: u64,
        successful_jobs: u64,
        failed_jobs: u64,
        consecutive_successes: u64,
        total_earnings: u256,
        join_timestamp: u64,
        last_active: u64,
    }

    // Achievement record
    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct Achievement {
        achievement_type: u8,
        earned_at: u64,
        reward_amount: u256,
        nft_token_id: u256,
    }

    // Leaderboard entry
    #[derive(Drop, Serde, Copy)]
    struct LeaderboardEntry {
        worker_id: felt252,
        score: u64,
        rank: u64,
    }

    #[storage]
    struct Storage {
        // Admin
        owner: ContractAddress,
        job_manager: ContractAddress,
        ciro_token: ContractAddress,
        staking_contract: ContractAddress, // Added for worker address lookup
        nft_contract: ContractAddress,
        
        // Worker profiles
        worker_profiles: Map<felt252, WorkerProfile>,
        worker_levels: Map<felt252, u8>,
        
        // XP thresholds for levels
        level_thresholds: Map<u8, u64>,
        
        // Achievements
        worker_achievements: Map<(felt252, u8), Achievement>,
        achievement_rewards: Map<u8, u256>,
        total_achievements_earned: u64,
        
        // Leaderboards (monthly)
        current_month: u64,
        earnings_leaderboard: Map<(u64, u64), felt252>, // (month, rank) -> worker_id
        speed_leaderboard: Map<(u64, u64), felt252>,
        reliability_leaderboard: Map<(u64, u64), felt252>,
        tee_leaderboard: Map<(u64, u64), felt252>,
        
        // Monthly stats per worker
        monthly_earnings: Map<(felt252, u64), u256>,
        monthly_avg_speed: Map<(felt252, u64), u64>,
        monthly_uptime: Map<(felt252, u64), u64>,
        monthly_tee_jobs: Map<(felt252, u64), u64>,
        
        // Reputation system
        base_reputation: u64,
        max_reputation: u64,
        daily_reputation_gain: u64,
        job_reputation_gain: u64,
        perfect_streak_bonus: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        XPEarned: XPEarned,
        LevelUp: LevelUp,
        AchievementUnlocked: AchievementUnlocked,
        ReputationChanged: ReputationChanged,
        LeaderboardUpdated: LeaderboardUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct XPEarned {
        #[key]
        worker_id: felt252,
        amount: u64,
        new_total: u64,
        source: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct LevelUp {
        #[key]
        worker_id: felt252,
        old_level: u8,
        new_level: u8,
        reward: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct AchievementUnlocked {
        #[key]
        worker_id: felt252,
        achievement_type: u8,
        reward: u256,
        nft_token_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ReputationChanged {
        #[key]
        worker_id: felt252,
        old_reputation: u64,
        new_reputation: u64,
        change: i64,
    }

    #[derive(Drop, starknet::Event)]
    struct LeaderboardUpdated {
        month: u64,
        leaderboard_type: felt252,
        worker_id: felt252,
        rank: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        ciro_token: ContractAddress,
    ) {
        self.owner.write(owner);
        self.ciro_token.write(ciro_token);
        
        // Set level thresholds
        self.level_thresholds.write(0, 0);      // Apprentice
        self.level_thresholds.write(1, 1000);   // Journeyman
        self.level_thresholds.write(2, 5000);   // Expert
        self.level_thresholds.write(3, 15000);  // Master
        self.level_thresholds.write(4, 50000);  // Legend
        
        // Set achievement rewards (in CIRO, 18 decimals)
        self.achievement_rewards.write(0, 100000000000000000000);    // FirstJob: 100 CIRO
        self.achievement_rewards.write(1, 500000000000000000000);    // Dedicated: 500 CIRO
        self.achievement_rewards.write(2, 1000000000000000000000);   // SpeedDemon: 1000 CIRO
        self.achievement_rewards.write(3, 2000000000000000000000);   // ConfidentialExpert: 2000 CIRO
        self.achievement_rewards.write(4, 5000000000000000000000);   // NetworkGuardian: 5000 CIRO
        self.achievement_rewards.write(5, 3000000000000000000000);   // Century: 3000 CIRO
        self.achievement_rewards.write(6, 10000000000000000000000);  // LegendStatus: 10000 CIRO
        
        // Set reputation parameters
        self.base_reputation.write(100);
        self.max_reputation.write(10000);
        self.daily_reputation_gain.write(10);
        self.job_reputation_gain.write(5);
        self.perfect_streak_bonus.write(50);
        
        // Initialize month
        self.current_month.write(self._get_current_month());
    }

    #[abi(embed_v0)]
    impl GamificationImpl of super::IGamification<ContractState> {
        /// Register new worker profile
        fn register_worker(ref self: ContractState, worker_id: felt252, worker_address: ContractAddress) {
            // Only job manager can register
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");
            
            let profile = WorkerProfile {
                worker_id,
                xp: 0,
                level: 0, // Apprentice
                reputation: self.base_reputation.read(),
                total_jobs: 0,
                successful_jobs: 0,
                failed_jobs: 0,
                consecutive_successes: 0,
                total_earnings: 0,
                join_timestamp: get_block_timestamp(),
                last_active: get_block_timestamp(),
            };
            
            self.worker_profiles.write(worker_id, profile);
            self.worker_levels.write(worker_id, 0);
        }

        /// Add XP to worker (called after job completion)
        fn add_xp(ref self: ContractState, worker_id: felt252, base_xp: u64, job_type: felt252) {
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");
            
            let mut profile = self.worker_profiles.read(worker_id);
            
            // Calculate XP with multipliers
            // Job complexity based on type
            let difficulty_mult: u64 = if job_type == 'AIInference' {
                150 // 1.5x for AI models
            } else if job_type == 'DataPipeline' {
                120 // 1.2x for data jobs
            } else if job_type == 'Render3D' {
                200 // 2.0x for rendering
            } else if job_type == 'ConfidentialVM' {
                250 // 2.5x for TEE/Confidential workloads
            } else {
                100 // 1.0x default
            };
            
            let streak_bonus = self._calculate_streak_bonus(profile.consecutive_successes);
            let final_xp: u64 = ((base_xp * difficulty_mult * streak_bonus) / 10000).try_into().unwrap();
            
            // Add XP
            let old_xp = profile.xp;
            profile.xp += final_xp;
            profile.last_active = get_block_timestamp();
            
            // Check for level up
            let old_level = profile.level;
            let new_level = self._calculate_level(profile.xp);
            
            if new_level > old_level {
                profile.level = new_level;
                self.worker_levels.write(worker_id, new_level);
                
                // Level up reward
                let reward = self._get_level_reward(new_level);
                if reward > 0 {
                    let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
                    token.transfer(starknet::get_contract_address(), reward); // TODO: Get worker address
                }
                
                self.emit(LevelUp {
                    worker_id,
                    old_level,
                    new_level,
                    reward,
                });
                
                // Check for Legend achievement
                if new_level == 4 { // Legend
                    self._award_achievement(worker_id, 6); // LegendStatus
                }
            }
            
            self.worker_profiles.write(worker_id, profile);
            
            self.emit(XPEarned {
                worker_id,
                amount: final_xp,
                new_total: profile.xp,
                source: job_type,
            });
        }

        /// Update reputation (positive or negative)
        fn update_reputation(ref self: ContractState, worker_id: felt252, change: i64) {
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");
            
            let mut profile = self.worker_profiles.read(worker_id);
            let old_reputation = profile.reputation;
            
            // Apply change with bounds checking
            let new_reputation = if change >= 0 {
                let increase: u64 = change.try_into().unwrap();
                let potential_new = old_reputation + increase;
                if potential_new > self.max_reputation.read() {
                    self.max_reputation.read()
                } else {
                    potential_new
                }
            } else {
                let decrease: u64 = (-change).try_into().unwrap();
                if decrease > old_reputation {
                    0
                } else {
                    old_reputation - decrease
                }
            };
            
            profile.reputation = new_reputation;
            self.worker_profiles.write(worker_id, profile);
            
            self.emit(ReputationChanged {
                worker_id,
                old_reputation,
                new_reputation,
                change,
            });
        }

        /// Record job completion
        fn record_job_completion(ref self: ContractState, worker_id: felt252, success: bool, earnings: u256) {
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");
            
            let mut profile = self.worker_profiles.read(worker_id);
            
            profile.total_jobs += 1;
            profile.total_earnings += earnings;
            profile.last_active = get_block_timestamp();
            
            if success {
                profile.successful_jobs += 1;
                profile.consecutive_successes += 1;
                
                // Reputation gain
                let rep_gain = self.job_reputation_gain.read();
                self.update_reputation(worker_id, rep_gain.try_into().unwrap());
                
                // Check for achievements
                if profile.total_jobs == 1 {
                    self._award_achievement(worker_id, 0); // FirstJob
                }
                if profile.successful_jobs == 100 {
                    self._award_achievement(worker_id, 5); // Century
                }
                if profile.consecutive_successes % 100 == 0 {
                    // Perfect streak bonus
                    let bonus = self.perfect_streak_bonus.read();
                    self.update_reputation(worker_id, bonus.try_into().unwrap());
                }
            } else {
                profile.failed_jobs += 1;
                profile.consecutive_successes = 0;
                
                // Reputation loss
                self.update_reputation(worker_id, -50);
            }
            
            self.worker_profiles.write(worker_id, profile);
            
            // Update monthly stats
            let current_month = self._get_current_month();
            let monthly_key = (worker_id, current_month);
            let current_monthly_earnings = self.monthly_earnings.read(monthly_key);
            self.monthly_earnings.write(monthly_key, current_monthly_earnings + earnings);
        }

        /// Award achievement to worker
        fn award_achievement(ref self: ContractState, worker_id: felt252, achievement_type: u8) {
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");
            self._award_achievement(worker_id, achievement_type);
        }

        /// Get worker profile
        fn get_profile(self: @ContractState, worker_id: felt252) -> WorkerProfile {
            self.worker_profiles.read(worker_id)
        }

        /// Get worker level
        fn get_level(self: @ContractState, worker_id: felt252) -> u8 {
            self.worker_levels.read(worker_id)
        }

        /// Get worker reputation
        fn get_reputation(self: @ContractState, worker_id: felt252) -> u64 {
            self.worker_profiles.read(worker_id).reputation
        }

        /// Check if worker has achievement
        fn has_achievement(self: @ContractState, worker_id: felt252, achievement_type: u8) -> bool {
            let achievement = self.worker_achievements.read((worker_id, achievement_type));
            achievement.earned_at > 0
        }

        /// Get leaderboard for current month
        fn get_leaderboard(self: @ContractState, leaderboard_type: felt252, limit: u64) -> Array<felt252> {
            let mut result = ArrayTrait::new();
            let current_month = self.current_month.read();
            
            let mut i: u64 = 1;
            loop {
                if i > limit {
                    break;
                }
                
                let worker_id = if leaderboard_type == 'earnings' {
                    self.earnings_leaderboard.read((current_month, i))
                } else if leaderboard_type == 'speed' {
                    self.speed_leaderboard.read((current_month, i))
                } else if leaderboard_type == 'reliability' {
                    self.reliability_leaderboard.read((current_month, i))
                } else {
                    self.tee_leaderboard.read((current_month, i))
                };
                
                if worker_id != 0 {
                    result.append(worker_id);
                }
                
                i += 1;
            };
            
            result
        }

        /// Admin: Set job manager
        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.job_manager.write(job_manager);
        }

        /// Admin: Set NFT contract
        fn set_nft_contract(ref self: ContractState, nft_contract: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.nft_contract.write(nft_contract);
        }

        fn set_staking_contract(ref self: ContractState, staking_contract: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.staking_contract.write(staking_contract);
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        /// Calculate level from XP
        fn _calculate_level(self: @ContractState, xp: u64) -> u8 {
            if xp >= self.level_thresholds.read(4) {
                4 // Legend
            } else if xp >= self.level_thresholds.read(3) {
                3 // Master
            } else if xp >= self.level_thresholds.read(2) {
                2 // Expert
            } else if xp >= self.level_thresholds.read(1) {
                1 // Journeyman
            } else {
                0 // Apprentice
            }
        }

        /// Calculate streak bonus multiplier
        fn _calculate_streak_bonus(self: @ContractState, streak: u64) -> u64 {
            // Max 2.0x multiplier at 100 streak
            let bonus = 100 + (streak * 100 / 100);
            if bonus > 200 {
                200
            } else {
                bonus
            }
        }

        /// Get level up reward
        fn _get_level_reward(self: @ContractState, level: u8) -> u256 {
            // Rewards per level (in CIRO)
            if level == 1 {
                500000000000000000000 // 500 CIRO
            } else if level == 2 {
                2000000000000000000000 // 2000 CIRO
            } else if level == 3 {
                5000000000000000000000 // 5000 CIRO
            } else if level == 4 {
                15000000000000000000000 // 15000 CIRO
            } else {
                0
            }
        }

        /// Award achievement
        fn _award_achievement(ref self: ContractState, worker_id: felt252, achievement_type: u8) {
            // Check if already earned
            let existing = self.worker_achievements.read((worker_id, achievement_type));
            if existing.earned_at > 0 {
                return;
            }
            
            let reward = self.achievement_rewards.read(achievement_type);
            let nft_token_id: u256 = (self.total_achievements_earned.read() + 1).into();
            
            let achievement = Achievement {
                achievement_type,
                earned_at: get_block_timestamp(),
                reward_amount: reward,
                nft_token_id,
            };
            
            self.worker_achievements.write((worker_id, achievement_type), achievement);
            let new_total = self.total_achievements_earned.read() + 1;
            self.total_achievements_earned.write(new_total);
            
            // Transfer reward
            if reward > 0 {
                let staking = IWorkerStakingDispatcher { contract_address: self.staking_contract.read() };
                let worker_address = staking.get_worker_address(worker_id);
                
                if !worker_address.is_zero() {
                    let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
                    token.transfer(worker_address, reward);
                }
            }
            
            // TODO: Mint NFT
            
            self.emit(AchievementUnlocked {
                worker_id,
                achievement_type,
                reward,
                nft_token_id,
            });
        }

        /// Get current month (for leaderboards)
        fn _get_current_month(self: @ContractState) -> u64 {
            get_block_timestamp() / (30 * 24 * 60 * 60) // Months since epoch
        }
    }
}

#[starknet::interface]
pub trait IGamification<TContractState> {
    fn register_worker(ref self: TContractState, worker_id: felt252, worker_address: starknet::ContractAddress);
    fn add_xp(ref self: TContractState, worker_id: felt252, base_xp: u64, job_type: felt252);
    fn update_reputation(ref self: TContractState, worker_id: felt252, change: i64);
    fn record_job_completion(ref self: TContractState, worker_id: felt252, success: bool, earnings: u256);
    fn award_achievement(ref self: TContractState, worker_id: felt252, achievement_type: u8);
    fn get_profile(self: @TContractState, worker_id: felt252) -> Gamification::WorkerProfile;
    fn get_level(self: @TContractState, worker_id: felt252) -> u8;
    fn get_reputation(self: @TContractState, worker_id: felt252) -> u64;
    fn has_achievement(self: @TContractState, worker_id: felt252, achievement_type: u8) -> bool;
    fn get_leaderboard(self: @TContractState, leaderboard_type: felt252, limit: u64) -> Array<felt252>;
    fn set_job_manager(ref self: TContractState, job_manager: starknet::ContractAddress);
    fn set_nft_contract(ref self: TContractState, nft_contract: starknet::ContractAddress);
    fn set_staking_contract(ref self: TContractState, staking_contract: starknet::ContractAddress);
}

