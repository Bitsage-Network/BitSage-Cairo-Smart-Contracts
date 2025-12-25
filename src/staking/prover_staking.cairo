//! Prover Staking Contract
//!
//! This contract manages staking for GPU proof workers in the BitSage Network.
//! Workers must stake SAGE tokens to participate in proof generation.
//!
//! # Slashing Conditions
//!
//! Workers can be slashed for:
//! - Invalid proofs (10% of stake)
//! - Timeouts (5% of stake)
//! - Repeated failures (25% of stake)
//!
//! # Rewards
//!
//! Stakers earn:
//! - 15% APY base staking rewards
//! - Priority access to high-value jobs
//! - Reputation boosts

use starknet::ContractAddress;

/// GPU tier for staking requirements
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum GpuTier {
    /// Consumer GPUs (RTX 30xx, 40xx)
    #[default]
    Consumer,
    /// Workstation GPUs (RTX A6000, L40S)
    Workstation,
    /// Data Center (A100)
    DataCenter,
    /// Enterprise (H100, H200)
    Enterprise,
    /// Frontier (B200)
    Frontier,
}

/// Lockup tier for bonus APY rewards
/// Longer lockups earn higher rewards
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum LockupTier {
    /// No lockup - base APY (15%)
    #[default]
    Flexible,
    /// 30-day lockup - base + 2% bonus (17% total)
    Month,
    /// 90-day lockup - base + 5% bonus (20% total)
    Quarter,
    /// 180-day lockup - base + 8% bonus (23% total)
    HalfYear,
    /// 365-day lockup - base + 12% bonus (27% total)
    Year,
}

/// Lockup tier configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct LockupTierConfig {
    /// Flexible tier bonus (basis points added to base APY)
    pub flexible_bonus_bps: u16,   // 0 = 0%
    /// 30-day tier bonus
    pub month_bonus_bps: u16,      // 200 = 2%
    /// 90-day tier bonus
    pub quarter_bonus_bps: u16,    // 500 = 5%
    /// 180-day tier bonus
    pub half_year_bonus_bps: u16,  // 800 = 8%
    /// 365-day tier bonus
    pub year_bonus_bps: u16,       // 1200 = 12%
    /// Early withdrawal penalty (basis points of principal)
    pub early_withdrawal_penalty_bps: u16, // 500 = 5%
}

/// Slashing reason
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum SlashReason {
    /// Proof failed verification
    #[default]
    InvalidProof,
    /// Job timed out
    Timeout,
    /// Multiple consecutive failures
    RepeatedFailures,
    /// Malicious behavior detected
    Malicious,
    /// Benchmark fraud (claimed wrong GPU)
    BenchmarkFraud,
}

/// Worker stake information
#[derive(Copy, Drop, Serde, starknet::Store, Default)]
pub struct WorkerStake {
    /// Total staked amount
    pub amount: u256,
    /// Locked amount (pending unstake)
    pub locked_amount: u256,
    /// Timestamp of stake
    pub staked_at: u64,
    /// Timestamp of last reward claim
    pub last_claim_at: u64,
    /// GPU tier (determines min stake)
    pub gpu_tier: GpuTier,
    /// Whether worker is active
    pub is_active: bool,
    /// Consecutive failures
    pub consecutive_failures: u8,
    /// Total slashed amount
    pub total_slashed: u256,
    /// Pending rewards
    pub pending_rewards: u256,
    /// SECURITY: Timestamp when worker becomes eligible for jobs (flash loan protection)
    /// Workers must wait this period before being assigned jobs
    pub eligible_at: u64,
    /// Lockup tier for bonus APY
    pub lockup_tier: LockupTier,
    /// Lockup end timestamp (0 for Flexible tier)
    pub lockup_ends_at: u64,
}

/// Staking configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct StakingConfig {
    /// Minimum stake for Consumer tier (in SAGE wei)
    pub min_stake_consumer: u256,
    /// Minimum stake for Workstation tier
    pub min_stake_workstation: u256,
    /// Minimum stake for DataCenter tier
    pub min_stake_datacenter: u256,
    /// Minimum stake for Enterprise tier
    pub min_stake_enterprise: u256,
    /// Minimum stake for Frontier tier
    pub min_stake_frontier: u256,
    /// Slash percentage for invalid proof (basis points, 1000 = 10%)
    pub slash_invalid_proof_bps: u16,
    /// Slash percentage for timeout
    pub slash_timeout_bps: u16,
    /// Slash percentage for repeated failures
    pub slash_repeated_failures_bps: u16,
    /// Slash percentage for malicious behavior
    pub slash_malicious_bps: u16,
    /// Slash percentage for benchmark fraud
    pub slash_benchmark_fraud_bps: u16,
    /// Unstake lockup period (seconds)
    pub unstake_lockup_secs: u64,
    /// Annual percentage yield (basis points, 1500 = 15%)
    pub reward_apy_bps: u16,
    /// Consecutive failures before major slash
    pub max_consecutive_failures: u8,
    /// SECURITY: Minimum time to wait after staking before eligible for jobs (flash loan protection)
    /// Default: 86400 (24 hours)
    pub stake_eligibility_delay_secs: u64,
}

#[starknet::interface]
pub trait IProverStaking<TContractState> {
    /// Stake tokens to become a prover
    fn stake(ref self: TContractState, amount: u256, gpu_tier: GpuTier);
    
    /// Request unstake (starts lockup period)
    fn request_unstake(ref self: TContractState, amount: u256);
    
    /// Complete unstake after lockup
    fn complete_unstake(ref self: TContractState);
    
    /// Claim pending rewards
    fn claim_rewards(ref self: TContractState) -> u256;
    
    /// Slash a worker (called by verifier contract)
    fn slash(ref self: TContractState, worker: ContractAddress, reason: SlashReason, job_id: felt252);
    
    /// Record successful job (called by job manager)
    fn record_success(ref self: TContractState, worker: ContractAddress, job_id: felt252);
    
    /// Get worker stake info
    fn get_stake(self: @TContractState, worker: ContractAddress) -> WorkerStake;
    
    /// Get minimum stake for a GPU tier
    fn get_min_stake(self: @TContractState, gpu_tier: GpuTier) -> u256;
    
    /// Check if worker meets stake requirements
    fn is_eligible(self: @TContractState, worker: ContractAddress) -> bool;
    
    /// Get staking configuration
    fn get_config(self: @TContractState) -> StakingConfig;
    
    /// Update staking configuration (admin only)
    fn update_config(ref self: TContractState, config: StakingConfig);

    /// Set OptimisticTEE contract (admin only)
    fn set_optimistic_tee(ref self: TContractState, tee: ContractAddress);

    /// Set verifier contract (admin only)
    fn set_verifier(ref self: TContractState, verifier: ContractAddress);

    /// Set job manager contract (admin only)
    fn set_job_manager(ref self: TContractState, job_manager: ContractAddress);

    /// Get total staked amount
    fn total_staked(self: @TContractState) -> u256;

    /// Get total slashed amount
    fn total_slashed(self: @TContractState) -> u256;

    // =========================================================================
    // Tier-Based Staking with Lockup Bonuses
    // =========================================================================

    /// Stake with a specific lockup tier for bonus APY
    fn stake_with_lockup(
        ref self: TContractState,
        amount: u256,
        gpu_tier: GpuTier,
        lockup_tier: LockupTier
    );

    /// Get lockup tier configuration
    fn get_lockup_tier_config(self: @TContractState) -> LockupTierConfig;

    /// Update lockup tier configuration (admin only)
    fn set_lockup_tier_config(ref self: TContractState, config: LockupTierConfig);

    /// Get effective APY for a worker (base + lockup bonus)
    fn get_effective_apy(self: @TContractState, worker: ContractAddress) -> u16;

    /// Early unstake with penalty (only for locked stakes)
    fn early_unstake(ref self: TContractState, amount: u256);

    /// Get lockup duration for a tier in seconds
    fn get_lockup_duration(self: @TContractState, lockup_tier: LockupTier) -> u64;

    // =========================================================================
    // Pausable
    // =========================================================================

    /// Pause the contract (owner only)
    fn pause(ref self: TContractState);

    /// Unpause the contract (owner only)
    fn unpause(ref self: TContractState);

    /// Check if contract is paused
    fn is_paused(self: @TContractState) -> bool;

    // =========================================================================
    // Emergency Operations
    // =========================================================================

    /// Emergency withdraw tokens (owner only, requires paused state)
    fn emergency_withdraw(
        ref self: TContractState,
        token: ContractAddress,
        recipient: ContractAddress,
        amount: u256
    );
}

#[starknet::contract]
mod ProverStaking {
    use super::{
        IProverStaking, WorkerStake, StakingConfig, GpuTier, SlashReason,
        LockupTier, LockupTierConfig,
    };
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use core::num::traits::Zero;

    // SECURITY: Slash lockup period - 7 days before slashed worker can re-stake
    const SLASH_LOCKUP_PERIOD: u64 = 604800; // 7 days in seconds

    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// SAGE token address
        sage_token: ContractAddress,
        /// Treasury address (receives slashed funds)
        treasury: ContractAddress,
        /// Verifier contract (can call slash)
        verifier: ContractAddress,
        /// Job manager contract (can record success)
        job_manager: ContractAddress,
        /// Optimistic TEE contract (can call slash on challenge success)
        optimistic_tee: ContractAddress,
        /// Staking configuration
        config: StakingConfig,
        /// Worker stakes
        stakes: Map<ContractAddress, WorkerStake>,
        /// Total staked
        total_staked: u256,
        /// Total slashed
        total_slashed: u256,
        /// Unstake requests: worker -> (amount, unlock_time)
        unstake_requests: Map<ContractAddress, (u256, u64)>,
        /// Whether contract is paused
        paused: bool,
        /// SECURITY: Slash lockup - prevents immediate re-staking after slash
        /// Maps worker address to timestamp when lockup ends
        slash_lockup_until: Map<ContractAddress, u64>,
        /// Lockup tier configuration for bonus APY
        lockup_tier_config: LockupTierConfig,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Staked: Staked,
        StakedWithLockup: StakedWithLockup,
        UnstakeRequested: UnstakeRequested,
        UnstakeCompleted: UnstakeCompleted,
        EarlyUnstake: EarlyUnstake,
        Slashed: Slashed,
        RewardsClaimed: RewardsClaimed,
        SuccessRecorded: SuccessRecorded,
        ConfigUpdated: ConfigUpdated,
        LockupTierConfigUpdated: LockupTierConfigUpdated,
        ContractAddressUpdated: ContractAddressUpdated,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        EmergencyWithdrawal: EmergencyWithdrawal,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractPaused {
        account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractUnpaused {
        account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyWithdrawal {
        #[key]
        token: ContractAddress,
        #[key]
        recipient: ContractAddress,
        amount: u256,
        withdrawn_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractAddressUpdated {
        #[key]
        updated_by: ContractAddress,
        contract_type: felt252, // 'optimistic_tee', 'verifier', 'job_manager'
        old_address: ContractAddress,
        new_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct Staked {
        #[key]
        worker: ContractAddress,
        amount: u256,
        gpu_tier: GpuTier,
        total_stake: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct UnstakeRequested {
        #[key]
        worker: ContractAddress,
        amount: u256,
        unlock_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UnstakeCompleted {
        #[key]
        worker: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Slashed {
        #[key]
        worker: ContractAddress,
        amount: u256,
        reason: SlashReason,
        job_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct RewardsClaimed {
        #[key]
        worker: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct SuccessRecorded {
        #[key]
        worker: ContractAddress,
        job_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        min_stake_consumer: u256,
        reward_apy_bps: u16,
    }

    #[derive(Drop, starknet::Event)]
    struct StakedWithLockup {
        #[key]
        worker: ContractAddress,
        amount: u256,
        gpu_tier: GpuTier,
        lockup_tier: LockupTier,
        lockup_ends_at: u64,
        effective_apy_bps: u16,
        total_stake: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct EarlyUnstake {
        #[key]
        worker: ContractAddress,
        amount: u256,
        penalty: u256,
        received: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct LockupTierConfigUpdated {
        #[key]
        updated_by: ContractAddress,
        month_bonus_bps: u16,
        quarter_bonus_bps: u16,
        half_year_bonus_bps: u16,
        year_bonus_bps: u16,
        early_withdrawal_penalty_bps: u16,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        treasury: ContractAddress,
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.treasury.write(treasury);
        
        // Default configuration
        self.config.write(StakingConfig {
            min_stake_consumer: 1000_000000000000000000,      // 1,000 SAGE
            min_stake_workstation: 2500_000000000000000000,   // 2,500 SAGE
            min_stake_datacenter: 5000_000000000000000000,    // 5,000 SAGE
            min_stake_enterprise: 10000_000000000000000000,   // 10,000 SAGE
            min_stake_frontier: 25000_000000000000000000,     // 25,000 SAGE
            slash_invalid_proof_bps: 1000,    // 10%
            slash_timeout_bps: 500,            // 5%
            slash_repeated_failures_bps: 2500, // 25%
            slash_malicious_bps: 5000,         // 50%
            slash_benchmark_fraud_bps: 7500,   // 75%
            unstake_lockup_secs: 604800,       // 7 days
            reward_apy_bps: 1500,              // 15% APY
            max_consecutive_failures: 3,
            stake_eligibility_delay_secs: 86400, // 24 hours - flash loan protection
        });
        
        self.total_staked.write(0);
        self.total_slashed.write(0);
        self.paused.write(false);

        // Initialize lockup tier configuration
        self.lockup_tier_config.write(LockupTierConfig {
            flexible_bonus_bps: 0,       // No bonus for flexible staking
            month_bonus_bps: 200,        // +2% for 30-day lockup (17% total)
            quarter_bonus_bps: 500,      // +5% for 90-day lockup (20% total)
            half_year_bonus_bps: 800,    // +8% for 180-day lockup (23% total)
            year_bonus_bps: 1200,        // +12% for 365-day lockup (27% total)
            early_withdrawal_penalty_bps: 500, // 5% penalty for early withdrawal
        });
    }

    #[abi(embed_v0)]
    impl ProverStakingImpl of IProverStaking<ContractState> {
        fn stake(ref self: ContractState, amount: u256, gpu_tier: GpuTier) {
            assert!(!self.paused.read(), "Contract is paused");

            // SECURITY: Amount validation
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();

            // SECURITY: Check slash lockup - prevent immediate re-stake after slashing
            let slash_lockup_end = self.slash_lockup_until.read(caller);
            let now = get_block_timestamp();
            assert!(now >= slash_lockup_end, "Slash lockup period not expired");
            let config = self.config.read();
            
            // Check minimum stake
            let min_stake = self._get_min_stake_internal(gpu_tier, @config);
            let mut stake = self.stakes.read(caller);
            let new_total = stake.amount + amount;
            assert!(new_total >= min_stake, "Insufficient stake for tier");
            
            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(caller, starknet::get_contract_address(), amount);
            
            // Calculate pending rewards before updating
            if stake.amount > 0 {
                let rewards = self._calculate_rewards(@stake, @config);
                stake.pending_rewards += rewards;
            }
            
            // Update stake
            let now = get_block_timestamp();
            stake.amount = new_total;
            stake.gpu_tier = gpu_tier;
            stake.is_active = true;
            stake.last_claim_at = now;
            if stake.staked_at == 0 {
                stake.staked_at = now;
            }

            // SECURITY: Set eligibility delay for flash loan protection
            // New stakes and additional stakes must wait before being eligible for jobs
            stake.eligible_at = now + config.stake_eligibility_delay_secs;
            
            self.stakes.write(caller, stake);
            
            // Update total
            let total = self.total_staked.read() + amount;
            self.total_staked.write(total);
            
            self.emit(Staked {
                worker: caller,
                amount,
                gpu_tier,
                total_stake: new_total,
            });
        }

        fn request_unstake(ref self: ContractState, amount: u256) {
            // SECURITY: Amount validation
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();
            let mut stake = self.stakes.read(caller);

            assert!(stake.amount >= amount, "Insufficient stake");
            assert!(stake.locked_amount == 0, "Pending unstake exists");
            
            let config = self.config.read();
            let unlock_time = get_block_timestamp() + config.unstake_lockup_secs;
            
            // Lock the amount
            stake.locked_amount = amount;
            self.stakes.write(caller, stake);
            
            // Record request
            self.unstake_requests.write(caller, (amount, unlock_time));
            
            self.emit(UnstakeRequested {
                worker: caller,
                amount,
                unlock_time,
            });
        }

        fn complete_unstake(ref self: ContractState) {
            let caller = get_caller_address();
            let (amount, unlock_time) = self.unstake_requests.read(caller);
            
            assert!(amount > 0, "No pending unstake");
            assert!(get_block_timestamp() >= unlock_time, "Lockup not expired");
            
            let mut stake = self.stakes.read(caller);
            stake.amount -= amount;
            stake.locked_amount = 0;
            
            // Check if still meets minimum
            let config = self.config.read();
            let min_stake = self._get_min_stake_internal(stake.gpu_tier, @config);
            if stake.amount < min_stake {
                stake.is_active = false;
            }
            
            self.stakes.write(caller, stake);
            self.unstake_requests.write(caller, (0, 0));
            
            // Update total
            let total = self.total_staked.read() - amount;
            self.total_staked.write(total);
            
            // Transfer tokens back
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(caller, amount);
            
            self.emit(UnstakeCompleted {
                worker: caller,
                amount,
            });
        }

        fn claim_rewards(ref self: ContractState) -> u256 {
            let caller = get_caller_address();
            let mut stake = self.stakes.read(caller);
            let config = self.config.read();
            
            // Calculate rewards
            let new_rewards = self._calculate_rewards(@stake, @config);
            let total_rewards = stake.pending_rewards + new_rewards;
            
            assert!(total_rewards > 0, "No rewards to claim");
            
            // Update stake
            stake.pending_rewards = 0;
            stake.last_claim_at = get_block_timestamp();
            self.stakes.write(caller, stake);
            
            // Transfer rewards from treasury
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(self.treasury.read(), caller, total_rewards);
            
            self.emit(RewardsClaimed {
                worker: caller,
                amount: total_rewards,
            });
            
            total_rewards
        }

        fn slash(
            ref self: ContractState,
            worker: ContractAddress,
            reason: SlashReason,
            job_id: felt252,
        ) {
            // Only verifier, job manager, or optimistic_tee can slash
            let caller = get_caller_address();
            assert!(
                caller == self.verifier.read()
                    || caller == self.job_manager.read()
                    || caller == self.optimistic_tee.read()
                    || caller == self.owner.read(),
                "Unauthorized"
            );
            
            let mut stake = self.stakes.read(worker);
            let config = self.config.read();
            
            // Determine slash percentage
            let slash_bps: u256 = match reason {
                SlashReason::InvalidProof => config.slash_invalid_proof_bps.into(),
                SlashReason::Timeout => config.slash_timeout_bps.into(),
                SlashReason::RepeatedFailures => config.slash_repeated_failures_bps.into(),
                SlashReason::Malicious => config.slash_malicious_bps.into(),
                SlashReason::BenchmarkFraud => config.slash_benchmark_fraud_bps.into(),
            };
            
            // Calculate slash amount
            let slash_amount = (stake.amount * slash_bps) / 10000;
            
            // Apply slash
            stake.amount -= slash_amount;
            stake.total_slashed += slash_amount;
            stake.consecutive_failures += 1;
            
            // Check if should be deactivated
            let min_stake = self._get_min_stake_internal(stake.gpu_tier, @config);
            if stake.amount < min_stake || stake.consecutive_failures >= config.max_consecutive_failures {
                stake.is_active = false;
            }
            
            self.stakes.write(worker, stake);
            
            // Update totals
            let total_staked = self.total_staked.read() - slash_amount;
            self.total_staked.write(total_staked);
            
            let total_slashed = self.total_slashed.read() + slash_amount;
            self.total_slashed.write(total_slashed);
            
            // Transfer slashed amount to treasury
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(self.treasury.read(), slash_amount);

            // SECURITY: Set slash lockup period to prevent immediate re-staking
            let now = get_block_timestamp();
            self.slash_lockup_until.write(worker, now + SLASH_LOCKUP_PERIOD);

            self.emit(Slashed {
                worker,
                amount: slash_amount,
                reason,
                job_id,
            });
        }

        fn record_success(ref self: ContractState, worker: ContractAddress, job_id: felt252) {
            let caller = get_caller_address();
            assert!(
                caller == self.job_manager.read() || caller == self.owner.read(),
                "Unauthorized"
            );
            
            let mut stake = self.stakes.read(worker);
            
            // Reset consecutive failures on success
            stake.consecutive_failures = 0;
            
            self.stakes.write(worker, stake);
            
            self.emit(SuccessRecorded { worker, job_id });
        }

        fn get_stake(self: @ContractState, worker: ContractAddress) -> WorkerStake {
            self.stakes.read(worker)
        }

        fn get_min_stake(self: @ContractState, gpu_tier: GpuTier) -> u256 {
            let config = self.config.read();
            self._get_min_stake_internal(gpu_tier, @config)
        }

        fn is_eligible(self: @ContractState, worker: ContractAddress) -> bool {
            let stake = self.stakes.read(worker);
            let config = self.config.read();
            let min_stake = self._get_min_stake_internal(stake.gpu_tier, @config);
            let now = get_block_timestamp();

            // SECURITY: Check eligibility delay has passed (flash loan protection)
            stake.is_active
                && stake.amount >= min_stake
                && stake.consecutive_failures < config.max_consecutive_failures
                && now >= stake.eligible_at
        }

        fn get_config(self: @ContractState) -> StakingConfig {
            self.config.read()
        }

        fn update_config(ref self: ContractState, config: StakingConfig) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.config.write(config);

            self.emit(ConfigUpdated {
                min_stake_consumer: config.min_stake_consumer,
                reward_apy_bps: config.reward_apy_bps,
            });
        }

        /// Set OptimisticTEE contract address (admin only)
        fn set_optimistic_tee(ref self: ContractState, tee: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            let old_address = self.optimistic_tee.read();
            self.optimistic_tee.write(tee);

            self.emit(ContractAddressUpdated {
                updated_by: get_caller_address(),
                contract_type: 'optimistic_tee',
                old_address,
                new_address: tee,
            });
        }

        /// Set verifier contract address (admin only)
        fn set_verifier(ref self: ContractState, verifier: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            let old_address = self.verifier.read();
            self.verifier.write(verifier);

            self.emit(ContractAddressUpdated {
                updated_by: get_caller_address(),
                contract_type: 'verifier',
                old_address,
                new_address: verifier,
            });
        }

        /// Set job manager contract address (admin only)
        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            let old_address = self.job_manager.read();
            self.job_manager.write(job_manager);

            self.emit(ContractAddressUpdated {
                updated_by: get_caller_address(),
                contract_type: 'job_manager',
                old_address,
                new_address: job_manager,
            });
        }

        fn total_staked(self: @ContractState) -> u256 {
            self.total_staked.read()
        }

        fn total_slashed(self: @ContractState) -> u256 {
            self.total_slashed.read()
        }

        // =========================================================================
        // Tier-Based Staking with Lockup Bonuses
        // =========================================================================

        fn stake_with_lockup(
            ref self: ContractState,
            amount: u256,
            gpu_tier: GpuTier,
            lockup_tier: LockupTier
        ) {
            assert!(!self.paused.read(), "Contract is paused");
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();
            let now = get_block_timestamp();

            // Check slash lockup
            let slash_lockup_end = self.slash_lockup_until.read(caller);
            assert!(now >= slash_lockup_end, "Slash lockup period not expired");

            let config = self.config.read();
            let lockup_config = self.lockup_tier_config.read();

            // Check minimum stake
            let min_stake = self._get_min_stake_internal(gpu_tier, @config);
            let mut stake = self.stakes.read(caller);
            let new_total = stake.amount + amount;
            assert!(new_total >= min_stake, "Insufficient stake for tier");

            // Cannot change lockup tier if already locked
            if stake.lockup_ends_at > now && stake.lockup_tier != lockup_tier {
                panic!("Cannot change lockup tier while locked");
            }

            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(caller, starknet::get_contract_address(), amount);

            // Calculate pending rewards before updating
            if stake.amount > 0 {
                let rewards = self._calculate_rewards_with_lockup(@stake, @config, @lockup_config);
                stake.pending_rewards += rewards;
            }

            // Calculate lockup end time
            let lockup_duration = self._get_lockup_duration(lockup_tier);
            let lockup_ends_at = now + lockup_duration;

            // Update stake
            stake.amount = new_total;
            stake.gpu_tier = gpu_tier;
            stake.is_active = true;
            stake.last_claim_at = now;
            stake.lockup_tier = lockup_tier;
            stake.lockup_ends_at = lockup_ends_at;
            if stake.staked_at == 0 {
                stake.staked_at = now;
            }

            // Set eligibility delay
            stake.eligible_at = now + config.stake_eligibility_delay_secs;

            self.stakes.write(caller, stake);

            // Update total
            let total = self.total_staked.read() + amount;
            self.total_staked.write(total);

            // Calculate effective APY for event
            let effective_apy = self._get_effective_apy_internal(lockup_tier, @config, @lockup_config);

            self.emit(StakedWithLockup {
                worker: caller,
                amount,
                gpu_tier,
                lockup_tier,
                lockup_ends_at,
                effective_apy_bps: effective_apy,
                total_stake: new_total,
            });
        }

        fn get_lockup_tier_config(self: @ContractState) -> LockupTierConfig {
            self.lockup_tier_config.read()
        }

        fn set_lockup_tier_config(ref self: ContractState, config: LockupTierConfig) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");

            // Validate: bonuses should be reasonable (max 30% total)
            assert!(config.flexible_bonus_bps <= 3000, "Flexible bonus too high");
            assert!(config.month_bonus_bps <= 3000, "Month bonus too high");
            assert!(config.quarter_bonus_bps <= 3000, "Quarter bonus too high");
            assert!(config.half_year_bonus_bps <= 3000, "Half year bonus too high");
            assert!(config.year_bonus_bps <= 3000, "Year bonus too high");

            // Validate: early withdrawal penalty should be reasonable (max 25%)
            assert!(config.early_withdrawal_penalty_bps <= 2500, "Penalty too high");

            // Validate: higher tiers should have higher bonuses
            assert!(config.month_bonus_bps >= config.flexible_bonus_bps, "Month should >= Flexible");
            assert!(config.quarter_bonus_bps >= config.month_bonus_bps, "Quarter should >= Month");
            assert!(config.half_year_bonus_bps >= config.quarter_bonus_bps, "HalfYear should >= Quarter");
            assert!(config.year_bonus_bps >= config.half_year_bonus_bps, "Year should >= HalfYear");

            self.lockup_tier_config.write(config);

            self.emit(LockupTierConfigUpdated {
                updated_by: get_caller_address(),
                month_bonus_bps: config.month_bonus_bps,
                quarter_bonus_bps: config.quarter_bonus_bps,
                half_year_bonus_bps: config.half_year_bonus_bps,
                year_bonus_bps: config.year_bonus_bps,
                early_withdrawal_penalty_bps: config.early_withdrawal_penalty_bps,
            });
        }

        fn get_effective_apy(self: @ContractState, worker: ContractAddress) -> u16 {
            let stake = self.stakes.read(worker);
            let config = self.config.read();
            let lockup_config = self.lockup_tier_config.read();
            self._get_effective_apy_internal(stake.lockup_tier, @config, @lockup_config)
        }

        fn early_unstake(ref self: ContractState, amount: u256) {
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();
            let now = get_block_timestamp();
            let mut stake = self.stakes.read(caller);
            let lockup_config = self.lockup_tier_config.read();

            assert!(stake.amount >= amount, "Insufficient stake");
            assert!(stake.locked_amount == 0, "Pending unstake exists");

            // Check if lockup is still active
            let is_early = now < stake.lockup_ends_at;
            assert!(is_early, "Lockup expired - use regular unstake");

            // Calculate penalty
            let penalty_bps: u256 = lockup_config.early_withdrawal_penalty_bps.into();
            let penalty = (amount * penalty_bps) / 10000;
            let received = amount - penalty;

            // Update stake
            stake.amount -= amount;

            // Check if still meets minimum
            let config = self.config.read();
            let min_stake = self._get_min_stake_internal(stake.gpu_tier, @config);
            if stake.amount < min_stake {
                stake.is_active = false;
            }

            // If fully unstaked, reset lockup
            if stake.amount == 0 {
                stake.lockup_tier = LockupTier::Flexible;
                stake.lockup_ends_at = 0;
            }

            self.stakes.write(caller, stake);

            // Update total staked
            let total = self.total_staked.read() - amount;
            self.total_staked.write(total);

            // Transfer tokens (minus penalty)
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            if received > 0 {
                token.transfer(caller, received);
            }

            // Transfer penalty to treasury
            if penalty > 0 {
                token.transfer(self.treasury.read(), penalty);
            }

            self.emit(EarlyUnstake {
                worker: caller,
                amount,
                penalty,
                received,
            });
        }

        fn get_lockup_duration(self: @ContractState, lockup_tier: LockupTier) -> u64 {
            self._get_lockup_duration(lockup_tier)
        }

        // =========================================================================
        // Pausable
        // =========================================================================

        fn pause(ref self: ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            assert!(!self.paused.read(), "Already paused");
            self.paused.write(true);
            self.emit(ContractPaused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            assert!(self.paused.read(), "Not paused");
            self.paused.write(false);
            self.emit(ContractUnpaused { account: get_caller_address() });
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        // =========================================================================
        // Emergency Operations
        // =========================================================================

        fn emergency_withdraw(
            ref self: ContractState,
            token: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");

            // SECURITY: Only allow emergency withdrawal when contract is paused
            assert!(self.paused.read(), "Contract must be paused");

            // Validate recipient
            assert!(!recipient.is_zero(), "Invalid recipient");

            // Validate amount
            assert!(amount > 0, "Amount must be greater than 0");

            // Transfer tokens
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let success = token_dispatcher.transfer(recipient, amount);
            assert!(success, "Emergency withdrawal failed");

            self.emit(EmergencyWithdrawal {
                token,
                recipient,
                amount,
                withdrawn_by: get_caller_address(),
            });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _get_min_stake_internal(
            self: @ContractState,
            gpu_tier: GpuTier,
            config: @StakingConfig,
        ) -> u256 {
            match gpu_tier {
                GpuTier::Consumer => *config.min_stake_consumer,
                GpuTier::Workstation => *config.min_stake_workstation,
                GpuTier::DataCenter => *config.min_stake_datacenter,
                GpuTier::Enterprise => *config.min_stake_enterprise,
                GpuTier::Frontier => *config.min_stake_frontier,
            }
        }

        fn _calculate_rewards(
            self: @ContractState,
            stake: @WorkerStake,
            config: @StakingConfig,
        ) -> u256 {
            let now = get_block_timestamp();
            let time_elapsed = now - *stake.last_claim_at;

            if time_elapsed == 0 || *stake.amount == 0 {
                return 0;
            }

            // Calculate rewards: amount * APY * time / year
            // APY is in basis points (1500 = 15%)
            let apy: u256 = (*config.reward_apy_bps).into();
            let seconds_per_year: u256 = 31536000; // 365 * 24 * 60 * 60

            let rewards = (*stake.amount * apy * time_elapsed.into())
                / (10000 * seconds_per_year);

            rewards
        }

        /// Calculate rewards with lockup tier bonus
        fn _calculate_rewards_with_lockup(
            self: @ContractState,
            stake: @WorkerStake,
            config: @StakingConfig,
            lockup_config: @LockupTierConfig,
        ) -> u256 {
            let now = get_block_timestamp();
            let time_elapsed = now - *stake.last_claim_at;

            if time_elapsed == 0 || *stake.amount == 0 {
                return 0;
            }

            // Get effective APY including lockup bonus
            let effective_apy = self._get_effective_apy_internal(*stake.lockup_tier, config, lockup_config);
            let apy: u256 = effective_apy.into();
            let seconds_per_year: u256 = 31536000; // 365 * 24 * 60 * 60

            let rewards = (*stake.amount * apy * time_elapsed.into())
                / (10000 * seconds_per_year);

            rewards
        }

        /// Get lockup duration in seconds for a tier
        fn _get_lockup_duration(self: @ContractState, lockup_tier: LockupTier) -> u64 {
            match lockup_tier {
                LockupTier::Flexible => 0,           // No lockup
                LockupTier::Month => 2592000,        // 30 days (30 * 24 * 60 * 60)
                LockupTier::Quarter => 7776000,      // 90 days (90 * 24 * 60 * 60)
                LockupTier::HalfYear => 15552000,    // 180 days (180 * 24 * 60 * 60)
                LockupTier::Year => 31536000,        // 365 days (365 * 24 * 60 * 60)
            }
        }

        /// Get effective APY (base + lockup bonus)
        fn _get_effective_apy_internal(
            self: @ContractState,
            lockup_tier: LockupTier,
            config: @StakingConfig,
            lockup_config: @LockupTierConfig,
        ) -> u16 {
            let base_apy = *config.reward_apy_bps;
            let bonus = match lockup_tier {
                LockupTier::Flexible => *lockup_config.flexible_bonus_bps,
                LockupTier::Month => *lockup_config.month_bonus_bps,
                LockupTier::Quarter => *lockup_config.quarter_bonus_bps,
                LockupTier::HalfYear => *lockup_config.half_year_bonus_bps,
                LockupTier::Year => *lockup_config.year_bonus_bps,
            };
            base_apy + bonus
        }
    }
}

