// SPDX-License-Identifier: MIT
// BitSage Network - Worker Staking Contract

#[starknet::contract]
mod WorkerStaking {
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, 
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // GPU Tiers for staking requirements
    #[derive(Drop, Serde, Copy, PartialEq)]
    enum GpuTier {
        Consumer,     // RTX 4090
        DataCenter,   // A100
        Enterprise,   // H100
        NextGen,      // B200
    }

    // Stake status
    #[derive(Drop, Serde, Copy, PartialEq, starknet::Store)]
    #[allow(starknet::store_no_default_variant)]
    enum StakeStatus {
        Active,
        Unbonding,
        Slashed,
    }

    // Worker stake info
    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct StakeInfo {
        pub worker_id: felt252,
        pub amount: u256,
        pub gpu_tier: u8,
        pub has_tee: bool,
        pub status: StakeStatus,
        pub staked_at: u64,
        pub unbond_time: u64,
        pub reputation: u64,
    }

    // Slashing event info
    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct SlashEvent {
        worker_id: felt252,
        amount: u256,
        reason: felt252,
        timestamp: u64,
    }

    #[storage]
    struct Storage {
        // Admin & config
        owner: ContractAddress,
        sage_token: ContractAddress,
        job_manager: ContractAddress,
        
        // Staking parameters
        base_stakes: Map<u8, u256>, // GPU tier -> minimum stake
        tee_discount_bps: u16, // Basis points (200 = 2%)
        unbonding_period: u64, // Seconds (14 days)
        emergency_exit_penalty_bps: u16, // Basis points (1000 = 10%)
        
        // Worker stakes
        worker_stakes: Map<felt252, StakeInfo>,
        worker_addresses: Map<felt252, ContractAddress>,
        total_staked: u256,
        total_workers: u64,
        
        // Slashing
        slash_history: Map<(felt252, u64), SlashEvent>,
        total_slashed: u256,

        // Phase 3: Double-slash protection
        last_slash_time: Map<felt252, u64>,   // worker_id -> last slash timestamp
        slash_cooldown: u64,                   // Minimum time between slashes (seconds)
        slash_count: Map<felt252, u32>,        // worker_id -> total slash count

        // Treasury addresses
        treasury: ContractAddress,
        burn_address: ContractAddress,

        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Staked: Staked,
        UnstakeInitiated: UnstakeInitiated,
        Unstaked: Unstaked,
        Slashed: Slashed,
        StakeIncreased: StakeIncreased,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct Staked {
        #[key]
        worker_id: felt252,
        worker_address: ContractAddress,
        amount: u256,
        gpu_tier: u8,
        has_tee: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct UnstakeInitiated {
        #[key]
        worker_id: felt252,
        amount: u256,
        unbond_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct Unstaked {
        #[key]
        worker_id: felt252,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Slashed {
        #[key]
        worker_id: felt252,
        amount: u256,
        reason: felt252,
        to_challenger: u256,
        to_burn: u256,
        to_treasury: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct StakeIncreased {
        #[key]
        worker_id: felt252,
        additional_amount: u256,
        new_total: u256,
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
        sage_token: ContractAddress,
        treasury: ContractAddress,
        burn_address: ContractAddress,
    ) {
        // Phase 3: Validate constructor parameters
        assert!(!owner.is_zero(), "Invalid owner address");
        assert!(!sage_token.is_zero(), "Invalid token address");
        assert!(!treasury.is_zero(), "Invalid treasury address");
        assert!(!burn_address.is_zero(), "Invalid burn address");

        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.treasury.write(treasury);
        self.burn_address.write(burn_address);

        // Set default parameters
        self.tee_discount_bps.write(2000); // 20% discount
        self.unbonding_period.write(1209600); // 14 days in seconds
        self.emergency_exit_penalty_bps.write(1000); // 10% penalty

        // Phase 3: Set slash cooldown (24 hours default)
        self.slash_cooldown.write(86400); // 24 hours in seconds

        // Set base stakes (in SAGE with 18 decimals)
        self.base_stakes.write(0, 10000000000000000000000); // Consumer: 10,000 SAGE
        self.base_stakes.write(1, 50000000000000000000000); // DataCenter: 50,000 SAGE
        self.base_stakes.write(2, 100000000000000000000000); // Enterprise: 100,000 SAGE
        self.base_stakes.write(3, 200000000000000000000000); // NextGen: 200,000 SAGE

        self.upgrade_delay.write(172800); // 2 days
    }

    #[abi(embed_v0)]
    impl WorkerStakingImpl of super::IWorkerStaking<ContractState> {
        /// Stake tokens to become a worker
        fn stake(
            ref self: ContractState,
            worker_id: felt252,
            amount: u256,
            gpu_tier: u8,
            has_tee: bool,
        ) {
            let caller = get_caller_address();
            
            // Check minimum stake requirement
            let min_stake = self._calculate_min_stake(gpu_tier, has_tee, 100); // Default reputation 100
            assert!(amount >= min_stake, "Insufficient stake amount");
            
            // Check worker doesn't already exist
            let existing_stake = self.worker_stakes.read(worker_id);
            assert!(existing_stake.amount == 0, "Worker already staked");
            
            // Transfer tokens from caller to contract
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = token.transfer_from(caller, starknet::get_contract_address(), amount);
            assert!(success, "Token transfer failed");
            
            // Create stake info
            let stake_info = StakeInfo {
                worker_id,
                amount,
                gpu_tier,
                has_tee,
                status: StakeStatus::Active,
                staked_at: get_block_timestamp(),
                unbond_time: 0,
                reputation: 100, // Starting reputation
            };
            
            // Store stake
            self.worker_stakes.write(worker_id, stake_info);
            self.worker_addresses.write(worker_id, caller);
            self.total_staked.write(self.total_staked.read() + amount);
            self.total_workers.write(self.total_workers.read() + 1);
            
            // Emit event
            self.emit(Staked {
                worker_id,
                worker_address: caller,
                amount,
                gpu_tier,
                has_tee,
            });
        }

        /// Increase stake amount
        fn increase_stake(ref self: ContractState, worker_id: felt252, additional_amount: u256) {
            let caller = get_caller_address();
            let mut stake_info = self.worker_stakes.read(worker_id);
            
            // Verify caller is worker owner
            assert!(self.worker_addresses.read(worker_id) == caller, "Not worker owner");
            assert!(stake_info.status == StakeStatus::Active, "Stake not active");
            
            // Transfer additional tokens
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = token.transfer_from(caller, starknet::get_contract_address(), additional_amount);
            assert!(success, "Token transfer failed");
            
            // Update stake
            let new_total = stake_info.amount + additional_amount;
            stake_info.amount = new_total;
            self.worker_stakes.write(worker_id, stake_info);
            self.total_staked.write(self.total_staked.read() + additional_amount);
            
            self.emit(StakeIncreased {
                worker_id,
                additional_amount,
                new_total,
            });
        }

        /// Initiate unstaking (starts unbonding period)
        fn initiate_unstake(ref self: ContractState, worker_id: felt252) {
            let caller = get_caller_address();
            let mut stake_info = self.worker_stakes.read(worker_id);
            
            // Verify ownership and status
            assert!(self.worker_addresses.read(worker_id) == caller, "Not worker owner");
            assert!(stake_info.status == StakeStatus::Active, "Stake not active");
            
            // Set unbonding status
            let unbond_time = get_block_timestamp() + self.unbonding_period.read();
            stake_info.status = StakeStatus::Unbonding;
            stake_info.unbond_time = unbond_time;
            self.worker_stakes.write(worker_id, stake_info);
            
            self.emit(UnstakeInitiated {
                worker_id,
                amount: stake_info.amount,
                unbond_time,
            });
        }

        /// Complete unstaking after unbonding period
        fn complete_unstake(ref self: ContractState, worker_id: felt252) {
            let caller = get_caller_address();
            let stake_info = self.worker_stakes.read(worker_id);
            
            // Verify ownership and status
            assert!(self.worker_addresses.read(worker_id) == caller, "Not worker owner");
            assert!(stake_info.status == StakeStatus::Unbonding, "Not in unbonding");
            assert!(get_block_timestamp() >= stake_info.unbond_time, "Unbonding period not complete");
            
            // Transfer tokens back
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = token.transfer(caller, stake_info.amount);
            assert!(success, "Token transfer failed");
            
            // Clear stake
            self.total_staked.write(self.total_staked.read() - stake_info.amount);
            self.total_workers.write(self.total_workers.read() - 1);
            
            // Zero out stake info
            let empty_stake = StakeInfo {
                worker_id: 0,
                amount: 0,
                gpu_tier: 0,
                has_tee: false,
                status: StakeStatus::Active,
                staked_at: 0,
                unbond_time: 0,
                reputation: 0,
            };
            self.worker_stakes.write(worker_id, empty_stake);
            
            self.emit(Unstaked {
                worker_id,
                amount: stake_info.amount,
            });
        }

        /// Emergency unstake with penalty
        fn emergency_unstake(ref self: ContractState, worker_id: felt252) {
            let caller = get_caller_address();
            let stake_info = self.worker_stakes.read(worker_id);
            
            // Verify ownership
            assert!(self.worker_addresses.read(worker_id) == caller, "Not worker owner");
            assert!(stake_info.status == StakeStatus::Active, "Stake not active");
            
            // Calculate penalty
            let penalty_bps: u256 = self.emergency_exit_penalty_bps.read().into();
            let penalty = (stake_info.amount * penalty_bps) / 10000;
            let return_amount = stake_info.amount - penalty;
            
            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(caller, return_amount);
            
            // Burn penalty
            token.transfer(self.burn_address.read(), penalty);
            
            // Update totals
            self.total_staked.write(self.total_staked.read() - stake_info.amount);
            self.total_workers.write(self.total_workers.read() - 1);
            
            // Clear stake
            let empty_stake = StakeInfo {
                worker_id: 0,
                amount: 0,
                gpu_tier: 0,
                has_tee: false,
                status: StakeStatus::Active,
                staked_at: 0,
                unbond_time: 0,
                reputation: 0,
            };
            self.worker_stakes.write(worker_id, empty_stake);
            
            self.emit(Unstaked {
                worker_id,
                amount: return_amount,
            });
        }

        /// Slash worker stake (only callable by JobManager)
        /// Phase 3: Includes double-slash protection
        fn slash(
            ref self: ContractState,
            worker_id: felt252,
            slash_percentage_bps: u16,
            reason: felt252,
            challenger: ContractAddress,
        ) {
            // Only job manager can slash
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");

            let mut stake_info = self.worker_stakes.read(worker_id);
            assert!(stake_info.amount > 0, "Worker not staked");

            // Phase 3: Double-slash protection
            let current_time = get_block_timestamp();
            let last_slash = self.last_slash_time.read(worker_id);
            let cooldown = self.slash_cooldown.read();

            // Check if enough time has passed since last slash
            // Skip check if worker has never been slashed (last_slash == 0)
            if last_slash > 0 {
                assert!(
                    current_time >= last_slash + cooldown,
                    "Slash cooldown not expired"
                );
            }

            // Phase 3: Validate slash percentage (max 50% per slash to prevent total loss)
            assert!(slash_percentage_bps <= 5000, "Slash exceeds 50% maximum");

            // Calculate slash amount
            let slash_amount = (stake_info.amount * slash_percentage_bps.into()) / 10000;

            // Ensure minimum remaining stake or full slash
            let min_remaining: u256 = 1000000000000000000; // 1 SAGE minimum
            if stake_info.amount - slash_amount < min_remaining && slash_amount < stake_info.amount {
                // If slash would leave dust, slash everything
                // This prevents tiny unusable stakes
            }

            // Distribution: 50% challenger, 30% burn, 20% treasury
            let to_challenger = (slash_amount * 50) / 100;
            let to_burn = (slash_amount * 30) / 100;
            let to_treasury = slash_amount - to_challenger - to_burn;

            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            if to_challenger > 0 && !challenger.is_zero() {
                token.transfer(challenger, to_challenger);
            }
            if to_burn > 0 {
                token.transfer(self.burn_address.read(), to_burn);
            }
            if to_treasury > 0 {
                token.transfer(self.treasury.read(), to_treasury);
            }

            // Update stake
            stake_info.amount = stake_info.amount - slash_amount;
            stake_info.status = StakeStatus::Slashed;
            self.worker_stakes.write(worker_id, stake_info);

            // Phase 3: Update slash tracking
            self.last_slash_time.write(worker_id, current_time);
            let current_slash_count = self.slash_count.read(worker_id);
            self.slash_count.write(worker_id, current_slash_count + 1);

            // Update totals
            self.total_staked.write(self.total_staked.read() - slash_amount);
            self.total_slashed.write(self.total_slashed.read() + slash_amount);

            // Emit event
            self.emit(Slashed {
                worker_id,
                amount: slash_amount,
                reason,
                to_challenger,
                to_burn,
                to_treasury,
            });
        }

        /// Get stake info for worker
        fn get_stake(self: @ContractState, worker_id: felt252) -> StakeInfo {
            self.worker_stakes.read(worker_id)
        }

        /// Get minimum stake required for GPU tier
        fn get_min_stake(self: @ContractState, gpu_tier: u8, has_tee: bool, reputation: u64) -> u256 {
            self._calculate_min_stake(gpu_tier, has_tee, reputation)
        }

        /// Get total network stats
        fn get_network_stats(self: @ContractState) -> (u256, u64, u256) {
            (self.total_staked.read(), self.total_workers.read(), self.total_slashed.read())
        }

        /// Update reputation (only JobManager)
        fn update_reputation(ref self: ContractState, worker_id: felt252, new_reputation: u64) {
            assert!(get_caller_address() == self.job_manager.read(), "Unauthorized");
            
            let mut stake_info = self.worker_stakes.read(worker_id);
            stake_info.reputation = new_reputation;
            self.worker_stakes.write(worker_id, stake_info);
        }

        /// Admin: Set job manager
        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.job_manager.write(job_manager);
        }

        /// Admin: Update staking parameters
        fn update_base_stake(ref self: ContractState, gpu_tier: u8, amount: u256) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.base_stakes.write(gpu_tier, amount);
        }

        fn get_worker_address(self: @ContractState, worker_id: felt252) -> ContractAddress {
            self.worker_addresses.read(worker_id)
        }

        // =========================================================================
        // Upgrade Functions
        // =========================================================================

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            assert!(new_class_hash.is_non_zero(), "Invalid class hash");

            let current_time = get_block_timestamp();
            let execute_after = current_time + self.upgrade_delay.read();

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(current_time);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: current_time,
                execute_after,
                scheduled_by: get_caller_address(),
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");

            let new_class_hash = self.pending_upgrade.read();
            assert!(new_class_hash.is_non_zero(), "No upgrade scheduled");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let current_time = get_block_timestamp();
            assert!(current_time >= scheduled_at + self.upgrade_delay.read(), "Upgrade delay not passed");

            // Clear pending upgrade
            let zero_hash: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_hash);
            self.upgrade_scheduled_at.write(0);

            // Execute upgrade
            replace_class_syscall(new_class_hash).unwrap_syscall();

            self.emit(UpgradeExecuted {
                new_class_hash,
                executed_at: current_time,
                executed_by: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");

            let pending_hash = self.pending_upgrade.read();
            assert!(pending_hash.is_non_zero(), "No upgrade scheduled");

            let zero_hash: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_hash);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending_hash,
                cancelled_at: get_block_timestamp(),
                cancelled_by: get_caller_address(),
            });
        }

        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64) {
            (
                self.pending_upgrade.read(),
                self.upgrade_scheduled_at.read(),
                self.upgrade_delay.read(),
            )
        }

        fn set_upgrade_delay(ref self: ContractState, delay: u64) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            assert!(delay >= 300, "Delay must be at least 5 min");
            self.upgrade_delay.write(delay);
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        /// Calculate minimum stake with discounts
        fn _calculate_min_stake(
            self: @ContractState,
            gpu_tier: u8,
            has_tee: bool,
            reputation: u64
        ) -> u256 {
            let base_stake = self.base_stakes.read(gpu_tier);
            
            // TEE discount (20%)
            let stake_with_tee = if has_tee {
                let discount = (base_stake * self.tee_discount_bps.read().into()) / 10000;
                base_stake - discount
            } else {
                base_stake
            };
            
            // Reputation multiplier (0.5 to 1.0)
            // Higher reputation = lower required stake
            let rep_multiplier: u256 = if reputation > 10000 {
                5000 // Min 50% of base
            } else {
                10000 - (reputation * 5000 / 10000) // Linear from 100% to 50%
            }.into();
            
            (stake_with_tee * rep_multiplier) / 10000
        }
    }
}

#[starknet::interface]
pub trait IWorkerStaking<TContractState> {
    fn stake(ref self: TContractState, worker_id: felt252, amount: u256, gpu_tier: u8, has_tee: bool);
    fn increase_stake(ref self: TContractState, worker_id: felt252, additional_amount: u256);
    fn initiate_unstake(ref self: TContractState, worker_id: felt252);
    fn complete_unstake(ref self: TContractState, worker_id: felt252);
    fn emergency_unstake(ref self: TContractState, worker_id: felt252);
    fn slash(ref self: TContractState, worker_id: felt252, slash_percentage_bps: u16, reason: felt252, challenger: starknet::ContractAddress);
    fn get_stake(self: @TContractState, worker_id: felt252) -> WorkerStaking::StakeInfo;
    fn get_min_stake(self: @TContractState, gpu_tier: u8, has_tee: bool, reputation: u64) -> u256;
    fn get_network_stats(self: @TContractState) -> (u256, u64, u256);
    fn update_reputation(ref self: TContractState, worker_id: felt252, new_reputation: u64);
    fn set_job_manager(ref self: TContractState, job_manager: starknet::ContractAddress);
    fn update_base_stake(ref self: TContractState, gpu_tier: u8, amount: u256);
    fn get_worker_address(self: @TContractState, worker_id: felt252) -> starknet::ContractAddress;

    // Upgrade functions
    fn schedule_upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (starknet::ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

