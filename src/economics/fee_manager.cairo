// =============================================================================
// FEE MANAGER CONTRACT - BitSage Network
// =============================================================================
//
// Implements the core fee economics based on BitSage Financial Model v2:
//
// Protocol Fee: 20% of GMV
// Fee Split:
//   - 70% → Burned (deflationary pressure)
//   - 20% → Treasury (operations)
//   - 10% → Stakers (real yield)
//
// This creates break-even GMV at ~$1.875M/month with $75K/month OpEx
//
// =============================================================================

use starknet::{ContractAddress, ClassHash};

// =============================================================================
// Constants (Basis Points)
// =============================================================================

const PROTOCOL_FEE_BPS: u16 = 2000;      // 20% of GMV
const BURN_SPLIT_BPS: u16 = 7000;        // 70% of protocol fee → burn
const TREASURY_SPLIT_BPS: u16 = 2000;    // 20% of protocol fee → treasury
const STAKER_SPLIT_BPS: u16 = 1000;      // 10% of protocol fee → stakers
const BPS_DENOMINATOR: u256 = 10000;

// =============================================================================
// Data Types
// =============================================================================

/// Fee distribution configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FeeConfig {
    /// Protocol fee in basis points (default: 2000 = 20%)
    pub protocol_fee_bps: u16,
    /// Burn percentage of protocol fee (default: 7000 = 70%)
    pub burn_split_bps: u16,
    /// Treasury percentage of protocol fee (default: 2000 = 20%)
    pub treasury_split_bps: u16,
    /// Staker percentage of protocol fee (default: 1000 = 10%)
    pub staker_split_bps: u16,
}

/// Fee distribution result
#[derive(Copy, Drop, Serde)]
pub struct FeeBreakdown {
    /// Total GMV (gross transaction value)
    pub gmv: u256,
    /// Protocol fee collected (GMV * protocol_fee_bps / 10000)
    pub protocol_fee: u256,
    /// Amount to burn
    pub burn_amount: u256,
    /// Amount to treasury
    pub treasury_amount: u256,
    /// Amount to stakers
    pub staker_amount: u256,
    /// Amount to worker (GMV - protocol_fee)
    pub worker_payment: u256,
}

/// Accumulated fee statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FeeStats {
    /// Total GMV processed
    pub total_gmv: u256,
    /// Total protocol fees collected
    pub total_protocol_fees: u256,
    /// Total tokens burned
    pub total_burned: u256,
    /// Total sent to treasury
    pub total_to_treasury: u256,
    /// Total distributed to stakers
    pub total_to_stakers: u256,
    /// Total paid to workers
    pub total_to_workers: u256,
    /// Number of transactions processed
    pub transaction_count: u64,
}

/// Staker reward tracking
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct StakerReward {
    /// Accumulated rewards pending claim
    pub pending_rewards: u256,
    /// Total rewards claimed
    pub total_claimed: u256,
    /// Last epoch rewards were calculated
    pub last_calculated_epoch: u64,
    /// Staker's share of total stake (basis points, updated on stake change)
    pub stake_share_bps: u256,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IFeeManager<TContractState> {
    // === Admin Functions ===
    fn update_fee_config(ref self: TContractState, config: FeeConfig);
    fn set_staking_contract(ref self: TContractState, staking: ContractAddress);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    
    // === Core Fee Processing ===
    /// Process a transaction and distribute fees
    fn process_transaction(
        ref self: TContractState,
        gmv: u256,
        worker: ContractAddress,
    ) -> FeeBreakdown;
    
    /// Calculate fee breakdown without processing
    fn calculate_fees(self: @TContractState, gmv: u256) -> FeeBreakdown;
    
    // === Staker Rewards ===
    /// Claim accumulated staker rewards
    fn claim_staker_rewards(ref self: TContractState) -> u256;
    
    /// Update staker's reward share (called by staking contract)
    fn update_staker_share(
        ref self: TContractState,
        staker: ContractAddress,
        stake_share_bps: u256,
    );
    
    /// Get pending rewards for a staker
    fn get_pending_rewards(self: @TContractState, staker: ContractAddress) -> u256;
    
    // === View Functions ===
    fn get_fee_config(self: @TContractState) -> FeeConfig;
    fn get_fee_stats(self: @TContractState) -> FeeStats;
    fn get_staker_reward(self: @TContractState, staker: ContractAddress) -> StakerReward;
    fn get_current_epoch(self: @TContractState) -> u64;
    fn get_epoch_staker_pool(self: @TContractState, epoch: u64) -> u256;

    // === Upgrade Functions ===
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod FeeManager {
    use super::{
        IFeeManager, FeeConfig, FeeBreakdown, FeeStats, StakerReward,
        PROTOCOL_FEE_BPS, BURN_SPLIT_BPS, TREASURY_SPLIT_BPS, STAKER_SPLIT_BPS,
        BPS_DENOMINATOR,
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use core::num::traits::Zero;

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// SAGE token address
        sage_token: ContractAddress,
        /// Treasury address
        treasury: ContractAddress,
        /// Staking contract address
        staking_contract: ContractAddress,
        /// Job manager contract (authorized caller)
        job_manager: ContractAddress,
        /// Fee configuration
        config: FeeConfig,
        /// Accumulated statistics
        stats: FeeStats,
        /// Staker rewards tracking
        staker_rewards: Map<ContractAddress, StakerReward>,
        /// Epoch staker pool (tokens accumulated per epoch for stakers)
        epoch_staker_pool: Map<u64, u256>,
        /// Current epoch number
        current_epoch: u64,
        /// Total active staker share (sum of all staker_share_bps)
        total_staker_share: u256,
        /// Paused state
        paused: bool,
        /// Burn address (zero address for Starknet)
        burn_address: ContractAddress,
        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransactionProcessed: TransactionProcessed,
        FeesDistributed: FeesDistributed,
        TokensBurned: TokensBurned,
        StakerRewardsClaimed: StakerRewardsClaimed,
        ConfigUpdated: ConfigUpdated,
        EpochAdvanced: EpochAdvanced,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionProcessed {
        #[key]
        worker: ContractAddress,
        gmv: u256,
        protocol_fee: u256,
        worker_payment: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct FeesDistributed {
        burn_amount: u256,
        treasury_amount: u256,
        staker_pool_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct TokensBurned {
        amount: u256,
        total_burned: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct StakerRewardsClaimed {
        #[key]
        staker: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        protocol_fee_bps: u16,
        burn_split_bps: u16,
    }

    #[derive(Drop, starknet::Event)]
    struct EpochAdvanced {
        old_epoch: u64,
        new_epoch: u64,
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

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        treasury: ContractAddress,
        job_manager: ContractAddress,
    ) {
        // Phase 3: Validate constructor parameters
        assert!(!owner.is_zero(), "Invalid owner address");
        assert!(!sage_token.is_zero(), "Invalid token address");
        assert!(!treasury.is_zero(), "Invalid treasury address");
        // Note: job_manager can be zero initially and set later

        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.treasury.write(treasury);
        self.job_manager.write(job_manager);
        
        // Default fee configuration from BitSage Financial Model v2
        self.config.write(FeeConfig {
            protocol_fee_bps: PROTOCOL_FEE_BPS,      // 20%
            burn_split_bps: BURN_SPLIT_BPS,          // 70% of fees burned
            treasury_split_bps: TREASURY_SPLIT_BPS,  // 20% of fees to treasury
            staker_split_bps: STAKER_SPLIT_BPS,      // 10% of fees to stakers
        });
        
        // Initialize stats
        self.stats.write(FeeStats {
            total_gmv: 0,
            total_protocol_fees: 0,
            total_burned: 0,
            total_to_treasury: 0,
            total_to_stakers: 0,
            total_to_workers: 0,
            transaction_count: 0,
        });
        
        self.current_epoch.write(1);
        self.total_staker_share.write(0);
        self.paused.write(false);
        
        // Burn address (dead address)
        let burn_addr: ContractAddress = 0xdead.try_into().unwrap();
        self.burn_address.write(burn_addr);

        // Initialize upgrade delay (2 days in seconds)
        self.upgrade_delay.write(172800);
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl FeeManagerImpl of IFeeManager<ContractState> {
        // === Admin Functions ===
        
        fn update_fee_config(ref self: ContractState, config: FeeConfig) {
            self._only_owner();
            
            // Validate splits sum to 100%
            let total_split: u32 = config.burn_split_bps.into() 
                + config.treasury_split_bps.into() 
                + config.staker_split_bps.into();
            assert(total_split == 10000, 'Splits must sum to 100%');
            
            self.config.write(config);
            
            self.emit(ConfigUpdated {
                protocol_fee_bps: config.protocol_fee_bps,
                burn_split_bps: config.burn_split_bps,
            });
        }

        fn set_staking_contract(ref self: ContractState, staking: ContractAddress) {
            self._only_owner();
            self.staking_contract.write(staking);
        }

        fn pause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(true);
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(false);
        }

        // === Core Fee Processing ===
        
        fn process_transaction(
            ref self: ContractState,
            gmv: u256,
            worker: ContractAddress,
        ) -> FeeBreakdown {
            assert(!self.paused.read(), 'Contract is paused');
            
            // Only job manager can process transactions
            let caller = get_caller_address();
            assert(
                caller == self.job_manager.read() || caller == self.owner.read(),
                'Unauthorized'
            );
            
            let breakdown = self._calculate_fees_internal(gmv);
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            
            // 1. Burn tokens (transfer to dead address or use burn function if available)
            token.transfer(self.burn_address.read(), breakdown.burn_amount);
            
            // 2. Send to treasury
            token.transfer(self.treasury.read(), breakdown.treasury_amount);
            
            // 3. Add to staker pool for current epoch
            let epoch = self.current_epoch.read();
            let current_pool = self.epoch_staker_pool.read(epoch);
            self.epoch_staker_pool.write(epoch, current_pool + breakdown.staker_amount);
            
            // 4. Pay worker
            token.transfer(worker, breakdown.worker_payment);
            
            // Update statistics
            let mut stats = self.stats.read();
            stats.total_gmv = stats.total_gmv + gmv;
            stats.total_protocol_fees = stats.total_protocol_fees + breakdown.protocol_fee;
            stats.total_burned = stats.total_burned + breakdown.burn_amount;
            stats.total_to_treasury = stats.total_to_treasury + breakdown.treasury_amount;
            stats.total_to_stakers = stats.total_to_stakers + breakdown.staker_amount;
            stats.total_to_workers = stats.total_to_workers + breakdown.worker_payment;
            stats.transaction_count = stats.transaction_count + 1;
            self.stats.write(stats);
            
            // Emit events
            self.emit(TransactionProcessed {
                worker,
                gmv,
                protocol_fee: breakdown.protocol_fee,
                worker_payment: breakdown.worker_payment,
            });
            
            self.emit(FeesDistributed {
                burn_amount: breakdown.burn_amount,
                treasury_amount: breakdown.treasury_amount,
                staker_pool_amount: breakdown.staker_amount,
            });
            
            self.emit(TokensBurned {
                amount: breakdown.burn_amount,
                total_burned: stats.total_burned,
            });
            
            breakdown
        }

        fn calculate_fees(self: @ContractState, gmv: u256) -> FeeBreakdown {
            self._calculate_fees_internal(gmv)
        }

        // === Staker Rewards ===
        
        fn claim_staker_rewards(ref self: ContractState) -> u256 {
            let caller = get_caller_address();
            let mut reward = self.staker_rewards.read(caller);
            
            // Calculate pending rewards based on stake share
            let epoch = self.current_epoch.read();
            let pending = self._calculate_pending_rewards(caller, epoch);
            
            let total_claim = reward.pending_rewards + pending;
            assert(total_claim > 0, 'No rewards to claim');
            
            // Reset pending and update claimed
            reward.pending_rewards = 0;
            reward.total_claimed = reward.total_claimed + total_claim;
            reward.last_calculated_epoch = epoch;
            self.staker_rewards.write(caller, reward);
            
            // Transfer rewards
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(caller, total_claim);
            
            self.emit(StakerRewardsClaimed {
                staker: caller,
                amount: total_claim,
            });
            
            total_claim
        }

        fn update_staker_share(
            ref self: ContractState,
            staker: ContractAddress,
            stake_share_bps: u256,
        ) {
            // Only staking contract can update shares
            let caller = get_caller_address();
            assert(
                caller == self.staking_contract.read() || caller == self.owner.read(),
                'Unauthorized'
            );

            // Phase 3: Validate stake share doesn't exceed 100%
            assert(stake_share_bps <= BPS_DENOMINATOR, 'Share exceeds 100%');

            let mut reward = self.staker_rewards.read(staker);
            let epoch = self.current_epoch.read();

            // Phase 3: Update total_staker_share atomically
            let old_share = reward.stake_share_bps;
            let current_total = self.total_staker_share.read();

            // Calculate new total (subtract old, add new)
            let new_total = current_total - old_share + stake_share_bps;
            assert(new_total <= BPS_DENOMINATOR, 'Total share exceeds 100%');
            self.total_staker_share.write(new_total);

            // Calculate and store pending rewards before changing share
            let pending = self._calculate_pending_rewards(staker, epoch);
            reward.pending_rewards = reward.pending_rewards + pending;
            reward.stake_share_bps = stake_share_bps;
            reward.last_calculated_epoch = epoch;

            self.staker_rewards.write(staker, reward);
        }

        fn get_pending_rewards(self: @ContractState, staker: ContractAddress) -> u256 {
            let reward = self.staker_rewards.read(staker);
            let epoch = self.current_epoch.read();
            let calculated = self._calculate_pending_rewards(staker, epoch);
            reward.pending_rewards + calculated
        }

        // === View Functions ===
        
        fn get_fee_config(self: @ContractState) -> FeeConfig {
            self.config.read()
        }

        fn get_fee_stats(self: @ContractState) -> FeeStats {
            self.stats.read()
        }

        fn get_staker_reward(self: @ContractState, staker: ContractAddress) -> StakerReward {
            self.staker_rewards.read(staker)
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
        }

        fn get_epoch_staker_pool(self: @ContractState, epoch: u64) -> u256 {
            self.epoch_staker_pool.read(epoch)
        }

        // === Upgrade Functions ===

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Another upgrade is already pending");
            assert!(!new_class_hash.is_zero(), "Invalid class hash");

            let current_time = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let execute_after = current_time + delay;

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
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let current_time = get_block_timestamp();

            assert!(current_time >= scheduled_at + delay, "Timelock not expired");

            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            replace_class_syscall(pending).unwrap_syscall();

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: current_time,
                executed_by: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade to cancel");

            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_at: get_block_timestamp(),
                cancelled_by: get_caller_address(),
            });
        }

        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64) {
            (
                self.pending_upgrade.read(),
                self.upgrade_scheduled_at.read(),
                self.upgrade_delay.read()
            )
        }

        fn set_upgrade_delay(ref self: ContractState, delay: u64) {
            self._only_owner();
            assert!(delay >= 86400, "Delay must be at least 1 day");
            assert!(delay <= 2592000, "Delay must be at most 30 days");
            self.upgrade_delay.write(delay);
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }

        fn _calculate_fees_internal(self: @ContractState, gmv: u256) -> FeeBreakdown {
            let config = self.config.read();
            
            // Protocol fee = GMV * protocol_fee_bps / 10000
            let protocol_fee = (gmv * config.protocol_fee_bps.into()) / BPS_DENOMINATOR;
            
            // Split the protocol fee
            let burn_amount = (protocol_fee * config.burn_split_bps.into()) / BPS_DENOMINATOR;
            let treasury_amount = (protocol_fee * config.treasury_split_bps.into()) / BPS_DENOMINATOR;
            let staker_amount = (protocol_fee * config.staker_split_bps.into()) / BPS_DENOMINATOR;
            
            // Worker gets GMV minus protocol fee
            let worker_payment = gmv - protocol_fee;
            
            FeeBreakdown {
                gmv,
                protocol_fee,
                burn_amount,
                treasury_amount,
                staker_amount,
                worker_payment,
            }
        }

        /// Phase 3: Calculate pending rewards with comprehensive zero-division protection
        /// @dev Uses proportional share calculation: reward = pool * staker_share / total_share
        /// @param staker The staker address to calculate rewards for
        /// @param current_epoch The current epoch number
        /// @return pending The calculated pending reward amount
        fn _calculate_pending_rewards(
            self: @ContractState,
            staker: ContractAddress,
            current_epoch: u64,
        ) -> u256 {
            let reward = self.staker_rewards.read(staker);

            // Early return if staker has no share
            if reward.stake_share_bps == 0 {
                return 0;
            }

            // Sum up rewards from unclaimed epochs
            let mut pending: u256 = 0;
            let mut epoch = reward.last_calculated_epoch;

            // Limit epoch iteration to prevent excessive gas (max 365 epochs = ~1 year)
            let max_epochs: u64 = 365;
            let mut iterations: u64 = 0;

            loop {
                if epoch >= current_epoch {
                    break;
                }
                if iterations >= max_epochs {
                    break; // Prevent gas exhaustion
                }

                epoch = epoch + 1;
                iterations = iterations + 1;

                let pool = self.epoch_staker_pool.read(epoch);

                // Skip if no rewards in this epoch
                if pool == 0 {
                    continue;
                }

                let total_share = self.total_staker_share.read();

                // Phase 3: Explicit zero-division protection
                // This should never happen if update_staker_share is called correctly,
                // but we protect against edge cases (e.g., all stakers unstake)
                if total_share > 0 {
                    // Calculate proportional reward: pool * staker_share / total_share
                    // Note: This is safe because we checked total_share > 0
                    let epoch_reward = (pool * reward.stake_share_bps) / total_share;
                    pending = pending + epoch_reward;
                }
                // If total_share == 0, the epoch pool remains undistributed
                // This is an edge case that shouldn't occur in practice
            };

            pending
        }
    }
}

