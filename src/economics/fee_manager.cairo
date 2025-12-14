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

use starknet::ContractAddress;

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
        ContractAddress, get_caller_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// CIRO token address
        ciro_token: ContractAddress,
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

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        ciro_token: ContractAddress,
        treasury: ContractAddress,
        job_manager: ContractAddress,
    ) {
        self.owner.write(owner);
        self.ciro_token.write(ciro_token);
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
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            
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
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
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
            
            let mut reward = self.staker_rewards.read(staker);
            let epoch = self.current_epoch.read();
            
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

        fn _calculate_pending_rewards(
            self: @ContractState,
            staker: ContractAddress,
            current_epoch: u64,
        ) -> u256 {
            let reward = self.staker_rewards.read(staker);
            
            if reward.stake_share_bps == 0 {
                return 0;
            }
            
            // Sum up rewards from unclaimed epochs
            let mut pending: u256 = 0;
            let mut epoch = reward.last_calculated_epoch;
            
            loop {
                if epoch >= current_epoch {
                    break;
                }
                epoch = epoch + 1;
                
                let pool = self.epoch_staker_pool.read(epoch);
                let total_share = self.total_staker_share.read();
                
                if total_share > 0 {
                    // Staker's share of the epoch pool
                    let epoch_reward = (pool * reward.stake_share_bps) / total_share;
                    pending = pending + epoch_reward;
                }
            };
            
            pending
        }
    }
}

