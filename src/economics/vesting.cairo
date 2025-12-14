// =============================================================================
// REWARD VESTING CONTRACT - BitSage Network
// =============================================================================
//
// Implements reward vesting to align long-term incentives:
//
// - Work Rewards: Fees from user requests (configurable vesting)
// - Subsidy Rewards: Newly minted tokens (180 epoch vesting)
// - Top Performer Rewards: Special rewards (configurable vesting)
//
// Vesting ensures participants have skin in the game for network success.
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_WORK_VESTING_EPOCHS: u64 = 0;        // Immediate for work rewards
const DEFAULT_SUBSIDY_VESTING_EPOCHS: u64 = 180;   // ~6 months for subsidies
const DEFAULT_TOP_MINER_VESTING_EPOCHS: u64 = 90;  // ~3 months for top performers

// =============================================================================
// Data Types
// =============================================================================

/// Vesting configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VestingConfig {
    /// Vesting period for work rewards (epochs)
    pub work_vesting_epochs: u64,
    /// Vesting period for subsidy rewards (epochs)
    pub subsidy_vesting_epochs: u64,
    /// Vesting period for top performer rewards (epochs)
    pub top_miner_vesting_epochs: u64,
    /// Minimum amount to vest (avoid dust)
    pub min_vest_amount: u256,
}

/// Reward type for vesting
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum RewardType {
    /// Fees from completed work
    Work,
    /// Inflationary subsidy rewards
    Subsidy,
    /// Top performer bonus
    TopMiner,
}

/// Individual vesting entry
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VestingEntry {
    /// Total amount vesting
    pub amount: u256,
    /// Epoch when vesting started
    pub start_epoch: u64,
    /// Epoch when fully vested
    pub end_epoch: u64,
    /// Amount already claimed
    pub claimed: u256,
    /// Reward type
    pub reward_type: RewardType,
}

/// Participant vesting summary
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VestingSummary {
    /// Total amount currently vesting
    pub total_vesting: u256,
    /// Amount available to claim now
    pub claimable: u256,
    /// Total claimed historically
    pub total_claimed: u256,
    /// Number of active vesting entries
    pub active_entries: u64,
}

/// Global vesting statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VestingStats {
    /// Total tokens in vesting
    pub total_vesting: u256,
    /// Total tokens released
    pub total_released: u256,
    /// Number of participants with vesting
    pub participant_count: u64,
    /// Current epoch
    pub current_epoch: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IRewardVesting<TContractState> {
    // === Participant Functions ===
    /// Claim vested rewards
    fn claim(ref self: TContractState) -> u256;
    
    /// Claim specific vesting entry
    fn claim_entry(ref self: TContractState, entry_id: u64) -> u256;
    
    // === Reward Distribution (called by other contracts) ===
    /// Add work rewards to vesting
    fn vest_work_reward(
        ref self: TContractState,
        participant: ContractAddress,
        amount: u256,
    );
    
    /// Add subsidy rewards to vesting
    fn vest_subsidy_reward(
        ref self: TContractState,
        participant: ContractAddress,
        amount: u256,
    );
    
    /// Add top miner rewards to vesting
    fn vest_top_miner_reward(
        ref self: TContractState,
        participant: ContractAddress,
        amount: u256,
    );
    
    // === Admin Functions ===
    fn update_config(ref self: TContractState, config: VestingConfig);
    fn advance_epoch(ref self: TContractState);
    fn set_fee_manager(ref self: TContractState, fee_manager: ContractAddress);
    fn set_staking_contract(ref self: TContractState, staking: ContractAddress);
    
    // === View Functions ===
    fn get_config(self: @TContractState) -> VestingConfig;
    fn get_vesting_summary(self: @TContractState, participant: ContractAddress) -> VestingSummary;
    fn get_vesting_entry(self: @TContractState, participant: ContractAddress, entry_id: u64) -> VestingEntry;
    fn get_claimable(self: @TContractState, participant: ContractAddress) -> u256;
    fn get_stats(self: @TContractState) -> VestingStats;
    fn get_current_epoch(self: @TContractState) -> u64;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod RewardVesting {
    use super::{
        IRewardVesting, VestingConfig, RewardType, VestingEntry, VestingSummary, VestingStats,
        DEFAULT_WORK_VESTING_EPOCHS, DEFAULT_SUBSIDY_VESTING_EPOCHS, DEFAULT_TOP_MINER_VESTING_EPOCHS,
    };
    use starknet::{
        ContractAddress, get_caller_address,
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
        /// Fee manager (can add work rewards)
        fee_manager: ContractAddress,
        /// Staking contract (can add subsidy rewards)
        staking_contract: ContractAddress,
        /// Configuration
        config: VestingConfig,
        /// Current epoch
        current_epoch: u64,
        /// Vesting entries: participant -> entry_id -> entry
        vesting_entries: Map<(ContractAddress, u64), VestingEntry>,
        /// Entry count per participant
        entry_counts: Map<ContractAddress, u64>,
        /// Participant summaries
        summaries: Map<ContractAddress, VestingSummary>,
        /// Global statistics
        stats: VestingStats,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        RewardVested: RewardVested,
        RewardClaimed: RewardClaimed,
        EpochAdvanced: EpochAdvanced,
        ConfigUpdated: ConfigUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct RewardVested {
        #[key]
        participant: ContractAddress,
        amount: u256,
        reward_type: RewardType,
        end_epoch: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RewardClaimed {
        #[key]
        participant: ContractAddress,
        amount: u256,
        entry_id: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EpochAdvanced {
        old_epoch: u64,
        new_epoch: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        work_vesting_epochs: u64,
        subsidy_vesting_epochs: u64,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        ciro_token: ContractAddress,
    ) {
        self.owner.write(owner);
        self.ciro_token.write(ciro_token);
        
        // Default configuration
        self.config.write(VestingConfig {
            work_vesting_epochs: DEFAULT_WORK_VESTING_EPOCHS,
            subsidy_vesting_epochs: DEFAULT_SUBSIDY_VESTING_EPOCHS,
            top_miner_vesting_epochs: DEFAULT_TOP_MINER_VESTING_EPOCHS,
            min_vest_amount: 1_000000000000000000_u256, // 1 CIRO minimum
        });
        
        self.current_epoch.write(1);
        
        self.stats.write(VestingStats {
            total_vesting: 0,
            total_released: 0,
            participant_count: 0,
            current_epoch: 1,
        });
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl RewardVestingImpl of IRewardVesting<ContractState> {
        fn claim(ref self: ContractState) -> u256 {
            let caller = get_caller_address();
            let entry_count = self.entry_counts.read(caller);
            let current_epoch = self.current_epoch.read();
            
            let mut total_claimed: u256 = 0;
            let mut i: u64 = 0;
            
            loop {
                if i >= entry_count {
                    break;
                }
                
                let mut entry = self.vesting_entries.read((caller, i));
                
                if entry.amount > entry.claimed {
                    let claimable = self._calculate_claimable(@entry, current_epoch);
                    
                    if claimable > 0 {
                        entry.claimed = entry.claimed + claimable;
                        self.vesting_entries.write((caller, i), entry);
                        total_claimed = total_claimed + claimable;
                        
                        self.emit(RewardClaimed {
                            participant: caller,
                            amount: claimable,
                            entry_id: i,
                        });
                    }
                }
                
                i = i + 1;
            };
            
            if total_claimed > 0 {
                // Update summary
                let mut summary = self.summaries.read(caller);
                summary.total_claimed = summary.total_claimed + total_claimed;
                summary.total_vesting = summary.total_vesting - total_claimed;
                summary.claimable = self._calculate_total_claimable(caller, current_epoch);
                self.summaries.write(caller, summary);
                
                // Update stats
                let mut stats = self.stats.read();
                stats.total_vesting = stats.total_vesting - total_claimed;
                stats.total_released = stats.total_released + total_claimed;
                self.stats.write(stats);
                
                // Transfer tokens
                let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
                token.transfer(caller, total_claimed);
            }
            
            total_claimed
        }

        fn claim_entry(ref self: ContractState, entry_id: u64) -> u256 {
            let caller = get_caller_address();
            let current_epoch = self.current_epoch.read();
            
            let mut entry = self.vesting_entries.read((caller, entry_id));
            assert(entry.amount > 0, 'Entry does not exist');
            
            let claimable = self._calculate_claimable(@entry, current_epoch);
            assert(claimable > 0, 'Nothing to claim');
            
            entry.claimed = entry.claimed + claimable;
            self.vesting_entries.write((caller, entry_id), entry);
            
            // Update summary
            let mut summary = self.summaries.read(caller);
            summary.total_claimed = summary.total_claimed + claimable;
            summary.total_vesting = summary.total_vesting - claimable;
            summary.claimable = self._calculate_total_claimable(caller, current_epoch);
            self.summaries.write(caller, summary);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_vesting = stats.total_vesting - claimable;
            stats.total_released = stats.total_released + claimable;
            self.stats.write(stats);
            
            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.transfer(caller, claimable);
            
            self.emit(RewardClaimed {
                participant: caller,
                amount: claimable,
                entry_id,
            });
            
            claimable
        }

        fn vest_work_reward(
            ref self: ContractState,
            participant: ContractAddress,
            amount: u256,
        ) {
            self._only_authorized();
            self._vest_reward(participant, amount, RewardType::Work);
        }

        fn vest_subsidy_reward(
            ref self: ContractState,
            participant: ContractAddress,
            amount: u256,
        ) {
            self._only_authorized();
            self._vest_reward(participant, amount, RewardType::Subsidy);
        }

        fn vest_top_miner_reward(
            ref self: ContractState,
            participant: ContractAddress,
            amount: u256,
        ) {
            self._only_authorized();
            self._vest_reward(participant, amount, RewardType::TopMiner);
        }

        fn update_config(ref self: ContractState, config: VestingConfig) {
            self._only_owner();
            self.config.write(config);
            
            self.emit(ConfigUpdated {
                work_vesting_epochs: config.work_vesting_epochs,
                subsidy_vesting_epochs: config.subsidy_vesting_epochs,
            });
        }

        fn advance_epoch(ref self: ContractState) {
            self._only_owner();
            let old_epoch = self.current_epoch.read();
            let new_epoch = old_epoch + 1;
            self.current_epoch.write(new_epoch);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.current_epoch = new_epoch;
            self.stats.write(stats);
            
            self.emit(EpochAdvanced {
                old_epoch,
                new_epoch,
            });
        }

        fn set_fee_manager(ref self: ContractState, fee_manager: ContractAddress) {
            self._only_owner();
            self.fee_manager.write(fee_manager);
        }

        fn set_staking_contract(ref self: ContractState, staking: ContractAddress) {
            self._only_owner();
            self.staking_contract.write(staking);
        }

        fn get_config(self: @ContractState) -> VestingConfig {
            self.config.read()
        }

        fn get_vesting_summary(self: @ContractState, participant: ContractAddress) -> VestingSummary {
            let mut summary = self.summaries.read(participant);
            summary.claimable = self._calculate_total_claimable(participant, self.current_epoch.read());
            summary
        }

        fn get_vesting_entry(
            self: @ContractState,
            participant: ContractAddress,
            entry_id: u64
        ) -> VestingEntry {
            self.vesting_entries.read((participant, entry_id))
        }

        fn get_claimable(self: @ContractState, participant: ContractAddress) -> u256 {
            self._calculate_total_claimable(participant, self.current_epoch.read())
        }

        fn get_stats(self: @ContractState) -> VestingStats {
            self.stats.read()
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
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

        fn _only_authorized(self: @ContractState) {
            let caller = get_caller_address();
            assert(
                caller == self.owner.read()
                    || caller == self.fee_manager.read()
                    || caller == self.staking_contract.read(),
                'Unauthorized'
            );
        }

        fn _vest_reward(
            ref self: ContractState,
            participant: ContractAddress,
            amount: u256,
            reward_type: RewardType,
        ) {
            let config = self.config.read();
            
            // Check minimum
            if amount < config.min_vest_amount {
                return;
            }
            
            let current_epoch = self.current_epoch.read();
            
            // Determine vesting period
            let vesting_epochs = match reward_type {
                RewardType::Work => config.work_vesting_epochs,
                RewardType::Subsidy => config.subsidy_vesting_epochs,
                RewardType::TopMiner => config.top_miner_vesting_epochs,
            };
            
            let end_epoch = current_epoch + vesting_epochs;
            
            // Create entry
            let entry_id = self.entry_counts.read(participant);
            let entry = VestingEntry {
                amount,
                start_epoch: current_epoch,
                end_epoch,
                claimed: 0,
                reward_type,
            };
            
            self.vesting_entries.write((participant, entry_id), entry);
            self.entry_counts.write(participant, entry_id + 1);
            
            // Update summary
            let mut summary = self.summaries.read(participant);
            let was_zero = summary.total_vesting == 0 && summary.total_claimed == 0;
            summary.total_vesting = summary.total_vesting + amount;
            summary.active_entries = summary.active_entries + 1;
            
            // If immediate vesting, update claimable
            if vesting_epochs == 0 {
                summary.claimable = summary.claimable + amount;
            }
            
            self.summaries.write(participant, summary);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_vesting = stats.total_vesting + amount;
            if was_zero {
                stats.participant_count = stats.participant_count + 1;
            }
            self.stats.write(stats);
            
            // Transfer tokens to contract for vesting
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.transfer_from(get_caller_address(), starknet::get_contract_address(), amount);
            
            self.emit(RewardVested {
                participant,
                amount,
                reward_type,
                end_epoch,
            });
        }

        fn _calculate_claimable(self: @ContractState, entry: @VestingEntry, current_epoch: u64) -> u256 {
            let remaining = *entry.amount - *entry.claimed;
            
            if remaining == 0 {
                return 0;
            }
            
            // If fully vested, return all remaining
            if current_epoch >= *entry.end_epoch {
                return remaining;
            }
            
            // If not started or immediate vesting (start == end)
            if *entry.start_epoch == *entry.end_epoch {
                return remaining;
            }
            
            // Linear vesting calculation
            let total_epochs = *entry.end_epoch - *entry.start_epoch;
            let elapsed_epochs = if current_epoch > *entry.start_epoch {
                current_epoch - *entry.start_epoch
            } else {
                0
            };
            
            // Amount that should be vested by now
            let vested = (*entry.amount * elapsed_epochs.into()) / total_epochs.into();
            
            // Claimable is vested minus already claimed
            if vested > *entry.claimed {
                vested - *entry.claimed
            } else {
                0
            }
        }

        fn _calculate_total_claimable(
            self: @ContractState,
            participant: ContractAddress,
            current_epoch: u64
        ) -> u256 {
            let entry_count = self.entry_counts.read(participant);
            let mut total: u256 = 0;
            let mut i: u64 = 0;
            
            loop {
                if i >= entry_count {
                    break;
                }
                
                let entry = self.vesting_entries.read((participant, i));
                total = total + self._calculate_claimable(@entry, current_epoch);
                i = i + 1;
            };
            
            total
        }
    }
}

