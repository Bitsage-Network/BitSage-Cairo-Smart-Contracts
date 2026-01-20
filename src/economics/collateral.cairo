// =============================================================================
// COLLATERAL CONTRACT - BitSage Network
// =============================================================================
//
// Implements collateral-backed weight system:
//
// - Base Weight Ratio: 20% (unconditional)
// - Collateral-Eligible Weight: 80% (requires collateral backing)
// - Grace Period: First 180 epochs (no collateral required)
// - Unbonding Period: 7 days (withdrawal delay)
//
// Slashing Conditions:
// - Invalid proof: 20% slash
// - Downtime: 10% slash
// - Malicious behavior: 50% slash
//
// =============================================================================

use starknet::{ContractAddress, ClassHash};

// =============================================================================
// Constants
// =============================================================================

const BASE_WEIGHT_RATIO_BPS: u16 = 2000;      // 20% base weight (no collateral needed)
const COLLATERAL_WEIGHT_RATIO_BPS: u16 = 8000; // 80% requires collateral
// SECURITY FIX: Reduced grace period from 180 to 30 epochs to prevent exploitation
// Previous 180 epochs (~6 months) allowed attackers to participate without collateral
// 30 epochs (~30 days) provides sufficient onboarding while limiting exposure
const GRACE_PERIOD_EPOCHS: u64 = 30;           // ~30 days (reduced from 180)
const UNBONDING_PERIOD_SECS: u64 = 604800;     // 7 days

// Slashing rates (basis points)
const SLASH_INVALID_PROOF_BPS: u16 = 2000;    // 20%
const SLASH_DOWNTIME_BPS: u16 = 1000;         // 10%
const SLASH_MALICIOUS_BPS: u16 = 5000;        // 50%

// =============================================================================
// Data Types
// =============================================================================

/// Collateral configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CollateralConfig {
    /// Base weight ratio (unconditional, default 20%)
    pub base_weight_ratio_bps: u16,
    /// Collateral per weight unit (tokens required per unit of weight)
    pub collateral_per_weight_unit: u256,
    /// Grace period end epoch (no collateral required before this)
    pub grace_period_end_epoch: u64,
    /// Unbonding period in seconds
    pub unbonding_period_secs: u64,
    /// Slash rate for invalid proofs (basis points)
    pub slash_invalid_bps: u16,
    /// Slash rate for downtime (basis points)
    pub slash_downtime_bps: u16,
    /// Slash rate for malicious behavior (basis points)
    pub slash_malicious_bps: u16,
    /// Downtime threshold (missed percentage, basis points)
    pub downtime_threshold_bps: u16,
}

/// Participant's collateral state
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CollateralState {
    /// Active collateral backing current weight
    pub active_collateral: u256,
    /// Collateral in unbonding queue
    pub unbonding_collateral: u256,
    /// Epoch when unbonding completes
    pub unbonding_completion_epoch: u64,
    /// Potential weight (from Proof of Compute)
    pub potential_weight: u256,
    /// Effective weight (base + collateral-backed)
    pub effective_weight: u256,
    /// Last epoch weight was calculated
    pub last_weight_epoch: u64,
    /// Total amount slashed
    pub total_slashed: u256,
    /// Is participant active
    pub is_active: bool,
}

/// Slashing reason
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum SlashReason {
    /// Proof verification failed
    InvalidProof,
    /// Missed participation threshold
    Downtime,
    /// Intentional malicious behavior
    Malicious,
    /// Consensus-level fault (from validator)
    ConsensusFault,
}

/// Unbonding entry
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct UnbondingEntry {
    /// Amount being unbonded
    pub amount: u256,
    /// Timestamp when unbonding completes
    pub completion_time: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait ICollateral<TContractState> {
    // === Participant Functions ===
    fn deposit_collateral(ref self: TContractState, amount: u256);
    fn withdraw_collateral(ref self: TContractState, amount: u256);
    fn complete_unbonding(ref self: TContractState);
    
    // === Weight Calculation ===
    fn calculate_effective_weight(
        self: @TContractState,
        participant: ContractAddress,
        potential_weight: u256,
    ) -> u256;
    
    fn update_participant_weight(
        ref self: TContractState,
        participant: ContractAddress,
        potential_weight: u256,
    );
    
    // === Slashing ===
    fn slash(
        ref self: TContractState,
        participant: ContractAddress,
        reason: SlashReason,
    ) -> u256;
    
    // === Admin ===
    fn update_config(ref self: TContractState, config: CollateralConfig);
    fn advance_epoch(ref self: TContractState);
    
    // === View Functions ===
    fn get_config(self: @TContractState) -> CollateralConfig;
    fn get_collateral_state(self: @TContractState, participant: ContractAddress) -> CollateralState;
    fn get_current_epoch(self: @TContractState) -> u64;
    fn is_grace_period(self: @TContractState) -> bool;
    fn get_required_collateral(self: @TContractState, weight: u256) -> u256;

    // Upgrade functions
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
mod Collateral {
    use super::{
        ICollateral, CollateralConfig, CollateralState, SlashReason, UnbondingEntry,
        BASE_WEIGHT_RATIO_BPS, COLLATERAL_WEIGHT_RATIO_BPS, GRACE_PERIOD_EPOCHS,
        UNBONDING_PERIOD_SECS, SLASH_INVALID_PROOF_BPS, SLASH_DOWNTIME_BPS, SLASH_MALICIOUS_BPS,
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    const BPS_DENOMINATOR: u256 = 10000;

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// SAGE token address
        sage_token: ContractAddress,
        /// Staking contract (authorized to call slash)
        staking_contract: ContractAddress,
        /// Verifier contract (authorized to call slash)
        verifier_contract: ContractAddress,
        /// Configuration
        config: CollateralConfig,
        /// Current epoch
        current_epoch: u64,
        /// Participant collateral states
        collateral_states: Map<ContractAddress, CollateralState>,
        /// Unbonding entries
        unbonding_entries: Map<ContractAddress, UnbondingEntry>,
        /// Total active collateral in system
        total_active_collateral: u256,
        /// Total unbonding collateral
        total_unbonding_collateral: u256,
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
        CollateralDeposited: CollateralDeposited,
        WithdrawalInitiated: WithdrawalInitiated,
        WithdrawalCompleted: WithdrawalCompleted,
        CollateralSlashed: CollateralSlashed,
        WeightUpdated: WeightUpdated,
        EpochAdvanced: EpochAdvanced,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct CollateralDeposited {
        #[key]
        participant: ContractAddress,
        amount: u256,
        new_total: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawalInitiated {
        #[key]
        participant: ContractAddress,
        amount: u256,
        completion_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawalCompleted {
        #[key]
        participant: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct CollateralSlashed {
        #[key]
        participant: ContractAddress,
        amount: u256,
        reason: SlashReason,
    }

    #[derive(Drop, starknet::Event)]
    struct WeightUpdated {
        #[key]
        participant: ContractAddress,
        potential_weight: u256,
        effective_weight: u256,
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
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        
        // Default configuration inspired by Gonka
        self.config.write(CollateralConfig {
            base_weight_ratio_bps: BASE_WEIGHT_RATIO_BPS,
            collateral_per_weight_unit: 1000_000000000000000000_u256, // 1000 SAGE per weight unit
            grace_period_end_epoch: GRACE_PERIOD_EPOCHS,
            unbonding_period_secs: UNBONDING_PERIOD_SECS,
            slash_invalid_bps: SLASH_INVALID_PROOF_BPS,
            slash_downtime_bps: SLASH_DOWNTIME_BPS,
            slash_malicious_bps: SLASH_MALICIOUS_BPS,
            downtime_threshold_bps: 500, // 5% missed threshold
        });
        
        self.current_epoch.write(1);
        self.total_active_collateral.write(0);
        self.total_unbonding_collateral.write(0);
        self.upgrade_delay.write(172800);
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl CollateralImpl of ICollateral<ContractState> {
        fn deposit_collateral(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            
            // Transfer tokens to contract
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(caller, starknet::get_contract_address(), amount);
            
            // Update state
            let mut state = self.collateral_states.read(caller);
            let new_total = state.active_collateral + amount;
            state.active_collateral = new_total;
            state.is_active = true;
            self.collateral_states.write(caller, state);
            
            // Update global total
            let total = self.total_active_collateral.read() + amount;
            self.total_active_collateral.write(total);
            
            self.emit(CollateralDeposited {
                participant: caller,
                amount,
                new_total,
            });
        }

        fn withdraw_collateral(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut state = self.collateral_states.read(caller);
            
            assert(state.active_collateral >= amount, 'Insufficient collateral');
            assert(state.unbonding_collateral == 0, 'Pending unbonding exists');
            
            let config = self.config.read();
            let completion_time = get_block_timestamp() + config.unbonding_period_secs;
            
            // Move to unbonding
            state.active_collateral = state.active_collateral - amount;
            state.unbonding_collateral = amount;
            state.unbonding_completion_epoch = self.current_epoch.read() + 1;
            self.collateral_states.write(caller, state);
            
            // Store unbonding entry
            self.unbonding_entries.write(caller, UnbondingEntry {
                amount,
                completion_time,
            });
            
            // Update totals
            let active_total = self.total_active_collateral.read() - amount;
            self.total_active_collateral.write(active_total);
            let unbonding_total = self.total_unbonding_collateral.read() + amount;
            self.total_unbonding_collateral.write(unbonding_total);
            
            self.emit(WithdrawalInitiated {
                participant: caller,
                amount,
                completion_time,
            });
        }

        fn complete_unbonding(ref self: ContractState) {
            let caller = get_caller_address();
            let entry = self.unbonding_entries.read(caller);
            
            assert(entry.amount > 0, 'No pending unbonding');
            assert(get_block_timestamp() >= entry.completion_time, 'Unbonding not complete');
            
            let mut state = self.collateral_states.read(caller);
            let amount = state.unbonding_collateral;
            state.unbonding_collateral = 0;
            self.collateral_states.write(caller, state);
            
            // Clear entry
            self.unbonding_entries.write(caller, UnbondingEntry {
                amount: 0,
                completion_time: 0,
            });
            
            // Update total
            let unbonding_total = self.total_unbonding_collateral.read() - amount;
            self.total_unbonding_collateral.write(unbonding_total);
            
            // Transfer back to participant
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(caller, amount);
            
            self.emit(WithdrawalCompleted {
                participant: caller,
                amount,
            });
        }

        fn calculate_effective_weight(
            self: @ContractState,
            participant: ContractAddress,
            potential_weight: u256,
        ) -> u256 {
            let config = self.config.read();
            let epoch = self.current_epoch.read();
            
            // During grace period, all potential weight is granted
            if epoch <= config.grace_period_end_epoch {
                return potential_weight;
            }
            
            // Base weight (unconditional)
            let base_weight = (potential_weight * config.base_weight_ratio_bps.into()) 
                / BPS_DENOMINATOR;
            
            // Collateral-eligible weight
            let collateral_eligible = potential_weight - base_weight;
            
            // Calculate how much weight can be backed by collateral
            let state = self.collateral_states.read(participant);
            let max_backed_weight = if config.collateral_per_weight_unit > 0 {
                state.active_collateral / config.collateral_per_weight_unit
            } else {
                collateral_eligible // If no collateral required per unit, grant all
            };
            
            // Activated weight is minimum of eligible and backed
            let activated_weight = if max_backed_weight < collateral_eligible {
                max_backed_weight
            } else {
                collateral_eligible
            };
            
            base_weight + activated_weight
        }

        fn update_participant_weight(
            ref self: ContractState,
            participant: ContractAddress,
            potential_weight: u256,
        ) {
            let effective = self.calculate_effective_weight(participant, potential_weight);
            
            let mut state = self.collateral_states.read(participant);
            state.potential_weight = potential_weight;
            state.effective_weight = effective;
            state.last_weight_epoch = self.current_epoch.read();
            self.collateral_states.write(participant, state);
            
            self.emit(WeightUpdated {
                participant,
                potential_weight,
                effective_weight: effective,
            });
        }

        fn slash(
            ref self: ContractState,
            participant: ContractAddress,
            reason: SlashReason,
        ) -> u256 {
            // Only authorized contracts can slash
            let caller = get_caller_address();
            assert(
                caller == self.staking_contract.read() 
                    || caller == self.verifier_contract.read()
                    || caller == self.owner.read(),
                'Unauthorized'
            );
            
            let config = self.config.read();
            let mut state = self.collateral_states.read(participant);
            
            // Determine slash percentage
            let slash_bps: u256 = match reason {
                SlashReason::InvalidProof => config.slash_invalid_bps.into(),
                SlashReason::Downtime => config.slash_downtime_bps.into(),
                SlashReason::Malicious => config.slash_malicious_bps.into(),
                SlashReason::ConsensusFault => config.slash_malicious_bps.into(),
            };
            
            // Total slashable = active + unbonding
            let total_slashable = state.active_collateral + state.unbonding_collateral;
            let slash_amount = (total_slashable * slash_bps) / BPS_DENOMINATOR;
            
            // Slash proportionally from active and unbonding
            if total_slashable > 0 {
                let active_ratio = (state.active_collateral * BPS_DENOMINATOR) / total_slashable;
                let active_slash = (slash_amount * active_ratio) / BPS_DENOMINATOR;
                let unbonding_slash = slash_amount - active_slash;
                
                state.active_collateral = state.active_collateral - active_slash;
                state.unbonding_collateral = state.unbonding_collateral - unbonding_slash;
                state.total_slashed = state.total_slashed + slash_amount;
                
                self.collateral_states.write(participant, state);
                
                // Update totals
                let active_total = self.total_active_collateral.read() - active_slash;
                self.total_active_collateral.write(active_total);
                let unbonding_total = self.total_unbonding_collateral.read() - unbonding_slash;
                self.total_unbonding_collateral.write(unbonding_total);
                
                // Burn slashed tokens (send to dead address)
                let dead_addr: ContractAddress = 0xdead.try_into().unwrap();
                let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
                token.transfer(dead_addr, slash_amount);
            }
            
            self.emit(CollateralSlashed {
                participant,
                amount: slash_amount,
                reason,
            });
            
            slash_amount
        }

        fn update_config(ref self: ContractState, config: CollateralConfig) {
            self._only_owner();
            self.config.write(config);
        }

        fn advance_epoch(ref self: ContractState) {
            self._only_owner();
            let old_epoch = self.current_epoch.read();
            let new_epoch = old_epoch + 1;
            self.current_epoch.write(new_epoch);
            
            self.emit(EpochAdvanced {
                old_epoch,
                new_epoch,
            });
        }

        fn get_config(self: @ContractState) -> CollateralConfig {
            self.config.read()
        }

        fn get_collateral_state(
            self: @ContractState,
            participant: ContractAddress
        ) -> CollateralState {
            self.collateral_states.read(participant)
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
        }

        fn is_grace_period(self: @ContractState) -> bool {
            let config = self.config.read();
            self.current_epoch.read() <= config.grace_period_end_epoch
        }

        fn get_required_collateral(self: @ContractState, weight: u256) -> u256 {
            let config = self.config.read();
            let collateral_eligible = (weight * COLLATERAL_WEIGHT_RATIO_BPS.into()) / BPS_DENOMINATOR;
            collateral_eligible * config.collateral_per_weight_unit
        }

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
    }
}

