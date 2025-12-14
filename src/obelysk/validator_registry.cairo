// =============================================================================
// VALIDATOR REGISTRY CONTRACT - BitSage Network / Obelysk Protocol
// =============================================================================
//
// Manages validator registration and coordination for the Obelysk Protocol:
//
// - Validator registration with TEE attestation
// - Proof-of-Compute weight tracking
// - Validator set management per epoch
// - Slashing coordination with Collateral contract
//
// Validators are nodes that verify proofs and participate in consensus.
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Constants
// =============================================================================

const MAX_VALIDATORS: u64 = 100;          // Maximum active validators
const MIN_VALIDATOR_STAKE: u256 = 10000_000000000000000000; // 10,000 SAGE

// =============================================================================
// Data Types
// =============================================================================

/// Validator status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum ValidatorStatus {
    /// Pending registration
    Pending,
    /// Active and validating
    Active,
    /// Temporarily jailed (can rejoin)
    Jailed,
    /// Permanently removed
    Tombstoned,
    /// Voluntarily exited
    Exited,
}

/// Validator information
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: ContractAddress,
    /// Operator address (can be different from validator)
    pub operator: ContractAddress,
    /// Total stake (own + delegated)
    pub total_stake: u256,
    /// Self-bonded stake
    pub self_stake: u256,
    /// Proof-of-Compute weight
    pub compute_weight: u256,
    /// Effective weight (stake + compute)
    pub effective_weight: u256,
    /// Commission rate (basis points)
    pub commission_bps: u16,
    /// Status
    pub status: ValidatorStatus,
    /// Blocks produced
    pub blocks_produced: u64,
    /// Proofs verified
    pub proofs_verified: u64,
    /// Last active epoch
    pub last_active_epoch: u64,
    /// Jail release epoch (0 if not jailed)
    pub jail_release_epoch: u64,
    /// TEE attestation hash
    pub attestation_hash: felt252,
}

/// Validator set for an epoch
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ValidatorSet {
    /// Total validators in set
    pub count: u64,
    /// Total effective weight
    pub total_weight: u256,
    /// Epoch number
    pub epoch: u64,
}

/// Validator statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ValidatorStats {
    /// Total registered validators
    pub total_registered: u64,
    /// Active validators
    pub active_count: u64,
    /// Jailed validators
    pub jailed_count: u64,
    /// Total stake across all validators
    pub total_stake: u256,
    /// Total compute weight
    pub total_compute_weight: u256,
    /// Current epoch
    pub current_epoch: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IValidatorRegistry<TContractState> {
    // === Registration ===
    /// Register as a validator
    fn register(
        ref self: TContractState,
        operator: ContractAddress,
        commission_bps: u16,
        attestation_hash: felt252,
    );
    
    /// Update validator info
    fn update_validator(
        ref self: TContractState,
        commission_bps: u16,
        attestation_hash: felt252,
    );
    
    /// Exit validator set
    fn exit(ref self: TContractState);
    
    // === Staking ===
    /// Add stake
    fn add_stake(ref self: TContractState, amount: u256);
    
    /// Remove stake (starts unbonding)
    fn remove_stake(ref self: TContractState, amount: u256);
    
    // === Proof of Compute ===
    /// Record compute work (called by prover contracts)
    fn record_compute_work(
        ref self: TContractState,
        validator: ContractAddress,
        weight: u256,
    );
    
    // === Admin / Coordination ===
    /// Jail a validator
    fn jail(
        ref self: TContractState,
        validator: ContractAddress,
        epochs: u64,
    );
    
    /// Unjail (if release epoch passed)
    fn unjail(ref self: TContractState);
    
    /// Tombstone (permanent removal)
    fn tombstone(ref self: TContractState, validator: ContractAddress);
    
    /// Update validator set for new epoch
    fn update_validator_set(ref self: TContractState);
    
    /// Advance epoch
    fn advance_epoch(ref self: TContractState);
    
    // === View Functions ===
    fn get_validator(self: @TContractState, validator: ContractAddress) -> ValidatorInfo;
    fn get_validator_set(self: @TContractState, epoch: u64) -> ValidatorSet;
    fn get_stats(self: @TContractState) -> ValidatorStats;
    fn get_current_epoch(self: @TContractState) -> u64;
    fn is_active_validator(self: @TContractState, validator: ContractAddress) -> bool;
    fn get_active_validators(self: @TContractState) -> Array<ContractAddress>;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod ValidatorRegistry {
    use super::{
        IValidatorRegistry, ValidatorStatus, ValidatorInfo, ValidatorSet, ValidatorStats,
        MAX_VALIDATORS, MIN_VALIDATOR_STAKE,
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
        /// SAGE token address
        sage_token: ContractAddress,
        /// Collateral contract
        collateral_contract: ContractAddress,
        /// Staking contract
        staking_contract: ContractAddress,
        /// Current epoch
        current_epoch: u64,
        /// Validators
        validators: Map<ContractAddress, ValidatorInfo>,
        /// Active validator list
        active_validators: Map<u64, ContractAddress>,
        /// Active validator count
        active_count: u64,
        /// All validator list (for iteration)
        all_validators: Map<u64, ContractAddress>,
        /// Total validators
        total_validators: u64,
        /// Validator sets per epoch
        validator_sets: Map<u64, ValidatorSet>,
        /// Statistics
        stats: ValidatorStats,
        /// Minimum stake requirement
        min_stake: u256,
        /// Maximum commission (basis points)
        max_commission_bps: u16,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ValidatorRegistered: ValidatorRegistered,
        ValidatorUpdated: ValidatorUpdated,
        ValidatorJailed: ValidatorJailed,
        ValidatorUnjailed: ValidatorUnjailed,
        ValidatorTombstoned: ValidatorTombstoned,
        ValidatorExited: ValidatorExited,
        StakeAdded: StakeAdded,
        StakeRemoved: StakeRemoved,
        ComputeWorkRecorded: ComputeWorkRecorded,
        ValidatorSetUpdated: ValidatorSetUpdated,
        EpochAdvanced: EpochAdvanced,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorRegistered {
        #[key]
        validator: ContractAddress,
        operator: ContractAddress,
        commission_bps: u16,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorUpdated {
        #[key]
        validator: ContractAddress,
        commission_bps: u16,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorJailed {
        #[key]
        validator: ContractAddress,
        release_epoch: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorUnjailed {
        #[key]
        validator: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorTombstoned {
        #[key]
        validator: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorExited {
        #[key]
        validator: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct StakeAdded {
        #[key]
        validator: ContractAddress,
        amount: u256,
        new_total: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct StakeRemoved {
        #[key]
        validator: ContractAddress,
        amount: u256,
        new_total: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ComputeWorkRecorded {
        #[key]
        validator: ContractAddress,
        weight: u256,
        new_compute_weight: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ValidatorSetUpdated {
        epoch: u64,
        count: u64,
        total_weight: u256,
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
        sage_token: ContractAddress,
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.current_epoch.write(1);
        self.active_count.write(0);
        self.total_validators.write(0);
        self.min_stake.write(MIN_VALIDATOR_STAKE);
        self.max_commission_bps.write(2000); // 20% max commission
        
        self.stats.write(ValidatorStats {
            total_registered: 0,
            active_count: 0,
            jailed_count: 0,
            total_stake: 0,
            total_compute_weight: 0,
            current_epoch: 1,
        });
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl ValidatorRegistryImpl of IValidatorRegistry<ContractState> {
        fn register(
            ref self: ContractState,
            operator: ContractAddress,
            commission_bps: u16,
            attestation_hash: felt252,
        ) {
            let caller = get_caller_address();
            
            // Check not already registered
            let existing = self.validators.read(caller);
            let zero_addr: ContractAddress = 0.try_into().unwrap();
            assert(existing.address == zero_addr, 'Already registered');
            
            // Check commission
            assert(commission_bps <= self.max_commission_bps.read(), 'Commission too high');
            
            // Create validator
            let validator = ValidatorInfo {
                address: caller,
                operator,
                total_stake: 0,
                self_stake: 0,
                compute_weight: 0,
                effective_weight: 0,
                commission_bps,
                status: ValidatorStatus::Pending,
                blocks_produced: 0,
                proofs_verified: 0,
                last_active_epoch: 0,
                jail_release_epoch: 0,
                attestation_hash,
            };
            
            self.validators.write(caller, validator);
            
            // Add to list
            let idx = self.total_validators.read();
            self.all_validators.write(idx, caller);
            self.total_validators.write(idx + 1);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_registered = stats.total_registered + 1;
            self.stats.write(stats);
            
            self.emit(ValidatorRegistered {
                validator: caller,
                operator,
                commission_bps,
            });
        }

        fn update_validator(
            ref self: ContractState,
            commission_bps: u16,
            attestation_hash: felt252,
        ) {
            let caller = get_caller_address();
            let mut validator = self.validators.read(caller);
            
            let zero_addr: ContractAddress = 0.try_into().unwrap();
            assert(validator.address != zero_addr, 'Not registered');
            assert(commission_bps <= self.max_commission_bps.read(), 'Commission too high');
            
            validator.commission_bps = commission_bps;
            validator.attestation_hash = attestation_hash;
            self.validators.write(caller, validator);
            
            self.emit(ValidatorUpdated {
                validator: caller,
                commission_bps,
            });
        }

        fn exit(ref self: ContractState) {
            let caller = get_caller_address();
            let mut validator = self.validators.read(caller);
            
            assert(validator.status == ValidatorStatus::Active, 'Not active');
            
            validator.status = ValidatorStatus::Exited;
            self.validators.write(caller, validator);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.active_count = stats.active_count - 1;
            stats.total_stake = stats.total_stake - validator.total_stake;
            stats.total_compute_weight = stats.total_compute_weight - validator.compute_weight;
            self.stats.write(stats);
            
            // Remove from active list (swap and pop)
            self._remove_from_active_list(caller);
            
            self.emit(ValidatorExited {
                validator: caller,
            });
        }

        fn add_stake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut validator = self.validators.read(caller);
            
            let zero_addr: ContractAddress = 0.try_into().unwrap();
            assert(validator.address != zero_addr, 'Not registered');
            
            // Transfer tokens
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer_from(caller, starknet::get_contract_address(), amount);
            
            validator.self_stake = validator.self_stake + amount;
            validator.total_stake = validator.total_stake + amount;
            validator.effective_weight = validator.total_stake + validator.compute_weight;
            
            // Check if can become active
            if validator.status == ValidatorStatus::Pending 
                && validator.total_stake >= self.min_stake.read() {
                validator.status = ValidatorStatus::Active;
                
                // Add to active list
                let active_idx = self.active_count.read();
                self.active_validators.write(active_idx, caller);
                self.active_count.write(active_idx + 1);
                
                // Update stats
                let mut stats = self.stats.read();
                stats.active_count = stats.active_count + 1;
                self.stats.write(stats);
            }
            
            self.validators.write(caller, validator);
            
            // Update global stats
            let mut stats = self.stats.read();
            stats.total_stake = stats.total_stake + amount;
            self.stats.write(stats);
            
            self.emit(StakeAdded {
                validator: caller,
                amount,
                new_total: validator.total_stake,
            });
        }

        fn remove_stake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut validator = self.validators.read(caller);
            
            assert(validator.self_stake >= amount, 'Insufficient stake');
            
            validator.self_stake = validator.self_stake - amount;
            validator.total_stake = validator.total_stake - amount;
            validator.effective_weight = validator.total_stake + validator.compute_weight;
            
            // Check if falls below minimum
            if validator.status == ValidatorStatus::Active 
                && validator.total_stake < self.min_stake.read() {
                validator.status = ValidatorStatus::Pending;
                self._remove_from_active_list(caller);
                
                let mut stats = self.stats.read();
                stats.active_count = stats.active_count - 1;
                self.stats.write(stats);
            }
            
            self.validators.write(caller, validator);
            
            // Update global stats
            let mut stats = self.stats.read();
            stats.total_stake = stats.total_stake - amount;
            self.stats.write(stats);
            
            // Transfer tokens back (would go through unbonding in production)
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(caller, amount);
            
            self.emit(StakeRemoved {
                validator: caller,
                amount,
                new_total: validator.total_stake,
            });
        }

        fn record_compute_work(
            ref self: ContractState,
            validator: ContractAddress,
            weight: u256,
        ) {
            let caller = get_caller_address();
            assert(
                caller == self.staking_contract.read() || caller == self.owner.read(),
                'Unauthorized'
            );
            
            let mut info = self.validators.read(validator);
            info.compute_weight = info.compute_weight + weight;
            info.effective_weight = info.total_stake + info.compute_weight;
            info.last_active_epoch = self.current_epoch.read();
            self.validators.write(validator, info);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_compute_weight = stats.total_compute_weight + weight;
            self.stats.write(stats);
            
            self.emit(ComputeWorkRecorded {
                validator,
                weight,
                new_compute_weight: info.compute_weight,
            });
        }

        fn jail(
            ref self: ContractState,
            validator: ContractAddress,
            epochs: u64,
        ) {
            self._only_owner();
            
            let mut info = self.validators.read(validator);
            assert(info.status == ValidatorStatus::Active, 'Not active');
            
            info.status = ValidatorStatus::Jailed;
            info.jail_release_epoch = self.current_epoch.read() + epochs;
            self.validators.write(validator, info);
            
            self._remove_from_active_list(validator);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.active_count = stats.active_count - 1;
            stats.jailed_count = stats.jailed_count + 1;
            self.stats.write(stats);
            
            self.emit(ValidatorJailed {
                validator,
                release_epoch: info.jail_release_epoch,
            });
        }

        fn unjail(ref self: ContractState) {
            let caller = get_caller_address();
            let mut info = self.validators.read(caller);
            
            assert(info.status == ValidatorStatus::Jailed, 'Not jailed');
            assert(self.current_epoch.read() >= info.jail_release_epoch, 'Too early');
            assert(info.total_stake >= self.min_stake.read(), 'Insufficient stake');
            
            info.status = ValidatorStatus::Active;
            info.jail_release_epoch = 0;
            self.validators.write(caller, info);
            
            // Add back to active list
            let active_idx = self.active_count.read();
            self.active_validators.write(active_idx, caller);
            self.active_count.write(active_idx + 1);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.active_count = stats.active_count + 1;
            stats.jailed_count = stats.jailed_count - 1;
            self.stats.write(stats);
            
            self.emit(ValidatorUnjailed {
                validator: caller,
            });
        }

        fn tombstone(ref self: ContractState, validator: ContractAddress) {
            self._only_owner();
            
            let mut info = self.validators.read(validator);
            info.status = ValidatorStatus::Tombstoned;
            self.validators.write(validator, info);
            
            self.emit(ValidatorTombstoned { validator });
        }

        fn update_validator_set(ref self: ContractState) {
            self._only_owner();
            
            let epoch = self.current_epoch.read();
            let count = self.active_count.read();
            
            // Calculate total weight
            let mut total_weight: u256 = 0;
            let mut i: u64 = 0;
            
            loop {
                if i >= count {
                    break;
                }
                
                let validator_addr = self.active_validators.read(i);
                let info = self.validators.read(validator_addr);
                total_weight = total_weight + info.effective_weight;
                
                i = i + 1;
            };
            
            // Store validator set
            let set = ValidatorSet {
                count,
                total_weight,
                epoch,
            };
            self.validator_sets.write(epoch, set);
            
            self.emit(ValidatorSetUpdated {
                epoch,
                count,
                total_weight,
            });
        }

        fn advance_epoch(ref self: ContractState) {
            self._only_owner();
            
            // Update validator set before advancing
            self.update_validator_set();
            
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

        fn get_validator(self: @ContractState, validator: ContractAddress) -> ValidatorInfo {
            self.validators.read(validator)
        }

        fn get_validator_set(self: @ContractState, epoch: u64) -> ValidatorSet {
            self.validator_sets.read(epoch)
        }

        fn get_stats(self: @ContractState) -> ValidatorStats {
            self.stats.read()
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
        }

        fn is_active_validator(self: @ContractState, validator: ContractAddress) -> bool {
            let info = self.validators.read(validator);
            info.status == ValidatorStatus::Active
        }

        fn get_active_validators(self: @ContractState) -> Array<ContractAddress> {
            let mut result: Array<ContractAddress> = ArrayTrait::new();
            let count = self.active_count.read();
            let mut i: u64 = 0;
            
            loop {
                if i >= count {
                    break;
                }
                
                result.append(self.active_validators.read(i));
                i = i + 1;
            };
            
            result
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

        fn _remove_from_active_list(ref self: ContractState, validator: ContractAddress) {
            let count = self.active_count.read();
            let mut i: u64 = 0;
            
            loop {
                if i >= count {
                    break;
                }
                
                if self.active_validators.read(i) == validator {
                    // Swap with last and decrease count
                    let last_idx = count - 1;
                    if i != last_idx {
                        let last = self.active_validators.read(last_idx);
                        self.active_validators.write(i, last);
                    }
                    self.active_count.write(last_idx);
                    break;
                }
                
                i = i + 1;
            };
        }
    }
}

