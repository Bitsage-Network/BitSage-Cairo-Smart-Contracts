// CIRO Network Linear Vesting with Cliff
// Token distribution schedules with cliff periods and linear release

use starknet::ContractAddress;

/// Vesting schedule structure
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct VestingSchedule {
    pub beneficiary: ContractAddress,
    pub total_amount: u256,
    pub released_amount: u256,
    pub start_time: u64,
    pub cliff_duration: u64,
    pub vesting_duration: u64,
    pub revocable: bool,
    pub revoked: bool,
    pub created_by: ContractAddress,
}

/// Vesting configuration
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct VestingConfig {
    pub min_cliff_duration: u64,
    pub max_cliff_duration: u64,
    pub min_vesting_duration: u64,
    pub max_vesting_duration: u64,
    pub allow_revocation: bool,
}

/// Vesting Events
#[derive(Drop, starknet::Event)]
pub struct VestingScheduleCreated {
    pub schedule_id: u256,
    pub beneficiary: ContractAddress,
    pub total_amount: u256,
    pub start_time: u64,
    pub cliff_duration: u64,
    pub vesting_duration: u64,
}

#[derive(Drop, starknet::Event)]
pub struct TokensReleased {
    pub schedule_id: u256,
    pub beneficiary: ContractAddress,
    pub amount: u256,
    pub released_timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct VestingRevoked {
    pub schedule_id: u256,
    pub beneficiary: ContractAddress,
    pub revoked_amount: u256,
    pub released_amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct VestingTransferred {
    pub schedule_id: u256,
    pub old_beneficiary: ContractAddress,
    pub new_beneficiary: ContractAddress,
}

/// Linear Vesting Contract
#[starknet::contract]
pub mod LinearVestingWithCliff {
    use super::{
        VestingSchedule, VestingConfig,
        VestingScheduleCreated, TokensReleased, VestingRevoked, VestingTransferred
    };
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;

    #[storage]
    struct Storage {
        // Core state
        owner: ContractAddress,
        token_contract: ContractAddress,
        config: VestingConfig,
        
        // Vesting schedules
        schedule_count: u256,
        schedules: Map<u256, VestingSchedule>,
        beneficiary_schedules: Map<ContractAddress, u256>, // beneficiary -> schedule count
        beneficiary_schedule_ids: Map<(ContractAddress, u256), u256>, // (beneficiary, index) -> schedule_id
        
        // Total amounts
        total_allocated: u256,
        total_released: u256,
        
        // Access control
        authorized_creators: Map<ContractAddress, bool>,
        paused: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        VestingScheduleCreated: VestingScheduleCreated,
        TokensReleased: TokensReleased,
        VestingRevoked: VestingRevoked,
        VestingTransferred: VestingTransferred,
        OwnershipTransferred: OwnershipTransferred,
        CreatorAuthorized: CreatorAuthorized,
        CreatorDeauthorized: CreatorDeauthorized,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnershipTransferred {
        pub previous_owner: ContractAddress,
        pub new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CreatorAuthorized {
        pub creator: ContractAddress,
        pub authorized_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CreatorDeauthorized {
        pub creator: ContractAddress,
        pub deauthorized_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContractPaused {
        pub paused_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContractUnpaused {
        pub unpaused_by: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        token_contract: ContractAddress,
        config: VestingConfig
    ) {
        self.owner.write(owner);
        self.token_contract.write(token_contract);
        self.config.write(config);
        self.schedule_count.write(0);
        self.total_allocated.write(0);
        self.total_released.write(0);
        self.paused.write(false);
        
        // Owner is automatically authorized creator
        self.authorized_creators.write(owner, true);
    }

    #[abi(embed_v0)]
    impl LinearVestingImpl of super::ILinearVesting<ContractState> {
        fn create_vesting_schedule(
            ref self: ContractState,
            beneficiary: ContractAddress,
            total_amount: u256,
            cliff_duration: u64,
            vesting_duration: u64,
            revocable: bool
        ) -> u256 {
            self._assert_not_paused();
            let caller = get_caller_address();
            assert(self.authorized_creators.read(caller), 'Not authorized creator');
            assert(!beneficiary.is_zero(), 'Invalid beneficiary');
            assert(total_amount > 0, 'Amount must be positive');
            
            let config = self.config.read();
            self._validate_vesting_parameters(cliff_duration, vesting_duration, config);
            
            let schedule_id = self.schedule_count.read();
            let current_time = get_block_timestamp();
            
            let schedule = VestingSchedule {
                beneficiary,
                total_amount,
                released_amount: 0,
                start_time: current_time,
                cliff_duration,
                vesting_duration,
                revocable,
                revoked: false,
                created_by: caller,
            };
            
            self.schedules.write(schedule_id, schedule);
            
            // Update beneficiary tracking
            let beneficiary_count = self.beneficiary_schedules.read(beneficiary);
            self.beneficiary_schedule_ids.write((beneficiary, beneficiary_count), schedule_id);
            self.beneficiary_schedules.write(beneficiary, beneficiary_count + 1);
            
            // Update counters
            self.schedule_count.write(schedule_id + 1);
            self.total_allocated.write(self.total_allocated.read() + total_amount);
            
            self.emit(VestingScheduleCreated {
                schedule_id,
                beneficiary,
                total_amount,
                start_time: current_time,
                cliff_duration,
                vesting_duration,
            });
            
            schedule_id
        }

        fn release_tokens(ref self: ContractState, schedule_id: u256) -> u256 {
            self._assert_not_paused();
            let caller = get_caller_address();
            let mut schedule = self.schedules.read(schedule_id);
            
            assert(schedule.beneficiary == caller || caller == self.owner.read(), 'Not authorized');
            assert(!schedule.revoked, 'Schedule revoked');
            
            let releasable_amount = self._calculate_releasable_amount(schedule);
            assert(releasable_amount > 0, 'No tokens to release');
            
            schedule.released_amount += releasable_amount;
            self.schedules.write(schedule_id, schedule);
            
            self.total_released.write(self.total_released.read() + releasable_amount);
            
            // Transfer tokens (in real implementation, would call token contract)
            // IERC20(token_contract).transfer(schedule.beneficiary, releasable_amount);
            
            self.emit(TokensReleased {
                schedule_id,
                beneficiary: schedule.beneficiary,
                amount: releasable_amount,
                released_timestamp: get_block_timestamp(),
            });
            
            releasable_amount
        }

        fn revoke_vesting_schedule(ref self: ContractState, schedule_id: u256) {
            self._assert_only_owner();
            let mut schedule = self.schedules.read(schedule_id);
            
            assert(schedule.revocable, 'Schedule not revocable');
            assert(!schedule.revoked, 'Already revoked');
            
            let releasable_amount = self._calculate_releasable_amount(schedule);
            let revoked_amount = schedule.total_amount - schedule.released_amount - releasable_amount;
            
            // Release any currently releasable tokens
            if releasable_amount > 0 {
                schedule.released_amount += releasable_amount;
                self.total_released.write(self.total_released.read() + releasable_amount);
                
                // Transfer releasable tokens
                // IERC20(token_contract).transfer(schedule.beneficiary, releasable_amount);
            }
            
            schedule.revoked = true;
            self.schedules.write(schedule_id, schedule);
            
            // Return revoked tokens to owner/treasury
            if revoked_amount > 0 {
                // IERC20(token_contract).transfer(owner, revoked_amount);
            }
            
            self.emit(VestingRevoked {
                schedule_id,
                beneficiary: schedule.beneficiary,
                revoked_amount,
                released_amount: releasable_amount,
            });
        }

        fn transfer_vesting_schedule(
            ref self: ContractState,
            schedule_id: u256,
            new_beneficiary: ContractAddress
        ) {
            let caller = get_caller_address();
            let mut schedule = self.schedules.read(schedule_id);
            
            assert(schedule.beneficiary == caller, 'Not beneficiary');
            assert(!new_beneficiary.is_zero(), 'Invalid new beneficiary');
            assert(!schedule.revoked, 'Schedule revoked');
            
            let old_beneficiary = schedule.beneficiary;
            schedule.beneficiary = new_beneficiary;
            self.schedules.write(schedule_id, schedule);
            
            // Update beneficiary tracking for new beneficiary
            let new_beneficiary_count = self.beneficiary_schedules.read(new_beneficiary);
            self.beneficiary_schedule_ids.write((new_beneficiary, new_beneficiary_count), schedule_id);
            self.beneficiary_schedules.write(new_beneficiary, new_beneficiary_count + 1);
            
            self.emit(VestingTransferred {
                schedule_id,
                old_beneficiary,
                new_beneficiary,
            });
        }

        fn get_vesting_schedule(self: @ContractState, schedule_id: u256) -> VestingSchedule {
            self.schedules.read(schedule_id)
        }

        fn get_releasable_amount(self: @ContractState, schedule_id: u256) -> u256 {
            let schedule = self.schedules.read(schedule_id);
            self._calculate_releasable_amount(schedule)
        }

        fn get_beneficiary_schedules(
            self: @ContractState,
            beneficiary: ContractAddress
        ) -> Array<u256> {
            let mut schedule_ids = ArrayTrait::new();
            let count = self.beneficiary_schedules.read(beneficiary);
            
            let mut i = 0;
            while i != count {
                let schedule_id = self.beneficiary_schedule_ids.read((beneficiary, i));
                schedule_ids.append(schedule_id);
                i += 1;
            };
            
            schedule_ids
        }

        fn get_total_allocated(self: @ContractState) -> u256 {
            self.total_allocated.read()
        }

        fn get_total_released(self: @ContractState) -> u256 {
            self.total_released.read()
        }

        fn authorize_creator(ref self: ContractState, creator: ContractAddress) {
            self._assert_only_owner();
            self.authorized_creators.write(creator, true);
            
            self.emit(CreatorAuthorized {
                creator,
                authorized_by: get_caller_address(),
            });
        }

        fn deauthorize_creator(ref self: ContractState, creator: ContractAddress) {
            self._assert_only_owner();
            self.authorized_creators.write(creator, false);
            
            self.emit(CreatorDeauthorized {
                creator,
                deauthorized_by: get_caller_address(),
            });
        }

        fn pause(ref self: ContractState) {
            self._assert_only_owner();
            self.paused.write(true);
            
            self.emit(ContractPaused {
                paused_by: get_caller_address(),
            });
        }

        fn unpause(ref self: ContractState) {
            self._assert_only_owner();
            self.paused.write(false);
            
            self.emit(ContractUnpaused {
                unpaused_by: get_caller_address(),
            });
        }

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self._assert_only_owner();
            assert(!new_owner.is_zero(), 'Invalid new owner');
            
            let previous_owner = self.owner.read();
            self.owner.write(new_owner);
            
            // Deauthorize old owner and authorize new owner
            self.authorized_creators.write(previous_owner, false);
            self.authorized_creators.write(new_owner, true);
            
            self.emit(OwnershipTransferred {
                previous_owner,
                new_owner,
            });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Only owner');
        }

        fn _assert_not_paused(self: @ContractState) {
            assert(!self.paused.read(), 'Contract paused');
        }

        fn _validate_vesting_parameters(
            self: @ContractState,
            cliff_duration: u64,
            vesting_duration: u64,
            config: VestingConfig
        ) {
            assert(cliff_duration >= config.min_cliff_duration, 'Cliff too short');
            assert(cliff_duration <= config.max_cliff_duration, 'Cliff too long');
            assert(vesting_duration >= config.min_vesting_duration, 'Vesting too short');
            assert(vesting_duration <= config.max_vesting_duration, 'Vesting too long');
            assert(vesting_duration > cliff_duration, 'Vesting > cliff');
        }

        fn _calculate_releasable_amount(self: @ContractState, schedule: VestingSchedule) -> u256 {
            if schedule.revoked {
                return 0;
            }
            
            let current_time = get_block_timestamp();
            let cliff_end = schedule.start_time + schedule.cliff_duration;
            
            // Before cliff, nothing is releasable
            if current_time < cliff_end {
                return 0;
            }
            
            let vesting_end = schedule.start_time + schedule.vesting_duration;
            
            let vested_amount = if current_time >= vesting_end {
                // Fully vested
                schedule.total_amount
            } else {
                // Linear vesting after cliff
                let time_since_cliff = current_time - cliff_end;
                let vesting_period = vesting_end - cliff_end;
                (schedule.total_amount * time_since_cliff.into()) / vesting_period.into()
            };
            
            // Return releasable amount (vested - already released)
            if vested_amount > schedule.released_amount {
                vested_amount - schedule.released_amount
            } else {
                0
            }
        }
    }
}

/// Interface for Linear Vesting Contract
#[starknet::interface]
pub trait ILinearVesting<TContractState> {
    fn create_vesting_schedule(
        ref self: TContractState,
        beneficiary: ContractAddress,
        total_amount: u256,
        cliff_duration: u64,
        vesting_duration: u64,
        revocable: bool
    ) -> u256;
    
    fn release_tokens(ref self: TContractState, schedule_id: u256) -> u256;
    fn revoke_vesting_schedule(ref self: TContractState, schedule_id: u256);
    fn transfer_vesting_schedule(ref self: TContractState, schedule_id: u256, new_beneficiary: ContractAddress);
    
    fn get_vesting_schedule(self: @TContractState, schedule_id: u256) -> VestingSchedule;
    fn get_releasable_amount(self: @TContractState, schedule_id: u256) -> u256;
    fn get_beneficiary_schedules(self: @TContractState, beneficiary: ContractAddress) -> Array<u256>;
    fn get_total_allocated(self: @TContractState) -> u256;
    fn get_total_released(self: @TContractState) -> u256;
    
    fn authorize_creator(ref self: TContractState, creator: ContractAddress);
    fn deauthorize_creator(ref self: TContractState, creator: ContractAddress);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
}

/// Utility functions for vesting calculations
pub fn calculate_vested_amount(
    total_amount: u256,
    start_time: u64,
    cliff_duration: u64,
    vesting_duration: u64,
    current_time: u64
) -> u256 {
    let cliff_end = start_time + cliff_duration;
    
    if current_time < cliff_end {
        return 0;
    }
    
    let vesting_end = start_time + vesting_duration;
    
    if current_time >= vesting_end {
        return total_amount;
    }
    
    let time_since_cliff = current_time - cliff_end;
    let vesting_period = vesting_end - cliff_end;
    (total_amount * time_since_cliff.into()) / vesting_period.into()
}

pub fn get_default_vesting_config() -> VestingConfig {
    VestingConfig {
        min_cliff_duration: 0,                    // No minimum cliff
        max_cliff_duration: 365 * 24 * 3600,     // Max 1 year cliff
        min_vesting_duration: 30 * 24 * 3600,    // Min 30 days vesting
        max_vesting_duration: 4 * 365 * 24 * 3600, // Max 4 years vesting
        allow_revocation: true,
    }
}

pub fn validate_vesting_schedule(
    total_amount: u256,
    cliff_duration: u64,
    vesting_duration: u64,
    config: VestingConfig
) -> bool {
    total_amount > 0 &&
    cliff_duration >= config.min_cliff_duration &&
    cliff_duration <= config.max_cliff_duration &&
    vesting_duration >= config.min_vesting_duration &&
    vesting_duration <= config.max_vesting_duration &&
    vesting_duration > cliff_duration
} 