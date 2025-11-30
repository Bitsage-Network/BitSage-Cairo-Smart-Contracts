// CIRO Network Milestone Vesting
// Token distribution based on achievement of specific milestones

use starknet::ContractAddress;

/// Milestone structure
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct Milestone {
    pub id: u256,
    pub description: felt252,
    pub target_amount: u256,
    pub completion_deadline: u64,
    pub completed: bool,
    pub completion_timestamp: u64,
    pub verified_by: ContractAddress,
    pub evidence_hash: felt252,
}

/// Milestone vesting schedule
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct MilestoneVestingSchedule {
    pub beneficiary: ContractAddress,
    pub total_amount: u256,
    pub released_amount: u256,
    pub milestone_count: u256,
    pub start_time: u64,
    pub created_by: ContractAddress,
    pub active: bool,
}

/// Milestone verification configuration
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct VerificationConfig {
    pub require_verification: bool,
    pub verification_timeout: u64,
    pub auto_verify_after_timeout: bool,
    pub min_verifiers: u8,
}

/// Events
#[derive(Drop, starknet::Event)]
pub struct MilestoneVestingCreated {
    pub schedule_id: u256,
    pub beneficiary: ContractAddress,
    pub total_amount: u256,
    pub milestone_count: u256,
}

#[derive(Drop, starknet::Event)]
pub struct MilestoneAdded {
    pub schedule_id: u256,
    pub milestone_id: u256,
    pub description: felt252,
    pub target_amount: u256,
    pub deadline: u64,
}

#[derive(Drop, starknet::Event)]
pub struct MilestoneCompleted {
    pub schedule_id: u256,
    pub milestone_id: u256,
    pub beneficiary: ContractAddress,
    pub amount_released: u256,
    pub verified_by: ContractAddress,
}

#[derive(Drop, starknet::Event)]
pub struct MilestoneVerified {
    pub schedule_id: u256,
    pub milestone_id: u256,
    pub verifier: ContractAddress,
    pub evidence_hash: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct TokensReleased {
    pub schedule_id: u256,
    pub beneficiary: ContractAddress,
    pub milestone_id: u256,
    pub amount: u256,
}

/// Milestone Vesting Contract
#[starknet::contract]
pub mod MilestoneVesting {
    use super::{
        Milestone, MilestoneVestingSchedule, VerificationConfig,
        MilestoneVestingCreated, MilestoneAdded, MilestoneCompleted,
        MilestoneVerified, TokensReleased
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
        config: VerificationConfig,
        
        // Vesting schedules
        schedule_count: u256,
        schedules: Map<u256, MilestoneVestingSchedule>,
        
        // Milestones - (schedule_id, milestone_index) -> milestone
        milestones: Map<(u256, u256), Milestone>,
        
        // Verification tracking
        verifiers: Map<ContractAddress, bool>,
        milestone_verifications: Map<(u256, u256, ContractAddress), bool>, // (schedule_id, milestone_id, verifier) -> verified
        milestone_verification_count: Map<(u256, u256), u8>, // (schedule_id, milestone_id) -> count
        
        // Beneficiary tracking
        beneficiary_schedules: Map<ContractAddress, u256>,
        beneficiary_schedule_ids: Map<(ContractAddress, u256), u256>,
        
        // Totals
        total_allocated: u256,
        total_released: u256,
        
        // Access control
        paused: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        MilestoneVestingCreated: MilestoneVestingCreated,
        MilestoneAdded: MilestoneAdded,
        MilestoneCompleted: MilestoneCompleted,
        MilestoneVerified: MilestoneVerified,
        TokensReleased: TokensReleased,
        VerifierAdded: VerifierAdded,
        VerifierRemoved: VerifierRemoved,
        OwnershipTransferred: OwnershipTransferred,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VerifierAdded {
        pub verifier: ContractAddress,
        pub added_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VerifierRemoved {
        pub verifier: ContractAddress,
        pub removed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct OwnershipTransferred {
        pub previous_owner: ContractAddress,
        pub new_owner: ContractAddress,
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
        config: VerificationConfig
    ) {
        self.owner.write(owner);
        self.token_contract.write(token_contract);
        self.config.write(config);
        self.schedule_count.write(0);
        self.total_allocated.write(0);
        self.total_released.write(0);
        self.paused.write(false);
        
        // Owner is automatically a verifier
        self.verifiers.write(owner, true);
    }

    #[abi(embed_v0)]
    impl MilestoneVestingImpl of super::IMilestoneVesting<ContractState> {
        fn create_milestone_vesting_schedule(
            ref self: ContractState,
            beneficiary: ContractAddress,
            total_amount: u256,
            milestones: Array<(felt252, u256, u64)> // (description, amount, deadline)
        ) -> u256 {
            self._assert_only_owner();
            self._assert_not_paused();
            assert(!beneficiary.is_zero(), 'Invalid beneficiary');
            assert(total_amount > 0, 'Amount must be positive');
            assert(milestones.len() > 0, 'Must have milestones');
            
            let schedule_id = self.schedule_count.read();
            let current_time = get_block_timestamp();
            
            // Validate milestone amounts sum to total
            let mut total_milestone_amount = 0;
            let mut i = 0;
            while i != milestones.len() {
                let (_, amount, _) = *milestones.at(i);
                total_milestone_amount += amount;
                i += 1;
            };
            assert(total_milestone_amount == total_amount, 'Milestone amounts mismatch');
            
            let schedule = MilestoneVestingSchedule {
                beneficiary,
                total_amount,
                released_amount: 0,
                milestone_count: milestones.len().into(),
                start_time: current_time,
                created_by: get_caller_address(),
                active: true,
            };
            
            self.schedules.write(schedule_id, schedule);
            
            // Create milestones
            let mut milestone_index = 0;
            while milestone_index != milestones.len() {
                let (description, amount, deadline) = *milestones.at(milestone_index);
                assert(deadline > current_time, 'Deadline must be in future');
                
                let milestone = Milestone {
                    id: milestone_index.into(),
                    description,
                    target_amount: amount,
                    completion_deadline: deadline,
                    completed: false,
                    completion_timestamp: 0,
                    verified_by: 0.try_into().unwrap(),
                    evidence_hash: 0,
                };
                
                self.milestones.write((schedule_id, milestone_index.into()), milestone);
                
                self.emit(MilestoneAdded {
                    schedule_id,
                    milestone_id: milestone_index.into(),
                    description,
                    target_amount: amount,
                    deadline,
                });
                
                milestone_index += 1;
            };
            
            // Update beneficiary tracking
            let beneficiary_count = self.beneficiary_schedules.read(beneficiary);
            self.beneficiary_schedule_ids.write((beneficiary, beneficiary_count), schedule_id);
            self.beneficiary_schedules.write(beneficiary, beneficiary_count + 1);
            
            // Update counters
            self.schedule_count.write(schedule_id + 1);
            self.total_allocated.write(self.total_allocated.read() + total_amount);
            
            self.emit(MilestoneVestingCreated {
                schedule_id,
                beneficiary,
                total_amount,
                milestone_count: milestones.len().into(),
            });
            
            schedule_id
        }

        fn submit_milestone_completion(
            ref self: ContractState,
            schedule_id: u256,
            milestone_id: u256,
            evidence_hash: felt252
        ) {
            self._assert_not_paused();
            let caller = get_caller_address();
            let schedule = self.schedules.read(schedule_id);
            
            assert(schedule.active, 'Schedule not active');
            assert(schedule.beneficiary == caller, 'Only beneficiary can submit');
            assert(milestone_id < schedule.milestone_count, 'Invalid milestone ID');
            
            let milestone = self.milestones.read((schedule_id, milestone_id));
            assert(!milestone.completed, 'Milestone already completed');
            assert(get_block_timestamp() <= milestone.completion_deadline, 'Milestone deadline passed');
            
            // Update milestone with evidence
            let mut updated_milestone = milestone;
            updated_milestone.evidence_hash = evidence_hash;
            self.milestones.write((schedule_id, milestone_id), updated_milestone);
            
            // If verification not required, auto-complete
            let config = self.config.read();
            if !config.require_verification {
                self._complete_milestone(schedule_id, milestone_id, caller);
            }
        }

        fn verify_milestone(
            ref self: ContractState,
            schedule_id: u256,
            milestone_id: u256,
            approved: bool
        ) {
            self._assert_not_paused();
            let caller = get_caller_address();
            assert(self.verifiers.read(caller), 'Not authorized verifier');
            
            let schedule = self.schedules.read(schedule_id);
            assert(schedule.active, 'Schedule not active');
            
            let milestone = self.milestones.read((schedule_id, milestone_id));
            assert(!milestone.completed, 'Milestone already completed');
            assert(milestone.evidence_hash != 0, 'No evidence submitted');
            
            // Check if verifier already voted
            assert(!self.milestone_verifications.read((schedule_id, milestone_id, caller)), 'Already verified');
            
            if approved {
                self.milestone_verifications.write((schedule_id, milestone_id, caller), true);
                let verification_count = self.milestone_verification_count.read((schedule_id, milestone_id)) + 1;
                self.milestone_verification_count.write((schedule_id, milestone_id), verification_count);
                
                self.emit(MilestoneVerified {
                    schedule_id,
                    milestone_id,
                    verifier: caller,
                    evidence_hash: milestone.evidence_hash,
                });
                
                // Check if enough verifications
                let config = self.config.read();
                if verification_count >= config.min_verifiers {
                    self._complete_milestone(schedule_id, milestone_id, caller);
                }
            }
        }

        fn release_milestone_tokens(ref self: ContractState, schedule_id: u256, milestone_id: u256) -> u256 {
            self._assert_not_paused();
            let caller = get_caller_address();
            let schedule = self.schedules.read(schedule_id);
            
            assert(schedule.beneficiary == caller || caller == self.owner.read(), 'Not authorized');
            assert(schedule.active, 'Schedule not active');
            
            let milestone = self.milestones.read((schedule_id, milestone_id));
            assert(milestone.completed, 'Milestone not completed');
            
            let amount = milestone.target_amount;
            
            // Update schedule released amount
            let mut updated_schedule = schedule;
            updated_schedule.released_amount += amount;
            self.schedules.write(schedule_id, updated_schedule);
            
            // Update total released
            self.total_released.write(self.total_released.read() + amount);
            
            // Transfer tokens (in real implementation, would call token contract)
            // IERC20(token_contract).transfer(schedule.beneficiary, amount);
            
            self.emit(TokensReleased {
                schedule_id,
                beneficiary: schedule.beneficiary,
                milestone_id,
                amount,
            });
            
            amount
        }

        fn get_milestone_vesting_schedule(self: @ContractState, schedule_id: u256) -> MilestoneVestingSchedule {
            self.schedules.read(schedule_id)
        }

        fn get_milestone(self: @ContractState, schedule_id: u256, milestone_id: u256) -> Milestone {
            self.milestones.read((schedule_id, milestone_id))
        }

        fn get_schedule_milestones(
            self: @ContractState,
            schedule_id: u256
        ) -> Array<Milestone> {
            let schedule = self.schedules.read(schedule_id);
            let mut milestones = ArrayTrait::new();
            
            let mut i = 0;
            while i != schedule.milestone_count {
                let milestone = self.milestones.read((schedule_id, i));
                milestones.append(milestone);
                i += 1;
            };
            
            milestones
        }

        fn get_completed_milestones_count(self: @ContractState, schedule_id: u256) -> u256 {
            let schedule = self.schedules.read(schedule_id);
            let mut completed = 0;
            
            let mut i = 0;
            while i != schedule.milestone_count {
                let milestone = self.milestones.read((schedule_id, i));
                if milestone.completed {
                    completed += 1;
                }
                i += 1;
            };
            
            completed
        }

        fn get_releasable_amount(self: @ContractState, schedule_id: u256) -> u256 {
            let schedule = self.schedules.read(schedule_id);
            let mut releasable = 0;
            
            let mut i = 0;
            while i != schedule.milestone_count {
                let milestone = self.milestones.read((schedule_id, i));
                if milestone.completed {
                    releasable += milestone.target_amount;
                }
                i += 1;
            };
            
            // Subtract already released amount
            if releasable > schedule.released_amount {
                releasable - schedule.released_amount
            } else {
                0
            }
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

        fn add_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._assert_only_owner();
            self.verifiers.write(verifier, true);
            
            self.emit(VerifierAdded {
                verifier,
                added_by: get_caller_address(),
            });
        }

        fn remove_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._assert_only_owner();
            self.verifiers.write(verifier, false);
            
            self.emit(VerifierRemoved {
                verifier,
                removed_by: get_caller_address(),
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
            
            // Transfer verifier status
            self.verifiers.write(previous_owner, false);
            self.verifiers.write(new_owner, true);
            
            self.emit(OwnershipTransferred {
                previous_owner,
                new_owner,
            });
        }

        fn get_total_allocated(self: @ContractState) -> u256 {
            self.total_allocated.read()
        }

        fn get_total_released(self: @ContractState) -> u256 {
            self.total_released.read()
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

        fn _complete_milestone(
            ref self: ContractState,
            schedule_id: u256,
            milestone_id: u256,
            verifier: ContractAddress
        ) {
            let mut milestone = self.milestones.read((schedule_id, milestone_id));
            milestone.completed = true;
            milestone.completion_timestamp = get_block_timestamp();
            milestone.verified_by = verifier;
            self.milestones.write((schedule_id, milestone_id), milestone);
            
            let schedule = self.schedules.read(schedule_id);
            
            self.emit(MilestoneCompleted {
                schedule_id,
                milestone_id,
                beneficiary: schedule.beneficiary,
                amount_released: milestone.target_amount,
                verified_by: verifier,
            });
        }
    }
}

/// Interface for Milestone Vesting Contract
#[starknet::interface]
pub trait IMilestoneVesting<TContractState> {
    fn create_milestone_vesting_schedule(
        ref self: TContractState,
        beneficiary: ContractAddress,
        total_amount: u256,
        milestones: Array<(felt252, u256, u64)>
    ) -> u256;
    
    fn submit_milestone_completion(
        ref self: TContractState,
        schedule_id: u256,
        milestone_id: u256,
        evidence_hash: felt252
    );
    
    fn verify_milestone(
        ref self: TContractState,
        schedule_id: u256,
        milestone_id: u256,
        approved: bool
    );
    
    fn release_milestone_tokens(ref self: TContractState, schedule_id: u256, milestone_id: u256) -> u256;
    
    fn get_milestone_vesting_schedule(self: @TContractState, schedule_id: u256) -> MilestoneVestingSchedule;
    fn get_milestone(self: @TContractState, schedule_id: u256, milestone_id: u256) -> Milestone;
    fn get_schedule_milestones(self: @TContractState, schedule_id: u256) -> Array<Milestone>;
    fn get_completed_milestones_count(self: @TContractState, schedule_id: u256) -> u256;
    fn get_releasable_amount(self: @TContractState, schedule_id: u256) -> u256;
    fn get_beneficiary_schedules(self: @TContractState, beneficiary: ContractAddress) -> Array<u256>;
    
    fn add_verifier(ref self: TContractState, verifier: ContractAddress);
    fn remove_verifier(ref self: TContractState, verifier: ContractAddress);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn get_total_allocated(self: @TContractState) -> u256;
    fn get_total_released(self: @TContractState) -> u256;
}

/// Utility functions for milestone vesting
pub fn validate_milestones(
    milestones: @Array<(felt252, u256, u64)>,
    total_amount: u256,
    current_time: u64
) -> bool {
    if milestones.len() == 0 {
        return false;
    }
    
    let mut total_milestone_amount = 0;
    let mut i = 0;
    
    while i != milestones.len() {
        let (_, amount, deadline) = *milestones.at(i);
        
        if amount == 0 || deadline <= current_time {
            return false;
        }
        
        total_milestone_amount += amount;
        i += 1;
    };
    
    total_milestone_amount == total_amount
}

pub fn get_default_verification_config() -> VerificationConfig {
    VerificationConfig {
        require_verification: true,
        verification_timeout: 7 * 24 * 3600, // 7 days
        auto_verify_after_timeout: false,
        min_verifiers: 2,
    }
} 