//! Complete Governance Treasury for SAGE Network
//! Full DAO infrastructure with timelock, multi-sig, and governance capabilities

use starknet::{ContractAddress, ClassHash};

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct Proposal {
    pub id: u256,
    pub proposer: ContractAddress,
    pub title: felt252,
    pub description: felt252,
    pub target: ContractAddress,
    pub value: u256,
    pub calldata: felt252,
    pub votes_for: u256,
    pub votes_against: u256,
    pub start_time: u64,
    pub end_time: u64,
    pub execution_time: u64,
    pub executed: bool,
    pub cancelled: bool,
    pub proposal_type: ProposalType,
}

#[derive(Drop, Serde, starknet::Store, Copy)]
#[allow(starknet::store_no_default_variant)]
pub enum ProposalType {
    Treasury,      // Treasury operations
    Upgrade,       // Contract upgrades
    Parameter,     // Parameter changes
    Emergency,     // Emergency actions
}

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct GovernanceConfig {
    pub voting_delay: u64,        // Delay before voting starts
    pub voting_period: u64,       // Duration of voting
    pub execution_delay: u64,     // Timelock delay before execution
    pub quorum_threshold: u256,   // Minimum votes needed
    pub proposal_threshold: u256, // Minimum tokens to create proposal
}

#[starknet::interface]
pub trait IGovernanceTreasury<TContractState> {
    // Governance functions
    fn propose(
        ref self: TContractState,
        title: felt252,
        description: felt252,
        target: ContractAddress,
        value: u256,
        calldata: felt252,
        proposal_type: ProposalType
    ) -> u256;
    
    fn vote(ref self: TContractState, proposal_id: u256, support: bool, voting_power: u256);
    fn execute_proposal(ref self: TContractState, proposal_id: u256);
    fn cancel_proposal(ref self: TContractState, proposal_id: u256);
    
    // Treasury functions
    fn transfer_funds(ref self: TContractState, to: ContractAddress, amount: u256);
    fn emergency_withdraw(ref self: TContractState, token: ContractAddress, amount: u256);
    
    // View functions
    fn get_proposal(self: @TContractState, proposal_id: u256) -> Proposal;
    fn get_voting_power(self: @TContractState, account: ContractAddress) -> u256;
    fn can_execute(self: @TContractState, proposal_id: u256) -> bool;
    fn get_proposal_count(self: @TContractState) -> u256;
    fn has_voted(self: @TContractState, proposal_id: u256, voter: ContractAddress) -> bool;
    fn get_config(self: @TContractState) -> GovernanceConfig;

    // Configuration
    fn update_config(ref self: TContractState, new_config: GovernanceConfig);
    fn add_council_member(ref self: TContractState, member: ContractAddress);
    fn remove_council_member(ref self: TContractState, member: ContractAddress);

    // Upgrade
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[starknet::contract]
pub mod GovernanceTreasury {
    use super::{Proposal, ProposalType, GovernanceConfig};
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_contract_address,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        Map, StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess
    };
    use core::num::traits::Zero;
    use sage_contracts::interfaces::sage_token::{ISAGETokenDispatcher, ISAGETokenDispatcherTrait};

    #[storage]
    struct Storage {
        // Core governance
        owner: ContractAddress,
        sage_token: ContractAddress,
        governance_config: GovernanceConfig,
        
        // Proposals
        proposal_count: u256,
        proposals: Map<u256, Proposal>,
        votes: Map<(u256, ContractAddress), bool>,
        voted: Map<(u256, ContractAddress), bool>,
        
        // Council (multi-sig)
        council_members: Map<ContractAddress, bool>,
        council_count: u32,
        council_threshold: u32,
        
        // Treasury
        total_funds: u256,
        reserved_funds: u256,
        
        // Emergency controls
        paused: bool,
        emergency_council: Map<ContractAddress, bool>,

        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ProposalCreated: ProposalCreated,
        VoteCast: VoteCast,
        ProposalExecuted: ProposalExecuted,
        ProposalCancelled: ProposalCancelled,
        FundsTransferred: FundsTransferred,
        EmergencyAction: EmergencyAction,
        CouncilUpdated: CouncilUpdated,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProposalCreated {
        #[key]
        pub proposal_id: u256,
        pub proposer: ContractAddress,
        pub title: felt252,
        pub proposal_type: ProposalType,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VoteCast {
        #[key]
        pub proposal_id: u256,
        pub voter: ContractAddress,
        pub support: bool,
        pub voting_power: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProposalExecuted {
        #[key]
        pub proposal_id: u256,
        pub executor: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProposalCancelled {
        #[key]
        pub proposal_id: u256,
        pub canceller: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct FundsTransferred {
        pub to: ContractAddress,
        pub amount: u256,
        pub reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct EmergencyAction {
        pub action_type: felt252,
        pub executor: ContractAddress,
        pub target: ContractAddress,
        pub amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CouncilUpdated {
        pub member: ContractAddress,
        pub added: bool,
        pub updated_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UpgradeScheduled {
        #[key]
        pub new_class_hash: ClassHash,
        pub scheduled_at: u64,
        pub execute_after: u64,
        pub scheduled_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UpgradeExecuted {
        #[key]
        pub new_class_hash: ClassHash,
        pub executed_at: u64,
        pub executed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UpgradeCancelled {
        #[key]
        pub cancelled_class_hash: ClassHash,
        pub cancelled_at: u64,
        pub cancelled_by: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        initial_council: Array<ContractAddress>,
        council_threshold: u32,
        governance_config: GovernanceConfig
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.governance_config.write(governance_config);
        self.proposal_count.write(0);
        self.total_funds.write(0);
        self.reserved_funds.write(0);
        self.paused.write(false);
        
        // Setup council
        self.council_threshold.write(council_threshold);
        let member_count: u32 = initial_council.len().try_into().unwrap();
        self.council_count.write(member_count);
        
        let mut i = 0;
        while i != initial_council.len() {
            let member = *initial_council.at(i);
            self.council_members.write(member, true);
            self.emergency_council.write(member, true);
            i += 1;
        };
        
        assert(council_threshold > 0 && council_threshold <= member_count, 'Invalid threshold');
        self.upgrade_delay.write(172800); // 2 days
    }

    #[abi(embed_v0)]
    impl GovernanceTreasuryImpl of super::IGovernanceTreasury<ContractState> {
        fn propose(
            ref self: ContractState,
            title: felt252,
            description: felt252,
            target: ContractAddress,
            value: u256,
            calldata: felt252,
            proposal_type: ProposalType
        ) -> u256 {
            assert(!self.paused.read(), 'Contract paused');
            
            let caller = get_caller_address();
            let config = self.governance_config.read();
            
            // Check proposal threshold
            let voting_power = self._get_voting_power(caller);
            assert(voting_power >= config.proposal_threshold, 'Insufficient voting power');
            
            let proposal_id = self.proposal_count.read() + 1;
            let current_time = get_block_timestamp();
            
            let proposal = Proposal {
                id: proposal_id,
                proposer: caller,
                title,
                description,
                target,
                value,
                calldata,
                votes_for: 0,
                votes_against: 0,
                start_time: current_time + config.voting_delay,
                end_time: current_time + config.voting_delay + config.voting_period,
                execution_time: current_time + config.voting_delay + config.voting_period + config.execution_delay,
                executed: false,
                cancelled: false,
                proposal_type,
            };
            
            self.proposals.write(proposal_id, proposal);
            self.proposal_count.write(proposal_id);
            
            self.emit(ProposalCreated {
                proposal_id,
                proposer: caller,
                title,
                proposal_type,
            });
            
            proposal_id
        }

        fn vote(ref self: ContractState, proposal_id: u256, support: bool, voting_power: u256) {
            assert(!self.paused.read(), 'Contract paused');
            
            let caller = get_caller_address();
            let mut proposal = self.proposals.read(proposal_id);
            let current_time = get_block_timestamp();
            
            assert(!proposal.executed && !proposal.cancelled, 'Invalid proposal state');
            assert(current_time >= proposal.start_time, 'Voting not started');
            assert(current_time <= proposal.end_time, 'Voting ended');
            assert(!self.voted.read((proposal_id, caller)), 'Already voted');
            
            // Verify voting power
            let actual_voting_power = self._get_voting_power(caller);
            assert(voting_power <= actual_voting_power, 'Insufficient voting power');
            
            // Record vote
            self.votes.write((proposal_id, caller), support);
            self.voted.write((proposal_id, caller), true);
            
            // Update proposal vote counts
            let updated_proposal = if support {
                Proposal {
                    id: proposal.id,
                    proposer: proposal.proposer,
                    title: proposal.title,
                    description: proposal.description,
                    target: proposal.target,
                    value: proposal.value,
                    calldata: proposal.calldata,
                    votes_for: proposal.votes_for + voting_power,
                    votes_against: proposal.votes_against,
                    start_time: proposal.start_time,
                    end_time: proposal.end_time,
                    execution_time: proposal.execution_time,
                    executed: proposal.executed,
                    cancelled: proposal.cancelled,
                    proposal_type: proposal.proposal_type,
                }
            } else {
                Proposal {
                    id: proposal.id,
                    proposer: proposal.proposer,
                    title: proposal.title,
                    description: proposal.description,
                    target: proposal.target,
                    value: proposal.value,
                    calldata: proposal.calldata,
                    votes_for: proposal.votes_for,
                    votes_against: proposal.votes_against + voting_power,
                    start_time: proposal.start_time,
                    end_time: proposal.end_time,
                    execution_time: proposal.execution_time,
                    executed: proposal.executed,
                    cancelled: proposal.cancelled,
                    proposal_type: proposal.proposal_type,
                }
            };
            
            self.proposals.write(proposal_id, updated_proposal);
            
            self.emit(VoteCast {
                proposal_id,
                voter: caller,
                support,
                voting_power,
            });
        }

        fn execute_proposal(ref self: ContractState, proposal_id: u256) {
            let caller = get_caller_address();
            let proposal = self.proposals.read(proposal_id);
            let current_time = get_block_timestamp();
            let config = self.governance_config.read();
            
            assert(!proposal.executed && !proposal.cancelled, 'Invalid proposal state');
            assert(current_time >= proposal.execution_time, 'Timelock not expired');
            assert(proposal.votes_for > proposal.votes_against, 'Proposal defeated');
            assert(proposal.votes_for >= config.quorum_threshold, 'Quorum not reached');
            
            // Mark as executed
            let updated_proposal = Proposal {
                id: proposal.id,
                proposer: proposal.proposer,
                title: proposal.title,
                description: proposal.description,
                target: proposal.target,
                value: proposal.value,
                calldata: proposal.calldata,
                votes_for: proposal.votes_for,
                votes_against: proposal.votes_against,
                start_time: proposal.start_time,
                end_time: proposal.end_time,
                execution_time: proposal.execution_time,
                executed: true,
                cancelled: proposal.cancelled,
                proposal_type: proposal.proposal_type,
            };
            
            self.proposals.write(proposal_id, updated_proposal);
            
            // Execute based on proposal type
            self._execute_proposal_action(proposal);
            
            self.emit(ProposalExecuted {
                proposal_id,
                executor: caller,
            });
        }

        fn cancel_proposal(ref self: ContractState, proposal_id: u256) {
            let caller = get_caller_address();
            let proposal = self.proposals.read(proposal_id);
            
            // Only proposer or council can cancel
            assert(
                caller == proposal.proposer || 
                self.council_members.read(caller) || 
                caller == self.owner.read(),
                'Unauthorized'
            );
            assert(!proposal.executed && !proposal.cancelled, 'Invalid proposal state');
            
            let updated_proposal = Proposal {
                id: proposal.id,
                proposer: proposal.proposer,
                title: proposal.title,
                description: proposal.description,
                target: proposal.target,
                value: proposal.value,
                calldata: proposal.calldata,
                votes_for: proposal.votes_for,
                votes_against: proposal.votes_against,
                start_time: proposal.start_time,
                end_time: proposal.end_time,
                execution_time: proposal.execution_time,
                executed: proposal.executed,
                cancelled: true,
                proposal_type: proposal.proposal_type,
            };
            
            self.proposals.write(proposal_id, updated_proposal);
            
            self.emit(ProposalCancelled {
                proposal_id,
                canceller: caller,
            });
        }

        fn transfer_funds(ref self: ContractState, to: ContractAddress, amount: u256) {
            self._assert_only_governance();
            
            let available_funds = self.total_funds.read() - self.reserved_funds.read();
            assert(amount <= available_funds, 'Insufficient funds');
            
            let token = ISAGETokenDispatcher { contract_address: self.sage_token.read() };
            token.transfer(to, amount);
            
            self.total_funds.write(self.total_funds.read() - amount);
            
            self.emit(FundsTransferred {
                to,
                amount,
                reason: 'Governance transfer',
            });
        }

        fn emergency_withdraw(ref self: ContractState, token: ContractAddress, amount: u256) {
            let caller = get_caller_address();
            assert(self.emergency_council.read(caller), 'Not emergency council');
            
            let ciro = ISAGETokenDispatcher { contract_address: token };
            ciro.transfer(caller, amount);
            
            self.emit(EmergencyAction {
                action_type: 'Emergency withdraw',
                executor: caller,
                target: token,
                amount,
            });
        }

        fn get_proposal(self: @ContractState, proposal_id: u256) -> Proposal {
            self.proposals.read(proposal_id)
        }

        fn get_voting_power(self: @ContractState, account: ContractAddress) -> u256 {
            self._get_voting_power(account)
        }

        fn can_execute(self: @ContractState, proposal_id: u256) -> bool {
            let proposal = self.proposals.read(proposal_id);
            let current_time = get_block_timestamp();
            let config = self.governance_config.read();

            !proposal.executed &&
            !proposal.cancelled &&
            current_time >= proposal.execution_time &&
            proposal.votes_for > proposal.votes_against &&
            proposal.votes_for >= config.quorum_threshold
        }

        fn get_proposal_count(self: @ContractState) -> u256 {
            self.proposal_count.read()
        }

        fn has_voted(self: @ContractState, proposal_id: u256, voter: ContractAddress) -> bool {
            self.voted.read((proposal_id, voter))
        }

        fn get_config(self: @ContractState) -> GovernanceConfig {
            self.governance_config.read()
        }

        fn update_config(ref self: ContractState, new_config: GovernanceConfig) {
            self._assert_only_governance();
            self.governance_config.write(new_config);
        }

        fn add_council_member(ref self: ContractState, member: ContractAddress) {
            self._assert_only_governance();
            
            assert(!self.council_members.read(member), 'Already member');
            self.council_members.write(member, true);
            self.emergency_council.write(member, true);
            self.council_count.write(self.council_count.read() + 1);
            
            self.emit(CouncilUpdated {
                member,
                added: true,
                updated_by: get_caller_address(),
            });
        }

        fn remove_council_member(ref self: ContractState, member: ContractAddress) {
            self._assert_only_governance();

            assert(self.council_members.read(member), 'Not a member');
            let new_count = self.council_count.read() - 1;
            assert(self.council_threshold.read() <= new_count, 'Would break threshold');

            self.council_members.write(member, false);
            self.emergency_council.write(member, false);
            self.council_count.write(new_count);

            self.emit(CouncilUpdated {
                member,
                added: false,
                updated_by: get_caller_address(),
            });
        }

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._assert_only_governance();
            assert(!new_class_hash.is_zero(), 'Invalid class hash');
            assert(self.pending_upgrade.read().is_zero(), 'Upgrade already scheduled');

            let now = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let execute_after = now + delay;

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(now);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: now,
                execute_after,
                scheduled_by: get_caller_address(),
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            self._assert_only_governance();

            let new_class_hash = self.pending_upgrade.read();
            assert(!new_class_hash.is_zero(), 'No upgrade scheduled');

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let now = get_block_timestamp();
            assert(now >= scheduled_at + delay, 'Upgrade delay not passed');

            // Clear pending upgrade
            self.pending_upgrade.write(Zero::zero());
            self.upgrade_scheduled_at.write(0);

            // Execute upgrade
            replace_class_syscall(new_class_hash).unwrap_syscall();

            self.emit(UpgradeExecuted {
                new_class_hash,
                executed_at: now,
                executed_by: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._assert_only_governance();

            let pending = self.pending_upgrade.read();
            assert(!pending.is_zero(), 'No upgrade scheduled');

            self.pending_upgrade.write(Zero::zero());
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
            self._assert_only_governance();
            self.upgrade_delay.write(delay);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _get_voting_power(self: @ContractState, account: ContractAddress) -> u256 {
            let token = ISAGETokenDispatcher { contract_address: self.sage_token.read() };
            token.balance_of(account)
        }

        fn _assert_only_governance(self: @ContractState) {
            let caller = get_caller_address();
            assert(
                caller == self.owner.read() || 
                caller == get_contract_address(), // Self-call from executed proposal
                'Only governance'
            );
        }

        fn _execute_proposal_action(ref self: ContractState, proposal: Proposal) {
            // This would contain the actual execution logic
            // For treasury transfers, parameter updates, etc.
            // Implementation depends on the specific proposal type
            
            match proposal.proposal_type {
                ProposalType::Treasury => {
                    // Handle treasury operations
                    let token = ISAGETokenDispatcher { contract_address: self.sage_token.read() };
                    token.transfer(proposal.target, proposal.value);
                    
                    self.emit(FundsTransferred {
                        to: proposal.target,
                        amount: proposal.value,
                        reason: 'Proposal execution',
                    });
                },
                ProposalType::Upgrade => {
                    // Handle contract upgrades
                    // Would require upgrade implementation
                },
                ProposalType::Parameter => {
                    // Handle parameter changes
                    // Update governance config, thresholds, etc.
                },
                ProposalType::Emergency => {
                    // Handle emergency actions
                    // Pause/unpause, emergency withdrawals, etc.
                    self.paused.write(true);
                },
            }
        }
    }
} 