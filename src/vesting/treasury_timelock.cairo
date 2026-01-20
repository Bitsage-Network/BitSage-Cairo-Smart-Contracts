//! Treasury Timelock Contract
//! SAGE Network - Secure Multi-Sig Treasury Management
//! Implements timelocked operations with multi-signature approval

use starknet::{ContractAddress, ClassHash, get_caller_address, get_block_timestamp};
use starknet::storage::{
    StoragePointerReadAccess, StoragePointerWriteAccess,
    StorageMapReadAccess, StorageMapWriteAccess, Map
};

#[starknet::interface]
pub trait ITreasuryTimelock<TContractState> {
    // Core timelock functions
    fn propose_transaction(ref self: TContractState, target: ContractAddress, value: u256, data: Array<felt252>, description: felt252) -> u256;
    fn approve_transaction(ref self: TContractState, tx_id: u256);
    fn execute_transaction(ref self: TContractState, tx_id: u256);
    fn cancel_transaction(ref self: TContractState, tx_id: u256);
    
    // Emergency functions
    fn emergency_pause(ref self: TContractState, reason: felt252);
    fn emergency_unpause(ref self: TContractState);
    fn emergency_cancel_all(ref self: TContractState);
    
    // View functions
    fn get_transaction(self: @TContractState, tx_id: u256) -> TimelockTransaction;
    fn get_pending_transactions(self: @TContractState) -> Array<u256>;
    fn can_execute(self: @TContractState, tx_id: u256) -> bool;
    fn get_required_approvals(self: @TContractState) -> u32;
    fn is_paused(self: @TContractState) -> bool;
    fn is_multisig_member(self: @TContractState, member: ContractAddress) -> bool;
    
    // Administration
    fn update_timelock_delay(ref self: TContractState, new_delay: u64);
    fn add_multisig_member(ref self: TContractState, member: ContractAddress);
    fn remove_multisig_member(ref self: TContractState, member: ContractAddress);
    fn update_threshold(ref self: TContractState, new_threshold: u32);

    // Upgrade functions
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct TimelockTransaction {
    pub tx_id: u256,
    pub proposer: ContractAddress,
    pub target: ContractAddress,
    pub value: u256,
    pub data_hash: felt252,
    pub description: felt252,
    pub created_time: u64,
    pub execution_time: u64,
    pub approvals: u32,
    pub executed: bool,
    pub cancelled: bool,
    pub approval_threshold: u32
}

#[starknet::contract]
mod TreasuryTimelock {
    use super::*;
    use core::array::ArrayTrait;
    use starknet::{syscalls::replace_class_syscall, SyscallResultTrait};
    use core::num::traits::Zero;

    const DEFAULT_ADMIN_ROLE: felt252 = 0x0;
    const MULTISIG_ROLE: felt252 = 'MULTISIG';
    const EMERGENCY_ROLE: felt252 = 'EMERGENCY';

    #[storage]
    struct Storage {
        // Core storage
        transactions: Map<u256, TimelockTransaction>,
        approvals: Map<(u256, ContractAddress), bool>,
        next_tx_id: u256,
        timelock_delay: u64,
        multisig_threshold: u32,
        multisig_count: u32,
        multisig_members: Map<ContractAddress, bool>,
        
        // Simple access control
        admin: ContractAddress,
        emergency_multisig: Map<ContractAddress, bool>,
        
        // Simple pausable
        paused: bool,

        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TransactionProposed: TransactionProposed,
        TransactionApproved: TransactionApproved,
        TransactionExecuted: TransactionExecuted,
        TransactionCancelled: TransactionCancelled,
        EmergencyPause: EmergencyPause,
        EmergencyUnpause: EmergencyUnpause,
        MultisigMemberAdded: MultisigMemberAdded,
        MultisigMemberRemoved: MultisigMemberRemoved,
        ThresholdUpdated: ThresholdUpdated,
        TimelockDelayUpdated: TimelockDelayUpdated,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionProposed {
        #[key]
        tx_id: u256,
        proposer: ContractAddress,
        target: ContractAddress,
        value: u256,
        execution_time: u64
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionApproved {
        #[key]
        tx_id: u256,
        approver: ContractAddress,
        approvals: u32,
        threshold: u32
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionExecuted {
        #[key]
        tx_id: u256,
        executor: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionCancelled {
        #[key]
        tx_id: u256,
        canceller: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyPause {
        pauser: ContractAddress,
        reason: felt252
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyUnpause {
        unpauser: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct MultisigMemberAdded {
        member: ContractAddress,
        by: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct MultisigMemberRemoved {
        member: ContractAddress,
        by: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct ThresholdUpdated {
        old_threshold: u32,
        new_threshold: u32,
        by: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct TimelockDelayUpdated {
        old_delay: u64,
        new_delay: u64,
        by: ContractAddress
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
        multisig_members: Array<ContractAddress>,
        threshold: u32,
        timelock_delay: u64,
        admin: ContractAddress,
        emergency_members: Array<ContractAddress>
    ) {
        // Set admin
        self.admin.write(admin);

        let member_count: u32 = multisig_members.len().try_into().unwrap();
        assert(threshold > 0 && threshold <= member_count, 'Invalid threshold');
        
        self.multisig_threshold.write(threshold);
        self.multisig_count.write(member_count);
        self.timelock_delay.write(timelock_delay);
        self.next_tx_id.write(1);
        self.paused.write(false);
        self.upgrade_delay.write(172800); // 2 days

        // Set multisig members
        let mut i = 0;
        loop {
            if i >= multisig_members.len() {
                break;
            }
            let member = *multisig_members.at(i);
            self.multisig_members.write(member, true);
            i += 1;
        };

        // Set emergency members
        let mut j = 0;
        loop {
            if j >= emergency_members.len() {
                break;
            }
            let member = *emergency_members.at(j);
            self.emergency_multisig.write(member, true);
            j += 1;
        };
    }

    #[abi(embed_v0)]
    impl TreasuryTimelockImpl of super::ITreasuryTimelock<ContractState> {
        fn propose_transaction(ref self: ContractState, target: ContractAddress, value: u256, data: Array<felt252>, description: felt252) -> u256 {
            self._assert_only_multisig();
            self._assert_not_paused();

            let tx_id = self.next_tx_id.read();
            let current_time = get_block_timestamp();
            let execution_time = current_time + self.timelock_delay.read();

            let tx = TimelockTransaction {
                tx_id,
                proposer: get_caller_address(),
                target,
                value,
                data_hash: self._hash_data(data),
                description,
                created_time: current_time,
                execution_time,
                approvals: 1,
                executed: false,
                cancelled: false,
                approval_threshold: self.multisig_threshold.read()
            };

            self.transactions.write(tx_id, tx);
            self.approvals.write((tx_id, get_caller_address()), true);
            self.next_tx_id.write(tx_id + 1);

            self.emit(TransactionProposed {
                tx_id,
                proposer: get_caller_address(),
                target,
                value,
                execution_time
            });

            tx_id
        }

        fn approve_transaction(ref self: ContractState, tx_id: u256) {
            self._assert_only_multisig();
            
            let tx = self.transactions.read(tx_id);
            assert(!tx.executed && !tx.cancelled, 'Invalid transaction state');
            assert(!self.approvals.read((tx_id, get_caller_address())), 'Already approved');

            let updated_tx = TimelockTransaction {
                tx_id: tx.tx_id,
                proposer: tx.proposer,
                target: tx.target,
                value: tx.value,
                data_hash: tx.data_hash,
                description: tx.description,
                created_time: tx.created_time,
                execution_time: tx.execution_time,
                approvals: tx.approvals + 1,
                executed: tx.executed,
                cancelled: tx.cancelled,
                approval_threshold: tx.approval_threshold
            };
            self.transactions.write(tx_id, updated_tx);
            self.approvals.write((tx_id, get_caller_address()), true);

            self.emit(TransactionApproved {
                tx_id,
                approver: get_caller_address(),
                approvals: updated_tx.approvals,
                threshold: updated_tx.approval_threshold
            });
        }

        fn execute_transaction(ref self: ContractState, tx_id: u256) {
            self._assert_only_multisig();

            let tx = self.transactions.read(tx_id);
            assert(!tx.executed && !tx.cancelled, 'Invalid transaction state');
            assert(tx.approvals >= tx.approval_threshold, 'Insufficient approvals');
            assert(get_block_timestamp() >= tx.execution_time, 'Timelock not expired');

            let updated_tx = TimelockTransaction {
                tx_id: tx.tx_id,
                proposer: tx.proposer,
                target: tx.target,
                value: tx.value,
                data_hash: tx.data_hash,
                description: tx.description,
                created_time: tx.created_time,
                execution_time: tx.execution_time,
                approvals: tx.approvals,
                executed: true,
                cancelled: tx.cancelled,
                approval_threshold: tx.approval_threshold
            };
            self.transactions.write(tx_id, updated_tx);

            // Note: Actual execution would require call_contract_syscall
            // For now, we mark as executed to track the approval process
            
            self.emit(TransactionExecuted {
                tx_id,
                executor: get_caller_address()
            });
        }

        fn cancel_transaction(ref self: ContractState, tx_id: u256) {
            let tx = self.transactions.read(tx_id);
            let caller = get_caller_address();
            assert(
                caller == tx.proposer || 
                caller == self.admin.read() || 
                self.emergency_multisig.read(caller), 
                'Unauthorized'
            );
            assert(!tx.executed && !tx.cancelled, 'Invalid transaction state');

            let updated_tx = TimelockTransaction {
                tx_id: tx.tx_id,
                proposer: tx.proposer,
                target: tx.target,
                value: tx.value,
                data_hash: tx.data_hash,
                description: tx.description,
                created_time: tx.created_time,
                execution_time: tx.execution_time,
                approvals: tx.approvals,
                executed: tx.executed,
                cancelled: true,
                approval_threshold: tx.approval_threshold
            };
            self.transactions.write(tx_id, updated_tx);

            self.emit(TransactionCancelled {
                tx_id,
                canceller: get_caller_address()
            });
        }

        fn emergency_pause(ref self: ContractState, reason: felt252) {
            self._assert_only_emergency();
            self.paused.write(true);
            
            self.emit(EmergencyPause {
                pauser: get_caller_address(),
                reason
            });
        }

        fn emergency_unpause(ref self: ContractState) {
            self._assert_only_emergency();
            self.paused.write(false);
            
            self.emit(EmergencyUnpause {
                unpauser: get_caller_address()
            });
        }

        fn emergency_cancel_all(ref self: ContractState) {
            self._assert_only_emergency();
            
            // Mark all pending transactions as cancelled
            let total = self.next_tx_id.read();
            let mut i = 1;
            
            loop {
                if i >= total {
                    break;
                }
                let tx = self.transactions.read(i);
                if !tx.executed && !tx.cancelled {
                    let updated_tx = TimelockTransaction {
                        tx_id: tx.tx_id,
                        proposer: tx.proposer,
                        target: tx.target,
                        value: tx.value,
                        data_hash: tx.data_hash,
                        description: tx.description,
                        created_time: tx.created_time,
                        execution_time: tx.execution_time,
                        approvals: tx.approvals,
                        executed: tx.executed,
                        cancelled: true,
                        approval_threshold: tx.approval_threshold
                    };
                    self.transactions.write(i, updated_tx);
                }
                i += 1;
            };
        }

        fn get_transaction(self: @ContractState, tx_id: u256) -> TimelockTransaction {
            self.transactions.read(tx_id)
        }

        fn get_pending_transactions(self: @ContractState) -> Array<u256> {
            let mut pending = ArrayTrait::new();
            let total = self.next_tx_id.read();
            let mut i = 1;
            
            loop {
                if i >= total {
                    break;
                }
                let tx = self.transactions.read(i);
                if !tx.executed && !tx.cancelled {
                    pending.append(i);
                }
                i += 1;
            };
            
            pending
        }

        fn can_execute(self: @ContractState, tx_id: u256) -> bool {
            let tx = self.transactions.read(tx_id);
            !tx.executed && !tx.cancelled && 
            tx.approvals >= tx.approval_threshold && 
            get_block_timestamp() >= tx.execution_time &&
            !self.paused.read()
        }

        fn get_required_approvals(self: @ContractState) -> u32 {
            self.multisig_threshold.read()
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn is_multisig_member(self: @ContractState, member: ContractAddress) -> bool {
            self.multisig_members.read(member)
        }

        fn update_timelock_delay(ref self: ContractState, new_delay: u64) {
            self._assert_only_admin();
            let old_delay = self.timelock_delay.read();
            self.timelock_delay.write(new_delay);
            
            self.emit(TimelockDelayUpdated {
                old_delay,
                new_delay,
                by: get_caller_address()
            });
        }

        fn add_multisig_member(ref self: ContractState, member: ContractAddress) {
            self._assert_only_admin();
            
            assert(!self.multisig_members.read(member), 'Member already exists');
            self.multisig_members.write(member, true);
            self.multisig_count.write(self.multisig_count.read() + 1);
            
            self.emit(MultisigMemberAdded {
                member,
                by: get_caller_address()
            });
        }

        fn remove_multisig_member(ref self: ContractState, member: ContractAddress) {
            self._assert_only_admin();
            
            assert(self.multisig_members.read(member), 'Member not found');
            let new_count = self.multisig_count.read() - 1;
            assert(self.multisig_threshold.read() <= new_count, 'Would break threshold');
            
            self.multisig_members.write(member, false);
            self.multisig_count.write(new_count);
            
            self.emit(MultisigMemberRemoved {
                member,
                by: get_caller_address()
            });
        }

        fn update_threshold(ref self: ContractState, new_threshold: u32) {
            self._assert_only_admin();
            
            let member_count = self.multisig_count.read();
            assert(new_threshold > 0 && new_threshold <= member_count, 'Invalid threshold');
            
            let old_threshold = self.multisig_threshold.read();
            self.multisig_threshold.write(new_threshold);
            
            self.emit(ThresholdUpdated {
                old_threshold,
                new_threshold,
                by: get_caller_address()
            });
        }

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._assert_only_admin();
            assert(new_class_hash.is_non_zero(), 'Invalid class hash');

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
            self._assert_only_admin();

            let pending = self.pending_upgrade.read();
            assert(pending.is_non_zero(), 'No upgrade scheduled');

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let now = get_block_timestamp();

            assert(now >= scheduled_at + delay, 'Upgrade delay not passed');

            // Clear pending upgrade
            self.pending_upgrade.write(Zero::zero());
            self.upgrade_scheduled_at.write(0);

            // Execute upgrade
            replace_class_syscall(pending).unwrap_syscall();

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: now,
                executed_by: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._assert_only_admin();

            let pending = self.pending_upgrade.read();
            assert(pending.is_non_zero(), 'No upgrade scheduled');

            let now = get_block_timestamp();

            // Clear pending upgrade
            self.pending_upgrade.write(Zero::zero());
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_at: now,
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
            self._assert_only_admin();
            self.upgrade_delay.write(delay);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_only_admin(self: @ContractState) {
            assert(get_caller_address() == self.admin.read(), 'Only admin');
        }

        fn _assert_only_multisig(self: @ContractState) {
            assert(self.multisig_members.read(get_caller_address()), 'Only multisig');
        }

        fn _assert_only_emergency(self: @ContractState) {
            let caller = get_caller_address();
            assert(
                caller == self.admin.read() || 
                self.emergency_multisig.read(caller), 
                'Only emergency'
            );
        }

        fn _assert_not_paused(self: @ContractState) {
            assert(!self.paused.read(), 'Contract paused');
        }

        fn _hash_data(self: @ContractState, data: Array<felt252>) -> felt252 {
            // Simple hash implementation - in production use proper hashing
            let mut hash: felt252 = 0;
            let mut i = 0;
            loop {
                if i >= data.len() {
                    break;
                }
                hash = hash + *data.at(i);
                i += 1;
            };
            hash
        }
    }
}