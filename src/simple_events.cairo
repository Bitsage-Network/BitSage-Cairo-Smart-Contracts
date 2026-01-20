use starknet::ClassHash;

#[starknet::interface]
pub trait ISimpleEvents<TContractState> {
    fn emit_event(ref self: TContractState, message: felt252);

    // === Upgrade ===
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[starknet::contract]
pub mod SimpleEvents {
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::num::traits::Zero;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TestEvent: TestEvent,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TestEvent {
        pub message: felt252,
        pub timestamp: u64,
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
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.upgrade_delay.write(172800); // 2 days

        // Emit event on deployment
        self.emit(Event::TestEvent(TestEvent {
            message: 'Contract Deployed',
            timestamp: starknet::get_block_timestamp(),
        }));
    }

    #[abi(embed_v0)]
    impl SimpleEventsImpl of super::ISimpleEvents<ContractState> {
        fn emit_event(ref self: ContractState, message: felt252) {
            self.emit(Event::TestEvent(TestEvent {
                message,
                timestamp: starknet::get_block_timestamp(),
            }));
        }

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
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
            assert(get_caller_address() == self.owner.read(), 'Only owner');

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
            assert(get_caller_address() == self.owner.read(), 'Only owner');

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
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            self.upgrade_delay.write(delay);
        }
    }
}
