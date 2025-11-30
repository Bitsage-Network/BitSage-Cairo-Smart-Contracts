#[starknet::interface]
pub trait ISimpleEvents<TContractState> {
    fn emit_event(ref self: TContractState, message: felt252);
}

#[starknet::contract]
pub mod SimpleEvents {
    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TestEvent: TestEvent,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TestEvent {
        pub message: felt252,
        pub timestamp: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
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
    }
}
