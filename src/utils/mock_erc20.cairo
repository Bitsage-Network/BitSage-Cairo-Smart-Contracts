//! MockERC20 - Simple ERC20 token for devnet testing
//!
//! Features:
//! - Standard ERC20 interface
//! - Public mint function (anyone can mint for testing)
//! - Configurable decimals
//!
//! Used for: USDC, STRK, wBTC mock tokens on devnet

use starknet::ContractAddress;

#[starknet::interface]
pub trait IMockERC20<TContractState> {
    // ERC20 Standard
    fn name(self: @TContractState) -> felt252;
    fn symbol(self: @TContractState) -> felt252;
    fn decimals(self: @TContractState) -> u8;
    fn total_supply(self: @TContractState) -> u256;
    fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn allowance(self: @TContractState, owner: ContractAddress, spender: ContractAddress) -> u256;
    fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
    fn transfer_from(ref self: TContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) -> bool;
    fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;

    // Mock-specific: Public mint for testing
    fn mint(ref self: TContractState, to: ContractAddress, amount: u256);

    // Faucet function - get test tokens
    fn faucet(ref self: TContractState, amount: u256);
}

#[starknet::contract]
mod MockERC20 {
    use super::IMockERC20;
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;

    #[storage]
    struct Storage {
        name: felt252,
        symbol: felt252,
        decimals: u8,
        total_supply: u256,
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Transfer: Transfer,
        Approval: Approval,
    }

    #[derive(Drop, starknet::Event)]
    struct Transfer {
        #[key]
        from: ContractAddress,
        #[key]
        to: ContractAddress,
        value: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Approval {
        #[key]
        owner: ContractAddress,
        #[key]
        spender: ContractAddress,
        value: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        name: felt252,
        symbol: felt252,
        decimals: u8,
        initial_supply_low: u128,
        initial_supply_high: u128,
        recipient: ContractAddress,
    ) {
        self.name.write(name);
        self.symbol.write(symbol);
        self.decimals.write(decimals);

        let initial_supply = u256 { low: initial_supply_low, high: initial_supply_high };

        if initial_supply > 0 && !recipient.is_zero() {
            self.balances.write(recipient, initial_supply);
            self.total_supply.write(initial_supply);

            self.emit(Transfer {
                from: Zero::zero(),
                to: recipient,
                value: initial_supply,
            });
        }
    }

    #[abi(embed_v0)]
    impl MockERC20Impl of IMockERC20<ContractState> {
        fn name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn symbol(self: @ContractState) -> felt252 {
            self.symbol.read()
        }

        fn decimals(self: @ContractState) -> u8 {
            self.decimals.read()
        }

        fn total_supply(self: @ContractState) -> u256 {
            self.total_supply.read()
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }

        fn allowance(self: @ContractState, owner: ContractAddress, spender: ContractAddress) -> u256 {
            self.allowances.read((owner, spender))
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            let sender = get_caller_address();
            self._transfer(sender, recipient, amount);
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) -> bool {
            let caller = get_caller_address();
            let current_allowance = self.allowances.read((sender, caller));

            assert!(current_allowance >= amount, "ERC20: insufficient allowance");

            self.allowances.write((sender, caller), current_allowance - amount);
            self._transfer(sender, recipient, amount);
            true
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            let owner = get_caller_address();
            self.allowances.write((owner, spender), amount);

            self.emit(Approval {
                owner,
                spender,
                value: amount,
            });
            true
        }

        /// Public mint function for testing - anyone can mint
        fn mint(ref self: ContractState, to: ContractAddress, amount: u256) {
            assert!(!to.is_zero(), "ERC20: mint to zero address");

            let supply = self.total_supply.read();
            self.total_supply.write(supply + amount);

            let balance = self.balances.read(to);
            self.balances.write(to, balance + amount);

            self.emit(Transfer {
                from: Zero::zero(),
                to,
                value: amount,
            });
        }

        /// Faucet - mint tokens to caller for testing
        fn faucet(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();

            // Limit faucet to reasonable amounts (1M tokens with max decimals)
            let max_faucet: u256 = 1000000_000000000000000000; // 1M with 18 decimals
            let actual_amount = if amount > max_faucet { max_faucet } else { amount };

            self.mint(caller, actual_amount);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _transfer(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) {
            assert!(!sender.is_zero(), "ERC20: transfer from zero address");
            assert!(!recipient.is_zero(), "ERC20: transfer to zero address");

            let sender_balance = self.balances.read(sender);
            assert!(sender_balance >= amount, "ERC20: insufficient balance");

            self.balances.write(sender, sender_balance - amount);

            let recipient_balance = self.balances.read(recipient);
            self.balances.write(recipient, recipient_balance + amount);

            self.emit(Transfer {
                from: sender,
                to: recipient,
                value: amount,
            });
        }
    }
}
