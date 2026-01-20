// =============================================================================
// ADDRESS REGISTRY - BitSage Network
// =============================================================================
//
// Human-readable address naming system for Obelysk Protocol
//
// Allows registering friendly names:
//   "obelysk:prover-registry" → 0x04736828c69fda...
//   "sage:token" → 0x0662c81332894...
//   "bitsage:treasury" → 0x0737c361e784...
//
// =============================================================================

use starknet::{ContractAddress, ClassHash};

// =============================================================================
// Data Types
// =============================================================================

/// Registered address info
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RegisteredAddress {
    /// The actual contract address
    pub address: ContractAddress,
    /// Owner who registered it
    pub owner: ContractAddress,
    /// Registration timestamp
    pub registered_at: u64,
    /// Is active
    pub is_active: bool,
}

/// Protocol prefixes
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum Protocol {
    /// Obelysk GPU proving protocol
    Obelysk,
    /// SAGE token contracts
    Sage,
    /// BitSage network contracts
    BitSage,
    /// Custom prefix
    Custom,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IAddressRegistry<TContractState> {
    // === Registration ===
    /// Register a named address
    /// name: "prover-registry", "token", "treasury"
    /// protocol: Obelysk, Sage, BitSage
    fn register(
        ref self: TContractState,
        protocol: Protocol,
        name: felt252,
        address: ContractAddress,
    );
    
    /// Update a registered address (owner only)
    fn update(
        ref self: TContractState,
        protocol: Protocol,
        name: felt252,
        new_address: ContractAddress,
    );
    
    /// Transfer ownership of a name
    fn transfer_ownership(
        ref self: TContractState,
        protocol: Protocol,
        name: felt252,
        new_owner: ContractAddress,
    );
    
    /// Deactivate a name
    fn deactivate(ref self: TContractState, protocol: Protocol, name: felt252);
    
    // === Resolution ===
    /// Resolve a name to address
    /// e.g., resolve(Obelysk, "prover-registry") → 0x04736...
    fn resolve(
        self: @TContractState,
        protocol: Protocol,
        name: felt252,
    ) -> ContractAddress;
    
    /// Check if a name is registered
    fn is_registered(
        self: @TContractState,
        protocol: Protocol,
        name: felt252,
    ) -> bool;
    
    /// Get full registration info
    fn get_info(
        self: @TContractState,
        protocol: Protocol,
        name: felt252,
    ) -> RegisteredAddress;
    
    // === Reverse Lookup ===
    /// Get the name for an address (if registered)
    fn reverse_lookup(
        self: @TContractState,
        address: ContractAddress,
    ) -> (Protocol, felt252);
    
    // === Admin ===
    fn set_registration_fee(ref self: TContractState, fee: u256);
    fn get_registration_fee(self: @TContractState) -> u256;

    // === Upgrade ===
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
mod AddressRegistry {
    use super::{IAddressRegistry, RegisteredAddress, Protocol};
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use core::num::traits::Zero;

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// Registered addresses: (protocol, name) -> info
        registry: Map<(felt252, felt252), RegisteredAddress>,
        /// Reverse lookup: address -> (protocol, name)
        reverse: Map<ContractAddress, (felt252, felt252)>,
        /// Registration fee (in SAGE)
        registration_fee: u256,
        /// Total registrations
        total_registrations: u64,
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
        AddressRegistered: AddressRegistered,
        AddressUpdated: AddressUpdated,
        OwnershipTransferred: OwnershipTransferred,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct AddressRegistered {
        #[key]
        protocol: felt252,
        #[key]
        name: felt252,
        address: ContractAddress,
        owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AddressUpdated {
        #[key]
        protocol: felt252,
        #[key]
        name: felt252,
        old_address: ContractAddress,
        new_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferred {
        #[key]
        protocol: felt252,
        #[key]
        name: felt252,
        old_owner: ContractAddress,
        new_owner: ContractAddress,
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
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.registration_fee.write(0); // Free for now
        self.total_registrations.write(0);
        self.upgrade_delay.write(172800); // 2 days
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl AddressRegistryImpl of IAddressRegistry<ContractState> {
        fn register(
            ref self: ContractState,
            protocol: Protocol,
            name: felt252,
            address: ContractAddress,
        ) {
            let caller = get_caller_address();
            let protocol_felt = self._protocol_to_felt(protocol);
            
            // Check not already registered
            let existing = self.registry.read((protocol_felt, name));
            let zero_addr: ContractAddress = 0.try_into().unwrap();
            assert(existing.address == zero_addr || !existing.is_active, 'Name already registered');
            
            // Register
            let info = RegisteredAddress {
                address,
                owner: caller,
                registered_at: get_block_timestamp(),
                is_active: true,
            };
            
            self.registry.write((protocol_felt, name), info);
            self.reverse.write(address, (protocol_felt, name));
            
            let count = self.total_registrations.read();
            self.total_registrations.write(count + 1);
            
            self.emit(AddressRegistered {
                protocol: protocol_felt,
                name,
                address,
                owner: caller,
            });
        }

        fn update(
            ref self: ContractState,
            protocol: Protocol,
            name: felt252,
            new_address: ContractAddress,
        ) {
            let caller = get_caller_address();
            let protocol_felt = self._protocol_to_felt(protocol);
            
            let mut info = self.registry.read((protocol_felt, name));
            assert(info.is_active, 'Name not registered');
            assert(info.owner == caller || caller == self.owner.read(), 'Not authorized');
            
            let old_address = info.address;
            info.address = new_address;
            
            self.registry.write((protocol_felt, name), info);
            
            // Update reverse lookup
            self.reverse.write(old_address, (0, 0));
            self.reverse.write(new_address, (protocol_felt, name));
            
            self.emit(AddressUpdated {
                protocol: protocol_felt,
                name,
                old_address,
                new_address,
            });
        }

        fn transfer_ownership(
            ref self: ContractState,
            protocol: Protocol,
            name: felt252,
            new_owner: ContractAddress,
        ) {
            let caller = get_caller_address();
            let protocol_felt = self._protocol_to_felt(protocol);
            
            let mut info = self.registry.read((protocol_felt, name));
            assert(info.is_active, 'Name not registered');
            assert(info.owner == caller, 'Not owner');
            
            let old_owner = info.owner;
            info.owner = new_owner;
            self.registry.write((protocol_felt, name), info);
            
            self.emit(OwnershipTransferred {
                protocol: protocol_felt,
                name,
                old_owner,
                new_owner,
            });
        }

        fn deactivate(ref self: ContractState, protocol: Protocol, name: felt252) {
            let caller = get_caller_address();
            let protocol_felt = self._protocol_to_felt(protocol);
            
            let mut info = self.registry.read((protocol_felt, name));
            assert(info.is_active, 'Name not registered');
            assert(info.owner == caller || caller == self.owner.read(), 'Not authorized');
            
            info.is_active = false;
            self.registry.write((protocol_felt, name), info);
        }

        fn resolve(
            self: @ContractState,
            protocol: Protocol,
            name: felt252,
        ) -> ContractAddress {
            let protocol_felt = self._protocol_to_felt(protocol);
            let info = self.registry.read((protocol_felt, name));
            
            if info.is_active {
                info.address
            } else {
                let zero: ContractAddress = 0.try_into().unwrap();
                zero
            }
        }

        fn is_registered(
            self: @ContractState,
            protocol: Protocol,
            name: felt252,
        ) -> bool {
            let protocol_felt = self._protocol_to_felt(protocol);
            let info = self.registry.read((protocol_felt, name));
            info.is_active
        }

        fn get_info(
            self: @ContractState,
            protocol: Protocol,
            name: felt252,
        ) -> RegisteredAddress {
            let protocol_felt = self._protocol_to_felt(protocol);
            self.registry.read((protocol_felt, name))
        }

        fn reverse_lookup(
            self: @ContractState,
            address: ContractAddress,
        ) -> (Protocol, felt252) {
            let (protocol_felt, name) = self.reverse.read(address);
            (self._felt_to_protocol(protocol_felt), name)
        }

        fn set_registration_fee(ref self: ContractState, fee: u256) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            self.registration_fee.write(fee);
        }

        fn get_registration_fee(self: @ContractState) -> u256 {
            self.registration_fee.read()
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

    // =========================================================================
    // Internal Functions
    // =========================================================================
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _protocol_to_felt(self: @ContractState, protocol: Protocol) -> felt252 {
            match protocol {
                Protocol::Obelysk => 'obelysk',
                Protocol::Sage => 'sage',
                Protocol::BitSage => 'bitsage',
                Protocol::Custom => 'custom',
            }
        }

        fn _felt_to_protocol(self: @ContractState, felt: felt252) -> Protocol {
            if felt == 'obelysk' {
                Protocol::Obelysk
            } else if felt == 'sage' {
                Protocol::Sage
            } else if felt == 'bitsage' {
                Protocol::BitSage
            } else {
                Protocol::Custom
            }
        }
    }
}

