//! Enclave Registry Contract
//!
//! Central registry for TEE enclave measurements. Both proof verifiers
//! (proof_verifier.cairo and stwo_verifier.cairo) should reference this
//! contract to check enclave whitelist status.
//!
//! This ensures:
//! - Single source of truth for enclave whitelisting
//! - Consistent enclave management across all verifiers
//! - Atomic updates to enclave status

use starknet::{ContractAddress, ClassHash};

/// Enclave information stored in registry
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EnclaveInfo {
    /// TEE type: 1 = Intel TDX, 2 = AMD SEV-SNP, 3 = NVIDIA CC
    pub tee_type: u8,
    /// Whether this enclave is currently whitelisted
    pub is_whitelisted: bool,
    /// Timestamp when enclave was whitelisted
    pub whitelisted_at: u64,
    /// Address that authorized this enclave
    pub authorized_by: ContractAddress,
    /// Description/purpose of this enclave
    pub description: felt252,
}

#[starknet::interface]
pub trait IEnclaveRegistry<TContractState> {
    /// Check if an enclave measurement is whitelisted
    fn is_whitelisted(self: @TContractState, measurement: felt252) -> bool;

    /// Get full enclave info
    fn get_enclave_info(self: @TContractState, measurement: felt252) -> EnclaveInfo;

    /// Get TEE type for an enclave
    fn get_tee_type(self: @TContractState, measurement: felt252) -> u8;

    /// Whitelist an enclave measurement (admin only)
    fn whitelist_enclave(
        ref self: TContractState,
        measurement: felt252,
        tee_type: u8,
        description: felt252,
    );

    /// Revoke an enclave's whitelist status (admin only)
    fn revoke_enclave(ref self: TContractState, measurement: felt252);

    /// Batch whitelist multiple enclaves (admin only)
    fn batch_whitelist(
        ref self: TContractState,
        measurements: Array<felt252>,
        tee_types: Array<u8>,
        descriptions: Array<felt252>,
    );

    /// Get total whitelisted enclave count
    fn get_whitelisted_count(self: @TContractState) -> u32;

    /// Check if caller is authorized admin
    fn is_admin(self: @TContractState, address: ContractAddress) -> bool;

    /// Add admin (owner only)
    fn add_admin(ref self: TContractState, admin: ContractAddress);

    /// Remove admin (owner only)
    fn remove_admin(ref self: TContractState, admin: ContractAddress);

    /// Transfer ownership (owner only)
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);

    // === Upgrade ===
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[starknet::contract]
mod EnclaveRegistry {
    use super::{IEnclaveRegistry, EnclaveInfo};
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use core::array::ArrayTrait;
    use core::num::traits::Zero;
    use sage_contracts::utils::verification::{
        TEE_TYPE_INTEL_TDX, TEE_TYPE_AMD_SEV_SNP, TEE_TYPE_NVIDIA_CC, is_valid_tee_type
    };

    // =========================================================================
    // Events
    // =========================================================================
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        EnclaveWhitelisted: EnclaveWhitelisted,
        EnclaveRevoked: EnclaveRevoked,
        AdminAdded: AdminAdded,
        AdminRemoved: AdminRemoved,
        OwnershipTransferred: OwnershipTransferred,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct EnclaveWhitelisted {
        #[key]
        measurement: felt252,
        tee_type: u8,
        authorized_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EnclaveRevoked {
        #[key]
        measurement: felt252,
        revoked_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AdminAdded {
        #[key]
        admin: ContractAddress,
        added_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AdminRemoved {
        #[key]
        admin: ContractAddress,
        removed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferred {
        previous_owner: ContractAddress,
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
    // Storage
    // =========================================================================
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// Admin addresses that can whitelist/revoke enclaves
        admins: Map<ContractAddress, bool>,
        /// Enclave measurement -> info mapping
        enclaves: Map<felt252, EnclaveInfo>,
        /// Quick whitelist check (for gas optimization)
        whitelist_status: Map<felt252, bool>,
        /// Total whitelisted count
        whitelisted_count: u32,
        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.admins.write(owner, true); // Owner is also admin
        self.whitelisted_count.write(0);
        self.upgrade_delay.write(172800); // 2 days
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    #[abi(embed_v0)]
    impl EnclaveRegistryImpl of IEnclaveRegistry<ContractState> {
        fn is_whitelisted(self: @ContractState, measurement: felt252) -> bool {
            self.whitelist_status.read(measurement)
        }

        fn get_enclave_info(self: @ContractState, measurement: felt252) -> EnclaveInfo {
            self.enclaves.read(measurement)
        }

        fn get_tee_type(self: @ContractState, measurement: felt252) -> u8 {
            let info = self.enclaves.read(measurement);
            info.tee_type
        }

        fn whitelist_enclave(
            ref self: ContractState,
            measurement: felt252,
            tee_type: u8,
            description: felt252,
        ) {
            // Only admins can whitelist
            self._only_admin();

            // Validate inputs
            assert!(measurement != 0, "Invalid measurement");
            assert!(is_valid_tee_type(tee_type), "Invalid TEE type");

            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            // Check if already whitelisted
            let was_whitelisted = self.whitelist_status.read(measurement);

            // Store enclave info
            let info = EnclaveInfo {
                tee_type,
                is_whitelisted: true,
                whitelisted_at: timestamp,
                authorized_by: caller,
                description,
            };
            self.enclaves.write(measurement, info);
            self.whitelist_status.write(measurement, true);

            // Update count if newly whitelisted
            if !was_whitelisted {
                let count = self.whitelisted_count.read();
                self.whitelisted_count.write(count + 1);
            }

            self.emit(EnclaveWhitelisted {
                measurement,
                tee_type,
                authorized_by: caller,
                timestamp,
            });
        }

        fn revoke_enclave(ref self: ContractState, measurement: felt252) {
            // Only admins can revoke
            self._only_admin();

            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            // Check if currently whitelisted
            let was_whitelisted = self.whitelist_status.read(measurement);
            assert!(was_whitelisted, "Enclave not whitelisted");

            // Update status
            let mut info = self.enclaves.read(measurement);
            info.is_whitelisted = false;
            self.enclaves.write(measurement, info);
            self.whitelist_status.write(measurement, false);

            // Update count
            let count = self.whitelisted_count.read();
            if count > 0 {
                self.whitelisted_count.write(count - 1);
            }

            self.emit(EnclaveRevoked {
                measurement,
                revoked_by: caller,
                timestamp,
            });
        }

        fn batch_whitelist(
            ref self: ContractState,
            measurements: Array<felt252>,
            tee_types: Array<u8>,
            descriptions: Array<felt252>,
        ) {
            // Only admins can batch whitelist
            self._only_admin();

            let len = measurements.len();
            assert!(len == tee_types.len(), "Array length mismatch");
            assert!(len == descriptions.len(), "Array length mismatch");
            assert!(len > 0, "Empty batch");
            assert!(len <= 50, "Batch too large"); // Gas limit protection

            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            let mut i: u32 = 0;
            while i < len {
                let measurement = *measurements.at(i);
                let tee_type = *tee_types.at(i);
                let description = *descriptions.at(i);

                // Validate
                if measurement != 0 && is_valid_tee_type(tee_type) {
                    let was_whitelisted = self.whitelist_status.read(measurement);

                    let info = EnclaveInfo {
                        tee_type,
                        is_whitelisted: true,
                        whitelisted_at: timestamp,
                        authorized_by: caller,
                        description,
                    };
                    self.enclaves.write(measurement, info);
                    self.whitelist_status.write(measurement, true);

                    if !was_whitelisted {
                        let count = self.whitelisted_count.read();
                        self.whitelisted_count.write(count + 1);
                    }

                    self.emit(EnclaveWhitelisted {
                        measurement,
                        tee_type,
                        authorized_by: caller,
                        timestamp,
                    });
                }

                i += 1;
            };
        }

        fn get_whitelisted_count(self: @ContractState) -> u32 {
            self.whitelisted_count.read()
        }

        fn is_admin(self: @ContractState, address: ContractAddress) -> bool {
            self.admins.read(address)
        }

        fn add_admin(ref self: ContractState, admin: ContractAddress) {
            self._only_owner();

            self.admins.write(admin, true);

            self.emit(AdminAdded {
                admin,
                added_by: get_caller_address(),
            });
        }

        fn remove_admin(ref self: ContractState, admin: ContractAddress) {
            self._only_owner();

            // Cannot remove owner as admin
            assert!(admin != self.owner.read(), "Cannot remove owner");

            self.admins.write(admin, false);

            self.emit(AdminRemoved {
                admin,
                removed_by: get_caller_address(),
            });
        }

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self._only_owner();

            let previous_owner = self.owner.read();
            self.owner.write(new_owner);

            // New owner becomes admin
            self.admins.write(new_owner, true);

            self.emit(OwnershipTransferred {
                previous_owner,
                new_owner,
            });
        }

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            assert!(!new_class_hash.is_zero(), "Invalid class hash");
            assert!(self.pending_upgrade.read().is_zero(), "Upgrade already scheduled");

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
            self._only_owner();

            let new_class_hash = self.pending_upgrade.read();
            assert!(!new_class_hash.is_zero(), "No upgrade scheduled");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let now = get_block_timestamp();
            assert!(now >= scheduled_at + delay, "Upgrade delay not passed");

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
            self._only_owner();

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No upgrade scheduled");

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
            self._only_owner();
            self.upgrade_delay.write(delay);
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");
        }

        fn _only_admin(self: @ContractState) {
            let caller = get_caller_address();
            assert!(self.admins.read(caller), "Only admin");
        }
    }
}
