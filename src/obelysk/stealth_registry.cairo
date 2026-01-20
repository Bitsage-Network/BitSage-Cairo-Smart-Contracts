// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Stealth Payment Registry Contract
// On-chain registry for stealth meta-addresses and payment announcements
//
// This contract:
// 1. Stores worker stealth meta-addresses
// 2. Announces stealth payments (stores ephemeral keys)
// 3. Tracks payment claims
// 4. Verifies spending proofs
// 5. Integrates with SAGE token for transfers

use starknet::ContractAddress;
use sage_contracts::obelysk::stealth_payments::{
    StealthMetaAddress, StealthPaymentAnnouncement, StealthSpendingProof,
    derive_stealth_address, verify_spending_proof, encrypt_amount_to_stealth
};
use sage_contracts::obelysk::elgamal::{ECPoint, ElGamalCiphertext};

#[starknet::interface]
pub trait IStealthRegistry<TContractState> {
    // =========================================================================
    // Meta-Address Management
    // =========================================================================

    /// Register a stealth meta-address for receiving payments
    /// Workers call this to publish their stealth receiving capability
    fn register_meta_address(
        ref self: TContractState,
        spending_pubkey: ECPoint,
        viewing_pubkey: ECPoint
    );

    /// Update an existing meta-address
    fn update_meta_address(
        ref self: TContractState,
        spending_pubkey: ECPoint,
        viewing_pubkey: ECPoint
    );

    /// Get a worker's meta-address
    fn get_meta_address(
        self: @TContractState,
        worker: ContractAddress
    ) -> StealthMetaAddress;

    /// Check if worker has registered a meta-address
    fn has_meta_address(
        self: @TContractState,
        worker: ContractAddress
    ) -> bool;

    // =========================================================================
    // Stealth Payments
    // =========================================================================

    /// Send a stealth payment to a worker
    /// Derives stealth address, transfers tokens, announces payment
    /// @param worker: Worker's public address (to look up meta-address)
    /// @param amount: SAGE amount to send
    /// @param ephemeral_secret: Random secret for address derivation
    /// @param encryption_randomness: Randomness for amount encryption
    /// @param job_id: Associated job ID (0 for direct transfers)
    fn send_stealth_payment(
        ref self: TContractState,
        worker: ContractAddress,
        amount: u256,
        ephemeral_secret: felt252,
        encryption_randomness: felt252,
        job_id: u256
    ) -> u256; // Returns announcement index

    /// Send stealth payment directly to a meta-address (no lookup)
    fn send_stealth_payment_direct(
        ref self: TContractState,
        meta_address: StealthMetaAddress,
        amount: u256,
        ephemeral_secret: felt252,
        encryption_randomness: felt252,
        job_id: u256
    ) -> u256;

    /// Claim a stealth payment by providing spending proof
    /// @param announcement_index: Index of the payment announcement
    /// @param spending_proof: Proof of spending key ownership
    /// @param recipient: Address to receive the claimed funds
    fn claim_stealth_payment(
        ref self: TContractState,
        announcement_index: u256,
        spending_proof: StealthSpendingProof,
        recipient: ContractAddress
    );

    /// Batch claim multiple stealth payments
    fn batch_claim_stealth_payments(
        ref self: TContractState,
        announcement_indices: Array<u256>,
        spending_proofs: Array<StealthSpendingProof>,
        recipient: ContractAddress
    );

    // =========================================================================
    // View Functions
    // =========================================================================

    /// Get a payment announcement by index
    fn get_announcement(
        self: @TContractState,
        index: u256
    ) -> StealthPaymentAnnouncement;

    /// Get total number of announcements
    fn get_announcement_count(self: @TContractState) -> u256;

    /// Get announcements in range (for scanning)
    fn get_announcements_range(
        self: @TContractState,
        start: u256,
        count: u32
    ) -> Array<StealthPaymentAnnouncement>;

    /// Check if an announcement has been claimed
    fn is_claimed(self: @TContractState, index: u256) -> bool;

    /// Get payment amount for an announcement (encrypted)
    fn get_payment_amount(
        self: @TContractState,
        index: u256
    ) -> ElGamalCiphertext;

    /// Get total registered workers with meta-addresses
    fn get_registered_worker_count(self: @TContractState) -> u256;

    // =========================================================================
    // Time-Based Indexing (Efficient Scanning)
    // =========================================================================

    /// Get announcements by time range
    /// Returns announcement indices in the given time window
    /// Uses binary search for O(log n) lookup
    fn get_announcements_by_time(
        self: @TContractState,
        start_timestamp: u64,
        end_timestamp: u64,
        max_results: u32
    ) -> Array<u256>;

    /// Get the announcement index for a given timestamp (binary search)
    /// Returns the first announcement at or after the timestamp
    fn get_announcement_at_time(
        self: @TContractState,
        timestamp: u64
    ) -> u256;

    /// Get announcements by view tag (fast filter for workers)
    fn get_announcements_by_view_tag(
        self: @TContractState,
        view_tag: u8,
        start_index: u256,
        max_results: u32
    ) -> Array<u256>;

    /// Get time range boundaries for efficient scanning
    /// Returns (first_timestamp, last_timestamp, count)
    fn get_time_range_info(self: @TContractState) -> (u64, u64, u256);

    /// Get hourly announcement counts for analytics
    /// Returns count of announcements in the given hour (0-23)
    fn get_hourly_count(self: @TContractState, hour_index: u256) -> u256;

    // =========================================================================
    // Admin Functions
    // =========================================================================

    /// Pause the registry (emergency)
    fn pause(ref self: TContractState);

    /// Unpause the registry
    fn unpause(ref self: TContractState);

    /// Set the SAGE token address
    fn set_sage_token(ref self: TContractState, token: ContractAddress);

    // ===================== UPGRADE FUNCTIONS =====================
    fn schedule_upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (starknet::ClassHash, u64, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, new_delay: u64);
}

#[starknet::contract]
mod StealthRegistry {
    use super::{
        IStealthRegistry, StealthMetaAddress, StealthPaymentAnnouncement,
        StealthSpendingProof, derive_stealth_address, verify_spending_proof,
        encrypt_amount_to_stealth, ECPoint, ElGamalCiphertext
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_contract_address,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use sage_contracts::obelysk::elgamal::is_zero as point_is_zero;

    // =========================================================================
    // Storage
    // =========================================================================

    #[storage]
    struct Storage {
        // Contract configuration
        owner: ContractAddress,
        sage_token: ContractAddress,
        paused: bool,

        // Meta-address registry
        meta_addresses: Map<ContractAddress, StealthMetaAddress>,
        has_meta_address: Map<ContractAddress, bool>,
        registered_worker_count: u256,

        // Payment announcements
        announcement_count: u256,
        announcements: Map<u256, StealthPaymentAnnouncement>,

        // Payment amounts (stored separately for gas efficiency)
        payment_amounts: Map<u256, u256>,  // announcement_index -> amount

        // Claim tracking
        claimed: Map<u256, bool>,  // announcement_index -> is_claimed
        claimed_by: Map<u256, ContractAddress>,  // announcement_index -> claimer

        // Stealth address to announcement mapping (for verification)
        stealth_to_announcement: Map<felt252, u256>,  // stealth_address -> announcement_index

        // Statistics
        total_volume: u256,
        total_claimed: u256,

        // =====================================================================
        // Time-Based Index (for efficient scanning)
        // =====================================================================

        // Announcement timestamps for binary search (sorted by index)
        // Since announcements are appended in order, timestamps are naturally sorted
        announcement_timestamps: Map<u256, u64>,  // index -> timestamp

        // View tag index for fast filtering
        // Maps (view_tag, position) -> announcement_index
        view_tag_index: Map<(u8, u256), u256>,
        view_tag_count: Map<u8, u256>,  // view_tag -> count

        // Hourly index for time-bucketed queries
        // Maps hour_index -> count of announcements in that hour
        // hour_index = timestamp / 3600
        hourly_counts: Map<u256, u256>,

        // First and last timestamps for range info
        first_announcement_time: u64,
        last_announcement_time: u64,

        // ================ UPGRADE STORAGE ================
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
        MetaAddressRegistered: MetaAddressRegistered,
        MetaAddressUpdated: MetaAddressUpdated,
        StealthPaymentSent: StealthPaymentSent,
        StealthPaymentClaimed: StealthPaymentClaimed,
        RegistryPaused: RegistryPaused,
        RegistryUnpaused: RegistryUnpaused,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct MetaAddressRegistered {
        #[key]
        worker: ContractAddress,
        spending_pubkey_x: felt252,
        viewing_pubkey_x: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct MetaAddressUpdated {
        #[key]
        worker: ContractAddress,
        spending_pubkey_x: felt252,
        viewing_pubkey_x: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StealthPaymentSent {
        #[key]
        announcement_index: u256,
        #[key]
        stealth_address: felt252,
        ephemeral_pubkey_x: felt252,
        view_tag: u8,
        job_id: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StealthPaymentClaimed {
        #[key]
        announcement_index: u256,
        #[key]
        claimer: ContractAddress,
        recipient: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RegistryPaused {
        paused_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RegistryUnpaused {
        unpaused_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        new_class_hash: ClassHash,
        scheduled_at: u64,
        execute_after: u64,
        scheduler: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        old_class_hash: ClassHash,
        new_class_hash: ClassHash,
        executor: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        cancelled_class_hash: ClassHash,
        canceller: ContractAddress,
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress
    ) {
        assert!(!owner.is_zero(), "Invalid owner");
        assert!(!sage_token.is_zero(), "Invalid SAGE token");

        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.paused.write(false);
        self.announcement_count.write(0);
        self.registered_worker_count.write(0);
        self.total_volume.write(0);
        self.total_claimed.write(0);
        self.upgrade_delay.write(172800); // 2 days
    }

    // =========================================================================
    // Implementation
    // =========================================================================

    #[abi(embed_v0)]
    impl StealthRegistryImpl of IStealthRegistry<ContractState> {
        // =====================================================================
        // Meta-Address Management
        // =====================================================================

        fn register_meta_address(
            ref self: ContractState,
            spending_pubkey: ECPoint,
            viewing_pubkey: ECPoint
        ) {
            self._require_not_paused();

            let caller = get_caller_address();

            // Ensure not already registered
            assert!(!self.has_meta_address.read(caller), "Already registered");

            // Validate public keys are not zero
            assert!(!point_is_zero(spending_pubkey), "Invalid spending pubkey");
            assert!(!point_is_zero(viewing_pubkey), "Invalid viewing pubkey");

            let meta_address = StealthMetaAddress {
                spending_pubkey,
                viewing_pubkey,
                scheme_id: 1,
            };

            self.meta_addresses.write(caller, meta_address);
            self.has_meta_address.write(caller, true);

            let count = self.registered_worker_count.read();
            self.registered_worker_count.write(count + 1);

            self.emit(MetaAddressRegistered {
                worker: caller,
                spending_pubkey_x: spending_pubkey.x,
                viewing_pubkey_x: viewing_pubkey.x,
                timestamp: get_block_timestamp(),
            });
        }

        fn update_meta_address(
            ref self: ContractState,
            spending_pubkey: ECPoint,
            viewing_pubkey: ECPoint
        ) {
            self._require_not_paused();

            let caller = get_caller_address();

            // Must be already registered
            assert!(self.has_meta_address.read(caller), "Not registered");

            // Validate public keys
            assert!(!point_is_zero(spending_pubkey), "Invalid spending pubkey");
            assert!(!point_is_zero(viewing_pubkey), "Invalid viewing pubkey");

            let meta_address = StealthMetaAddress {
                spending_pubkey,
                viewing_pubkey,
                scheme_id: 1,
            };

            self.meta_addresses.write(caller, meta_address);

            self.emit(MetaAddressUpdated {
                worker: caller,
                spending_pubkey_x: spending_pubkey.x,
                viewing_pubkey_x: viewing_pubkey.x,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_meta_address(
            self: @ContractState,
            worker: ContractAddress
        ) -> StealthMetaAddress {
            assert!(self.has_meta_address.read(worker), "Worker not registered");
            self.meta_addresses.read(worker)
        }

        fn has_meta_address(
            self: @ContractState,
            worker: ContractAddress
        ) -> bool {
            self.has_meta_address.read(worker)
        }

        // =====================================================================
        // Stealth Payments
        // =====================================================================

        fn send_stealth_payment(
            ref self: ContractState,
            worker: ContractAddress,
            amount: u256,
            ephemeral_secret: felt252,
            encryption_randomness: felt252,
            job_id: u256
        ) -> u256 {
            // Look up worker's meta-address
            assert!(self.has_meta_address.read(worker), "Worker not registered");
            let meta_address = self.meta_addresses.read(worker);

            self.send_stealth_payment_direct(
                meta_address,
                amount,
                ephemeral_secret,
                encryption_randomness,
                job_id
            )
        }

        fn send_stealth_payment_direct(
            ref self: ContractState,
            meta_address: StealthMetaAddress,
            amount: u256,
            ephemeral_secret: felt252,
            encryption_randomness: felt252,
            job_id: u256
        ) -> u256 {
            self._require_not_paused();

            let caller = get_caller_address();
            let now = get_block_timestamp();

            // Validate inputs
            assert!(amount > 0, "Amount must be positive");
            assert!(ephemeral_secret != 0, "Invalid ephemeral secret");

            // Derive stealth address
            let (stealth_address, ephemeral_pubkey, view_tag) = derive_stealth_address(
                meta_address,
                ephemeral_secret
            );

            // Encrypt amount for recipient
            let encrypted_amount = encrypt_amount_to_stealth(
                amount,
                meta_address.spending_pubkey, // Use spending pubkey for encryption
                encryption_randomness
            );

            // Transfer SAGE from sender to this contract
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage.transfer_from(caller, get_contract_address(), amount);

            // Create and store announcement
            let announcement_index = self.announcement_count.read();

            let announcement = StealthPaymentAnnouncement {
                ephemeral_pubkey,
                stealth_address,
                encrypted_amount,
                view_tag,
                timestamp: now,
                job_id,
            };

            self.announcements.write(announcement_index, announcement);
            self.payment_amounts.write(announcement_index, amount);
            self.stealth_to_announcement.write(stealth_address, announcement_index);
            self.announcement_count.write(announcement_index + 1);

            // =========================================================
            // Update Time-Based Index
            // =========================================================

            // Store timestamp for binary search
            self.announcement_timestamps.write(announcement_index, now);

            // Update first/last timestamps
            if announcement_index == 0 {
                self.first_announcement_time.write(now);
            }
            self.last_announcement_time.write(now);

            // Update view tag index
            let tag_count = self.view_tag_count.read(view_tag);
            self.view_tag_index.write((view_tag, tag_count), announcement_index);
            self.view_tag_count.write(view_tag, tag_count + 1);

            // Update hourly index
            let hour_index: u256 = (now / 3600).into();
            let hourly = self.hourly_counts.read(hour_index);
            self.hourly_counts.write(hour_index, hourly + 1);

            // =========================================================

            // Update statistics
            let total = self.total_volume.read();
            self.total_volume.write(total + amount);

            self.emit(StealthPaymentSent {
                announcement_index,
                stealth_address,
                ephemeral_pubkey_x: ephemeral_pubkey.x,
                view_tag,
                job_id,
                timestamp: now,
            });

            announcement_index
        }

        fn claim_stealth_payment(
            ref self: ContractState,
            announcement_index: u256,
            spending_proof: StealthSpendingProof,
            recipient: ContractAddress
        ) {
            self._require_not_paused();

            let caller = get_caller_address();
            let now = get_block_timestamp();

            // Validate announcement exists
            let count = self.announcement_count.read();
            assert!(announcement_index < count, "Invalid announcement index");

            // Check not already claimed
            assert!(!self.claimed.read(announcement_index), "Already claimed");

            // Get announcement
            let announcement = self.announcements.read(announcement_index);

            // Verify spending proof
            assert!(
                verify_spending_proof(spending_proof, announcement.stealth_address),
                "Invalid spending proof"
            );

            // Mark as claimed
            self.claimed.write(announcement_index, true);
            self.claimed_by.write(announcement_index, caller);

            // Get payment amount
            let amount = self.payment_amounts.read(announcement_index);

            // Transfer SAGE to recipient
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage.transfer(recipient, amount);

            // Update statistics
            let total_claimed = self.total_claimed.read();
            self.total_claimed.write(total_claimed + amount);

            self.emit(StealthPaymentClaimed {
                announcement_index,
                claimer: caller,
                recipient,
                amount,
                timestamp: now,
            });
        }

        fn batch_claim_stealth_payments(
            ref self: ContractState,
            announcement_indices: Array<u256>,
            spending_proofs: Array<StealthSpendingProof>,
            recipient: ContractAddress
        ) {
            let len = announcement_indices.len();
            assert!(len == spending_proofs.len(), "Array length mismatch");
            assert!(len <= 20, "Max 20 claims per batch");

            let mut i: u32 = 0;
            loop {
                if i >= len {
                    break;
                }

                let index = *announcement_indices.at(i);
                let proof = *spending_proofs.at(i);

                self.claim_stealth_payment(index, proof, recipient);

                i += 1;
            };
        }

        // =====================================================================
        // View Functions
        // =====================================================================

        fn get_announcement(
            self: @ContractState,
            index: u256
        ) -> StealthPaymentAnnouncement {
            assert!(index < self.announcement_count.read(), "Invalid index");
            self.announcements.read(index)
        }

        fn get_announcement_count(self: @ContractState) -> u256 {
            self.announcement_count.read()
        }

        fn get_announcements_range(
            self: @ContractState,
            start: u256,
            count: u32
        ) -> Array<StealthPaymentAnnouncement> {
            let total = self.announcement_count.read();
            let mut result: Array<StealthPaymentAnnouncement> = array![];

            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }

                let index = start + i.into();
                if index >= total {
                    break;
                }

                result.append(self.announcements.read(index));
                i += 1;
            };

            result
        }

        fn is_claimed(self: @ContractState, index: u256) -> bool {
            self.claimed.read(index)
        }

        fn get_payment_amount(
            self: @ContractState,
            index: u256
        ) -> ElGamalCiphertext {
            assert!(index < self.announcement_count.read(), "Invalid index");
            self.announcements.read(index).encrypted_amount
        }

        fn get_registered_worker_count(self: @ContractState) -> u256 {
            self.registered_worker_count.read()
        }

        // =====================================================================
        // Time-Based Indexing (Efficient Scanning)
        // =====================================================================

        /// Get announcements in a time range using binary search
        fn get_announcements_by_time(
            self: @ContractState,
            start_timestamp: u64,
            end_timestamp: u64,
            max_results: u32
        ) -> Array<u256> {
            let mut results: Array<u256> = array![];
            let total = self.announcement_count.read();

            if total == 0 {
                return results;
            }

            // Binary search for start position
            let start_idx = self._binary_search_timestamp(start_timestamp);

            // Collect announcements in range
            let mut i = start_idx;
            let mut count: u32 = 0;

            loop {
                if i >= total || count >= max_results {
                    break;
                }

                let ts = self.announcement_timestamps.read(i);
                if ts > end_timestamp {
                    break;
                }

                if ts >= start_timestamp {
                    results.append(i);
                    count += 1;
                }

                i += 1;
            };

            results
        }

        /// Get announcement index at or after a timestamp (binary search)
        fn get_announcement_at_time(
            self: @ContractState,
            timestamp: u64
        ) -> u256 {
            self._binary_search_timestamp(timestamp)
        }

        /// Get announcements by view tag (fast filter for workers)
        fn get_announcements_by_view_tag(
            self: @ContractState,
            view_tag: u8,
            start_index: u256,
            max_results: u32
        ) -> Array<u256> {
            let mut results: Array<u256> = array![];
            let total_for_tag = self.view_tag_count.read(view_tag);

            let mut i = start_index;
            let mut count: u32 = 0;

            loop {
                if i >= total_for_tag || count >= max_results {
                    break;
                }

                let announcement_idx = self.view_tag_index.read((view_tag, i));
                results.append(announcement_idx);
                count += 1;
                i += 1;
            };

            results
        }

        /// Get time range info for scanning optimization
        fn get_time_range_info(self: @ContractState) -> (u64, u64, u256) {
            let first = self.first_announcement_time.read();
            let last = self.last_announcement_time.read();
            let count = self.announcement_count.read();
            (first, last, count)
        }

        /// Get hourly announcement count for analytics
        fn get_hourly_count(self: @ContractState, hour_index: u256) -> u256 {
            self.hourly_counts.read(hour_index)
        }

        // =====================================================================
        // Admin Functions
        // =====================================================================

        fn pause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(true);

            self.emit(RegistryPaused {
                paused_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(false);

            self.emit(RegistryUnpaused {
                unpaused_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn set_sage_token(ref self: ContractState, token: ContractAddress) {
            self._only_owner();
            assert!(!token.is_zero(), "Invalid token address");
            self.sage_token.write(token);
        }

        // =====================================================================
        // UPGRADE FUNCTIONS
        // =====================================================================

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            assert!(self.pending_upgrade.read().is_zero(), "Another upgrade pending");
            assert!(!new_class_hash.is_zero(), "Invalid class hash");

            let current_time = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(current_time);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: current_time,
                execute_after: current_time + delay,
                scheduler: get_caller_address(),
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            assert!(get_block_timestamp() >= scheduled_at + delay, "Timelock not expired");

            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            replace_class_syscall(pending).unwrap_syscall();
            self.emit(UpgradeExecuted {
                old_class_hash: pending,
                new_class_hash: pending,
                executor: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                canceller: get_caller_address(),
            });
        }

        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64, u64) {
            let pending = self.pending_upgrade.read();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            (pending, scheduled_at, if scheduled_at > 0 { scheduled_at + delay } else { 0 }, delay)
        }

        fn set_upgrade_delay(ref self: ContractState, new_delay: u64) {
            self._only_owner();
            assert!(self.pending_upgrade.read().is_zero(), "Cannot change with pending upgrade");
            assert!(new_delay >= 3600 && new_delay <= 2592000, "Invalid delay range");
            self.upgrade_delay.write(new_delay);
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
        }

        fn _require_not_paused(self: @ContractState) {
            assert!(!self.paused.read(), "Registry paused");
        }

        /// Binary search for the first announcement at or after a timestamp
        /// Returns the index of the first announcement with timestamp >= target
        /// If no such announcement exists, returns the total count
        fn _binary_search_timestamp(self: @ContractState, target: u64) -> u256 {
            let total = self.announcement_count.read();

            if total == 0 {
                return 0;
            }

            // Check if target is before first announcement
            let first_ts = self.announcement_timestamps.read(0);
            if target <= first_ts {
                return 0;
            }

            // Check if target is after last announcement
            let last_ts = self.announcement_timestamps.read(total - 1);
            if target > last_ts {
                return total;
            }

            // Binary search
            let mut low: u256 = 0;
            let mut high: u256 = total;

            loop {
                if low >= high {
                    break;
                }

                let mid = (low + high) / 2;
                let mid_ts = self.announcement_timestamps.read(mid);

                if mid_ts < target {
                    low = mid + 1;
                } else {
                    high = mid;
                }
            };

            low
        }

        /// Binary search for view tag filtering within a time range
        fn _find_view_tag_in_range(
            self: @ContractState,
            view_tag: u8,
            start_idx: u256,
            end_idx: u256
        ) -> Array<u256> {
            let mut results: Array<u256> = array![];
            let total_for_tag = self.view_tag_count.read(view_tag);

            // Iterate through view tag index and filter by range
            let mut i: u256 = 0;
            loop {
                if i >= total_for_tag {
                    break;
                }

                let announcement_idx = self.view_tag_index.read((view_tag, i));
                if announcement_idx >= start_idx && announcement_idx < end_idx {
                    results.append(announcement_idx);
                }

                i += 1;
            };

            results
        }
    }
}
