// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Privacy Pools Contract
// Implements Vitalik Buterin's compliance-compatible privacy protocol
//
// Features:
// - Association Set Providers (ASPs) for curated deposit lists
// - Inclusion/Exclusion sets backed by LeanIMT
// - Flexible compliance levels (full privacy → verified clean)
// - Ragequit extension for excluded users
//
// Based on: "Blockchain Privacy and Regulatory Compliance: Towards a Practical Equilibrium"
// by Buterin, Illum, Nadler, Schär, Soleimani (2023)

use starknet::ContractAddress;
use sage_contracts::obelysk::elgamal::ECPoint;
use sage_contracts::obelysk::lean_imt::{
    LeanIMTState, LeanIMTProof, LeanIMTBatchResult,
};

// =============================================================================
// PRIVACY POOLS TYPES
// =============================================================================

/// ASP (Association Set Provider) status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum ASPStatus {
    /// Pending auditor approval
    #[default]
    Pending,
    /// Active and operational
    Active,
    /// Temporarily suspended
    Suspended,
    /// Permanently revoked
    Revoked,
}

/// Association Set Provider information
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ASPInfo {
    /// Unique identifier (Poseidon hash of registration data)
    pub asp_id: felt252,
    /// Hash of ASP name for display
    pub name_hash: felt252,
    /// ASP's public key for encrypted communications
    pub public_key: ECPoint,
    /// Hash of off-chain metadata URI
    pub metadata_uri_hash: felt252,
    /// Current status
    pub status: ASPStatus,
    /// Registration timestamp
    pub registered_at: u64,
    /// Staked amount (collateral for good behavior)
    pub staked_amount: u256,
    /// Number of auditor approval votes received
    pub approval_votes: u32,
    /// Total association sets created by this ASP
    pub total_sets: u32,
    /// Index in the ASP list for iteration
    pub list_index: u32,
}

/// Type of association set
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum AssociationSetType {
    /// Inclusion set: deposits approved by ASP
    #[default]
    Inclusion,
    /// Exclusion set: deposits blocked by ASP
    Exclusion,
}

/// Association Set information (LeanIMT-backed Merkle tree of commitments)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AssociationSetInfo {
    /// Unique set identifier
    pub set_id: felt252,
    /// Owning ASP's ID
    pub asp_id: felt252,
    /// Type of set (inclusion or exclusion)
    pub set_type: AssociationSetType,
    /// LeanIMT state for this set's Merkle tree
    pub tree_state: LeanIMTState,
    /// Number of commitments in this set
    pub member_count: u64,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub last_updated: u64,
    /// Whether this set is currently active
    pub is_active: bool,
}

/// Privacy Pools deposit record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PPDeposit {
    /// Deposit commitment: H(secret, nullifier_seed, amount, asset_id)
    pub commitment: felt252,
    /// Pedersen commitment to the amount (for range proofs)
    pub amount_commitment: ECPoint,
    /// Asset ID (0=SAGE, 1=USDC, etc.)
    pub asset_id: felt252,
    /// Original depositor address (for emergency ragequit)
    pub depositor: ContractAddress,
    /// Deposit timestamp
    pub timestamp: u64,
    /// Index in global deposit tree
    pub global_index: u64,
}

/// Exclusion proof data for proving non-membership
#[derive(Drop, Serde)]
pub struct ExclusionProofData {
    /// LeanIMT proof for non-membership verification
    pub non_membership_proof: LeanIMTProof,
    /// Left boundary commitment (neighbor in sorted set)
    pub boundary_left: felt252,
    /// Right boundary commitment (neighbor in sorted set)
    pub boundary_right: felt252,
}

/// Privacy Pools withdrawal proof
#[derive(Drop, Serde)]
pub struct PPWithdrawalProof {
    // === Global Tree Membership ===
    /// Proof of deposit in global deposit tree
    pub global_tree_proof: LeanIMTProof,
    /// The deposit commitment being withdrawn
    pub deposit_commitment: felt252,

    // === Association Set Membership (Optional for full privacy) ===
    /// Association set ID (None for full privacy mode)
    pub association_set_id: Option<felt252>,
    /// Proof of membership in association set
    pub association_proof: Option<LeanIMTProof>,

    // === Exclusion Proof (Optional for verified clean) ===
    /// Exclusion set ID to prove not-in
    pub exclusion_set_id: Option<felt252>,
    /// Proof of non-membership in exclusion set
    pub exclusion_proof: Option<ExclusionProofData>,

    // === Withdrawal Details ===
    /// Nullifier: H(secret, commitment) - prevents double-spend
    pub nullifier: felt252,
    /// Amount being withdrawn
    pub amount: u256,
    /// Recipient address
    pub recipient: ContractAddress,
    /// Range proof data (Bulletproof for amount validation)
    pub range_proof_data: Span<felt252>,
}

/// Privacy Pools ragequit status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum PPRagequitStatus {
    /// Ragequit initiated, waiting for delay period
    #[default]
    Pending,
    /// Delay period passed, can be executed
    Executable,
    /// Successfully completed
    Completed,
    /// Cancelled (user was re-included in a set)
    Cancelled,
    /// Expired (not executed within window)
    Expired,
}

/// Privacy Pools ragequit request
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PPRagequitRequest {
    /// Unique request ID
    pub request_id: u256,
    /// Deposit commitment being ragequit
    pub commitment: felt252,
    /// Original depositor (must sign)
    pub depositor: ContractAddress,
    /// Amount to withdraw
    pub amount: u256,
    /// Recipient address
    pub recipient: ContractAddress,
    /// Timestamp when ragequit was initiated
    pub initiated_at: u64,
    /// Timestamp when ragequit becomes executable
    pub executable_at: u64,
    /// Current status
    pub status: PPRagequitStatus,
}

/// Privacy Pools ragequit proof
#[derive(Drop, Serde)]
pub struct PPRagequitProof {
    /// Deposit commitment being ragequit
    pub deposit_commitment: felt252,
    /// Proof of deposit in global tree
    pub global_tree_proof: LeanIMTProof,
    /// Proofs of exclusion from ALL active inclusion sets
    pub exclusion_proofs: Array<ExclusionProofData>,
    /// IDs of sets being proven excluded from
    pub excluded_set_ids: Array<felt252>,
    /// Depositor signature (r, s)
    pub depositor_signature: (felt252, felt252),
    /// Amount to withdraw
    pub amount: u256,
    /// Recipient address
    pub recipient: ContractAddress,
}

/// Auditor info for ASP approval (minimal, references main registry)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AuditorRef {
    /// Auditor address
    pub address: ContractAddress,
    /// Whether active
    pub is_active: bool,
}

// =============================================================================
// PRIVACY POOLS CONSTANTS
// =============================================================================

/// Ragequit delay period (24 hours in seconds)
pub const PP_RAGEQUIT_DELAY: u64 = 86400;

/// Minimum stake required to register as ASP (10,000 SAGE with 18 decimals)
pub const PP_MIN_ASP_STAKE: u256 = 10000000000000000000000;

/// Required auditor votes for ASP approval
pub const PP_ASP_APPROVAL_THRESHOLD: u32 = 2;

/// Maximum deposits per batch operation
pub const PP_MAX_BATCH_SIZE: u32 = 100;

/// Number of historical roots to keep for delayed proofs
pub const PP_ROOT_HISTORY_SIZE: u32 = 100;

/// Domain separator for Privacy Pools
pub const PP_DOMAIN_SEPARATOR: felt252 = 'OBELYSK_PRIVACY_POOLS_V1';

// =============================================================================
// PRIVACY POOLS INTERFACE
// =============================================================================

#[starknet::interface]
pub trait IPrivacyPools<TContractState> {
    // --- Initialization ---
    fn initialize(
        ref self: TContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        privacy_router: ContractAddress
    );
    fn is_initialized(self: @TContractState) -> bool;

    // --- ASP Registry ---
    fn register_asp(
        ref self: TContractState,
        name_hash: felt252,
        public_key: ECPoint,
        metadata_uri_hash: felt252
    ) -> felt252;
    fn approve_asp(ref self: TContractState, asp_id: felt252);
    fn suspend_asp(ref self: TContractState, asp_id: felt252, reason: felt252);
    fn revoke_asp(ref self: TContractState, asp_id: felt252, reason: felt252);
    fn get_asp_info(self: @TContractState, asp_id: felt252) -> ASPInfo;
    fn is_asp_active(self: @TContractState, asp_id: felt252) -> bool;
    fn get_asp_count(self: @TContractState) -> u32;

    // --- Auditor Management (for ASP approval) ---
    fn add_auditor(ref self: TContractState, auditor: ContractAddress);
    fn remove_auditor(ref self: TContractState, auditor: ContractAddress);
    fn is_auditor(self: @TContractState, address: ContractAddress) -> bool;

    // --- Association Sets ---
    fn create_association_set(
        ref self: TContractState,
        set_type: AssociationSetType,
        initial_commitments: Span<felt252>
    ) -> felt252;
    fn add_to_association_set(
        ref self: TContractState,
        set_id: felt252,
        commitments: Span<felt252>
    );
    fn remove_from_association_set(
        ref self: TContractState,
        set_id: felt252,
        commitments: Span<felt252>
    );
    fn get_association_set_info(self: @TContractState, set_id: felt252) -> AssociationSetInfo;
    fn get_association_set_root(self: @TContractState, set_id: felt252) -> felt252;
    fn is_in_association_set(
        self: @TContractState,
        set_id: felt252,
        commitment: felt252
    ) -> bool;

    // --- Privacy Pools Deposits ---
    /// Deposit tokens into the privacy pool
    /// @param commitment: Unique deposit ID = H(secret, nullifier_seed, amount, asset_id)
    /// @param amount_commitment: ElGamal encrypted amount (C2 = m*H + r*PK)
    /// @param asset_id: Token identifier (0=SAGE, 1=USDC, etc.)
    /// @param amount: Plaintext amount being deposited (for token transfer)
    /// @param range_proof_data: Range proof proving amount matches commitment
    /// @returns: Index of deposit in global Merkle tree (leafIndex)
    fn pp_deposit(
        ref self: TContractState,
        commitment: felt252,
        amount_commitment: ECPoint,
        asset_id: felt252,
        amount: u256,
        range_proof_data: Span<felt252>
    ) -> u64;
    fn pp_batch_deposit(
        ref self: TContractState,
        commitments: Span<felt252>,
        amount_commitments: Span<ECPoint>,
        asset_ids: Span<felt252>,
        amounts: Span<u256>,
        range_proof_data: Span<felt252>
    ) -> LeanIMTBatchResult;
    fn get_global_deposit_root(self: @TContractState) -> felt252;
    fn get_pp_deposit_info(self: @TContractState, commitment: felt252) -> PPDeposit;
    fn is_pp_deposit_valid(self: @TContractState, commitment: felt252) -> bool;

    // --- Privacy Pools Withdrawals ---
    fn pp_withdraw(ref self: TContractState, proof: PPWithdrawalProof) -> bool;
    fn is_pp_nullifier_used(self: @TContractState, nullifier: felt252) -> bool;

    // --- Ragequit ---
    fn initiate_pp_ragequit(ref self: TContractState, proof: PPRagequitProof) -> u256;
    fn complete_pp_ragequit(ref self: TContractState, request_id: u256);
    fn cancel_pp_ragequit(
        ref self: TContractState,
        request_id: u256,
        new_inclusion_set_id: felt252,
        inclusion_proof: LeanIMTProof
    );
    fn get_pp_ragequit_request(self: @TContractState, request_id: u256) -> PPRagequitRequest;

    // --- Stats ---
    fn get_pp_stats(self: @TContractState) -> (u64, u64, u256, u256);

    // --- Admin ---
    fn set_ragequit_delay(ref self: TContractState, delay: u64);
    fn set_asp_stake_minimum(ref self: TContractState, minimum: u256);
    fn set_compliance_required(ref self: TContractState, required: bool);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);

    // --- Upgrade ---
    fn schedule_upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (starknet::ClassHash, u64, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, new_delay: u64);
}

// =============================================================================
// PRIVACY POOLS CONTRACT
// =============================================================================

#[starknet::contract]
pub mod PrivacyPools {
    use super::{
        IPrivacyPools,
        ASPStatus, ASPInfo, AssociationSetType, AssociationSetInfo,
        PPDeposit, PPWithdrawalProof,
        PPRagequitStatus, PPRagequitRequest, PPRagequitProof,
        AuditorRef,
        PP_RAGEQUIT_DELAY, PP_MIN_ASP_STAKE, PP_ASP_APPROVAL_THRESHOLD,
        PP_MAX_BATCH_SIZE, PP_ROOT_HISTORY_SIZE,
    };
    use sage_contracts::obelysk::elgamal::ECPoint;
    use sage_contracts::obelysk::lean_imt::{
        LeanIMTState, LeanIMTProof, LeanIMTBatchResult,
        calculate_depth, hash_pair, verify_proof,
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_contract_address,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::poseidon::poseidon_hash_span;
    use core::traits::TryInto;
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // =========================================================================
    // STORAGE
    // =========================================================================

    #[storage]
    struct Storage {
        // --- Core ---
        owner: ContractAddress,
        sage_token: ContractAddress,
        privacy_router: ContractAddress,
        initialized: bool,
        paused: bool,

        // --- Global Deposit Tree (LeanIMT) ---
        global_deposit_tree: LeanIMTState,
        global_deposit_nodes: Map<(u8, u64), felt252>,
        global_deposit_side_nodes: Map<u8, felt252>,
        deposit_exists: Map<felt252, bool>,
        deposit_info: Map<felt252, PPDeposit>,

        // --- ASP Registry ---
        asp_count: u32,
        asp_info: Map<felt252, ASPInfo>,
        asp_by_index: Map<u32, felt252>,
        asp_exists: Map<felt252, bool>,
        asp_by_address: Map<ContractAddress, felt252>,
        asp_stake_minimum: u256,
        asp_approval_threshold: u32,
        asp_approval_votes: Map<(felt252, ContractAddress), bool>,

        // --- Auditors (for ASP approval) ---
        auditors: Map<ContractAddress, AuditorRef>,
        auditor_count: u32,

        // --- Association Sets ---
        association_set_count: u64,
        association_set_info: Map<felt252, AssociationSetInfo>,
        association_set_nodes: Map<(felt252, u8, u64), felt252>,
        association_set_side_nodes: Map<(felt252, u8), felt252>,
        commitment_in_set: Map<(felt252, felt252), bool>,
        asp_sets: Map<(felt252, u32), felt252>,
        set_exists: Map<felt252, bool>,

        // --- Privacy Pools Nullifiers ---
        nullifier_used: Map<felt252, bool>,
        nullifier_tree: LeanIMTState,
        nullifier_nodes: Map<(u8, u64), felt252>,
        nullifier_side_nodes: Map<u8, felt252>,

        // --- Historical Roots ---
        known_global_roots: Map<felt252, bool>,
        known_set_roots: Map<(felt252, felt252), bool>,
        global_root_history: Map<u32, felt252>,
        global_root_index: u32,
        set_root_history: Map<(felt252, u32), felt252>,
        set_root_index: Map<felt252, u32>,

        // --- Ragequit ---
        ragequit_requests: Map<u256, PPRagequitRequest>,
        next_ragequit_id: u256,
        ragequit_by_commitment: Map<felt252, u256>,
        total_ragequits: u64,

        // --- Configuration ---
        ragequit_delay: u64,
        max_withdrawal_amount: u256,
        compliance_required: bool,

        // --- Statistics ---
        total_deposits: u64,
        total_withdrawals: u64,
        total_volume_deposited: u256,
        total_volume_withdrawn: u256,

        // --- Upgrade ---
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Initialized: Initialized,
        ASPRegistered: ASPRegistered,
        ASPApproved: ASPApproved,
        ASPSuspended: ASPSuspended,
        ASPRevoked: ASPRevoked,
        AuditorAdded: AuditorAdded,
        AuditorRemoved: AuditorRemoved,
        AssociationSetCreated: AssociationSetCreated,
        AssociationSetUpdated: AssociationSetUpdated,
        CommitmentsAddedToSet: CommitmentsAddedToSet,
        CommitmentsRemovedFromSet: CommitmentsRemovedFromSet,
        PPDepositExecuted: PPDepositExecuted,
        PPWithdrawalExecuted: PPWithdrawalExecuted,
        PPRagequitInitiated: PPRagequitInitiated,
        PPRagequitCompleted: PPRagequitCompleted,
        PPRagequitCancelled: PPRagequitCancelled,
        Paused: Paused,
        Unpaused: Unpaused,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct Initialized {
        owner: ContractAddress,
        sage_token: ContractAddress,
        privacy_router: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ASPRegistered {
        #[key]
        asp_id: felt252,
        registrant: ContractAddress,
        name_hash: felt252,
        staked_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ASPApproved {
        #[key]
        asp_id: felt252,
        approved_by: ContractAddress,
        approval_count: u32,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ASPSuspended {
        #[key]
        asp_id: felt252,
        suspended_by: ContractAddress,
        reason: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ASPRevoked {
        #[key]
        asp_id: felt252,
        revoked_by: ContractAddress,
        reason: felt252,
        slashed_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AuditorAdded {
        #[key]
        auditor: ContractAddress,
        added_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AuditorRemoved {
        #[key]
        auditor: ContractAddress,
        removed_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AssociationSetCreated {
        #[key]
        set_id: felt252,
        #[key]
        asp_id: felt252,
        set_type: AssociationSetType,
        initial_size: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AssociationSetUpdated {
        #[key]
        set_id: felt252,
        old_root: felt252,
        new_root: felt252,
        new_size: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CommitmentsAddedToSet {
        #[key]
        set_id: felt252,
        count: u32,
        new_root: felt252,
        new_size: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CommitmentsRemovedFromSet {
        #[key]
        set_id: felt252,
        count: u32,
        new_root: felt252,
        new_size: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PPDepositExecuted {
        #[key]
        commitment: felt252,
        depositor: ContractAddress,
        asset_id: felt252,
        global_index: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PPWithdrawalExecuted {
        #[key]
        nullifier: felt252,
        recipient: ContractAddress,
        amount: u256,
        compliance_level: u8,
        association_set_id: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PPRagequitInitiated {
        #[key]
        request_id: u256,
        #[key]
        commitment: felt252,
        depositor: ContractAddress,
        amount: u256,
        executable_at: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PPRagequitCompleted {
        #[key]
        request_id: u256,
        commitment: felt252,
        recipient: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PPRagequitCancelled {
        #[key]
        request_id: u256,
        commitment: felt252,
        new_inclusion_set_id: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct Paused {
        by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct Unpaused {
        by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        #[key]
        new_class_hash: ClassHash,
        scheduled_at: u64,
        executable_at: u64,
        scheduler: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        #[key]
        new_class_hash: ClassHash,
        executed_at: u64,
        executor: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        #[key]
        cancelled_class_hash: ClassHash,
        cancelled_at: u64,
        canceller: ContractAddress,
    }

    // =========================================================================
    // IMPLEMENTATION
    // =========================================================================

    #[abi(embed_v0)]
    impl PrivacyPoolsImpl of IPrivacyPools<ContractState> {
        // --- Initialization ---

        fn initialize(
            ref self: ContractState,
            owner: ContractAddress,
            sage_token: ContractAddress,
            privacy_router: ContractAddress
        ) {
            assert!(!self.initialized.read(), "Already initialized");

            self.owner.write(owner);
            self.sage_token.write(sage_token);
            self.privacy_router.write(privacy_router);

            // Initialize trees
            let initial_tree_state = LeanIMTState { root: 0, size: 0, depth: 0 };
            self.global_deposit_tree.write(initial_tree_state);
            self.nullifier_tree.write(initial_tree_state);

            // Set default configuration
            self.ragequit_delay.write(PP_RAGEQUIT_DELAY);
            self.asp_stake_minimum.write(PP_MIN_ASP_STAKE);
            self.asp_approval_threshold.write(PP_ASP_APPROVAL_THRESHOLD);
            self.compliance_required.write(false);
            // Default 2-day upgrade delay
            self.upgrade_delay.write(172800);

            self.initialized.write(true);

            self.emit(Initialized {
                owner,
                sage_token,
                privacy_router,
                timestamp: get_block_timestamp(),
            });
        }

        fn is_initialized(self: @ContractState) -> bool {
            self.initialized.read()
        }

        // --- ASP Registry ---

        fn register_asp(
            ref self: ContractState,
            name_hash: felt252,
            public_key: ECPoint,
            metadata_uri_hash: felt252
        ) -> felt252 {
            self._require_not_paused();
            self._require_initialized();

            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            // Check caller isn't already an ASP
            let existing_asp_id = self.asp_by_address.read(caller);
            assert!(existing_asp_id == 0, "Already registered as ASP");

            // Transfer stake from caller
            let stake_amount = self.asp_stake_minimum.read();
            let sage_token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage_token.transfer_from(caller, get_contract_address(), stake_amount);

            // Generate ASP ID
            let asp_id = poseidon_hash_span(
                array![name_hash, public_key.x, public_key.y, caller.into(), timestamp.into()].span()
            );

            // Create ASP info
            let asp_count = self.asp_count.read();
            let asp_info = ASPInfo {
                asp_id,
                name_hash,
                public_key,
                metadata_uri_hash,
                status: ASPStatus::Pending,
                registered_at: timestamp,
                staked_amount: stake_amount,
                approval_votes: 0,
                total_sets: 0,
                list_index: asp_count,
            };

            // Store ASP
            self.asp_info.write(asp_id, asp_info);
            self.asp_exists.write(asp_id, true);
            self.asp_by_address.write(caller, asp_id);
            self.asp_by_index.write(asp_count, asp_id);
            self.asp_count.write(asp_count + 1);

            self.emit(ASPRegistered {
                asp_id,
                registrant: caller,
                name_hash,
                staked_amount: stake_amount,
                timestamp,
            });

            asp_id
        }

        fn approve_asp(ref self: ContractState, asp_id: felt252) {
            self._require_not_paused();

            let caller = get_caller_address();
            let auditor_ref = self.auditors.read(caller);
            assert!(auditor_ref.is_active, "Caller is not an active auditor");

            assert!(self.asp_exists.read(asp_id), "ASP does not exist");
            let mut asp_info = self.asp_info.read(asp_id);
            assert!(asp_info.status == ASPStatus::Pending, "ASP is not pending approval");

            let vote_key = (asp_id, caller);
            assert!(!self.asp_approval_votes.read(vote_key), "Already voted");

            self.asp_approval_votes.write(vote_key, true);
            asp_info.approval_votes += 1;

            let timestamp = get_block_timestamp();

            if asp_info.approval_votes >= self.asp_approval_threshold.read() {
                asp_info.status = ASPStatus::Active;
            }

            self.asp_info.write(asp_id, asp_info);

            self.emit(ASPApproved {
                asp_id,
                approved_by: caller,
                approval_count: asp_info.approval_votes,
                timestamp,
            });
        }

        fn suspend_asp(ref self: ContractState, asp_id: felt252, reason: felt252) {
            self._only_owner();
            assert!(self.asp_exists.read(asp_id), "ASP does not exist");

            let mut asp_info = self.asp_info.read(asp_id);
            assert!(asp_info.status == ASPStatus::Active, "ASP is not active");

            asp_info.status = ASPStatus::Suspended;
            self.asp_info.write(asp_id, asp_info);

            self.emit(ASPSuspended {
                asp_id,
                suspended_by: get_caller_address(),
                reason,
                timestamp: get_block_timestamp(),
            });
        }

        fn revoke_asp(ref self: ContractState, asp_id: felt252, reason: felt252) {
            self._only_owner();
            assert!(self.asp_exists.read(asp_id), "ASP does not exist");

            let mut asp_info = self.asp_info.read(asp_id);
            let slashed_amount = asp_info.staked_amount;

            asp_info.status = ASPStatus::Revoked;
            asp_info.staked_amount = 0;
            self.asp_info.write(asp_id, asp_info);

            self.emit(ASPRevoked {
                asp_id,
                revoked_by: get_caller_address(),
                reason,
                slashed_amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_asp_info(self: @ContractState, asp_id: felt252) -> ASPInfo {
            self.asp_info.read(asp_id)
        }

        fn is_asp_active(self: @ContractState, asp_id: felt252) -> bool {
            let asp_info = self.asp_info.read(asp_id);
            asp_info.status == ASPStatus::Active
        }

        fn get_asp_count(self: @ContractState) -> u32 {
            self.asp_count.read()
        }

        // --- Auditor Management ---

        fn add_auditor(ref self: ContractState, auditor: ContractAddress) {
            self._only_owner();

            let auditor_ref = AuditorRef { address: auditor, is_active: true };
            self.auditors.write(auditor, auditor_ref);
            self.auditor_count.write(self.auditor_count.read() + 1);

            self.emit(AuditorAdded {
                auditor,
                added_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn remove_auditor(ref self: ContractState, auditor: ContractAddress) {
            self._only_owner();

            let mut auditor_ref = self.auditors.read(auditor);
            auditor_ref.is_active = false;
            self.auditors.write(auditor, auditor_ref);

            self.emit(AuditorRemoved {
                auditor,
                removed_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn is_auditor(self: @ContractState, address: ContractAddress) -> bool {
            self.auditors.read(address).is_active
        }

        // --- Association Sets ---

        fn create_association_set(
            ref self: ContractState,
            set_type: AssociationSetType,
            initial_commitments: Span<felt252>
        ) -> felt252 {
            self._require_not_paused();

            let caller = get_caller_address();
            let asp_id = self.asp_by_address.read(caller);
            assert!(asp_id != 0, "Caller is not a registered ASP");
            assert!(self.is_asp_active(asp_id), "ASP is not active");

            let timestamp = get_block_timestamp();
            let set_count = self.association_set_count.read();

            let set_id = poseidon_hash_span(
                array![asp_id, set_count.into(), timestamp.into()].span()
            );

            let initial_tree_state = LeanIMTState { root: 0, size: 0, depth: 0 };

            let set_info = AssociationSetInfo {
                set_id,
                asp_id,
                set_type,
                tree_state: initial_tree_state,
                member_count: 0,
                created_at: timestamp,
                last_updated: timestamp,
                is_active: true,
            };

            self.association_set_info.write(set_id, set_info);
            self.set_exists.write(set_id, true);

            let mut asp_info = self.asp_info.read(asp_id);
            self.asp_sets.write((asp_id, asp_info.total_sets), set_id);
            asp_info.total_sets += 1;
            self.asp_info.write(asp_id, asp_info);

            self.association_set_count.write(set_count + 1);

            if initial_commitments.len() > 0 {
                self._add_commitments_to_set(set_id, initial_commitments);
            }

            self.emit(AssociationSetCreated {
                set_id,
                asp_id,
                set_type,
                initial_size: initial_commitments.len().into(),
                timestamp,
            });

            set_id
        }

        fn add_to_association_set(
            ref self: ContractState,
            set_id: felt252,
            commitments: Span<felt252>
        ) {
            self._require_not_paused();
            assert!(self.set_exists.read(set_id), "Set does not exist");

            let set_info = self.association_set_info.read(set_id);
            let caller_asp_id = self.asp_by_address.read(get_caller_address());
            assert!(caller_asp_id == set_info.asp_id, "Caller does not own this set");
            assert!(set_info.is_active, "Set is not active");

            self._add_commitments_to_set(set_id, commitments);
        }

        fn remove_from_association_set(
            ref self: ContractState,
            set_id: felt252,
            commitments: Span<felt252>
        ) {
            self._require_not_paused();
            assert!(self.set_exists.read(set_id), "Set does not exist");

            let set_info = self.association_set_info.read(set_id);
            let caller_asp_id = self.asp_by_address.read(get_caller_address());
            assert!(caller_asp_id == set_info.asp_id, "Caller does not own this set");

            let mut i: u32 = 0;
            let len = commitments.len();
            loop {
                if i >= len {
                    break;
                }
                let commitment = *commitments.at(i);
                self.commitment_in_set.write((set_id, commitment), false);
                i += 1;
            };

            let timestamp = get_block_timestamp();
            let mut updated_info = self.association_set_info.read(set_id);
            updated_info.last_updated = timestamp;
            self.association_set_info.write(set_id, updated_info);

            self.emit(CommitmentsRemovedFromSet {
                set_id,
                count: len,
                new_root: updated_info.tree_state.root,
                new_size: updated_info.tree_state.size,
                timestamp,
            });
        }

        fn get_association_set_info(self: @ContractState, set_id: felt252) -> AssociationSetInfo {
            self.association_set_info.read(set_id)
        }

        fn get_association_set_root(self: @ContractState, set_id: felt252) -> felt252 {
            let set_info = self.association_set_info.read(set_id);
            set_info.tree_state.root
        }

        fn is_in_association_set(
            self: @ContractState,
            set_id: felt252,
            commitment: felt252
        ) -> bool {
            self.commitment_in_set.read((set_id, commitment))
        }

        // --- Privacy Pools Deposits ---

        fn pp_deposit(
            ref self: ContractState,
            commitment: felt252,
            amount_commitment: ECPoint,
            asset_id: felt252,
            amount: u256,
            range_proof_data: Span<felt252>
        ) -> u64 {
            self._require_not_paused();
            self._require_initialized();
            assert!(commitment != 0, "Invalid commitment");
            assert!(!self.deposit_exists.read(commitment), "Deposit already exists");
            assert!(amount > 0, "Amount must be positive");

            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            // Transfer tokens from depositor to this contract
            // User must have approved this contract to spend their tokens first
            let sage_token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let transfer_success = sage_token.transfer_from(caller, get_contract_address(), amount);
            assert!(transfer_success, "Token transfer failed");

            // Insert deposit into global Merkle tree
            let global_index = self._insert_global_deposit(commitment);

            let deposit = PPDeposit {
                commitment,
                amount_commitment,
                asset_id,
                depositor: caller,
                timestamp,
                global_index,
            };

            self.deposit_exists.write(commitment, true);
            self.deposit_info.write(commitment, deposit);
            self.total_deposits.write(self.total_deposits.read() + 1);
            self.total_volume_deposited.write(self.total_volume_deposited.read() + amount);

            self.emit(PPDepositExecuted {
                commitment,
                depositor: caller,
                asset_id,
                global_index,
                timestamp,
            });

            global_index
        }

        fn pp_batch_deposit(
            ref self: ContractState,
            commitments: Span<felt252>,
            amount_commitments: Span<ECPoint>,
            asset_ids: Span<felt252>,
            amounts: Span<u256>,
            range_proof_data: Span<felt252>
        ) -> LeanIMTBatchResult {
            self._require_not_paused();
            self._require_initialized();

            let len = commitments.len();
            assert!(len > 0, "Empty batch");
            assert!(len <= PP_MAX_BATCH_SIZE, "Batch too large");
            assert!(len == amount_commitments.len(), "Mismatched lengths");
            assert!(len == asset_ids.len(), "Mismatched lengths");
            assert!(len == amounts.len(), "Mismatched amounts length");

            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            // Calculate total amount and transfer all tokens at once
            let mut total_amount: u256 = 0;
            let mut j: u32 = 0;
            loop {
                if j >= len {
                    break;
                }
                let amt = *amounts.at(j);
                assert!(amt > 0, "Amount must be positive");
                total_amount += amt;
                j += 1;
            };

            // Transfer all tokens from depositor to this contract
            let sage_token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let transfer_success = sage_token.transfer_from(caller, get_contract_address(), total_amount);
            assert!(transfer_success, "Token transfer failed");

            let state = self.global_deposit_tree.read();
            let start_index = state.size;

            let mut i: u32 = 0;
            loop {
                if i >= len {
                    break;
                }
                let commitment = *commitments.at(i);
                assert!(commitment != 0, "Invalid commitment");
                assert!(!self.deposit_exists.read(commitment), "Deposit already exists");

                let global_index = start_index + i.into();
                self.global_deposit_nodes.write((0, global_index), commitment);

                let deposit = PPDeposit {
                    commitment,
                    amount_commitment: *amount_commitments.at(i),
                    asset_id: *asset_ids.at(i),
                    depositor: caller,
                    timestamp,
                    global_index,
                };

                self.deposit_exists.write(commitment, true);
                self.deposit_info.write(commitment, deposit);

                self.emit(PPDepositExecuted {
                    commitment,
                    depositor: caller,
                    asset_id: *asset_ids.at(i),
                    global_index,
                    timestamp,
                });

                i += 1;
            };

            // Update total volume deposited
            self.total_volume_deposited.write(self.total_volume_deposited.read() + total_amount);

            let final_size = start_index + len.into();
            let new_depth = calculate_depth(final_size);
            let new_root = self._rebuild_global_deposit_tree(start_index, final_size, new_depth);

            let new_state = LeanIMTState { root: new_root, size: final_size, depth: new_depth };
            self.global_deposit_tree.write(new_state);

            self.known_global_roots.write(new_root, true);
            let root_idx = self.global_root_index.read();
            self.global_root_history.write(root_idx, new_root);
            self.global_root_index.write((root_idx + 1) % PP_ROOT_HISTORY_SIZE);

            self.total_deposits.write(self.total_deposits.read() + len.into());

            LeanIMTBatchResult {
                new_root,
                new_size: final_size,
                new_depth,
                start_index,
                inserted_count: len,
            }
        }

        fn get_global_deposit_root(self: @ContractState) -> felt252 {
            self.global_deposit_tree.read().root
        }

        fn get_pp_deposit_info(self: @ContractState, commitment: felt252) -> PPDeposit {
            self.deposit_info.read(commitment)
        }

        fn is_pp_deposit_valid(self: @ContractState, commitment: felt252) -> bool {
            self.deposit_exists.read(commitment)
        }

        // --- Privacy Pools Withdrawals ---

        fn pp_withdraw(ref self: ContractState, proof: PPWithdrawalProof) -> bool {
            self._require_not_paused();
            self._require_initialized();
            assert!(!self.nullifier_used.read(proof.nullifier), "Nullifier already used");

            let is_valid_global = verify_proof(@proof.global_tree_proof);
            assert!(is_valid_global, "Invalid global tree proof");
            assert!(
                self.known_global_roots.read(proof.global_tree_proof.root),
                "Unknown global root"
            );

            let mut compliance_level: u8 = 0;
            let mut association_set_id: felt252 = 0;

            if proof.association_set_id.is_some() {
                let set_id = proof.association_set_id.unwrap();
                association_set_id = set_id;
                compliance_level = 1;

                if proof.association_proof.is_some() {
                    let assoc_proof = proof.association_proof.unwrap();
                    let is_valid_assoc = verify_proof(@assoc_proof);
                    assert!(is_valid_assoc, "Invalid association proof");
                    assert!(
                        self.known_set_roots.read((set_id, assoc_proof.root)),
                        "Unknown association set root"
                    );
                }
            }

            if proof.exclusion_set_id.is_some() && proof.exclusion_proof.is_some() {
                compliance_level = 2;
            }

            self.nullifier_used.write(proof.nullifier, true);
            self._insert_nullifier(proof.nullifier);

            let sage_token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage_token.transfer(proof.recipient, proof.amount);

            self.total_withdrawals.write(self.total_withdrawals.read() + 1);
            self.total_volume_withdrawn.write(
                self.total_volume_withdrawn.read() + proof.amount
            );

            self.emit(PPWithdrawalExecuted {
                nullifier: proof.nullifier,
                recipient: proof.recipient,
                amount: proof.amount,
                compliance_level,
                association_set_id,
                timestamp: get_block_timestamp(),
            });

            true
        }

        fn is_pp_nullifier_used(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifier_used.read(nullifier)
        }

        // --- Ragequit ---

        fn initiate_pp_ragequit(ref self: ContractState, proof: PPRagequitProof) -> u256 {
            self._require_not_paused();
            self._require_initialized();
            assert!(
                self.deposit_exists.read(proof.deposit_commitment),
                "Deposit does not exist"
            );

            let deposit = self.deposit_info.read(proof.deposit_commitment);
            assert!(deposit.depositor == get_caller_address(), "Not the original depositor");

            let is_valid = verify_proof(@proof.global_tree_proof);
            assert!(is_valid, "Invalid global tree proof");

            let timestamp = get_block_timestamp();
            let request_id = self.next_ragequit_id.read();

            let request = PPRagequitRequest {
                request_id,
                commitment: proof.deposit_commitment,
                depositor: deposit.depositor,
                amount: proof.amount,
                recipient: proof.recipient,
                initiated_at: timestamp,
                executable_at: timestamp + self.ragequit_delay.read(),
                status: PPRagequitStatus::Pending,
            };

            self.ragequit_requests.write(request_id, request);
            self.ragequit_by_commitment.write(proof.deposit_commitment, request_id);
            self.next_ragequit_id.write(request_id + 1);
            self.total_ragequits.write(self.total_ragequits.read() + 1);

            self.emit(PPRagequitInitiated {
                request_id,
                commitment: proof.deposit_commitment,
                depositor: deposit.depositor,
                amount: proof.amount,
                executable_at: request.executable_at,
                timestamp,
            });

            request_id
        }

        fn complete_pp_ragequit(ref self: ContractState, request_id: u256) {
            self._require_not_paused();

            let mut request = self.ragequit_requests.read(request_id);
            assert!(request.status == PPRagequitStatus::Pending, "Invalid request status");
            assert!(get_block_timestamp() >= request.executable_at, "Delay not passed");

            request.status = PPRagequitStatus::Completed;
            self.ragequit_requests.write(request_id, request);

            let sage_token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage_token.transfer(request.recipient, request.amount);

            self.emit(PPRagequitCompleted {
                request_id,
                commitment: request.commitment,
                recipient: request.recipient,
                amount: request.amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn cancel_pp_ragequit(
            ref self: ContractState,
            request_id: u256,
            new_inclusion_set_id: felt252,
            inclusion_proof: LeanIMTProof
        ) {
            let mut request = self.ragequit_requests.read(request_id);
            assert!(request.status == PPRagequitStatus::Pending, "Invalid request status");

            let is_valid = verify_proof(@inclusion_proof);
            assert!(is_valid, "Invalid inclusion proof");

            let set_info = self.association_set_info.read(new_inclusion_set_id);
            assert!(set_info.set_type == AssociationSetType::Inclusion, "Not an inclusion set");

            request.status = PPRagequitStatus::Cancelled;
            self.ragequit_requests.write(request_id, request);

            self.emit(PPRagequitCancelled {
                request_id,
                commitment: request.commitment,
                new_inclusion_set_id,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_pp_ragequit_request(self: @ContractState, request_id: u256) -> PPRagequitRequest {
            self.ragequit_requests.read(request_id)
        }

        // --- Stats ---

        fn get_pp_stats(self: @ContractState) -> (u64, u64, u256, u256) {
            (
                self.total_deposits.read(),
                self.total_withdrawals.read(),
                self.total_volume_deposited.read(),
                self.total_volume_withdrawn.read()
            )
        }

        // --- Admin ---

        fn set_ragequit_delay(ref self: ContractState, delay: u64) {
            self._only_owner();
            self.ragequit_delay.write(delay);
        }

        fn set_asp_stake_minimum(ref self: ContractState, minimum: u256) {
            self._only_owner();
            self.asp_stake_minimum.write(minimum);
        }

        fn set_compliance_required(ref self: ContractState, required: bool) {
            self._only_owner();
            self.compliance_required.write(required);
        }

        fn pause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(true);
            self.emit(Paused { by: get_caller_address(), timestamp: get_block_timestamp() });
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(false);
            self.emit(Unpaused { by: get_caller_address(), timestamp: get_block_timestamp() });
        }

        // --- Upgrade ---

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Another upgrade is already pending");

            let current_time = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let executable_at = current_time + delay;

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(current_time);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: current_time,
                executable_at,
                scheduler: get_caller_address(),
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let current_time = get_block_timestamp();
            assert!(current_time >= scheduled_at + delay, "Upgrade delay not elapsed");

            // Clear pending upgrade state
            let zero_class: ClassHash = 0_felt252.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: current_time,
                executor: get_caller_address(),
            });

            // Upgrade the contract
            starknet::syscalls::replace_class_syscall(pending).unwrap();
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade to cancel");

            let zero_class: ClassHash = 0_felt252.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_at: get_block_timestamp(),
                canceller: get_caller_address(),
            });
        }

        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64, u64) {
            let pending = self.pending_upgrade.read();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let executable_at = scheduled_at + delay;
            (pending, scheduled_at, executable_at, delay)
        }

        fn set_upgrade_delay(ref self: ContractState, new_delay: u64) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Cannot change delay with pending upgrade");
            self.upgrade_delay.write(new_delay);
        }
    }

    // =========================================================================
    // INTERNAL FUNCTIONS
    // =========================================================================

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
        }

        fn _require_not_paused(self: @ContractState) {
            assert!(!self.paused.read(), "Contract is paused");
        }

        fn _require_initialized(self: @ContractState) {
            assert!(self.initialized.read(), "Not initialized");
        }

        fn _add_commitments_to_set(
            ref self: ContractState,
            set_id: felt252,
            commitments: Span<felt252>
        ) {
            let mut set_info = self.association_set_info.read(set_id);
            let start_index = set_info.tree_state.size;
            let len = commitments.len();

            let mut i: u32 = 0;
            loop {
                if i >= len {
                    break;
                }
                let commitment = *commitments.at(i);
                let index = start_index + i.into();

                self.association_set_nodes.write((set_id, 0, index), commitment);
                self.commitment_in_set.write((set_id, commitment), true);

                i += 1;
            };

            let final_size = start_index + len.into();
            let new_depth = calculate_depth(final_size);
            let new_root = self._rebuild_association_set_tree(set_id, start_index, final_size, new_depth);

            set_info.tree_state = LeanIMTState { root: new_root, size: final_size, depth: new_depth };
            set_info.member_count = final_size;
            set_info.last_updated = get_block_timestamp();
            self.association_set_info.write(set_id, set_info);

            self.known_set_roots.write((set_id, new_root), true);

            self.emit(CommitmentsAddedToSet {
                set_id,
                count: len,
                new_root,
                new_size: final_size,
                timestamp: set_info.last_updated,
            });
        }

        fn _rebuild_association_set_tree(
            ref self: ContractState,
            set_id: felt252,
            start_index: u64,
            size: u64,
            depth: u8
        ) -> felt252 {
            if size == 0 {
                return 0;
            }
            if size == 1 {
                return self.association_set_nodes.read((set_id, 0, 0));
            }

            let mut level: u8 = 0;
            let mut level_size: u64 = 1;
            loop {
                if level >= depth {
                    break;
                }

                let nodes_at_level = (size + level_size - 1) / level_size;
                let mut i: u64 = 0;

                loop {
                    if i >= nodes_at_level / 2 {
                        break;
                    }

                    let left_index = i * 2;
                    let right_index = left_index + 1;

                    let left_hash = self.association_set_nodes.read((set_id, level, left_index));

                    let parent_hash = if right_index < nodes_at_level {
                        let right_hash = self.association_set_nodes.read((set_id, level, right_index));
                        hash_pair(left_hash, right_hash)
                    } else {
                        left_hash
                    };

                    self.association_set_nodes.write((set_id, level + 1, i), parent_hash);
                    i += 1;
                };

                level += 1;
                level_size *= 2;
            };

            self.association_set_nodes.read((set_id, depth, 0))
        }

        fn _insert_global_deposit(ref self: ContractState, commitment: felt252) -> u64 {
            let state = self.global_deposit_tree.read();
            let index = state.size;

            self.global_deposit_nodes.write((0, index), commitment);

            let new_size = index + 1;
            let new_depth = calculate_depth(new_size);

            let new_root = self._update_global_deposit_path(index, commitment, new_depth);

            let new_state = LeanIMTState { root: new_root, size: new_size, depth: new_depth };
            self.global_deposit_tree.write(new_state);

            self.known_global_roots.write(new_root, true);
            let root_idx = self.global_root_index.read();
            self.global_root_history.write(root_idx, new_root);
            self.global_root_index.write((root_idx + 1) % PP_ROOT_HISTORY_SIZE);

            index
        }

        fn _update_global_deposit_path(
            ref self: ContractState,
            index: u64,
            value: felt252,
            depth: u8
        ) -> felt252 {
            let mut current_hash = value;
            let mut current_index = index;
            let mut level: u8 = 0;

            loop {
                if level >= depth {
                    break;
                }

                let is_right = current_index % 2 == 1;
                let sibling_index = if is_right { current_index - 1 } else { current_index + 1 };
                let parent_index = current_index / 2;

                let sibling_hash = self.global_deposit_nodes.read((level, sibling_index));

                current_hash = if is_right {
                    if sibling_hash != 0 {
                        hash_pair(sibling_hash, current_hash)
                    } else {
                        current_hash
                    }
                } else {
                    if sibling_hash != 0 {
                        hash_pair(current_hash, sibling_hash)
                    } else {
                        self.global_deposit_side_nodes.write(level, current_hash);
                        current_hash
                    }
                };

                self.global_deposit_nodes.write((level + 1, parent_index), current_hash);
                current_index = parent_index;
                level += 1;
            };

            current_hash
        }

        fn _rebuild_global_deposit_tree(
            ref self: ContractState,
            start_index: u64,
            size: u64,
            depth: u8
        ) -> felt252 {
            if size == 0 {
                return 0;
            }
            if size == 1 {
                return self.global_deposit_nodes.read((0, 0));
            }

            let mut level: u8 = 0;
            let mut level_size: u64 = 1;
            loop {
                if level >= depth {
                    break;
                }

                let nodes_at_level = (size + level_size - 1) / level_size;
                let mut i: u64 = 0;

                loop {
                    if i >= nodes_at_level / 2 {
                        break;
                    }

                    let left_index = i * 2;
                    let right_index = left_index + 1;

                    let left_hash = self.global_deposit_nodes.read((level, left_index));

                    let parent_hash = if right_index < nodes_at_level {
                        let right_hash = self.global_deposit_nodes.read((level, right_index));
                        hash_pair(left_hash, right_hash)
                    } else {
                        left_hash
                    };

                    self.global_deposit_nodes.write((level + 1, i), parent_hash);
                    i += 1;
                };

                level += 1;
                level_size *= 2;
            };

            self.global_deposit_nodes.read((depth, 0))
        }

        fn _insert_nullifier(ref self: ContractState, nullifier: felt252) {
            let state = self.nullifier_tree.read();
            let index = state.size;

            self.nullifier_nodes.write((0, index), nullifier);

            let new_size = index + 1;
            let new_depth = calculate_depth(new_size);

            let new_root = self._update_nullifier_path(index, nullifier, new_depth);

            let new_state = LeanIMTState { root: new_root, size: new_size, depth: new_depth };
            self.nullifier_tree.write(new_state);
        }

        fn _update_nullifier_path(
            ref self: ContractState,
            index: u64,
            value: felt252,
            depth: u8
        ) -> felt252 {
            let mut current_hash = value;
            let mut current_index = index;
            let mut level: u8 = 0;

            loop {
                if level >= depth {
                    break;
                }

                let is_right = current_index % 2 == 1;
                let sibling_index = if is_right { current_index - 1 } else { current_index + 1 };
                let parent_index = current_index / 2;

                let sibling_hash = self.nullifier_nodes.read((level, sibling_index));

                current_hash = if is_right {
                    if sibling_hash != 0 {
                        hash_pair(sibling_hash, current_hash)
                    } else {
                        current_hash
                    }
                } else {
                    if sibling_hash != 0 {
                        hash_pair(current_hash, sibling_hash)
                    } else {
                        self.nullifier_side_nodes.write(level, current_hash);
                        current_hash
                    }
                };

                self.nullifier_nodes.write((level + 1, parent_index), current_hash);
                current_index = parent_index;
                level += 1;
            };

            current_hash
        }
    }
}
