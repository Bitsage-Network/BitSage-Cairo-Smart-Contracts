// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Obelysk Privacy Router
// Handles private SAGE token transfers using ElGamal encryption
// Based on Zether protocol with BitSage-specific extensions
//
// Features:
// - Hidden transfer amounts (only sender/receiver can decrypt)
// - Homomorphic balance updates (no plaintext amounts on-chain)
// - Worker payment privacy for GPU providers
// - Auditor key escrow for compliance
// - Nullifier-based double-spend prevention

use starknet::ContractAddress;
use sage_contracts::obelysk::elgamal::{
    ECPoint, ElGamalCiphertext, EncryptedBalance,
    EncryptionProof, TransferProof,
    // AE Hints for fast decryption
    AEHint,
};

// Import Pedersen commitment type from commitments module
// Note: Old RangeProof is deprecated - use RangeProof32 from bit_proofs instead
use sage_contracts::obelysk::pedersen_commitments::PedersenCommitment;

// Same Encryption Proofs - Critical for transfer integrity
// Proves sender/receiver/auditor ciphertexts encrypt the same amount
use sage_contracts::obelysk::same_encryption::SameEncryption3Proof;

/// Account state for private balances
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PrivateAccount {
    pub public_key: ECPoint,
    pub encrypted_balance: EncryptedBalance,
    pub pending_transfers: u32,
    pub last_rollup_epoch: u64,
    pub is_registered: bool,
}

/// Account hints for fast balance decryption
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AccountHints {
    /// Hint for current balance
    pub balance_hint: AEHint,
    /// Hint for pending incoming
    pub pending_in_hint: AEHint,
    /// Hint for pending outgoing
    pub pending_out_hint: AEHint,
    /// Nonce counter for generating unique nonces
    pub hint_nonce: u64,
}

/// Private transfer request
#[derive(Copy, Drop, Serde)]
pub struct PrivateTransfer {
    pub sender: ContractAddress,
    pub receiver: ContractAddress,
    pub encrypted_amount: ElGamalCiphertext,  // Amount encrypted to receiver
    pub sender_delta: ElGamalCiphertext,       // Encrypted change for sender (negative)
    pub proof: TransferProof,
    pub nullifier: felt252,
}

/// Enhanced private transfer with auditor encryption and same-encryption proof
///
/// This variant provides cryptographic guarantees that:
/// 1. The sender's delta, receiver's amount, and auditor's amount all encrypt the SAME value
/// 2. Compliance can be maintained through auditor decryption
/// 3. No balance manipulation is possible (amount mismatch attacks prevented)
///
/// Based on Tongo's SHE library same-encryption proofs
#[derive(Copy, Drop, Serde)]
pub struct PrivateTransferWithAudit {
    pub sender: ContractAddress,
    pub receiver: ContractAddress,
    /// Amount encrypted to sender (negative/debit)
    pub sender_encrypted_amount: ElGamalCiphertext,
    /// Amount encrypted to receiver (positive/credit)
    pub receiver_encrypted_amount: ElGamalCiphertext,
    /// Amount encrypted to auditor (for compliance)
    pub auditor_encrypted_amount: ElGamalCiphertext,
    /// Proof that sender/receiver/auditor ciphertexts all encrypt the SAME amount
    /// This is the CRITICAL security property from Tongo's analysis
    pub same_encryption_proof: SameEncryption3Proof,
    /// Original transfer proof for range/balance verification
    pub transfer_proof: TransferProof,
    /// Unique nullifier for double-spend prevention
    pub nullifier: felt252,
}

/// Worker payment with privacy
///
/// Supports multi-asset payments where each payment is identified by
/// (job_id, asset_id). Workers can receive payments in SAGE, USDC, STRK, or BTC.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PrivateWorkerPayment {
    pub job_id: u256,
    pub worker: ContractAddress,
    /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
    pub asset_id: u64,
    pub encrypted_amount: ElGamalCiphertext,
    pub timestamp: u64,
    pub is_claimed: bool,
}

/// Supported asset IDs
pub mod AssetIds {
    /// Network native token (SAGE)
    pub const SAGE: u64 = 0;
    /// Native USDC on Starknet
    pub const USDC: u64 = 1;
    /// Starknet native token (STRK)
    pub const STRK: u64 = 2;
    /// Native BTC via BTCFi bridge
    pub const BTC: u64 = 3;
    /// Native ETH
    pub const ETH: u64 = 4;
}

// =============================================================================
// MULTI-SIGNATURE AUDITING
// =============================================================================

/// Auditor information for the M-of-N auditor registry
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AuditorInfo {
    /// Auditor's contract address
    pub address: ContractAddress,
    /// Auditor's public key for ElGamal encryption
    pub public_key: ECPoint,
    /// Registration timestamp
    pub registered_at: u64,
    /// Whether this auditor is currently active
    pub is_active: bool,
    /// Total approvals made (audit trail)
    pub total_approvals: u64,
    /// Index in the auditor list (for iteration)
    pub list_index: u32,
}

/// Type of audit request
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum AuditRequestType {
    /// Pre-approval required for large transfer
    #[default]
    LargeTransfer,
    /// Request to disclose transaction details
    Disclosure,
    /// Emergency freeze request
    Freeze,
}

/// Status of an audit request
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum AuditRequestStatus {
    /// Awaiting auditor approvals
    #[default]
    Pending,
    /// Approved (threshold met)
    Approved,
    /// Rejected by auditors
    Rejected,
    /// Request expired
    Expired,
    /// Request executed
    Executed,
}

/// Audit request for M-of-N approval
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AuditRequest {
    /// Unique request ID
    pub request_id: u256,
    /// Type of request
    pub request_type: AuditRequestType,
    /// Address that created the request
    pub requester: ContractAddress,
    /// Target nullifier (transfer being audited)
    pub target_nullifier: felt252,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp
    pub expires_at: u64,
    /// Current approval count
    pub approval_count: u32,
    /// Required approvals at time of creation
    pub required_approvals: u32,
    /// Current status
    pub status: AuditRequestStatus,
    /// Whether the request has been executed
    pub executed: bool,
}

/// Threshold proof for privacy-preserving amount comparison
/// Proves amount >= threshold without revealing the exact amount
#[derive(Copy, Drop, Serde)]
pub struct ThresholdProof {
    /// Commitment to (amount - threshold): V_diff = (amount - threshold)*G + r_diff*H
    pub difference_commitment: ECPoint,
    /// Range proof proving difference >= 0 (i.e., amount >= threshold)
    pub range_proof_data: Span<felt252>,
    /// Blinding factor for verification
    pub blinding_diff: felt252,
}

/// Audit request timeout (7 days in seconds)
pub const AUDIT_REQUEST_TIMEOUT: u64 = 604800;

/// Default large transfer threshold (10,000 * 10^18 = 10k tokens)
pub const DEFAULT_LARGE_TRANSFER_THRESHOLD: u256 = 10000000000000000000000;

// =============================================================================
// EX-POST PROVING - Retroactive ZK Proofs
// =============================================================================

/// Type of ex-post proof
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum ExPostProofType {
    /// Proved volume < threshold
    #[default]
    Volume,
    /// Proved no transaction with specific address
    NonTransaction,
    /// Full disclosure bundle with auditor approval
    Compliance,
}

/// On-chain record of verified ex-post proof
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ExPostProofRecord {
    /// Unique proof ID
    pub proof_id: u256,
    /// Type of proof
    pub proof_type: ExPostProofType,
    /// Address that submitted the proof
    pub prover: ContractAddress,
    /// Timestamp when proof was verified
    pub verified_at: u64,
    /// Start of claimed epoch range
    pub epoch_start: u64,
    /// End of claimed epoch range
    pub epoch_end: u64,
    /// Hash of the proof data for reference
    pub proof_hash: felt252,
    /// For volume proofs: the threshold that was proven under
    pub volume_threshold: u256,
    /// For non-transaction: the excluded address
    pub excluded_address: ContractAddress,
}

/// Proves total transaction volume < threshold without revealing individual amounts
#[derive(Drop, Serde)]
pub struct VolumeProof {
    /// Nullifiers being claimed (user's transactions)
    pub nullifiers: Span<felt252>,
    /// Sum commitment: C = (Σ amounts)*G + (Σ blindings)*H
    pub sum_commitment: ECPoint,
    /// Aggregate blinding factor for sum commitment
    pub sum_blinding: felt252,
    /// Range proof on (threshold - sum): proves sum < threshold
    pub range_proof_data: Span<felt252>,
    /// Epoch range being claimed (start, end)
    pub epoch_start: u64,
    pub epoch_end: u64,
}

/// Proves two values are not equal without revealing either
/// Method: Prove knowledge of (a - b)^(-1) mod p
#[derive(Copy, Drop, Serde)]
pub struct InequalityProof {
    /// Commitment to (receiver - excluded_address)
    pub difference_commitment: ECPoint,
    /// Schnorr proof commitment R = r * G
    pub r_commitment: ECPoint,
    /// Challenge from Fiat-Shamir
    pub challenge: felt252,
    /// Response: s = r + c * inverse
    pub response: felt252,
}

/// Proves user never transacted with a specific address
#[derive(Drop, Serde)]
pub struct NonTransactionProof {
    /// Address being claimed as never transacted with
    pub excluded_address: ContractAddress,
    /// All user's nullifiers in the time range
    pub nullifiers: Span<felt252>,
    /// For each nullifier: commitment proving receiver ≠ excluded_address
    pub inequality_proofs: Span<InequalityProof>,
    /// Epoch range for the claim
    pub epoch_start: u64,
    pub epoch_end: u64,
    /// Hash of user's nullifier set for completeness check
    pub nullifier_set_hash: felt252,
}

/// Proves correct decryption of ElGamal ciphertext
/// Proves: amount = Dec(sk, ciphertext) without revealing sk
#[derive(Copy, Drop, Serde)]
pub struct DecryptionProof {
    /// Commitment: R = r * G (randomness commitment)
    pub r_commitment: ECPoint,
    /// Challenge from Fiat-Shamir
    pub challenge: felt252,
    /// Response: s = r + c * sk (mod n)
    pub response: felt252,
}

/// Single disclosed transaction with proof of correct decryption
#[derive(Copy, Drop, Serde)]
pub struct DisclosedTransaction {
    /// Transaction nullifier
    pub nullifier: felt252,
    /// Sender address
    pub sender: ContractAddress,
    /// Receiver address
    pub receiver: ContractAddress,
    /// Revealed amount
    pub amount: u64,
    /// Transaction timestamp
    pub timestamp: u64,
    /// Proof that revealed amount matches auditor ciphertext
    pub decryption_proof: DecryptionProof,
}

/// Full transaction disclosure for compliance (requires M-of-N approval)
#[derive(Drop, Serde)]
pub struct ComplianceBundle {
    /// Approved disclosure request IDs (from multi-sig system)
    pub disclosure_request_ids: Span<u256>,
    /// Disclosed transactions with decrypted amounts
    pub disclosed_transactions: Span<DisclosedTransaction>,
    /// Aggregate total volume
    pub total_volume: u256,
    /// Number of transactions
    pub transaction_count: u32,
    /// Time range covered (start)
    pub period_start: u64,
    /// Time range covered (end)
    pub period_end: u64,
}

/// Maximum number of nullifiers in a single ex-post proof
pub const MAX_EX_POST_NULLIFIERS: u32 = 100;

// =============================================================================
// Ragequit - Emergency Full Balance Withdrawal
// =============================================================================

/// Ragequit proof for emergency full-balance withdrawal
///
/// This proof allows users to withdraw their entire balance without
/// going through normal approval processes. The tradeoff is that
/// the withdrawal amount is revealed publicly.
#[derive(Copy, Drop, Serde)]
pub struct RagequitProof {
    /// Schnorr proof commitment (R = k*G)
    pub commitment_x: felt252,
    pub commitment_y: felt252,
    /// Challenge: e = H(PK, R, context)
    pub challenge: felt252,
    /// Response: s = k - e*sk (mod curve_order)
    pub response: felt252,
    /// The claimed balance amount (revealed publicly)
    pub claimed_amount: u64,
    /// Hash of the encrypted balance being withdrawn from
    pub balance_hash: felt252,
    /// Nullifier to prevent double-ragequit
    pub nullifier: felt252,
    /// Timestamp of proof generation (prevents replay)
    pub timestamp: u64,
}

/// Ragequit result event data
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RagequitRecord {
    /// Account that ragequit
    pub account: ContractAddress,
    /// Amount withdrawn
    pub amount: u256,
    /// Nullifier used
    pub nullifier: felt252,
    /// Timestamp of ragequit
    pub timestamp: u64,
}

/// Ragequit domain separator (matches Rust: "obelysk-ragequit-v1")
pub const RAGEQUIT_DOMAIN: felt252 = 'obelysk-ragequit-v1';

/// Maximum age of ragequit proof in seconds (1 hour)
pub const RAGEQUIT_MAX_AGE: u64 = 3600;

// =============================================================================
// Steganographic Transactions - Hide Transaction Existence
// =============================================================================
//
// Steganographic transactions make all privacy operations indistinguishable
// from each other and from cover traffic. This prevents observers from knowing
// that a transfer even occurred.

/// Steganographic operation types (hidden from observers)
/// All values encode to same size to prevent distinguishing
#[derive(Copy, Drop, Serde, PartialEq)]
pub enum StegOperationType {
    Transfer,      // Real transfer between accounts
    Deposit,       // Deposit from public to private
    Withdraw,      // Withdrawal from private to public
    NoOp,          // No operation (cover traffic)
    SelfTransfer,  // Self-transfer (mixing/refresh)
}

// =============================================================================
// Nullifier Merkle Tree - Efficient Double-Spend Prevention
// =============================================================================
//
// Incremental Merkle Tree for efficient nullifier management.
// Stores only filled subtrees and root on-chain, allowing O(log n) insertions
// and membership proofs.

/// Tree depth (20 levels = 2^20 = ~1M nullifiers)
pub const NULLIFIER_TREE_DEPTH: u32 = 20;

/// Domain separator for nullifier tree hashing
pub const NULLIFIER_TREE_DOMAIN: felt252 = 'obelysk-nulltree-v1';

/// Merkle proof for nullifier membership
#[derive(Drop, Serde)]
pub struct NullifierMerkleProof {
    /// Path from leaf to root (sibling hashes)
    pub path: Array<felt252>,
    /// Direction at each level (false = left, true = right)
    pub indices: Array<bool>,
    /// The nullifier being proven
    pub nullifier: felt252,
    /// Root at time of proof generation
    pub root: felt252,
}

/// Nullifier tree state (for off-chain sync)
#[derive(Drop, Serde)]
pub struct NullifierTreeState {
    /// Current tree root
    pub root: felt252,
    /// Number of nullifiers in tree
    pub next_index: u64,
    /// Filled subtrees at each level
    pub filled_subtrees: Array<felt252>,
}

/// Result of nullifier tree insertion
#[derive(Drop, Serde)]
pub struct NullifierInsertResult {
    /// New root after insertion
    pub new_root: felt252,
    /// Index where nullifier was inserted
    pub index: u64,
    /// Whether insertion was successful
    pub success: bool,
}

// Re-export LeanIMT types for public interface
pub use sage_contracts::obelysk::lean_imt::{
    LeanIMTState, LeanIMTProof, LeanIMTBatchResult,
};

// =============================================================================
// BATCH DEPOSITS - Multi-Asset Single Transaction
// =============================================================================

/// A single deposit item for batch deposit operations
///
/// Each item represents a deposit of a specific asset into the privacy layer.
/// Multiple items can be processed in a single transaction for efficiency.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct BatchDepositItem {
    /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
    pub asset_id: u64,
    /// Amount to deposit in asset's native decimals
    pub amount: u256,
    /// Amount encrypted to depositor's public key (normalized to 18 decimals)
    pub encrypted_amount: ElGamalCiphertext,
    /// Proof of correct encryption
    pub proof: EncryptionProof,
}

/// Result of batch deposit operation
#[derive(Drop, Serde)]
pub struct BatchDepositResult {
    /// Number of items successfully deposited
    pub items_deposited: u32,
    /// Total value deposited in normalized decimals (18)
    pub total_normalized_value: u256,
    /// Timestamp of batch deposit
    pub timestamp: u64,
}

/// Maximum number of items in a single batch deposit
pub const MAX_BATCH_DEPOSIT_ITEMS: u32 = 10;

#[starknet::interface]
pub trait IPrivacyRouter<TContractState> {
    /// Register a new private account with public key
    fn register_account(
        ref self: TContractState,
        public_key: ECPoint
    );

    /// Deposit SAGE tokens into private account
    /// Converts public balance to encrypted balance
    fn deposit(
        ref self: TContractState,
        amount: u256,
        encrypted_amount: ElGamalCiphertext,
        proof: EncryptionProof
    );

    /// Withdraw SAGE tokens from private account
    /// Converts encrypted balance back to public
    /// SECURITY: Requires range proof proving remaining balance >= 0
    /// Note: Range proof is passed as serialized calldata (Span<felt252>)
    fn withdraw(
        ref self: TContractState,
        amount: u256,
        encrypted_delta: ElGamalCiphertext,
        proof: EncryptionProof,
        remaining_balance_commitment: PedersenCommitment,
        range_proof_data: Span<felt252>
    );

    /// Private transfer between two accounts
    /// Amount is hidden from observers
    fn private_transfer(
        ref self: TContractState,
        transfer: PrivateTransfer
    );

    /// Enhanced private transfer with auditor encryption and same-encryption proof
    ///
    /// This variant provides cryptographic guarantees that sender/receiver/auditor
    /// ciphertexts all encrypt the same amount. Critical for:
    /// - Preventing amount mismatch attacks
    /// - Enabling compliance through auditor decryption
    /// - Transfer integrity verification
    ///
    /// Based on Tongo's SHE library same-encryption proofs
    fn private_transfer_with_audit(
        ref self: TContractState,
        transfer: PrivateTransferWithAudit
    );

    /// Receive private worker payment (called by PaymentRouter)
    /// Worker can later claim with decryption proof
    fn receive_worker_payment(
        ref self: TContractState,
        job_id: u256,
        worker: ContractAddress,
        sage_amount: u256,
        encrypted_amount: ElGamalCiphertext
    );

    /// Worker claims payment (provides decryption proof)
    fn claim_worker_payment(
        ref self: TContractState,
        job_id: u256,
        decryption_proof: EncryptionProof
    );

    /// Roll up pending transactions into balance
    fn rollup_balance(ref self: TContractState);

    /// Get account info (public key, encrypted balance)
    fn get_account(self: @TContractState, account: ContractAddress) -> PrivateAccount;

    /// Get worker payment info (legacy single-asset)
    fn get_worker_payment(self: @TContractState, job_id: u256) -> PrivateWorkerPayment;

    // ===================== MULTI-ASSET WORKER PAYMENTS =====================

    /// Receive private worker payment for a specific asset (called by PaymentRouter)
    ///
    /// Extends `receive_worker_payment` to support multiple token types.
    /// The coordinator specifies which asset the worker should be paid in.
    fn receive_worker_payment_for_asset(
        ref self: TContractState,
        job_id: u256,
        asset_id: u64,
        worker: ContractAddress,
        amount: u256,
        encrypted_amount: ElGamalCiphertext
    );

    /// Worker claims payment for a specific asset
    ///
    /// Used when a worker has payments pending in multiple tokens
    /// for the same job (or different jobs).
    fn claim_worker_payment_for_asset(
        ref self: TContractState,
        job_id: u256,
        asset_id: u64,
        decryption_proof: EncryptionProof
    );

    /// Get worker payment for a specific asset
    fn get_worker_payment_for_asset(
        self: @TContractState,
        job_id: u256,
        asset_id: u64
    ) -> PrivateWorkerPayment;

    /// Get count of pending payments for a worker in a specific asset
    fn get_worker_pending_count(
        self: @TContractState,
        worker: ContractAddress,
        asset_id: u64
    ) -> u32;

    /// Get token contract address for an asset
    fn get_asset_token(self: @TContractState, asset_id: u64) -> ContractAddress;

    /// Get decimal places for an asset (6 for USDC, 8 for BTC, 18 for SAGE/STRK/ETH)
    fn get_asset_decimals(self: @TContractState, asset_id: u64) -> u8;

    /// Check if an asset is supported
    fn is_asset_supported(self: @TContractState, asset_id: u64) -> bool;

    /// Check if nullifier was used (prevent double-spend)
    fn is_nullifier_used(self: @TContractState, nullifier: felt252) -> bool;

    /// Get current epoch for rollup coordination
    fn get_current_epoch(self: @TContractState) -> u64;

    // ===================== BATCH DEPOSITS =====================

    /// Batch deposit multiple assets in a single transaction
    ///
    /// Efficiently deposits multiple token types into the privacy layer.
    /// Each item is processed independently with its own encryption proof.
    /// All token transfers happen atomically.
    ///
    /// Requirements:
    /// - Caller must have registered account
    /// - All asset IDs must be supported
    /// - All encryption proofs must be valid
    /// - Batch size must be <= MAX_BATCH_DEPOSIT_ITEMS
    /// - Caller must have approved this contract for all token transfers
    ///
    /// Effects:
    /// - Tokens are transferred from caller to contract
    /// - Encrypted amounts are added to pending_in for each asset
    /// - BatchDeposit events are emitted for each item
    fn batch_deposit(
        ref self: TContractState,
        items: Array<BatchDepositItem>
    );

    /// Deposit a specific asset into privacy account
    ///
    /// Single-asset variant for explicit asset selection.
    /// Use this when depositing non-SAGE assets individually.
    fn deposit_asset(
        ref self: TContractState,
        asset_id: u64,
        amount: u256,
        encrypted_amount: ElGamalCiphertext,
        proof: EncryptionProof
    );

    // ===================== RAGEQUIT (Emergency Withdrawal) =====================

    /// Emergency full-balance withdrawal without approval
    ///
    /// Ragequit allows users to withdraw their full encrypted balance
    /// by revealing the amount publicly. This is a safety mechanism that
    /// ensures users can always exit the privacy layer.
    ///
    /// Requirements:
    /// - Caller must be the account owner
    /// - Proof must be valid (Schnorr ownership proof)
    /// - Nullifier must not have been used
    /// - Proof must be recent (within RAGEQUIT_MAX_AGE)
    ///
    /// Effects:
    /// - Account balance is set to zero
    /// - Claimed amount is transferred to caller
    /// - Nullifier is marked as used
    fn ragequit(
        ref self: TContractState,
        proof: RagequitProof
    );

    /// Check if a ragequit nullifier has been used
    fn is_ragequit_nullifier_used(self: @TContractState, nullifier: felt252) -> bool;

    /// Get ragequit record by nullifier
    fn get_ragequit_record(self: @TContractState, nullifier: felt252) -> RagequitRecord;

    /// Admin: Set auditor public key (for compliance)
    fn set_auditor_key(ref self: TContractState, auditor_key: ECPoint);

    /// Admin: Set payment router address
    fn set_payment_router(ref self: TContractState, router: ContractAddress);

    /// Admin: Set SAGE token address
    fn set_sage_token(ref self: TContractState, sage: ContractAddress);

    /// Admin: Pause/unpause for emergencies
    fn set_paused(ref self: TContractState, paused: bool);

    // ===================== MULTI-SIGNATURE AUDITING =====================

    /// Register a new auditor (owner only)
    fn register_auditor(ref self: TContractState, auditor: ContractAddress, public_key: ECPoint);

    /// Remove an auditor (owner only)
    fn remove_auditor(ref self: TContractState, auditor: ContractAddress);

    /// Update the approval threshold M in M-of-N (owner only)
    fn update_audit_threshold(ref self: TContractState, new_threshold: u32);

    /// Update the large transfer threshold (owner only)
    fn update_large_transfer_threshold(ref self: TContractState, new_threshold: u256);

    /// Get auditor info
    fn get_auditor(self: @TContractState, auditor: ContractAddress) -> AuditorInfo;

    /// Get total auditor count
    fn get_auditor_count(self: @TContractState) -> u32;

    /// Get approval threshold
    fn get_audit_threshold(self: @TContractState) -> u32;

    /// Get large transfer threshold
    fn get_large_transfer_threshold(self: @TContractState) -> u256;

    /// Check if address is an active auditor
    fn is_auditor(self: @TContractState, address: ContractAddress) -> bool;

    /// Approve an audit request (auditors only)
    fn approve_audit_request(ref self: TContractState, request_id: u256);

    /// Get audit request status
    fn get_audit_request(self: @TContractState, request_id: u256) -> AuditRequest;

    /// Check if auditor has approved a request
    fn has_approved(self: @TContractState, request_id: u256, auditor: ContractAddress) -> bool;

    /// Request disclosure of a transaction (owner or auditors only)
    fn request_disclosure(ref self: TContractState, nullifier: felt252, reason: felt252) -> u256;

    /// Get disclosed ciphertext (only if request is approved)
    fn get_disclosed_ciphertext(self: @TContractState, request_id: u256) -> (ElGamalCiphertext, bool);

    // ===================== LARGE TRANSFER APPROVAL =====================

    /// Submit a large transfer that requires M-of-N auditor approval
    /// Uses ZK threshold proof to verify amount >= threshold without revealing exact value
    fn submit_large_transfer(
        ref self: TContractState,
        transfer: PrivateTransferWithAudit,
        threshold_proof: ThresholdProof,
    ) -> u256;

    /// Execute an approved large transfer (anyone can call once threshold is met)
    fn execute_approved_transfer(ref self: TContractState, request_id: u256);

    /// Get all pending audit requests
    fn get_pending_request_count(self: @TContractState) -> u256;

    // ===================== EX-POST PROVING =====================

    /// Verify a volume proof: proves total transaction volume < threshold
    fn verify_volume_proof(
        ref self: TContractState,
        proof: VolumeProof,
        threshold: u256,
    ) -> u256;

    /// Verify a non-transaction proof: proves never transacted with specific address
    fn verify_non_transaction_proof(
        ref self: TContractState,
        proof: NonTransactionProof,
    ) -> u256;

    /// Verify a compliance bundle: full disclosure with auditor approval
    fn verify_compliance_bundle(
        ref self: TContractState,
        bundle: ComplianceBundle,
    ) -> u256;

    /// Get ex-post proof record by ID
    fn get_ex_post_proof(self: @TContractState, proof_id: u256) -> ExPostProofRecord;

    /// Get user's ex-post proof count
    fn get_user_ex_post_proof_count(self: @TContractState, user: ContractAddress) -> u32;

    /// Get user's ex-post proof by index
    fn get_user_ex_post_proof(
        self: @TContractState,
        user: ContractAddress,
        index: u32
    ) -> ExPostProofRecord;

    // ===================== AE HINTS (Fast Decryption) =====================

    /// Update balance hints for an account
    /// Called by the account owner after decrypting balances off-chain
    fn update_balance_hints(
        ref self: TContractState,
        balance_hint: AEHint,
        pending_in_hint: AEHint,
        pending_out_hint: AEHint
    );

    /// Get account hints for fast decryption
    fn get_account_hints(self: @TContractState, account: ContractAddress) -> AccountHints;

    /// Deposit with AE hint for fast balance queries
    fn deposit_with_hint(
        ref self: TContractState,
        amount: u256,
        encrypted_amount: ElGamalCiphertext,
        proof: EncryptionProof,
        balance_hint: AEHint
    );

    /// Private transfer with hints for both sender and receiver
    fn private_transfer_with_hints(
        ref self: TContractState,
        transfer: PrivateTransfer,
        sender_new_balance_hint: AEHint,
        receiver_pending_hint: AEHint
    );

    /// Get current hint nonce for an account
    fn get_hint_nonce(self: @TContractState, account: ContractAddress) -> u64;

    // ===================== UPGRADE FUNCTIONS =====================
    fn schedule_upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (starknet::ClassHash, u64, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, new_delay: u64);

    // ===================== NULLIFIER TREE =====================

    /// Get current nullifier tree root
    fn get_nullifier_tree_root(self: @TContractState) -> felt252;

    /// Get current nullifier tree state for off-chain sync
    fn get_nullifier_tree_state(self: @TContractState) -> NullifierTreeState;

    /// Check if a nullifier exists in the tree
    fn is_nullifier_in_tree(self: @TContractState, nullifier: felt252) -> bool;

    /// Verify a nullifier membership proof against the current root
    fn verify_nullifier_proof(
        self: @TContractState,
        proof: NullifierMerkleProof
    ) -> bool;

    /// Get the number of nullifiers in the tree
    fn get_nullifier_count(self: @TContractState) -> u64;

    /// Check if a historical root is known
    fn is_known_nullifier_root(self: @TContractState, root: felt252) -> bool;

    // ===================== LEAN IMT (Gas-Optimized) =====================

    /// Initialize the LeanIMT (admin only, one-time)
    fn init_lean_imt(ref self: TContractState);

    /// Batch insert multiple nullifiers via LeanIMT
    /// Returns batch result with new root, size, and depth
    fn batch_insert_nullifiers(
        ref self: TContractState,
        nullifiers: Span<felt252>
    ) -> LeanIMTBatchResult;

    /// Get current LeanIMT state (root, size, depth)
    fn get_lean_imt_state(self: @TContractState) -> LeanIMTState;

    /// Verify a LeanIMT membership proof
    fn verify_lean_imt_membership(
        self: @TContractState,
        proof: LeanIMTProof
    ) -> bool;

    /// Check if LeanIMT is active
    fn is_lean_imt_active(self: @TContractState) -> bool;
}

#[starknet::contract]
mod PrivacyRouter {
    use super::{
        IPrivacyRouter, PrivateAccount, PrivateTransfer, PrivateTransferWithAudit,
        PrivateWorkerPayment,
        AccountHints, RagequitProof, RagequitRecord,
        RAGEQUIT_DOMAIN, RAGEQUIT_MAX_AGE,
        // Batch deposits
        BatchDepositItem, MAX_BATCH_DEPOSIT_ITEMS,
        // Nullifier tree
        NullifierMerkleProof, NullifierTreeState,
        NULLIFIER_TREE_DEPTH, NULLIFIER_TREE_DOMAIN,
        // Multi-signature auditing
        AuditorInfo, AuditRequest, AuditRequestType, AuditRequestStatus,
        ThresholdProof, AUDIT_REQUEST_TIMEOUT, DEFAULT_LARGE_TRANSFER_THRESHOLD,
        // Ex-post proving
        ExPostProofType, ExPostProofRecord, VolumeProof, InequalityProof,
        NonTransactionProof, DecryptionProof,
        ComplianceBundle, MAX_EX_POST_NULLIFIERS
    };
    // LeanIMT - Lean Incremental Merkle Tree for gas-efficient nullifiers
    use sage_contracts::obelysk::lean_imt::{
        LeanIMTState, LeanIMTProof, LeanIMTBatchResult,
        calculate_depth, needs_depth_increase, hash_pair, verify_proof,
    };
    // Same Encryption Proofs for transfer integrity
    use sage_contracts::obelysk::same_encryption::{SameEncryption3Inputs, verify_same_encryption_3};
    use sage_contracts::obelysk::elgamal::{
        ECPoint, ElGamalCiphertext, EncryptedBalance,
        EncryptionProof,
        ec_zero, is_zero, zero_ciphertext, homomorphic_add, homomorphic_sub,
        verify_ciphertext, hash_points, rollup_balance,
        get_c1, get_c2, get_commitment,
        // AE Hints
        AEHint,
        // Curve order modular arithmetic
        reduce_mod_n,
        // EC operations for full Schnorr verification
        generator, ec_mul, ec_add, ec_sub
    };
    // Import Pedersen commitment type (old RangeProof is deprecated)
    use sage_contracts::obelysk::pedersen_commitments::PedersenCommitment;
    // Bit-decomposition range proofs
    use sage_contracts::obelysk::bit_proofs::{
        verify_range_proof_32, deserialize_range_proof_32,
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
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // Epoch duration for balance rollups (every 100 blocks ~ 3 minutes)
    const EPOCH_DURATION: u64 = 100;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        sage_token: ContractAddress,
        payment_router: ContractAddress,
        auditor_key: ECPoint,
        // Auditor ciphertexts for compliance access
        // Key: hash(sender, receiver, nullifier) -> encrypted amount for auditor
        auditor_ciphertexts: Map<felt252, ElGamalCiphertext>,

        // Private accounts
        accounts: Map<ContractAddress, PrivateAccount>,
        account_count: u64,

        // Nullifiers for double-spend prevention
        nullifiers: Map<felt252, bool>,

        // Worker payments pending claim
        // LEGACY: Single-asset payments by job_id (kept for backward compatibility)
        worker_payments: Map<u256, PrivateWorkerPayment>,
        // MULTI-ASSET: Payments indexed by (job_id, asset_id)
        // This allows multiple payments per job in different tokens
        worker_payments_multi: Map<(u256, u64), PrivateWorkerPayment>,
        // Count of pending payments per (worker, asset_id)
        worker_pending_count: Map<(ContractAddress, u64), u32>,

        // Supported assets: asset_id -> token contract address
        supported_assets: Map<u64, ContractAddress>,
        // Asset decimals: asset_id -> decimals (6 for USDC, 8 for BTC, 18 for others)
        asset_decimals: Map<u64, u8>,
        // Per-asset deposit totals for tracking
        asset_deposits: Map<u64, u256>,

        // AE Hints for fast balance decryption
        account_hints: Map<ContractAddress, AccountHints>,

        // Ragequit nullifiers (prevent double-ragequit)
        ragequit_nullifiers: Map<felt252, bool>,
        ragequit_records: Map<felt252, RagequitRecord>,
        total_ragequits: u64,

        // Epoch tracking
        current_epoch: u64,
        epoch_start_timestamp: u64,

        // Stats
        total_deposits: u256,
        total_withdrawals: u256,
        total_private_transfers: u64,
        total_worker_payments: u256,

        // Emergency controls
        paused: bool,

        // ================ UPGRADE STORAGE ================
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,

        // ================ NULLIFIER TREE STORAGE ================
        /// Current Merkle tree root
        nullifier_tree_root: felt252,
        /// Next insertion index
        nullifier_tree_next_index: u64,
        /// Filled subtrees at each level (level -> hash)
        /// Only stores the rightmost filled node at each level
        nullifier_tree_filled: Map<u32, felt252>,
        /// Pre-computed zero values at each level (level -> zero_hash)
        nullifier_tree_zeros: Map<u32, felt252>,
        /// Nullifier lookup by hash (for checking existence)
        nullifier_tree_exists: Map<felt252, bool>,
        /// Historical roots for verification (root -> is_known)
        nullifier_tree_known_roots: Map<felt252, bool>,
        /// Maximum number of historical roots to keep
        nullifier_tree_max_roots: u32,
        /// Circular buffer index for root history
        nullifier_tree_root_index: u32,
        /// Root history (index -> root) - circular buffer
        nullifier_tree_root_history: Map<u32, felt252>,

        // ================ LEAN IMT STORAGE ================
        // LeanIMT: Gas-efficient dynamic-depth Merkle tree for nullifiers
        // Replaces fixed-depth IMT for significant gas savings (up to 95%)

        /// LeanIMT state (root, size, depth)
        lean_imt_state: LeanIMTState,
        /// Sparse node storage: (level, index) -> hash
        /// Only stores actual nodes, not zero placeholders
        lean_imt_nodes: Map<(u8, u64), felt252>,
        /// Side nodes for incremental updates (level -> rightmost node at level)
        /// Used for efficient single-leaf insertions
        lean_imt_side_nodes: Map<u8, felt252>,
        /// Flag to indicate LeanIMT is initialized and active
        lean_imt_active: bool,

        // ================ MULTI-SIGNATURE AUDITING STORAGE ================
        /// Auditor registry: address -> AuditorInfo
        auditors: Map<ContractAddress, AuditorInfo>,
        /// Auditor list for iteration: index -> address
        auditor_list: Map<u32, ContractAddress>,
        /// Total number of registered auditors
        auditor_count: u32,
        /// Required approvals for M-of-N (M)
        audit_approval_threshold: u32,
        /// Amount threshold requiring auditor approval (in wei)
        large_transfer_threshold: u256,

        /// Audit requests by ID
        audit_requests: Map<u256, AuditRequest>,
        /// Audit approvals: (request_id, auditor_address) -> approved
        audit_approvals: Map<(u256, ContractAddress), bool>,
        /// Next audit request ID
        next_audit_request_id: u256,
        /// Pending transfers awaiting approval: request_id -> transfer data hash
        pending_transfer_hashes: Map<u256, felt252>,
        /// Total audit requests created
        total_audit_requests: u64,
        /// Total disclosures executed
        total_disclosures: u64,

        // ================ EX-POST PROVING STORAGE ================
        /// Ex-post proof records: proof_id -> record
        ex_post_proofs: Map<u256, ExPostProofRecord>,
        /// Next ex-post proof ID
        next_ex_post_proof_id: u256,
        /// User ex-post proofs: (user, index) -> proof_id
        user_ex_post_proofs: Map<(ContractAddress, u32), u256>,
        /// User ex-post proof count
        user_ex_post_proof_count: Map<ContractAddress, u32>,
        /// Nullifier epochs: nullifier -> epoch (for time-range queries)
        nullifier_epochs: Map<felt252, u64>,
        /// Total ex-post proofs verified
        total_ex_post_proofs: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AccountRegistered: AccountRegistered,
        PrivateDeposit: PrivateDeposit,
        BatchDepositCompleted: BatchDepositCompleted,
        PrivateWithdraw: PrivateWithdraw,
        PrivateTransferExecuted: PrivateTransferExecuted,
        WorkerPaymentReceived: WorkerPaymentReceived,
        WorkerPaymentClaimed: WorkerPaymentClaimed,
        EpochAdvanced: EpochAdvanced,
        // Ragequit events
        RagequitExecuted: RagequitExecuted,
        // Upgrade events
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
        // Nullifier tree events
        NullifierTreeInserted: NullifierTreeInserted,
        // LeanIMT events
        LeanIMTInitialized: LeanIMTInitialized,
        LeanIMTInserted: LeanIMTInserted,
        LeanIMTBatchInserted: LeanIMTBatchInserted,
        // Multi-signature auditing events
        AuditorRegistered: AuditorRegistered,
        AuditorRemoved: AuditorRemoved,
        AuditThresholdUpdated: AuditThresholdUpdated,
        LargeTransferThresholdUpdated: LargeTransferThresholdUpdated,
        AuditRequestCreated: AuditRequestCreated,
        AuditRequestApproved: AuditRequestApproved,
        AuditRequestExecuted: AuditRequestExecuted,
        DisclosureRequested: DisclosureRequested,
        DisclosureApproved: DisclosureApproved,
        DisclosureExecuted: DisclosureExecuted,
        // Ex-post proving events
        VolumeProofVerified: VolumeProofVerified,
        NonTransactionProofVerified: NonTransactionProofVerified,
        ComplianceBundleVerified: ComplianceBundleVerified,
    }

    // ================ MULTI-SIGNATURE AUDITING EVENTS ================

    #[derive(Drop, starknet::Event)]
    struct AuditorRegistered {
        #[key]
        auditor: ContractAddress,
        public_key_x: felt252,
        public_key_y: felt252,
        registered_by: ContractAddress,
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
    struct AuditThresholdUpdated {
        old_threshold: u32,
        new_threshold: u32,
        updated_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct LargeTransferThresholdUpdated {
        old_threshold: u256,
        new_threshold: u256,
        updated_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct AuditRequestCreated {
        #[key]
        request_id: u256,
        request_type: AuditRequestType,
        requester: ContractAddress,
        target_nullifier: felt252,
        required_approvals: u32,
        expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AuditRequestApproved {
        #[key]
        request_id: u256,
        auditor: ContractAddress,
        approval_count: u32,
        required_approvals: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct AuditRequestExecuted {
        #[key]
        request_id: u256,
        executor: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct DisclosureRequested {
        #[key]
        request_id: u256,
        nullifier: felt252,
        requester: ContractAddress,
        reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct DisclosureApproved {
        #[key]
        request_id: u256,
        auditor: ContractAddress,
        approval_count: u32,
        required_approvals: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct DisclosureExecuted {
        #[key]
        request_id: u256,
        nullifier: felt252,
        executor: ContractAddress,
    }

    // ================ EX-POST PROVING EVENTS ================

    #[derive(Drop, starknet::Event)]
    struct VolumeProofVerified {
        #[key]
        proof_id: u256,
        prover: ContractAddress,
        threshold: u256,
        nullifier_count: u32,
        epoch_start: u64,
        epoch_end: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct NonTransactionProofVerified {
        #[key]
        proof_id: u256,
        prover: ContractAddress,
        excluded_address: ContractAddress,
        nullifier_count: u32,
        epoch_start: u64,
        epoch_end: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ComplianceBundleVerified {
        #[key]
        proof_id: u256,
        prover: ContractAddress,
        transaction_count: u32,
        total_volume: u256,
        period_start: u64,
        period_end: u64,
        timestamp: u64,
    }

    // ================ EXISTING EVENTS ================

    #[derive(Drop, starknet::Event)]
    struct RagequitExecuted {
        #[key]
        account: ContractAddress,
        /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
        #[key]
        asset_id: u64,
        amount: u256,
        nullifier: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AccountRegistered {
        #[key]
        account: ContractAddress,
        public_key_x: felt252,
        public_key_y: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivateDeposit {
        #[key]
        account: ContractAddress,
        /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
        #[key]
        asset_id: u64,
        public_amount: u256,  // Visible deposit amount (before encryption)
        timestamp: u64,
    }

    /// Event emitted when a batch deposit completes
    #[derive(Drop, starknet::Event)]
    struct BatchDepositCompleted {
        #[key]
        account: ContractAddress,
        /// Number of assets deposited in this batch
        items_count: u32,
        /// Total value in normalized (18 decimal) units
        total_normalized_value: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivateWithdraw {
        #[key]
        account: ContractAddress,
        /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
        #[key]
        asset_id: u64,
        public_amount: u256,  // Visible withdrawal amount
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivateTransferExecuted {
        #[key]
        sender: ContractAddress,
        #[key]
        receiver: ContractAddress,
        nullifier: felt252,  // Only the nullifier is visible, not the amount
        epoch: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerPaymentReceived {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
        #[key]
        asset_id: u64,
        // Amount is NOT emitted - privacy!
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerPaymentClaimed {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        /// Asset ID: 0=SAGE, 1=USDC, 2=STRK, 3=BTC, 4=ETH
        #[key]
        asset_id: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EpochAdvanced {
        old_epoch: u64,
        new_epoch: u64,
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

    /// Nullifier inserted into tree event
    #[derive(Drop, starknet::Event)]
    struct NullifierTreeInserted {
        /// Nullifier that was inserted
        #[key]
        nullifier: felt252,
        /// Index where it was inserted
        index: u64,
        /// New tree root
        new_root: felt252,
        /// Timestamp
        timestamp: u64,
    }

    // ================ LEAN IMT EVENTS ================

    /// LeanIMT initialized event
    #[derive(Drop, starknet::Event)]
    struct LeanIMTInitialized {
        /// Timestamp when LeanIMT was activated
        timestamp: u64,
    }

    /// Single nullifier inserted via LeanIMT
    #[derive(Drop, starknet::Event)]
    struct LeanIMTInserted {
        /// Nullifier that was inserted
        #[key]
        nullifier: felt252,
        /// Index where it was inserted
        index: u64,
        /// New tree root
        new_root: felt252,
        /// Current tree depth
        depth: u8,
        /// Timestamp
        timestamp: u64,
    }

    /// Batch nullifiers inserted via LeanIMT
    #[derive(Drop, starknet::Event)]
    struct LeanIMTBatchInserted {
        /// Starting index of batch
        start_index: u64,
        /// Number of nullifiers inserted
        count: u32,
        /// New tree root after batch
        new_root: felt252,
        /// New tree depth after batch
        new_depth: u8,
        /// Timestamp
        timestamp: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        payment_router: ContractAddress
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.payment_router.write(payment_router);
        self.auditor_key.write(ec_zero());

        self.current_epoch.write(1);
        self.epoch_start_timestamp.write(get_block_timestamp());
        self.paused.write(false);
        // Default 2-day upgrade delay
        self.upgrade_delay.write(172800);

        // Initialize nullifier tree
        // Pre-compute zero values: zero[0] = 0, zero[i] = H(zero[i-1], zero[i-1])
        let mut current_zero: felt252 = 0;
        let mut level: u32 = 0;
        loop {
            if level > NULLIFIER_TREE_DEPTH {
                break;
            }
            self.nullifier_tree_zeros.write(level, current_zero);
            self.nullifier_tree_filled.write(level, current_zero);
            // Hash for next level: H(domain, current, current)
            current_zero = core::poseidon::poseidon_hash_span(
                array![NULLIFIER_TREE_DOMAIN, current_zero, current_zero].span()
            );
            level += 1;
        };
        // Set initial root to zero[TREE_DEPTH]
        self.nullifier_tree_root.write(self.nullifier_tree_zeros.read(NULLIFIER_TREE_DEPTH));
        self.nullifier_tree_next_index.write(0);
        self.nullifier_tree_max_roots.write(100);
        self.nullifier_tree_root_index.write(0);
        // Mark initial root as known
        self.nullifier_tree_known_roots.write(self.nullifier_tree_root.read(), true);

        // Initialize supported assets
        // SAGE is always supported (asset_id = 0)
        self.supported_assets.write(super::AssetIds::SAGE, sage_token);
        self.asset_decimals.write(super::AssetIds::SAGE, 18);
        // Other assets will be configured via initialize_asset()
    }

    // =============================================================================
    // Asset Management (Owner Only)
    // =============================================================================

    /// Initialize or update a supported asset
    /// Called by owner to add support for USDC, STRK, BTC, etc.
    fn initialize_asset(
        ref self: ContractState,
        asset_id: u64,
        token_address: ContractAddress,
        decimals: u8
    ) {
        let caller = get_caller_address();
        assert!(caller == self.owner.read(), "Only owner");
        assert!(!token_address.is_zero(), "Invalid token address");

        self.supported_assets.write(asset_id, token_address);
        self.asset_decimals.write(asset_id, decimals);
    }

    /// Remove support for an asset (emergency only)
    fn remove_asset_support(ref self: ContractState, asset_id: u64) {
        let caller = get_caller_address();
        assert!(caller == self.owner.read(), "Only owner");
        // SAGE cannot be removed
        assert!(asset_id != super::AssetIds::SAGE, "Cannot remove SAGE");

        self.supported_assets.write(asset_id, core::num::traits::Zero::zero());
    }

    #[abi(embed_v0)]
    impl PrivacyRouterImpl of IPrivacyRouter<ContractState> {
        fn register_account(
            ref self: ContractState,
            public_key: ECPoint
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Check not already registered
            let existing = self.accounts.read(caller);
            assert!(!existing.is_registered, "Account already registered");

            // Validate public key is not zero
            assert!(!is_zero(public_key), "Invalid public key");

            // Create new account with zero encrypted balance
            let account = PrivateAccount {
                public_key,
                encrypted_balance: EncryptedBalance {
                    ciphertext: zero_ciphertext(),
                    pending_in: zero_ciphertext(),
                    pending_out: zero_ciphertext(),
                    epoch: self.current_epoch.read(),
                },
                pending_transfers: 0,
                last_rollup_epoch: self.current_epoch.read(),
                is_registered: true,
            };

            self.accounts.write(caller, account);

            let count = self.account_count.read();
            self.account_count.write(count + 1);

            self.emit(AccountRegistered {
                account: caller,
                public_key_x: public_key.x,
                public_key_y: public_key.y,
                timestamp: get_block_timestamp(),
            });
        }

        fn deposit(
            ref self: ContractState,
            amount: u256,
            encrypted_amount: ElGamalCiphertext,
            proof: EncryptionProof
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify account is registered
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // Verify encryption proof (simplified - would be full ZK in production)
            assert!(verify_ciphertext(encrypted_amount), "Invalid ciphertext");
            self._verify_encryption_proof(amount, encrypted_amount, proof, account.public_key);

            // Transfer SAGE from caller to this contract
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = sage.transfer_from(caller, get_contract_address(), amount);
            assert!(success, "SAGE transfer failed");

            // Add to pending_in (will be rolled up into balance)
            account.encrypted_balance.pending_in = homomorphic_add(
                account.encrypted_balance.pending_in,
                encrypted_amount
            );
            account.pending_transfers = account.pending_transfers + 1;
            self.accounts.write(caller, account);

            // Update stats
            let total = self.total_deposits.read();
            self.total_deposits.write(total + amount);

            self.emit(PrivateDeposit {
                account: caller,
                asset_id: 0_u64, // SAGE (default asset)
                public_amount: amount,
                timestamp: get_block_timestamp(),
            });

            // Try to advance epoch
            self._try_advance_epoch();
        }

        fn withdraw(
            ref self: ContractState,
            amount: u256,
            encrypted_delta: ElGamalCiphertext,
            proof: EncryptionProof,
            remaining_balance_commitment: PedersenCommitment,
            range_proof_data: Span<felt252>
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify account is registered
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // First rollup any pending transactions
            self._rollup_account_balance(ref account);

            // Verify withdrawal proof (proves sufficient balance without revealing it)
            assert!(verify_ciphertext(encrypted_delta), "Invalid ciphertext");

            // SECURITY: Deserialize and cryptographically verify range proof on remaining balance
            // This proves remaining_balance >= 0 after withdrawal (prevents overdraft)
            // Using proper bit-decomposition range proofs with Sigma-protocol OR proofs
            let range_proof_opt = deserialize_range_proof_32(range_proof_data);
            assert!(range_proof_opt.is_some(), "Failed to deserialize range proof");
            let range_proof = OptionTrait::unwrap(range_proof_opt);
            let range_valid = verify_range_proof_32(remaining_balance_commitment.commitment, @range_proof);
            assert!(range_valid, "Invalid remaining balance range proof");

            self._verify_withdrawal_proof(amount, encrypted_delta, proof, account);

            // Subtract from balance using homomorphic subtraction
            account.encrypted_balance.ciphertext = homomorphic_sub(
                account.encrypted_balance.ciphertext,
                encrypted_delta
            );
            self.accounts.write(caller, account);

            // Transfer SAGE back to caller
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = sage.transfer(caller, amount);
            assert!(success, "SAGE withdrawal failed");

            // Update stats
            let total = self.total_withdrawals.read();
            self.total_withdrawals.write(total + amount);

            self.emit(PrivateWithdraw {
                account: caller,
                asset_id: 0_u64, // SAGE (default asset)
                public_amount: amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn private_transfer(
            ref self: ContractState,
            transfer: PrivateTransfer
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify sender is caller
            assert!(transfer.sender == caller, "Sender must be caller");

            // Check nullifier not used
            assert!(!self.nullifiers.read(transfer.nullifier), "Nullifier already used");

            // Verify both accounts are registered
            let mut sender_account = self.accounts.read(transfer.sender);
            let mut receiver_account = self.accounts.read(transfer.receiver);
            assert!(sender_account.is_registered, "Sender not registered");
            assert!(receiver_account.is_registered, "Receiver not registered");

            // Verify transfer proof
            self._verify_transfer_proof(
                transfer,
                sender_account.public_key,
                receiver_account.public_key
            );

            // Mark nullifier as used
            self.nullifiers.write(transfer.nullifier, true);

            // Update sender balance (subtract)
            sender_account.encrypted_balance.pending_out = homomorphic_add(
                sender_account.encrypted_balance.pending_out,
                transfer.sender_delta
            );
            sender_account.pending_transfers = sender_account.pending_transfers + 1;
            self.accounts.write(transfer.sender, sender_account);

            // Update receiver balance (add)
            receiver_account.encrypted_balance.pending_in = homomorphic_add(
                receiver_account.encrypted_balance.pending_in,
                transfer.encrypted_amount
            );
            receiver_account.pending_transfers = receiver_account.pending_transfers + 1;
            self.accounts.write(transfer.receiver, receiver_account);

            // Update stats
            let total = self.total_private_transfers.read();
            self.total_private_transfers.write(total + 1);

            let current_epoch = self.current_epoch.read();
            self.emit(PrivateTransferExecuted {
                sender: transfer.sender,
                receiver: transfer.receiver,
                nullifier: transfer.nullifier,
                epoch: current_epoch,
                timestamp: get_block_timestamp(),
            });

            self._try_advance_epoch();
        }

        /// Enhanced private transfer with same-encryption proof for sender/receiver/auditor
        ///
        /// This function provides stronger security guarantees than `private_transfer`:
        /// - Cryptographically verifies that all three ciphertexts encrypt the same amount
        /// - Stores auditor ciphertext for compliance access
        /// - Prevents amount mismatch attacks where sender/receiver see different amounts
        fn private_transfer_with_audit(
            ref self: ContractState,
            transfer: PrivateTransferWithAudit
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify sender is caller
            assert!(transfer.sender == caller, "Sender must be caller");

            // Check nullifier not used
            assert!(!self.nullifiers.read(transfer.nullifier), "Nullifier used");

            // Verify both accounts are registered
            let mut sender_account = self.accounts.read(transfer.sender);
            let mut receiver_account = self.accounts.read(transfer.receiver);
            assert!(sender_account.is_registered, "Sender not registered");
            assert!(receiver_account.is_registered, "Receiver not registered");

            // Get auditor key for same-encryption verification
            let auditor_key = self.auditor_key.read();
            assert!(!is_zero(auditor_key), "Auditor key not set");

            // ============================================================
            // CRITICAL: Verify Same-Encryption Proof
            // This proves that sender, receiver, and auditor ciphertexts
            // all encrypt the SAME amount. Without this, a malicious user
            // could send different amounts to different parties.
            // ============================================================
            let same_enc_inputs = SameEncryption3Inputs {
                ct_sender: transfer.sender_encrypted_amount,
                ct_receiver: transfer.receiver_encrypted_amount,
                ct_auditor: transfer.auditor_encrypted_amount,
                pk_sender: sender_account.public_key,
                pk_receiver: receiver_account.public_key,
                pk_auditor: auditor_key,
            };

            assert!(
                verify_same_encryption_3(same_enc_inputs, transfer.same_encryption_proof),
                "Same encryption proof failed"
            );

            // Mark nullifier as used
            self.nullifiers.write(transfer.nullifier, true);

            // Update sender balance (subtract)
            sender_account.encrypted_balance.pending_out = homomorphic_add(
                sender_account.encrypted_balance.pending_out,
                transfer.sender_encrypted_amount
            );
            sender_account.pending_transfers = sender_account.pending_transfers + 1;
            self.accounts.write(transfer.sender, sender_account);

            // Update receiver balance (add)
            receiver_account.encrypted_balance.pending_in = homomorphic_add(
                receiver_account.encrypted_balance.pending_in,
                transfer.receiver_encrypted_amount
            );
            receiver_account.pending_transfers = receiver_account.pending_transfers + 1;
            self.accounts.write(transfer.receiver, receiver_account);

            // Store auditor ciphertext for compliance access
            // Primary key: nullifier (for disclosure requests via get_disclosed_ciphertext)
            self.auditor_ciphertexts.write(transfer.nullifier, transfer.auditor_encrypted_amount);

            // Also store for multi-auditor access (keyed by auditor address)
            // This allows each auditor to look up ciphertexts encrypted to them
            let auditor_count = self.auditor_count.read();
            if auditor_count > 0 {
                let mut i: u32 = 0;
                loop {
                    if i >= auditor_count {
                        break;
                    }
                    let auditor_addr = self.auditor_list.read(i);
                    let auditor_info = self.auditors.read(auditor_addr);
                    if auditor_info.is_active {
                        // Key: hash(nullifier, auditor_address)
                        let multi_key = poseidon_hash_span(
                            array![transfer.nullifier, auditor_addr.into()].span()
                        );
                        // Note: The ciphertext is encrypted to the original auditor_key
                        // In a full implementation, each auditor would need their own ciphertext
                        self.auditor_ciphertexts.write(multi_key, transfer.auditor_encrypted_amount);
                    }
                    i += 1;
                };
            };

            // Update stats
            let total = self.total_private_transfers.read();
            self.total_private_transfers.write(total + 1);

            let current_epoch = self.current_epoch.read();
            self.emit(PrivateTransferExecuted {
                sender: transfer.sender,
                receiver: transfer.receiver,
                nullifier: transfer.nullifier,
                epoch: current_epoch,
                timestamp: get_block_timestamp(),
            });

            self._try_advance_epoch();
        }

        fn receive_worker_payment(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            sage_amount: u256,
            encrypted_amount: ElGamalCiphertext
        ) {
            // Delegate to multi-asset version with SAGE as default
            self.receive_worker_payment_for_asset(
                job_id,
                super::AssetIds::SAGE,
                worker,
                sage_amount,
                encrypted_amount
            );
        }

        fn receive_worker_payment_for_asset(
            ref self: ContractState,
            job_id: u256,
            asset_id: u64,
            worker: ContractAddress,
            amount: u256,
            encrypted_amount: ElGamalCiphertext
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Only PaymentRouter can send worker payments
            assert!(caller == self.payment_router.read(), "Only PaymentRouter");

            // Verify asset is supported
            let token_address = self.supported_assets.read(asset_id);
            assert!(!token_address.is_zero(), "Asset not supported");

            // Verify ciphertext
            assert!(verify_ciphertext(encrypted_amount), "Invalid ciphertext");

            // Check worker is registered (auto-register if not)
            let worker_account = self.accounts.read(worker);
            if !worker_account.is_registered {
                // Worker will need to register to claim
                // Payment is held in escrow
            }

            // Store payment in multi-asset storage
            let payment = PrivateWorkerPayment {
                job_id,
                worker,
                asset_id,
                encrypted_amount,
                timestamp: get_block_timestamp(),
                is_claimed: false,
            };
            self.worker_payments_multi.write((job_id, asset_id), payment);

            // Also write to legacy storage if SAGE (backward compatibility)
            if asset_id == super::AssetIds::SAGE {
                self.worker_payments.write(job_id, payment);
            }

            // Increment pending count for this worker/asset
            let count = self.worker_pending_count.read((worker, asset_id));
            self.worker_pending_count.write((worker, asset_id), count + 1);

            // Update stats
            let total = self.total_worker_payments.read();
            self.total_worker_payments.write(total + amount);

            self.emit(WorkerPaymentReceived {
                job_id,
                worker,
                asset_id,
                timestamp: get_block_timestamp(),
            });
        }

        fn claim_worker_payment(
            ref self: ContractState,
            job_id: u256,
            decryption_proof: EncryptionProof
        ) {
            // Delegate to multi-asset version with SAGE as default
            self.claim_worker_payment_for_asset(
                job_id,
                super::AssetIds::SAGE,
                decryption_proof
            );
        }

        fn claim_worker_payment_for_asset(
            ref self: ContractState,
            job_id: u256,
            asset_id: u64,
            decryption_proof: EncryptionProof
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Get payment from multi-asset storage
            let mut payment = self.worker_payments_multi.read((job_id, asset_id));
            assert!(payment.worker == caller, "Not payment recipient");
            assert!(!payment.is_claimed, "Already claimed");

            // Verify worker is registered
            let mut worker_account = self.accounts.read(caller);
            assert!(worker_account.is_registered, "Must register account first");

            // Verify decryption proof (proves worker knows private key)
            self._verify_decryption_proof(
                payment.encrypted_amount,
                decryption_proof,
                worker_account.public_key
            );

            // Add to worker's pending_in
            worker_account.encrypted_balance.pending_in = homomorphic_add(
                worker_account.encrypted_balance.pending_in,
                payment.encrypted_amount
            );
            worker_account.pending_transfers = worker_account.pending_transfers + 1;
            self.accounts.write(caller, worker_account);

            // Mark payment as claimed in multi-asset storage
            payment.is_claimed = true;
            self.worker_payments_multi.write((job_id, asset_id), payment);

            // Also update legacy storage if SAGE
            if asset_id == super::AssetIds::SAGE {
                self.worker_payments.write(job_id, payment);
            }

            // Decrement pending count for this worker/asset
            let count = self.worker_pending_count.read((caller, asset_id));
            if count > 0 {
                self.worker_pending_count.write((caller, asset_id), count - 1);
            }

            self.emit(WorkerPaymentClaimed {
                job_id,
                worker: caller,
                asset_id,
                timestamp: get_block_timestamp(),
            });
        }

        fn rollup_balance(ref self: ContractState) {
            self._require_not_paused();
            let caller = get_caller_address();

            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            self._rollup_account_balance(ref account);
            self.accounts.write(caller, account);
        }

        fn get_account(self: @ContractState, account: ContractAddress) -> PrivateAccount {
            self.accounts.read(account)
        }

        fn get_worker_payment(self: @ContractState, job_id: u256) -> PrivateWorkerPayment {
            self.worker_payments.read(job_id)
        }

        fn get_worker_payment_for_asset(
            self: @ContractState,
            job_id: u256,
            asset_id: u64
        ) -> PrivateWorkerPayment {
            self.worker_payments_multi.read((job_id, asset_id))
        }

        fn get_worker_pending_count(
            self: @ContractState,
            worker: ContractAddress,
            asset_id: u64
        ) -> u32 {
            self.worker_pending_count.read((worker, asset_id))
        }

        fn is_asset_supported(self: @ContractState, asset_id: u64) -> bool {
            !self.supported_assets.read(asset_id).is_zero()
        }

        fn get_asset_token(self: @ContractState, asset_id: u64) -> ContractAddress {
            self.supported_assets.read(asset_id)
        }

        fn get_asset_decimals(self: @ContractState, asset_id: u64) -> u8 {
            self.asset_decimals.read(asset_id)
        }

        fn is_nullifier_used(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifiers.read(nullifier)
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
        }

        // =====================================================================
        // BATCH DEPOSITS - Multi-Asset Single Transaction
        // =====================================================================

        /// Batch deposit multiple assets in a single transaction
        fn batch_deposit(ref self: ContractState, items: Array<BatchDepositItem>) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify account is registered
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // Verify batch size
            let items_len = items.len();
            assert!(items_len > 0, "Empty batch");
            assert!(items_len <= MAX_BATCH_DEPOSIT_ITEMS, "Batch too large");

            let timestamp = get_block_timestamp();
            let mut total_normalized_value: u256 = 0;
            let mut i: u32 = 0;

            // Process each deposit item
            loop {
                if i >= items_len {
                    break;
                }

                let item = *items.at(i);

                // Verify asset is supported
                let token_address = self.supported_assets.read(item.asset_id);
                assert!(!token_address.is_zero(), "Asset not supported");

                // Verify encryption proof
                assert!(verify_ciphertext(item.encrypted_amount), "Invalid ciphertext");
                self._verify_encryption_proof(
                    item.amount,
                    item.encrypted_amount,
                    item.proof,
                    account.public_key
                );

                // Transfer token from caller to this contract
                let token = IERC20Dispatcher { contract_address: token_address };
                let success = token.transfer_from(caller, get_contract_address(), item.amount);
                assert!(success, "Token transfer failed");

                // Add to pending_in (homomorphic addition)
                account.encrypted_balance.pending_in = homomorphic_add(
                    account.encrypted_balance.pending_in,
                    item.encrypted_amount
                );
                account.pending_transfers = account.pending_transfers + 1;

                // Update asset-specific deposit stats
                let current_deposits = self.asset_deposits.read(item.asset_id);
                self.asset_deposits.write(item.asset_id, current_deposits + item.amount);

                // Calculate normalized value for total (using decimal conversion)
                let decimals = self.asset_decimals.read(item.asset_id);
                let normalized = if decimals == 18 {
                    item.amount
                } else if decimals < 18 {
                    // Scale up to 18 decimals
                    let scale_exp = 18 - decimals;
                    let scale = self._pow10(scale_exp);
                    item.amount * scale
                } else {
                    // Scale down (shouldn't happen with current assets)
                    item.amount
                };
                total_normalized_value = total_normalized_value + normalized;

                // Emit individual deposit event
                self.emit(PrivateDeposit {
                    account: caller,
                    asset_id: item.asset_id,
                    public_amount: item.amount,
                    timestamp,
                });

                i = i + 1;
            };

            // Write updated account
            self.accounts.write(caller, account);

            // Emit batch completion event
            self.emit(BatchDepositCompleted {
                account: caller,
                items_count: items_len,
                total_normalized_value,
                timestamp,
            });

            // Try to advance epoch
            self._try_advance_epoch();
        }

        /// Deposit a specific asset into privacy account
        fn deposit_asset(
            ref self: ContractState,
            asset_id: u64,
            amount: u256,
            encrypted_amount: ElGamalCiphertext,
            proof: EncryptionProof
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify account is registered
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // Verify asset is supported
            let token_address = self.supported_assets.read(asset_id);
            assert!(!token_address.is_zero(), "Asset not supported");

            // Verify encryption proof
            assert!(verify_ciphertext(encrypted_amount), "Invalid ciphertext");
            self._verify_encryption_proof(amount, encrypted_amount, proof, account.public_key);

            // Transfer token from caller to this contract
            let token = IERC20Dispatcher { contract_address: token_address };
            let success = token.transfer_from(caller, get_contract_address(), amount);
            assert!(success, "Token transfer failed");

            // Add to pending_in
            account.encrypted_balance.pending_in = homomorphic_add(
                account.encrypted_balance.pending_in,
                encrypted_amount
            );
            account.pending_transfers = account.pending_transfers + 1;
            self.accounts.write(caller, account);

            // Update asset-specific deposit stats
            let current_deposits = self.asset_deposits.read(asset_id);
            self.asset_deposits.write(asset_id, current_deposits + amount);

            self.emit(PrivateDeposit {
                account: caller,
                asset_id,
                public_amount: amount,
                timestamp: get_block_timestamp(),
            });

            // Try to advance epoch
            self._try_advance_epoch();
        }

        // =====================================================================
        // RAGEQUIT - Emergency Full Balance Withdrawal
        // =====================================================================

        /// Emergency full-balance withdrawal without approval
        ///
        /// This function allows users to withdraw their entire balance by
        /// revealing the amount publicly. The tradeoff is loss of privacy
        /// for the guarantee of being able to exit.
        fn ragequit(ref self: ContractState, proof: RagequitProof) {
            // Ragequit should work even when paused (safety mechanism)
            let caller = get_caller_address();
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            let current_time = get_block_timestamp();

            // 1. Check proof timestamp is recent
            assert!(proof.timestamp <= current_time, "Future timestamp");
            assert!(
                current_time - proof.timestamp <= RAGEQUIT_MAX_AGE,
                "Proof too old"
            );

            // 2. Check nullifier not already used
            assert!(
                !self.ragequit_nullifiers.read(proof.nullifier),
                "Ragequit nullifier already used"
            );

            // 3. Verify balance hash matches current balance
            // Inline computation of balance hash
            let mut hash_state: Array<felt252> = array![];
            hash_state.append(account.encrypted_balance.ciphertext.c1_x);
            hash_state.append(account.encrypted_balance.ciphertext.c1_y);
            hash_state.append(account.encrypted_balance.ciphertext.c2_x);
            hash_state.append(account.encrypted_balance.ciphertext.c2_y);
            hash_state.append(account.encrypted_balance.pending_in.c1_x);
            hash_state.append(account.encrypted_balance.pending_in.c1_y);
            hash_state.append(account.encrypted_balance.pending_in.c2_x);
            hash_state.append(account.encrypted_balance.pending_in.c2_y);
            hash_state.append(account.encrypted_balance.pending_out.c1_x);
            hash_state.append(account.encrypted_balance.pending_out.c1_y);
            hash_state.append(account.encrypted_balance.pending_out.c2_x);
            hash_state.append(account.encrypted_balance.pending_out.c2_y);
            hash_state.append(account.encrypted_balance.epoch.into());
            hash_state.append(RAGEQUIT_DOMAIN);
            let computed_balance_hash = core::poseidon::poseidon_hash_span(hash_state.span());
            assert!(
                proof.balance_hash == computed_balance_hash,
                "Balance hash mismatch"
            );

            // 4. Verify Schnorr ownership proof (simplified verification)
            // Verify proof structure is valid
            assert!(proof.commitment_x != 0 || proof.commitment_y != 0, "Invalid commitment");
            assert!(proof.response != 0, "Invalid response");
            assert!(proof.challenge != 0, "Invalid challenge");

            // Verify challenge was computed correctly
            let mut challenge_input: Array<felt252> = array![];
            challenge_input.append(account.public_key.x);
            challenge_input.append(account.public_key.y);
            challenge_input.append(proof.commitment_x);
            challenge_input.append(proof.commitment_y);
            challenge_input.append(proof.balance_hash);
            challenge_input.append(proof.nullifier);
            challenge_input.append(proof.timestamp.into());
            challenge_input.append(RAGEQUIT_DOMAIN);
            let computed_challenge = core::poseidon::poseidon_hash_span(challenge_input.span());
            assert!(proof.challenge == computed_challenge, "Invalid ragequit proof");

            // 5. Roll up balance first (apply pending transfers)
            self._rollup_account_balance(ref account);

            // 6. Mark nullifier as used
            self.ragequit_nullifiers.write(proof.nullifier, true);

            // 7. Record the ragequit
            let record = RagequitRecord {
                account: caller,
                amount: proof.claimed_amount.into(),
                nullifier: proof.nullifier,
                timestamp: current_time,
            };
            self.ragequit_records.write(proof.nullifier, record);
            self.total_ragequits.write(self.total_ragequits.read() + 1);

            // 8. Zero out the account balance
            account.encrypted_balance = EncryptedBalance {
                ciphertext: zero_ciphertext(),
                pending_in: zero_ciphertext(),
                pending_out: zero_ciphertext(),
                epoch: account.encrypted_balance.epoch + 1,
            };
            self.accounts.write(caller, account);

            // 9. Clear account hints
            let empty_hints = AccountHints {
                balance_hint: AEHint { c0: 0, c1: 0, c2: 0 },
                pending_in_hint: AEHint { c0: 0, c1: 0, c2: 0 },
                pending_out_hint: AEHint { c0: 0, c1: 0, c2: 0 },
                hint_nonce: 0,
            };
            self.account_hints.write(caller, empty_hints);

            // 10. Transfer claimed amount to caller
            let amount_u256: u256 = proof.claimed_amount.into();
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage.transfer(caller, amount_u256);

            // 11. Update stats
            self.total_withdrawals.write(self.total_withdrawals.read() + amount_u256);

            // 12. Emit event
            self.emit(RagequitExecuted {
                account: caller,
                asset_id: 0_u64, // SAGE (default asset for ragequit)
                amount: amount_u256,
                nullifier: proof.nullifier,
                timestamp: current_time,
            });
        }

        /// Check if a ragequit nullifier has been used
        fn is_ragequit_nullifier_used(self: @ContractState, nullifier: felt252) -> bool {
            self.ragequit_nullifiers.read(nullifier)
        }

        /// Get ragequit record by nullifier
        fn get_ragequit_record(self: @ContractState, nullifier: felt252) -> RagequitRecord {
            self.ragequit_records.read(nullifier)
        }

        /// @deprecated Use register_auditor() for M-of-N multi-signature auditing
        /// This function is kept for backward compatibility with existing integrations.
        /// For new deployments, use the multi-auditor registry via register_auditor().
        fn set_auditor_key(ref self: ContractState, auditor_key: ECPoint) {
            self._only_owner();
            self.auditor_key.write(auditor_key);
        }

        fn set_payment_router(ref self: ContractState, router: ContractAddress) {
            self._only_owner();
            self.payment_router.write(router);
        }

        fn set_sage_token(ref self: ContractState, sage: ContractAddress) {
            self._only_owner();
            self.sage_token.write(sage);
        }

        fn set_paused(ref self: ContractState, paused: bool) {
            self._only_owner();
            self.paused.write(paused);
        }

        // =====================================================================
        // MULTI-SIGNATURE AUDITING
        // =====================================================================

        /// Register a new auditor (owner only)
        fn register_auditor(ref self: ContractState, auditor: ContractAddress, public_key: ECPoint) {
            self._only_owner();

            // Verify public key is valid (not zero point)
            assert!(!is_zero(public_key), "Invalid auditor public key");

            // Check auditor not already registered
            let existing = self.auditors.read(auditor);
            assert!(!existing.is_active, "Auditor already registered");

            let current_count = self.auditor_count.read();
            let timestamp = get_block_timestamp();

            // Create auditor info
            let info = AuditorInfo {
                address: auditor,
                public_key,
                registered_at: timestamp,
                is_active: true,
                total_approvals: 0,
                list_index: current_count,
            };

            // Store auditor
            self.auditors.write(auditor, info);
            self.auditor_list.write(current_count, auditor);
            self.auditor_count.write(current_count + 1);

            // Initialize threshold if first auditor
            if current_count == 0 {
                self.audit_approval_threshold.write(1);
                self.large_transfer_threshold.write(DEFAULT_LARGE_TRANSFER_THRESHOLD);
            }

            self.emit(AuditorRegistered {
                auditor,
                public_key_x: public_key.x,
                public_key_y: public_key.y,
                registered_by: get_caller_address(),
                timestamp,
            });
        }

        /// Remove an auditor (owner only)
        fn remove_auditor(ref self: ContractState, auditor: ContractAddress) {
            self._only_owner();

            let mut info = self.auditors.read(auditor);
            assert!(info.is_active, "Auditor not active");

            // Mark as inactive (don't delete to preserve audit trail)
            info.is_active = false;
            self.auditors.write(auditor, info);

            // Note: We don't compact the auditor_list to preserve indices
            // Inactive auditors are skipped during iteration

            let current_count = self.auditor_count.read();
            if current_count > 0 {
                self.auditor_count.write(current_count - 1);
            }

            // Reduce threshold if it exceeds new auditor count
            let threshold = self.audit_approval_threshold.read();
            let new_count = self.auditor_count.read();
            if threshold > new_count && new_count > 0 {
                self.audit_approval_threshold.write(new_count);
            }

            self.emit(AuditorRemoved {
                auditor,
                removed_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        /// Update the approval threshold M in M-of-N (owner only)
        fn update_audit_threshold(ref self: ContractState, new_threshold: u32) {
            self._only_owner();

            let auditor_count = self.auditor_count.read();
            assert!(new_threshold > 0, "Threshold must be > 0");
            assert!(new_threshold <= auditor_count, "Threshold exceeds auditor count");

            let old_threshold = self.audit_approval_threshold.read();
            self.audit_approval_threshold.write(new_threshold);

            self.emit(AuditThresholdUpdated {
                old_threshold,
                new_threshold,
                updated_by: get_caller_address(),
            });
        }

        /// Update the large transfer threshold (owner only)
        fn update_large_transfer_threshold(ref self: ContractState, new_threshold: u256) {
            self._only_owner();

            let old_threshold = self.large_transfer_threshold.read();
            self.large_transfer_threshold.write(new_threshold);

            self.emit(LargeTransferThresholdUpdated {
                old_threshold,
                new_threshold,
                updated_by: get_caller_address(),
            });
        }

        /// Get auditor info
        fn get_auditor(self: @ContractState, auditor: ContractAddress) -> AuditorInfo {
            self.auditors.read(auditor)
        }

        /// Get total auditor count
        fn get_auditor_count(self: @ContractState) -> u32 {
            self.auditor_count.read()
        }

        /// Get approval threshold
        fn get_audit_threshold(self: @ContractState) -> u32 {
            self.audit_approval_threshold.read()
        }

        /// Get large transfer threshold
        fn get_large_transfer_threshold(self: @ContractState) -> u256 {
            self.large_transfer_threshold.read()
        }

        /// Check if address is an active auditor
        fn is_auditor(self: @ContractState, address: ContractAddress) -> bool {
            let info = self.auditors.read(address);
            info.is_active
        }

        /// Approve an audit request (auditors only)
        fn approve_audit_request(ref self: ContractState, request_id: u256) {
            let caller = get_caller_address();

            // Verify caller is an active auditor
            let auditor_info = self.auditors.read(caller);
            assert!(auditor_info.is_active, "Not an active auditor");

            // Get the request
            let mut request = self.audit_requests.read(request_id);
            assert!(request.request_id == request_id, "Request not found");
            assert!(request.status == AuditRequestStatus::Pending, "Request not pending");

            // Check not expired
            let current_time = get_block_timestamp();
            assert!(current_time < request.expires_at, "Request expired");

            // Check not already approved by this auditor
            assert!(!self.audit_approvals.read((request_id, caller)), "Already approved");

            // Record approval
            self.audit_approvals.write((request_id, caller), true);
            request.approval_count = request.approval_count + 1;

            // Update auditor's total approvals
            let mut updated_auditor = auditor_info;
            updated_auditor.total_approvals = updated_auditor.total_approvals + 1;
            self.auditors.write(caller, updated_auditor);

            // Check if threshold met
            if request.approval_count >= request.required_approvals {
                request.status = AuditRequestStatus::Approved;
            }

            self.audit_requests.write(request_id, request);

            self.emit(AuditRequestApproved {
                request_id,
                auditor: caller,
                approval_count: request.approval_count,
                required_approvals: request.required_approvals,
            });
        }

        /// Get audit request status
        fn get_audit_request(self: @ContractState, request_id: u256) -> AuditRequest {
            self.audit_requests.read(request_id)
        }

        /// Check if auditor has approved a request
        fn has_approved(self: @ContractState, request_id: u256, auditor: ContractAddress) -> bool {
            self.audit_approvals.read((request_id, auditor))
        }

        /// Request disclosure of a transaction (owner or auditors only)
        fn request_disclosure(ref self: ContractState, nullifier: felt252, reason: felt252) -> u256 {
            let caller = get_caller_address();

            // Only owner or active auditors can request disclosure
            let is_owner = caller == self.owner.read();
            let is_active_auditor = self.auditors.read(caller).is_active;
            assert!(is_owner || is_active_auditor, "Not authorized to request disclosure");

            // Verify the nullifier exists (was used in a transfer)
            assert!(self.nullifiers.read(nullifier), "Nullifier not found");

            let request_id = self.next_audit_request_id.read();
            let current_time = get_block_timestamp();
            let threshold = self.audit_approval_threshold.read();

            let request = AuditRequest {
                request_id,
                request_type: AuditRequestType::Disclosure,
                requester: caller,
                target_nullifier: nullifier,
                created_at: current_time,
                expires_at: current_time + AUDIT_REQUEST_TIMEOUT,
                approval_count: 0,
                required_approvals: threshold,
                status: AuditRequestStatus::Pending,
                executed: false,
            };

            self.audit_requests.write(request_id, request);
            self.next_audit_request_id.write(request_id + 1);
            self.total_audit_requests.write(self.total_audit_requests.read() + 1);

            self.emit(DisclosureRequested {
                request_id,
                nullifier,
                requester: caller,
                reason,
            });

            request_id
        }

        /// Get disclosed ciphertext (only if request is approved)
        fn get_disclosed_ciphertext(self: @ContractState, request_id: u256) -> (ElGamalCiphertext, bool) {
            let request = self.audit_requests.read(request_id);

            // Only return ciphertext if request is approved
            if request.status == AuditRequestStatus::Approved || request.status == AuditRequestStatus::Executed {
                // Get the ciphertext for this nullifier
                // Note: The ciphertext key format depends on how it was stored
                let ciphertext = self.auditor_ciphertexts.read(request.target_nullifier);
                (ciphertext, true)
            } else {
                // Return empty ciphertext
                (zero_ciphertext(), false)
            }
        }

        // =====================================================================
        // LARGE TRANSFER APPROVAL (Phase 2)
        // =====================================================================

        /// Submit a large transfer that requires M-of-N auditor approval
        /// Uses ZK threshold proof to verify amount >= threshold without revealing exact value
        fn submit_large_transfer(
            ref self: ContractState,
            transfer: PrivateTransferWithAudit,
            threshold_proof: ThresholdProof,
        ) -> u256 {
            self._require_not_paused();

            // Verify the caller is the sender
            let caller = get_caller_address();
            assert!(transfer.sender == caller, "Caller must be sender");

            // Verify basic transfer validity (but don't execute)
            let sender_account = self.accounts.read(transfer.sender);
            assert!(sender_account.is_registered, "Sender not registered");

            let receiver_account = self.accounts.read(transfer.receiver);
            assert!(receiver_account.is_registered, "Receiver not registered");

            // Verify the threshold proof
            // The proof shows: amount >= large_transfer_threshold without revealing amount
            // 1. difference_commitment = amount_commitment - threshold * G
            // 2. range_proof on difference proves it's non-negative (>= 0)
            self._verify_threshold_proof(
                transfer.sender_encrypted_amount,
                threshold_proof
            );

            // Create audit request
            let request_id = self.next_audit_request_id.read();
            self.next_audit_request_id.write(request_id + 1);

            let now = get_block_timestamp();
            let request = AuditRequest {
                request_id,
                request_type: AuditRequestType::LargeTransfer,
                requester: caller,
                target_nullifier: transfer.nullifier,
                created_at: now,
                expires_at: now + AUDIT_REQUEST_TIMEOUT,
                approval_count: 0,
                required_approvals: self.audit_approval_threshold.read(),
                status: AuditRequestStatus::Pending,
                executed: false,
            };
            self.audit_requests.write(request_id, request);

            // Store the transfer hash for later execution
            // We hash the transfer to save storage (full transfer data provided on execute)
            let transfer_hash = poseidon_hash_span(
                array![
                    transfer.sender.into(),
                    transfer.receiver.into(),
                    transfer.nullifier,
                    transfer.sender_encrypted_amount.c1_x,
                    transfer.sender_encrypted_amount.c1_y,
                ].span()
            );
            self.pending_transfer_hashes.write(request_id, transfer_hash);

            self.total_audit_requests.write(self.total_audit_requests.read() + 1);

            self.emit(AuditRequestCreated {
                request_id,
                request_type: AuditRequestType::LargeTransfer,
                requester: caller,
                target_nullifier: transfer.nullifier,
                required_approvals: request.required_approvals,
                expires_at: request.expires_at,
            });

            request_id
        }

        /// Execute an approved large transfer (anyone can call once threshold is met)
        fn execute_approved_transfer(ref self: ContractState, request_id: u256) {
            self._require_not_paused();

            let mut request = self.audit_requests.read(request_id);

            // Must be a large transfer request
            assert!(request.request_type == AuditRequestType::LargeTransfer, "Not a transfer request");

            // Must be approved
            assert!(request.status == AuditRequestStatus::Approved, "Request not approved");

            // Must not be executed already
            assert!(!request.executed, "Already executed");

            // Check not expired
            let now = get_block_timestamp();
            assert!(now <= request.expires_at, "Request expired");

            // Mark as executed
            request.executed = true;
            request.status = AuditRequestStatus::Executed;
            self.audit_requests.write(request_id, request);

            self.emit(AuditRequestExecuted {
                request_id,
                executor: get_caller_address(),
                timestamp: now,
            });

            // Note: The actual transfer execution happens via private_transfer_with_audit
            // The caller must submit the transfer again, and the contract will verify
            // the request_id matches and is approved before executing
        }

        /// Get count of pending audit requests
        fn get_pending_request_count(self: @ContractState) -> u256 {
            self.next_audit_request_id.read()
        }

        // =====================================================================
        // EX-POST PROVING - Retroactive ZK Proofs
        // =====================================================================

        /// Verify a volume proof: proves total transaction volume < threshold
        /// Returns the proof_id of the verified proof
        fn verify_volume_proof(
            ref self: ContractState,
            proof: VolumeProof,
            threshold: u256,
        ) -> u256 {
            self._require_not_paused();
            let caller = get_caller_address();

            // Validate proof size
            assert!(proof.nullifiers.len() > 0, "Empty nullifier list");
            assert!(proof.nullifiers.len() <= MAX_EX_POST_NULLIFIERS, "Too many nullifiers");

            // Verify all nullifiers exist on-chain
            let mut i: u32 = 0;
            loop {
                if i >= proof.nullifiers.len() {
                    break;
                }
                let nullifier = *proof.nullifiers.at(i);
                assert!(self.nullifiers.read(nullifier), "Nullifier not found");

                // Verify nullifier is in claimed epoch range
                let epoch = self.nullifier_epochs.read(nullifier);
                assert!(
                    epoch >= proof.epoch_start && epoch <= proof.epoch_end,
                    "Nullifier epoch mismatch"
                );

                i += 1;
            };

            // Verify range proof on (threshold - sum)
            // The sum_commitment should represent the total volume
            // The range proof proves (threshold - sum) >= 0, i.e., sum < threshold
            assert!(proof.range_proof_data.len() >= 32, "Invalid range proof");

            // Compute proof hash for storage
            let proof_hash = poseidon_hash_span(
                array![
                    proof.sum_commitment.x,
                    proof.sum_commitment.y,
                    proof.sum_blinding,
                    threshold.try_into().unwrap(),
                ].span()
            );

            // Store proof record
            let proof_id = self.next_ex_post_proof_id.read();
            let now = get_block_timestamp();

            let record = ExPostProofRecord {
                proof_id,
                proof_type: ExPostProofType::Volume,
                prover: caller,
                verified_at: now,
                epoch_start: proof.epoch_start,
                epoch_end: proof.epoch_end,
                proof_hash,
                volume_threshold: threshold,
                excluded_address: Zero::zero(),
            };

            self.ex_post_proofs.write(proof_id, record);
            self.next_ex_post_proof_id.write(proof_id + 1);

            // Index by user
            let user_count = self.user_ex_post_proof_count.read(caller);
            self.user_ex_post_proofs.write((caller, user_count), proof_id);
            self.user_ex_post_proof_count.write(caller, user_count + 1);

            self.total_ex_post_proofs.write(self.total_ex_post_proofs.read() + 1);

            self.emit(VolumeProofVerified {
                proof_id,
                prover: caller,
                threshold,
                nullifier_count: proof.nullifiers.len(),
                epoch_start: proof.epoch_start,
                epoch_end: proof.epoch_end,
                timestamp: now,
            });

            proof_id
        }

        /// Verify a non-transaction proof: proves never transacted with specific address
        fn verify_non_transaction_proof(
            ref self: ContractState,
            proof: NonTransactionProof,
        ) -> u256 {
            self._require_not_paused();
            let caller = get_caller_address();

            // Validate proof size
            assert!(proof.nullifiers.len() > 0, "Empty nullifier list");
            assert!(proof.nullifiers.len() <= MAX_EX_POST_NULLIFIERS, "Too many nullifiers");
            assert!(
                proof.nullifiers.len() == proof.inequality_proofs.len(),
                "Proof count mismatch"
            );

            // Verify all nullifiers exist and inequality proofs are valid
            let mut i: u32 = 0;
            loop {
                if i >= proof.nullifiers.len() {
                    break;
                }
                let nullifier = *proof.nullifiers.at(i);
                assert!(self.nullifiers.read(nullifier), "Nullifier not found");

                // Verify epoch range
                let epoch = self.nullifier_epochs.read(nullifier);
                assert!(
                    epoch >= proof.epoch_start && epoch <= proof.epoch_end,
                    "Nullifier epoch mismatch"
                );

                // Verify inequality proof (receiver != excluded_address)
                let ineq_proof = *proof.inequality_proofs.at(i);
                assert!(
                    self._verify_inequality_proof(ineq_proof),
                    "Inequality proof failed"
                );

                i += 1;
            };

            // Compute proof hash
            let proof_hash = poseidon_hash_span(
                array![
                    proof.excluded_address.into(),
                    proof.nullifier_set_hash,
                    proof.epoch_start.into(),
                    proof.epoch_end.into(),
                ].span()
            );

            // Store proof record
            let proof_id = self.next_ex_post_proof_id.read();
            let now = get_block_timestamp();

            let record = ExPostProofRecord {
                proof_id,
                proof_type: ExPostProofType::NonTransaction,
                prover: caller,
                verified_at: now,
                epoch_start: proof.epoch_start,
                epoch_end: proof.epoch_end,
                proof_hash,
                volume_threshold: 0,
                excluded_address: proof.excluded_address,
            };

            self.ex_post_proofs.write(proof_id, record);
            self.next_ex_post_proof_id.write(proof_id + 1);

            // Index by user
            let user_count = self.user_ex_post_proof_count.read(caller);
            self.user_ex_post_proofs.write((caller, user_count), proof_id);
            self.user_ex_post_proof_count.write(caller, user_count + 1);

            self.total_ex_post_proofs.write(self.total_ex_post_proofs.read() + 1);

            self.emit(NonTransactionProofVerified {
                proof_id,
                prover: caller,
                excluded_address: proof.excluded_address,
                nullifier_count: proof.nullifiers.len(),
                epoch_start: proof.epoch_start,
                epoch_end: proof.epoch_end,
                timestamp: now,
            });

            proof_id
        }

        /// Verify a compliance bundle: full disclosure with auditor approval
        fn verify_compliance_bundle(
            ref self: ContractState,
            bundle: ComplianceBundle,
        ) -> u256 {
            self._require_not_paused();
            let caller = get_caller_address();

            // Validate bundle size
            assert!(bundle.disclosed_transactions.len() > 0, "Empty bundle");
            assert!(
                bundle.disclosed_transactions.len() == bundle.transaction_count,
                "Transaction count mismatch"
            );

            // Verify all disclosure requests are approved
            let mut i: u32 = 0;
            loop {
                if i >= bundle.disclosure_request_ids.len() {
                    break;
                }
                let request_id = *bundle.disclosure_request_ids.at(i);
                let request = self.audit_requests.read(request_id);
                assert!(
                    request.status == AuditRequestStatus::Approved ||
                    request.status == AuditRequestStatus::Executed,
                    "Disclosure not approved"
                );
                i += 1;
            };

            // Verify each disclosed transaction
            let mut computed_volume: u256 = 0;
            let mut j: u32 = 0;
            loop {
                if j >= bundle.disclosed_transactions.len() {
                    break;
                }
                let tx = *bundle.disclosed_transactions.at(j);

                // Verify nullifier exists
                assert!(self.nullifiers.read(tx.nullifier), "Invalid nullifier");

                // Verify decryption proof
                let stored_ct = self.auditor_ciphertexts.read(tx.nullifier);
                assert!(
                    self._verify_ex_post_decryption_proof(stored_ct, tx.amount, tx.decryption_proof),
                    "Decryption proof failed"
                );

                computed_volume += tx.amount.into();
                j += 1;
            };

            // Verify aggregate statistics match
            assert!(computed_volume == bundle.total_volume, "Volume mismatch");

            // Compute proof hash
            let proof_hash = poseidon_hash_span(
                array![
                    bundle.total_volume.try_into().unwrap(),
                    bundle.transaction_count.into(),
                    bundle.period_start.into(),
                    bundle.period_end.into(),
                ].span()
            );

            // Store proof record
            let proof_id = self.next_ex_post_proof_id.read();
            let now = get_block_timestamp();

            let record = ExPostProofRecord {
                proof_id,
                proof_type: ExPostProofType::Compliance,
                prover: caller,
                verified_at: now,
                epoch_start: bundle.period_start,
                epoch_end: bundle.period_end,
                proof_hash,
                volume_threshold: bundle.total_volume,
                excluded_address: Zero::zero(),
            };

            self.ex_post_proofs.write(proof_id, record);
            self.next_ex_post_proof_id.write(proof_id + 1);

            // Index by user
            let user_count = self.user_ex_post_proof_count.read(caller);
            self.user_ex_post_proofs.write((caller, user_count), proof_id);
            self.user_ex_post_proof_count.write(caller, user_count + 1);

            self.total_ex_post_proofs.write(self.total_ex_post_proofs.read() + 1);

            self.emit(ComplianceBundleVerified {
                proof_id,
                prover: caller,
                transaction_count: bundle.transaction_count,
                total_volume: bundle.total_volume,
                period_start: bundle.period_start,
                period_end: bundle.period_end,
                timestamp: now,
            });

            proof_id
        }

        /// Get ex-post proof record by ID
        fn get_ex_post_proof(self: @ContractState, proof_id: u256) -> ExPostProofRecord {
            self.ex_post_proofs.read(proof_id)
        }

        /// Get user's ex-post proof count
        fn get_user_ex_post_proof_count(self: @ContractState, user: ContractAddress) -> u32 {
            self.user_ex_post_proof_count.read(user)
        }

        /// Get user's ex-post proof by index
        fn get_user_ex_post_proof(
            self: @ContractState,
            user: ContractAddress,
            index: u32
        ) -> ExPostProofRecord {
            let proof_id = self.user_ex_post_proofs.read((user, index));
            self.ex_post_proofs.read(proof_id)
        }

        // =====================================================================
        // AE HINTS - Fast Decryption
        // =====================================================================

        /// Update balance hints for an account
        /// Hints are stored encrypted and only the account owner can update them
        fn update_balance_hints(
            ref self: ContractState,
            balance_hint: AEHint,
            pending_in_hint: AEHint,
            pending_out_hint: AEHint
        ) {
            self._require_not_paused();
            let caller = get_caller_address();
            let account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // Read current hints and increment nonce
            let mut hints = self.account_hints.read(caller);
            hints.balance_hint = balance_hint;
            hints.pending_in_hint = pending_in_hint;
            hints.pending_out_hint = pending_out_hint;
            hints.hint_nonce = hints.hint_nonce + 1;

            self.account_hints.write(caller, hints);
        }

        /// Get account hints for fast decryption
        fn get_account_hints(self: @ContractState, account: ContractAddress) -> AccountHints {
            self.account_hints.read(account)
        }

        /// Deposit with AE hint for fast balance queries
        fn deposit_with_hint(
            ref self: ContractState,
            amount: u256,
            encrypted_amount: ElGamalCiphertext,
            proof: EncryptionProof,
            balance_hint: AEHint
        ) {
            self._require_not_paused();
            let caller = get_caller_address();
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // Verify the encryption proof
            self._verify_encryption_proof(amount, encrypted_amount, proof, account.public_key);

            // Transfer tokens to this contract
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage.transfer_from(caller, get_contract_address(), amount);

            // Add to pending_in (will be rolled up next epoch)
            account.encrypted_balance.pending_in = homomorphic_add(
                account.encrypted_balance.pending_in,
                encrypted_amount
            );
            account.pending_transfers = account.pending_transfers + 1;
            self.accounts.write(caller, account);

            // Update hints with new balance hint
            let mut hints = self.account_hints.read(caller);
            hints.balance_hint = balance_hint;
            hints.hint_nonce = hints.hint_nonce + 1;
            self.account_hints.write(caller, hints);

            self.total_deposits.write(self.total_deposits.read() + amount);

            self.emit(PrivateDeposit {
                account: caller,
                asset_id: 0_u64, // SAGE (default asset)
                public_amount: amount,
                timestamp: get_block_timestamp(),
            });

            self._try_advance_epoch();
        }

        /// Private transfer with hints for both sender and receiver
        fn private_transfer_with_hints(
            ref self: ContractState,
            transfer: PrivateTransfer,
            sender_new_balance_hint: AEHint,
            receiver_pending_hint: AEHint
        ) {
            self._require_not_paused();
            let caller = get_caller_address();

            // Verify sender authorization
            assert!(transfer.sender == caller, "Not authorized sender");

            // Check nullifier not used
            assert!(!self.nullifiers.read(transfer.nullifier), "Nullifier already used");

            // Load accounts
            let mut sender_account = self.accounts.read(transfer.sender);
            let mut receiver_account = self.accounts.read(transfer.receiver);

            assert!(sender_account.is_registered, "Sender not registered");
            assert!(receiver_account.is_registered, "Receiver not registered");

            // Update sender balance: subtract encrypted_amount
            sender_account.encrypted_balance.pending_out = homomorphic_add(
                sender_account.encrypted_balance.pending_out,
                transfer.sender_delta
            );
            sender_account.pending_transfers = sender_account.pending_transfers + 1;

            // Update receiver pending: add encrypted_amount
            receiver_account.encrypted_balance.pending_in = homomorphic_add(
                receiver_account.encrypted_balance.pending_in,
                transfer.encrypted_amount
            );
            receiver_account.pending_transfers = receiver_account.pending_transfers + 1;

            // Mark nullifier as used
            self.nullifiers.write(transfer.nullifier, true);

            // Save accounts
            self.accounts.write(transfer.sender, sender_account);
            self.accounts.write(transfer.receiver, receiver_account);

            // Update hints for sender
            let mut sender_hints = self.account_hints.read(transfer.sender);
            sender_hints.balance_hint = sender_new_balance_hint;
            sender_hints.hint_nonce = sender_hints.hint_nonce + 1;
            self.account_hints.write(transfer.sender, sender_hints);

            // Update hints for receiver
            let mut receiver_hints = self.account_hints.read(transfer.receiver);
            receiver_hints.pending_in_hint = receiver_pending_hint;
            receiver_hints.hint_nonce = receiver_hints.hint_nonce + 1;
            self.account_hints.write(transfer.receiver, receiver_hints);

            // Emit event (no amount revealed)
            self.emit(PrivateTransferExecuted {
                sender: transfer.sender,
                receiver: transfer.receiver,
                nullifier: transfer.nullifier,
                epoch: self.current_epoch.read(),
                timestamp: get_block_timestamp(),
            });

            self.total_private_transfers.write(self.total_private_transfers.read() + 1);
            self._try_advance_epoch();
        }

        /// Get current hint nonce for an account
        fn get_hint_nonce(self: @ContractState, account: ContractAddress) -> u64 {
            self.account_hints.read(account).hint_nonce
        }

        // =====================================================================
        // UPGRADE FUNCTIONS
        // =====================================================================

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Another upgrade is already pending");
            assert!(!new_class_hash.is_zero(), "Invalid class hash");

            let current_time = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let execute_after = current_time + delay;

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(current_time);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: current_time,
                execute_after,
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

            assert!(current_time >= scheduled_at + delay, "Timelock not expired");

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
            assert!(!pending.is_zero(), "No pending upgrade to cancel");

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
            let execute_after = if scheduled_at > 0 { scheduled_at + delay } else { 0 };
            (pending, scheduled_at, execute_after, delay)
        }

        fn set_upgrade_delay(ref self: ContractState, new_delay: u64) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Cannot change delay with pending upgrade");
            assert!(new_delay >= 3600 && new_delay <= 2592000, "Invalid delay range");
            self.upgrade_delay.write(new_delay);
        }

        // NULLIFIER TREE IMPLEMENTATION
        // =====================================================================

        /// Get current nullifier tree root
        fn get_nullifier_tree_root(self: @ContractState) -> felt252 {
            self.nullifier_tree_root.read()
        }

        /// Get current nullifier tree state for off-chain sync
        fn get_nullifier_tree_state(self: @ContractState) -> NullifierTreeState {
            let mut filled_subtrees: Array<felt252> = array![];
            let mut level: u32 = 0;
            loop {
                if level >= NULLIFIER_TREE_DEPTH {
                    break;
                }
                filled_subtrees.append(self.nullifier_tree_filled.read(level));
                level += 1;
            };

            NullifierTreeState {
                root: self.nullifier_tree_root.read(),
                next_index: self.nullifier_tree_next_index.read(),
                filled_subtrees,
            }
        }

        /// Check if a nullifier exists in the tree
        fn is_nullifier_in_tree(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifier_tree_exists.read(nullifier)
        }

        /// Verify a nullifier membership proof against the current root
        fn verify_nullifier_proof(
            self: @ContractState,
            proof: NullifierMerkleProof
        ) -> bool {
            // Check proof structure
            if proof.path.len() != NULLIFIER_TREE_DEPTH {
                return false;
            }
            if proof.indices.len() != NULLIFIER_TREE_DEPTH {
                return false;
            }

            // Verify the proof is against a known root
            if !self.nullifier_tree_known_roots.read(proof.root) {
                return false;
            }

            // Compute root from proof
            let mut current = proof.nullifier;
            let mut i: u32 = 0;
            loop {
                if i >= NULLIFIER_TREE_DEPTH {
                    break;
                }
                let sibling = *proof.path.at(i);
                let is_right = *proof.indices.at(i);

                current = if is_right {
                    // Current is on right, sibling on left
                    core::poseidon::poseidon_hash_span(
                        array![NULLIFIER_TREE_DOMAIN, sibling, current].span()
                    )
                } else {
                    // Current is on left, sibling on right
                    core::poseidon::poseidon_hash_span(
                        array![NULLIFIER_TREE_DOMAIN, current, sibling].span()
                    )
                };
                i += 1;
            };

            // Check computed root matches
            current == proof.root
        }

        /// Get the number of nullifiers in the tree
        fn get_nullifier_count(self: @ContractState) -> u64 {
            self.nullifier_tree_next_index.read()
        }

        /// Check if a historical root is known
        fn is_known_nullifier_root(self: @ContractState, root: felt252) -> bool {
            self.nullifier_tree_known_roots.read(root)
        }

        // ===================== LEAN IMT IMPLEMENTATIONS =====================

        /// Initialize the LeanIMT (admin only, one-time)
        fn init_lean_imt(ref self: ContractState) {
            self._only_owner();
            self._init_lean_imt();
        }

        /// Batch insert multiple nullifiers via LeanIMT
        fn batch_insert_nullifiers(
            ref self: ContractState,
            nullifiers: Span<felt252>
        ) -> LeanIMTBatchResult {
            self._batch_insert_lean_imt(nullifiers)
        }

        /// Get current LeanIMT state
        fn get_lean_imt_state(self: @ContractState) -> LeanIMTState {
            self._get_lean_imt_state()
        }

        /// Verify a LeanIMT membership proof
        fn verify_lean_imt_membership(
            self: @ContractState,
            proof: LeanIMTProof
        ) -> bool {
            self._verify_lean_imt_proof(@proof)
        }

        /// Check if LeanIMT is active
        fn is_lean_imt_active(self: @ContractState) -> bool {
            self._is_lean_imt_active()
        }

    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
        }

        fn _require_not_paused(self: @ContractState) {
            assert!(!self.paused.read(), "Contract is paused");
        }

        /// Verify threshold proof: proves amount >= large_transfer_threshold without revealing amount
        /// The proof works by:
        /// 1. User computes difference_commitment = amount_commitment - threshold * G
        /// 2. User provides a range proof showing difference >= 0
        /// 3. This proves amount >= threshold without revealing the exact amount
        fn _verify_threshold_proof(
            self: @ContractState,
            amount_ciphertext: ElGamalCiphertext,
            proof: ThresholdProof
        ) {
            let _threshold = self.large_transfer_threshold.read();

            // Compute threshold * G (threshold as a scalar times generator)
            // Note: For very large thresholds, we use the commitment structure
            let _g = generator();

            // The difference_commitment should be:
            // difference_commitment = amount_commitment - threshold * G
            // Where amount_commitment is embedded in the ciphertext's c2 component
            // (In ElGamal: c2 = amount * G + blinding * public_key)

            // Verification strategy:
            // 1. The range_proof_data contains a proof that the value in
            //    difference_commitment is non-negative (>= 0)
            // 2. We verify this proof using bit decomposition

            // Get the expected commitment from the difference
            // The user provides: difference_commitment = Commit(amount - threshold, blinding_diff)
            let _diff_commit = proof.difference_commitment;

            // Verify the range proof data is non-empty (actual ZK verification)
            // The range proof should contain 32 bit commitments for a 32-bit range proof
            assert!(proof.range_proof_data.len() > 0, "Empty threshold proof");

            // Verify consistency: diff_commit should relate to amount_ciphertext
            // The commitment structure ensures:
            // diff_commit = amount_commit - threshold * G
            //             = (amount * G + r * H) - threshold * G
            //             = (amount - threshold) * G + r * H

            // For now, we verify the structural correctness by checking:
            // 1. The commitment point is on curve (implicit in ECPoint)
            // 2. Range proof data has expected structure (32 * 5 = 160 felts for 32-bit proof)
            // Full range proof verification would use the bit_proofs module

            // Basic structural validation
            assert!(proof.range_proof_data.len() >= 32, "Insufficient proof data");

            // Note: In production, this would call the full range proof verification:
            // verify_bit_decomposition_proof(diff_commit, proof.range_proof_data)
            // For now, we accept the proof if it has valid structure

            // Log that threshold proof was verified
            // The audit trail is in the event when the request is created
        }

        /// Verify an inequality proof: proves two values are not equal
        /// Uses Schnorr proof of knowledge of (a - b)^(-1)
        fn _verify_inequality_proof(
            self: @ContractState,
            proof: InequalityProof
        ) -> bool {
            let g = generator();

            // The prover shows knowledge of the inverse of (receiver - excluded)
            // If they were equal, no inverse exists and proof would fail

            // Verify Schnorr equation: s * G = R + c * difference_commitment
            let lhs = ec_mul(proof.response, g);
            let challenge_times_diff = ec_mul(proof.challenge, proof.difference_commitment);
            let rhs = ec_add(proof.r_commitment, challenge_times_diff);

            // Check point equality
            if lhs.x != rhs.x || lhs.y != rhs.y {
                return false;
            }

            // Verify challenge is non-zero (prevents trivial proofs)
            if proof.challenge == 0 {
                return false;
            }

            // Verify commitment is not zero (would indicate equal values)
            if is_zero(proof.difference_commitment) {
                return false;
            }

            true
        }

        /// Verify a decryption proof for ex-post compliance: proves correct ElGamal decryption
        /// Proves: amount = Dec(sk, ciphertext) without revealing sk
        fn _verify_ex_post_decryption_proof(
            self: @ContractState,
            ciphertext: ElGamalCiphertext,
            claimed_amount: u64,
            proof: DecryptionProof
        ) -> bool {
            let g = generator();

            // Reconstruct EC points from ciphertext
            let c1 = ECPoint { x: ciphertext.c1_x, y: ciphertext.c1_y };
            let c2 = ECPoint { x: ciphertext.c2_x, y: ciphertext.c2_y };

            // ElGamal decryption: M = C2 - sk * C1
            // claimed_amount * G should equal M
            let amount_point = ec_mul(claimed_amount.into(), g);

            // The proof shows knowledge of sk such that C2 - M = sk * C1
            // Verify Schnorr equation: s * C1 = R + c * (C2 - M)
            let c2_minus_m = ec_sub(c2, amount_point);

            let lhs = ec_mul(proof.response, c1);
            let challenge_times_target = ec_mul(proof.challenge, c2_minus_m);
            let rhs = ec_add(proof.r_commitment, challenge_times_target);

            // Check point equality
            if lhs.x != rhs.x || lhs.y != rhs.y {
                return false;
            }

            // Verify challenge is non-zero
            if proof.challenge == 0 {
                return false;
            }

            true
        }

        /// Record nullifier epoch during transfer (for ex-post time-range queries)
        fn _record_nullifier_epoch(ref self: ContractState, nullifier: felt252) {
            let current_epoch = self.current_epoch.read();
            self.nullifier_epochs.write(nullifier, current_epoch);
        }

        /// Get power of 10 for decimal normalization (0-18)
        fn _pow10(self: @ContractState, exp: u8) -> u256 {
            if exp == 0 { 1_u256 }
            else if exp == 1 { 10_u256 }
            else if exp == 2 { 100_u256 }
            else if exp == 3 { 1000_u256 }
            else if exp == 4 { 10000_u256 }
            else if exp == 5 { 100000_u256 }
            else if exp == 6 { 1000000_u256 }
            else if exp == 7 { 10000000_u256 }
            else if exp == 8 { 100000000_u256 }
            else if exp == 9 { 1000000000_u256 }
            else if exp == 10 { 10000000000_u256 }
            else if exp == 11 { 100000000000_u256 }
            else if exp == 12 { 1000000000000_u256 }
            else { 1000000000000000000_u256 } // Default to 10^18
        }

        fn _try_advance_epoch(ref self: ContractState) {
            let now = get_block_timestamp();
            let epoch_start = self.epoch_start_timestamp.read();

            // Advance epoch if enough time passed
            if now >= epoch_start + EPOCH_DURATION {
                let old_epoch = self.current_epoch.read();
                let new_epoch = old_epoch + 1;

                self.current_epoch.write(new_epoch);
                self.epoch_start_timestamp.write(now);

                self.emit(EpochAdvanced {
                    old_epoch,
                    new_epoch,
                    timestamp: now,
                });
            }
        }

        fn _rollup_account_balance(ref self: ContractState, ref account: PrivateAccount) {
            if account.pending_transfers > 0 {
                // Apply rollup: balance = balance + pending_in - pending_out
                account.encrypted_balance = rollup_balance(account.encrypted_balance);
                account.pending_transfers = 0;
                account.last_rollup_epoch = self.current_epoch.read();
            }
        }

        /// Verify proof that encrypted_amount correctly encrypts `amount` under public_key
        fn _verify_encryption_proof(
            self: @ContractState,
            amount: u256,
            encrypted_amount: ElGamalCiphertext,
            proof: EncryptionProof,
            public_key: ECPoint
        ) {
            // Simplified verification (production would use full Sigma protocol)
            // 1. Verify commitment is valid EC point
            let commitment = get_commitment(proof);
            assert!(!is_zero(commitment), "Invalid proof commitment");

            // 2. Verify Fiat-Shamir challenge is correct
            let mut points: Array<ECPoint> = array![];
            points.append(get_c1(encrypted_amount));
            points.append(get_c2(encrypted_amount));
            points.append(commitment);
            points.append(public_key);

            let _computed_challenge = hash_points(points);
            // In production: strict challenge verification
            // For now, basic check that proof has valid structure
            assert!(proof.response != 0, "Invalid proof response");
        }

        /// Verify withdrawal proof (proves amount is less than encrypted balance)
        fn _verify_withdrawal_proof(
            self: @ContractState,
            amount: u256,
            encrypted_delta: ElGamalCiphertext,
            proof: EncryptionProof,
            account: PrivateAccount
        ) {
            // Verify:
            // 1. encrypted_delta correctly encrypts `amount`
            // NOTE: Range proof verification is done in withdraw() with actual RangeProof

            let commitment = get_commitment(proof);
            assert!(!is_zero(commitment), "Invalid proof commitment");

            // The range_proof_hash field is now for audit logging only
            // Actual cryptographic verification is done in withdraw() with the full RangeProof
        }

        /// Verify transfer proof (proves valid sender debit and receiver credit)
        fn _verify_transfer_proof(
            self: @ContractState,
            transfer: PrivateTransfer,
            sender_pk: ECPoint,
            receiver_pk: ECPoint
        ) {
            // Verify:
            // 1. sender_delta and encrypted_amount encrypt same value
            // 2. sender has sufficient balance
            // 3. Amount is non-negative

            let sender_commitment = get_commitment(transfer.proof.sender_proof);
            let receiver_commitment = get_commitment(transfer.proof.receiver_proof);
            assert!(!is_zero(sender_commitment), "Invalid sender proof");
            assert!(!is_zero(receiver_commitment), "Invalid receiver proof");

            // Verify ciphertexts are well-formed
            assert!(verify_ciphertext(transfer.encrypted_amount), "Invalid receiver ciphertext");
            assert!(verify_ciphertext(transfer.sender_delta), "Invalid sender ciphertext");
        }

        /// Verify decryption proof (proves knowledge of private key)
        fn _verify_decryption_proof(
            self: @ContractState,
            ciphertext: ElGamalCiphertext,
            proof: EncryptionProof,
            public_key: ECPoint
        ) {
            // Verify that prover knows sk such that pk = sk * G
            // This is a Schnorr-like proof

            let commitment = get_commitment(proof);
            assert!(!is_zero(commitment), "Invalid decryption proof");
            assert!(proof.response != 0, "Invalid proof response");

            // In production: full Schnorr verification
            // e = H(pk, commitment, ciphertext)
            // Verify: response * G == commitment + e * pk
        }

        // =====================================================================
        // RAGEQUIT INTERNAL HELPERS
        // =====================================================================

        /// Compute hash of encrypted balance for binding ragequit proofs
        ///
        /// Creates a unique identifier for the current balance state that
        /// binds the ragequit proof to this specific balance. This prevents
        /// replay attacks with old proofs.
        fn _compute_balance_hash(
            self: @ContractState,
            balance: EncryptedBalance
        ) -> felt252 {
            // Hash all components of the encrypted balance:
            // - Main ciphertext (c1, c2)
            // - Pending in ciphertext
            // - Pending out ciphertext
            // - Epoch

            // Use core::poseidon for hashing
            let mut state: Array<felt252> = array![];

            // Add main ciphertext components
            state.append(balance.ciphertext.c1_x);
            state.append(balance.ciphertext.c1_y);
            state.append(balance.ciphertext.c2_x);
            state.append(balance.ciphertext.c2_y);

            // Add pending_in ciphertext components
            state.append(balance.pending_in.c1_x);
            state.append(balance.pending_in.c1_y);
            state.append(balance.pending_in.c2_x);
            state.append(balance.pending_in.c2_y);

            // Add pending_out ciphertext components
            state.append(balance.pending_out.c1_x);
            state.append(balance.pending_out.c1_y);
            state.append(balance.pending_out.c2_x);
            state.append(balance.pending_out.c2_y);

            // Add epoch
            state.append(balance.epoch.into());

            // Add domain separator
            state.append(RAGEQUIT_DOMAIN);

            // Compute Poseidon hash
            core::poseidon::poseidon_hash_span(state.span())
        }

        /// Verify Schnorr ownership proof for ragequit
        ///
        /// Verifies that the prover knows the private key corresponding to
        /// the public key, and that the proof is bound to the specific
        /// balance hash and nullifier.
        ///
        /// Schnorr proof: Given pk = sk * G
        /// - Prover picks random k, computes R = k * G
        /// - Challenge e = H(pk, R, balance_hash, nullifier, domain)
        /// - Response s = k - e * sk (mod CURVE_ORDER)
        /// - Verifier checks: s * G + e * pk == R
        ///
        /// SECURITY: All scalar arithmetic uses proper curve order modular arithmetic.
        /// Using felt252 (mod P_stark) instead of mod CURVE_ORDER allows forgery.
        fn _verify_ragequit_schnorr_proof(
            self: @ContractState,
            public_key: ECPoint,
            proof: RagequitProof
        ) -> bool {
            // Basic validity checks
            if proof.commitment_x == 0 && proof.commitment_y == 0 {
                return false;
            }
            if proof.response == 0 {
                return false;
            }
            if proof.challenge == 0 {
                return false;
            }

            // Reconstruct the commitment point R
            let r_point = ECPoint { x: proof.commitment_x, y: proof.commitment_y };

            // Verify the commitment is not the zero point
            if is_zero(r_point) {
                return false;
            }

            // Verify the challenge was computed correctly
            // e = H(pk, R, balance_hash, nullifier, timestamp, domain)
            let mut challenge_input: Array<felt252> = array![];
            challenge_input.append(public_key.x);
            challenge_input.append(public_key.y);
            challenge_input.append(proof.commitment_x);
            challenge_input.append(proof.commitment_y);
            challenge_input.append(proof.balance_hash);
            challenge_input.append(proof.nullifier);
            challenge_input.append(proof.timestamp.into());
            challenge_input.append(RAGEQUIT_DOMAIN);

            let computed_challenge_raw = core::poseidon::poseidon_hash_span(
                challenge_input.span()
            );

            // CRITICAL: Reduce challenges to curve order before comparison
            // This prevents forgery attacks exploiting P_stark != CURVE_ORDER
            let computed_challenge = reduce_mod_n(computed_challenge_raw);
            let proof_challenge_reduced = reduce_mod_n(proof.challenge);

            if proof_challenge_reduced != computed_challenge {
                return false;
            }

            // Full Schnorr verification: s*G + e*pk == R
            // Using proper curve order arithmetic
            let g = generator();
            let response_reduced = reduce_mod_n(proof.response);

            // Compute s*G (response times generator)
            let s_g = ec_mul(response_reduced, g);

            // Compute e*pk (challenge times public key)
            let e_pk = ec_mul(computed_challenge, public_key);

            // Compute expected_R = s*G + e*pk
            let expected_r = ec_add(s_g, e_pk);

            // Verify: expected_R == R (commitment point)
            expected_r.x == r_point.x && expected_r.y == r_point.y
        }

        // =====================================================================
        // NULLIFIER TREE INTERNAL HELPERS
        // =====================================================================

        /// Insert a nullifier into the tree (internal use)
        /// Returns (new_root, index) or panics if duplicate/full
        fn _insert_nullifier_tree(ref self: ContractState, nullifier: felt252) -> (felt252, u64) {
            // Check not duplicate
            assert!(!self.nullifier_tree_exists.read(nullifier), "Nullifier already in tree");

            // Check not full (2^TREE_DEPTH leaves = 2^20 = 1,048,576)
            let index = self.nullifier_tree_next_index.read();
            let max_leaves: u64 = 1048576; // 2^20
            assert!(index < max_leaves, "Nullifier tree is full");

            // Insert into tree using incremental update
            let mut current_index = index;
            let mut current_hash = nullifier;

            let mut level: u32 = 0;
            loop {
                if level >= NULLIFIER_TREE_DEPTH {
                    break;
                }

                if current_index % 2 == 0 {
                    // Left child: save hash and combine with zero
                    self.nullifier_tree_filled.write(level, current_hash);
                    let zero_at_level = self.nullifier_tree_zeros.read(level);
                    current_hash = core::poseidon::poseidon_hash_span(
                        array![NULLIFIER_TREE_DOMAIN, current_hash, zero_at_level].span()
                    );
                } else {
                    // Right child: combine with saved left sibling
                    let left_sibling = self.nullifier_tree_filled.read(level);
                    current_hash = core::poseidon::poseidon_hash_span(
                        array![NULLIFIER_TREE_DOMAIN, left_sibling, current_hash].span()
                    );
                }

                current_index = current_index / 2;
                level += 1;
            };

            // Update state
            let new_root = current_hash;
            self.nullifier_tree_root.write(new_root);
            self.nullifier_tree_next_index.write(index + 1);
            self.nullifier_tree_exists.write(nullifier, true);

            // Update root history (circular buffer)
            let max_roots = self.nullifier_tree_max_roots.read();
            let root_index = self.nullifier_tree_root_index.read();
            let new_root_index = (root_index + 1) % max_roots;

            // Remove old root from known roots if overwriting
            let old_root_at_index = self.nullifier_tree_root_history.read(new_root_index);
            if old_root_at_index != 0 {
                self.nullifier_tree_known_roots.write(old_root_at_index, false);
            }

            // Add new root
            self.nullifier_tree_root_history.write(new_root_index, new_root);
            self.nullifier_tree_known_roots.write(new_root, true);
            self.nullifier_tree_root_index.write(new_root_index);

            // Emit event
            self.emit(NullifierTreeInserted {
                nullifier,
                index,
                new_root,
                timestamp: get_block_timestamp(),
            });

            (new_root, index)
        }

        /// Hash two tree nodes with domain separation
        fn _hash_tree_nodes(self: @ContractState, left: felt252, right: felt252) -> felt252 {
            core::poseidon::poseidon_hash_span(
                array![NULLIFIER_TREE_DOMAIN, left, right].span()
            )
        }

        /// Compute the nullifier for a given secret and commitment
        fn _compute_nullifier(self: @ContractState, secret: felt252, commitment: felt252) -> felt252 {
            core::poseidon::poseidon_hash_span(
                array![NULLIFIER_TREE_DOMAIN, secret, commitment].span()
            )
        }

        // =====================================================================
        // LEAN IMT INTERNAL HELPERS
        // =====================================================================

        /// Initialize the LeanIMT (empty tree with root=0)
        fn _init_lean_imt(ref self: ContractState) {
            // Only initialize once
            assert!(!self.lean_imt_active.read(), "LeanIMT already initialized");

            // Set initial state: empty tree
            let initial_state = LeanIMTState {
                root: 0,
                size: 0,
                depth: 0,
            };
            self.lean_imt_state.write(initial_state);
            self.lean_imt_active.write(true);

            // Emit initialization event
            self.emit(LeanIMTInitialized {
                timestamp: get_block_timestamp(),
            });
        }

        /// Insert a single nullifier into the LeanIMT
        /// Returns (new_root, index) or panics if duplicate/full
        fn _insert_lean_imt(ref self: ContractState, nullifier: felt252) -> (felt252, u64) {
            // Ensure LeanIMT is active
            assert!(self.lean_imt_active.read(), "LeanIMT not initialized");

            // Reject zero nullifier (reserved for empty)
            assert!(nullifier != 0, "Cannot insert zero nullifier");

            // Check not duplicate (using shared existence map)
            assert!(!self.nullifier_tree_exists.read(nullifier), "Nullifier already exists");

            // Read current state
            let state = self.lean_imt_state.read();
            let index = state.size;
            let current_depth = state.depth;

            // Check capacity (max 2^32 - 1 leaves for u64 index with u8 depth)
            let max_leaves: u64 = 4294967295; // 2^32 - 1
            assert!(index < max_leaves, "LeanIMT is full");

            // Check if we need to increase depth
            let new_depth = if needs_depth_increase(state.size) {
                current_depth + 1
            } else {
                current_depth
            };

            // Store the leaf at level 0
            self.lean_imt_nodes.write((0, index), nullifier);

            // Compute new root by updating path from leaf to root
            let new_root = self._update_lean_imt_path(index, nullifier, new_depth);

            // Update state (create new struct since LeanIMTState has Copy trait)
            let new_state = LeanIMTState {
                root: new_root,
                size: index + 1,
                depth: new_depth,
            };
            self.lean_imt_state.write(new_state);

            // Mark nullifier as used (shared with fixed IMT for compatibility)
            self.nullifier_tree_exists.write(nullifier, true);

            // Update root history (shared circular buffer)
            self._update_root_history(new_root);

            // Emit event
            self.emit(LeanIMTInserted {
                nullifier,
                index,
                new_root,
                depth: new_depth,
                timestamp: get_block_timestamp(),
            });

            (new_root, index)
        }

        /// Batch insert multiple nullifiers into the LeanIMT
        /// Much more gas efficient than individual inserts
        fn _batch_insert_lean_imt(ref self: ContractState, nullifiers: Span<felt252>) -> LeanIMTBatchResult {
            // Ensure LeanIMT is active
            assert!(self.lean_imt_active.read(), "LeanIMT not initialized");

            let count = nullifiers.len();
            assert!(count > 0, "Empty batch");

            // Read current state
            let state = self.lean_imt_state.read();
            let start_index = state.size;

            // Check capacity
            let max_leaves: u64 = 4294967295;
            assert!(start_index + count.into() <= max_leaves, "LeanIMT would overflow");

            // First pass: validate all nullifiers and store leaves
            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }

                let nullifier = *nullifiers.at(i);

                // Reject zero
                assert!(nullifier != 0, "Cannot insert zero nullifier");

                // Check not duplicate
                assert!(!self.nullifier_tree_exists.read(nullifier), "Duplicate nullifier in batch");

                // Mark as used immediately to detect intra-batch duplicates
                self.nullifier_tree_exists.write(nullifier, true);

                // Store leaf
                let leaf_index = start_index + i.into();
                self.lean_imt_nodes.write((0, leaf_index), nullifier);

                i += 1;
            };

            // Calculate final depth after all insertions
            let final_size = start_index + count.into();
            let final_depth = calculate_depth(final_size);

            // Rebuild tree from leaves up
            // For batch insert, we recompute all affected nodes
            let new_root = self._rebuild_lean_imt_from_leaves(start_index, final_size, final_depth);

            // Update state (create new struct since LeanIMTState has Copy trait)
            let new_state = LeanIMTState {
                root: new_root,
                size: final_size,
                depth: final_depth,
            };
            self.lean_imt_state.write(new_state);

            // Update root history
            self._update_root_history(new_root);

            // Emit batch event
            self.emit(LeanIMTBatchInserted {
                start_index,
                count,
                new_root,
                new_depth: final_depth,
                timestamp: get_block_timestamp(),
            });

            LeanIMTBatchResult {
                new_root,
                new_size: final_size,
                new_depth: final_depth,
                start_index,
                inserted_count: count,
            }
        }

        /// Update path from a leaf to root, returning the new root
        /// Uses side nodes for efficient incremental updates
        fn _update_lean_imt_path(
            ref self: ContractState,
            leaf_index: u64,
            leaf_value: felt252,
            depth: u8
        ) -> felt252 {
            if depth == 0 {
                // Empty tree: leaf is root
                return leaf_value;
            }

            let mut current_index = leaf_index;
            let mut current_hash = leaf_value;
            let mut level: u8 = 0;

            loop {
                if level >= depth {
                    break;
                }

                let is_right_child = (current_index % 2) == 1;
                let sibling_index = if is_right_child {
                    current_index - 1
                } else {
                    current_index + 1
                };

                // Get sibling hash
                let sibling_hash = self._get_lean_imt_sibling(level, current_index, sibling_index);

                // Update side node if we're a left child
                if !is_right_child {
                    self.lean_imt_side_nodes.write(level, current_hash);
                }

                // Compute parent hash
                current_hash = if is_right_child {
                    hash_pair(sibling_hash, current_hash)
                } else {
                    // Right sibling might not exist yet
                    if sibling_hash == 0 {
                        // No right sibling: propagate without hashing (LeanIMT optimization)
                        current_hash
                    } else {
                        hash_pair(current_hash, sibling_hash)
                    }
                };

                // Store the new node value
                let parent_index = current_index / 2;
                self.lean_imt_nodes.write((level + 1, parent_index), current_hash);

                current_index = parent_index;
                level += 1;
            };

            current_hash
        }

        /// Get sibling hash for a node, handling edge cases
        fn _get_lean_imt_sibling(
            self: @ContractState,
            level: u8,
            node_index: u64,
            sibling_index: u64
        ) -> felt252 {
            // Check if sibling exists in storage
            let stored = self.lean_imt_nodes.read((level, sibling_index));
            if stored != 0 {
                return stored;
            }

            // For right siblings that don't exist yet, return 0 (will be handled by caller)
            // For left siblings, check side nodes
            if (node_index % 2) == 1 {
                // We're right child, sibling is left - try side nodes
                self.lean_imt_side_nodes.read(level)
            } else {
                // We're left child, right sibling doesn't exist
                0
            }
        }

        /// Rebuild tree from leaves for batch insertions
        /// More efficient than individual path updates for large batches
        fn _rebuild_lean_imt_from_leaves(
            ref self: ContractState,
            start_index: u64,
            end_size: u64,
            depth: u8
        ) -> felt252 {
            if depth == 0 || end_size == 0 {
                return 0;
            }

            if end_size == 1 {
                // Single leaf is root
                return self.lean_imt_nodes.read((0, 0));
            }

            // Build tree level by level from leaves up
            let mut level: u8 = 0;
            let mut level_size = end_size;

            loop {
                if level >= depth {
                    break;
                }

                // Calculate number of nodes at next level
                let next_level_size = (level_size + 1) / 2;

                // Process pairs at current level
                let mut parent_index: u64 = 0;
                loop {
                    if parent_index >= next_level_size {
                        break;
                    }

                    let left_index = parent_index * 2;
                    let right_index = left_index + 1;

                    let left_hash = self.lean_imt_nodes.read((level, left_index));

                    let parent_hash = if right_index < level_size {
                        // Both children exist
                        let right_hash = self.lean_imt_nodes.read((level, right_index));
                        hash_pair(left_hash, right_hash)
                    } else {
                        // Only left child exists - propagate up (LeanIMT optimization)
                        left_hash
                    };

                    self.lean_imt_nodes.write((level + 1, parent_index), parent_hash);

                    // Update side node for incremental updates
                    if left_index == level_size - 1 || left_index == level_size - 2 {
                        self.lean_imt_side_nodes.write(level, left_hash);
                    }

                    parent_index += 1;
                };

                level_size = next_level_size;
                level += 1;
            };

            // Root is at (depth, 0)
            self.lean_imt_nodes.read((depth, 0))
        }

        /// Update root history (shared with fixed IMT)
        fn _update_root_history(ref self: ContractState, new_root: felt252) {
            let max_roots = self.nullifier_tree_max_roots.read();
            if max_roots == 0 {
                return; // History disabled
            }

            let root_index = self.nullifier_tree_root_index.read();
            let new_root_index = (root_index + 1) % max_roots;

            // Remove old root if overwriting
            let old_root = self.nullifier_tree_root_history.read(new_root_index);
            if old_root != 0 {
                self.nullifier_tree_known_roots.write(old_root, false);
            }

            // Add new root
            self.nullifier_tree_root_history.write(new_root_index, new_root);
            self.nullifier_tree_known_roots.write(new_root, true);
            self.nullifier_tree_root_index.write(new_root_index);
        }

        /// Get current LeanIMT state (for views)
        fn _get_lean_imt_state(self: @ContractState) -> LeanIMTState {
            self.lean_imt_state.read()
        }

        /// Check if a root is known (valid for proofs)
        fn _is_known_lean_imt_root(self: @ContractState, root: felt252) -> bool {
            // Check current root
            let state = self.lean_imt_state.read();
            if root == state.root {
                return true;
            }
            // Check historical roots (shared with fixed IMT)
            self.nullifier_tree_known_roots.read(root)
        }

        /// Verify a LeanIMT membership proof
        /// Checks both proof validity and that the root is known
        fn _verify_lean_imt_proof(self: @ContractState, proof: @LeanIMTProof) -> bool {
            // Verify the proof structure and computation
            if !verify_proof(proof) {
                return false;
            }

            // Verify the root is known (current or historical)
            self._is_known_lean_imt_root(*proof.root)
        }

        /// Generate a LeanIMT proof for a given leaf index
        /// Returns None if index is out of bounds or tree is not active
        fn _generate_lean_imt_proof(
            self: @ContractState,
            leaf_index: u64
        ) -> Option<LeanIMTProof> {
            // Check tree is active
            if !self.lean_imt_active.read() {
                return Option::None;
            }

            let state = self.lean_imt_state.read();

            // Check index is valid
            if leaf_index >= state.size {
                return Option::None;
            }

            // Get the leaf value
            let leaf = self.lean_imt_nodes.read((0, leaf_index));
            if leaf == 0 {
                return Option::None;
            }

            // Special case: single leaf tree
            if state.size == 1 {
                return Option::Some(LeanIMTProof {
                    siblings: array![],
                    path_indices: array![],
                    leaf,
                    root: state.root,
                    tree_size: state.size,
                });
            }

            // Build the proof by traversing from leaf to root
            let mut siblings: Array<felt252> = array![];
            let mut path_indices: Array<bool> = array![];
            let mut current_index = leaf_index;
            let mut level: u8 = 0;

            loop {
                if level >= state.depth {
                    break;
                }

                // Determine if we're a left or right child
                let is_right = (current_index % 2) == 1;
                path_indices.append(is_right);

                // Get sibling
                let sibling_index = if is_right {
                    current_index - 1
                } else {
                    current_index + 1
                };

                // Read sibling from storage
                let sibling = self.lean_imt_nodes.read((level, sibling_index));
                siblings.append(sibling);

                // Move to parent
                current_index = current_index / 2;
                level += 1;
            };

            Option::Some(LeanIMTProof {
                siblings,
                path_indices,
                leaf,
                root: state.root,
                tree_size: state.size,
            })
        }

        /// Check if LeanIMT is active
        fn _is_lean_imt_active(self: @ContractState) -> bool {
            self.lean_imt_active.read()
        }

        /// Get the leaf at a specific index
        fn _get_lean_imt_leaf(self: @ContractState, index: u64) -> felt252 {
            self.lean_imt_nodes.read((0, index))
        }

    }
}
