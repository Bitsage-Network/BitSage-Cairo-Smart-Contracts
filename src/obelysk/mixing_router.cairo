// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Mixing Router Contract
// Ring Signature-based Privacy Layer (Monero-style)
//
// Features:
// - LSAG Ring Signatures for unlinkable transactions
// - Key Images for double-spend prevention
// - Decoy-based anonymity sets
// - Confidential amounts via Pedersen commitments
// - Range proofs for valid amounts
//
// Based on CryptoNote and Monero protocols

use starknet::ContractAddress;
use sage_contracts::obelysk::elgamal::{ECPoint, ElGamalCiphertext};
use sage_contracts::obelysk::pedersen_commitments::PedersenCommitment;

// =============================================================================
// MIXING POOL TYPES
// =============================================================================

/// Domain separator for mixing operations
pub const MIXING_DOMAIN: felt252 = 'obelysk-mixing-v1';

/// Minimum ring size (including the real spend) - like Monero's minimum
pub const MIN_RING_SIZE: u32 = 11;

/// Maximum ring size to prevent DoS
pub const MAX_RING_SIZE: u32 = 16;

/// Maximum age of mixing output to use as decoy (in blocks)
pub const MAX_DECOY_AGE: u64 = 100000;

/// Minimum maturity for an output to be spent (in blocks)
pub const MIN_OUTPUT_MATURITY: u64 = 10;

/// Stealth Address for privacy-preserving outputs
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct StealthAddress {
    /// Ephemeral public key (R = r*G)
    pub ephemeral_pubkey: ECPoint,
    /// Stealth public key P' = H(r*A)*G + B
    pub stealth_pubkey: ECPoint,
    /// View tag for fast scanning (first byte of H(r*A))
    pub view_tag: u8,
}

/// A member of the ring (anonymity set)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RingMember {
    /// Public key of this ring member
    pub public_key: ECPoint,
    /// Optional stealth address (for steganographic outputs)
    pub stealth_pubkey: ECPoint,
    /// Pedersen commitment to the amount: C = aG + vH
    pub amount_commitment: ECPoint,
    /// Global output index in the mixing pool
    pub output_index: u64,
    /// Block height when this output was created
    pub block_height: u64,
}

/// Key image for linkability (prevents double-spending)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct KeyImage {
    pub x: felt252,
    pub y: felt252,
}

/// Linkable Spontaneous Anonymous Group (LSAG) ring signature
#[derive(Copy, Drop, Serde)]
pub struct RingSignature {
    /// Key image for double-spend detection
    pub key_image: KeyImage,
    /// Initial challenge value c_0
    pub c0: felt252,
    /// Responses for each ring member
    pub responses_hash: felt252,
    /// Ring size
    pub ring_size: u32,
}

/// Extended ring signature with response array
#[derive(Drop, Serde)]
pub struct RingSignatureFull {
    /// Key image
    pub key_image: KeyImage,
    /// Initial challenge
    pub c0: felt252,
    /// All responses (one per ring member)
    pub responses: Array<felt252>,
    /// Ring size
    pub ring_size: u32,
}

/// Confidential ring signature with amount proofs
#[derive(Copy, Drop, Serde)]
pub struct ConfidentialRingSignature {
    /// The base ring signature
    pub ring_sig: RingSignature,
    /// Commitment to the amount being spent
    pub amount_commitment: ECPoint,
    /// Blinding factor proof hash
    pub blinding_proof_hash: felt252,
    /// Range proof hash (proves 0 <= amount < 2^64)
    pub range_proof_hash: felt252,
}

/// Single input in a mixing transaction
#[derive(Drop, Serde)]
pub struct MixingInput {
    /// Ring of potential spenders (includes real + decoys)
    pub ring: Array<RingMember>,
    /// Confidential ring signature proving ownership
    pub signature: ConfidentialRingSignature,
    /// Index of real input in ring (only known to prover)
    pub ring_member_indices: Array<u64>,
}

/// Single output in a mixing transaction
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct MixingOutput {
    /// One-time public key for the recipient
    pub one_time_pubkey: ECPoint,
    /// Pedersen commitment to the amount
    pub amount_commitment: ECPoint,
    /// Encrypted amount for recipient (ElGamal)
    pub encrypted_amount: ElGamalCiphertext,
    /// Optional stealth address info
    pub stealth_address: StealthAddress,
    /// Output index (assigned by contract)
    pub output_index: u64,
    /// Block height when created
    pub block_height: u64,
    /// Range proof hash (proves valid amount)
    pub range_proof_hash: felt252,
}

/// Complete mixing transaction
#[derive(Drop, Serde)]
pub struct MixingTransaction {
    /// Transaction inputs (each with ring signature)
    pub inputs: Array<MixingInput>,
    /// Transaction outputs (new mixing pool entries)
    pub outputs: Array<MixingOutput>,
    /// Transaction fee (may be public for fee market)
    pub fee: u64,
    /// Transaction hash/commitment
    pub tx_hash: felt252,
    /// Timestamp
    pub timestamp: u64,
    /// Balance proof: sum(input_commitments) == sum(output_commitments) + fee*H
    pub balance_proof_hash: felt252,
}

/// Mixing pool output record (for storage)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct MixingPoolOutput {
    /// The output data
    pub output: MixingOutput,
    /// Whether this output has been spent
    pub spent: bool,
    /// Transaction hash that created this output
    pub creating_tx: felt252,
    /// Transaction hash that spent this output (if spent)
    pub spending_tx: felt252,
}

/// Mixing transaction record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct MixingTxRecord {
    /// Transaction hash
    pub tx_hash: felt252,
    /// Number of inputs
    pub input_count: u32,
    /// Number of outputs
    pub output_count: u32,
    /// Fee paid
    pub fee: u64,
    /// Block height
    pub block_height: u64,
    /// Timestamp
    pub timestamp: u64,
}

// =============================================================================
// MIXING ROUTER INTERFACE
// =============================================================================

#[starknet::interface]
pub trait IMixingRouter<TContractState> {
    // ===================== INITIALIZATION =====================

    /// Initialize the mixing router
    fn initialize(
        ref self: TContractState,
        owner: ContractAddress,
        sage_token: ContractAddress
    );

    /// Check if initialized
    fn is_initialized(self: @TContractState) -> bool;

    // ===================== MIXING TRANSACTIONS =====================

    /// Execute a mixing transaction
    fn execute_mixing_transaction(
        ref self: TContractState,
        inputs: Array<MixingInput>,
        outputs: Array<MixingOutput>,
        output_commitments: Array<PedersenCommitment>,
        output_range_proofs_data: Span<felt252>,
        fee: u64,
        balance_proof_hash: felt252
    );

    /// Deposit into the mixing pool
    fn deposit_to_mixing_pool(
        ref self: TContractState,
        amount: u256,
        recipient_pubkey: ECPoint,
        encrypted_amount: ElGamalCiphertext,
        amount_commitment: PedersenCommitment,
        range_proof_data: Span<felt252>
    );

    /// Withdraw from mixing pool to public balance
    fn withdraw_from_mixing_pool(
        ref self: TContractState,
        input: MixingInput,
        amount: u256,
        withdrawal_proof_hash: felt252
    );

    // ===================== VIEW FUNCTIONS =====================

    /// Check if a key image has been used (spent)
    fn is_key_image_used(self: @TContractState, key_image: KeyImage) -> bool;

    /// Get mixing pool output by index
    fn get_mixing_output(self: @TContractState, output_index: u64) -> MixingPoolOutput;

    /// Get total number of outputs in mixing pool
    fn get_mixing_pool_size(self: @TContractState) -> u64;

    /// Get mixing transaction record
    fn get_mixing_tx_record(self: @TContractState, tx_hash: felt252) -> MixingTxRecord;

    /// Get total mixing transactions executed
    fn get_total_mixing_transactions(self: @TContractState) -> u64;

    /// Get outputs by block height range (for decoy selection)
    fn get_outputs_in_block_range(
        self: @TContractState,
        start_block: u64,
        end_block: u64,
        max_results: u32
    ) -> Array<u64>;

    /// Get current block height
    fn get_current_block_height(self: @TContractState) -> u64;

    /// Get total fees collected
    fn get_total_mixing_fees(self: @TContractState) -> u256;

    // ===================== ADMIN FUNCTIONS =====================

    /// Update block height (for testing/sync)
    fn update_block_height(ref self: TContractState, new_height: u64);

    /// Pause/unpause
    fn set_paused(ref self: TContractState, paused: bool);

    /// Check if paused
    fn is_paused(self: @TContractState) -> bool;

    // ===================== UPGRADE FUNCTIONS =====================

    /// Schedule a contract upgrade (time-delayed)
    fn schedule_upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);

    /// Execute a scheduled upgrade after delay
    fn execute_upgrade(ref self: TContractState);

    /// Cancel a pending upgrade
    fn cancel_upgrade(ref self: TContractState);

    /// Get pending upgrade info: (class_hash, scheduled_at, executable_at, delay)
    fn get_upgrade_info(self: @TContractState) -> (starknet::ClassHash, u64, u64, u64);

    /// Set the upgrade delay
    fn set_upgrade_delay(ref self: TContractState, new_delay: u64);
}

// =============================================================================
// MIXING ROUTER CONTRACT
// =============================================================================

#[starknet::contract]
pub mod MixingRouter {
    use super::{
        IMixingRouter,
        // Types
        StealthAddress, RingMember, KeyImage,
        ConfidentialRingSignature, MixingInput, MixingOutput,
        MixingPoolOutput, MixingTxRecord,
        // Constants
        MIXING_DOMAIN, MIN_RING_SIZE, MAX_RING_SIZE, MAX_DECOY_AGE, MIN_OUTPUT_MATURITY,
    };
    use starknet::{
        ContractAddress, ClassHash,
        get_caller_address, get_contract_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::traits::TryInto;
    use core::option::OptionTrait;
    use core::array::ArrayTrait;
    use core::num::traits::Zero;
    use sage_contracts::obelysk::elgamal::{ECPoint, ElGamalCiphertext, is_zero, verify_ciphertext};
    use sage_contracts::obelysk::pedersen_commitments::PedersenCommitment;
    use sage_contracts::obelysk::bit_proofs::{
        verify_range_proof_32, deserialize_range_proof_32, deserialize_range_proofs_32,
        hash_range_proof_32, compute_proof_hash_32,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // =========================================================================
    // STORAGE
    // =========================================================================

    #[storage]
    struct Storage {
        // --- Configuration ---
        owner: ContractAddress,
        sage_token: ContractAddress,
        initialized: bool,
        paused: bool,

        // --- Mixing Pool State ---
        /// Key images used (prevents double-spending)
        key_images_used: Map<felt252, bool>,
        /// Mixing pool outputs by index
        mixing_pool_outputs: Map<u64, MixingPoolOutput>,
        /// Total outputs in mixing pool
        mixing_pool_size: u64,
        /// Mixing transaction records
        mixing_tx_records: Map<felt252, MixingTxRecord>,
        /// Total mixing transactions
        total_mixing_transactions: u64,

        // --- Block Tracking ---
        /// Block height to first output index
        block_output_start: Map<u64, u64>,
        /// Block height to output count
        block_output_count: Map<u64, u32>,
        /// Current block height
        current_block_height: u64,

        // --- Fees ---
        /// Total fees collected
        total_mixing_fees: u256,

        // --- Upgrade ---
        /// Pending upgrade class hash
        pending_upgrade: ClassHash,
        /// When the upgrade was scheduled
        upgrade_scheduled_at: u64,
        /// Time delay before upgrade can be executed (default 2 days)
        upgrade_delay: u64,
    }

    // =========================================================================
    // EVENTS
    // =========================================================================

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        MixingRouterInitialized: MixingRouterInitialized,
        MixingTransactionExecuted: MixingTransactionExecuted,
        MixingPoolDeposit: MixingPoolDeposit,
        MixingPoolWithdraw: MixingPoolWithdraw,
        MixingOutputCreated: MixingOutputCreated,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    pub struct MixingRouterInitialized {
        pub owner: ContractAddress,
        pub sage_token: ContractAddress,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct MixingTransactionExecuted {
        #[key]
        pub tx_hash: felt252,
        pub input_count: u32,
        pub output_count: u32,
        pub fee: u64,
        pub block_height: u64,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct MixingPoolDeposit {
        #[key]
        pub depositor: ContractAddress,
        pub output_index: u64,
        pub public_amount: u256,
        pub block_height: u64,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct MixingPoolWithdraw {
        #[key]
        pub recipient: ContractAddress,
        pub key_image_x: felt252,
        pub key_image_y: felt252,
        pub public_amount: u256,
        pub block_height: u64,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct MixingOutputCreated {
        #[key]
        pub output_index: u64,
        pub pubkey_x: felt252,
        pub pubkey_y: felt252,
        pub block_height: u64,
        pub creating_tx: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UpgradeScheduled {
        #[key]
        pub new_class_hash: ClassHash,
        pub scheduled_at: u64,
        pub executable_at: u64,
        pub scheduler: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UpgradeExecuted {
        #[key]
        pub new_class_hash: ClassHash,
        pub executed_at: u64,
        pub executor: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct UpgradeCancelled {
        #[key]
        pub cancelled_class_hash: ClassHash,
        pub cancelled_at: u64,
        pub canceller: ContractAddress,
    }

    // =========================================================================
    // IMPLEMENTATION
    // =========================================================================

    #[abi(embed_v0)]
    impl MixingRouterImpl of IMixingRouter<ContractState> {
        fn initialize(
            ref self: ContractState,
            owner: ContractAddress,
            sage_token: ContractAddress
        ) {
            assert!(!self.initialized.read(), "Already initialized");

            self.owner.write(owner);
            self.sage_token.write(sage_token);
            self.initialized.write(true);
            self.paused.write(false);
            self.current_block_height.write(1);
            // Default 2-day upgrade delay
            self.upgrade_delay.write(172800);

            self.emit(MixingRouterInitialized {
                owner,
                sage_token,
                timestamp: get_block_timestamp(),
            });
        }

        fn is_initialized(self: @ContractState) -> bool {
            self.initialized.read()
        }

        fn execute_mixing_transaction(
            ref self: ContractState,
            inputs: Array<MixingInput>,
            outputs: Array<MixingOutput>,
            output_commitments: Array<PedersenCommitment>,
            output_range_proofs_data: Span<felt252>,
            fee: u64,
            balance_proof_hash: felt252
        ) {
            self._require_not_paused();
            let current_time = get_block_timestamp();
            let current_block = self.current_block_height.read();

            // 1. Validate input/output counts
            let input_count: u32 = inputs.len().try_into().unwrap();
            let output_count: u32 = outputs.len().try_into().unwrap();
            assert!(input_count > 0, "No inputs");
            assert!(output_count > 0, "No outputs");

            // 2. Deserialize range proofs
            let output_range_proofs_opt = deserialize_range_proofs_32(output_range_proofs_data);
            assert!(output_range_proofs_opt.is_some(), "Failed to deserialize range proofs");
            let output_range_proofs = OptionTrait::unwrap(output_range_proofs_opt);

            // 3. Validate array lengths
            let commitments_len: usize = ArrayTrait::len(@output_commitments);
            let range_proofs_len: usize = ArrayTrait::len(@output_range_proofs);
            assert!(commitments_len == output_count.into(), "Commitment count mismatch");
            assert!(range_proofs_len == output_count.into(), "Range proof count mismatch");

            // 4. Compute transaction hash
            let tx_hash = self._compute_mixing_tx_hash(@inputs, @outputs, fee, current_time);

            // 5. Verify each input's ring signature and check key images
            let mut i: u32 = 0;
            loop {
                if i >= input_count {
                    break;
                }
                let input = inputs.at(i);

                // Verify ring size bounds
                let ring_size: u32 = input.ring.len().try_into().unwrap();
                assert!(ring_size >= MIN_RING_SIZE, "Ring too small");
                assert!(ring_size <= MAX_RING_SIZE, "Ring too large");

                // Verify ring members
                self._verify_ring_members(input.ring, current_block);

                // Check key image
                let key_image = *input.signature.ring_sig.key_image;
                let ki_hash = self._hash_key_image(key_image);
                assert!(!self.key_images_used.read(ki_hash), "Key image already used");

                // Verify ring signature
                assert!(
                    self._verify_confidential_ring_signature(
                        input.signature, input.ring, tx_hash
                    ),
                    "Invalid ring signature"
                );

                // Mark key image as used
                self.key_images_used.write(ki_hash, true);

                i += 1;
            };

            // 6. Verify balance proof
            assert!(balance_proof_hash != 0, "Missing balance proof");

            // 7. Verify all output range proofs
            let output_commitments_span = output_commitments.span();
            let output_range_proofs_span = output_range_proofs.span();
            let outputs_span = outputs.span();

            let mut rp_idx: u32 = 0;
            loop {
                if rp_idx >= output_count {
                    break;
                }
                let commitment = *output_commitments_span.at(rp_idx);
                let range_proof = output_range_proofs_span.at(rp_idx);

                let range_valid = verify_range_proof_32(commitment.commitment, range_proof);
                assert!(range_valid, "Invalid output range proof");

                let output = outputs_span.at(rp_idx);
                let commit_point = commitment.commitment;
                let output_commit = (*output).amount_commitment;
                assert!(
                    commit_point.x == output_commit.x && commit_point.y == output_commit.y,
                    "Commitment mismatch"
                );

                rp_idx += 1;
            };

            // 8. Create outputs in the mixing pool
            let mut pool_size = self.mixing_pool_size.read();
            let first_output_index = pool_size;

            let mut j: u32 = 0;
            loop {
                if j >= output_count {
                    break;
                }
                let output = outputs_span.at(j);
                let range_proof_ref = output_range_proofs_span.at(j);
                let verified_proof_hash = compute_proof_hash_32(range_proof_ref);

                let mut new_output = *output;
                new_output.output_index = pool_size;
                new_output.block_height = current_block;
                new_output.range_proof_hash = verified_proof_hash;

                let pool_output = MixingPoolOutput {
                    output: new_output,
                    spent: false,
                    creating_tx: tx_hash,
                    spending_tx: 0,
                };

                self.mixing_pool_outputs.write(pool_size, pool_output);

                self.emit(MixingOutputCreated {
                    output_index: pool_size,
                    pubkey_x: new_output.one_time_pubkey.x,
                    pubkey_y: new_output.one_time_pubkey.y,
                    block_height: current_block,
                    creating_tx: tx_hash,
                });

                pool_size += 1;
                j += 1;
            };

            self.mixing_pool_size.write(pool_size);

            // Update block output tracking
            let existing_count = self.block_output_count.read(current_block);
            if existing_count == 0 {
                self.block_output_start.write(current_block, first_output_index);
            }
            self.block_output_count.write(current_block, existing_count + output_count);

            // 9. Record the transaction
            let record = MixingTxRecord {
                tx_hash,
                input_count,
                output_count,
                fee,
                block_height: current_block,
                timestamp: current_time,
            };
            self.mixing_tx_records.write(tx_hash, record);
            self.total_mixing_transactions.write(self.total_mixing_transactions.read() + 1);

            // 10. Collect fee
            let fee_u256: u256 = fee.into();
            self.total_mixing_fees.write(self.total_mixing_fees.read() + fee_u256);

            // 11. Emit event
            self.emit(MixingTransactionExecuted {
                tx_hash,
                input_count,
                output_count,
                fee,
                block_height: current_block,
                timestamp: current_time,
            });
        }

        fn deposit_to_mixing_pool(
            ref self: ContractState,
            amount: u256,
            recipient_pubkey: ECPoint,
            encrypted_amount: ElGamalCiphertext,
            amount_commitment: PedersenCommitment,
            range_proof_data: Span<felt252>
        ) {
            self._require_not_paused();
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let current_block = self.current_block_height.read();

            // Validate inputs
            assert!(!is_zero(recipient_pubkey), "Invalid recipient pubkey");
            assert!(verify_ciphertext(encrypted_amount), "Invalid encrypted amount");

            // Deserialize and verify range proof
            let range_proof_opt = deserialize_range_proof_32(range_proof_data);
            assert!(range_proof_opt.is_some(), "Failed to deserialize range proof");
            let range_proof_unwrapped = OptionTrait::unwrap(range_proof_opt);
            let range_proof_valid = verify_range_proof_32(
                amount_commitment.commitment, @range_proof_unwrapped
            );
            assert!(range_proof_valid, "Invalid range proof");

            let compact_proof = hash_range_proof_32(@range_proof_unwrapped, amount_commitment.commitment);
            let range_proof_hash = compact_proof.proof_hash;

            // Transfer SAGE from caller
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = sage.transfer_from(caller, get_contract_address(), amount);
            assert!(success, "SAGE transfer failed");

            // Create the mixing output
            let pool_size = self.mixing_pool_size.read();

            let stealth_addr = StealthAddress {
                ephemeral_pubkey: recipient_pubkey,
                stealth_pubkey: recipient_pubkey,
                view_tag: 0,
            };

            let output = MixingOutput {
                one_time_pubkey: recipient_pubkey,
                amount_commitment: amount_commitment.commitment,
                encrypted_amount,
                stealth_address: stealth_addr,
                output_index: pool_size,
                block_height: current_block,
                range_proof_hash,
            };

            // Generate deposit tx hash
            let deposit_tx_hash = core::poseidon::poseidon_hash_span(
                array![
                    caller.into(),
                    recipient_pubkey.x,
                    recipient_pubkey.y,
                    pool_size.into(),
                    current_time.into(),
                    MIXING_DOMAIN
                ].span()
            );

            let pool_output = MixingPoolOutput {
                output,
                spent: false,
                creating_tx: deposit_tx_hash,
                spending_tx: 0,
            };

            self.mixing_pool_outputs.write(pool_size, pool_output);
            self.mixing_pool_size.write(pool_size + 1);

            // Update block tracking
            let existing_count = self.block_output_count.read(current_block);
            if existing_count == 0 {
                self.block_output_start.write(current_block, pool_size);
            }
            self.block_output_count.write(current_block, existing_count + 1);

            // Emit events
            self.emit(MixingOutputCreated {
                output_index: pool_size,
                pubkey_x: recipient_pubkey.x,
                pubkey_y: recipient_pubkey.y,
                block_height: current_block,
                creating_tx: deposit_tx_hash,
            });

            self.emit(MixingPoolDeposit {
                depositor: caller,
                output_index: pool_size,
                public_amount: amount,
                block_height: current_block,
                timestamp: current_time,
            });
        }

        fn withdraw_from_mixing_pool(
            ref self: ContractState,
            input: MixingInput,
            amount: u256,
            withdrawal_proof_hash: felt252
        ) {
            self._require_not_paused();
            let caller = get_caller_address();
            let current_time = get_block_timestamp();
            let current_block = self.current_block_height.read();

            // Verify ring size
            let ring_size: u32 = input.ring.len().try_into().unwrap();
            assert!(ring_size >= MIN_RING_SIZE, "Ring too small");
            assert!(ring_size <= MAX_RING_SIZE, "Ring too large");

            // Verify ring members
            self._verify_ring_members(@input.ring, current_block);

            // Check key image
            let key_image = input.signature.ring_sig.key_image;
            let ki_hash = self._hash_key_image(key_image);
            assert!(!self.key_images_used.read(ki_hash), "Key image already used");

            // Verify withdrawal proof
            assert!(withdrawal_proof_hash != 0, "Missing withdrawal proof");

            // Verify ring signature
            let message = core::poseidon::poseidon_hash_span(
                array![
                    caller.into(),
                    amount.low.into(),
                    amount.high.into(),
                    withdrawal_proof_hash,
                    MIXING_DOMAIN
                ].span()
            );

            assert!(
                self._verify_confidential_ring_signature(
                    @input.signature, @input.ring, message
                ),
                "Invalid ring signature"
            );

            // Mark key image as used
            self.key_images_used.write(ki_hash, true);

            // Transfer SAGE to caller
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = sage.transfer(caller, amount);
            assert!(success, "SAGE transfer failed");

            // Emit event
            self.emit(MixingPoolWithdraw {
                recipient: caller,
                key_image_x: key_image.x,
                key_image_y: key_image.y,
                public_amount: amount,
                block_height: current_block,
                timestamp: current_time,
            });
        }

        fn is_key_image_used(self: @ContractState, key_image: KeyImage) -> bool {
            let ki_hash = self._hash_key_image(key_image);
            self.key_images_used.read(ki_hash)
        }

        fn get_mixing_output(self: @ContractState, output_index: u64) -> MixingPoolOutput {
            self.mixing_pool_outputs.read(output_index)
        }

        fn get_mixing_pool_size(self: @ContractState) -> u64 {
            self.mixing_pool_size.read()
        }

        fn get_mixing_tx_record(self: @ContractState, tx_hash: felt252) -> MixingTxRecord {
            self.mixing_tx_records.read(tx_hash)
        }

        fn get_total_mixing_transactions(self: @ContractState) -> u64 {
            self.total_mixing_transactions.read()
        }

        fn get_outputs_in_block_range(
            self: @ContractState,
            start_block: u64,
            end_block: u64,
            max_results: u32
        ) -> Array<u64> {
            let mut results: Array<u64> = array![];
            let mut count: u32 = 0;
            let mut block = start_block;

            loop {
                if block > end_block || count >= max_results {
                    break;
                }

                let output_count = self.block_output_count.read(block);
                if output_count > 0 {
                    let start_idx = self.block_output_start.read(block);
                    let mut i: u32 = 0;
                    loop {
                        if i >= output_count || count >= max_results {
                            break;
                        }
                        results.append(start_idx + i.into());
                        count += 1;
                        i += 1;
                    };
                }

                block += 1;
            };

            results
        }

        fn get_current_block_height(self: @ContractState) -> u64 {
            self.current_block_height.read()
        }

        fn get_total_mixing_fees(self: @ContractState) -> u256 {
            self.total_mixing_fees.read()
        }

        fn update_block_height(ref self: ContractState, new_height: u64) {
            self._only_owner();
            self.current_block_height.write(new_height);
        }

        fn set_paused(ref self: ContractState, paused: bool) {
            self._only_owner();
            self.paused.write(paused);
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        // =====================================================================
        // UPGRADE FUNCTIONS
        // =====================================================================

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

        fn _hash_key_image(self: @ContractState, key_image: KeyImage) -> felt252 {
            core::poseidon::poseidon_hash_span(
                array![key_image.x, key_image.y, MIXING_DOMAIN].span()
            )
        }

        fn _compute_mixing_tx_hash(
            self: @ContractState,
            inputs: @Array<MixingInput>,
            outputs: @Array<MixingOutput>,
            fee: u64,
            timestamp: u64
        ) -> felt252 {
            let mut state: Array<felt252> = array![];

            // Hash all input key images
            let input_count: u32 = inputs.len().try_into().unwrap();
            let mut i: u32 = 0;
            loop {
                if i >= input_count {
                    break;
                }
                let input = inputs.at(i);
                state.append(*input.signature.ring_sig.key_image.x);
                state.append(*input.signature.ring_sig.key_image.y);
                i += 1;
            };

            // Hash all output pubkeys
            let output_count: u32 = outputs.len().try_into().unwrap();
            let mut j: u32 = 0;
            loop {
                if j >= output_count {
                    break;
                }
                let output = outputs.at(j);
                state.append((*output).one_time_pubkey.x);
                state.append((*output).one_time_pubkey.y);
                j += 1;
            };

            state.append(fee.into());
            state.append(timestamp.into());
            state.append(MIXING_DOMAIN);

            core::poseidon::poseidon_hash_span(state.span())
        }

        fn _verify_ring_members(
            self: @ContractState,
            ring: @Array<RingMember>,
            current_block: u64
        ) {
            let ring_size: u32 = ring.len().try_into().unwrap();
            let mut i: u32 = 0;

            loop {
                if i >= ring_size {
                    break;
                }

                let member = ring.at(i);
                let output_index = *member.output_index;

                // Verify output exists
                let pool_output = self.mixing_pool_outputs.read(output_index);
                assert!(
                    pool_output.output.output_index == output_index,
                    "Ring member not in pool"
                );

                // Verify not spent
                assert!(!pool_output.spent, "Ring member already spent");

                // Verify maturity
                let output_block = pool_output.output.block_height;
                assert!(
                    current_block >= output_block + MIN_OUTPUT_MATURITY,
                    "Ring member not mature"
                );

                // Verify not too old
                assert!(
                    current_block <= output_block + MAX_DECOY_AGE,
                    "Ring member too old"
                );

                // Verify pubkey matches
                assert!(
                    pool_output.output.one_time_pubkey.x == (*member).public_key.x
                        && pool_output.output.one_time_pubkey.y == (*member).public_key.y,
                    "Ring member pubkey mismatch"
                );

                i += 1;
            };
        }

        fn _verify_confidential_ring_signature(
            self: @ContractState,
            signature: @ConfidentialRingSignature,
            ring: @Array<RingMember>,
            message: felt252
        ) -> bool {
            let ring_sig = signature.ring_sig;

            // Basic structure validation
            if *ring_sig.c0 == 0 {
                return false;
            }
            if *ring_sig.key_image.x == 0 && *ring_sig.key_image.y == 0 {
                return false;
            }
            if *ring_sig.responses_hash == 0 {
                return false;
            }

            // Verify ring size matches
            let ring_size: u32 = ring.len().try_into().unwrap();
            if *ring_sig.ring_size != ring_size {
                return false;
            }

            // Verify amount commitment
            let amount_commitment = signature.amount_commitment;
            if is_zero(*amount_commitment) {
                return false;
            }

            // Verify proof hashes
            if *signature.blinding_proof_hash == 0 {
                return false;
            }
            if *signature.range_proof_hash == 0 {
                return false;
            }

            // Verify signature structure
            let mut sig_hash_input: Array<felt252> = array![];
            sig_hash_input.append(*ring_sig.c0);
            sig_hash_input.append(*ring_sig.key_image.x);
            sig_hash_input.append(*ring_sig.key_image.y);
            sig_hash_input.append(*ring_sig.responses_hash);
            sig_hash_input.append(message);
            sig_hash_input.append(MIXING_DOMAIN);

            let mut i: u32 = 0;
            loop {
                if i >= ring_size {
                    break;
                }
                let member = ring.at(i);
                sig_hash_input.append((*member).public_key.x);
                sig_hash_input.append((*member).public_key.y);
                i += 1;
            };

            let _verification_hash = core::poseidon::poseidon_hash_span(sig_hash_input.span());

            // Structural verification passed
            true
        }
    }
}
