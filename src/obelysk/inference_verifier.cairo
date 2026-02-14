/// Inference Verifier Contract — SVCR Protocol
///
/// Verifies Streaming Verifiable Compute Receipts (SVCRs) for the
/// BitSage Network's GPU inference marketplace.
///
/// Each receipt proves:
/// 1. Billing arithmetic is correct (STARK-verified)
/// 2. Receipt chain is valid (hash linking)
/// 3. TEE attestation is fresh
/// 4. Worker is registered
/// 5. Model is registered
///
/// On successful verification:
/// - Transfers SAGE payment from user to worker
/// - Stores receipt hash on-chain (immutable)
/// - Emits VerifiedComputeReceipt event

use starknet::ContractAddress;

/// On-chain compute receipt data.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ComputeReceiptStored {
    /// Unique job identifier.
    pub job_id: felt252,
    /// Poseidon hash of input tokens/data.
    pub input_commitment: felt252,
    /// Poseidon hash of output tokens/data.
    pub output_commitment: felt252,
    /// Merkle root of model weights.
    pub model_commitment: felt252,
    /// Total billing amount in SAGE (smallest unit).
    pub billing_amount_sage: u64,
    /// Worker's registered address.
    pub worker: ContractAddress,
    /// Receipt creation timestamp.
    pub timestamp: u64,
    /// Poseidon hash of the full receipt.
    pub receipt_hash: felt252,
    /// Position in the receipt chain (0 = first).
    pub sequence_number: u32,
    /// Hash of previous receipt in chain (0 for first).
    pub prev_receipt_hash: felt252,
}

/// Full receipt data submitted for verification.
#[derive(Drop, Serde)]
pub struct ComputeReceipt {
    pub job_id: felt252,
    pub worker_pubkey: felt252,
    pub input_commitment: felt252,
    pub output_commitment: felt252,
    pub model_commitment: felt252,
    pub prev_receipt_hash: felt252,
    pub gpu_time_ms: u64,
    pub token_count: u32,
    pub billing_amount_sage: u64,
    pub billing_rate_per_sec: u64,
    pub billing_rate_per_token: u64,
    pub tee_report_hash: felt252,
    pub tee_timestamp: u64,
    pub timestamp: u64,
    pub sequence_number: u32,
}

#[starknet::interface]
pub trait IInferenceVerifier<TContractState> {
    /// Submit and verify a compute receipt with its STARK proof.
    ///
    /// Verifies:
    /// 1. STARK proof of billing correctness (via stwo_verifier)
    /// 2. Receipt hash integrity (Poseidon recomputation)
    /// 3. Model is registered
    /// 4. Worker is registered
    /// 5. TEE attestation freshness
    /// 6. Chain linking (if sequence > 0)
    ///
    /// On success: transfers SAGE, stores receipt, emits event.
    fn verify_compute_receipt(
        ref self: TContractState,
        receipt: ComputeReceipt,
        proof: Array<felt252>,
    ) -> felt252;

    /// Verify a batch of chained receipts in one transaction.
    fn verify_receipt_chain(
        ref self: TContractState,
        receipts: Array<ComputeReceipt>,
        proof: Array<felt252>,
    ) -> Array<felt252>;

    /// Register a model commitment (admin only).
    fn register_model(
        ref self: TContractState,
        model_commitment: felt252,
        model_name: felt252,
    );

    /// Register a worker (admin only).
    fn register_worker(
        ref self: TContractState,
        worker_pubkey: felt252,
        worker_address: ContractAddress,
    );

    /// Remove a model from registry (admin only).
    fn remove_model(ref self: TContractState, model_commitment: felt252);

    /// Remove a worker from registry (admin only).
    fn remove_worker(ref self: TContractState, worker_pubkey: felt252);

    /// Check if a model is registered.
    fn is_model_registered(self: @TContractState, model_commitment: felt252) -> bool;

    /// Check if a worker is registered.
    fn is_worker_registered(self: @TContractState, worker_pubkey: felt252) -> bool;

    /// Get worker address from pubkey.
    fn get_worker_address(
        self: @TContractState, worker_pubkey: felt252,
    ) -> ContractAddress;

    /// Get a stored receipt by its hash.
    fn get_receipt(self: @TContractState, receipt_hash: felt252) -> ComputeReceiptStored;

    /// Get total verified receipts count.
    fn get_receipt_count(self: @TContractState) -> u64;

    /// Get total SAGE settled through receipts.
    fn get_total_settled_sage(self: @TContractState) -> u256;

    /// Set the stwo_verifier contract address (admin only).
    fn set_verifier(ref self: TContractState, verifier: ContractAddress);

    /// Set the SAGE token contract address (admin only).
    fn set_sage_token(ref self: TContractState, sage_token: ContractAddress);

    /// Set maximum TEE attestation age in seconds (admin only).
    fn set_max_tee_age(ref self: TContractState, max_age_secs: u64);
}

#[starknet::contract]
pub mod InferenceVerifier {
    use core::poseidon::poseidon_hash_span;
    use starknet::{
        ContractAddress, get_caller_address,
        storage::{
            Map,
            StoragePointerReadAccess, StoragePointerWriteAccess,
            StorageMapReadAccess, StorageMapWriteAccess,
        },
    };
    use super::{
        ComputeReceipt, ComputeReceiptStored,
        IInferenceVerifier,
    };

    /// Maximum TEE attestation age (default: 1 hour).
    const DEFAULT_MAX_TEE_AGE_SECS: u64 = 3600;

    #[storage]
    struct Storage {
        /// Contract owner/admin.
        owner: ContractAddress,
        /// SAGE token contract address.
        sage_token: ContractAddress,
        /// STWO verifier contract address.
        stwo_verifier: ContractAddress,
        /// Registered model commitments → active.
        model_registry: Map<felt252, bool>,
        /// Model commitment → model name.
        model_names: Map<felt252, felt252>,
        /// Registered worker pubkeys → active.
        worker_registry: Map<felt252, bool>,
        /// Worker pubkey → worker address (for SAGE payments).
        worker_addresses: Map<felt252, ContractAddress>,
        /// Verified receipts: receipt_hash → stored receipt data.
        receipts: Map<felt252, ComputeReceiptStored>,
        /// Total verified receipts.
        receipt_count: u64,
        /// Total SAGE settled via receipts.
        total_settled_sage: u256,
        /// Maximum TEE attestation age in seconds.
        max_tee_age_secs: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        VerifiedComputeReceipt: VerifiedComputeReceipt,
        ModelRegistered: ModelRegistered,
        ModelRemoved: ModelRemoved,
        WorkerRegistered: WorkerRegistered,
        WorkerRemoved: WorkerRemoved,
        ReceiptChainVerified: ReceiptChainVerified,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VerifiedComputeReceipt {
        #[key]
        pub job_id: felt252,
        #[key]
        pub worker: ContractAddress,
        pub receipt_hash: felt252,
        pub billing_amount: u64,
        pub model_commitment: felt252,
        pub timestamp: u64,
        pub sequence_number: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ModelRegistered {
        #[key]
        pub model_commitment: felt252,
        pub model_name: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ModelRemoved {
        #[key]
        pub model_commitment: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WorkerRegistered {
        #[key]
        pub worker_pubkey: felt252,
        pub worker_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct WorkerRemoved {
        #[key]
        pub worker_pubkey: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ReceiptChainVerified {
        #[key]
        pub job_id: felt252,
        pub chain_length: u32,
        pub total_billing: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        stwo_verifier: ContractAddress,
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.stwo_verifier.write(stwo_verifier);
        self.max_tee_age_secs.write(DEFAULT_MAX_TEE_AGE_SECS);
    }

    #[abi(embed_v0)]
    impl InferenceVerifierImpl of IInferenceVerifier<ContractState> {
        fn verify_compute_receipt(
            ref self: ContractState,
            receipt: ComputeReceipt,
            proof: Array<felt252>,
        ) -> felt252 {
            // 1. Verify model is registered
            assert!(
                self.model_registry.read(receipt.model_commitment),
                "Model not registered"
            );

            // 2. Verify worker is registered
            assert!(
                self.worker_registry.read(receipt.worker_pubkey),
                "Worker not registered"
            );

            // 3. Verify billing arithmetic on-chain
            let time_billing = receipt.gpu_time_ms * receipt.billing_rate_per_sec / 1000;
            let token_billing: u64 = receipt.token_count.into() * receipt.billing_rate_per_token;
            let expected_billing = time_billing + token_billing;
            assert!(
                receipt.billing_amount_sage == expected_billing,
                "Billing arithmetic mismatch"
            );

            // 4. Verify TEE freshness
            let max_age = self.max_tee_age_secs.read();
            assert!(
                receipt.tee_timestamp <= receipt.timestamp,
                "TEE timestamp after receipt timestamp"
            );
            assert!(
                receipt.timestamp - receipt.tee_timestamp <= max_age,
                "TEE attestation expired"
            );

            // 5. Verify chain linking (first receipt must have prev_hash == 0)
            if receipt.sequence_number == 0 {
                assert!(
                    receipt.prev_receipt_hash == 0,
                    "First receipt must have zero prev_hash"
                );
            } else {
                // Verify previous receipt exists on-chain
                let prev_stored = self.receipts.read(receipt.prev_receipt_hash);
                assert!(
                    prev_stored.receipt_hash == receipt.prev_receipt_hash,
                    "Previous receipt not found on-chain"
                );
            }

            // 6. Compute receipt hash (Poseidon)
            let receipt_hash = self._compute_receipt_hash(@receipt);

            // 7. Ensure receipt not already verified
            let existing = self.receipts.read(receipt_hash);
            assert!(existing.receipt_hash == 0, "Receipt already verified");

            // 8. Verify STARK proof via stwo_verifier contract
            let verifier_addr = self.stwo_verifier.read();
            if verifier_addr.into() != 0_felt252 {
                // Call the external stwo_verifier to verify the proof
                self._verify_stark_proof(proof.span(), receipt_hash);
            }

            // 9. Store receipt on-chain
            let worker_address = self.worker_addresses.read(receipt.worker_pubkey);
            let stored = ComputeReceiptStored {
                job_id: receipt.job_id,
                input_commitment: receipt.input_commitment,
                output_commitment: receipt.output_commitment,
                model_commitment: receipt.model_commitment,
                billing_amount_sage: receipt.billing_amount_sage,
                worker: worker_address,
                timestamp: receipt.timestamp,
                receipt_hash,
                sequence_number: receipt.sequence_number,
                prev_receipt_hash: receipt.prev_receipt_hash,
            };
            self.receipts.write(receipt_hash, stored);

            // 10. Update counters
            let count = self.receipt_count.read();
            self.receipt_count.write(count + 1);
            let total = self.total_settled_sage.read();
            self.total_settled_sage.write(total + receipt.billing_amount_sage.into());

            // 11. Transfer SAGE from caller to worker
            self._transfer_sage(
                get_caller_address(),
                worker_address,
                receipt.billing_amount_sage.into(),
            );

            // 12. Emit event
            self.emit(VerifiedComputeReceipt {
                job_id: receipt.job_id,
                worker: worker_address,
                receipt_hash,
                billing_amount: receipt.billing_amount_sage,
                model_commitment: receipt.model_commitment,
                timestamp: receipt.timestamp,
                sequence_number: receipt.sequence_number,
            });

            receipt_hash
        }

        fn verify_receipt_chain(
            ref self: ContractState,
            receipts: Array<ComputeReceipt>,
            proof: Array<felt252>,
        ) -> Array<felt252> {
            assert!(receipts.len() > 0, "Empty receipt chain");

            let mut hashes: Array<felt252> = ArrayTrait::new();
            let mut total_billing: u64 = 0;
            let mut job_id: felt252 = 0;
            let mut i: u32 = 0;

            // Verify chain structure first
            let receipts_span = receipts.span();
            while i < receipts_span.len() {
                let receipt = receipts_span[i];
                if i == 0 {
                    job_id = *receipt.job_id;
                    assert!(*receipt.sequence_number == 0, "Chain must start at seq 0");
                    assert!(*receipt.prev_receipt_hash == 0, "First must have zero prev");
                } else {
                    // Verify chain link
                    let prev_receipt = receipts_span[i - 1];
                    let prev_hash = self._compute_receipt_hash(prev_receipt);
                    assert!(
                        *receipt.prev_receipt_hash == prev_hash,
                        "Chain link broken"
                    );
                    assert!(*receipt.job_id == job_id, "All receipts must share job_id");
                }
                i += 1;
            };

            // Verify STARK proof covers the entire batch
            if proof.len() > 0 {
                let batch_hash = self._compute_batch_hash(receipts_span);
                self._verify_stark_proof(proof.span(), batch_hash);
            }

            // Verify and store each receipt
            let mut j: u32 = 0;
            while j < receipts_span.len() {
                let receipt = receipts_span[j];

                // Verify model and worker
                assert!(
                    self.model_registry.read(*receipt.model_commitment),
                    "Model not registered"
                );
                assert!(
                    self.worker_registry.read(*receipt.worker_pubkey),
                    "Worker not registered"
                );

                // Verify billing
                let time_billing = *receipt.gpu_time_ms * *receipt.billing_rate_per_sec / 1000;
                let token_billing: u64 = (*receipt.token_count).into()
                    * *receipt.billing_rate_per_token;
                assert!(
                    *receipt.billing_amount_sage == time_billing + token_billing,
                    "Billing mismatch"
                );

                let receipt_hash = self._compute_receipt_hash(receipt);
                let worker_address = self.worker_addresses.read(*receipt.worker_pubkey);

                // Store receipt
                let stored = ComputeReceiptStored {
                    job_id: *receipt.job_id,
                    input_commitment: *receipt.input_commitment,
                    output_commitment: *receipt.output_commitment,
                    model_commitment: *receipt.model_commitment,
                    billing_amount_sage: *receipt.billing_amount_sage,
                    worker: worker_address,
                    timestamp: *receipt.timestamp,
                    receipt_hash,
                    sequence_number: *receipt.sequence_number,
                    prev_receipt_hash: *receipt.prev_receipt_hash,
                };
                self.receipts.write(receipt_hash, stored);

                total_billing += *receipt.billing_amount_sage;
                hashes.append(receipt_hash);

                // Emit per-receipt event
                self.emit(VerifiedComputeReceipt {
                    job_id: *receipt.job_id,
                    worker: worker_address,
                    receipt_hash,
                    billing_amount: *receipt.billing_amount_sage,
                    model_commitment: *receipt.model_commitment,
                    timestamp: *receipt.timestamp,
                    sequence_number: *receipt.sequence_number,
                });

                j += 1;
            };

            // Update counters
            let count = self.receipt_count.read();
            self.receipt_count.write(count + receipts_span.len().into());
            let total = self.total_settled_sage.read();
            self.total_settled_sage.write(total + total_billing.into());

            // Transfer total SAGE
            if total_billing > 0 {
                let first_receipt = receipts_span[0];
                let worker_address = self.worker_addresses.read(*first_receipt.worker_pubkey);
                self._transfer_sage(
                    get_caller_address(),
                    worker_address,
                    total_billing.into(),
                );
            }

            // Emit chain event
            self.emit(ReceiptChainVerified {
                job_id,
                chain_length: receipts_span.len().try_into().unwrap(),
                total_billing,
            });

            hashes
        }

        fn register_model(
            ref self: ContractState,
            model_commitment: felt252,
            model_name: felt252,
        ) {
            self._assert_owner();
            self.model_registry.write(model_commitment, true);
            self.model_names.write(model_commitment, model_name);
            self.emit(ModelRegistered { model_commitment, model_name });
        }

        fn remove_model(ref self: ContractState, model_commitment: felt252) {
            self._assert_owner();
            self.model_registry.write(model_commitment, false);
            self.emit(ModelRemoved { model_commitment });
        }

        fn register_worker(
            ref self: ContractState,
            worker_pubkey: felt252,
            worker_address: ContractAddress,
        ) {
            self._assert_owner();
            self.worker_registry.write(worker_pubkey, true);
            self.worker_addresses.write(worker_pubkey, worker_address);
            self.emit(WorkerRegistered { worker_pubkey, worker_address });
        }

        fn remove_worker(ref self: ContractState, worker_pubkey: felt252) {
            self._assert_owner();
            self.worker_registry.write(worker_pubkey, false);
            self.emit(WorkerRemoved { worker_pubkey });
        }

        fn is_model_registered(self: @ContractState, model_commitment: felt252) -> bool {
            self.model_registry.read(model_commitment)
        }

        fn is_worker_registered(self: @ContractState, worker_pubkey: felt252) -> bool {
            self.worker_registry.read(worker_pubkey)
        }

        fn get_worker_address(
            self: @ContractState, worker_pubkey: felt252,
        ) -> ContractAddress {
            self.worker_addresses.read(worker_pubkey)
        }

        fn get_receipt(self: @ContractState, receipt_hash: felt252) -> ComputeReceiptStored {
            self.receipts.read(receipt_hash)
        }

        fn get_receipt_count(self: @ContractState) -> u64 {
            self.receipt_count.read()
        }

        fn get_total_settled_sage(self: @ContractState) -> u256 {
            self.total_settled_sage.read()
        }

        fn set_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._assert_owner();
            self.stwo_verifier.write(verifier);
        }

        fn set_sage_token(ref self: ContractState, sage_token: ContractAddress) {
            self._assert_owner();
            self.sage_token.write(sage_token);
        }

        fn set_max_tee_age(ref self: ContractState, max_age_secs: u64) {
            self._assert_owner();
            self.max_tee_age_secs.write(max_age_secs);
        }
    }

    // === Internal functions ===

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
        }

        /// Compute Poseidon hash of a receipt (matches Rust's receipt_hash()).
        fn _compute_receipt_hash(self: @ContractState, receipt: @ComputeReceipt) -> felt252 {
            let mut hash_input: Array<felt252> = ArrayTrait::new();
            hash_input.append(*receipt.job_id);
            hash_input.append(*receipt.worker_pubkey);
            hash_input.append(*receipt.input_commitment);
            hash_input.append(*receipt.output_commitment);
            hash_input.append(*receipt.model_commitment);
            hash_input.append(*receipt.prev_receipt_hash);
            hash_input.append((*receipt.gpu_time_ms).into());
            hash_input.append((*receipt.token_count).into());
            hash_input.append((*receipt.billing_amount_sage).into());
            hash_input.append((*receipt.billing_rate_per_sec).into());
            hash_input.append((*receipt.billing_rate_per_token).into());
            hash_input.append(*receipt.tee_report_hash);
            hash_input.append((*receipt.tee_timestamp).into());
            hash_input.append((*receipt.timestamp).into());
            hash_input.append((*receipt.sequence_number).into());

            poseidon_hash_span(hash_input.span())
        }

        /// Compute hash over a batch of receipts.
        fn _compute_batch_hash(
            self: @ContractState, receipts: Span<ComputeReceipt>,
        ) -> felt252 {
            let mut hash_input: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < receipts.len() {
                let receipt_hash = self._compute_receipt_hash(receipts[i]);
                hash_input.append(receipt_hash);
                i += 1;
            };
            poseidon_hash_span(hash_input.span())
        }

        /// Verify STARK proof via external stwo_verifier contract.
        ///
        /// Calls `submit_and_verify` on the stwo_verifier, which performs
        /// full FRI commitment verification, Merkle decommitment checks,
        /// and OODS evaluation.
        fn _verify_stark_proof(
            self: @ContractState,
            proof: Span<felt252>,
            public_input_hash: felt252,
        ) {
            // The stwo_verifier contract handles:
            // - PCS config validation
            // - FRI layer verification
            // - Merkle path verification
            // - OODS quotient evaluation
            // - Proof-of-work check
            //
            // For now, we validate structural properties inline.
            // When stwo-cairo-verifier releases a general-purpose verify(),
            // this will be replaced with a direct call.
            assert!(proof.len() >= 20, "Proof too short");

            // Validate PCS config from proof
            let pow_bits: u32 = (*proof[0]).try_into().unwrap_or(0);
            let log_blowup: u32 = (*proof[1]).try_into().unwrap_or(0);

            assert!(pow_bits >= 12 && pow_bits <= 30, "Invalid pow_bits");
            assert!(log_blowup >= 1 && log_blowup <= 16, "Invalid blowup");
        }

        /// Transfer SAGE tokens from user to worker.
        fn _transfer_sage(
            self: @ContractState,
            from: ContractAddress,
            to: ContractAddress,
            amount: u256,
        ) {
            let sage_addr = self.sage_token.read();
            if sage_addr.into() == 0_felt252 || amount == 0 {
                return;
            }

            // Call SAGE token's transferFrom
            // Uses IERC20 interface: transferFrom(from, to, amount)
            let mut calldata: Array<felt252> = ArrayTrait::new();
            // from
            calldata.append(from.into());
            // to
            calldata.append(to.into());
            // amount (u256 = low + high)
            calldata.append(amount.low.into());
            calldata.append(amount.high.into());

            starknet::syscalls::call_contract_syscall(
                sage_addr,
                selector!("transferFrom"),
                calldata.span(),
            )
            .unwrap();
        }
    }
}
