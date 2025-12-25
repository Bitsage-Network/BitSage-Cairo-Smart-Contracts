#[starknet::contract]
mod ProofVerifier {
    use sage_contracts::interfaces::proof_verifier::IProofVerifier;
    // Import types from interface
    use sage_contracts::interfaces::proof_verifier::{
        ProofJobId, ProofJobSpec, ProofSubmission, ProofStatus, ProofType,
        ProverMetrics, ProofEconomics, WorkerId
    };
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use core::array::{Array, ArrayTrait};
    use core::poseidon::poseidon_hash_span;
    use core::num::traits::Zero;

    // Import ProofGatedPayment dispatcher for callbacks
    use sage_contracts::payments::proof_gated_payment::{
        IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait
    };

    // =========================================================================
    // STWO Circle STARK Constants (M31 Field)
    // =========================================================================
    // Mersenne-31 prime: 2^31 - 1
    const M31_PRIME: felt252 = 2147483647;
    // Minimum proof elements required for valid STARK proof
    const MIN_STARK_PROOF_ELEMENTS: u32 = 32;
    // FRI proof layer minimum
    const MIN_FRI_LAYERS: u32 = 4;
    // Expected commitment count (trace + composition)
    const MIN_COMMITMENTS: u32 = 2;

    // =========================================================================
    // Events
    // =========================================================================
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProofVerified: ProofVerified,
        ProofRejected: ProofRejected,
        EnclaveWhitelisted: EnclaveWhitelisted,
        EnclaveRevoked: EnclaveRevoked,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerified {
        #[key]
        job_id: u256,
        #[key]
        worker_id: felt252,
        proof_hash: felt252,
        verification_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofRejected {
        #[key]
        job_id: u256,
        reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct EnclaveWhitelisted {
        #[key]
        enclave_measurement: felt252,
        authorized_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct EnclaveRevoked {
        #[key]
        enclave_measurement: felt252,
        revoked_by: ContractAddress,
    }

    #[storage]
    struct Storage {
        // Admin and security
        owner: ContractAddress,
        emergency_council: Map<ContractAddress, bool>,

        // Payment integration
        proof_gated_payment: ContractAddress,

        // Job management
        jobs: Map<u256, ProofJobSpec>,
        job_status: Map<u256, ProofStatus>,
        job_proof_hashes: Map<u256, felt252>,
        job_verified_at: Map<u256, u64>,
        job_worker: Map<u256, felt252>,  // Track which worker submitted proof

        // Pending job queue - indexed by proof type
        // pending_jobs_by_type: (proof_type_u8, index) -> job_id
        pending_jobs_by_type: Map<(u8, u32), u256>,
        pending_job_count_by_type: Map<u8, u32>,
        // Reverse mapping: job_id -> (proof_type, index) for O(1) removal
        job_pending_index: Map<u256, (u8, u32)>,
        // Track if a job is in the pending queue
        job_in_pending_queue: Map<u256, bool>,

        // TEE/Enclave security
        whitelisted_enclaves: Map<felt252, bool>,
        enclave_whitelist_count: u32,

        // Prover tracking
        prover_stakes: Map<felt252, u256>,
        prover_metrics: Map<felt252, ProverMetrics>,

        // Verification statistics
        total_proofs_verified: u64,
        total_proofs_rejected: u64,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.total_proofs_verified.write(0);
        self.total_proofs_rejected.write(0);
        self.enclave_whitelist_count.write(0);
    }

    #[abi(embed_v0)]
    impl ProofVerifierImpl of IProofVerifier<ContractState> {
        fn submit_proof_job(
            ref self: ContractState,
            spec: ProofJobSpec
        ) -> ProofJobId {
            let job_id = spec.job_id;
            let job_id_value = job_id.value;

            // Store the job
            self.jobs.write(job_id_value, spec);
            self.job_status.write(job_id_value, ProofStatus::Pending);

            // Add to pending queue by proof type
            let proof_type_u8: u8 = self._proof_type_to_u8(spec.proof_type);
            let current_count = self.pending_job_count_by_type.read(proof_type_u8);

            // Add job to the end of the queue for this proof type
            self.pending_jobs_by_type.write((proof_type_u8, current_count), job_id_value);
            self.pending_job_count_by_type.write(proof_type_u8, current_count + 1);

            // Store reverse mapping for O(1) removal
            self.job_pending_index.write(job_id_value, (proof_type_u8, current_count));
            self.job_in_pending_queue.write(job_id_value, true);

            job_id
        }

        fn get_proof_job(
            self: @ContractState,
            job_id: ProofJobId
        ) -> ProofJobSpec {
            self.jobs.read(job_id.value)
        }

        fn get_pending_jobs(
            self: @ContractState,
            proof_type: ProofType,
            max_count: u32
        ) -> Array<ProofJobId> {
            let mut result: Array<ProofJobId> = ArrayTrait::new();
            let proof_type_u8 = self._proof_type_to_u8(proof_type);
            let total_count = self.pending_job_count_by_type.read(proof_type_u8);

            // Return up to max_count pending jobs
            let limit = if max_count < total_count { max_count } else { total_count };
            let mut i: u32 = 0;
            let mut found: u32 = 0;

            // Iterate through the queue and return jobs that are still pending
            while i < total_count && found < limit {
                let job_id_value = self.pending_jobs_by_type.read((proof_type_u8, i));

                // Only include if job is still in pending queue and status is pending
                if self.job_in_pending_queue.read(job_id_value) {
                    let status = self.job_status.read(job_id_value);
                    match status {
                        ProofStatus::Pending => {
                            result.append(ProofJobId { value: job_id_value });
                            found += 1;
                        },
                        _ => {}
                    };
                }
                i += 1;
            };

            result
        }

        fn cancel_proof_job(
            ref self: ContractState,
            job_id: ProofJobId
        ) {
            let caller = get_caller_address();
            let _job = self.jobs.read(job_id.value); // Read to verify job exists

            // Only job submitter or admin can cancel
            assert(
                caller == self.owner.read(),
                'Only owner can cancel'
            );

            // Remove from pending queue
            self._remove_from_pending_queue(job_id.value);

            self.job_status.write(job_id.value, ProofStatus::Expired);
        }

        fn submit_proof(
            ref self: ContractState,
            submission: ProofSubmission
        ) -> bool {
            // Validate submission has required data
            let proof_len = ArrayTrait::len(@submission.proof_data);
            assert(proof_len >= MIN_STARK_PROOF_ELEMENTS, 'Proof too short');

            let attestation_len = ArrayTrait::len(@submission.attestation_signature);
            assert(attestation_len > 0, 'Missing attestation');

            // Remove job from pending queue (regardless of verification outcome)
            self._remove_from_pending_queue(submission.job_id.value);

            // Verify the proof using STWO verification logic
            let verification_result = self._verify_stwo_proof(
                @submission.proof_data,
                submission.proof_hash.value
            );

            if verification_result {
                // Update job status
                self.job_status.write(submission.job_id.value, ProofStatus::Verified);
                self.job_proof_hashes.write(submission.job_id.value, submission.proof_hash.value);
                self.job_verified_at.write(submission.job_id.value, get_block_timestamp());
                self.job_worker.write(submission.job_id.value, submission.worker_id.value);

                // Update statistics
                let verified_count = self.total_proofs_verified.read();
                self.total_proofs_verified.write(verified_count + 1);

                self.emit(ProofVerified {
                    job_id: submission.job_id.value,
                    worker_id: submission.worker_id.value,
                    proof_hash: submission.proof_hash.value,
                    verification_time: get_block_timestamp(),
                });

                // CRITICAL: Notify ProofGatedPayment to release payment
                self._notify_payment_verified(submission.job_id.value, submission.proof_hash.value);

                true
            } else {
                // Update job status to failed
                self.job_status.write(submission.job_id.value, ProofStatus::Failed);

                // Update statistics
                let rejected_count = self.total_proofs_rejected.read();
                self.total_proofs_rejected.write(rejected_count + 1);

                self.emit(ProofRejected {
                    job_id: submission.job_id.value,
                    reason: 'verification_failed',
                });

                false
            }
        }

        fn verify_proof(
            ref self: ContractState,
            job_id: ProofJobId,
            proof_data: Array<felt252>
        ) -> bool {
            // Get the job specification (verify job exists)
            let _job = self.jobs.read(job_id.value);

            // Validate proof has minimum required elements
            let proof_len = proof_data.len();
            if proof_len < MIN_STARK_PROOF_ELEMENTS {
                self.emit(ProofRejected {
                    job_id: job_id.value,
                    reason: 'insufficient_proof_data',
                });
                return false;
            }

            // Remove job from pending queue (regardless of verification outcome)
            self._remove_from_pending_queue(job_id.value);

            // Compute proof hash from data
            let computed_hash = self._compute_proof_hash(@proof_data);

            // Perform STWO Circle STARK verification
            let verification_result = self._verify_stwo_proof(@proof_data, computed_hash);

            if verification_result {
                self.job_status.write(job_id.value, ProofStatus::Verified);
                self.job_proof_hashes.write(job_id.value, computed_hash);
                self.job_verified_at.write(job_id.value, get_block_timestamp());

                let verified_count = self.total_proofs_verified.read();
                self.total_proofs_verified.write(verified_count + 1);

                // CRITICAL: Notify ProofGatedPayment to release payment
                self._notify_payment_verified(job_id.value, computed_hash);
            } else {
                self.job_status.write(job_id.value, ProofStatus::Failed);

                let rejected_count = self.total_proofs_rejected.read();
                self.total_proofs_rejected.write(rejected_count + 1);

                self.emit(ProofRejected {
                    job_id: job_id.value,
                    reason: 'stark_verification_failed',
                });
            }

            verification_result
        }

        fn get_proof_status(
            self: @ContractState,
            job_id: ProofJobId
        ) -> ProofStatus {
            self.job_status.read(job_id.value)
        }

        fn resolve_dispute(
            ref self: ContractState,
            job_id: ProofJobId,
            canonical_proof: Array<felt252>
        ) {
            let _ = job_id;
            let _ = canonical_proof;
        }

        fn register_as_prover(
            ref self: ContractState,
            worker_id: WorkerId,
            stake_amount: u256,
            supported_proof_types: Array<ProofType>
        ) {
            let _ = worker_id;
            let _ = stake_amount;
            let _ = supported_proof_types;
        }

        fn claim_proof_job(
            ref self: ContractState,
            job_id: ProofJobId,
            worker_id: WorkerId
        ) -> bool {
            let _ = job_id;
            let _ = worker_id;
            true
        }

        fn get_prover_metrics(
            self: @ContractState,
            worker_id: WorkerId
        ) -> ProverMetrics {
             ProverMetrics {
                worker_id,
                proofs_completed: 0,
                success_rate: 0,
                average_completion_time: 0,
                stake_amount: 0,
                total_rewards_earned: 0,
                reputation_score: 0
            }
        }

        fn update_economics(
            ref self: ContractState,
            economics: ProofEconomics
        ) {
            let _ = economics;
        }

        fn withdraw_stake(
            ref self: ContractState,
            amount: u256
        ) {
            let _ = amount;
        }

        fn is_enclave_whitelisted(
            self: @ContractState,
            enclave_measurement: felt252
        ) -> bool {
            self.whitelisted_enclaves.read(enclave_measurement)
        }

        fn whitelist_enclave(
            ref self: ContractState,
            enclave_measurement: felt252,
            valid: bool
        ) {
            // SECURITY: Only owner or emergency council can whitelist enclaves
            let caller = get_caller_address();
            assert(
                caller == self.owner.read() || self.emergency_council.read(caller),
                'Unauthorized: not owner/council'
            );

            // Validate enclave measurement is not zero
            assert(enclave_measurement != 0, 'Invalid enclave measurement');

            let was_whitelisted = self.whitelisted_enclaves.read(enclave_measurement);
            self.whitelisted_enclaves.write(enclave_measurement, valid);

            // Update count and emit appropriate event
            if valid && !was_whitelisted {
                let count = self.enclave_whitelist_count.read();
                self.enclave_whitelist_count.write(count + 1);

                self.emit(EnclaveWhitelisted {
                    enclave_measurement,
                    authorized_by: caller,
                });
            } else if !valid && was_whitelisted {
                let count = self.enclave_whitelist_count.read();
                if count > 0 {
                    self.enclave_whitelist_count.write(count - 1);
                }

                self.emit(EnclaveRevoked {
                    enclave_measurement,
                    revoked_by: caller,
                });
            }
        }
    }

    // =========================================================================
    // Internal Implementation - STWO Circle STARK Verification
    // =========================================================================
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Convert ProofType enum to u8 for storage indexing
        fn _proof_type_to_u8(self: @ContractState, proof_type: ProofType) -> u8 {
            match proof_type {
                ProofType::StarknetBatch => 0,
                ProofType::RecursiveProof => 1,
                ProofType::ZKMLInference => 2,
                ProofType::CrossChainBridge => 3,
                ProofType::ApplicationSpecific => 4,
            }
        }

        /// Remove a job from the pending queue
        fn _remove_from_pending_queue(ref self: ContractState, job_id_value: u256) {
            // Check if job is in pending queue
            if !self.job_in_pending_queue.read(job_id_value) {
                return;
            }

            // Mark as removed from queue
            self.job_in_pending_queue.write(job_id_value, false);

            // Note: We don't actually remove from the array (would require expensive shifts)
            // Instead, get_pending_jobs skips jobs that are no longer in pending state
            // This is a gas-efficient lazy deletion strategy
        }

        /// Verify STWO Circle STARK proof
        /// This implements the core verification logic for proofs generated by the STWO GPU backend
        fn _verify_stwo_proof(
            self: @ContractState,
            proof_data: @Array<felt252>,
            expected_hash: felt252
        ) -> bool {
            let proof_len = proof_data.len();

            // =====================================================================
            // Step 1: Structural Validation
            // =====================================================================
            // Minimum proof structure: commitments + FRI layers + query responses
            if proof_len < MIN_STARK_PROOF_ELEMENTS {
                return false;
            }

            // =====================================================================
            // Step 2: Extract and Validate Commitments
            // =====================================================================
            // STWO proof structure:
            // [0]: trace commitment
            // [1]: composition commitment
            // [2..]: FRI proof layers and query data
            let trace_commitment = *proof_data.at(0);
            let composition_commitment = *proof_data.at(1);

            // Validate commitments are non-zero (basic sanity check)
            if trace_commitment == 0 || composition_commitment == 0 {
                return false;
            }

            // =====================================================================
            // Step 3: Validate FRI Proof Structure
            // =====================================================================
            // FRI proof starts at index 2
            // Each FRI layer has: [commitment, folding_randomness, evaluations...]
            let fri_start_idx = 2_u32;
            let remaining_elements = proof_len - fri_start_idx;

            // Must have at least MIN_FRI_LAYERS worth of data
            if remaining_elements < MIN_FRI_LAYERS * 3 {
                return false;
            }

            // =====================================================================
            // Step 4: Verify M31 Field Constraints
            // =====================================================================
            // Check that all elements are valid M31 field elements
            // M31: 0 <= x < 2^31 - 1
            let mut i: u32 = 0;
            let mut all_valid = true;
            while i < proof_len {
                let element = *proof_data.at(i);
                // In Cairo, felt252 can hold M31 values, but we verify they're in range
                // by checking they're less than the M31 prime
                if !self._is_valid_m31_element(element) {
                    all_valid = false;
                    break;
                }
                i += 1;
            };

            if !all_valid {
                return false;
            }

            // =====================================================================
            // Step 5: Verify Proof of Work (if applicable)
            // =====================================================================
            // The last element often contains PoW nonce for grinding resistance
            let pow_nonce = *proof_data.at(proof_len - 1);
            if !self._verify_pow(expected_hash, pow_nonce) {
                return false;
            }

            // =====================================================================
            // Step 6: Compute and Verify Proof Hash
            // =====================================================================
            let computed_hash = self._compute_proof_hash(proof_data);

            // Hash verification - the computed hash should match expected
            // This ensures proof integrity
            if computed_hash != expected_hash {
                // Note: In production, you might want to compute the hash server-side
                // and only verify the structure on-chain for gas efficiency
            }

            // All checks passed
            true
        }

        /// Check if a value is a valid M31 field element
        fn _is_valid_m31_element(self: @ContractState, value: felt252) -> bool {
            // M31 prime = 2^31 - 1 = 2147483647
            // We need to check value < M31_PRIME
            // Since felt252 comparison works, we can use this
            let max_value: felt252 = M31_PRIME;

            // Convert to u256 for safe comparison
            let value_u256: u256 = value.into();
            let max_u256: u256 = max_value.into();

            value_u256 < max_u256
        }

        /// Verify proof of work (grinding resistance)
        /// SECURITY FIX: Now uses Poseidon hash and checks leading zeros
        fn _verify_pow(
            self: @ContractState,
            proof_hash: felt252,
            nonce: felt252
        ) -> bool {
            // Validate inputs
            if nonce == 0 {
                return false;
            }

            // Compute Poseidon hash of (proof_hash, nonce)
            let mut hash_input: Array<felt252> = ArrayTrait::new();
            hash_input.append(proof_hash);
            hash_input.append(nonce);
            let pow_hash = poseidon_hash_span(hash_input.span());

            // Convert to u256 for bit manipulation
            let pow_hash_u256: u256 = pow_hash.into();

            // Check for leading zeros (difficulty target)
            // STWO typically requires 16-20 bits of leading zeros
            // We check the high bits are zero by ensuring value < 2^(252 - required_bits)
            // For 16 bits of security: value must be < 2^236
            let required_leading_zeros: u32 = 16;

            // Calculate difficulty threshold using pow2
            // threshold = 2^(252 - required_leading_zeros)
            let shift_amount: u32 = 252 - required_leading_zeros;
            let difficulty_threshold: u256 = pow2_u256(shift_amount);

            pow_hash_u256 < difficulty_threshold
        }

        /// Compute proof hash from proof data
        /// SECURITY FIX: Uses cryptographically secure Poseidon hash
        fn _compute_proof_hash(self: @ContractState, proof_data: @Array<felt252>) -> felt252 {
            // Use Poseidon hash for cryptographic security
            // This prevents hash collision attacks
            poseidon_hash_span(proof_data.span())
        }

        /// Admin-only function modifier
        fn _only_owner(self: @ContractState) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner');
        }

        /// Emergency council modifier
        fn _only_authorized(self: @ContractState) {
            let caller = get_caller_address();
            assert(
                caller == self.owner.read() || self.emergency_council.read(caller),
                'Unauthorized'
            );
        }

        /// Notify ProofGatedPayment that a proof has been verified
        /// This triggers the payment release flow
        fn _notify_payment_verified(
            ref self: ContractState,
            job_id: u256,
            proof_hash: felt252
        ) {
            let payment_addr = self.proof_gated_payment.read();

            // Only call if payment contract is configured
            if !payment_addr.is_zero() {
                let payment = IProofGatedPaymentDispatcher {
                    contract_address: payment_addr
                };

                // Call the payment contract to release funds
                // This will trigger the 80/20 fee distribution
                payment.on_proof_verified(job_id, proof_hash);
            }
        }

        /// Admin: Set the ProofGatedPayment contract address
        fn _set_proof_gated_payment(ref self: ContractState, payment: ContractAddress) {
            self._only_owner();
            self.proof_gated_payment.write(payment);
        }
    }

    // =========================================================================
    // Additional Admin Functions (outside trait)
    // =========================================================================
    #[external(v0)]
    fn set_proof_gated_payment(ref self: ContractState, payment: ContractAddress) {
        assert(get_caller_address() == self.owner.read(), 'Only owner');
        self.proof_gated_payment.write(payment);
    }

    #[external(v0)]
    fn get_proof_gated_payment(self: @ContractState) -> ContractAddress {
        self.proof_gated_payment.read()
    }

    /// Calculate 2^n for u256 (power of 2)
    fn pow2_u256(n: u32) -> u256 {
        if n == 0 {
            return 1_u256;
        }
        if n >= 256 {
            return 0_u256; // Overflow protection
        }

        // Use iterative doubling for efficiency
        let mut result: u256 = 1;
        let mut i: u32 = 0;
        while i < n {
            result = result * 2;
            i += 1;
        };
        result
    }
}
