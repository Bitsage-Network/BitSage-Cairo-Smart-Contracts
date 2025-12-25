#[starknet::contract]
mod OptimisticTEE {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use core::array::Array;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use sage_contracts::interfaces::proof_verifier::{
        IProofVerifierDispatcher, IProofVerifierDispatcherTrait, ProofJobId, ProofStatus
    };
    use sage_contracts::payments::proof_gated_payment::{
        IProofGatedPaymentDispatcher, IProofGatedPaymentDispatcherTrait
    };
    use sage_contracts::staking::prover_staking::{
        IProverStakingDispatcher, IProverStakingDispatcherTrait, SlashReason
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    // Production TEE attestation verification
    use sage_contracts::obelysk::tee_attestation::{
        verify_attestation, verify_report_data_matches,
        TEE_TYPE_INTEL_TDX, TEE_TYPE_AMD_SEV_SNP, TEE_TYPE_NVIDIA_CC,
    };

    // TEE Result Status Constants
    const STATUS_PENDING: u8 = 0;
    const STATUS_FINALIZED: u8 = 1;
    const STATUS_CHALLENGED: u8 = 2;
    const STATUS_INVALID: u8 = 3;

    // Keeper Constants
    const DEFAULT_KEEPER_REWARD_BPS: u16 = 50; // 0.5% of job payment as keeper reward
    const MAX_BATCH_SIZE: u32 = 50; // Max jobs to finalize in one tx

    // Slash/Reward Constants
    const CHALLENGER_REWARD_BPS: u16 = 5000; // 50% of slashed amount goes to challenger
    const MIN_CHALLENGE_STAKE: u256 = 100000000000000000000; // 100 SAGE minimum stake

    #[derive(Drop, Serde, Copy, starknet::Store)]
    struct TEEResult {
        worker_id: felt252,
        worker_address: ContractAddress,
        result_hash: felt252,
        timestamp: u64,
        status: u8 // 0: Pending, 1: Finalized, 2: Challenged, 3: Invalid
    }

    #[derive(Drop, Serde, Copy, starknet::Store)]
    struct Challenge {
        challenger: ContractAddress,
        job_id: u256,
        evidence_hash: felt252,
        stake_amount: u256
    }

    #[storage]
    struct Storage {
        proof_verifier: ContractAddress,
        proof_gated_payment: ContractAddress,
        challenge_period: u64,
        challenge_stake: u256,           // Required stake to challenge
        tee_results: Map<u256, TEEResult>,
        challenges: Map<u256, Challenge>,
        owner: ContractAddress,
        // Worker address mapping
        worker_addresses: Map<felt252, ContractAddress>,

        // === KEEPER INFRASTRUCTURE ===
        // Pending jobs queue (for keepers to scan)
        pending_job_ids: Map<u64, u256>,      // index -> job_id
        pending_job_count: u64,                // total pending jobs
        job_pending_index: Map<u256, u64>,     // job_id -> index (for O(1) removal)
        job_in_queue: Map<u256, bool>,         // job_id -> is_in_queue

        // Keeper reward configuration
        sage_token: ContractAddress,           // SAGE token for rewards
        keeper_reward_bps: u16,                // Basis points (50 = 0.5%)
        keeper_reward_pool: u256,              // Pool of SAGE for keeper rewards
        job_payment_amounts: Map<u256, u256>,  // job_id -> payment amount (for reward calc)

        // Keeper stats
        total_keeper_rewards_paid: u256,
        total_jobs_finalized_by_keepers: u64,

        // === STAKING & SLASHING ===
        prover_staking: ContractAddress,           // ProverStaking contract
        require_staking: bool,                      // Enforce staking requirement
        challenger_stakes: Map<u256, u256>,         // job_id -> actual stake locked
        challenger_stake_locked: Map<u256, bool>,   // job_id -> stake collected

        // Slash/reward stats
        total_workers_slashed: u64,
        total_slash_amount: u256,
        total_challenger_rewards: u256,

        // === TEE ATTESTATION VERIFICATION ===
        // Nonce tracking for replay protection
        job_nonces: Map<u256, felt252>,           // job_id -> expected nonce
        used_nonces: Map<felt252, bool>,          // nonce -> already used
        nonce_counter: u64,                        // Global nonce counter
        // Verified attestation results
        verified_attestations: Map<u256, felt252>, // job_id -> attestation hash
        // TEE type per job
        job_tee_types: Map<u256, u8>,             // job_id -> TEE type used
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ResultSubmitted: ResultSubmitted,
        ResultChallenged: ResultChallenged,
        ResultFinalized: ResultFinalized,
        // Keeper events
        BatchFinalized: BatchFinalized,
        KeeperRewarded: KeeperRewarded,
        KeeperPoolFunded: KeeperPoolFunded,
        // Slashing events
        WorkerSlashed: WorkerSlashed,
        ChallengerRewarded: ChallengerRewarded,
        ChallengerSlashed: ChallengerSlashed,
        ChallengeStakeCollected: ChallengeStakeCollected,
    }

    #[derive(Drop, starknet::Event)]
    struct ResultSubmitted {
        job_id: u256,
        worker_id: felt252,
        result_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ResultChallenged {
        job_id: u256,
        challenger: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ResultFinalized {
        job_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct BatchFinalized {
        #[key]
        keeper: ContractAddress,
        jobs_finalized: u32,
        total_reward: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct KeeperRewarded {
        #[key]
        keeper: ContractAddress,
        #[key]
        job_id: u256,
        reward_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct KeeperPoolFunded {
        funder: ContractAddress,
        amount: u256,
        new_pool_balance: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerSlashed {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        slash_amount: u256,
        challenger_reward: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ChallengerRewarded {
        #[key]
        job_id: u256,
        #[key]
        challenger: ContractAddress,
        stake_returned: u256,
        reward_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ChallengerSlashed {
        #[key]
        job_id: u256,
        #[key]
        challenger: ContractAddress,
        stake_lost: u256,
        worker_reward: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ChallengeStakeCollected {
        #[key]
        job_id: u256,
        #[key]
        challenger: ContractAddress,
        stake_amount: u256,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        proof_verifier: ContractAddress,
        proof_gated_payment: ContractAddress,
        sage_token: ContractAddress,
        prover_staking: ContractAddress,
        owner: ContractAddress
    ) {
        self.proof_verifier.write(proof_verifier);
        self.proof_gated_payment.write(proof_gated_payment);
        self.sage_token.write(sage_token);
        self.prover_staking.write(prover_staking);
        self.owner.write(owner);
        self.challenge_period.write(14400); // 4 hours
        self.challenge_stake.write(MIN_CHALLENGE_STAKE); // 100 SAGE to challenge

        // Initialize keeper settings
        self.keeper_reward_bps.write(DEFAULT_KEEPER_REWARD_BPS);
        self.pending_job_count.write(0);
        self.keeper_reward_pool.write(0);

        // Initialize staking settings
        self.require_staking.write(true); // Enforce staking by default
        self.total_workers_slashed.write(0);
        self.total_slash_amount.write(0);
        self.total_challenger_rewards.write(0);
    }

    #[abi(embed_v0)]
    impl OptimisticTEEImpl of super::IOptimisticTEE<ContractState> {
        /// Submit a TEE-attested result with full cryptographic verification
        ///
        /// # Arguments
        /// * `job_id` - The job identifier
        /// * `worker_id` - Worker identifier (must match report_data in quote)
        /// * `result_hash` - Hash of computation result (must match report_data in quote)
        /// * `enclave_measurement` - Expected enclave/TD measurement
        /// * `tee_type` - Type of TEE (1=TDX, 2=SEV-SNP, 3=NVIDIA)
        /// * `attestation_quote` - Full attestation quote from TEE hardware
        fn submit_result(
            ref self: ContractState,
            job_id: u256,
            worker_id: felt252,
            result_hash: felt252,
            enclave_measurement: felt252,
            tee_type: u8,
            attestation_quote: Array<felt252>
        ) {
            let worker_address = get_caller_address();
            let current_timestamp = get_block_timestamp();

            // === SECURITY CHECK 1: Worker Staking Requirement ===
            if self.require_staking.read() {
                let staking_addr = self.prover_staking.read();
                if !staking_addr.is_zero() {
                    let staking = IProverStakingDispatcher { contract_address: staking_addr };
                    assert!(staking.is_eligible(worker_address), "Worker not staked or ineligible");
                }
            }

            // === SECURITY CHECK 2: Validate TEE Type ===
            assert!(
                tee_type == TEE_TYPE_INTEL_TDX
                || tee_type == TEE_TYPE_AMD_SEV_SNP
                || tee_type == TEE_TYPE_NVIDIA_CC,
                "Invalid TEE type"
            );

            // === SECURITY CHECK 3: Enclave Whitelist ===
            let verifier = IProofVerifierDispatcher { contract_address: self.proof_verifier.read() };
            assert!(verifier.is_enclave_whitelisted(enclave_measurement), "Enclave not whitelisted");

            // === SECURITY CHECK 4: Get Expected Nonce (Replay Protection) ===
            let expected_nonce = self.job_nonces.read(job_id);
            assert!(expected_nonce != 0, "No nonce registered for job - call request_attestation first");
            assert!(!self.used_nonces.read(expected_nonce), "Nonce already used - replay attack");

            // === SECURITY CHECK 5: Cryptographic Attestation Verification ===
            let verification_result = verify_attestation(
                tee_type,
                attestation_quote.span(),
                enclave_measurement,
                expected_nonce,
                current_timestamp,
            );

            assert!(verification_result.is_valid, "TEE attestation verification failed");
            assert!(verification_result.tee_type == tee_type, "TEE type mismatch in quote");

            // === SECURITY CHECK 6: Verify Report Data Matches Claimed Result ===
            // The TEE hardware embeds result_hash and worker_id in report_data
            // This proves the TEE actually computed and signed this specific result
            let report_data_valid = verify_report_data_matches(
                verification_result.report_data,  // report_data_high from verified quote
                0,  // report_data_low (extended data, zero if not provided)
                result_hash,
                worker_id,
            );
            assert!(report_data_valid, "Report data mismatch - result not from this TEE");

            // === SECURITY CHECK 7: Mark Nonce as Used ===
            self.used_nonces.write(expected_nonce, true);

            // === Store Verified Result ===
            self.worker_addresses.write(worker_id, worker_address);
            self.job_tee_types.write(job_id, tee_type);

            // Store attestation hash for audit trail
            let attestation_hash = poseidon_hash_span(attestation_quote.span());
            self.verified_attestations.write(job_id, attestation_hash);

            let result = TEEResult {
                worker_id,
                worker_address,
                result_hash,
                timestamp: current_timestamp,
                status: STATUS_PENDING
            };
            self.tee_results.write(job_id, result);

            // Add to pending jobs queue for keeper finalization
            self._add_to_pending_queue(job_id);

            self.emit(ResultSubmitted { job_id, worker_id, result_hash });
        }

        /// Submit result with payment amount (for keeper reward calculation)
        /// This version includes the job payment amount for keeper reward calculations
        fn submit_result_with_payment(
            ref self: ContractState,
            job_id: u256,
            worker_id: felt252,
            result_hash: felt252,
            enclave_measurement: felt252,
            tee_type: u8,
            attestation_quote: Array<felt252>,
            payment_amount: u256  // Job payment amount for keeper reward calc
        ) {
            // Store payment amount for keeper rewards
            self.job_payment_amounts.write(job_id, payment_amount);

            // Call standard submit with full TEE verification
            self.submit_result(job_id, worker_id, result_hash, enclave_measurement, tee_type, attestation_quote);
        }

        /// Request attestation for a job - generates and registers a nonce
        /// Must be called before worker submits result to get the expected nonce
        /// Returns the nonce that must be embedded in the TEE attestation quote
        fn request_attestation(ref self: ContractState, job_id: u256) -> felt252 {
            // Increment global nonce counter
            let counter = self.nonce_counter.read();
            self.nonce_counter.write(counter + 1);

            // Generate unique nonce using poseidon hash
            let nonce = poseidon_hash_span(
                array![
                    job_id.low.into(),
                    job_id.high.into(),
                    counter.into(),
                    get_block_timestamp().into(),
                    get_caller_address().into()
                ].span()
            );

            // Register nonce for this job
            self.job_nonces.write(job_id, nonce);

            nonce
        }

        /// Get the expected nonce for a job (view function)
        fn get_job_nonce(self: @ContractState, job_id: u256) -> felt252 {
            self.job_nonces.read(job_id)
        }

        /// Check if a nonce has been used
        fn is_nonce_used(self: @ContractState, nonce: felt252) -> bool {
            self.used_nonces.read(nonce)
        }

        /// Get the TEE type used for a job
        fn get_job_tee_type(self: @ContractState, job_id: u256) -> u8 {
            self.job_tee_types.read(job_id)
        }

        /// Get verified attestation hash for audit
        fn get_attestation_hash(self: @ContractState, job_id: u256) -> felt252 {
            self.verified_attestations.read(job_id)
        }

        fn challenge_result(
            ref self: ContractState,
            job_id: u256,
            evidence_hash: felt252
        ) {
            let mut result = self.tee_results.read(job_id);
            assert!(result.status == STATUS_PENDING, "Result not pending");

            // Check if challenge period active
            let time_passed = get_block_timestamp() - result.timestamp;
            assert!(time_passed < self.challenge_period.read(), "Challenge period expired");

            let challenger = get_caller_address();
            let stake_required = self.challenge_stake.read();

            // CRITICAL: Collect actual stake from challenger
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = sage.transfer_from(challenger, get_contract_address(), stake_required);
            assert!(success, "Challenger stake transfer failed");

            // Track that we collected the stake
            self.challenger_stakes.write(job_id, stake_required);
            self.challenger_stake_locked.write(job_id, true);

            // Record Challenge
            result.status = STATUS_CHALLENGED;
            self.tee_results.write(job_id, result);

            // Remove from pending queue (challenged jobs can't be auto-finalized)
            self._remove_from_pending_queue(job_id);

            let challenge = Challenge {
                challenger,
                job_id,
                evidence_hash,
                stake_amount: stake_required
            };
            self.challenges.write(job_id, challenge);

            self.emit(ChallengeStakeCollected {
                job_id,
                challenger,
                stake_amount: stake_required,
                timestamp: get_block_timestamp(),
            });

            self.emit(ResultChallenged { job_id, challenger });
        }

        fn resolve_challenge(
            ref self: ContractState,
            job_id: u256,
            zk_proof_id: u256
        ) {
            let challenge = self.challenges.read(job_id);
            let mut result = self.tee_results.read(job_id);
            assert!(result.status == STATUS_CHALLENGED, "Not challenged");

            // Verify ZK Proof via ProofVerifier
            let verifier = IProofVerifierDispatcher { contract_address: self.proof_verifier.read() };
            let proof_job_id = ProofJobId { value: zk_proof_id };
            let status = verifier.get_proof_status(proof_job_id);

            let payment = IProofGatedPaymentDispatcher {
                contract_address: self.proof_gated_payment.read()
            };

            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let challenger_stake = self.challenger_stakes.read(job_id);
            let now = get_block_timestamp();

            match status {
                ProofStatus::Verified => {
                    // ZK proof shows worker was DISHONEST - Challenger Wins!
                    result.status = STATUS_INVALID;
                    self.tee_results.write(job_id, result);

                    // 1. Slash worker via ProverStaking
                    let staking_addr = self.prover_staking.read();
                    if !staking_addr.is_zero() {
                        let staking = IProverStakingDispatcher { contract_address: staking_addr };
                        // Convert job_id to felt252 for the slash call
                        let job_id_felt: felt252 = job_id.try_into().unwrap_or(0);
                        staking.slash(result.worker_address, SlashReason::InvalidProof, job_id_felt);

                        // Update stats
                        let workers_slashed = self.total_workers_slashed.read();
                        self.total_workers_slashed.write(workers_slashed + 1);

                        self.emit(WorkerSlashed {
                            job_id,
                            worker: result.worker_address,
                            slash_amount: 0, // Actual amount determined by ProverStaking
                            challenger_reward: challenger_stake,
                            timestamp: now,
                        });
                    }

                    // 2. Return challenger stake + reward
                    // Challenger gets their stake back
                    let transfer_success = sage.transfer(challenge.challenger, challenger_stake);
                    assert!(transfer_success, "Challenger reward transfer failed");

                    let rewards = self.total_challenger_rewards.read();
                    self.total_challenger_rewards.write(rewards + challenger_stake);

                    self.emit(ChallengerRewarded {
                        job_id,
                        challenger: challenge.challenger,
                        stake_returned: challenger_stake,
                        reward_amount: 0, // Additional reward from worker slash goes via ProverStaking
                        timestamp: now,
                    });

                    // Mark stake as handled
                    self.challenger_stake_locked.write(job_id, false);

                    // Notify payment system - challenger wins, no payment to worker
                    payment.on_challenge_resolved(job_id, true);
                },
                ProofStatus::Failed => {
                    // ZK proof failed - Worker was HONEST, challenger made false accusation
                    result.status = STATUS_FINALIZED;
                    self.tee_results.write(job_id, result);

                    // 1. Challenger loses their stake (goes to worker as compensation)
                    let half_stake = challenger_stake / 2;
                    let worker_reward = half_stake;
                    let protocol_fee = challenger_stake - half_stake;

                    // Worker gets 50% of challenger stake
                    let worker_transfer = sage.transfer(result.worker_address, worker_reward);
                    assert!(worker_transfer, "Worker reward transfer failed");

                    // Protocol keeps 50% (add to keeper pool or treasury)
                    let current_pool = self.keeper_reward_pool.read();
                    self.keeper_reward_pool.write(current_pool + protocol_fee);

                    self.emit(ChallengerSlashed {
                        job_id,
                        challenger: challenge.challenger,
                        stake_lost: challenger_stake,
                        worker_reward,
                        timestamp: now,
                    });

                    // Mark stake as handled
                    self.challenger_stake_locked.write(job_id, false);

                    // Notify payment system - worker wins, release payment
                    payment.on_challenge_resolved(job_id, false);
                },
                _ => {
                    // Proof still pending - cannot resolve yet
                    assert!(false, "Proof not finalized");
                }
            }
        }

        fn finalize_result(ref self: ContractState, job_id: u256) {
            let mut result = self.tee_results.read(job_id);
            assert!(result.status == STATUS_PENDING, "Not pending");

            let time_passed = get_block_timestamp() - result.timestamp;
            assert!(time_passed >= self.challenge_period.read(), "Challenge period active");

            // Update status to finalized
            result.status = STATUS_FINALIZED;
            self.tee_results.write(job_id, result);

            // Remove from pending queue
            self._remove_from_pending_queue(job_id);

            // CRITICAL: Trigger payment release via ProofGatedPayment
            let payment = IProofGatedPaymentDispatcher {
                contract_address: self.proof_gated_payment.read()
            };
            payment.on_tee_finalized(job_id);

            self.emit(ResultFinalized { job_id });
        }

        // =====================================================================
        // KEEPER FUNCTIONS - Batch finalization with rewards
        // =====================================================================

        /// Batch finalize multiple jobs - called by keepers
        /// Returns total reward earned
        fn batch_finalize(ref self: ContractState, job_ids: Array<u256>) -> u256 {
            let keeper = get_caller_address();
            let mut total_reward: u256 = 0;
            let mut jobs_finalized: u32 = 0;

            assert!(job_ids.len() <= MAX_BATCH_SIZE, "Batch too large");

            let mut i: u32 = 0;
            let job_ids_span = job_ids.span();

            while i < job_ids_span.len() {
                let job_id = *job_ids_span.at(i);

                // Check if job can be finalized
                if self._can_finalize_internal(job_id) {
                    // Finalize the job
                    self._finalize_internal(job_id);

                    // Calculate and track reward
                    let reward = self._calculate_keeper_reward(job_id);
                    total_reward += reward;
                    jobs_finalized += 1;
                }

                i += 1;
            };

            // Pay keeper if any jobs were finalized
            if total_reward > 0 && jobs_finalized > 0 {
                self._pay_keeper(keeper, total_reward);

                // Update stats
                let total_paid = self.total_keeper_rewards_paid.read();
                self.total_keeper_rewards_paid.write(total_paid + total_reward);

                let total_finalized = self.total_jobs_finalized_by_keepers.read();
                self.total_jobs_finalized_by_keepers.write(total_finalized + jobs_finalized.into());
            }

            self.emit(BatchFinalized {
                keeper,
                jobs_finalized,
                total_reward,
                timestamp: get_block_timestamp(),
            });

            total_reward
        }

        /// Finalize all ready jobs up to max_count - convenience for keepers
        fn finalize_ready_jobs(ref self: ContractState, max_count: u32) -> u256 {
            let ready_jobs = self._get_finalizable_jobs(max_count);
            self.batch_finalize(ready_jobs)
        }

        /// Fund the keeper reward pool (anyone can fund)
        fn fund_keeper_pool(ref self: ContractState, amount: u256) {
            let funder = get_caller_address();
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };

            // Transfer SAGE to this contract
            let success = sage.transfer_from(funder, get_contract_address(), amount);
            assert!(success, "Transfer failed");

            // Update pool balance
            let current_pool = self.keeper_reward_pool.read();
            let new_pool = current_pool + amount;
            self.keeper_reward_pool.write(new_pool);

            self.emit(KeeperPoolFunded {
                funder,
                amount,
                new_pool_balance: new_pool,
            });
        }

        // === Admin Functions ===

        fn set_proof_gated_payment(ref self: ContractState, payment: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.proof_gated_payment.write(payment);
        }

        fn set_challenge_period(ref self: ContractState, period: u64) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.challenge_period.write(period);
        }

        fn set_challenge_stake(ref self: ContractState, stake: u256) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.challenge_stake.write(stake);
        }

        fn get_result_status(self: @ContractState, job_id: u256) -> u8 {
            self.tee_results.read(job_id).status
        }

        fn get_challenge_period(self: @ContractState) -> u64 {
            self.challenge_period.read()
        }

        fn is_finalized(self: @ContractState, job_id: u256) -> bool {
            self.tee_results.read(job_id).status == STATUS_FINALIZED
        }

        fn can_finalize(self: @ContractState, job_id: u256) -> bool {
            let result = self.tee_results.read(job_id);
            if result.status != STATUS_PENDING {
                return false;
            }
            let time_passed = get_block_timestamp() - result.timestamp;
            time_passed >= self.challenge_period.read()
        }

        // =====================================================================
        // KEEPER VIEW FUNCTIONS
        // =====================================================================

        /// Get number of pending jobs awaiting finalization
        fn get_pending_job_count(self: @ContractState) -> u64 {
            self.pending_job_count.read()
        }

        /// Get pending job ID at index
        fn get_pending_job_at(self: @ContractState, index: u64) -> u256 {
            assert!(index < self.pending_job_count.read(), "Index out of bounds");
            self.pending_job_ids.read(index)
        }

        /// Get list of finalizable jobs (ready for keeper action)
        fn get_finalizable_jobs(self: @ContractState, max_count: u32) -> Array<u256> {
            let mut result: Array<u256> = array![];
            let pending_count = self.pending_job_count.read();
            let challenge_period = self.challenge_period.read();
            let current_time = get_block_timestamp();

            let mut i: u64 = 0;
            let mut found: u32 = 0;

            while i < pending_count && found < max_count {
                let job_id = self.pending_job_ids.read(i);
                let tee_result = self.tee_results.read(job_id);

                if tee_result.status == STATUS_PENDING {
                    let time_passed = current_time - tee_result.timestamp;
                    if time_passed >= challenge_period {
                        result.append(job_id);
                        found += 1;
                    }
                }
                i += 1;
            };

            result
        }

        /// Get keeper reward pool balance
        fn get_keeper_pool_balance(self: @ContractState) -> u256 {
            self.keeper_reward_pool.read()
        }

        /// Get keeper reward BPS
        fn get_keeper_reward_bps(self: @ContractState) -> u16 {
            self.keeper_reward_bps.read()
        }

        /// Get keeper stats
        fn get_keeper_stats(self: @ContractState) -> (u256, u64) {
            (
                self.total_keeper_rewards_paid.read(),
                self.total_jobs_finalized_by_keepers.read()
            )
        }

        /// Estimate reward for finalizing a specific job
        fn estimate_keeper_reward(self: @ContractState, job_id: u256) -> u256 {
            let payment = self.job_payment_amounts.read(job_id);
            let bps = self.keeper_reward_bps.read();

            // Reward = payment * bps / 10000
            if payment == 0 {
                // Default fixed reward if no payment amount stored
                10000000000000000_u256 // 0.01 SAGE
            } else {
                (payment * bps.into()) / 10000
            }
        }

        // =====================================================================
        // KEEPER ADMIN FUNCTIONS
        // =====================================================================

        /// Set keeper reward basis points (admin only)
        fn set_keeper_reward_bps(ref self: ContractState, bps: u16) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            assert!(bps <= 500, "Max 5% reward"); // Cap at 5%
            self.keeper_reward_bps.write(bps);
        }

        /// Set SAGE token address (admin only)
        fn set_sage_token(ref self: ContractState, token: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.sage_token.write(token);
        }

        // =====================================================================
        // STAKING/SLASHING ADMIN FUNCTIONS
        // =====================================================================

        /// Set ProverStaking contract address (admin only)
        fn set_prover_staking(ref self: ContractState, staking: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.prover_staking.write(staking);
        }

        /// Enable/disable staking requirement (admin only)
        fn set_require_staking(ref self: ContractState, required: bool) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.require_staking.write(required);
        }

        // =====================================================================
        // STAKING/SLASHING VIEW FUNCTIONS
        // =====================================================================

        /// Get slashing statistics
        fn get_slash_stats(self: @ContractState) -> (u64, u256, u256) {
            (
                self.total_workers_slashed.read(),
                self.total_slash_amount.read(),
                self.total_challenger_rewards.read()
            )
        }

        /// Check if staking is required
        fn is_staking_required(self: @ContractState) -> bool {
            self.require_staking.read()
        }

        /// Get ProverStaking contract address
        fn get_prover_staking(self: @ContractState) -> ContractAddress {
            self.prover_staking.read()
        }

        /// Check if worker is eligible to submit results
        fn is_worker_eligible(self: @ContractState, worker: ContractAddress) -> bool {
            if !self.require_staking.read() {
                return true;
            }

            let staking_addr = self.prover_staking.read();
            if staking_addr.is_zero() {
                return true;
            }

            let staking = IProverStakingDispatcher { contract_address: staking_addr };
            staking.is_eligible(worker)
        }

        /// Get challenger stake amount for a job
        fn get_challenger_stake(self: @ContractState, job_id: u256) -> (u256, bool) {
            (
                self.challenger_stakes.read(job_id),
                self.challenger_stake_locked.read(job_id)
            )
        }

        /// Withdraw excess from keeper pool (admin only, for emergencies)
        fn withdraw_keeper_pool(ref self: ContractState, amount: u256, to: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            assert!(amount <= self.keeper_reward_pool.read(), "Insufficient pool");

            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = sage.transfer(to, amount);
            assert!(success, "Transfer failed");

            let new_pool = self.keeper_reward_pool.read() - amount;
            self.keeper_reward_pool.write(new_pool);
        }
    }

    // =========================================================================
    // INTERNAL HELPER FUNCTIONS
    // =========================================================================

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Add job to pending queue
        fn _add_to_pending_queue(ref self: ContractState, job_id: u256) {
            // Check if already in queue
            if self.job_in_queue.read(job_id) {
                return;
            }

            let index = self.pending_job_count.read();
            self.pending_job_ids.write(index, job_id);
            self.job_pending_index.write(job_id, index);
            self.job_in_queue.write(job_id, true);
            self.pending_job_count.write(index + 1);
        }

        /// Remove job from pending queue (swap-and-pop for O(1) removal)
        fn _remove_from_pending_queue(ref self: ContractState, job_id: u256) {
            // Check if in queue
            if !self.job_in_queue.read(job_id) {
                return;
            }

            let index = self.job_pending_index.read(job_id);
            let last_index = self.pending_job_count.read() - 1;

            // Swap with last element if not already last
            if index != last_index {
                let last_job_id = self.pending_job_ids.read(last_index);
                self.pending_job_ids.write(index, last_job_id);
                self.job_pending_index.write(last_job_id, index);
            }

            // Remove last element
            self.pending_job_count.write(last_index);
            self.job_in_queue.write(job_id, false);
        }

        /// Internal check if job can be finalized
        fn _can_finalize_internal(self: @ContractState, job_id: u256) -> bool {
            let result = self.tee_results.read(job_id);
            if result.status != STATUS_PENDING {
                return false;
            }
            let time_passed = get_block_timestamp() - result.timestamp;
            time_passed >= self.challenge_period.read()
        }

        /// Internal finalize without checks (called from batch_finalize)
        fn _finalize_internal(ref self: ContractState, job_id: u256) {
            let mut result = self.tee_results.read(job_id);

            // Update status to finalized
            result.status = STATUS_FINALIZED;
            self.tee_results.write(job_id, result);

            // Remove from pending queue
            self._remove_from_pending_queue(job_id);

            // Trigger payment release via ProofGatedPayment
            let payment = IProofGatedPaymentDispatcher {
                contract_address: self.proof_gated_payment.read()
            };
            payment.on_tee_finalized(job_id);

            self.emit(ResultFinalized { job_id });
        }

        /// Calculate keeper reward for a job
        fn _calculate_keeper_reward(self: @ContractState, job_id: u256) -> u256 {
            let payment = self.job_payment_amounts.read(job_id);
            let bps = self.keeper_reward_bps.read();
            let pool = self.keeper_reward_pool.read();

            // Calculate reward
            let reward = if payment == 0 {
                // Fixed reward if no payment amount
                10000000000000000_u256 // 0.01 SAGE
            } else {
                (payment * bps.into()) / 10000
            };

            // Cap at available pool
            if reward > pool {
                pool
            } else {
                reward
            }
        }

        /// Pay keeper their reward
        fn _pay_keeper(ref self: ContractState, keeper: ContractAddress, amount: u256) {
            let pool = self.keeper_reward_pool.read();
            if amount == 0 || pool == 0 {
                return;
            }

            let actual_amount = if amount > pool { pool } else { amount };

            // Deduct from pool
            self.keeper_reward_pool.write(pool - actual_amount);

            // Transfer to keeper
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let sage_addr = self.sage_token.read();

            if !sage_addr.is_zero() {
                let success = sage.transfer(keeper, actual_amount);
                if success {
                    self.emit(KeeperRewarded {
                        keeper,
                        job_id: 0, // Batch payment, no specific job
                        reward_amount: actual_amount,
                    });
                }
            }
        }

        /// Get list of finalizable jobs (internal, returns Array)
        fn _get_finalizable_jobs(self: @ContractState, max_count: u32) -> Array<u256> {
            let mut result: Array<u256> = array![];
            let pending_count = self.pending_job_count.read();
            let challenge_period = self.challenge_period.read();
            let current_time = get_block_timestamp();

            let mut i: u64 = 0;
            let mut found: u32 = 0;

            while i < pending_count && found < max_count {
                let job_id = self.pending_job_ids.read(i);
                let tee_result = self.tee_results.read(job_id);

                if tee_result.status == STATUS_PENDING {
                    let time_passed = current_time - tee_result.timestamp;
                    if time_passed >= challenge_period {
                        result.append(job_id);
                        found += 1;
                    }
                }
                i += 1;
            };

            result
        }
    }
}

use starknet::ContractAddress;

#[starknet::interface]
pub trait IOptimisticTEE<TContractState> {
    // =========================================================================
    // CORE FUNCTIONS - TEE Result Submission with Cryptographic Verification
    // =========================================================================

    /// Submit a TEE-attested result with full cryptographic verification
    /// Verifies: staking, enclave whitelist, nonce, attestation quote, report data
    fn submit_result(
        ref self: TContractState,
        job_id: u256,
        worker_id: felt252,
        result_hash: felt252,
        enclave_measurement: felt252,
        tee_type: u8,                    // 1=TDX, 2=SEV-SNP, 3=NVIDIA
        attestation_quote: Array<felt252>  // Full TEE attestation quote
    );

    /// Submit result with payment amount for keeper reward calculation
    fn submit_result_with_payment(
        ref self: TContractState,
        job_id: u256,
        worker_id: felt252,
        result_hash: felt252,
        enclave_measurement: felt252,
        tee_type: u8,
        attestation_quote: Array<felt252>,
        payment_amount: u256
    );

    /// Request attestation nonce for a job (must be called before submit)
    fn request_attestation(ref self: TContractState, job_id: u256) -> felt252;

    fn challenge_result(ref self: TContractState, job_id: u256, evidence_hash: felt252);
    fn resolve_challenge(ref self: TContractState, job_id: u256, zk_proof_id: u256);
    fn finalize_result(ref self: TContractState, job_id: u256);

    // =========================================================================
    // KEEPER FUNCTIONS - Batch finalization with rewards
    // =========================================================================
    fn batch_finalize(ref self: TContractState, job_ids: Array<u256>) -> u256;
    fn finalize_ready_jobs(ref self: TContractState, max_count: u32) -> u256;
    fn fund_keeper_pool(ref self: TContractState, amount: u256);

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================
    fn set_proof_gated_payment(ref self: TContractState, payment: ContractAddress);
    fn set_challenge_period(ref self: TContractState, period: u64);
    fn set_challenge_stake(ref self: TContractState, stake: u256);
    fn set_keeper_reward_bps(ref self: TContractState, bps: u16);
    fn set_sage_token(ref self: TContractState, token: ContractAddress);
    fn withdraw_keeper_pool(ref self: TContractState, amount: u256, to: ContractAddress);

    // Staking admin functions
    fn set_prover_staking(ref self: TContractState, staking: ContractAddress);
    fn set_require_staking(ref self: TContractState, required: bool);

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================
    fn get_result_status(self: @TContractState, job_id: u256) -> u8;
    fn get_challenge_period(self: @TContractState) -> u64;
    fn is_finalized(self: @TContractState, job_id: u256) -> bool;
    fn can_finalize(self: @TContractState, job_id: u256) -> bool;

    // Keeper view functions
    fn get_pending_job_count(self: @TContractState) -> u64;
    fn get_pending_job_at(self: @TContractState, index: u64) -> u256;
    fn get_finalizable_jobs(self: @TContractState, max_count: u32) -> Array<u256>;
    fn get_keeper_pool_balance(self: @TContractState) -> u256;
    fn get_keeper_reward_bps(self: @TContractState) -> u16;
    fn get_keeper_stats(self: @TContractState) -> (u256, u64);
    fn estimate_keeper_reward(self: @TContractState, job_id: u256) -> u256;

    // Staking/slashing view functions
    fn get_slash_stats(self: @TContractState) -> (u64, u256, u256);
    fn is_staking_required(self: @TContractState) -> bool;
    fn get_prover_staking(self: @TContractState) -> ContractAddress;
    fn is_worker_eligible(self: @TContractState, worker: ContractAddress) -> bool;
    fn get_challenger_stake(self: @TContractState, job_id: u256) -> (u256, bool);

    // =========================================================================
    // TEE ATTESTATION VIEW FUNCTIONS
    // =========================================================================

    /// Get the expected nonce for a job
    fn get_job_nonce(self: @TContractState, job_id: u256) -> felt252;

    /// Check if a nonce has been used (replay protection)
    fn is_nonce_used(self: @TContractState, nonce: felt252) -> bool;

    /// Get the TEE type used for a job (1=TDX, 2=SEV-SNP, 3=NVIDIA)
    fn get_job_tee_type(self: @TContractState, job_id: u256) -> u8;

    /// Get verified attestation hash for audit trail
    fn get_attestation_hash(self: @TContractState, job_id: u256) -> felt252;
}

