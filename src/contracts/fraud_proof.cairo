// SPDX-License-Identifier: MIT
// BitSage Network - Optimistic Fraud Proof System

#[starknet::contract]
mod FraudProof {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, 
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use sage_contracts::interfaces::proof_verifier::{IProofVerifierDispatcher, IProofVerifierDispatcherTrait, ProofJobId, ProofStatus};
    use sage_contracts::contracts::staking::{IWorkerStakingDispatcher, IWorkerStakingDispatcherTrait};

    // Challenge status
    #[derive(Drop, Serde, Copy, PartialEq, starknet::Store)]
    #[allow(starknet::store_no_default_variant)]
    enum ChallengeStatus {
        Pending,
        ValidProof,    // Challenger wins
        InvalidProof,  // Worker wins
        Expired,       // No resolution
    }

    // Verification method
    #[derive(Drop, Serde, Copy, PartialEq)]
    enum VerificationMethod {
        ZKProof,           // ZK-SNARK verification (EZKL)
        HashComparison,    // Simple hash verification
        TEEAttestation,    // Hardware TEE verification
        ManualArbitration, // DAO/Committee vote
    }

    // Challenge record
    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct Challenge {
        challenge_id: u256,
        job_id: u256,
        worker_id: felt252,
        challenger: ContractAddress,
        deposit: u256,
        original_result_hash: felt252,
        disputed_result_hash: felt252,
        verification_method: u8,
        status: ChallengeStatus,
        created_at: u64,
        resolved_at: u64,
        evidence_hash: felt252,
    }

    // Arbitration vote
    #[derive(Drop, Serde, Copy, starknet::Store)]
    pub struct ArbitrationVote {
        voter: ContractAddress,
        supports_challenger: bool,
        voting_power: u256,
        voted_at: u64,
    }

    #[storage]
    struct Storage {
        // Admin
        owner: ContractAddress,
        job_manager: ContractAddress,
        staking_contract: ContractAddress,
        proof_verifier: ContractAddress, // Added for verification
        sage_token: ContractAddress,
        
        // Challenge parameters
        challenge_deposit: u256,        // 500 SAGE
        challenge_period: u64,          // 24 hours
        arbitration_period: u64,        // 48 hours
        min_arbitration_threshold: u256, // Min job value for arbitration
        
        // Challenges
        next_challenge_id: u256,
        challenges: Map<u256, Challenge>,
        job_challenges: Map<u256, u256>, // job_id -> challenge_id
        total_challenges: u64,
        valid_challenges: u64,
        invalid_challenges: u64,
        
        // Arbitration
        challenge_votes: Map<(u256, ContractAddress), ArbitrationVote>,
        challenge_vote_counts: Map<u256, (u256, u256)>, // (support, oppose)
        arbitration_quorum: u256, // Min votes needed
        
        // Slashing penalties (basis points)
        minor_violation_penalty: u16,    // 100 = 1%
        major_violation_penalty: u16,    // 1000 = 10%
        critical_violation_penalty: u16, // 5000 = 50%
        
        // Statistics
        total_slashed: u256,
        total_rewards_paid: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ChallengeSubmitted: ChallengeSubmitted,
        ChallengeResolved: ChallengeResolved,
        VoteCast: VoteCast,
        FraudDetected: FraudDetected,
        WorkerSlashed: WorkerSlashed,
    }

    #[derive(Drop, starknet::Event)]
    struct ChallengeSubmitted {
        #[key]
        challenge_id: u256,
        #[key]
        job_id: u256,
        worker_id: felt252,
        challenger: ContractAddress,
        deposit: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ChallengeResolved {
        #[key]
        challenge_id: u256,
        status: ChallengeStatus,
        winner: ContractAddress,
        reward: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct VoteCast {
        #[key]
        challenge_id: u256,
        voter: ContractAddress,
        supports_challenger: bool,
        voting_power: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct FraudDetected {
        #[key]
        job_id: u256,
        worker_id: felt252,
        penalty_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerSlashed {
        #[key]
        worker_id: felt252,
        amount: u256,
        reason: felt252,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        staking_contract: ContractAddress,
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.staking_contract.write(staking_contract);
        
        // Set default parameters
        self.challenge_deposit.write(500000000000000000000); // 500 SAGE
        self.challenge_period.write(86400); // 24 hours
        self.arbitration_period.write(172800); // 48 hours
        self.min_arbitration_threshold.write(10000000000000000000000); // 10,000 SAGE
        self.arbitration_quorum.write(1000000000000000000000); // 1,000 SAGE voting power
        
        // Set slashing penalties
        self.minor_violation_penalty.write(100);   // 1%
        self.major_violation_penalty.write(1000);  // 10%
        self.critical_violation_penalty.write(5000); // 50%
        
        self.next_challenge_id.write(1);
    }

    #[abi(embed_v0)]
    impl FraudProofImpl of super::IFraudProof<ContractState> {
        /// Submit fraud proof challenge
        fn submit_challenge(
            ref self: ContractState,
            job_id: u256,
            worker_id: felt252,
            original_result_hash: felt252,
            disputed_result_hash: felt252,
            verification_method: u8,
            evidence_hash: felt252,
        ) -> u256 {
            let challenger = get_caller_address();
            
            // Check if job already has active challenge
            let existing_challenge_id = self.job_challenges.read(job_id);
            if existing_challenge_id > 0 {
                let existing = self.challenges.read(existing_challenge_id);
                assert!(existing.status != ChallengeStatus::Pending, "Challenge already active");
            }
            
            // Require deposit
            let deposit = self.challenge_deposit.read();
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let success = token.transfer_from(challenger, starknet::get_contract_address(), deposit);
            assert!(success, "Deposit transfer failed");
            
            // Create challenge
            let challenge_id = self.next_challenge_id.read();
            let challenge = Challenge {
                challenge_id,
                job_id,
                worker_id,
                challenger,
                deposit,
                original_result_hash,
                disputed_result_hash,
                verification_method,
                status: ChallengeStatus::Pending,
                created_at: get_block_timestamp(),
                resolved_at: 0,
                evidence_hash,
            };
            
            self.challenges.write(challenge_id, challenge);
            self.job_challenges.write(job_id, challenge_id);
            self.next_challenge_id.write(challenge_id + 1);
            self.total_challenges.write(self.total_challenges.read() + 1);
            
            self.emit(ChallengeSubmitted {
                challenge_id,
                job_id,
                worker_id,
                challenger,
                deposit,
            });
            
            challenge_id
        }

        /// Resolve challenge automatically (for simple verifications)
        fn resolve_challenge(ref self: ContractState, challenge_id: u256) {
            let mut challenge = self.challenges.read(challenge_id);
            assert!(challenge.status == ChallengeStatus::Pending, "Challenge not pending");
            
            let current_time = get_block_timestamp();
            
            // Check if challenge period expired
            if current_time > challenge.created_at + self.challenge_period.read() {
                challenge.status = ChallengeStatus::Expired;
                challenge.resolved_at = current_time;
                self.challenges.write(challenge_id, challenge);
                return;
            }
            
            // Verify based on method
            let is_valid = if challenge.verification_method == 0 {
                // ZKProof - TODO: Implement ZK verification
                self._verify_zk_proof(challenge.evidence_hash, challenge.disputed_result_hash)
            } else if challenge.verification_method == 1 {
                // HashComparison - Simple comparison
                challenge.original_result_hash != challenge.disputed_result_hash
            } else if challenge.verification_method == 2 {
                // TEEAttestation - Verify hardware attestation
                self._verify_tee_attestation(challenge.evidence_hash)
            } else {
                // ManualArbitration - Requires voting
                false
            };
            
            if is_valid {
                self._resolve_valid_challenge(challenge_id);
            } else {
                self._resolve_invalid_challenge(challenge_id);
            }
        }

        /// Cast vote on challenge requiring arbitration
        fn vote_on_challenge(
            ref self: ContractState,
            challenge_id: u256,
            supports_challenger: bool,
        ) {
            let voter = get_caller_address();
            let challenge = self.challenges.read(challenge_id);
            
            assert!(challenge.status == ChallengeStatus::Pending, "Challenge not pending");
            assert!(challenge.verification_method == 3, "Not arbitration challenge");
            
            // Check arbitration period
            let current_time = get_block_timestamp();
            assert!(
                current_time <= challenge.created_at + self.arbitration_period.read(),
                "Arbitration period expired"
            );
            
            // Get voter's voting power (based on staked SAGE)
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let voting_power = token.balance_of(voter);
            assert!(voting_power > 0, "No voting power");
            
            // Record vote
            let vote = ArbitrationVote {
                voter,
                supports_challenger,
                voting_power,
                voted_at: current_time,
            };
            
            self.challenge_votes.write((challenge_id, voter), vote);
            
            // Update vote counts
            let (mut support, mut oppose) = self.challenge_vote_counts.read(challenge_id);
            if supports_challenger {
                support += voting_power;
            } else {
                oppose += voting_power;
            }
            self.challenge_vote_counts.write(challenge_id, (support, oppose));
            
            self.emit(VoteCast {
                challenge_id,
                voter,
                supports_challenger,
                voting_power,
            });
            
            // Check if quorum reached
            if support + oppose >= self.arbitration_quorum.read() {
                if support > oppose {
                    self._resolve_valid_challenge(challenge_id);
                } else {
                    self._resolve_invalid_challenge(challenge_id);
                }
            }
        }

        /// Finalize arbitration after voting period
        fn finalize_arbitration(ref self: ContractState, challenge_id: u256) {
            let challenge = self.challenges.read(challenge_id);
            
            assert!(challenge.status == ChallengeStatus::Pending, "Challenge not pending");
            assert!(challenge.verification_method == 3, "Not arbitration challenge");
            
            let current_time = get_block_timestamp();
            assert!(
                current_time > challenge.created_at + self.arbitration_period.read(),
                "Arbitration period not ended"
            );
            
            // Tally votes
            let (support, oppose) = self.challenge_vote_counts.read(challenge_id);
            
            if support + oppose < self.arbitration_quorum.read() {
                // Quorum not reached - invalid challenge
                self._resolve_invalid_challenge(challenge_id);
            } else if support > oppose {
                self._resolve_valid_challenge(challenge_id);
            } else {
                self._resolve_invalid_challenge(challenge_id);
            }
        }

        /// Get challenge details
        fn get_challenge(self: @ContractState, challenge_id: u256) -> Challenge {
            self.challenges.read(challenge_id)
        }

        /// Get challenge for job
        fn get_job_challenge(self: @ContractState, job_id: u256) -> u256 {
            self.job_challenges.read(job_id)
        }

        /// Get network stats
        fn get_stats(self: @ContractState) -> (u64, u64, u64, u256, u256) {
            (
                self.total_challenges.read(),
                self.valid_challenges.read(),
                self.invalid_challenges.read(),
                self.total_slashed.read(),
                self.total_rewards_paid.read(),
            )
        }

        /// Admin: Set job manager
        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.job_manager.write(job_manager);
        }

        fn set_proof_verifier(ref self: ContractState, proof_verifier: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.proof_verifier.write(proof_verifier);
        }

        /// Admin: Update parameters
        fn update_challenge_deposit(ref self: ContractState, amount: u256) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.challenge_deposit.write(amount);
        }

        fn update_challenge_period(ref self: ContractState, period: u64) {
            assert!(get_caller_address() == self.owner.read(), "Not owner");
            self.challenge_period.write(period);
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        /// Resolve valid challenge (challenger wins)
        fn _resolve_valid_challenge(ref self: ContractState, challenge_id: u256) {
            let mut challenge = self.challenges.read(challenge_id);
            challenge.status = ChallengeStatus::ValidProof;
            challenge.resolved_at = get_block_timestamp();
            self.challenges.write(challenge_id, challenge);
            
            self.valid_challenges.write(self.valid_challenges.read() + 1);
            
            // Slash worker
            let penalty_bps = self._determine_penalty(challenge.verification_method);
            let staking_contract = self.staking_contract.read();
            
            // Call staking contract to slash
            let staking_dispatcher = IWorkerStakingDispatcher { contract_address: staking_contract };
            staking_dispatcher.slash(challenge.worker_id, penalty_bps, 'fraud_proof', challenge.challenger);
            
            // Reward challenger (50% of slashed amount + deposit back)
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(challenge.challenger, challenge.deposit);
            
            self.emit(ChallengeResolved {
                challenge_id,
                status: ChallengeStatus::ValidProof,
                winner: challenge.challenger,
                reward: challenge.deposit,
            });
            
            self.emit(FraudDetected {
                job_id: challenge.job_id,
                worker_id: challenge.worker_id,
                penalty_amount: 0, // TODO: Calculate from slashing
            });
        }

        /// Resolve invalid challenge (worker wins)
        fn _resolve_invalid_challenge(ref self: ContractState, challenge_id: u256) {
            let mut challenge = self.challenges.read(challenge_id);
            challenge.status = ChallengeStatus::InvalidProof;
            challenge.resolved_at = get_block_timestamp();
            self.challenges.write(challenge_id, challenge);
            
            self.invalid_challenges.write(self.invalid_challenges.read() + 1);
            
            // Challenger loses deposit (burned or to treasury)
            let token = IERC20Dispatcher { contract_address: self.sage_token.read() };
            token.transfer(self.owner.read(), challenge.deposit); // To treasury
            
            self.emit(ChallengeResolved {
                challenge_id,
                status: ChallengeStatus::InvalidProof,
                winner: 0.try_into().unwrap(), // Worker wins (zero address)
                reward: 0_u256,
            });
        }

        /// Determine penalty based on violation severity
        fn _determine_penalty(self: @ContractState, verification_method: u8) -> u16 {
            if verification_method == 0 {
                // ZK Proof fraud = Critical
                self.critical_violation_penalty.read()
            } else if verification_method == 2 {
                // TEE attestation failure = Major
                self.major_violation_penalty.read()
            } else {
                // Hash mismatch = Major
                self.major_violation_penalty.read()
            }
        }

        /// Verify ZK proof via ProofVerifier oracle
        fn _verify_zk_proof(self: @ContractState, proof_hash: felt252, result_hash: felt252) -> bool {
            let _ = result_hash; // TODO: Verify proof matches result hash
            let proof_verifier = IProofVerifierDispatcher { contract_address: self.proof_verifier.read() };
            let job_id = ProofJobId { value: proof_hash.into() };
            
            let status = proof_verifier.get_proof_status(job_id);
            match status {
                ProofStatus::Verified => true,
                _ => false
            }
        }

        /// Verify TEE attestation via ProofVerifier oracle
        fn _verify_tee_attestation(self: @ContractState, attestation_hash: felt252) -> bool {
            let proof_verifier = IProofVerifierDispatcher { contract_address: self.proof_verifier.read() };
            let job_id = ProofJobId { value: attestation_hash.into() };
            
            let status = proof_verifier.get_proof_status(job_id);
            match status {
                ProofStatus::Verified => true,
                _ => false
            }
        }
    }
}

#[starknet::interface]
pub trait IFraudProof<TContractState> {
    fn submit_challenge(
        ref self: TContractState,
        job_id: u256,
        worker_id: felt252,
        original_result_hash: felt252,
        disputed_result_hash: felt252,
        verification_method: u8,
        evidence_hash: felt252,
    ) -> u256;
    fn resolve_challenge(ref self: TContractState, challenge_id: u256);
    fn vote_on_challenge(ref self: TContractState, challenge_id: u256, supports_challenger: bool);
    fn finalize_arbitration(ref self: TContractState, challenge_id: u256);
    fn get_challenge(self: @TContractState, challenge_id: u256) -> FraudProof::Challenge;
    fn get_job_challenge(self: @TContractState, job_id: u256) -> u256;
    fn get_stats(self: @TContractState) -> (u64, u64, u64, u256, u256);
    fn set_job_manager(ref self: TContractState, job_manager: starknet::ContractAddress);
    fn set_proof_verifier(ref self: TContractState, proof_verifier: starknet::ContractAddress);
    fn update_challenge_deposit(ref self: TContractState, amount: u256);
    fn update_challenge_period(ref self: TContractState, period: u64);
}

