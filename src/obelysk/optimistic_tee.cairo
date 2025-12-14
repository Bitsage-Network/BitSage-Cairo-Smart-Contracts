#[starknet::contract]
mod OptimisticTEE {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use core::array::Array;
    use sage_contracts::interfaces::proof_verifier::{
        IProofVerifierDispatcher, IProofVerifierDispatcherTrait, ProofJobId, ProofStatus
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, 
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };

    #[derive(Drop, Serde, Copy, starknet::Store)]
    struct TEEResult {
        worker_id: felt252,
        result_hash: felt252,
        timestamp: u64,
        status: u8 // 0: Pending, 1: Finalized, 2: Challenged
    }

    #[derive(Drop, Serde, Copy, starknet::Store)]
    struct Challenge {
        challenger: ContractAddress,
        job_id: u256,
        evidence_hash: felt252
    }

    #[storage]
    struct Storage {
        proof_verifier: ContractAddress,
        challenge_period: u64,
        tee_results: Map<u256, TEEResult>,
        challenges: Map<u256, Challenge>,
        owner: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ResultSubmitted: ResultSubmitted,
        ResultChallenged: ResultChallenged,
        ResultFinalized: ResultFinalized,
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

    #[constructor]
    fn constructor(ref self: ContractState, proof_verifier: ContractAddress, owner: ContractAddress) {
        self.proof_verifier.write(proof_verifier);
        self.owner.write(owner);
        self.challenge_period.write(14400); // 4 hours
    }

    #[abi(embed_v0)]
    impl OptimisticTEEImpl of super::IOptimisticTEE<ContractState> {
        fn submit_result(
            ref self: ContractState,
            job_id: u256,
            worker_id: felt252,
            result_hash: felt252,
            enclave_measurement: felt252,
            signature: Array<felt252> // TEE signature
        ) {
            // 1. Verify Enclave is Whitelisted
            let verifier = IProofVerifierDispatcher { contract_address: self.proof_verifier.read() };
            assert!(verifier.is_enclave_whitelisted(enclave_measurement), "Invalid Enclave");

            // 2. Verify Signature (Mock for now, would use signature verification syscall)
            assert!(signature.len() > 0, "Missing signature");

            // 3. Store Result
            let result = TEEResult {
                worker_id,
                result_hash,
                timestamp: get_block_timestamp(),
                status: 0 // Pending
            };
            self.tee_results.write(job_id, result);

            self.emit(ResultSubmitted { job_id, worker_id, result_hash });
        }

        fn challenge_result(
            ref self: ContractState,
            job_id: u256,
            evidence_hash: felt252
        ) {
            let mut result = self.tee_results.read(job_id);
            assert!(result.status == 0, "Result not pending");
            
            // Check if challenge period active
            let time_passed = get_block_timestamp() - result.timestamp;
            assert!(time_passed < self.challenge_period.read(), "Challenge period expired");

            // Record Challenge
            result.status = 2; // Challenged
            self.tee_results.write(job_id, result);

            let challenge = Challenge {
                challenger: get_caller_address(),
                job_id,
                evidence_hash
            };
            self.challenges.write(job_id, challenge); // One challenge per job for simplicity

            self.emit(ResultChallenged { job_id, challenger: challenge.challenger });
        }

        fn resolve_challenge(
            ref self: ContractState,
            job_id: u256,
            zk_proof_id: u256
        ) {
            let challenge = self.challenges.read(job_id);
            let result = self.tee_results.read(job_id);
            assert!(result.status == 2, "Not challenged");

            // Verify ZK Proof via Oracle
            let verifier = IProofVerifierDispatcher { contract_address: self.proof_verifier.read() };
            
            // Convert u256 ID to ProofJobId
            let proof_job_id = ProofJobId { value: zk_proof_id };
            let status = verifier.get_proof_status(proof_job_id);

            match status {
                ProofStatus::Verified => {
                    // Challenger Wins!
                    // In real logic: Slash worker, Reward challenger
                    // For now, just mark resolved?
                    // We might remove the result or mark it invalid.
                    // Currently TEEResult doesn't have Invalid status, so maybe we delete it?
                    // Or add status 3: Invalid.
                },
                _ => {
                    // Proof not verified yet or failed
                    // Do nothing, or require valid proof to resolve?
                    assert!(false, "Proof not verified");
                }
            }
        }

        fn finalize_result(ref self: ContractState, job_id: u256) {
            let mut result = self.tee_results.read(job_id);
            assert!(result.status == 0, "Not pending");

            let time_passed = get_block_timestamp() - result.timestamp;
            assert!(time_passed >= self.challenge_period.read(), "Challenge period active");

            result.status = 1; // Finalized
            self.tee_results.write(job_id, result);

            self.emit(ResultFinalized { job_id });
        }
    }
}

#[starknet::interface]
trait IOptimisticTEE<TContractState> {
    fn submit_result(
        ref self: TContractState,
        job_id: u256,
        worker_id: felt252,
        result_hash: felt252,
        enclave_measurement: felt252,
        signature: Array<felt252>
    );
    fn challenge_result(ref self: TContractState, job_id: u256, evidence_hash: felt252);
    fn resolve_challenge(ref self: TContractState, job_id: u256, zk_proof_id: u256);
    fn finalize_result(ref self: TContractState, job_id: u256);
}

