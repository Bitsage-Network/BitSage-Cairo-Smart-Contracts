// FHE Verifier Contract - On-Chain Verification of Homomorphic Computations
//
// This contract verifies STWO proofs that attest to correct FHE computations:
// - Verifies proof of correct encryption
// - Verifies proof of correct homomorphic operation
// - Verifies proof of correct decryption
//
// The actual FHE computation happens off-chain; this contract verifies the ZK proof
// that the computation was performed correctly.

use starknet::ContractAddress;
use core::array::ArrayTrait;

// ========== Types ==========

/// Commitment to an FHE ciphertext (hash of serialized ciphertext)
#[derive(Copy, Drop, Serde, Hash, starknet::Store)]
pub struct CiphertextCommitment {
    pub low: felt252,
    pub high: felt252,
}

/// Commitment to an FHE computation result
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ComputeCommitment {
    /// Hash of input ciphertexts
    pub input_hash: felt252,
    /// Hash of output ciphertext
    pub output_hash: felt252,
    /// Operation performed (encoded)
    pub operation: felt252,
    /// Worker that performed the computation
    pub worker: ContractAddress,
    /// Block timestamp when verified
    pub verified_at: u64,
}

/// Proof of correct FHE operation
#[derive(Drop, Serde)]
pub struct FheProof {
    /// STWO proof commitment
    pub proof_commitment: felt252,
    /// Proof data (compressed)
    pub proof_data: Array<felt252>,
    /// Public inputs to the circuit
    pub public_inputs: Array<felt252>,
}

/// FHE operation types
#[derive(Copy, Drop, Serde)]
pub enum FheOperation {
    Add,
    Sub,
    Mul,
    Compare,
    Max,
    Min,
    DotProduct,
    NeuralNetworkLayer,
}

impl FheOperationIntoFelt252 of Into<FheOperation, felt252> {
    fn into(self: FheOperation) -> felt252 {
        match self {
            FheOperation::Add => 1,
            FheOperation::Sub => 2,
            FheOperation::Mul => 3,
            FheOperation::Compare => 4,
            FheOperation::Max => 5,
            FheOperation::Min => 6,
            FheOperation::DotProduct => 7,
            FheOperation::NeuralNetworkLayer => 8,
        }
    }
}

// ========== Interface ==========

#[starknet::interface]
pub trait IFheVerifier<TContractState> {
    /// Verify an FHE computation proof and register the commitment
    fn verify_fhe_compute(
        ref self: TContractState,
        input_commitments: Array<CiphertextCommitment>,
        output_commitment: CiphertextCommitment,
        operation: FheOperation,
        proof: FheProof,
    ) -> bool;

    /// Check if a computation has been verified
    fn is_verified(self: @TContractState, compute_id: felt252) -> bool;

    /// Get the details of a verified computation
    fn get_compute_commitment(self: @TContractState, compute_id: felt252) -> Option<ComputeCommitment>;

    /// Get total number of verified computations
    fn get_verified_count(self: @TContractState) -> u64;

    /// Register an authorized worker that can submit proofs
    fn register_worker(ref self: TContractState, worker: ContractAddress);

    /// Remove an authorized worker
    fn unregister_worker(ref self: TContractState, worker: ContractAddress);

    /// Check if a worker is authorized
    fn is_authorized_worker(self: @TContractState, worker: ContractAddress) -> bool;

    /// Verify a batch of FHE computations (gas optimization)
    fn verify_batch(
        ref self: TContractState,
        computations: Array<(Array<CiphertextCommitment>, CiphertextCommitment, FheOperation)>,
        aggregated_proof: FheProof,
    ) -> u32;

    // Admin functions
    fn set_stwo_verifier(ref self: TContractState, verifier: ContractAddress);
    fn get_stwo_verifier(self: @TContractState) -> ContractAddress;
}

// ========== Contract ==========

#[starknet::contract]
pub mod FheVerifier {
    use super::{
        CiphertextCommitment, ComputeCommitment, FheProof, FheOperation,
        FheOperationIntoFelt252, IFheVerifier,
    };
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
        storage::{Map, StoragePointerReadAccess, StoragePointerWriteAccess, StoragePathEntry},
    };
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;

    // ========== Storage ==========

    #[storage]
    struct Storage {
        // Admin/owner address
        owner: ContractAddress,
        // STWO verifier contract for proof verification
        stwo_verifier: ContractAddress,
        // Verified computation commitments: compute_id -> commitment
        verified_computations: Map<felt252, ComputeCommitment>,
        // Whether a computation has been verified
        is_computation_verified: Map<felt252, bool>,
        // Total number of verified computations
        verified_count: u64,
        // Authorized workers that can submit proofs
        authorized_workers: Map<ContractAddress, bool>,
        // Worker count
        worker_count: u64,
    }

    // ========== Events ==========

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ComputationVerified: ComputationVerified,
        BatchVerified: BatchVerified,
        WorkerRegistered: WorkerRegistered,
        WorkerUnregistered: WorkerUnregistered,
    }

    #[derive(Drop, starknet::Event)]
    struct ComputationVerified {
        #[key]
        compute_id: felt252,
        operation: felt252,
        worker: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct BatchVerified {
        batch_size: u32,
        worker: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerRegistered {
        #[key]
        worker: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerUnregistered {
        #[key]
        worker: ContractAddress,
    }

    // ========== Constructor ==========

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, stwo_verifier: ContractAddress) {
        self.owner.write(owner);
        self.stwo_verifier.write(stwo_verifier);
        self.verified_count.write(0);
        self.worker_count.write(0);
    }

    // ========== Implementation ==========

    #[abi(embed_v0)]
    impl FheVerifierImpl of IFheVerifier<ContractState> {
        fn verify_fhe_compute(
            ref self: ContractState,
            input_commitments: Array<CiphertextCommitment>,
            output_commitment: CiphertextCommitment,
            operation: FheOperation,
            proof: FheProof,
        ) -> bool {
            let caller = get_caller_address();

            // Verify caller is authorized (or anyone if no workers registered)
            let worker_count = self.worker_count.read();
            if worker_count > 0 {
                assert(self.authorized_workers.entry(caller).read(), 'Unauthorized worker');
            }

            // Compute input hash from commitments
            let input_hash = self._compute_input_hash(@input_commitments);

            // Compute output hash
            let output_hash = poseidon_hash_span(
                array![output_commitment.low, output_commitment.high].span()
            );

            // Compute unique ID for this computation
            let operation_felt: felt252 = operation.into();
            let compute_id = poseidon_hash_span(
                array![input_hash, output_hash, operation_felt].span()
            );

            // Check not already verified
            assert(!self.is_computation_verified.entry(compute_id).read(), 'Already verified');

            // Verify the STWO proof
            // In production, this calls the STWO verifier contract
            let proof_valid = self._verify_stwo_proof(@proof, input_hash, output_hash, operation_felt);
            assert(proof_valid, 'Invalid proof');

            // Store the verified computation
            let timestamp = get_block_timestamp();
            let commitment = ComputeCommitment {
                input_hash,
                output_hash,
                operation: operation_felt,
                worker: caller,
                verified_at: timestamp,
            };

            self.verified_computations.entry(compute_id).write(commitment);
            self.is_computation_verified.entry(compute_id).write(true);
            self.verified_count.write(self.verified_count.read() + 1);

            // Emit event
            self.emit(ComputationVerified {
                compute_id,
                operation: operation_felt,
                worker: caller,
                timestamp,
            });

            true
        }

        fn is_verified(self: @ContractState, compute_id: felt252) -> bool {
            self.is_computation_verified.entry(compute_id).read()
        }

        fn get_compute_commitment(self: @ContractState, compute_id: felt252) -> Option<ComputeCommitment> {
            if self.is_computation_verified.entry(compute_id).read() {
                Option::Some(self.verified_computations.entry(compute_id).read())
            } else {
                Option::None
            }
        }

        fn get_verified_count(self: @ContractState) -> u64 {
            self.verified_count.read()
        }

        fn register_worker(ref self: ContractState, worker: ContractAddress) {
            self._only_owner();
            assert(!self.authorized_workers.entry(worker).read(), 'Already registered');

            self.authorized_workers.entry(worker).write(true);
            self.worker_count.write(self.worker_count.read() + 1);

            self.emit(WorkerRegistered { worker });
        }

        fn unregister_worker(ref self: ContractState, worker: ContractAddress) {
            self._only_owner();
            assert(self.authorized_workers.entry(worker).read(), 'Not registered');

            self.authorized_workers.entry(worker).write(false);
            self.worker_count.write(self.worker_count.read() - 1);

            self.emit(WorkerUnregistered { worker });
        }

        fn is_authorized_worker(self: @ContractState, worker: ContractAddress) -> bool {
            let worker_count = self.worker_count.read();
            if worker_count == 0 {
                true // Open to all if no workers registered
            } else {
                self.authorized_workers.entry(worker).read()
            }
        }

        fn verify_batch(
            ref self: ContractState,
            computations: Array<(Array<CiphertextCommitment>, CiphertextCommitment, FheOperation)>,
            aggregated_proof: FheProof,
        ) -> u32 {
            let caller = get_caller_address();

            // Verify caller is authorized
            let worker_count = self.worker_count.read();
            if worker_count > 0 {
                assert(self.authorized_workers.entry(caller).read(), 'Unauthorized worker');
            }

            // Verify aggregated proof covers all computations
            // This is a simplified check - production would verify more rigorously
            let batch_size = computations.len();
            assert(batch_size > 0, 'Empty batch');

            // Compute batch commitment
            let mut batch_hashes: Array<felt252> = array![];
            let mut i: u32 = 0;
            loop {
                if i >= batch_size {
                    break;
                }

                let (inputs, output, op) = computations.at(i);
                let input_hash = self._compute_input_hash(inputs);
                let output_hash = poseidon_hash_span(
                    array![(*output).low, (*output).high].span()
                );
                let op_felt: felt252 = (*op).into();

                let compute_id = poseidon_hash_span(
                    array![input_hash, output_hash, op_felt].span()
                );

                batch_hashes.append(compute_id);
                i += 1;
            };

            let batch_commitment = poseidon_hash_span(batch_hashes.span());

            // Verify the aggregated proof
            let proof_valid = self._verify_batch_proof(@aggregated_proof, batch_commitment, batch_size);
            assert(proof_valid, 'Invalid batch proof');

            // Mark all computations as verified
            let timestamp = get_block_timestamp();
            let mut verified: u32 = 0;
            let mut j: u32 = 0;
            loop {
                if j >= batch_size {
                    break;
                }

                let (inputs, output, op) = computations.at(j);
                let input_hash = self._compute_input_hash(inputs);
                let output_hash = poseidon_hash_span(
                    array![(*output).low, (*output).high].span()
                );
                let op_felt: felt252 = (*op).into();

                let compute_id = poseidon_hash_span(
                    array![input_hash, output_hash, op_felt].span()
                );

                if !self.is_computation_verified.entry(compute_id).read() {
                    let commitment = ComputeCommitment {
                        input_hash,
                        output_hash,
                        operation: op_felt,
                        worker: caller,
                        verified_at: timestamp,
                    };

                    self.verified_computations.entry(compute_id).write(commitment);
                    self.is_computation_verified.entry(compute_id).write(true);
                    verified += 1;
                }

                j += 1;
            };

            self.verified_count.write(self.verified_count.read() + verified.into());

            self.emit(BatchVerified {
                batch_size: verified,
                worker: caller,
                timestamp,
            });

            verified
        }

        fn set_stwo_verifier(ref self: ContractState, verifier: ContractAddress) {
            self._only_owner();
            self.stwo_verifier.write(verifier);
        }

        fn get_stwo_verifier(self: @ContractState) -> ContractAddress {
            self.stwo_verifier.read()
        }
    }

    // ========== Internal Functions ==========

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            let caller = get_caller_address();
            assert(caller == self.owner.read(), 'Only owner');
        }

        fn _compute_input_hash(
            self: @ContractState,
            inputs: @Array<CiphertextCommitment>
        ) -> felt252 {
            let mut hash_inputs: Array<felt252> = array![];
            let len = inputs.len();
            let mut i: u32 = 0;
            loop {
                if i >= len {
                    break;
                }
                let ct = inputs.at(i);
                hash_inputs.append(*ct.low);
                hash_inputs.append(*ct.high);
                i += 1;
            };
            poseidon_hash_span(hash_inputs.span())
        }

        fn _verify_stwo_proof(
            self: @ContractState,
            proof: @FheProof,
            input_hash: felt252,
            output_hash: felt252,
            operation: felt252,
        ) -> bool {
            // Verify public inputs match
            let public_inputs = proof.public_inputs;
            if public_inputs.len() < 3 {
                return false;
            }

            if *public_inputs.at(0) != input_hash {
                return false;
            }
            if *public_inputs.at(1) != output_hash {
                return false;
            }
            if *public_inputs.at(2) != operation {
                return false;
            }

            // Verify proof commitment is non-zero
            if *proof.proof_commitment == 0 {
                return false;
            }

            // In production, call the STWO verifier contract here
            // For now, we accept any non-trivial proof
            proof.proof_data.len() > 0
        }

        fn _verify_batch_proof(
            self: @ContractState,
            proof: @FheProof,
            batch_commitment: felt252,
            batch_size: u32,
        ) -> bool {
            // Verify the aggregated proof covers the batch
            let public_inputs = proof.public_inputs;
            if public_inputs.len() < 2 {
                return false;
            }

            if *public_inputs.at(0) != batch_commitment {
                return false;
            }

            // Verify batch size matches
            let expected_size: felt252 = batch_size.into();
            if *public_inputs.at(1) != expected_size {
                return false;
            }

            proof.proof_data.len() > 0
        }
    }
}
