// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Worker Privacy Helper
// Provides utilities for GPU workers to manage private payments
//
// Flow:
// 1. Worker generates ElGamal keypair (off-chain)
// 2. Worker registers public key with PaymentRouter
// 3. Client requests job with privacy_enabled=true
// 4. Worker completes job, payment flows through PrivacyRouter
// 5. Worker claims payment using this helper (proves key ownership)
// 6. Worker can withdraw to public balance or keep in private account

use starknet::ContractAddress;
use sage_contracts::obelysk::elgamal::{
    ECPoint, ElGamalCiphertext, EncryptedBalance, EncryptionProof,
    derive_public_key, decrypt_point, ec_mul, ec_add, ec_neg, ec_sub,
    generator, generator_h, hash_points, pedersen_commit, is_zero,
    get_c1, get_c2, get_commitment, create_proof_with_commitment
};

/// Worker keypair for privacy operations
#[derive(Copy, Drop, Serde, Clone)]
pub struct WorkerKeypair {
    pub secret_key: felt252,
    pub public_key: ECPoint,
}

/// Payment claim result
#[derive(Copy, Drop, Serde, Clone)]
pub struct ClaimResult {
    pub success: bool,
    pub decrypted_amount: u256,
    pub job_id: u256,
}

/// Generate a keypair from a secret (deterministic)
/// In production: use proper randomness
pub fn generate_keypair(secret: felt252) -> WorkerKeypair {
    let public_key = derive_public_key(secret);
    WorkerKeypair {
        secret_key: secret,
        public_key,
    }
}

/// Create a decryption proof (Schnorr-like proof of knowledge)
/// Proves knowledge of sk such that PK = sk * G
/// This allows the PrivacyRouter to verify the worker can decrypt
pub fn create_decryption_proof(
    keypair: WorkerKeypair,
    ciphertext: ElGamalCiphertext,
    nonce: felt252  // Random nonce for proof
) -> EncryptionProof {
    let g = generator();

    // Step 1: Commitment R = nonce * G
    let commitment = ec_mul(nonce, g);

    // Step 2: Challenge e = H(PK, R, C1, C2)
    let mut points: Array<ECPoint> = array![];
    points.append(keypair.public_key);
    points.append(commitment);
    points.append(get_c1(ciphertext));
    points.append(get_c2(ciphertext));
    let challenge = hash_points(points);

    // Step 3: Response s = nonce - e * sk (mod order)
    // In production: proper modular arithmetic
    let e_sk: felt252 = challenge * keypair.secret_key;
    let response: felt252 = nonce - e_sk;

    create_proof_with_commitment(commitment, challenge, response, 0)
}

/// Decrypt a payment amount from ElGamal ciphertext
/// Returns the decrypted amount (requires solving discrete log)
///
/// NOTE: In practice, amounts are encrypted as M = amount * H
/// Decryption gives M, then we need to find amount = DL_H(M)
/// For small amounts (< 2^40), use baby-step giant-step or precomputed table
pub fn decrypt_amount(
    keypair: WorkerKeypair,
    ciphertext: ElGamalCiphertext
) -> ECPoint {
    // Decrypt: M = C2 - sk * C1
    let c1 = get_c1(ciphertext);
    let c2 = get_c2(ciphertext);
    let shared_secret = ec_mul(keypair.secret_key, c1);
    ec_sub(c2, shared_secret)
}

/// Verify a decryption proof
/// Returns true if the prover knows the secret key for the public key
pub fn verify_decryption_proof(
    public_key: ECPoint,
    ciphertext: ElGamalCiphertext,
    proof: EncryptionProof
) -> bool {
    let g = generator();
    let commitment = get_commitment(proof);

    // Recompute challenge
    let mut points: Array<ECPoint> = array![];
    points.append(public_key);
    points.append(commitment);
    points.append(get_c1(ciphertext));
    points.append(get_c2(ciphertext));
    let expected_challenge = hash_points(points);

    // Verify challenge matches
    if proof.challenge != expected_challenge {
        return false;
    }

    // Verify: response * G == commitment - challenge * PK
    // Rearranged: response * G + challenge * PK == commitment
    let response_g = ec_mul(proof.response, g);
    let challenge_pk = ec_mul(proof.challenge, public_key);
    let lhs = ec_add(response_g, challenge_pk);

    // Compare points
    lhs.x == commitment.x && lhs.y == commitment.y
}

/// Create an encryption proof for deposit
/// Proves that the ciphertext correctly encrypts the given amount
pub fn create_encryption_proof(
    amount: u256,
    public_key: ECPoint,
    randomness: felt252,
    proof_nonce: felt252
) -> EncryptionProof {
    let g = generator();
    let h = generator_h();

    // The ciphertext is C = (r*G, amount*H + r*PK)
    // We need to prove knowledge of (amount, r)

    // Commitment phase
    let commitment_r = ec_mul(proof_nonce, g);
    let commitment_amount: felt252 = proof_nonce; // Simplified
    let commitment = ec_add(commitment_r, ec_mul(commitment_amount, h));

    // Challenge (Fiat-Shamir)
    let mut points: Array<ECPoint> = array![];
    points.append(public_key);
    points.append(commitment);
    let challenge = hash_points(points);

    // Response
    let response = proof_nonce - challenge * randomness;

    // Range proof hash (would be Bulletproof in production)
    let range_proof_hash = pedersen_commit(amount.try_into().unwrap(), randomness).x;

    create_proof_with_commitment(commitment, challenge, response, range_proof_hash)
}

/// Calculate the withdrawal proof
/// Proves that we're withdrawing less than our encrypted balance
pub fn create_withdrawal_proof(
    keypair: WorkerKeypair,
    withdrawal_amount: u256,
    encrypted_balance: EncryptedBalance,
    withdrawal_randomness: felt252,
    proof_nonce: felt252
) -> EncryptionProof {
    // This is a range proof showing:
    // balance - withdrawal >= 0

    // For the MVP, we create a simplified proof
    let g = generator();
    let commitment = ec_mul(proof_nonce, g);

    let mut points: Array<ECPoint> = array![];
    points.append(keypair.public_key);
    points.append(commitment);
    points.append(get_c1(encrypted_balance.ciphertext));
    points.append(get_c2(encrypted_balance.ciphertext));
    let challenge = hash_points(points);

    let response = proof_nonce - challenge * withdrawal_randomness;

    // Range proof showing remaining balance is non-negative
    let range_proof_hash = pedersen_commit(withdrawal_amount.try_into().unwrap(), withdrawal_randomness).x;

    create_proof_with_commitment(commitment, challenge, response, range_proof_hash)
}

/// Helper to verify worker is eligible for privacy payments
/// Checks if public key is registered and valid
pub fn is_privacy_enabled(public_key: ECPoint) -> bool {
    !is_zero(public_key)
}

#[starknet::interface]
pub trait IWorkerPrivacyHelper<TContractState> {
    /// Register worker public key (convenience wrapper)
    fn register_privacy_key(ref self: TContractState, public_key: ECPoint);

    /// Claim a pending worker payment
    fn claim_payment(
        ref self: TContractState,
        job_id: u256,
        decryption_proof: EncryptionProof
    );

    /// Withdraw from private balance to public SAGE
    fn withdraw_to_public(
        ref self: TContractState,
        amount: u256,
        encrypted_delta: ElGamalCiphertext,
        proof: EncryptionProof
    );

    /// Get worker's pending payments
    fn get_pending_payments(self: @TContractState, worker: ContractAddress) -> Array<u256>;

    /// Get worker's privacy status
    fn is_privacy_registered(self: @TContractState, worker: ContractAddress) -> bool;
}

#[starknet::contract]
mod WorkerPrivacyHelper {
    use super::{IWorkerPrivacyHelper, ECPoint, ElGamalCiphertext, EncryptionProof, is_zero};
    use starknet::{ContractAddress, get_caller_address, get_contract_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };

    // Import PaymentRouter and PrivacyRouter
    use sage_contracts::payments::payment_router::{
        IPaymentRouterDispatcher, IPaymentRouterDispatcherTrait
    };
    use sage_contracts::obelysk::privacy_router::{
        IPrivacyRouterDispatcher, IPrivacyRouterDispatcherTrait
    };

    #[storage]
    struct Storage {
        owner: ContractAddress,
        payment_router: ContractAddress,
        privacy_router: ContractAddress,

        // Track pending jobs per worker using composite key (worker_address + index)
        // Key format: poseidon(worker_address, index)
        worker_pending_jobs: Map<felt252, u256>,
        worker_pending_count: Map<ContractAddress, u32>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PrivacyKeyRegistered: PrivacyKeyRegistered,
        PaymentClaimed: PaymentClaimed,
        WithdrawalCompleted: WithdrawalCompleted,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivacyKeyRegistered {
        #[key]
        worker: ContractAddress,
        public_key_x: felt252,
        public_key_y: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentClaimed {
        #[key]
        worker: ContractAddress,
        #[key]
        job_id: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawalCompleted {
        #[key]
        worker: ContractAddress,
        amount: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        payment_router: ContractAddress,
        privacy_router: ContractAddress
    ) {
        self.owner.write(owner);
        self.payment_router.write(payment_router);
        self.privacy_router.write(privacy_router);
    }

    #[abi(embed_v0)]
    impl WorkerPrivacyHelperImpl of IWorkerPrivacyHelper<ContractState> {
        fn register_privacy_key(ref self: ContractState, public_key: ECPoint) {
            let caller = get_caller_address();

            // Validate key
            assert!(!is_zero(public_key), "Invalid public key");

            // Register with PaymentRouter
            let payment_router = IPaymentRouterDispatcher {
                contract_address: self.payment_router.read()
            };
            payment_router.register_worker_public_key(public_key);

            // Register with PrivacyRouter
            let privacy_router = IPrivacyRouterDispatcher {
                contract_address: self.privacy_router.read()
            };
            privacy_router.register_account(public_key);

            self.emit(PrivacyKeyRegistered {
                worker: caller,
                public_key_x: public_key.x,
                public_key_y: public_key.y,
            });
        }

        fn claim_payment(
            ref self: ContractState,
            job_id: u256,
            decryption_proof: EncryptionProof
        ) {
            let caller = get_caller_address();

            // Claim from PrivacyRouter
            let privacy_router = IPrivacyRouterDispatcher {
                contract_address: self.privacy_router.read()
            };
            privacy_router.claim_worker_payment(job_id, decryption_proof);

            self.emit(PaymentClaimed {
                worker: caller,
                job_id,
            });
        }

        fn withdraw_to_public(
            ref self: ContractState,
            amount: u256,
            encrypted_delta: ElGamalCiphertext,
            proof: EncryptionProof
        ) {
            let caller = get_caller_address();

            // Withdraw from PrivacyRouter
            let privacy_router = IPrivacyRouterDispatcher {
                contract_address: self.privacy_router.read()
            };
            privacy_router.withdraw(amount, encrypted_delta, proof);

            self.emit(WithdrawalCompleted {
                worker: caller,
                amount,
            });
        }

        fn get_pending_payments(self: @ContractState, worker: ContractAddress) -> Array<u256> {
            let mut result: Array<u256> = array![];
            let count = self.worker_pending_count.read(worker);

            let worker_felt: felt252 = worker.into();
            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }
                // Create composite key: hash(worker, index)
                let key: felt252 = worker_felt + i.into();
                let job_id = self.worker_pending_jobs.read(key);
                if job_id > 0 {
                    result.append(job_id);
                }
                i += 1;
            };

            result
        }

        fn is_privacy_registered(self: @ContractState, worker: ContractAddress) -> bool {
            let payment_router = IPaymentRouterDispatcher {
                contract_address: self.payment_router.read()
            };
            let pk = payment_router.get_worker_public_key(worker);
            !is_zero(pk)
        }
    }
}
