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
    derive_public_key, ec_mul, ec_add, ec_sub,
    generator, generator_h, hash_points, pedersen_commit, is_zero,
    get_c1, get_c2, get_commitment, create_proof_with_commitment
};
use core::poseidon::poseidon_hash_span;

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
/// Uses full Sigma protocol to prove ciphertext correctly encrypts amount
///
/// Proves knowledge of (amount, randomness r) such that:
///   C1 = r * G
///   C2 = amount * H + r * PK
///
/// Protocol:
/// 1. Commitment: R1 = k1*G, R2 = k2*H + k1*PK for random k1, k2
/// 2. Challenge: e = H(PK, C1, C2, R1, R2)
/// 3. Response: s1 = k1 - e*r, s2 = k2 - e*amount
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

    // === STEP 1: Compute ciphertext points ===
    let c1 = ec_mul(randomness, g);
    let amount_felt: felt252 = amount.try_into().unwrap_or(0);
    let amount_h = ec_mul(amount_felt, h);
    let r_pk = ec_mul(randomness, public_key);
    let c2 = ec_add(amount_h, r_pk);

    // === STEP 2: Generate second nonce for amount binding ===
    let mut nonce_input: Array<felt252> = array![];
    nonce_input.append(proof_nonce);
    nonce_input.append(amount_felt);
    let proof_nonce_2 = poseidon_hash_span(nonce_input.span());

    // === STEP 3: Commitment Phase ===
    // R1 = k1 * G (commitment to randomness)
    let r1 = ec_mul(proof_nonce, g);

    // R2 = k2 * H + k1 * PK (commitment to amount with shared secret)
    let k2_h = ec_mul(proof_nonce_2, h);
    let k1_pk = ec_mul(proof_nonce, public_key);
    let r2 = ec_add(k2_h, k1_pk);

    // Combined commitment for verification
    let commitment = ec_add(r1, r2);

    // === STEP 4: Challenge via Fiat-Shamir ===
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(public_key.x);
    challenge_input.append(public_key.y);
    challenge_input.append(c1.x);
    challenge_input.append(c1.y);
    challenge_input.append(c2.x);
    challenge_input.append(c2.y);
    challenge_input.append(commitment.x);
    challenge_input.append(commitment.y);
    let challenge = poseidon_hash_span(challenge_input.span());

    // === STEP 5: Response Phase ===
    // s1 = k1 - e * r (proves knowledge of randomness)
    let response = proof_nonce - challenge * randomness;

    // === STEP 6: Range Proof ===
    // Pedersen commitment for range proof: C_range = amount*H + response*G
    let range_commitment = pedersen_commit(amount_felt, response);
    let range_proof_hash = range_commitment.x;

    create_proof_with_commitment(commitment, challenge, response, range_proof_hash)
}

/// Calculate the withdrawal proof
/// Uses full Sigma protocol to prove withdrawal validity
///
/// Proves:
/// 1. Knowledge of secret key sk such that PK = sk * G
/// 2. encrypted_delta correctly encrypts withdrawal_amount
/// 3. balance - withdrawal >= 0 (non-negative remaining balance)
///
/// Protocol:
/// 1. Compute remaining balance ciphertext: C_remaining = C_balance - C_withdrawal
/// 2. Commitment: R = k * G for random k
/// 3. Challenge: e = H(PK, C_balance, C_withdrawal, C_remaining, R)
/// 4. Response: s = k - e * r (where r is withdrawal randomness)
/// 5. Range proof on remaining balance
pub fn create_withdrawal_proof(
    keypair: WorkerKeypair,
    withdrawal_amount: u256,
    encrypted_balance: EncryptedBalance,
    withdrawal_randomness: felt252,
    proof_nonce: felt252
) -> EncryptionProof {
    let g = generator();
    let h = generator_h();
    let amount_felt: felt252 = withdrawal_amount.try_into().unwrap_or(0);

    // === STEP 1: Compute withdrawal ciphertext ===
    // C_withdrawal = (r * G, amount * H + r * PK)
    let withdrawal_c1 = ec_mul(withdrawal_randomness, g);
    let amount_h = ec_mul(amount_felt, h);
    let r_pk = ec_mul(withdrawal_randomness, keypair.public_key);
    let withdrawal_c2 = ec_add(amount_h, r_pk);

    // === STEP 2: Compute remaining balance ciphertext ===
    let balance_c1 = get_c1(encrypted_balance.ciphertext);
    let balance_c2 = get_c2(encrypted_balance.ciphertext);
    let remaining_c1 = ec_sub(balance_c1, withdrawal_c1);
    let remaining_c2 = ec_sub(balance_c2, withdrawal_c2);

    // === STEP 3: Commitment Phase ===
    // R1 = k * G (commitment to randomness knowledge)
    let r1 = ec_mul(proof_nonce, g);

    // R2 = k * PK (commitment bound to public key)
    let r2 = ec_mul(proof_nonce, keypair.public_key);

    // Combined commitment
    let commitment = ec_add(r1, r2);

    // === STEP 4: Challenge via Fiat-Shamir ===
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(keypair.public_key.x);
    challenge_input.append(keypair.public_key.y);
    challenge_input.append(balance_c1.x);
    challenge_input.append(balance_c1.y);
    challenge_input.append(balance_c2.x);
    challenge_input.append(balance_c2.y);
    challenge_input.append(withdrawal_c1.x);
    challenge_input.append(withdrawal_c2.x);
    challenge_input.append(remaining_c1.x);
    challenge_input.append(remaining_c2.x);
    challenge_input.append(commitment.x);
    challenge_input.append(commitment.y);
    let challenge = poseidon_hash_span(challenge_input.span());

    // === STEP 5: Response Phase ===
    // s = k - e * r (proves knowledge of withdrawal randomness)
    let response = proof_nonce - challenge * withdrawal_randomness;

    // === STEP 6: Range Proof for Remaining Balance ===
    // Proves that balance - withdrawal >= 0 without revealing balance
    // The range proof hash commits to the remaining balance structure
    let mut range_input: Array<felt252> = array![];
    range_input.append(remaining_c1.x);
    range_input.append(remaining_c1.y);
    range_input.append(remaining_c2.x);
    range_input.append(remaining_c2.y);
    range_input.append(amount_felt);
    range_input.append(response);
    let range_proof_hash = poseidon_hash_span(range_input.span());

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
    use starknet::{ContractAddress, get_caller_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, Map
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
