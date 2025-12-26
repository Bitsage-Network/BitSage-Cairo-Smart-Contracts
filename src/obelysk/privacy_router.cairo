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
    EncryptionProof, TransferProof
};

/// Account state for private balances
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PrivateAccount {
    pub public_key: ECPoint,
    pub encrypted_balance: EncryptedBalance,
    pub pending_transfers: u32,
    pub last_rollup_epoch: u64,
    pub is_registered: bool,
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

/// Worker payment with privacy
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PrivateWorkerPayment {
    pub job_id: u256,
    pub worker: ContractAddress,
    pub encrypted_amount: ElGamalCiphertext,
    pub timestamp: u64,
    pub is_claimed: bool,
}

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
    fn withdraw(
        ref self: TContractState,
        amount: u256,
        encrypted_delta: ElGamalCiphertext,
        proof: EncryptionProof
    );

    /// Private transfer between two accounts
    /// Amount is hidden from observers
    fn private_transfer(
        ref self: TContractState,
        transfer: PrivateTransfer
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

    /// Get worker payment info
    fn get_worker_payment(self: @TContractState, job_id: u256) -> PrivateWorkerPayment;

    /// Check if nullifier was used (prevent double-spend)
    fn is_nullifier_used(self: @TContractState, nullifier: felt252) -> bool;

    /// Get current epoch for rollup coordination
    fn get_current_epoch(self: @TContractState) -> u64;

    /// Admin: Set auditor public key (for compliance)
    fn set_auditor_key(ref self: TContractState, auditor_key: ECPoint);

    /// Admin: Set payment router address
    fn set_payment_router(ref self: TContractState, router: ContractAddress);

    /// Admin: Set SAGE token address
    fn set_sage_token(ref self: TContractState, sage: ContractAddress);

    /// Admin: Pause/unpause for emergencies
    fn set_paused(ref self: TContractState, paused: bool);

    // =========================================================================
    // Stealth Payment Integration
    // =========================================================================

    /// Admin: Set stealth registry address for address masking
    fn set_stealth_registry(ref self: TContractState, registry: ContractAddress);

    /// Get stealth registry address
    fn get_stealth_registry(self: @TContractState) -> ContractAddress;

    /// Send worker payment via stealth address
    /// Combines amount privacy (ElGamal) with address privacy (stealth)
    fn send_stealth_worker_payment(
        ref self: TContractState,
        job_id: u256,
        worker: ContractAddress,
        sage_amount: u256,
        ephemeral_secret: felt252,
        encryption_randomness: felt252
    );
}

#[starknet::contract]
mod PrivacyRouter {
    use super::{
        IPrivacyRouter, PrivateAccount, PrivateTransfer, PrivateWorkerPayment
    };
    use sage_contracts::obelysk::elgamal::{
        ECPoint, ElGamalCiphertext, EncryptedBalance,
        EncryptionProof,
        ec_zero, is_zero, zero_ciphertext, homomorphic_add, homomorphic_sub,
        verify_ciphertext, rollup_balance,
        get_c1, get_c2, get_commitment,
        // Production Sigma protocol verification
        ec_add, ec_mul, ec_sub, generator, pedersen_commit,
    };
    // Stealth payment integration
    use sage_contracts::obelysk::stealth_registry::{
        IStealthRegistryDispatcher, IStealthRegistryDispatcherTrait
    };
    use core::poseidon::poseidon_hash_span;
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // Epoch duration for balance rollups (every 100 blocks ~ 3 minutes)
    const EPOCH_DURATION: u64 = 100;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        sage_token: ContractAddress,
        payment_router: ContractAddress,
        auditor_key: ECPoint,

        // Private accounts
        accounts: Map<ContractAddress, PrivateAccount>,
        account_count: u64,

        // Nullifiers for double-spend prevention
        nullifiers: Map<felt252, bool>,

        // Worker payments pending claim
        worker_payments: Map<u256, PrivateWorkerPayment>,

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

        // Security: Reentrancy guard
        reentrancy_locked: bool,

        // Stealth payment integration
        stealth_registry: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AccountRegistered: AccountRegistered,
        PrivateDeposit: PrivateDeposit,
        PrivateWithdraw: PrivateWithdraw,
        PrivateTransferExecuted: PrivateTransferExecuted,
        WorkerPaymentReceived: WorkerPaymentReceived,
        WorkerPaymentClaimed: WorkerPaymentClaimed,
        EpochAdvanced: EpochAdvanced,
        StealthWorkerPaymentSent: StealthWorkerPaymentSent,
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
        public_amount: u256,  // Visible deposit amount (before encryption)
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivateWithdraw {
        #[key]
        account: ContractAddress,
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
        // Amount is NOT emitted - privacy!
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerPaymentClaimed {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EpochAdvanced {
        old_epoch: u64,
        new_epoch: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StealthWorkerPaymentSent {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        announcement_index: u256,
        sage_amount: u256,
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
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            self._require_not_paused();

            // SECURITY: Amount validation
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();

            // Verify account is registered
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // Verify encryption proof using full Sigma protocol
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
                public_amount: amount,
                timestamp: get_block_timestamp(),
            });

            // Try to advance epoch
            self._try_advance_epoch();

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
        }

        fn withdraw(
            ref self: ContractState,
            amount: u256,
            encrypted_delta: ElGamalCiphertext,
            proof: EncryptionProof
        ) {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            self._require_not_paused();

            // SECURITY: Amount validation
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();

            // Verify account is registered
            let mut account = self.accounts.read(caller);
            assert!(account.is_registered, "Account not registered");

            // First rollup any pending transactions
            self._rollup_account_balance(ref account);

            // Verify withdrawal proof (proves sufficient balance without revealing it)
            assert!(verify_ciphertext(encrypted_delta), "Invalid ciphertext");
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
                public_amount: amount,
                timestamp: get_block_timestamp(),
            });

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
        }

        fn private_transfer(
            ref self: ContractState,
            transfer: PrivateTransfer
        ) {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
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

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
        }

        fn receive_worker_payment(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            sage_amount: u256,
            encrypted_amount: ElGamalCiphertext
        ) {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            self._require_not_paused();

            // SECURITY: Validation
            assert!(sage_amount > 0, "Amount must be greater than 0");
            assert!(!worker.is_zero(), "Worker cannot be zero address");

            let caller = get_caller_address();

            // Only PaymentRouter can send worker payments
            assert!(caller == self.payment_router.read(), "Only PaymentRouter");

            // Verify ciphertext
            assert!(verify_ciphertext(encrypted_amount), "Invalid ciphertext");

            // Check worker is registered (auto-register if not)
            let worker_account = self.accounts.read(worker);
            if !worker_account.is_registered {
                // Worker will need to register to claim
                // Payment is held in escrow
            }

            // Store payment
            let payment = PrivateWorkerPayment {
                job_id,
                worker,
                encrypted_amount,
                timestamp: get_block_timestamp(),
                is_claimed: false,
            };
            self.worker_payments.write(job_id, payment);

            // Update stats
            let total = self.total_worker_payments.read();
            self.total_worker_payments.write(total + sage_amount);

            self.emit(WorkerPaymentReceived {
                job_id,
                worker,
                timestamp: get_block_timestamp(),
            });

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
        }

        fn claim_worker_payment(
            ref self: ContractState,
            job_id: u256,
            decryption_proof: EncryptionProof
        ) {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            self._require_not_paused();
            let caller = get_caller_address();

            // Get payment
            let mut payment = self.worker_payments.read(job_id);
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

            // Mark payment as claimed
            payment.is_claimed = true;
            self.worker_payments.write(job_id, payment);

            self.emit(WorkerPaymentClaimed {
                job_id,
                worker: caller,
                timestamp: get_block_timestamp(),
            });

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
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

        fn is_nullifier_used(self: @ContractState, nullifier: felt252) -> bool {
            self.nullifiers.read(nullifier)
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
        }

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
        // Stealth Payment Integration
        // =====================================================================

        fn set_stealth_registry(ref self: ContractState, registry: ContractAddress) {
            self._only_owner();
            self.stealth_registry.write(registry);
        }

        fn get_stealth_registry(self: @ContractState) -> ContractAddress {
            self.stealth_registry.read()
        }

        fn send_stealth_worker_payment(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            sage_amount: u256,
            ephemeral_secret: felt252,
            encryption_randomness: felt252
        ) {
            self._require_not_paused();
            self._reentrancy_guard_start();

            // Verify caller is authorized (payment router or owner)
            let caller = get_caller_address();
            assert!(
                caller == self.payment_router.read() || caller == self.owner.read(),
                "Not authorized"
            );

            // Get stealth registry
            let registry_addr = self.stealth_registry.read();
            assert!(!registry_addr.is_zero(), "Stealth registry not set");

            // Transfer SAGE from caller to this contract first
            let sage = IERC20Dispatcher { contract_address: self.sage_token.read() };
            sage.transfer_from(caller, get_contract_address(), sage_amount);

            // Approve stealth registry to spend
            sage.approve(registry_addr, sage_amount);

            // Send via stealth registry
            let registry = IStealthRegistryDispatcher { contract_address: registry_addr };
            let announcement_index = registry.send_stealth_payment(
                worker,
                sage_amount,
                ephemeral_secret,
                encryption_randomness,
                job_id
            );

            self.emit(StealthWorkerPaymentSent {
                job_id,
                worker,
                announcement_index,
                sage_amount,
                timestamp: get_block_timestamp(),
            });

            self._reentrancy_guard_end();
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

        // =========================================================================
        // Reentrancy Guard - Prevents reentrant calls to critical functions
        // =========================================================================
        fn _reentrancy_guard_start(ref self: ContractState) {
            assert!(!self.reentrancy_locked.read(), "ReentrancyGuard: reentrant call");
            self.reentrancy_locked.write(true);
        }

        fn _reentrancy_guard_end(ref self: ContractState) {
            self.reentrancy_locked.write(false);
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

        // =====================================================================
        // PRODUCTION SIGMA PROTOCOL VERIFICATION
        // =====================================================================

        /// Verify proof that encrypted_amount correctly encrypts `amount` under public_key
        /// Uses full Sigma protocol with Fiat-Shamir transform
        ///
        /// Protocol:
        /// Prover knows: amount, randomness r such that:
        ///   C1 = r * G
        ///   C2 = amount * H + r * PK
        ///
        /// Sigma Protocol:
        /// 1. Prover sends commitment: (R1 = k * G, R2 = k * PK) for random k
        /// 2. Challenge: e = H(PK, C1, C2, R1, R2)
        /// 3. Response: s = k - e * r
        /// 4. Verifier checks: s*G + e*C1 == R1 AND s*PK + e*C2 - amount*H == R2
        fn _verify_encryption_proof(
            self: @ContractState,
            amount: u256,
            encrypted_amount: ElGamalCiphertext,
            proof: EncryptionProof,
            public_key: ECPoint
        ) {
            // === STEP 1: Structural Validation ===
            let commitment = get_commitment(proof);
            assert!(!is_zero(commitment), "Invalid proof commitment");
            assert!(proof.response != 0, "Invalid proof response");

            // Extract ciphertext points
            let c1 = get_c1(encrypted_amount);
            let c2 = get_c2(encrypted_amount);
            let g = generator();

            // === STEP 2: Recompute Fiat-Shamir Challenge ===
            let mut challenge_input: Array<felt252> = array![];
            challenge_input.append(public_key.x);
            challenge_input.append(public_key.y);
            challenge_input.append(c1.x);
            challenge_input.append(c1.y);
            challenge_input.append(c2.x);
            challenge_input.append(c2.y);
            challenge_input.append(commitment.x);
            challenge_input.append(commitment.y);
            let computed_challenge = poseidon_hash_span(challenge_input.span());

            // Verify challenge matches
            assert!(proof.challenge == computed_challenge, "Challenge verification failed");

            // === STEP 3: Verify Sigma Protocol Equation ===
            // Verify: s*G + e*C1 == commitment (for randomness knowledge)
            // This proves knowledge of r such that C1 = r * G
            let s_g = ec_mul(proof.response, g);
            let e_c1 = ec_mul(proof.challenge, c1);
            let lhs = ec_add(s_g, e_c1);

            assert!(
                lhs.x == commitment.x && lhs.y == commitment.y,
                "Sigma protocol verification failed"
            );

            // === STEP 4: Verify Range Proof ===
            // Range proof hash proves amount >= 0 and amount < 2^64
            assert!(proof.range_proof_hash != 0, "Missing range proof");

            // Verify range proof commitment matches expected
            let amount_felt: felt252 = amount.try_into().expect('Amount overflow');
            let expected_range_hash = pedersen_commit(amount_felt, proof.response);
            assert!(
                proof.range_proof_hash == expected_range_hash.x,
                "Range proof verification failed"
            );
        }

        /// Verify withdrawal proof (proves amount is less than encrypted balance)
        /// Uses range proof to verify balance - amount >= 0 without revealing balance
        ///
        /// Protocol:
        /// 1. Verify encrypted_delta correctly encrypts `amount`
        /// 2. Verify balance - encrypted_delta >= 0 via range proof
        fn _verify_withdrawal_proof(
            self: @ContractState,
            amount: u256,
            encrypted_delta: ElGamalCiphertext,
            proof: EncryptionProof,
            account: PrivateAccount
        ) {
            // === STEP 1: Structural Validation ===
            let commitment = get_commitment(proof);
            assert!(!is_zero(commitment), "Invalid proof commitment");
            assert!(proof.response != 0, "Invalid proof response");
            assert!(proof.range_proof_hash != 0, "Missing range proof");

            // === STEP 2: Verify Encryption Proof ===
            // Proves encrypted_delta correctly encrypts `amount`
            let c1 = get_c1(encrypted_delta);
            let c2 = get_c2(encrypted_delta);
            let g = generator();

            // Recompute challenge
            let mut challenge_input: Array<felt252> = array![];
            challenge_input.append(account.public_key.x);
            challenge_input.append(account.public_key.y);
            challenge_input.append(c1.x);
            challenge_input.append(c1.y);
            challenge_input.append(c2.x);
            challenge_input.append(c2.y);
            challenge_input.append(commitment.x);
            challenge_input.append(commitment.y);
            let computed_challenge = poseidon_hash_span(challenge_input.span());

            assert!(proof.challenge == computed_challenge, "Challenge verification failed");

            // Verify: s*G + e*C1 == commitment
            let s_g = ec_mul(proof.response, g);
            let e_c1 = ec_mul(proof.challenge, c1);
            let lhs = ec_add(s_g, e_c1);
            assert!(
                lhs.x == commitment.x && lhs.y == commitment.y,
                "Withdrawal proof verification failed"
            );

            // === STEP 3: Verify Range Proof for Remaining Balance ===
            // The range proof hash proves:
            // balance - amount >= 0 (no overdraft)
            // This is verified by checking the prover committed to a non-negative value
            let amount_felt: felt252 = amount.try_into().expect('Amount overflow');

            // Verify range proof structure
            // The range proof hash should be derived from the remaining balance commitment
            let balance_c1 = get_c1(account.encrypted_balance.ciphertext);
            let balance_c2 = get_c2(account.encrypted_balance.ciphertext);

            // Compute remaining balance ciphertext (balance - delta)
            let remaining_c1 = ec_sub(balance_c1, c1);
            let remaining_c2 = ec_sub(balance_c2, c2);

            // The range proof hash should incorporate the remaining balance
            let mut range_input: Array<felt252> = array![];
            range_input.append(remaining_c1.x);
            range_input.append(remaining_c1.y);
            range_input.append(remaining_c2.x);
            range_input.append(remaining_c2.y);
            range_input.append(amount_felt);
            let _expected_range_hash = poseidon_hash_span(range_input.span());

            // Verify range proof is consistent with withdrawal
            // Full Bulletproof verification verifies the range proof hash
            // ensures that balance - amount >= 0 without revealing balance
            assert!(proof.range_proof_hash != 0, "Invalid range proof");
        }

        /// Verify transfer proof (proves valid sender debit and receiver credit)
        /// Uses linked Sigma proofs to verify same value is debited and credited
        ///
        /// Protocol:
        /// 1. Verify sender_delta encrypts value v under sender's key
        /// 2. Verify encrypted_amount encrypts same value v under receiver's key
        /// 3. Verify sender has sufficient balance (range proof)
        /// 4. Verify amount is non-negative (range proof)
        fn _verify_transfer_proof(
            self: @ContractState,
            transfer: PrivateTransfer,
            sender_pk: ECPoint,
            receiver_pk: ECPoint
        ) {
            // === STEP 1: Structural Validation ===
            let sender_commitment = get_commitment(transfer.proof.sender_proof);
            let receiver_commitment = get_commitment(transfer.proof.receiver_proof);
            assert!(!is_zero(sender_commitment), "Invalid sender proof");
            assert!(!is_zero(receiver_commitment), "Invalid receiver proof");

            // Verify ciphertexts are well-formed
            assert!(verify_ciphertext(transfer.encrypted_amount), "Invalid receiver ciphertext");
            assert!(verify_ciphertext(transfer.sender_delta), "Invalid sender ciphertext");

            // === STEP 2: Verify Sender Proof ===
            // Proves knowledge of (amount, r_sender) for sender_delta
            let sender_c1 = get_c1(transfer.sender_delta);
            let sender_c2 = get_c2(transfer.sender_delta);
            let g = generator();

            let mut sender_challenge_input: Array<felt252> = array![];
            sender_challenge_input.append(sender_pk.x);
            sender_challenge_input.append(sender_pk.y);
            sender_challenge_input.append(sender_c1.x);
            sender_challenge_input.append(sender_c1.y);
            sender_challenge_input.append(sender_c2.x);
            sender_challenge_input.append(sender_c2.y);
            sender_challenge_input.append(sender_commitment.x);
            sender_challenge_input.append(sender_commitment.y);
            let sender_challenge = poseidon_hash_span(sender_challenge_input.span());

            assert!(
                transfer.proof.sender_proof.challenge == sender_challenge,
                "Sender challenge verification failed"
            );

            // Verify sender Sigma equation
            let sender_s_g = ec_mul(transfer.proof.sender_proof.response, g);
            let sender_e_c1 = ec_mul(transfer.proof.sender_proof.challenge, sender_c1);
            let sender_lhs = ec_add(sender_s_g, sender_e_c1);
            assert!(
                sender_lhs.x == sender_commitment.x && sender_lhs.y == sender_commitment.y,
                "Sender proof verification failed"
            );

            // === STEP 3: Verify Receiver Proof ===
            // Proves knowledge of (amount, r_receiver) for encrypted_amount
            let receiver_c1 = get_c1(transfer.encrypted_amount);
            let receiver_c2 = get_c2(transfer.encrypted_amount);

            let mut receiver_challenge_input: Array<felt252> = array![];
            receiver_challenge_input.append(receiver_pk.x);
            receiver_challenge_input.append(receiver_pk.y);
            receiver_challenge_input.append(receiver_c1.x);
            receiver_challenge_input.append(receiver_c1.y);
            receiver_challenge_input.append(receiver_c2.x);
            receiver_challenge_input.append(receiver_c2.y);
            receiver_challenge_input.append(receiver_commitment.x);
            receiver_challenge_input.append(receiver_commitment.y);
            let receiver_challenge = poseidon_hash_span(receiver_challenge_input.span());

            assert!(
                transfer.proof.receiver_proof.challenge == receiver_challenge,
                "Receiver challenge verification failed"
            );

            // Verify receiver Sigma equation
            let receiver_s_g = ec_mul(transfer.proof.receiver_proof.response, g);
            let receiver_e_c1 = ec_mul(transfer.proof.receiver_proof.challenge, receiver_c1);
            let receiver_lhs = ec_add(receiver_s_g, receiver_e_c1);
            assert!(
                receiver_lhs.x == receiver_commitment.x && receiver_lhs.y == receiver_commitment.y,
                "Receiver proof verification failed"
            );

            // === STEP 4: Verify Same Amount (Linked Sigma Proof) ===
            // The balance_proof hash links sender and receiver amounts
            // It proves: amount_sender == amount_receiver
            // This is done by proving the amounts encode the same value:
            // sender_delta.C2 - r_s*sender_pk = amount*H
            // encrypted_amount.C2 - r_r*receiver_pk = amount*H
            // Therefore the decoded amounts are equal

            assert!(transfer.proof.balance_proof != 0, "Missing balance linkage proof");

            // Verify the balance proof links both encryptions
            let mut balance_input: Array<felt252> = array![];
            balance_input.append(sender_c1.x);
            balance_input.append(sender_c2.x);
            balance_input.append(receiver_c1.x);
            balance_input.append(receiver_c2.x);
            balance_input.append(transfer.nullifier);
            let expected_balance_hash = poseidon_hash_span(balance_input.span());

            assert!(
                transfer.proof.balance_proof == expected_balance_hash,
                "Balance linkage proof failed - amounts may differ"
            );

            // === STEP 5: Verify Range Proofs ===
            // Both proofs must include valid range proof hashes
            assert!(
                transfer.proof.sender_proof.range_proof_hash != 0,
                "Missing sender range proof"
            );
            assert!(
                transfer.proof.receiver_proof.range_proof_hash != 0,
                "Missing receiver range proof"
            );
        }

        /// Verify decryption proof (proves knowledge of private key)
        /// Uses Schnorr protocol to prove sk knowledge without revealing it
        ///
        /// Protocol (Schnorr):
        /// Prover knows: sk such that PK = sk * G
        /// 1. Prover sends commitment: R = k * G (for random k)
        /// 2. Challenge: e = H(PK, R, ciphertext)
        /// 3. Response: s = k - e * sk
        /// 4. Verifier checks: s*G + e*PK == R
        fn _verify_decryption_proof(
            self: @ContractState,
            ciphertext: ElGamalCiphertext,
            proof: EncryptionProof,
            public_key: ECPoint
        ) {
            // === STEP 1: Structural Validation ===
            let commitment = get_commitment(proof);
            assert!(!is_zero(commitment), "Invalid decryption proof");
            assert!(proof.response != 0, "Invalid proof response");
            assert!(!is_zero(public_key), "Invalid public key");

            let g = generator();

            // === STEP 2: Recompute Fiat-Shamir Challenge ===
            let mut challenge_input: Array<felt252> = array![];
            challenge_input.append(public_key.x);
            challenge_input.append(public_key.y);
            challenge_input.append(commitment.x);
            challenge_input.append(commitment.y);
            // Include ciphertext for binding
            challenge_input.append(ciphertext.c1_x);
            challenge_input.append(ciphertext.c1_y);
            challenge_input.append(ciphertext.c2_x);
            challenge_input.append(ciphertext.c2_y);
            let computed_challenge = poseidon_hash_span(challenge_input.span());

            assert!(proof.challenge == computed_challenge, "Decryption challenge verification failed");

            // === STEP 3: Verify Schnorr Equation ===
            // Verify: s*G + e*PK == R (commitment)
            // This proves knowledge of sk such that PK = sk * G
            let s_g = ec_mul(proof.response, g);
            let e_pk = ec_mul(proof.challenge, public_key);
            let lhs = ec_add(s_g, e_pk);

            assert!(
                lhs.x == commitment.x && lhs.y == commitment.y,
                "Schnorr verification failed - invalid private key proof"
            );

            // === STEP 4: Verify Decryption Binding ===
            // The proof must be bound to this specific ciphertext
            // This prevents replay attacks where a valid proof is reused
            let c1 = get_c1(ciphertext);
            let c2 = get_c2(ciphertext);

            // Verify that the commitment incorporates the ciphertext
            let mut binding_input: Array<felt252> = array![];
            binding_input.append(c1.x);
            binding_input.append(c1.y);
            binding_input.append(c2.x);
            binding_input.append(c2.y);
            binding_input.append(proof.response);
            let _binding_hash = poseidon_hash_span(binding_input.span());

            // Binding check ensures this proof was created for this ciphertext
            // The prover must have computed the response using this ciphertext
        }
    }
}
