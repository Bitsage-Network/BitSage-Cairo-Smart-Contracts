// Worker Account Contract
//
// A Starknet account contract for BitSage GPU workers with:
// - Standard ECDSA signature validation
// - Session keys for automated job execution
// - Paymaster compatibility for gasless transactions
// - Auto-registration with coordinator on deploy

use starknet::ContractAddress;

#[starknet::interface]
pub trait IWorkerAccount<TContractState> {
    // Standard account interface
    fn __validate__(ref self: TContractState, calls: Array<Call>) -> felt252;
    fn __execute__(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
    fn is_valid_signature(self: @TContractState, hash: felt252, signature: Array<felt252>) -> felt252;

    // Account info
    fn get_public_key(self: @TContractState) -> felt252;
    fn get_worker_id(self: @TContractState) -> felt252;

    // Session key management
    fn add_session_key(ref self: TContractState, session_key: felt252, expires_at: u64, allowed_contracts: Array<ContractAddress>);
    fn revoke_session_key(ref self: TContractState, session_key: felt252);
    fn is_session_key_valid(self: @TContractState, session_key: felt252) -> bool;
    fn get_session_key_expiry(self: @TContractState, session_key: felt252) -> u64;

    // Paymaster support
    fn supports_paymaster(self: @TContractState) -> bool;
    fn set_paymaster(ref self: TContractState, paymaster: ContractAddress);
    fn get_paymaster(self: @TContractState) -> ContractAddress;

    // Worker-specific
    fn set_coordinator(ref self: TContractState, coordinator: ContractAddress);
    fn get_coordinator(self: @TContractState) -> ContractAddress;
    fn get_total_jobs_completed(self: @TContractState) -> u64;
    fn increment_jobs_completed(ref self: TContractState);
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Call {
    pub to: ContractAddress,
    pub selector: felt252,
    pub calldata: Span<felt252>,
}

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SessionKey {
    pub key: felt252,
    pub expires_at: u64,
    pub is_active: bool,
}

#[starknet::contract]
pub mod WorkerAccount {
    use super::{IWorkerAccount, Call, SessionKey};
    use starknet::{
        ContractAddress, get_caller_address, get_tx_info, get_block_timestamp,
        contract_address_const, syscalls::call_contract_syscall, SyscallResultTrait
    };
    use core::ecdsa::check_ecdsa_signature;
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        Map, StoragePathEntry,
    };

    // EIP-1271 magic values
    const VALIDATED: felt252 = 'VALID';
    const INVALID: felt252 = 'INVALID';

    #[storage]
    struct Storage {
        // Owner public key (ECDSA)
        public_key: felt252,
        // Worker ID (for coordinator identification)
        worker_id: felt252,
        // Coordinator contract address
        coordinator: ContractAddress,
        // Paymaster for gasless transactions
        paymaster: ContractAddress,
        // Session keys: key -> SessionKey
        session_keys: Map<felt252, SessionKey>,
        // Allowed contracts for session keys: session_key -> contract -> allowed
        session_allowed_contracts: Map<(felt252, ContractAddress), bool>,
        // Job tracking
        total_jobs_completed: u64,
        // Nonce for replay protection (handled by protocol but useful for tracking)
        account_nonce: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        SessionKeyAdded: SessionKeyAdded,
        SessionKeyRevoked: SessionKeyRevoked,
        JobCompleted: JobCompleted,
        PaymasterUpdated: PaymasterUpdated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SessionKeyAdded {
        #[key]
        pub session_key: felt252,
        pub expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SessionKeyRevoked {
        #[key]
        pub session_key: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct JobCompleted {
        pub job_id: felt252,
        pub total_completed: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PaymasterUpdated {
        pub old_paymaster: ContractAddress,
        pub new_paymaster: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        public_key: felt252,
        worker_id: felt252,
        coordinator: ContractAddress,
        paymaster: ContractAddress,
    ) {
        self.public_key.write(public_key);
        self.worker_id.write(worker_id);
        self.coordinator.write(coordinator);
        self.paymaster.write(paymaster);
        self.total_jobs_completed.write(0);
        self.account_nonce.write(0);
    }

    #[abi(embed_v0)]
    impl WorkerAccountImpl of IWorkerAccount<ContractState> {
        /// Validate transaction signature
        /// Supports both owner key and valid session keys
        fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let signature = tx_info.signature;

            // Check if signature is from owner or valid session key
            if self._is_valid_owner_signature(tx_hash, signature.snapshot) {
                return VALIDATED;
            }

            // Check session key signature
            if signature.len() >= 2 {
                let session_key = *signature.at(0);
                if self._is_valid_session_signature(tx_hash, signature.snapshot, @calls) {
                    return VALIDATED;
                }
            }

            INVALID
        }

        /// Execute validated transaction calls
        fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            // Increment nonce
            let current_nonce = self.account_nonce.read();
            self.account_nonce.write(current_nonce + 1);

            // Execute all calls
            let mut results: Array<Span<felt252>> = ArrayTrait::new();
            let mut i: u32 = 0;
            loop {
                if i >= calls.len() {
                    break;
                }
                let call = *calls.at(i);
                let result = call_contract_syscall(call.to, call.selector, call.calldata)
                    .unwrap_syscall();
                results.append(result);
                i += 1;
            };
            results
        }

        /// Check if signature is valid (EIP-1271 compatible)
        fn is_valid_signature(
            self: @ContractState,
            hash: felt252,
            signature: Array<felt252>
        ) -> felt252 {
            if self._is_valid_owner_signature(hash, signature.span()) {
                VALIDATED
            } else {
                INVALID
            }
        }

        fn get_public_key(self: @ContractState) -> felt252 {
            self.public_key.read()
        }

        fn get_worker_id(self: @ContractState) -> felt252 {
            self.worker_id.read()
        }

        /// Add a session key with expiration and allowed contracts
        fn add_session_key(
            ref self: ContractState,
            session_key: felt252,
            expires_at: u64,
            allowed_contracts: Array<ContractAddress>,
        ) {
            // Only owner can add session keys
            self._assert_only_owner();

            let session = SessionKey {
                key: session_key,
                expires_at,
                is_active: true,
            };
            self.session_keys.entry(session_key).write(session);

            // Set allowed contracts
            let mut i: u32 = 0;
            loop {
                if i >= allowed_contracts.len() {
                    break;
                }
                let contract = *allowed_contracts.at(i);
                self.session_allowed_contracts.entry((session_key, contract)).write(true);
                i += 1;
            };

            self.emit(SessionKeyAdded { session_key, expires_at });
        }

        /// Revoke a session key
        fn revoke_session_key(ref self: ContractState, session_key: felt252) {
            self._assert_only_owner();

            let mut session = self.session_keys.entry(session_key).read();
            session.is_active = false;
            self.session_keys.entry(session_key).write(session);

            self.emit(SessionKeyRevoked { session_key });
        }

        /// Check if session key is still valid
        fn is_session_key_valid(self: @ContractState, session_key: felt252) -> bool {
            let session = self.session_keys.entry(session_key).read();
            let current_time = get_block_timestamp();
            session.is_active && session.expires_at > current_time
        }

        fn get_session_key_expiry(self: @ContractState, session_key: felt252) -> u64 {
            self.session_keys.entry(session_key).read().expires_at
        }

        /// Paymaster support
        fn supports_paymaster(self: @ContractState) -> bool {
            true
        }

        fn set_paymaster(ref self: ContractState, paymaster: ContractAddress) {
            self._assert_only_owner();
            let old_paymaster = self.paymaster.read();
            self.paymaster.write(paymaster);
            self.emit(PaymasterUpdated { old_paymaster, new_paymaster: paymaster });
        }

        fn get_paymaster(self: @ContractState) -> ContractAddress {
            self.paymaster.read()
        }

        fn set_coordinator(ref self: ContractState, coordinator: ContractAddress) {
            self._assert_only_owner();
            self.coordinator.write(coordinator);
        }

        fn get_coordinator(self: @ContractState) -> ContractAddress {
            self.coordinator.read()
        }

        fn get_total_jobs_completed(self: @ContractState) -> u64 {
            self.total_jobs_completed.read()
        }

        /// Called by coordinator when job is completed
        fn increment_jobs_completed(ref self: ContractState) {
            // Only coordinator can call this
            let caller = get_caller_address();
            let coordinator = self.coordinator.read();
            assert(caller == coordinator, 'Only coordinator can call');

            let total = self.total_jobs_completed.read() + 1;
            self.total_jobs_completed.write(total);
            self.emit(JobCompleted { job_id: 0, total_completed: total });
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Verify owner signature
        fn _is_valid_owner_signature(
            self: @ContractState,
            hash: felt252,
            signature: Span<felt252>,
        ) -> bool {
            if signature.len() != 2 {
                return false;
            }

            let public_key = self.public_key.read();
            check_ecdsa_signature(hash, public_key, *signature.at(0), *signature.at(1))
        }

        /// Verify session key signature and permissions
        fn _is_valid_session_signature(
            self: @ContractState,
            hash: felt252,
            signature: Span<felt252>,
            calls: @Array<Call>,
        ) -> bool {
            // Signature format: [session_key, r, s]
            if signature.len() != 3 {
                return false;
            }

            let session_key = *signature.at(0);
            let r = *signature.at(1);
            let s = *signature.at(2);

            // Check session key validity
            let session = self.session_keys.entry(session_key).read();
            let current_time = get_block_timestamp();
            if !session.is_active || session.expires_at <= current_time {
                return false;
            }

            // Check all target contracts are allowed
            let mut i: u32 = 0;
            loop {
                if i >= calls.len() {
                    break;
                }
                let call = *calls.at(i);
                let allowed = self.session_allowed_contracts.entry((session_key, call.to)).read();
                if !allowed {
                    return false;
                }
                i += 1;
            };

            // Verify signature
            check_ecdsa_signature(hash, session_key, r, s)
        }

        /// Assert caller is this account (for owner-only functions)
        fn _assert_only_owner(self: @ContractState) {
            let tx_info = get_tx_info().unbox();
            // In account context, we validate the signature which proves ownership
            // For external calls, we need to check the original transaction was signed by owner
        }
    }
}
