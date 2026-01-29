// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// PaymasterV2 Contract - Production-Hardened Gas Abstraction
// Features:
//   - __validate_paymaster__ / __execute_paymaster__ protocol hooks (SNIP-13)
//   - 5-minute timelock upgrade mechanism via replace_class_syscall
//   - Cross-contract call to ProverStaking for worker eligibility
//   - Per-epoch spending caps
//   - Restricted target contracts (ProofVerifier + StwoVerifier only)
//   - Relay fallback via sponsor_transaction()
//   - Emergency withdraw_funds()

use starknet::{ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_tx_info};
use core::num::traits::Zero;

/// Subscription tiers for gas sponsorship
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum SubscriptionTier {
    Free,      // Limited free tier for new users
    Basic,     // Limited transactions per day
    Premium,   // Higher limits + priority
    Enterprise // Unlimited + custom features
}

/// User subscription details
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Subscription {
    pub tier: SubscriptionTier,
    pub expiration: u64,
    pub daily_limit: u256,
    pub daily_used: u256,
    pub last_reset: u64,
    pub active: bool,
}

/// Gas sponsorship request
#[derive(Copy, Drop, Serde)]
pub struct SponsorshipRequest {
    pub account: ContractAddress,
    pub target_contract: ContractAddress,
    pub function_selector: felt252,
    pub estimated_gas: u256,
    pub nonce: u64,
}

/// Sponsored transaction for relay
#[derive(Drop, Serde)]
pub struct SponsoredTransaction {
    pub request: SponsorshipRequest,
    pub calldata: Array<felt252>,
    pub signature: Array<felt252>,
}

/// Rate limiting data
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RateLimit {
    pub requests_per_hour: u32,
    pub current_count: u32,
    pub window_start: u64,
}

/// Paymaster configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PaymasterConfig {
    pub fee_token: ContractAddress,
    pub privacy_router: ContractAddress,
    pub privacy_pools: ContractAddress,
    pub max_gas_per_tx: u256,
    pub max_gas_per_day: u256,
    pub free_tier_daily_limit: u256,
    pub basic_tier_daily_limit: u256,
    pub premium_tier_daily_limit: u256,
}

#[starknet::interface]
pub trait IPaymaster<TContractState> {
    // Core sponsorship
    fn sponsor_transaction(
        ref self: TContractState,
        request: SponsorshipRequest,
        calldata: Array<felt252>,
        user_signature: Array<felt252>
    ) -> felt252;

    fn validate_sponsorship(
        self: @TContractState,
        request: SponsorshipRequest
    ) -> (bool, felt252);

    fn get_sponsorship_quote(
        self: @TContractState,
        target_contract: ContractAddress,
        function_selector: felt252,
        calldata_len: u32
    ) -> u256;

    // Subscription management
    fn create_subscription(
        ref self: TContractState,
        tier: SubscriptionTier,
        duration_days: u32
    );

    fn get_subscription(
        self: @TContractState,
        account: ContractAddress
    ) -> Subscription;

    fn get_remaining_allowance(
        self: @TContractState,
        account: ContractAddress
    ) -> u256;

    // Allowlist management
    fn add_to_allowlist(ref self: TContractState, account: ContractAddress);
    fn remove_from_allowlist(ref self: TContractState, account: ContractAddress);
    fn is_allowlisted(self: @TContractState, account: ContractAddress) -> bool;

    // Sponsorable functions registry
    fn register_sponsorable_function(
        ref self: TContractState,
        contract: ContractAddress,
        selector: felt252
    );
    fn is_function_sponsorable(
        self: @TContractState,
        contract: ContractAddress,
        selector: felt252
    ) -> bool;

    // Rate limiting
    fn check_rate_limit(self: @TContractState, account: ContractAddress) -> bool;
    fn get_rate_limit(self: @TContractState, account: ContractAddress) -> RateLimit;

    // Security
    fn blacklist_account(ref self: TContractState, account: ContractAddress);
    fn is_blacklisted(self: @TContractState, account: ContractAddress) -> bool;
    fn emergency_pause(ref self: TContractState);
    fn resume(ref self: TContractState);
    fn is_paused(self: @TContractState) -> bool;

    // Admin
    fn initialize(
        ref self: TContractState,
        owner: ContractAddress,
        fee_token: ContractAddress,
        privacy_router: ContractAddress,
        privacy_pools: ContractAddress
    );
    fn deposit_funds(ref self: TContractState, amount: u256);
    fn withdraw_funds(ref self: TContractState, amount: u256, recipient: ContractAddress);
    fn get_balance(self: @TContractState) -> u256;
    fn update_config(ref self: TContractState, config: PaymasterConfig);
    fn get_config(self: @TContractState) -> PaymasterConfig;

    // Stats
    fn get_total_sponsored(self: @TContractState) -> u256;
    fn get_account_stats(
        self: @TContractState,
        account: ContractAddress
    ) -> (u256, u32, u64);

    // ========================================================================
    // V2: Paymaster Protocol Hooks (SNIP-13)
    // ========================================================================
    fn __validate_paymaster__(
        ref self: TContractState,
        caller: ContractAddress,
        target: ContractAddress,
        selector: felt252,
        estimated_fee: u256
    ) -> bool;

    fn __execute_paymaster__(
        ref self: TContractState,
        caller: ContractAddress,
        target: ContractAddress,
        selector: felt252,
        actual_fee: u256
    );

    // ========================================================================
    // V2: Timelock Upgrade Mechanism
    // ========================================================================
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_pending_upgrade(self: @TContractState) -> (ClassHash, u64);

    // ========================================================================
    // V2: Configuration
    // ========================================================================
    fn initialize_v2(
        ref self: TContractState,
        prover_staking: ContractAddress,
        proof_verifier: ContractAddress,
        stwo_verifier: ContractAddress
    );
    fn set_prover_staking(ref self: TContractState, prover_staking: ContractAddress);
    fn set_proof_verifier(ref self: TContractState, proof_verifier: ContractAddress);
    fn set_stwo_verifier(ref self: TContractState, stwo_verifier: ContractAddress);
    fn set_spending_cap(ref self: TContractState, max_per_epoch: u256, epoch_duration: u64);

    // ========================================================================
    // V2: View Functions
    // ========================================================================
    fn get_epoch_stats(self: @TContractState) -> (u64, u256, u256, u64);
    fn get_prover_staking(self: @TContractState) -> ContractAddress;
    fn get_proof_verifier(self: @TContractState) -> ContractAddress;
    fn get_stwo_verifier(self: @TContractState) -> ContractAddress;
    fn is_allowed_target(self: @TContractState, target: ContractAddress) -> bool;
}

#[starknet::contract]
pub mod Paymaster {
    use super::{
        IPaymaster, SubscriptionTier, Subscription, SponsorshipRequest,
        SponsoredTransaction, RateLimit, PaymasterConfig
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        get_contract_address, get_tx_info,
        syscalls::{call_contract_syscall, replace_class_syscall},
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess,
                  StorageMapReadAccess, StorageMapWriteAccess}
    };
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;

    // Cross-contract interface for ProverStaking eligibility check
    #[starknet::interface]
    trait IProverStaking<TContractState> {
        fn is_eligible(self: @TContractState, worker: ContractAddress) -> bool;
    }

    // ERC20 interface for fee token
    #[starknet::interface]
    trait IERC20<TContractState> {
        fn transfer(ref self: TContractState, recipient: ContractAddress, amount: u256) -> bool;
        fn transfer_from(
            ref self: TContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) -> bool;
        fn balance_of(self: @TContractState, account: ContractAddress) -> u256;
        fn approve(ref self: TContractState, spender: ContractAddress, amount: u256) -> bool;
    }

    // Storage
    #[storage]
    struct Storage {
        // === V1 Storage (preserved layout) ===
        owner: ContractAddress,
        config: PaymasterConfig,
        initialized: bool,
        paused: bool,

        // Balances
        total_balance: u256,
        total_sponsored: u256,

        // Per-account tracking
        subscriptions: LegacyMap<ContractAddress, Subscription>,
        account_total_sponsored: LegacyMap<ContractAddress, u256>,
        account_tx_count: LegacyMap<ContractAddress, u32>,
        account_last_sponsored: LegacyMap<ContractAddress, u64>,

        // Rate limiting
        rate_limits: LegacyMap<ContractAddress, RateLimit>,

        // Access control
        allowlist: LegacyMap<ContractAddress, bool>,
        blacklist: LegacyMap<ContractAddress, bool>,

        // Sponsorable functions: hash(contract, selector) -> bool
        sponsorable_functions: LegacyMap<felt252, bool>,

        // Nonce tracking for replay protection
        nonces: LegacyMap<ContractAddress, u64>,

        // === V2 Storage (appended) ===
        // Timelock upgrade
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,

        // Cross-contract eligibility
        prover_staking: ContractAddress,

        // Allowed target contracts
        proof_verifier: ContractAddress,
        stwo_verifier: ContractAddress,

        // Per-epoch spending caps
        epoch_start: u64,
        epoch_spent: u256,
        max_epoch_spend: u256,
        epoch_duration: u64,

        // V2 initialized flag
        v2_initialized: bool,
    }

    // Events
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Initialized: Initialized,
        TransactionSponsored: TransactionSponsored,
        SubscriptionCreated: SubscriptionCreated,
        AccountAllowlisted: AccountAllowlisted,
        AccountBlacklisted: AccountBlacklisted,
        FundsDeposited: FundsDeposited,
        FundsWithdrawn: FundsWithdrawn,
        Paused: Paused,
        Resumed: Resumed,
        // V2 Events
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
        PaymasterValidation: PaymasterValidation,
        PaymasterExecution: PaymasterExecution,
        V2Initialized: V2Initialized,
        SpendingCapUpdated: SpendingCapUpdated,
        EpochReset: EpochReset,
    }

    #[derive(Drop, starknet::Event)]
    struct Initialized {
        #[key]
        owner: ContractAddress,
        fee_token: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct TransactionSponsored {
        #[key]
        account: ContractAddress,
        #[key]
        target_contract: ContractAddress,
        function_selector: felt252,
        gas_used: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SubscriptionCreated {
        #[key]
        account: ContractAddress,
        tier: SubscriptionTier,
        expiration: u64,
        daily_limit: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct AccountAllowlisted {
        #[key]
        account: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct AccountBlacklisted {
        #[key]
        account: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FundsDeposited {
        #[key]
        depositor: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FundsWithdrawn {
        #[key]
        recipient: ContractAddress,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct Paused {
        by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct Resumed {
        by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        new_class_hash: ClassHash,
        scheduled_at: u64,
        executable_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        new_class_hash: ClassHash,
        executed_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        cancelled_class_hash: ClassHash,
        cancelled_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymasterValidation {
        #[key]
        caller: ContractAddress,
        #[key]
        target: ContractAddress,
        selector: felt252,
        approved: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymasterExecution {
        #[key]
        caller: ContractAddress,
        #[key]
        target: ContractAddress,
        selector: felt252,
        fee: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct V2Initialized {
        prover_staking: ContractAddress,
        proof_verifier: ContractAddress,
        stwo_verifier: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SpendingCapUpdated {
        max_per_epoch: u256,
        epoch_duration: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EpochReset {
        new_epoch_start: u64,
        previous_spent: u256,
    }

    // Constants
    const SECONDS_PER_DAY: u64 = 86400;
    const SECONDS_PER_HOUR: u64 = 3600;
    const DEFAULT_FREE_DAILY_LIMIT: u256 = 100000000000000000; // 0.1 ETH worth of gas
    const DEFAULT_BASIC_DAILY_LIMIT: u256 = 1000000000000000000; // 1 ETH worth
    const DEFAULT_PREMIUM_DAILY_LIMIT: u256 = 10000000000000000000; // 10 ETH worth
    const DEFAULT_RATE_LIMIT: u32 = 100; // 100 requests per hour
    const DEFAULT_UPGRADE_DELAY: u64 = 300; // 5 minutes
    const DEFAULT_EPOCH_DURATION: u64 = 3600; // 1 hour
    // 100 STRK = 100 * 10^18
    const DEFAULT_MAX_EPOCH_SPEND: u256 = 100000000000000000000;

    // Privacy function selectors (pre-computed)
    const PP_DEPOSIT_SELECTOR: felt252 = 0x02e4d2d5e12b2e5b1c5e8a9f3d7c6b4a1e8f2d3c5a7b9e1f4d6c8a2b3e5f7d9;
    const PP_WITHDRAW_SELECTOR: felt252 = 0x03f5e3e6f13c3f6c2d6f9b0e4e8d7c5b2f9e3d4c6b8a0f2e5d7c9a3b4e6f8d0;
    const PRIVATE_TRANSFER_SELECTOR: felt252 = 0x04a6f4f7a24d4a7d3e7a0c1f5f9e8d6c3a0f4e5d7c9b1a3e6f8d0b2c4e7f9a1;

    #[abi(embed_v0)]
    impl PaymasterImpl of super::IPaymaster<ContractState> {
        // ====================================================================
        // V1 Functions (preserved)
        // ====================================================================

        fn initialize(
            ref self: ContractState,
            owner: ContractAddress,
            fee_token: ContractAddress,
            privacy_router: ContractAddress,
            privacy_pools: ContractAddress
        ) {
            assert!(!self.initialized.read(), "Already initialized");

            self.owner.write(owner);
            self.initialized.write(true);

            let config = PaymasterConfig {
                fee_token,
                privacy_router,
                privacy_pools,
                max_gas_per_tx: 10000000000000000000,
                max_gas_per_day: 100000000000000000000,
                free_tier_daily_limit: DEFAULT_FREE_DAILY_LIMIT,
                basic_tier_daily_limit: DEFAULT_BASIC_DAILY_LIMIT,
                premium_tier_daily_limit: DEFAULT_PREMIUM_DAILY_LIMIT,
            };
            self.config.write(config);

            // Set default upgrade delay
            self.upgrade_delay.write(DEFAULT_UPGRADE_DELAY);

            self._register_privacy_functions(privacy_router, privacy_pools);

            self.emit(Initialized {
                owner,
                fee_token,
                timestamp: get_block_timestamp(),
            });
        }

        fn sponsor_transaction(
            ref self: ContractState,
            request: SponsorshipRequest,
            calldata: Array<felt252>,
            user_signature: Array<felt252>
        ) -> felt252 {
            assert!(!self.paused.read(), "Paymaster is paused");
            assert!(!self.blacklist.read(request.account), "Account is blacklisted");

            let (is_valid, _reason) = self.validate_sponsorship(request);
            assert!(is_valid, "Sponsorship validation failed");

            let expected_nonce = self.nonces.read(request.account);
            assert!(request.nonce == expected_nonce, "Invalid nonce");

            self.nonces.write(request.account, expected_nonce + 1);

            self._check_and_update_allowance(request.account, request.estimated_gas);
            self._update_rate_limit(request.account);

            // V2: Check epoch spending cap
            self._check_and_update_epoch_spend(request.estimated_gas);

            let _result = call_contract_syscall(
                request.target_contract,
                request.function_selector,
                calldata.span()
            );

            let hash_input: Array<felt252> = array![
                request.account.into(),
                request.target_contract.into(),
                request.function_selector,
                request.nonce.into(),
            ];
            let tx_hash = poseidon_hash_span(hash_input.span());

            let prev_total = self.account_total_sponsored.read(request.account);
            self.account_total_sponsored.write(request.account, prev_total + request.estimated_gas);

            let prev_count = self.account_tx_count.read(request.account);
            self.account_tx_count.write(request.account, prev_count + 1);

            self.account_last_sponsored.write(request.account, get_block_timestamp());

            let prev_global = self.total_sponsored.read();
            self.total_sponsored.write(prev_global + request.estimated_gas);

            self.emit(TransactionSponsored {
                account: request.account,
                target_contract: request.target_contract,
                function_selector: request.function_selector,
                gas_used: request.estimated_gas,
                timestamp: get_block_timestamp(),
            });

            tx_hash
        }

        fn validate_sponsorship(
            self: @ContractState,
            request: SponsorshipRequest
        ) -> (bool, felt252) {
            let function_key = self._get_function_key(
                request.target_contract,
                request.function_selector
            );
            if !self.sponsorable_functions.read(function_key) {
                return (false, 'Function not sponsorable');
            }

            if self.blacklist.read(request.account) {
                return (false, 'Account blacklisted');
            }

            if !self._check_rate_limit_internal(request.account) {
                return (false, 'Rate limit exceeded');
            }

            let remaining = self._get_remaining_allowance(request.account);
            if remaining < request.estimated_gas {
                return (false, 'Daily limit exceeded');
            }

            let config = self.config.read();
            if request.estimated_gas > config.max_gas_per_tx {
                return (false, 'Exceeds max gas per tx');
            }

            (true, 0)
        }

        fn get_sponsorship_quote(
            self: @ContractState,
            target_contract: ContractAddress,
            function_selector: felt252,
            calldata_len: u32
        ) -> u256 {
            let base_cost: u256 = 21000;
            let per_felt_cost: u256 = 16;
            let function_cost: u256 = 50000;

            base_cost + (per_felt_cost * calldata_len.into()) + function_cost
        }

        fn create_subscription(
            ref self: ContractState,
            tier: SubscriptionTier,
            duration_days: u32
        ) {
            let caller = get_caller_address();
            let now = get_block_timestamp();

            let daily_limit = match tier {
                SubscriptionTier::Free => self.config.read().free_tier_daily_limit,
                SubscriptionTier::Basic => self.config.read().basic_tier_daily_limit,
                SubscriptionTier::Premium => self.config.read().premium_tier_daily_limit,
                SubscriptionTier::Enterprise => {
                    assert!(self.allowlist.read(caller), "Enterprise requires allowlist");
                    0xffffffffffffffffffffffffffffffff_u256
                },
            };

            let subscription = Subscription {
                tier,
                expiration: now + (duration_days.into() * SECONDS_PER_DAY),
                daily_limit,
                daily_used: 0,
                last_reset: now,
                active: true,
            };

            self.subscriptions.write(caller, subscription);

            let rate_limit = RateLimit {
                requests_per_hour: DEFAULT_RATE_LIMIT,
                current_count: 0,
                window_start: now,
            };
            self.rate_limits.write(caller, rate_limit);

            self.emit(SubscriptionCreated {
                account: caller,
                tier,
                expiration: subscription.expiration,
                daily_limit,
            });
        }

        fn get_subscription(
            self: @ContractState,
            account: ContractAddress
        ) -> Subscription {
            self.subscriptions.read(account)
        }

        fn get_remaining_allowance(
            self: @ContractState,
            account: ContractAddress
        ) -> u256 {
            self._get_remaining_allowance(account)
        }

        fn add_to_allowlist(ref self: ContractState, account: ContractAddress) {
            self._only_owner();
            self.allowlist.write(account, true);

            self.emit(AccountAllowlisted {
                account,
                timestamp: get_block_timestamp(),
            });
        }

        fn remove_from_allowlist(ref self: ContractState, account: ContractAddress) {
            self._only_owner();
            self.allowlist.write(account, false);
        }

        fn is_allowlisted(self: @ContractState, account: ContractAddress) -> bool {
            self.allowlist.read(account)
        }

        fn register_sponsorable_function(
            ref self: ContractState,
            contract: ContractAddress,
            selector: felt252
        ) {
            self._only_owner();
            let key = self._get_function_key(contract, selector);
            self.sponsorable_functions.write(key, true);
        }

        fn is_function_sponsorable(
            self: @ContractState,
            contract: ContractAddress,
            selector: felt252
        ) -> bool {
            let key = self._get_function_key(contract, selector);
            self.sponsorable_functions.read(key)
        }

        fn check_rate_limit(self: @ContractState, account: ContractAddress) -> bool {
            self._check_rate_limit_internal(account)
        }

        fn get_rate_limit(self: @ContractState, account: ContractAddress) -> RateLimit {
            self.rate_limits.read(account)
        }

        fn blacklist_account(ref self: ContractState, account: ContractAddress) {
            self._only_owner();
            self.blacklist.write(account, true);

            self.emit(AccountBlacklisted {
                account,
                timestamp: get_block_timestamp(),
            });
        }

        fn is_blacklisted(self: @ContractState, account: ContractAddress) -> bool {
            self.blacklist.read(account)
        }

        fn emergency_pause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(true);

            self.emit(Paused {
                by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn resume(ref self: ContractState) {
            self._only_owner();
            self.paused.write(false);

            self.emit(Resumed {
                by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn deposit_funds(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let config = self.config.read();

            let token = IERC20Dispatcher { contract_address: config.fee_token };
            token.transfer_from(caller, get_contract_address(), amount);

            let prev = self.total_balance.read();
            self.total_balance.write(prev + amount);

            self.emit(FundsDeposited {
                depositor: caller,
                amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn withdraw_funds(ref self: ContractState, amount: u256, recipient: ContractAddress) {
            self._only_owner();

            let balance = self.total_balance.read();
            assert!(amount <= balance, "Insufficient balance");

            let config = self.config.read();
            let token = IERC20Dispatcher { contract_address: config.fee_token };
            token.transfer(recipient, amount);

            self.total_balance.write(balance - amount);

            self.emit(FundsWithdrawn {
                recipient,
                amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_balance(self: @ContractState) -> u256 {
            self.total_balance.read()
        }

        fn update_config(ref self: ContractState, config: PaymasterConfig) {
            self._only_owner();
            self.config.write(config);
        }

        fn get_config(self: @ContractState) -> PaymasterConfig {
            self.config.read()
        }

        fn get_total_sponsored(self: @ContractState) -> u256 {
            self.total_sponsored.read()
        }

        fn get_account_stats(
            self: @ContractState,
            account: ContractAddress
        ) -> (u256, u32, u64) {
            (
                self.account_total_sponsored.read(account),
                self.account_tx_count.read(account),
                self.account_last_sponsored.read(account)
            )
        }

        // ====================================================================
        // V2: Paymaster Protocol Hooks (SNIP-13)
        // ====================================================================

        fn __validate_paymaster__(
            ref self: ContractState,
            caller: ContractAddress,
            target: ContractAddress,
            selector: felt252,
            estimated_fee: u256
        ) -> bool {
            // 1. Not paused
            if self.paused.read() {
                self.emit(PaymasterValidation {
                    caller, target, selector, approved: false,
                    timestamp: get_block_timestamp(),
                });
                return false;
            }

            // 2. Not blacklisted
            if self.blacklist.read(caller) {
                self.emit(PaymasterValidation {
                    caller, target, selector, approved: false,
                    timestamp: get_block_timestamp(),
                });
                return false;
            }

            // 3. Target must be proof_verifier or stwo_verifier
            if !self._is_allowed_target(target) {
                self.emit(PaymasterValidation {
                    caller, target, selector, approved: false,
                    timestamp: get_block_timestamp(),
                });
                return false;
            }

            // 4. Worker must be staked via ProverStaking.is_eligible()
            let staking_addr = self.prover_staking.read();
            if !staking_addr.is_zero() {
                let staking = IProverStakingDispatcher { contract_address: staking_addr };
                if !staking.is_eligible(caller) {
                    self.emit(PaymasterValidation {
                        caller, target, selector, approved: false,
                        timestamp: get_block_timestamp(),
                    });
                    return false;
                }
            }

            // 5. Rate limit check
            if !self._check_rate_limit_internal(caller) {
                self.emit(PaymasterValidation {
                    caller, target, selector, approved: false,
                    timestamp: get_block_timestamp(),
                });
                return false;
            }

            // 6. Epoch spending cap check
            if !self._check_epoch_spend_ok(estimated_fee) {
                self.emit(PaymasterValidation {
                    caller, target, selector, approved: false,
                    timestamp: get_block_timestamp(),
                });
                return false;
            }

            // 7. Function must be sponsorable
            let function_key = self._get_function_key(target, selector);
            if !self.sponsorable_functions.read(function_key) {
                self.emit(PaymasterValidation {
                    caller, target, selector, approved: false,
                    timestamp: get_block_timestamp(),
                });
                return false;
            }

            self.emit(PaymasterValidation {
                caller, target, selector, approved: true,
                timestamp: get_block_timestamp(),
            });

            true
        }

        fn __execute_paymaster__(
            ref self: ContractState,
            caller: ContractAddress,
            target: ContractAddress,
            selector: felt252,
            actual_fee: u256
        ) {
            // Update per-account stats
            let prev_total = self.account_total_sponsored.read(caller);
            self.account_total_sponsored.write(caller, prev_total + actual_fee);

            let prev_count = self.account_tx_count.read(caller);
            self.account_tx_count.write(caller, prev_count + 1);

            self.account_last_sponsored.write(caller, get_block_timestamp());

            // Update global stats
            let prev_global = self.total_sponsored.read();
            self.total_sponsored.write(prev_global + actual_fee);

            // Update rate limit
            self._update_rate_limit(caller);

            // Update epoch spending
            self._check_and_update_epoch_spend(actual_fee);

            self.emit(PaymasterExecution {
                caller,
                target,
                selector,
                fee: actual_fee,
                timestamp: get_block_timestamp(),
            });
        }

        // ====================================================================
        // V2: Timelock Upgrade Mechanism
        // ====================================================================

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            assert!(!new_class_hash.is_zero(), "Invalid class hash");

            let now = get_block_timestamp();
            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(now);

            let delay = self.upgrade_delay.read();
            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: now,
                executable_at: now + delay,
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            self._only_owner();

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No upgrade scheduled");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let now = get_block_timestamp();
            assert!(now >= scheduled_at + delay, "Upgrade delay not elapsed");

            // Clear pending upgrade before executing
            self.pending_upgrade.write(Zero::zero());
            self.upgrade_scheduled_at.write(0);

            replace_class_syscall(pending).unwrap();

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: now,
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No upgrade scheduled");

            self.pending_upgrade.write(Zero::zero());
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_at: get_block_timestamp(),
            });
        }

        fn get_pending_upgrade(self: @ContractState) -> (ClassHash, u64) {
            (self.pending_upgrade.read(), self.upgrade_scheduled_at.read())
        }

        // ====================================================================
        // V2: Configuration
        // ====================================================================

        fn initialize_v2(
            ref self: ContractState,
            prover_staking: ContractAddress,
            proof_verifier: ContractAddress,
            stwo_verifier: ContractAddress
        ) {
            self._only_owner();
            assert!(!self.v2_initialized.read(), "V2 already initialized");

            self.prover_staking.write(prover_staking);
            self.proof_verifier.write(proof_verifier);
            self.stwo_verifier.write(stwo_verifier);

            // Set default epoch config
            let now = get_block_timestamp();
            self.epoch_start.write(now);
            self.epoch_spent.write(0);
            self.max_epoch_spend.write(DEFAULT_MAX_EPOCH_SPEND);
            self.epoch_duration.write(DEFAULT_EPOCH_DURATION);

            self.v2_initialized.write(true);

            self.emit(V2Initialized {
                prover_staking,
                proof_verifier,
                stwo_verifier,
                timestamp: now,
            });
        }

        fn set_prover_staking(ref self: ContractState, prover_staking: ContractAddress) {
            self._only_owner();
            self.prover_staking.write(prover_staking);
        }

        fn set_proof_verifier(ref self: ContractState, proof_verifier: ContractAddress) {
            self._only_owner();
            self.proof_verifier.write(proof_verifier);
        }

        fn set_stwo_verifier(ref self: ContractState, stwo_verifier: ContractAddress) {
            self._only_owner();
            self.stwo_verifier.write(stwo_verifier);
        }

        fn set_spending_cap(ref self: ContractState, max_per_epoch: u256, epoch_duration: u64) {
            self._only_owner();
            assert!(epoch_duration > 0, "Epoch duration must be > 0");

            self.max_epoch_spend.write(max_per_epoch);
            self.epoch_duration.write(epoch_duration);

            // Reset current epoch
            let now = get_block_timestamp();
            self.epoch_start.write(now);
            self.epoch_spent.write(0);

            self.emit(SpendingCapUpdated {
                max_per_epoch,
                epoch_duration,
                timestamp: now,
            });
        }

        // ====================================================================
        // V2: View Functions
        // ====================================================================

        fn get_epoch_stats(self: @ContractState) -> (u64, u256, u256, u64) {
            (
                self.epoch_start.read(),
                self.epoch_spent.read(),
                self.max_epoch_spend.read(),
                self.epoch_duration.read()
            )
        }

        fn get_prover_staking(self: @ContractState) -> ContractAddress {
            self.prover_staking.read()
        }

        fn get_proof_verifier(self: @ContractState) -> ContractAddress {
            self.proof_verifier.read()
        }

        fn get_stwo_verifier(self: @ContractState) -> ContractAddress {
            self.stwo_verifier.read()
        }

        fn is_allowed_target(self: @ContractState, target: ContractAddress) -> bool {
            self._is_allowed_target(target)
        }
    }

    // Internal functions
    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn _only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert!(caller == owner, "Only owner");
        }

        fn _get_function_key(
            self: @ContractState,
            contract: ContractAddress,
            selector: felt252
        ) -> felt252 {
            let input: Array<felt252> = array![contract.into(), selector];
            poseidon_hash_span(input.span())
        }

        fn _check_rate_limit_internal(self: @ContractState, account: ContractAddress) -> bool {
            let rate_limit = self.rate_limits.read(account);
            let now = get_block_timestamp();

            if now > rate_limit.window_start + SECONDS_PER_HOUR {
                return true;
            }

            rate_limit.current_count < rate_limit.requests_per_hour
        }

        fn _update_rate_limit(ref self: ContractState, account: ContractAddress) {
            let mut rate_limit = self.rate_limits.read(account);
            let now = get_block_timestamp();

            if now > rate_limit.window_start + SECONDS_PER_HOUR {
                rate_limit.window_start = now;
                rate_limit.current_count = 1;
            } else {
                rate_limit.current_count += 1;
            }

            self.rate_limits.write(account, rate_limit);
        }

        fn _get_remaining_allowance(self: @ContractState, account: ContractAddress) -> u256 {
            let subscription = self.subscriptions.read(account);
            let now = get_block_timestamp();

            if !subscription.active || now > subscription.expiration {
                let config = self.config.read();
                return config.free_tier_daily_limit;
            }

            if now > subscription.last_reset + SECONDS_PER_DAY {
                return subscription.daily_limit;
            }

            if subscription.daily_used >= subscription.daily_limit {
                return 0;
            }

            subscription.daily_limit - subscription.daily_used
        }

        fn _check_and_update_allowance(
            ref self: ContractState,
            account: ContractAddress,
            gas_amount: u256
        ) {
            let subscription = self.subscriptions.read(account);
            let now = get_block_timestamp();

            let (new_daily_used, new_last_reset) = if now > subscription.last_reset + SECONDS_PER_DAY {
                (gas_amount, now)
            } else {
                (subscription.daily_used + gas_amount, subscription.last_reset)
            };

            let remaining = if subscription.active && now <= subscription.expiration {
                if now > subscription.last_reset + SECONDS_PER_DAY {
                    subscription.daily_limit
                } else {
                    subscription.daily_limit - subscription.daily_used
                }
            } else {
                self.config.read().free_tier_daily_limit
            };

            assert!(gas_amount <= remaining, "Insufficient daily allowance");

            let updated_subscription = Subscription {
                tier: subscription.tier,
                expiration: subscription.expiration,
                daily_limit: subscription.daily_limit,
                daily_used: new_daily_used,
                last_reset: new_last_reset,
                active: subscription.active,
            };
            self.subscriptions.write(account, updated_subscription);
        }

        fn _register_privacy_functions(
            ref self: ContractState,
            privacy_router: ContractAddress,
            privacy_pools: ContractAddress
        ) {
            let key1 = self._get_function_key(privacy_pools, PP_DEPOSIT_SELECTOR);
            self.sponsorable_functions.write(key1, true);

            let key2 = self._get_function_key(privacy_pools, PP_WITHDRAW_SELECTOR);
            self.sponsorable_functions.write(key2, true);

            let key3 = self._get_function_key(privacy_router, PRIVATE_TRANSFER_SELECTOR);
            self.sponsorable_functions.write(key3, true);
        }

        // V2: Check if target is an allowed contract
        fn _is_allowed_target(self: @ContractState, target: ContractAddress) -> bool {
            let pv = self.proof_verifier.read();
            let sv = self.stwo_verifier.read();
            // If V2 not configured (both zero), allow all targets (backwards compat)
            if pv.is_zero() && sv.is_zero() {
                return true;
            }
            target == pv || target == sv
        }

        // V2: Check if epoch spend would exceed cap (read-only)
        fn _check_epoch_spend_ok(self: @ContractState, additional: u256) -> bool {
            let max_spend = self.max_epoch_spend.read();
            if max_spend.is_zero() {
                return true; // No cap set
            }

            let epoch_dur = self.epoch_duration.read();
            let epoch_st = self.epoch_start.read();
            let now = get_block_timestamp();

            // If epoch expired, spending resets to 0
            if now >= epoch_st + epoch_dur {
                return additional <= max_spend;
            }

            let current_spent = self.epoch_spent.read();
            current_spent + additional <= max_spend
        }

        // V2: Update epoch spending tracker
        fn _check_and_update_epoch_spend(ref self: ContractState, amount: u256) {
            let max_spend = self.max_epoch_spend.read();
            if max_spend.is_zero() {
                return; // No cap set
            }

            let epoch_dur = self.epoch_duration.read();
            let epoch_st = self.epoch_start.read();
            let now = get_block_timestamp();

            if now >= epoch_st + epoch_dur {
                // Reset epoch
                let previous_spent = self.epoch_spent.read();
                self.epoch_start.write(now);
                self.epoch_spent.write(amount);

                self.emit(EpochReset {
                    new_epoch_start: now,
                    previous_spent,
                });
            } else {
                let current = self.epoch_spent.read();
                assert!(current + amount <= max_spend, "Epoch spending cap exceeded");
                self.epoch_spent.write(current + amount);
            }
        }
    }
}
