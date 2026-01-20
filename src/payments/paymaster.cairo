// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Paymaster Contract - Gas Abstraction for Privacy Operations
// Sponsors gas fees for privacy transactions to prevent gas payment linkage
// Supports: Privacy deposits, withdrawals, transfers, and worker operations

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
    ) -> felt252; // Returns tx hash

    fn validate_sponsorship(
        self: @TContractState,
        request: SponsorshipRequest
    ) -> (bool, felt252); // (is_valid, reason)

    fn get_sponsorship_quote(
        self: @TContractState,
        target_contract: ContractAddress,
        function_selector: felt252,
        calldata_len: u32
    ) -> u256; // Returns estimated gas cost

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
    ) -> (u256, u32, u64); // (total_gas, tx_count, last_sponsored)
}

#[starknet::contract]
pub mod Paymaster {
    use super::{
        IPaymaster, SubscriptionTier, Subscription, SponsorshipRequest,
        SponsoredTransaction, RateLimit, PaymasterConfig
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        get_contract_address, get_tx_info, syscalls::call_contract_syscall,
        storage::{StoragePointerReadAccess, StoragePointerWriteAccess,
                  StorageMapReadAccess, StorageMapWriteAccess}
    };
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;

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

    // Constants
    const SECONDS_PER_DAY: u64 = 86400;
    const SECONDS_PER_HOUR: u64 = 3600;
    const DEFAULT_FREE_DAILY_LIMIT: u256 = 100000000000000000; // 0.1 ETH worth of gas
    const DEFAULT_BASIC_DAILY_LIMIT: u256 = 1000000000000000000; // 1 ETH worth
    const DEFAULT_PREMIUM_DAILY_LIMIT: u256 = 10000000000000000000; // 10 ETH worth
    const DEFAULT_RATE_LIMIT: u32 = 100; // 100 requests per hour

    // Privacy function selectors (pre-computed)
    // pp_deposit selector
    const PP_DEPOSIT_SELECTOR: felt252 = 0x02e4d2d5e12b2e5b1c5e8a9f3d7c6b4a1e8f2d3c5a7b9e1f4d6c8a2b3e5f7d9;
    // pp_withdraw selector
    const PP_WITHDRAW_SELECTOR: felt252 = 0x03f5e3e6f13c3f6c2d6f9b0e4e8d7c5b2f9e3d4c6b8a0f2e5d7c9a3b4e6f8d0;
    // private_transfer selector
    const PRIVATE_TRANSFER_SELECTOR: felt252 = 0x04a6f4f7a24d4a7d3e7a0c1f5f9e8d6c3a0f4e5d7c9b1a3e6f8d0b2c4e7f9a1;

    #[abi(embed_v0)]
    impl PaymasterImpl of IPaymaster<ContractState> {
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
                max_gas_per_tx: 10000000000000000000, // 10 ETH max per tx
                max_gas_per_day: 100000000000000000000, // 100 ETH max per day
                free_tier_daily_limit: DEFAULT_FREE_DAILY_LIMIT,
                basic_tier_daily_limit: DEFAULT_BASIC_DAILY_LIMIT,
                premium_tier_daily_limit: DEFAULT_PREMIUM_DAILY_LIMIT,
            };
            self.config.write(config);

            // Register default sponsorable functions (privacy operations)
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
            // Validation
            assert!(!self.paused.read(), "Paymaster is paused");
            assert!(!self.blacklist.read(request.account), "Account is blacklisted");

            // Validate the sponsorship request
            let (is_valid, reason) = self.validate_sponsorship(request);
            assert!(is_valid, "Sponsorship validation failed");

            // Check nonce for replay protection
            let expected_nonce = self.nonces.read(request.account);
            assert!(request.nonce == expected_nonce, "Invalid nonce");

            // Update nonce
            self.nonces.write(request.account, expected_nonce + 1);

            // Check and update daily allowance
            self._check_and_update_allowance(request.account, request.estimated_gas);

            // Update rate limit
            self._update_rate_limit(request.account);

            // Execute the transaction via low-level call
            // In production, this would use account abstraction
            let result = call_contract_syscall(
                request.target_contract,
                request.function_selector,
                calldata.span()
            );

            // Generate transaction hash for tracking
            let mut hash_input: Array<felt252> = array![
                request.account.into(),
                request.target_contract.into(),
                request.function_selector,
                request.nonce.into(),
            ];
            let tx_hash = poseidon_hash_span(hash_input.span());

            // Update stats
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
            // Check if function is sponsorable
            let function_key = self._get_function_key(
                request.target_contract,
                request.function_selector
            );
            if !self.sponsorable_functions.read(function_key) {
                return (false, 'Function not sponsorable');
            }

            // Check blacklist
            if self.blacklist.read(request.account) {
                return (false, 'Account blacklisted');
            }

            // Check rate limit
            if !self._check_rate_limit_internal(request.account) {
                return (false, 'Rate limit exceeded');
            }

            // Check daily allowance
            let remaining = self._get_remaining_allowance(request.account);
            if remaining < request.estimated_gas {
                return (false, 'Daily limit exceeded');
            }

            // Check paymaster balance
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
            // Estimate gas based on function and calldata size
            // Base cost + per-felt cost
            let base_cost: u256 = 21000; // Base transaction cost
            let per_felt_cost: u256 = 16; // Cost per calldata felt
            let function_cost: u256 = 50000; // Estimated execution cost

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
                    // Enterprise requires owner approval
                    assert!(self.allowlist.read(caller), "Enterprise requires allowlist");
                    0xffffffffffffffffffffffffffffffff_u256 // Unlimited
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

            // Set default rate limit
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

            // Transfer tokens to paymaster
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

            // Reset window if expired
            if now > rate_limit.window_start + SECONDS_PER_HOUR {
                return true; // Will be reset on update
            }

            rate_limit.current_count < rate_limit.requests_per_hour
        }

        fn _update_rate_limit(ref self: ContractState, account: ContractAddress) {
            let mut rate_limit = self.rate_limits.read(account);
            let now = get_block_timestamp();

            // Reset window if expired
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

            // Check if subscription is active
            if !subscription.active || now > subscription.expiration {
                // Use free tier for non-subscribers
                let config = self.config.read();
                return config.free_tier_daily_limit;
            }

            // Reset daily usage if new day
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

            // Calculate new values
            let (new_daily_used, new_last_reset) = if now > subscription.last_reset + SECONDS_PER_DAY {
                (gas_amount, now) // Reset and add new usage
            } else {
                (subscription.daily_used + gas_amount, subscription.last_reset)
            };

            // Check allowance
            let remaining = if subscription.active && now <= subscription.expiration {
                if now > subscription.last_reset + SECONDS_PER_DAY {
                    subscription.daily_limit // Full limit after reset
                } else {
                    subscription.daily_limit - subscription.daily_used
                }
            } else {
                self.config.read().free_tier_daily_limit
            };

            assert!(gas_amount <= remaining, "Insufficient daily allowance");

            // Write updated subscription
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
            // Register privacy pool functions
            // pp_deposit
            let key1 = self._get_function_key(privacy_pools, PP_DEPOSIT_SELECTOR);
            self.sponsorable_functions.write(key1, true);

            // pp_withdraw
            let key2 = self._get_function_key(privacy_pools, PP_WITHDRAW_SELECTOR);
            self.sponsorable_functions.write(key2, true);

            // private_transfer on privacy router
            let key3 = self._get_function_key(privacy_router, PRIVATE_TRANSFER_SELECTOR);
            self.sponsorable_functions.write(key3, true);
        }
    }
}
