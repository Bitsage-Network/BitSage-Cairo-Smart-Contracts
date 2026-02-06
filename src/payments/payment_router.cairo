// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Payment Router - Multi-token payment system with OTC desk
// Accepts: USDC, STRK, wBTC, SAGE with tiered discounts
// All payments flow through Obelysk as SAGE with optional privacy

use starknet::{ContractAddress, ClassHash};

// Re-export ECPoint for interface usage
pub use sage_contracts::obelysk::elgamal::ECPoint;

/// Supported payment tokens
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum PaymentToken {
    USDC,
    STRK,
    WBTC,
    SAGE,
    STAKED_SAGE,    // Pay from staked position
    PRIVACY_CREDIT, // Anonymous pre-funded balance
}

/// Payment quote from OTC desk
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PaymentQuote {
    pub quote_id: u256,
    pub payment_token: PaymentToken,
    pub payment_amount: u256,      // Amount user pays (in payment token)
    pub sage_equivalent: u256,     // SAGE value after conversion
    pub discount_bps: u32,         // Discount applied in basis points
    pub usd_value: u256,           // USD value (18 decimals)
    pub expires_at: u64,           // Quote expiration timestamp
    pub is_valid: bool,
}

/// OTC desk configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct OTCConfig {
    pub usdc_address: ContractAddress,
    pub strk_address: ContractAddress,
    pub wbtc_address: ContractAddress,
    pub sage_address: ContractAddress,
    pub oracle_address: ContractAddress,
    pub staking_address: ContractAddress,
    pub quote_validity_seconds: u64,    // How long quotes are valid
    pub max_slippage_bps: u32,          // Max price movement allowed
}

/// Fee distribution configuration
/// BitSage Model: 80% to worker, 20% protocol fee
/// Protocol fee split: 70% burn, 20% treasury, 10% stakers
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FeeDistribution {
    pub worker_bps: u32,            // Worker share (8000 = 80%)
    pub protocol_fee_bps: u32,      // Protocol fee (2000 = 20%)
    // Protocol fee breakdown (must sum to 10000):
    pub burn_share_bps: u32,        // Burn from protocol fee (7000 = 70%)
    pub treasury_share_bps: u32,    // Treasury from protocol fee (2000 = 20%)
    pub staker_share_bps: u32,      // Staker rewards from protocol fee (1000 = 10%)
}

/// Discount tiers by payment method
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct DiscountTiers {
    pub stablecoin_discount_bps: u32,   // USDC/USDT: 0%
    pub strk_discount_bps: u32,          // STRK: 0%
    pub wbtc_discount_bps: u32,          // wBTC: 0%
    pub sage_discount_bps: u32,          // SAGE direct: 500 = 5%
    pub staked_sage_discount_bps: u32,   // Staked SAGE: 1000 = 10%
    pub privacy_credit_discount_bps: u32, // Privacy: 200 = 2%
}

#[starknet::interface]
pub trait IPaymentRouter<TContractState> {
    /// Get a payment quote for compute services
    /// @param payment_token: Token user wants to pay with
    /// @param usd_amount: USD value of compute services (18 decimals)
    /// @return quote: Payment quote with amounts and discount
    fn get_quote(
        self: @TContractState,
        payment_token: PaymentToken,
        usd_amount: u256
    ) -> PaymentQuote;

    /// Execute payment for compute services
    /// @param quote_id: Quote ID to execute
    /// @param job_id: Job being paid for
    /// @return success: Whether payment succeeded
    fn execute_payment(
        ref self: TContractState,
        quote_id: u256,
        job_id: u256
    ) -> bool;

    /// Execute direct SAGE payment (no quote needed)
    /// @param amount: SAGE amount to pay
    /// @param job_id: Job being paid for
    fn pay_with_sage(
        ref self: TContractState,
        amount: u256,
        job_id: u256
    );

    /// Pay using staked SAGE position (best discount)
    /// @param usd_amount: USD value of compute
    /// @param job_id: Job being paid for
    fn pay_with_staked_sage(
        ref self: TContractState,
        usd_amount: u256,
        job_id: u256
    );

    /// Deposit privacy credits (pre-fund anonymous balance)
    /// @param amount: SAGE amount to deposit
    /// @param commitment: Privacy commitment hash
    fn deposit_privacy_credits(
        ref self: TContractState,
        amount: u256,
        commitment: felt252
    );

    /// Pay using privacy credits
    /// @param usd_amount: USD value of compute
    /// @param nullifier: Nullifier to prevent double-spend
    /// @param proof: ZK proof of valid balance
    fn pay_with_privacy_credits(
        ref self: TContractState,
        usd_amount: u256,
        nullifier: felt252,
        proof: Array<felt252>
    );

    /// Get current discount tiers
    fn get_discount_tiers(self: @TContractState) -> DiscountTiers;

    /// Get fee distribution config
    fn get_fee_distribution(self: @TContractState) -> FeeDistribution;

    /// Get OTC desk config
    fn get_otc_config(self: @TContractState) -> OTCConfig;

    /// Admin: Update discount tiers
    fn set_discount_tiers(ref self: TContractState, tiers: DiscountTiers);

    /// Admin: Update fee distribution
    fn set_fee_distribution(ref self: TContractState, distribution: FeeDistribution);

    /// Admin: Update OTC config
    fn set_otc_config(ref self: TContractState, config: OTCConfig);

    // === Configuration Functions (Production-grade initialization) ===

    /// Configure the obelysk_router dependency. Call after PrivacyRouter is deployed.
    fn configure(ref self: TContractState, obelysk_router: ContractAddress);

    /// Finalize configuration - locks obelysk_router permanently
    fn finalize_configuration(ref self: TContractState);

    /// Check if contract is configured
    fn is_contract_configured(self: @TContractState) -> bool;

    /// Check if configuration is locked
    fn is_configuration_locked(self: @TContractState) -> bool;

    /// Admin: Set Obelysk router address (deprecated, use configure())
    fn set_obelysk_router(ref self: TContractState, router: ContractAddress);

    /// Admin: Set staker rewards pool address
    fn set_staker_rewards_pool(ref self: TContractState, pool: ContractAddress);

    /// Admin: Set authorized proof submitter (coordinator address that can call register_job)
    fn set_authorized_submitter(ref self: TContractState, submitter: ContractAddress);

    /// Register job with worker (called by JobManager)
    /// @param job_id: Job identifier
    /// @param worker: GPU provider address
    /// @param privacy_enabled: Whether to use Obelysk privacy for payment
    fn register_job(
        ref self: TContractState,
        job_id: u256,
        worker: ContractAddress,
        privacy_enabled: bool
    );

    /// Get payment stats
    fn get_stats(self: @TContractState) -> (u256, u256, u256, u256, u256);

    /// Register worker public key for privacy payments
    /// Workers must register their ElGamal public key to receive encrypted payments
    fn register_worker_public_key(
        ref self: TContractState,
        public_key: ECPoint
    );

    /// Get worker's public key
    fn get_worker_public_key(self: @TContractState, worker: ContractAddress) -> ECPoint;

    // ==================== UPGRADE FUNCTIONS ====================

    /// Schedule a contract upgrade (owner only, timelocked)
    /// @param new_class_hash: The class hash of the new implementation
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);

    /// Execute a scheduled upgrade after timelock expires
    fn execute_upgrade(ref self: TContractState);

    /// Cancel a pending upgrade (owner only)
    fn cancel_upgrade(ref self: TContractState);

    /// Get pending upgrade information
    /// @return (pending_class_hash, scheduled_at, delay)
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);

    /// Set upgrade delay (owner only)
    /// @param delay: New delay in seconds (minimum 1 day)
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[starknet::contract]
mod PaymentRouter {
    use super::{
        IPaymentRouter, PaymentToken, PaymentQuote, OTCConfig,
        FeeDistribution, DiscountTiers, ECPoint
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_contract_address,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use core::num::traits::Zero;
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use sage_contracts::oracle::pragma_oracle::{
        IOracleWrapperDispatcher, IOracleWrapperDispatcherTrait, PricePair
    };

    // ERC20 Interface for token transfers
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // SAGE Token interface for burn functionality
    use sage_contracts::interfaces::sage_token::{ISAGETokenDispatcher, ISAGETokenDispatcherTrait};

    // Obelysk Privacy Router for private worker payments
    use sage_contracts::obelysk::privacy_router::{IPrivacyRouterDispatcher, IPrivacyRouterDispatcherTrait};
    use sage_contracts::obelysk::elgamal::{encrypt, is_zero};

    // Base SAGE price: $0.10 = 100000000000000000 (0.1 * 10^18)
    const BASE_SAGE_PRICE_USD: u256 = 100000000000000000;
    const USD_DECIMALS: u256 = 1000000000000000000; // 10^18
    const BPS_DENOMINATOR: u256 = 10000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        otc_config: OTCConfig,
        fee_distribution: FeeDistribution,
        discount_tiers: DiscountTiers,

        // Quote management
        quote_counter: u256,
        quotes: Map<u256, PaymentQuote>,
        quote_user: Map<u256, ContractAddress>,

        // Treasury balances (multi-asset)
        treasury_usdc: u256,
        treasury_strk: u256,
        treasury_wbtc: u256,
        treasury_sage: u256,

        // Privacy credit commitments
        privacy_commitments: Map<felt252, bool>,
        privacy_nullifiers: Map<felt252, bool>,

        // Staked SAGE credit tracking
        staked_credits_used: Map<ContractAddress, u256>,

        // Obelysk integration
        // obelysk_router is set via configure() to avoid circular dependency with PrivacyRouter
        obelysk_router: ContractAddress,      // Privacy router for optional anonymous payments
        staker_rewards_pool: ContractAddress, // Where 10% of protocol fee goes
        treasury_address: ContractAddress,    // Where 20% of protocol fee goes

        // Configuration state - production-grade initialization pattern
        configured: bool,   // True once configure() is called
        finalized: bool,    // True once finalize() is called - locks forever

        // Authorized proof submitter (coordinator/deployer that can call register_job)
        authorized_submitter: ContractAddress,

        // Job-to-worker mapping (set by JobManager)
        job_worker: Map<u256, ContractAddress>,
        job_privacy_enabled: Map<u256, bool>,

        // Worker public keys for privacy payments
        worker_public_keys: Map<ContractAddress, ECPoint>,

        // Privacy payment randomness seed (incremented per payment)
        privacy_nonce: u256,

        // Stats
        total_payments_usd: u256,
        total_sage_burned: u256,
        total_worker_payments: u256,
        total_staker_rewards: u256,
        total_treasury_collected: u256,

        // ================ REENTRANCY GUARD ================
        _reentrancy_guard: bool,

        // ================ UPGRADE STORAGE ================
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        QuoteCreated: QuoteCreated,
        PaymentExecuted: PaymentExecuted,
        PrivacyCreditsDeposited: PrivacyCreditsDeposited,
        PrivacyPayment: PrivacyPayment,
        FeesDistributed: FeesDistributed,
        WorkerPaid: WorkerPaid,
        // Upgrade events
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct QuoteCreated {
        #[key]
        quote_id: u256,
        #[key]
        user: ContractAddress,
        payment_token: felt252,
        usd_amount: u256,
        payment_amount: u256,
        discount_bps: u32,
        expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PaymentExecuted {
        #[key]
        quote_id: u256,
        #[key]
        job_id: u256,
        #[key]
        payer: ContractAddress,
        payment_token: felt252,
        payment_amount: u256,
        sage_equivalent: u256,
        usd_value: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivacyCreditsDeposited {
        commitment: felt252,
        amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PrivacyPayment {
        #[key]
        job_id: u256,
        nullifier: felt252,
        usd_amount: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FeesDistributed {
        total_sage: u256,
        to_worker: u256,
        protocol_fee: u256,
        burned: u256,
        to_treasury: u256,
        to_stakers: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct WorkerPaid {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        sage_amount: u256,
        privacy_enabled: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        #[key]
        new_class_hash: ClassHash,
        scheduled_at: u64,
        execute_after: u64,
        scheduled_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        #[key]
        new_class_hash: ClassHash,
        executed_at: u64,
        executed_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        #[key]
        cancelled_class_hash: ClassHash,
        cancelled_at: u64,
        cancelled_by: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_address: ContractAddress,
        oracle_address: ContractAddress,
        staker_rewards_pool: ContractAddress,
        treasury_address: ContractAddress
    ) {
        // Production-grade: obelysk_router removed from constructor
        // It creates a circular dependency with PrivacyRouter
        // Set via configure() after PrivacyRouter is deployed
        assert!(!owner.is_zero(), "Invalid owner");
        assert!(!sage_address.is_zero(), "Invalid SAGE address");

        self.owner.write(owner);
        self.staker_rewards_pool.write(staker_rewards_pool);
        self.treasury_address.write(treasury_address);

        // Initialize with zero addresses - to be configured
        let config = OTCConfig {
            usdc_address: 0.try_into().unwrap(),
            strk_address: 0.try_into().unwrap(),
            wbtc_address: 0.try_into().unwrap(),
            sage_address,
            oracle_address,
            staking_address: 0.try_into().unwrap(),
            quote_validity_seconds: 300, // 5 minutes
            max_slippage_bps: 100,       // 1% max slippage
        };
        self.otc_config.write(config);

        // BitSage fee model: 80% to worker, 20% protocol fee
        // Protocol fee split: 70% burn, 20% treasury, 10% stakers
        let fee_dist = FeeDistribution {
            worker_bps: 8000,           // 80% to GPU provider
            protocol_fee_bps: 2000,     // 20% protocol fee
            burn_share_bps: 7000,       // 70% of protocol fee burned
            treasury_share_bps: 2000,   // 20% of protocol fee to treasury
            staker_share_bps: 1000,     // 10% of protocol fee to stakers
        };
        self.fee_distribution.write(fee_dist);

        // Default discount tiers
        let discounts = DiscountTiers {
            stablecoin_discount_bps: 0,      // 0%
            strk_discount_bps: 0,            // 0%
            wbtc_discount_bps: 0,            // 0%
            sage_discount_bps: 500,          // 5%
            staked_sage_discount_bps: 1000,  // 10%
            privacy_credit_discount_bps: 200, // 2%
        };
        self.discount_tiers.write(discounts);

        self.quote_counter.write(0);

        // Initialize upgrade delay: 5 minutes (300 seconds) - testnet friendly
        self.upgrade_delay.write(300);

        // Configuration state
        self.configured.write(false);
        self.finalized.write(false);
    }

    #[abi(embed_v0)]
    impl PaymentRouterImpl of IPaymentRouter<ContractState> {
        fn get_quote(
            self: @ContractState,
            payment_token: PaymentToken,
            usd_amount: u256
        ) -> PaymentQuote {
            let now = get_block_timestamp();
            let config = self.otc_config.read();
            let discounts = self.discount_tiers.read();

            // Get discount for payment method
            let discount_bps = self._get_discount_for_token(@payment_token, @discounts);

            // Apply discount to USD amount
            let discounted_usd = (usd_amount * (BPS_DENOMINATOR - discount_bps.into())) / BPS_DENOMINATOR;

            // Calculate payment amount based on token
            let (payment_amount, sage_equivalent) = self._calculate_payment_amount(
                @payment_token,
                discounted_usd
            );

            let quote_id = self.quote_counter.read() + 1;

            PaymentQuote {
                quote_id,
                payment_token,
                payment_amount,
                sage_equivalent,
                discount_bps,
                usd_value: usd_amount,
                expires_at: now + config.quote_validity_seconds,
                is_valid: true,
            }
        }

        fn execute_payment(
            ref self: ContractState,
            quote_id: u256,
            job_id: u256
        ) -> bool {
            // SECURITY: Reentrancy guard for external calls
            self._start_nonreentrant();

            let caller = get_caller_address();
            let now = get_block_timestamp();

            // Verify quote exists and belongs to caller
            let quote = self.quotes.read(quote_id);
            let quote_owner = self.quote_user.read(quote_id);

            assert(quote.is_valid, 'Invalid quote');
            assert(quote_owner == caller, 'Not quote owner');
            assert(now <= quote.expires_at, 'Quote expired');

            // Mark quote as used (state update BEFORE external calls - CEI pattern)
            let mut used_quote = quote;
            used_quote.is_valid = false;
            self.quotes.write(quote_id, used_quote);

            // Update stats BEFORE external calls
            let total_usd = self.total_payments_usd.read();
            self.total_payments_usd.write(total_usd + quote.usd_value);

            // Transfer payment token from user (external call)
            self._collect_payment(caller, quote.payment_token, quote.payment_amount);

            // Distribute fees in SAGE (external calls)
            self._distribute_fees(quote.sage_equivalent, job_id);

            self.emit(PaymentExecuted {
                quote_id,
                job_id,
                payer: caller,
                payment_token: self._token_to_felt(quote.payment_token),
                payment_amount: quote.payment_amount,
                sage_equivalent: quote.sage_equivalent,
                usd_value: quote.usd_value,
            });

            self._end_nonreentrant();
            true
        }

        fn pay_with_sage(
            ref self: ContractState,
            amount: u256,
            job_id: u256
        ) {
            // SECURITY: Reentrancy guard for external calls
            self._start_nonreentrant();

            let caller = get_caller_address();
            let discounts = self.discount_tiers.read();

            // Direct SAGE payment gets discount
            let effective_amount = (amount * (BPS_DENOMINATOR + discounts.sage_discount_bps.into())) / BPS_DENOMINATOR;

            // Calculate USD value for stats and update BEFORE external calls (CEI pattern)
            let usd_value = (amount * BASE_SAGE_PRICE_USD) / USD_DECIMALS;
            let total_usd = self.total_payments_usd.read();
            self.total_payments_usd.write(total_usd + usd_value);

            // Transfer SAGE from user (external call)
            self._collect_payment(caller, PaymentToken::SAGE, amount);

            // Distribute fees (external calls)
            self._distribute_fees(effective_amount, job_id);

            self.emit(PaymentExecuted {
                quote_id: 0,
                job_id,
                payer: caller,
                payment_token: 'SAGE',
                payment_amount: amount,
                sage_equivalent: effective_amount,
                usd_value,
            });

            self._end_nonreentrant();
        }

        fn pay_with_staked_sage(
            ref self: ContractState,
            usd_amount: u256,
            job_id: u256
        ) {
            let caller = get_caller_address();
            let discounts = self.discount_tiers.read();

            // Calculate discounted amount (10% off)
            let discounted_usd = (usd_amount * (BPS_DENOMINATOR - discounts.staked_sage_discount_bps.into())) / BPS_DENOMINATOR;

            // Convert to SAGE at current price
            let sage_amount = (discounted_usd * USD_DECIMALS) / BASE_SAGE_PRICE_USD;

            // Verify user has sufficient staked balance
            // Note: This would interact with the staking contract
            let credits_used = self.staked_credits_used.read(caller);
            // In production: check staking contract for available balance

            // Record credit usage
            self.staked_credits_used.write(caller, credits_used + sage_amount);

            // Distribute fees (from protocol reserves, not user transfer)
            self._distribute_fees(sage_amount, job_id);

            // Update stats
            let total_usd = self.total_payments_usd.read();
            self.total_payments_usd.write(total_usd + usd_amount);

            self.emit(PaymentExecuted {
                quote_id: 0,
                job_id,
                payer: caller,
                payment_token: 'STAKED_SAGE',
                payment_amount: sage_amount,
                sage_equivalent: sage_amount,
                usd_value: usd_amount,
            });
        }

        fn deposit_privacy_credits(
            ref self: ContractState,
            amount: u256,
            commitment: felt252
        ) {
            let caller = get_caller_address();

            // Verify commitment not already used
            assert(!self.privacy_commitments.read(commitment), 'Commitment exists');

            // Transfer SAGE from user
            self._collect_payment(caller, PaymentToken::SAGE, amount);

            // Record commitment
            self.privacy_commitments.write(commitment, true);

            self.emit(PrivacyCreditsDeposited {
                commitment,
                amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn pay_with_privacy_credits(
            ref self: ContractState,
            usd_amount: u256,
            nullifier: felt252,
            proof: Array<felt252>
        ) {
            // Verify nullifier not already used (prevent double-spend)
            assert(!self.privacy_nullifiers.read(nullifier), 'Nullifier used');

            // Verify ZK proof
            // In production: call proof verifier contract
            assert(proof.len() > 0, 'Invalid proof');

            // Mark nullifier as used
            self.privacy_nullifiers.write(nullifier, true);

            // Calculate SAGE equivalent with privacy discount (2%)
            let discounts = self.discount_tiers.read();
            let discounted_usd = (usd_amount * (BPS_DENOMINATOR - discounts.privacy_credit_discount_bps.into())) / BPS_DENOMINATOR;
            let sage_amount = (discounted_usd * USD_DECIMALS) / BASE_SAGE_PRICE_USD;

            // Distribute fees (from privacy pool)
            self._distribute_fees(sage_amount, 0);

            self.emit(PrivacyPayment {
                job_id: 0,
                nullifier,
                usd_amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_discount_tiers(self: @ContractState) -> DiscountTiers {
            self.discount_tiers.read()
        }

        fn get_fee_distribution(self: @ContractState) -> FeeDistribution {
            self.fee_distribution.read()
        }

        fn get_otc_config(self: @ContractState) -> OTCConfig {
            self.otc_config.read()
        }

        fn set_discount_tiers(ref self: ContractState, tiers: DiscountTiers) {
            self._only_owner();

            // Validate: discounts shouldn't exceed 50%
            assert(tiers.sage_discount_bps <= 5000, 'Discount too high');
            assert(tiers.staked_sage_discount_bps <= 5000, 'Discount too high');

            self.discount_tiers.write(tiers);
        }

        fn set_fee_distribution(ref self: ContractState, distribution: FeeDistribution) {
            self._only_owner();

            // Validate: worker + protocol must equal 100%
            let total_split = distribution.worker_bps + distribution.protocol_fee_bps;
            assert(total_split == 10000, 'Worker+Protocol must be 100%');

            // Validate: protocol fee shares must sum to 100%
            let protocol_shares = distribution.burn_share_bps
                + distribution.treasury_share_bps
                + distribution.staker_share_bps;
            assert(protocol_shares == 10000, 'Fee shares must sum to 100%');

            // Validate: worker must get at least 50% (prevent abuse)
            assert(distribution.worker_bps >= 5000, 'Worker share too low');

            self.fee_distribution.write(distribution);
        }

        fn set_otc_config(ref self: ContractState, config: OTCConfig) {
            self._only_owner();

            // Validate all token addresses are non-zero
            assert!(!config.usdc_address.is_zero(), "Invalid USDC address");
            assert!(!config.strk_address.is_zero(), "Invalid STRK address");
            assert!(!config.wbtc_address.is_zero(), "Invalid WBTC address");
            assert!(!config.sage_address.is_zero(), "Invalid SAGE address");
            assert!(!config.oracle_address.is_zero(), "Invalid oracle address");
            assert!(!config.staking_address.is_zero(), "Invalid staking address");

            // Validate reasonable quote validity (between 1 minute and 1 hour)
            assert!(config.quote_validity_seconds >= 60, "Quote validity too short");
            assert!(config.quote_validity_seconds <= 3600, "Quote validity too long");

            // Validate max slippage (0-10%)
            assert!(config.max_slippage_bps <= 1000, "Max slippage too high");

            self.otc_config.write(config);
        }

        // === Production-grade Configuration Functions ===

        fn configure(ref self: ContractState, obelysk_router: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Configuration locked");
            assert!(!obelysk_router.is_zero(), "Invalid obelysk router");

            self.obelysk_router.write(obelysk_router);
            self.configured.write(true);
        }

        fn finalize_configuration(ref self: ContractState) {
            self._only_owner();
            assert!(self.configured.read(), "Not configured");
            assert!(!self.finalized.read(), "Already finalized");

            self.finalized.write(true);
        }

        fn is_contract_configured(self: @ContractState) -> bool {
            self.configured.read()
        }

        fn is_configuration_locked(self: @ContractState) -> bool {
            self.finalized.read()
        }

        fn set_obelysk_router(ref self: ContractState, router: ContractAddress) {
            self._only_owner();
            assert!(!self.finalized.read(), "Configuration locked");
            assert!(!router.is_zero(), "Invalid obelysk router address");
            self.obelysk_router.write(router);
        }

        fn set_staker_rewards_pool(ref self: ContractState, pool: ContractAddress) {
            self._only_owner();
            assert!(!pool.is_zero(), "Invalid staker rewards pool address");
            self.staker_rewards_pool.write(pool);
        }

        fn set_authorized_submitter(ref self: ContractState, submitter: ContractAddress) {
            self._only_owner();
            self.authorized_submitter.write(submitter);
        }

        fn register_job(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            privacy_enabled: bool
        ) {
            // Allow owner OR authorized submitter (coordinator/deployer)
            let caller = get_caller_address();
            let is_owner = caller == self.owner.read();
            let submitter = self.authorized_submitter.read();
            let is_submitter = !submitter.is_zero() && caller == submitter;
            assert(is_owner || is_submitter, 'Not authorized');

            self.job_worker.write(job_id, worker);
            self.job_privacy_enabled.write(job_id, privacy_enabled);
        }

        fn get_stats(self: @ContractState) -> (u256, u256, u256, u256, u256) {
            (
                self.total_payments_usd.read(),
                self.total_sage_burned.read(),
                self.total_worker_payments.read(),
                self.total_staker_rewards.read(),
                self.total_treasury_collected.read()
            )
        }

        fn register_worker_public_key(
            ref self: ContractState,
            public_key: ECPoint
        ) {
            let caller = get_caller_address();

            // Validate public key is not zero
            assert(!is_zero(public_key), 'Invalid public key');

            // Store worker's public key
            self.worker_public_keys.write(caller, public_key);
        }

        fn get_worker_public_key(self: @ContractState, worker: ContractAddress) -> ECPoint {
            self.worker_public_keys.read(worker)
        }

        // ==================== UPGRADE FUNCTIONS ====================

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            // Only owner can schedule upgrades
            self._only_owner();

            // Check no pending upgrade
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Another upgrade is already pending");

            // Validate class hash
            assert!(!new_class_hash.is_zero(), "Invalid class hash");

            let current_time = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let execute_after = current_time + delay;

            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(current_time);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_at: current_time,
                execute_after,
                scheduled_by: get_caller_address(),
            });
        }

        fn execute_upgrade(ref self: ContractState) {
            // Only owner can execute upgrades
            self._only_owner();

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let current_time = get_block_timestamp();

            // Check timelock has expired
            assert!(current_time >= scheduled_at + delay, "Timelock not expired");

            // Clear pending upgrade state
            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            // Execute the upgrade
            replace_class_syscall(pending).unwrap_syscall();

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: current_time,
                executed_by: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            // Only owner can cancel upgrades
            self._only_owner();

            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade to cancel");

            // Clear pending upgrade state
            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_at: get_block_timestamp(),
                cancelled_by: get_caller_address(),
            });
        }

        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64) {
            (
                self.pending_upgrade.read(),
                self.upgrade_scheduled_at.read(),
                self.upgrade_delay.read()
            )
        }

        fn set_upgrade_delay(ref self: ContractState, delay: u64) {
            // Only owner can change delay
            self._only_owner();

            // Minimum delay: 5 minutes (300 seconds) - testnet friendly
            assert!(delay >= 300, "Delay must be at least 5 minutes");

            // Maximum delay: 30 days
            assert!(delay <= 2592000, "Delay must be at most 30 days");

            self.upgrade_delay.write(delay);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }

        fn _get_discount_for_token(
            self: @ContractState,
            token: @PaymentToken,
            discounts: @DiscountTiers
        ) -> u32 {
            match token {
                PaymentToken::USDC => *discounts.stablecoin_discount_bps,
                PaymentToken::STRK => *discounts.strk_discount_bps,
                PaymentToken::WBTC => *discounts.wbtc_discount_bps,
                PaymentToken::SAGE => *discounts.sage_discount_bps,
                PaymentToken::STAKED_SAGE => *discounts.staked_sage_discount_bps,
                PaymentToken::PRIVACY_CREDIT => *discounts.privacy_credit_discount_bps,
            }
        }

        /// Calculate payment amount using oracle for real-time prices
        /// Returns (payment_token_amount, sage_equivalent)
        fn _calculate_payment_amount(
            self: @ContractState,
            token: @PaymentToken,
            usd_amount: u256
        ) -> (u256, u256) {
            let config = self.otc_config.read();
            let oracle = IOracleWrapperDispatcher { contract_address: config.oracle_address };

            // Get SAGE price from oracle (18 decimals)
            let sage_price = oracle.get_price_usd(PricePair::SAGE_USD);
            let sage_price_final = if sage_price == 0 { BASE_SAGE_PRICE_USD } else { sage_price };

            // Calculate SAGE equivalent
            let sage_equivalent = (usd_amount * USD_DECIMALS) / sage_price_final;

            match token {
                PaymentToken::USDC => {
                    // USDC = $1, but get from oracle for accuracy
                    let usdc_price = oracle.get_price_usd(PricePair::USDC_USD);
                    let usdc_price_final = if usdc_price == 0 { USD_DECIMALS } else { usdc_price };

                    // USDC has 6 decimals, USD amount has 18
                    let usdc_amount = (usd_amount * 1000000) / usdc_price_final;
                    (usdc_amount, sage_equivalent)
                },
                PaymentToken::STRK => {
                    let strk_price = oracle.get_price_usd(PricePair::STRK_USD);
                    // Fallback to $0.50 if oracle returns 0
                    let strk_price_final = if strk_price == 0 { 500000000000000000 } else { strk_price };
                    let strk_amount = (usd_amount * USD_DECIMALS) / strk_price_final;
                    (strk_amount, sage_equivalent)
                },
                PaymentToken::WBTC => {
                    let btc_price = oracle.get_price_usd(PricePair::BTC_USD);
                    // Fallback to $100,000 if oracle returns 0
                    let btc_price_final = if btc_price == 0 { 100000_u256 * USD_DECIMALS } else { btc_price };
                    // wBTC has 8 decimals
                    let wbtc_amount = (usd_amount * 100000000) / btc_price_final;
                    (wbtc_amount, sage_equivalent)
                },
                PaymentToken::SAGE => {
                    (sage_equivalent, sage_equivalent)
                },
                PaymentToken::STAKED_SAGE => {
                    (sage_equivalent, sage_equivalent)
                },
                PaymentToken::PRIVACY_CREDIT => {
                    (sage_equivalent, sage_equivalent)
                },
            }
        }

        /// Collect payment from user - transfers tokens to this contract
        fn _collect_payment(
            ref self: ContractState,
            from: ContractAddress,
            token: PaymentToken,
            amount: u256
        ) {
            let config = self.otc_config.read();
            let this_contract = get_contract_address();

            match token {
                PaymentToken::USDC => {
                    let usdc = IERC20Dispatcher { contract_address: config.usdc_address };
                    let success = usdc.transfer_from(from, this_contract, amount);
                    assert(success, 'USDC transfer failed');

                    let current = self.treasury_usdc.read();
                    self.treasury_usdc.write(current + amount);
                },
                PaymentToken::STRK => {
                    let strk = IERC20Dispatcher { contract_address: config.strk_address };
                    let success = strk.transfer_from(from, this_contract, amount);
                    assert(success, 'STRK transfer failed');

                    let current = self.treasury_strk.read();
                    self.treasury_strk.write(current + amount);
                },
                PaymentToken::WBTC => {
                    let wbtc = IERC20Dispatcher { contract_address: config.wbtc_address };
                    let success = wbtc.transfer_from(from, this_contract, amount);
                    assert(success, 'WBTC transfer failed');

                    let current = self.treasury_wbtc.read();
                    self.treasury_wbtc.write(current + amount);
                },
                PaymentToken::SAGE => {
                    let sage = IERC20Dispatcher { contract_address: config.sage_address };
                    let success = sage.transfer_from(from, this_contract, amount);
                    assert(success, 'SAGE transfer failed');

                    let current = self.treasury_sage.read();
                    self.treasury_sage.write(current + amount);
                },
                PaymentToken::STAKED_SAGE => {
                    // No transfer for staked - handled by credit system
                },
                PaymentToken::PRIVACY_CREDIT => {
                    // No transfer - already deposited
                },
            }
        }

        /// Distribute payment: 80% to worker, 20% protocol fee (70% burn, 20% treasury, 10% stakers)
        /// All payments flow through Obelysk in SAGE, with optional privacy
        fn _distribute_fees(
            ref self: ContractState,
            sage_amount: u256,
            job_id: u256
        ) {
            let fee_dist = self.fee_distribution.read();
            let config = self.otc_config.read();

            // Get SAGE token dispatcher
            let sage_token = ISAGETokenDispatcher { contract_address: config.sage_address };
            let sage_erc20 = IERC20Dispatcher { contract_address: config.sage_address };

            // Step 1: Calculate worker share (80%)
            let worker_amount = (sage_amount * fee_dist.worker_bps.into()) / BPS_DENOMINATOR;

            // Step 2: Calculate protocol fee (20%)
            let protocol_fee = sage_amount - worker_amount;

            // Step 3: Split protocol fee (70% burn, 20% treasury, 10% stakers)
            let burn_amount = (protocol_fee * fee_dist.burn_share_bps.into()) / BPS_DENOMINATOR;
            let treasury_amount = (protocol_fee * fee_dist.treasury_share_bps.into()) / BPS_DENOMINATOR;
            let staker_amount = protocol_fee - burn_amount - treasury_amount;

            // Step 4: Pay worker via Obelysk (with optional privacy)
            let worker = self.job_worker.read(job_id);
            let privacy_enabled = self.job_privacy_enabled.read(job_id);

            if !worker.is_zero() {
                if privacy_enabled {
                    // Route through Obelysk privacy router
                    let obelysk = self.obelysk_router.read();
                    if !obelysk.is_zero() {
                        // Get worker's public key for encryption
                        let worker_pk = self.worker_public_keys.read(worker);

                        if !is_zero(worker_pk) {
                            // Worker has privacy key - send encrypted payment
                            let privacy_router = IPrivacyRouterDispatcher { contract_address: obelysk };

                            // Generate randomness for encryption (deterministic from nonce)
                            let nonce = self.privacy_nonce.read();
                            let randomness: felt252 = (nonce + job_id).try_into().unwrap();
                            self.privacy_nonce.write(nonce + 1);

                            // Encrypt the payment amount
                            let encrypted_amount = encrypt(worker_amount, worker_pk, randomness);

                            // First transfer SAGE to privacy router
                            let success = sage_erc20.transfer(obelysk, worker_amount);
                            assert(success, 'Privacy router transfer failed');

                            // Then notify privacy router of the payment
                            privacy_router.receive_worker_payment(job_id, worker, worker_amount, encrypted_amount);
                        } else {
                            // Worker not registered for privacy - direct transfer
                            let success = sage_erc20.transfer(worker, worker_amount);
                            assert(success, 'Worker transfer failed');
                        }
                    } else {
                        // Fallback to direct transfer if Obelysk not configured
                        let success = sage_erc20.transfer(worker, worker_amount);
                        assert(success, 'Worker transfer failed');
                    }
                } else {
                    // Direct SAGE transfer to worker
                    let success = sage_erc20.transfer(worker, worker_amount);
                    assert(success, 'Worker transfer failed');
                }

                self.emit(WorkerPaid {
                    job_id,
                    worker,
                    sage_amount: worker_amount,
                    privacy_enabled,
                    timestamp: get_block_timestamp(),
                });
            }

            // Step 5: Execute protocol fee distribution

            // 5a: Burn tokens (70% of protocol fee)
            // Use burn_from_revenue with protocol fee as revenue source
            if burn_amount > 0 {
                // revenue_source = protocol_fee in USD value (estimated)
                // execution_price = current SAGE price from oracle
                let oracle = IOracleWrapperDispatcher { contract_address: config.oracle_address };
                let sage_price = oracle.get_price_usd(PricePair::SAGE_USD);
                let execution_price = if sage_price == 0 { BASE_SAGE_PRICE_USD } else { sage_price };

                // Calculate USD value of burn amount
                let burn_usd_value = (burn_amount * execution_price) / USD_DECIMALS;

                sage_token.burn_from_revenue(burn_amount, burn_usd_value, execution_price);
            }

            // 5b: Transfer to staker rewards pool (10% of protocol fee)
            let staker_pool = self.staker_rewards_pool.read();
            if !staker_pool.is_zero() && staker_amount > 0 {
                let success = sage_erc20.transfer(staker_pool, staker_amount);
                assert(success, 'Staker transfer failed');
            }

            // 5c: Transfer to treasury (20% of protocol fee)
            let treasury = self.treasury_address.read();
            if !treasury.is_zero() && treasury_amount > 0 {
                let success = sage_erc20.transfer(treasury, treasury_amount);
                assert(success, 'Treasury transfer failed');
            }

            // Update stats
            let total_burned = self.total_sage_burned.read();
            self.total_sage_burned.write(total_burned + burn_amount);

            let total_worker = self.total_worker_payments.read();
            self.total_worker_payments.write(total_worker + worker_amount);

            let total_staker = self.total_staker_rewards.read();
            self.total_staker_rewards.write(total_staker + staker_amount);

            let total_treasury = self.total_treasury_collected.read();
            self.total_treasury_collected.write(total_treasury + treasury_amount);

            self.emit(FeesDistributed {
                total_sage: sage_amount,
                to_worker: worker_amount,
                protocol_fee,
                burned: burn_amount,
                to_treasury: treasury_amount,
                to_stakers: staker_amount,
                timestamp: get_block_timestamp(),
            });
        }

        fn _token_to_felt(self: @ContractState, token: PaymentToken) -> felt252 {
            match token {
                PaymentToken::USDC => 'USDC',
                PaymentToken::STRK => 'STRK',
                PaymentToken::WBTC => 'WBTC',
                PaymentToken::SAGE => 'SAGE',
                PaymentToken::STAKED_SAGE => 'STAKED_SAGE',
                PaymentToken::PRIVACY_CREDIT => 'PRIVACY_CREDIT',
            }
        }

        // ================ REENTRANCY GUARD ================

        /// Start nonreentrant section - prevents recursive calls
        fn _start_nonreentrant(ref self: ContractState) {
            assert!(!self._reentrancy_guard.read(), "ReentrancyGuard: reentrant call");
            self._reentrancy_guard.write(true);
        }

        /// End nonreentrant section - allows future calls
        fn _end_nonreentrant(ref self: ContractState) {
            self._reentrancy_guard.write(false);
        }
    }
}
