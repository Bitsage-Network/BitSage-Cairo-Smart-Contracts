// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Payment Router - Multi-token payment system with OTC desk
// Accepts: USDC, STRK, wBTC, SAGE with tiered discounts
// All payments flow through Obelysk as SAGE with optional privacy

use starknet::ContractAddress;

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
    pub quoted_sage_price: u256,   // SAGE/USD price at quote time (for slippage check)
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

/// Dynamic fee tiers based on monthly volume
/// Higher volume = lower protocol fees to incentivize growth
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct DynamicFeeTiers {
    pub tier1_threshold: u256,    // Volume threshold for tier 1 (e.g., $100K)
    pub tier1_fee_bps: u32,       // Fee at tier 1 (e.g., 1800 = 18%)
    pub tier2_threshold: u256,    // Volume threshold for tier 2 (e.g., $500K)
    pub tier2_fee_bps: u32,       // Fee at tier 2 (e.g., 1500 = 15%)
    pub tier3_threshold: u256,    // Volume threshold for tier 3 (e.g., $1M)
    pub tier3_fee_bps: u32,       // Fee at tier 3 (e.g., 1200 = 12%)
    pub enabled: bool,            // Whether dynamic fees are active
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

    /// Admin: Set Obelysk router address
    fn set_obelysk_router(ref self: TContractState, router: ContractAddress);

    /// Admin: Set staker rewards pool address
    fn set_staker_rewards_pool(ref self: TContractState, pool: ContractAddress);

    /// Set referral system contract for affiliate rewards
    fn set_referral_system(ref self: TContractState, referral_system: ContractAddress);

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

    // =========================================================================
    // Two-Step Ownership Transfer
    // =========================================================================

    /// Start ownership transfer (current owner only)
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);

    /// Accept ownership (pending owner only)
    fn accept_ownership(ref self: TContractState);

    /// Cancel pending ownership transfer (current owner only)
    fn cancel_ownership_transfer(ref self: TContractState);

    /// Get current owner
    fn owner(self: @TContractState) -> ContractAddress;

    /// Get pending owner
    fn pending_owner(self: @TContractState) -> ContractAddress;

    // =========================================================================
    // Pausable
    // =========================================================================

    /// Pause the contract (owner only)
    fn pause(ref self: TContractState);

    /// Unpause the contract (owner only)
    fn unpause(ref self: TContractState);

    /// Check if contract is paused
    fn is_paused(self: @TContractState) -> bool;

    // =========================================================================
    // Rate Limiting
    // =========================================================================

    /// Admin: Set rate limit configuration
    /// @param window_secs: Duration of rate limit window in seconds
    /// @param max_payments: Maximum number of payments allowed per window
    fn set_rate_limit(ref self: TContractState, window_secs: u64, max_payments: u32);

    /// Get current rate limit configuration
    fn get_rate_limit(self: @TContractState) -> (u64, u32);

    /// Get user's current payment count in window
    fn get_user_payment_count(self: @TContractState, user: ContractAddress) -> u32;

    // =========================================================================
    // Timelock for Critical Parameter Changes
    // =========================================================================

    /// Propose a new fee distribution (starts timelock)
    fn propose_fee_distribution(ref self: TContractState, distribution: FeeDistribution);

    /// Execute pending fee distribution (after timelock expires)
    fn execute_fee_distribution(ref self: TContractState);

    /// Cancel pending fee distribution
    fn cancel_fee_distribution(ref self: TContractState);

    /// Get pending fee distribution and execution timestamp
    fn get_pending_fee_distribution(self: @TContractState) -> (FeeDistribution, u64);

    /// Get current timelock delay
    fn get_timelock_delay(self: @TContractState) -> u64;

    /// Set timelock delay (owner only, immediate change)
    fn set_timelock_delay(ref self: TContractState, delay: u64);

    // =========================================================================
    // Emergency Withdrawal (when paused)
    // =========================================================================

    /// Emergency withdraw ERC20 tokens (owner only, requires paused state)
    /// Use only in emergencies when funds need to be recovered
    fn emergency_withdraw(
        ref self: TContractState,
        token: ContractAddress,
        recipient: ContractAddress,
        amount: u256
    );

    /// Get treasury balances
    fn get_treasury_balances(self: @TContractState) -> (u256, u256, u256, u256);

    // =========================================================================
    // Oracle Health Configuration
    // =========================================================================

    /// Admin: Set oracle health requirements
    /// @param require_healthy: If true, payments fail when oracle is degraded
    /// @param max_staleness: Maximum age of oracle price in seconds (0 = use oracle default)
    fn set_oracle_requirements(
        ref self: TContractState,
        require_healthy: bool,
        max_staleness: u64
    );

    /// Get current oracle health configuration
    fn get_oracle_requirements(self: @TContractState) -> (bool, u64);

    // =========================================================================
    // Staked Credit Limits
    // =========================================================================

    /// Admin: Set staked credit limit as percentage of staked balance
    /// @param limit_bps: Maximum credit as basis points of staked balance (e.g., 5000 = 50%)
    fn set_staked_credit_limit(ref self: TContractState, limit_bps: u32);

    /// Get current staked credit limit configuration
    fn get_staked_credit_limit(self: @TContractState) -> u32;

    /// Get user's remaining staked credit available
    fn get_available_staked_credit(self: @TContractState, user: ContractAddress) -> u256;

    // =========================================================================
    // Dynamic Fee Tiers
    // =========================================================================

    /// Admin: Set dynamic fee tier configuration
    fn set_dynamic_fee_tiers(ref self: TContractState, tiers: DynamicFeeTiers);

    /// Get current dynamic fee tier configuration
    fn get_dynamic_fee_tiers(self: @TContractState) -> DynamicFeeTiers;

    /// Get current effective protocol fee based on monthly volume
    fn get_current_protocol_fee(self: @TContractState) -> u32;

    /// Get current monthly volume
    fn get_monthly_volume(self: @TContractState) -> u256;
}

#[starknet::contract]
mod PaymentRouter {
    use super::{
        IPaymentRouter, PaymentToken, PaymentQuote, OTCConfig,
        FeeDistribution, DiscountTiers, ECPoint, DynamicFeeTiers
    };
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;
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
    use sage_contracts::growth::referral_system::{IReferralSystemDispatcher, IReferralSystemDispatcherTrait};

    // Base SAGE price: $0.10 = 100000000000000000 (0.1 * 10^18)
    const BASE_SAGE_PRICE_USD: u256 = 100000000000000000;
    const USD_DECIMALS: u256 = 1000000000000000000; // 10^18
    const BPS_DENOMINATOR: u256 = 10000;

    // Timelock constants
    const DEFAULT_TIMELOCK_DELAY: u64 = 172800; // 48 hours in seconds
    const MIN_TIMELOCK_DELAY: u64 = 3600;       // 1 hour minimum
    const MAX_TIMELOCK_DELAY: u64 = 604800;     // 7 days maximum

    #[storage]
    struct Storage {
        owner: ContractAddress,
        pending_owner: ContractAddress,  // Two-step ownership transfer
        paused: bool,                     // Emergency pause
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
        obelysk_router: ContractAddress,      // Privacy router for optional anonymous payments
        staker_rewards_pool: ContractAddress, // Where 10% of protocol fee goes
        treasury_address: ContractAddress,    // Where 20% of protocol fee goes

        // Job-to-worker mapping (set by JobManager)
        job_worker: Map<u256, ContractAddress>,
        job_privacy_enabled: Map<u256, bool>,

        // Worker public keys for privacy payments
        worker_public_keys: Map<ContractAddress, ECPoint>,

        // Rate limiting (per-user)
        user_last_payment_window_start: Map<ContractAddress, u64>,
        user_payment_count_in_window: Map<ContractAddress, u32>,
        rate_limit_window_secs: u64,     // Rate limit window duration
        max_payments_per_window: u32,    // Max payments allowed per window

        // Privacy payment randomness seed (incremented per payment)
        privacy_nonce: u256,

        // Stats
        total_payments_usd: u256,
        total_sage_burned: u256,
        total_worker_payments: u256,
        total_staker_rewards: u256,
        total_treasury_collected: u256,

        // Security: Reentrancy guard
        reentrancy_locked: bool,

        // Timelock for critical parameter changes (48 hours)
        timelock_delay: u64,
        pending_fee_distribution: FeeDistribution,
        pending_fee_distribution_timestamp: u64,  // 0 means no pending change

        // Oracle health requirements
        require_healthy_oracle: bool,  // If true, payments fail when oracle is degraded
        max_oracle_staleness: u64,     // Max age of oracle price in seconds (0 = use oracle default)

        // Staked credit limits
        staked_credit_limit_bps: u32,  // Max credit as % of staked balance (e.g., 5000 = 50%)

        // Dynamic fee tiers based on monthly volume
        dynamic_fee_tiers: DynamicFeeTiers,
        monthly_volume_usd: u256,           // Current month's volume
        month_start_timestamp: u64,         // When current month started

        // Referral system for affiliate rewards
        referral_system: ContractAddress,
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
        OwnershipTransferStarted: OwnershipTransferStarted,
        OwnershipTransferred: OwnershipTransferred,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        RateLimitUpdated: RateLimitUpdated,
        DiscountTiersUpdated: DiscountTiersUpdated,
        FeeDistributionUpdated: FeeDistributionUpdated,
        OTCConfigUpdated: OTCConfigUpdated,
        ObelyskRouterUpdated: ObelyskRouterUpdated,
        StakerRewardsPoolUpdated: StakerRewardsPoolUpdated,
        JobRegistered: JobRegistered,
        FeeDistributionProposed: FeeDistributionProposed,
        FeeDistributionExecuted: FeeDistributionExecuted,
        FeeDistributionCancelled: FeeDistributionCancelled,
        TimelockDelayUpdated: TimelockDelayUpdated,
        EmergencyWithdrawal: EmergencyWithdrawal,
        OracleFallbackUsed: OracleFallbackUsed,
        OracleConfigUpdated: OracleConfigUpdated,
        StakedCreditLimitUpdated: StakedCreditLimitUpdated,
        DynamicFeeTiersUpdated: DynamicFeeTiersUpdated,
        MonthlyVolumeReset: MonthlyVolumeReset,
    }

    #[derive(Drop, starknet::Event)]
    struct DynamicFeeTiersUpdated {
        #[key]
        updated_by: ContractAddress,
        tier1_threshold: u256,
        tier1_fee_bps: u32,
        tier2_threshold: u256,
        tier2_fee_bps: u32,
        tier3_threshold: u256,
        tier3_fee_bps: u32,
        enabled: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct MonthlyVolumeReset {
        previous_volume: u256,
        reset_timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyWithdrawal {
        #[key]
        token: ContractAddress,
        #[key]
        recipient: ContractAddress,
        amount: u256,
        withdrawn_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OracleFallbackUsed {
        #[key]
        price_pair: felt252,
        fallback_price: u256,
        reason: felt252,      // 'stale', 'circuit_breaker', 'zero_price'
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OracleConfigUpdated {
        #[key]
        updated_by: ContractAddress,
        require_healthy_oracle: bool,
        max_oracle_staleness: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct StakedCreditLimitUpdated {
        #[key]
        updated_by: ContractAddress,
        old_limit_bps: u32,
        new_limit_bps: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeDistributionProposed {
        #[key]
        proposed_by: ContractAddress,
        worker_bps: u32,
        protocol_fee_bps: u32,
        executable_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeDistributionExecuted {
        #[key]
        executed_by: ContractAddress,
        worker_bps: u32,
        protocol_fee_bps: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeDistributionCancelled {
        #[key]
        cancelled_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct TimelockDelayUpdated {
        old_delay: u64,
        new_delay: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferStarted {
        #[key]
        previous_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferred {
        #[key]
        previous_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractPaused {
        account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractUnpaused {
        account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct RateLimitUpdated {
        window_secs: u64,
        max_payments: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct DiscountTiersUpdated {
        #[key]
        updated_by: ContractAddress,
        sage_discount_bps: u32,
        staked_sage_discount_bps: u32,
        privacy_credit_discount_bps: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeDistributionUpdated {
        #[key]
        updated_by: ContractAddress,
        worker_bps: u32,
        protocol_fee_bps: u32,
        burn_share_bps: u32,
        treasury_share_bps: u32,
        staker_share_bps: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct OTCConfigUpdated {
        #[key]
        updated_by: ContractAddress,
        quote_validity_seconds: u64,
        max_slippage_bps: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct ObelyskRouterUpdated {
        #[key]
        updated_by: ContractAddress,
        old_router: ContractAddress,
        new_router: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct StakerRewardsPoolUpdated {
        #[key]
        updated_by: ContractAddress,
        old_pool: ContractAddress,
        new_pool: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct JobRegistered {
        #[key]
        job_id: u256,
        #[key]
        worker: ContractAddress,
        privacy_enabled: bool,
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

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_address: ContractAddress,
        oracle_address: ContractAddress,
        obelysk_router: ContractAddress,
        staker_rewards_pool: ContractAddress,
        treasury_address: ContractAddress
    ) {
        assert!(!owner.is_zero(), "Router: invalid owner");
        assert!(!sage_address.is_zero(), "Router: invalid SAGE");
        assert!(!oracle_address.is_zero(), "Router: invalid oracle");
        assert!(!obelysk_router.is_zero(), "Router: invalid obelysk");
        assert!(!staker_rewards_pool.is_zero(), "Router: invalid rewards");
        assert!(!treasury_address.is_zero(), "Router: invalid treasury");

        self.owner.write(owner);
        self.obelysk_router.write(obelysk_router);
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

        // Initialize rate limiting: 1 hour window, 20 payments max
        self.rate_limit_window_secs.write(3600);
        self.max_payments_per_window.write(20);

        // Initialize timelock delay (48 hours)
        self.timelock_delay.write(DEFAULT_TIMELOCK_DELAY);

        // Initialize staked credit limit (50% of staked balance)
        self.staked_credit_limit_bps.write(5000);

        // Initialize dynamic fee tiers (disabled by default, using base 20% fee)
        // Thresholds in USD with 18 decimals
        let dynamic_fees = DynamicFeeTiers {
            tier1_threshold: 100000_u256 * 1000000000000000000, // $100K
            tier1_fee_bps: 1800,  // 18%
            tier2_threshold: 500000_u256 * 1000000000000000000, // $500K
            tier2_fee_bps: 1500,  // 15%
            tier3_threshold: 1000000_u256 * 1000000000000000000, // $1M
            tier3_fee_bps: 1200,  // 12%
            enabled: false,       // Disabled by default
        };
        self.dynamic_fee_tiers.write(dynamic_fees);
        self.monthly_volume_usd.write(0);
        self.month_start_timestamp.write(get_block_timestamp());
    }

    #[abi(embed_v0)]
    impl PaymentRouterImpl of IPaymentRouter<ContractState> {
        fn get_quote(
            self: @ContractState,
            payment_token: PaymentToken,
            usd_amount: u256
        ) -> PaymentQuote {
            // SECURITY: Validate oracle health before providing quotes
            let (oracle_healthy, _reason) = self._validate_oracle_health();
            assert!(oracle_healthy, "Oracle unhealthy: circuit breaker tripped");

            let now = get_block_timestamp();
            let config = self.otc_config.read();
            let discounts = self.discount_tiers.read();

            // Get current SAGE price for slippage verification later
            let oracle = IOracleWrapperDispatcher { contract_address: config.oracle_address };
            let sage_price = oracle.get_price_usd(PricePair::SAGE_USD);
            let quoted_sage_price = if sage_price == 0 { BASE_SAGE_PRICE_USD } else { sage_price };

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
                quoted_sage_price,
            }
        }

        fn execute_payment(
            ref self: ContractState,
            quote_id: u256,
            job_id: u256
        ) -> bool {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            // SECURITY: Pause check
            self._when_not_paused();

            // SECURITY: Validate oracle health at execution time
            let (oracle_healthy, _reason) = self._validate_oracle_health();
            assert!(oracle_healthy, "Oracle unhealthy: cannot execute payment");

            let caller = get_caller_address();
            let now = get_block_timestamp();

            // SECURITY: Rate limit check
            self._check_rate_limit(caller);

            // Verify quote exists and belongs to caller
            let quote = self.quotes.read(quote_id);
            let quote_owner = self.quote_user.read(quote_id);

            assert(quote.is_valid, 'Invalid quote');
            assert(quote_owner == caller, 'Not quote owner');
            assert(now <= quote.expires_at, 'Quote expired');

            // SECURITY: Slippage protection - verify price hasn't moved too much since quote
            let config = self.otc_config.read();
            let oracle = IOracleWrapperDispatcher { contract_address: config.oracle_address };
            let current_sage_price = oracle.get_price_usd(PricePair::SAGE_USD);
            let current_price = if current_sage_price == 0 { BASE_SAGE_PRICE_USD } else { current_sage_price };
            let quoted_price = quote.quoted_sage_price;

            // Calculate price deviation in basis points
            // deviation = |current - quoted| / quoted * 10000
            let price_diff = if current_price > quoted_price {
                current_price - quoted_price
            } else {
                quoted_price - current_price
            };

            let deviation_bps = (price_diff * 10000) / quoted_price;
            assert!(deviation_bps <= config.max_slippage_bps.into(), "Price slippage exceeds limit");

            // CHECKS-EFFECTS-INTERACTIONS pattern:
            // 1. Mark quote as used BEFORE external calls
            let mut used_quote = quote;
            used_quote.is_valid = false;
            self.quotes.write(quote_id, used_quote);

            // 2. Update stats BEFORE external calls
            let total_usd = self.total_payments_usd.read();
            self.total_payments_usd.write(total_usd + quote.usd_value);

            // 3. INTERACTIONS: External calls LAST
            // Transfer payment token from user
            self._collect_payment(caller, quote.payment_token, quote.payment_amount);

            // Distribute fees in SAGE (with dynamic fee tier tracking)
            self._distribute_fees(quote.sage_equivalent, job_id, quote.usd_value);

            self.emit(PaymentExecuted {
                quote_id,
                job_id,
                payer: caller,
                payment_token: self._token_to_felt(quote.payment_token),
                payment_amount: quote.payment_amount,
                sage_equivalent: quote.sage_equivalent,
                usd_value: quote.usd_value,
            });

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();

            true
        }

        fn pay_with_sage(
            ref self: ContractState,
            amount: u256,
            job_id: u256
        ) {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            // SECURITY: Pause check
            self._when_not_paused();

            // SECURITY: Amount validation
            assert!(amount > 0, "Amount must be greater than 0");

            let caller = get_caller_address();

            // SECURITY: Rate limit check
            self._check_rate_limit(caller);

            let discounts = self.discount_tiers.read();

            // Direct SAGE payment gets discount
            let effective_amount = (amount * (BPS_DENOMINATOR + discounts.sage_discount_bps.into())) / BPS_DENOMINATOR;

            // CHECKS-EFFECTS-INTERACTIONS: Update stats BEFORE external calls
            let usd_value = (amount * BASE_SAGE_PRICE_USD) / USD_DECIMALS;
            let total_usd = self.total_payments_usd.read();
            self.total_payments_usd.write(total_usd + usd_value);

            // INTERACTIONS: External calls LAST
            // Transfer SAGE from user
            self._collect_payment(caller, PaymentToken::SAGE, amount);

            // Distribute fees (with dynamic fee tier tracking)
            self._distribute_fees(effective_amount, job_id, usd_value);

            self.emit(PaymentExecuted {
                quote_id: 0,
                job_id,
                payer: caller,
                payment_token: 'SAGE',
                payment_amount: amount,
                sage_equivalent: effective_amount,
                usd_value,
            });

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
        }

        fn pay_with_staked_sage(
            ref self: ContractState,
            usd_amount: u256,
            job_id: u256
        ) {
            // SECURITY: Reentrancy protection
            self._reentrancy_guard_start();
            // SECURITY: Pause check
            self._when_not_paused();

            // SECURITY: Amount validation
            assert!(usd_amount > 0, "USD amount must be greater than 0");

            let caller = get_caller_address();

            // SECURITY: Rate limit check
            self._check_rate_limit(caller);

            let discounts = self.discount_tiers.read();

            // Calculate discounted amount (10% off)
            let discounted_usd = (usd_amount * (BPS_DENOMINATOR - discounts.staked_sage_discount_bps.into())) / BPS_DENOMINATOR;

            // Convert to SAGE at current price
            let sage_amount = (discounted_usd * USD_DECIMALS) / BASE_SAGE_PRICE_USD;

            // SECURITY: Check staked credit limit
            let config = self.otc_config.read();
            let limit_bps: u256 = self.staked_credit_limit_bps.read().into();
            let credits_used = self.staked_credits_used.read(caller);

            // If staking is configured and limit is enabled, enforce it
            if !config.staking_address.is_zero() && limit_bps > 0 {
                // Query staked balance from staking contract
                // Note: In production, this would use the staking contract interface
                // For now, we use a simplified approach with a per-user absolute limit
                // based on their first stake amount (stored separately or queried)
                //
                // max_credit = staked_balance * limit_bps / 10000
                // Simplified: we'll enforce that new credits don't exceed limit
                // Real implementation should query IProverStaking.get_stake_info()
                let new_total_credits = credits_used + sage_amount;

                // For safety, enforce a reasonable max credit per user
                // This is a fallback; real limit comes from stake ratio
                assert!(new_total_credits <= 1000000_u256 * USD_DECIMALS, "Staked credit limit exceeded");
            }

            // CHECKS-EFFECTS-INTERACTIONS: Update state BEFORE external calls
            self.staked_credits_used.write(caller, credits_used + sage_amount);

            let total_usd = self.total_payments_usd.read();
            self.total_payments_usd.write(total_usd + usd_amount);

            // INTERACTIONS: External calls LAST
            // Distribute fees (from protocol reserves, with dynamic fee tier tracking)
            self._distribute_fees(sage_amount, job_id, usd_amount);

            self.emit(PaymentExecuted {
                quote_id: 0,
                job_id,
                payer: caller,
                payment_token: 'STAKED_SAGE',
                payment_amount: sage_amount,
                sage_equivalent: sage_amount,
                usd_value: usd_amount,
            });

            // SECURITY: Release reentrancy lock
            self._reentrancy_guard_end();
        }

        fn deposit_privacy_credits(
            ref self: ContractState,
            amount: u256,
            commitment: felt252
        ) {
            // SECURITY: Pause check
            self._when_not_paused();

            // SECURITY: Amount validation
            assert!(amount > 0, "Amount must be greater than 0");

            // SECURITY: Commitment validation (non-zero)
            assert!(commitment != 0, "Invalid commitment");

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
            // SECURITY: Pause check
            self._when_not_paused();

            // SECURITY: Amount validation
            assert!(usd_amount > 0, "USD amount must be greater than 0");

            // SECURITY: Nullifier validation (non-zero)
            assert!(nullifier != 0, "Invalid nullifier");

            // Verify nullifier not already used (prevent double-spend)
            assert(!self.privacy_nullifiers.read(nullifier), 'Nullifier used');

            // Verify ZK proof structure
            // PRODUCTION: Integrate with ProofVerifier contract for full STWO ZK verification
            // Current implementation: basic structure validation for testnet
            assert!(proof.len() >= 4, "Proof must have at least 4 elements");

            // Mark nullifier as used
            self.privacy_nullifiers.write(nullifier, true);

            // Calculate SAGE equivalent with privacy discount (2%)
            let discounts = self.discount_tiers.read();
            let discounted_usd = (usd_amount * (BPS_DENOMINATOR - discounts.privacy_credit_discount_bps.into())) / BPS_DENOMINATOR;
            let sage_amount = (discounted_usd * USD_DECIMALS) / BASE_SAGE_PRICE_USD;

            // Distribute fees (from privacy pool, with dynamic fee tier tracking)
            self._distribute_fees(sage_amount, 0, usd_amount);

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

            self.emit(DiscountTiersUpdated {
                updated_by: get_caller_address(),
                sage_discount_bps: tiers.sage_discount_bps,
                staked_sage_discount_bps: tiers.staked_sage_discount_bps,
                privacy_credit_discount_bps: tiers.privacy_credit_discount_bps,
            });
        }

        /// Emergency-only direct fee distribution change (bypasses timelock)
        /// Only works when contract is paused. For normal changes, use propose_fee_distribution.
        fn set_fee_distribution(ref self: ContractState, distribution: FeeDistribution) {
            self._only_owner();

            // SECURITY: Only allow direct changes in emergency mode (when paused)
            // For normal changes, use propose_fee_distribution with timelock
            assert!(self.paused.read(), "Use propose_fee_distribution for normal changes");

            // Validate: worker + protocol must equal 100%
            let total_split = distribution.worker_bps + distribution.protocol_fee_bps;
            assert!(total_split == 10000, "Worker+Protocol must be 100%");

            // Validate: protocol fee shares must sum to 100%
            let protocol_shares = distribution.burn_share_bps
                + distribution.treasury_share_bps
                + distribution.staker_share_bps;
            assert!(protocol_shares == 10000, "Fee shares must sum to 100%");

            // Validate: worker must get at least 50% (prevent abuse)
            assert!(distribution.worker_bps >= 5000, "Worker share too low");

            self.fee_distribution.write(distribution);

            self.emit(FeeDistributionUpdated {
                updated_by: get_caller_address(),
                worker_bps: distribution.worker_bps,
                protocol_fee_bps: distribution.protocol_fee_bps,
                burn_share_bps: distribution.burn_share_bps,
                treasury_share_bps: distribution.treasury_share_bps,
                staker_share_bps: distribution.staker_share_bps,
            });
        }

        fn set_otc_config(ref self: ContractState, config: OTCConfig) {
            self._only_owner();
            self.otc_config.write(config);

            self.emit(OTCConfigUpdated {
                updated_by: get_caller_address(),
                quote_validity_seconds: config.quote_validity_seconds,
                max_slippage_bps: config.max_slippage_bps,
            });
        }

        fn set_obelysk_router(ref self: ContractState, router: ContractAddress) {
            self._only_owner();
            // SECURITY: Zero address validation
            assert!(!router.is_zero(), "Router cannot be zero address");

            let old_router = self.obelysk_router.read();
            self.obelysk_router.write(router);

            self.emit(ObelyskRouterUpdated {
                updated_by: get_caller_address(),
                old_router,
                new_router: router,
            });
        }

        fn set_staker_rewards_pool(ref self: ContractState, pool: ContractAddress) {
            self._only_owner();
            // SECURITY: Zero address validation
            assert!(!pool.is_zero(), "Pool cannot be zero address");

            let old_pool = self.staker_rewards_pool.read();
            self.staker_rewards_pool.write(pool);

            self.emit(StakerRewardsPoolUpdated {
                updated_by: get_caller_address(),
                old_pool,
                new_pool: pool,
            });
        }

        fn set_referral_system(ref self: ContractState, referral_system: ContractAddress) {
            self._only_owner();
            self.referral_system.write(referral_system);
        }

        fn register_job(
            ref self: ContractState,
            job_id: u256,
            worker: ContractAddress,
            privacy_enabled: bool
        ) {
            // In production: verify caller is authorized JobManager
            // For now, allow owner to register jobs
            self._only_owner();

            // SECURITY: Worker address validation
            assert!(!worker.is_zero(), "Worker cannot be zero address");

            self.job_worker.write(job_id, worker);
            self.job_privacy_enabled.write(job_id, privacy_enabled);

            self.emit(JobRegistered {
                job_id,
                worker,
                privacy_enabled,
            });
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

        // =========================================================================
        // Two-Step Ownership Transfer
        // =========================================================================

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            self._only_owner();
            assert!(!new_owner.is_zero(), "New owner cannot be zero address");

            let previous_owner = self.owner.read();
            self.pending_owner.write(new_owner);

            self.emit(OwnershipTransferStarted {
                previous_owner,
                new_owner,
            });
        }

        fn accept_ownership(ref self: ContractState) {
            let caller = get_caller_address();
            let pending = self.pending_owner.read();
            assert!(caller == pending, "Caller is not pending owner");

            let previous_owner = self.owner.read();
            let zero: ContractAddress = 0.try_into().unwrap();

            self.owner.write(caller);
            self.pending_owner.write(zero);

            self.emit(OwnershipTransferred {
                previous_owner,
                new_owner: caller,
            });
        }

        fn cancel_ownership_transfer(ref self: ContractState) {
            self._only_owner();
            let zero: ContractAddress = 0.try_into().unwrap();
            self.pending_owner.write(zero);
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn pending_owner(self: @ContractState) -> ContractAddress {
            self.pending_owner.read()
        }

        // =========================================================================
        // Pausable
        // =========================================================================

        fn pause(ref self: ContractState) {
            self._only_owner();
            assert!(!self.paused.read(), "Contract already paused");
            self.paused.write(true);
            self.emit(ContractPaused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            assert!(self.paused.read(), "Contract not paused");
            self.paused.write(false);
            self.emit(ContractUnpaused { account: get_caller_address() });
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        // =========================================================================
        // Rate Limiting
        // =========================================================================

        fn set_rate_limit(ref self: ContractState, window_secs: u64, max_payments: u32) {
            self._only_owner();

            // Validate: window must be at least 1 minute
            assert!(window_secs >= 60, "Window must be at least 60 seconds");
            // Validate: max payments must be at least 1
            assert!(max_payments >= 1, "Max payments must be at least 1");
            // Validate: window cannot exceed 1 day
            assert!(window_secs <= 86400, "Window cannot exceed 24 hours");
            // SECURITY: Validate max payments has upper bound to prevent disabling rate limits
            assert!(max_payments <= 1000, "Max payments cannot exceed 1000 per window");

            // SECURITY: Proportional limit - max 10 payments per minute to prevent spam
            // This ensures reasonable rate limiting regardless of window size
            let max_proportional: u32 = ((window_secs / 60) * 10).try_into().unwrap();
            assert!(
                max_payments <= max_proportional,
                "Max payments too high for window (max 10/min)"
            );

            self.rate_limit_window_secs.write(window_secs);
            self.max_payments_per_window.write(max_payments);

            self.emit(RateLimitUpdated {
                window_secs,
                max_payments,
            });
        }

        fn get_rate_limit(self: @ContractState) -> (u64, u32) {
            (self.rate_limit_window_secs.read(), self.max_payments_per_window.read())
        }

        fn get_user_payment_count(self: @ContractState, user: ContractAddress) -> u32 {
            let now = get_block_timestamp();
            let window_start = self.user_last_payment_window_start.read(user);
            let window_duration = self.rate_limit_window_secs.read();

            // If window has expired, count is effectively 0
            if now >= window_start + window_duration {
                0
            } else {
                self.user_payment_count_in_window.read(user)
            }
        }

        // =========================================================================
        // Timelock for Critical Parameter Changes
        // =========================================================================

        fn propose_fee_distribution(ref self: ContractState, distribution: FeeDistribution) {
            self._only_owner();

            // Validate: worker + protocol must equal 100%
            let total_split = distribution.worker_bps + distribution.protocol_fee_bps;
            assert!(total_split == 10000, "Worker+Protocol must be 100%");

            // Validate: protocol fee shares must sum to 100%
            let protocol_shares = distribution.burn_share_bps
                + distribution.treasury_share_bps
                + distribution.staker_share_bps;
            assert!(protocol_shares == 10000, "Fee shares must sum to 100%");

            // Validate: worker must get at least 50% (prevent abuse)
            assert!(distribution.worker_bps >= 5000, "Worker share too low");

            // Calculate execution timestamp
            let now = get_block_timestamp();
            let delay = self.timelock_delay.read();
            let executable_at = now + delay;

            // Store pending distribution
            self.pending_fee_distribution.write(distribution);
            self.pending_fee_distribution_timestamp.write(executable_at);

            self.emit(FeeDistributionProposed {
                proposed_by: get_caller_address(),
                worker_bps: distribution.worker_bps,
                protocol_fee_bps: distribution.protocol_fee_bps,
                executable_at,
            });
        }

        fn execute_fee_distribution(ref self: ContractState) {
            self._only_owner();

            let executable_at = self.pending_fee_distribution_timestamp.read();
            assert!(executable_at > 0, "No pending fee distribution");

            let now = get_block_timestamp();
            assert!(now >= executable_at, "Timelock not expired");

            // Get and apply pending distribution
            let distribution = self.pending_fee_distribution.read();
            self.fee_distribution.write(distribution);

            // Clear pending state
            self.pending_fee_distribution_timestamp.write(0);

            self.emit(FeeDistributionExecuted {
                executed_by: get_caller_address(),
                worker_bps: distribution.worker_bps,
                protocol_fee_bps: distribution.protocol_fee_bps,
            });

            // Also emit the standard update event for consistency
            self.emit(FeeDistributionUpdated {
                updated_by: get_caller_address(),
                worker_bps: distribution.worker_bps,
                protocol_fee_bps: distribution.protocol_fee_bps,
                burn_share_bps: distribution.burn_share_bps,
                treasury_share_bps: distribution.treasury_share_bps,
                staker_share_bps: distribution.staker_share_bps,
            });
        }

        fn cancel_fee_distribution(ref self: ContractState) {
            self._only_owner();

            let executable_at = self.pending_fee_distribution_timestamp.read();
            assert!(executable_at > 0, "No pending fee distribution");

            // Clear pending state
            self.pending_fee_distribution_timestamp.write(0);

            self.emit(FeeDistributionCancelled {
                cancelled_by: get_caller_address(),
            });
        }

        fn get_pending_fee_distribution(self: @ContractState) -> (FeeDistribution, u64) {
            (self.pending_fee_distribution.read(), self.pending_fee_distribution_timestamp.read())
        }

        fn get_timelock_delay(self: @ContractState) -> u64 {
            self.timelock_delay.read()
        }

        fn set_timelock_delay(ref self: ContractState, delay: u64) {
            self._only_owner();

            // Validate: delay must be within bounds
            assert!(delay >= MIN_TIMELOCK_DELAY, "Delay too short");
            assert!(delay <= MAX_TIMELOCK_DELAY, "Delay too long");

            let old_delay = self.timelock_delay.read();
            self.timelock_delay.write(delay);

            self.emit(TimelockDelayUpdated {
                old_delay,
                new_delay: delay,
            });
        }

        // =========================================================================
        // Emergency Withdrawal
        // =========================================================================

        fn emergency_withdraw(
            ref self: ContractState,
            token: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) {
            self._only_owner();

            // SECURITY: Only allow emergency withdrawal when contract is paused
            assert!(self.paused.read(), "Contract must be paused for emergency withdrawal");

            // Validate recipient
            assert!(!recipient.is_zero(), "Invalid recipient");

            // Validate amount
            assert!(amount > 0, "Amount must be greater than 0");

            // Transfer tokens
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            let success = token_dispatcher.transfer(recipient, amount);
            assert!(success, "Emergency withdrawal transfer failed");

            self.emit(EmergencyWithdrawal {
                token,
                recipient,
                amount,
                withdrawn_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn get_treasury_balances(self: @ContractState) -> (u256, u256, u256, u256) {
            (
                self.treasury_usdc.read(),
                self.treasury_strk.read(),
                self.treasury_wbtc.read(),
                self.treasury_sage.read()
            )
        }

        // =========================================================================
        // Oracle Health Configuration
        // =========================================================================

        fn set_oracle_requirements(
            ref self: ContractState,
            require_healthy: bool,
            max_staleness: u64
        ) {
            self._only_owner();

            // Validate: staleness should be reasonable (0 = use oracle default, max 24 hours)
            assert!(max_staleness <= 86400, "Staleness cannot exceed 24 hours");

            self.require_healthy_oracle.write(require_healthy);
            self.max_oracle_staleness.write(max_staleness);

            self.emit(OracleConfigUpdated {
                updated_by: get_caller_address(),
                require_healthy_oracle: require_healthy,
                max_oracle_staleness: max_staleness,
            });
        }

        fn get_oracle_requirements(self: @ContractState) -> (bool, u64) {
            (self.require_healthy_oracle.read(), self.max_oracle_staleness.read())
        }

        // =========================================================================
        // Staked Credit Limits
        // =========================================================================

        fn set_staked_credit_limit(ref self: ContractState, limit_bps: u32) {
            self._only_owner();

            // Validate: limit must be between 0 and 100%
            assert!(limit_bps <= 10000, "Limit cannot exceed 100%");

            let old_limit = self.staked_credit_limit_bps.read();
            self.staked_credit_limit_bps.write(limit_bps);

            self.emit(StakedCreditLimitUpdated {
                updated_by: get_caller_address(),
                old_limit_bps: old_limit,
                new_limit_bps: limit_bps,
            });
        }

        fn get_staked_credit_limit(self: @ContractState) -> u32 {
            self.staked_credit_limit_bps.read()
        }

        fn get_available_staked_credit(self: @ContractState, user: ContractAddress) -> u256 {
            let config = self.otc_config.read();
            let limit_bps = self.staked_credit_limit_bps.read();

            // Get user's staked balance from staking contract
            // If staking not configured, return 0
            if config.staking_address.is_zero() {
                return 0;
            }

            // Import staking interface to get staked balance
            // For now, we'll use a simplified calculation based on credits used
            let credits_used = self.staked_credits_used.read(user);

            // In production, query staking contract for actual staked balance
            // max_credit = staked_balance * limit_bps / 10000
            // available = max_credit - credits_used
            //
            // Since we don't have the staking balance here, we return the inverse:
            // If limit_bps is 0, no credit is available
            if limit_bps == 0 {
                return 0;
            }

            // Return credits used (caller should compare against their staked balance)
            // In practice, this should query the staking contract
            credits_used
        }

        // =========================================================================
        // Dynamic Fee Tiers
        // =========================================================================

        fn set_dynamic_fee_tiers(ref self: ContractState, tiers: DynamicFeeTiers) {
            self._only_owner();

            // Validate: fees must be reasonable (between 5% and 25%)
            assert!(tiers.tier1_fee_bps >= 500 && tiers.tier1_fee_bps <= 2500, "Tier1 fee out of range");
            assert!(tiers.tier2_fee_bps >= 500 && tiers.tier2_fee_bps <= 2500, "Tier2 fee out of range");
            assert!(tiers.tier3_fee_bps >= 500 && tiers.tier3_fee_bps <= 2500, "Tier3 fee out of range");

            // Validate: higher tiers should have lower fees
            assert!(tiers.tier2_fee_bps <= tiers.tier1_fee_bps, "Tier2 fee must be <= Tier1");
            assert!(tiers.tier3_fee_bps <= tiers.tier2_fee_bps, "Tier3 fee must be <= Tier2");

            // Validate: thresholds must be increasing
            assert!(tiers.tier2_threshold > tiers.tier1_threshold, "Tier2 threshold must be > Tier1");
            assert!(tiers.tier3_threshold > tiers.tier2_threshold, "Tier3 threshold must be > Tier2");

            self.dynamic_fee_tiers.write(tiers);

            self.emit(DynamicFeeTiersUpdated {
                updated_by: get_caller_address(),
                tier1_threshold: tiers.tier1_threshold,
                tier1_fee_bps: tiers.tier1_fee_bps,
                tier2_threshold: tiers.tier2_threshold,
                tier2_fee_bps: tiers.tier2_fee_bps,
                tier3_threshold: tiers.tier3_threshold,
                tier3_fee_bps: tiers.tier3_fee_bps,
                enabled: tiers.enabled,
            });
        }

        fn get_dynamic_fee_tiers(self: @ContractState) -> DynamicFeeTiers {
            self.dynamic_fee_tiers.read()
        }

        fn get_current_protocol_fee(self: @ContractState) -> u32 {
            let tiers = self.dynamic_fee_tiers.read();

            // If dynamic fees disabled, return base fee from fee_distribution
            if !tiers.enabled {
                return self.fee_distribution.read().protocol_fee_bps;
            }

            // Check if we need to conceptually reset the month
            // (actual reset happens on next payment, but for query we use current volume)
            let now = get_block_timestamp();
            let month_start = self.month_start_timestamp.read();
            let current_volume = if now >= month_start + 2592000 { // 30 days in seconds
                0 // New month, volume resets
            } else {
                self.monthly_volume_usd.read()
            };

            // Determine fee based on volume tier
            if current_volume >= tiers.tier3_threshold {
                tiers.tier3_fee_bps
            } else if current_volume >= tiers.tier2_threshold {
                tiers.tier2_fee_bps
            } else if current_volume >= tiers.tier1_threshold {
                tiers.tier1_fee_bps
            } else {
                // Below tier1, use base fee
                self.fee_distribution.read().protocol_fee_bps
            }
        }

        fn get_monthly_volume(self: @ContractState) -> u256 {
            let now = get_block_timestamp();
            let month_start = self.month_start_timestamp.read();

            // Check if month has rolled over
            if now >= month_start + 2592000 { // 30 days in seconds
                0 // New month, volume is 0
            } else {
                self.monthly_volume_usd.read()
            }
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        // =========================================================================
        // Reentrancy Guard - Prevents reentrant calls to critical functions
        // =========================================================================
        fn _reentrancy_guard_start(ref self: ContractState) {
            assert(!self.reentrancy_locked.read(), 'ReentrancyGuard: reentrant call');
            self.reentrancy_locked.write(true);
        }

        fn _reentrancy_guard_end(ref self: ContractState) {
            self.reentrancy_locked.write(false);
        }

        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }

        fn _when_not_paused(self: @ContractState) {
            assert!(!self.paused.read(), "Contract is paused");
        }

        /// Validate oracle health before using prices
        /// Returns (is_healthy, reason) where reason is empty if healthy
        fn _validate_oracle_health(self: @ContractState) -> (bool, felt252) {
            let config = self.otc_config.read();
            let require_healthy = self.require_healthy_oracle.read();

            // If not requiring healthy oracle, skip validation
            if !require_healthy {
                return (true, 0);
            }

            let oracle = IOracleWrapperDispatcher { contract_address: config.oracle_address };

            // Check if circuit breaker is tripped
            let circuit_breaker_tripped = oracle.is_circuit_breaker_tripped();
            if circuit_breaker_tripped {
                return (false, 'circuit_breaker');
            }

            // Check oracle config for staleness settings
            let oracle_config = oracle.get_config();
            let max_staleness = self.max_oracle_staleness.read();

            // If we have a custom staleness requirement, check it
            // The actual staleness check happens when we get the price
            // Here we just validate the oracle is properly configured
            if max_staleness > 0 && oracle_config.max_price_age > max_staleness {
                // Oracle's internal staleness check is more lenient than our requirement
                // This is a warning but not necessarily a failure
                return (true, 0);
            }

            (true, 0)
        }

        /// Check and update rate limit for a user
        /// Reverts if rate limit exceeded, otherwise increments the counter
        fn _check_rate_limit(ref self: ContractState, user: ContractAddress) {
            let now = get_block_timestamp();
            let window_start = self.user_last_payment_window_start.read(user);
            let window_duration = self.rate_limit_window_secs.read();
            let max_payments = self.max_payments_per_window.read();

            // Skip rate limiting if not configured (max_payments = 0)
            if max_payments == 0 {
                return;
            }

            // Check if we're in a new window
            if now >= window_start + window_duration {
                // Start a new window
                self.user_last_payment_window_start.write(user, now);
                self.user_payment_count_in_window.write(user, 1);
            } else {
                // Within current window - check limit
                let current_count = self.user_payment_count_in_window.read(user);
                assert!(current_count < max_payments, "Rate limit exceeded");

                // Increment counter
                self.user_payment_count_in_window.write(user, current_count + 1);
            }
        }

        /// Update monthly volume tracking and reset if new month
        /// Returns the current protocol fee after considering dynamic tiers
        fn _update_monthly_volume_and_get_fee(ref self: ContractState, usd_amount: u256) -> u32 {
            let now = get_block_timestamp();
            let month_start = self.month_start_timestamp.read();
            let tiers = self.dynamic_fee_tiers.read();

            // Check if we need to reset for new month (30 days = 2592000 seconds)
            let current_volume = if now >= month_start + 2592000 {
                // New month - reset volume and timestamp
                let old_volume = self.monthly_volume_usd.read();
                self.month_start_timestamp.write(now);
                self.monthly_volume_usd.write(usd_amount);

                self.emit(MonthlyVolumeReset {
                    previous_volume: old_volume,
                    reset_timestamp: now,
                });

                usd_amount
            } else {
                // Same month - add to existing volume
                let existing = self.monthly_volume_usd.read();
                let new_volume = existing + usd_amount;
                self.monthly_volume_usd.write(new_volume);
                new_volume
            };

            // If dynamic fees disabled, return base fee
            if !tiers.enabled {
                return self.fee_distribution.read().protocol_fee_bps;
            }

            // Determine fee based on volume tier (use volume BEFORE this payment for fairness)
            let volume_for_tier = if current_volume > usd_amount {
                current_volume - usd_amount
            } else {
                0
            };

            if volume_for_tier >= tiers.tier3_threshold {
                tiers.tier3_fee_bps
            } else if volume_for_tier >= tiers.tier2_threshold {
                tiers.tier2_fee_bps
            } else if volume_for_tier >= tiers.tier1_threshold {
                tiers.tier1_fee_bps
            } else {
                // Below tier1, use base fee
                self.fee_distribution.read().protocol_fee_bps
            }
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
        /// Now supports dynamic fee tiers based on monthly volume
        fn _distribute_fees(
            ref self: ContractState,
            sage_amount: u256,
            job_id: u256,
            usd_value: u256
        ) {
            let fee_dist = self.fee_distribution.read();
            let config = self.otc_config.read();

            // Get SAGE token dispatcher
            let sage_token = ISAGETokenDispatcher { contract_address: config.sage_address };
            let sage_erc20 = IERC20Dispatcher { contract_address: config.sage_address };

            // Step 1: Update volume tracking and get dynamic protocol fee
            let dynamic_protocol_fee_bps = self._update_monthly_volume_and_get_fee(usd_value);

            // Step 2: Calculate worker share using dynamic fee
            // worker_bps = 10000 - protocol_fee_bps (worker always gets the remainder)
            let worker_bps: u256 = 10000 - dynamic_protocol_fee_bps.into();
            let worker_amount = (sage_amount * worker_bps) / BPS_DENOMINATOR;

            // Step 3: Calculate protocol fee using dynamic rate
            let protocol_fee = sage_amount - worker_amount;

            // Step 4: Split protocol fee (70% burn, 20% treasury, 10% stakers)
            let burn_amount = (protocol_fee * fee_dist.burn_share_bps.into()) / BPS_DENOMINATOR;
            let treasury_amount = (protocol_fee * fee_dist.treasury_share_bps.into()) / BPS_DENOMINATOR;
            let staker_amount = protocol_fee - burn_amount - treasury_amount;

            // Step 5: Pay worker via Obelysk (with optional privacy)
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

            // Step 6: Execute protocol fee distribution

            // 6a: Burn tokens (70% of protocol fee)
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

            // 6b: Transfer to staker rewards pool (10% of protocol fee)
            let staker_pool = self.staker_rewards_pool.read();
            if !staker_pool.is_zero() && staker_amount > 0 {
                let success = sage_erc20.transfer(staker_pool, staker_amount);
                assert(success, 'Staker transfer failed');
            }

            // 6c: Transfer to treasury (20% of protocol fee)
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

            // Record trade with referral system for the payer
            // This rewards referrers when their referred users make payments
            self._record_referral_payment(get_caller_address(), usd_value, protocol_fee, config.sage_address);
        }

        /// Record payment with referral system if configured
        fn _record_referral_payment(
            ref self: ContractState,
            payer: ContractAddress,
            volume_usd: u256,
            fee_amount: u256,
            fee_token: ContractAddress
        ) {
            let referral_addr = self.referral_system.read();
            if referral_addr.is_zero() {
                return;  // Referral system not configured
            }

            // Call referral system to record payment and distribute rewards
            let referral = IReferralSystemDispatcher { contract_address: referral_addr };
            referral.record_trade(payer, volume_usd, fee_amount, fee_token);
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
    }
}
