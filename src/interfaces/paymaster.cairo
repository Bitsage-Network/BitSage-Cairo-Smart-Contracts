use starknet::ContractAddress;
use super::job_manager::{JobId, ModelId};

/// Subscription tiers for gas sponsorship
#[derive(Copy, Drop, Serde, starknet::Store)]
#[allow(starknet::store_no_default_variant)]
pub enum SubscriptionTier {
    Basic,     // Limited transactions per day
    Premium,   // Higher limits + priority
    Enterprise // Unlimited + custom features
}

/// Payment channel state
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PaymentChannel {
    pub sender: ContractAddress,
    pub recipient: ContractAddress,
    pub balance: u256,
    pub nonce: u64,
    pub expiration: u64,
    pub open: bool,
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
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct SponsorshipRequest {
    pub account: ContractAddress,
    pub function_selector: felt252,
    pub estimated_gas: u256,
    pub job_id: Option<JobId>,
    pub priority: u8,
}

/// Rate limiting data
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RateLimit {
    pub requests_per_hour: u32,
    pub current_count: u32,
    pub window_start: u64,
}

/// Paymaster contract interface for gas abstraction and payment management
#[starknet::interface]
pub trait IPaymaster<TContractState> {
    // ============================================================================
    // Core Sponsorship Functions
    // ============================================================================
    
    /// Validate and sponsor a transaction
    /// Returns true if sponsorship is approved
    fn validate_and_sponsor(
        ref self: TContractState,
        request: SponsorshipRequest,
        signature: Array<felt252>
    ) -> bool;
    
    /// Direct fee payment for a transaction
    fn pay_transaction_fee(
        ref self: TContractState,
        account: ContractAddress,
        fee_amount: u256,
        transaction_hash: felt252
    ) -> bool;
    
    /// Reimburse transaction fees after execution
    fn reimburse_fee(
        ref self: TContractState,
        account: ContractAddress,
        fee_amount: u256,
        transaction_hash: felt252
    );
    
    /// Batch sponsor multiple transactions
    fn sponsor_batch(
        ref self: TContractState,
        requests: Array<SponsorshipRequest>
    ) -> Array<bool>;
    
    // ============================================================================
    // Account Management
    // ============================================================================
    
    /// Add account to sponsorship allowlist
    fn add_to_allowlist(ref self: TContractState, account: ContractAddress);
    
    /// Remove account from allowlist
    fn remove_from_allowlist(ref self: TContractState, account: ContractAddress);
    
    /// Check if account is in allowlist
    fn is_allowlisted(self: @TContractState, account: ContractAddress) -> bool;
    
    /// Set gas limit for specific account
    fn set_account_gas_limit(
        ref self: TContractState,
        account: ContractAddress,
        daily_limit: u256
    );
    
    /// Get remaining gas allowance for account
    fn get_gas_allowance(self: @TContractState, account: ContractAddress) -> u256;
    
    // ============================================================================
    // Subscription Management
    // ============================================================================
    
    /// Create or update subscription
    fn create_subscription(
        ref self: TContractState,
        account: ContractAddress,
        tier: SubscriptionTier,
        duration_days: u32
    );
    
    /// Cancel subscription
    fn cancel_subscription(ref self: TContractState, account: ContractAddress);
    
    /// Get subscription details
    fn get_subscription(self: @TContractState, account: ContractAddress) -> Subscription;
    
    /// Upgrade subscription tier
    fn upgrade_subscription(
        ref self: TContractState,
        account: ContractAddress,
        new_tier: SubscriptionTier
    );
    
    /// Check if subscription allows sponsorship
    fn can_sponsor_subscription(
        self: @TContractState,
        account: ContractAddress,
        estimated_gas: u256
    ) -> bool;
    
    // ============================================================================
    // Payment Channels
    // ============================================================================
    
    /// Open payment channel
    fn open_payment_channel(
        ref self: TContractState,
        recipient: ContractAddress,
        initial_deposit: u256,
        duration: u64
    ) -> felt252; // Returns channel ID
    
    /// Close payment channel
    fn close_payment_channel(
        ref self: TContractState,
        channel_id: felt252,
        final_balance: u256,
        signature: Array<felt252>
    );
    
    /// Claim payment from channel
    fn claim_channel_payment(
        ref self: TContractState,
        channel_id: felt252,
        amount: u256,
        nonce: u64,
        signature: Array<felt252>
    );
    
    /// Get payment channel details
    fn get_payment_channel(self: @TContractState, channel_id: felt252) -> PaymentChannel;
    
    /// Fund existing channel
    fn fund_channel(
        ref self: TContractState,
        channel_id: felt252,
        additional_amount: u256
    );
    
    // ============================================================================
    // CDC Network Integration
    // ============================================================================
    
    /// Sponsor job-related transactions
    fn sponsor_job_transaction(
        ref self: TContractState,
        job_id: JobId,
        worker: ContractAddress,
        function_selector: felt252,
        calldata: Array<felt252>
    ) -> bool;
    
    /// Sponsor job submission from clients
    fn sponsor_job_submission(
        ref self: TContractState,
        client: ContractAddress,
        model_id: ModelId,
        payment_amount: u256
    ) -> bool;
    
    /// Sponsor reward distribution to workers
    fn sponsor_reward_distribution(
        ref self: TContractState,
        workers: Array<ContractAddress>,
        amounts: Array<u256>
    ) -> bool;
    
    /// Pay for computation results
    fn pay_for_computation_result(
        ref self: TContractState,
        job_id: JobId,
        worker: ContractAddress,
        result_hash: felt252,
        proof: Array<felt252>
    );
    
    /// Sponsor based on worker reputation
    fn sponsor_by_reputation(
        ref self: TContractState,
        worker: ContractAddress,
        function_selector: felt252
    ) -> bool;
    
    // ============================================================================
    // Security & Rate Limiting
    // ============================================================================
    
    /// Set rate limits for account
    fn set_rate_limit(
        ref self: TContractState,
        account: ContractAddress,
        requests_per_hour: u32
    );
    
    /// Check if account is within rate limits
    fn check_rate_limit(self: @TContractState, account: ContractAddress) -> bool;
    
    /// Emergency pause all sponsorship
    fn emergency_pause(ref self: TContractState);
    
    /// Resume operations after pause
    fn resume_operations(ref self: TContractState);
    
    /// Check if operations are paused
    fn is_paused(self: @TContractState) -> bool;
    
    /// Blacklist malicious account
    fn blacklist_account(ref self: TContractState, account: ContractAddress);
    
    /// Remove account from blacklist
    fn remove_from_blacklist(ref self: TContractState, account: ContractAddress);
    
    /// Check if account is blacklisted
    fn is_blacklisted(self: @TContractState, account: ContractAddress) -> bool;
    
    // ============================================================================
    // Administrative Functions
    // ============================================================================
    
    /// Set contract addresses for integration
    fn set_job_manager(ref self: TContractState, job_manager: ContractAddress);
    fn set_cdc_pool(ref self: TContractState, cdc_pool: ContractAddress);
    
    /// Set fee token address
    fn set_fee_token(ref self: TContractState, token: ContractAddress);
    
    /// Withdraw accumulated fees
    fn withdraw_fees(ref self: TContractState, amount: u256, recipient: ContractAddress);
    
    /// Set maximum sponsorship amounts
    fn set_max_sponsorship_amounts(
        ref self: TContractState,
        max_per_transaction: u256,
        max_per_day: u256
    );
    
    /// Update subscription pricing
    fn update_subscription_pricing(
        ref self: TContractState,
        tier: SubscriptionTier,
        price_per_month: u256
    );
    
    /// Transfer ownership
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    
    // ============================================================================
    // View Functions
    // ============================================================================
    
    /// Get total fees collected
    fn get_total_fees_collected(self: @TContractState) -> u256;
    
    /// Get sponsorship statistics for account
    fn get_sponsorship_stats(
        self: @TContractState,
        account: ContractAddress
    ) -> (u256, u32, u64); // (total_sponsored, tx_count, last_sponsored)
    
    /// Get contract configuration
    fn get_config(self: @TContractState) -> (
        ContractAddress, // job_manager
        ContractAddress, // cdc_pool
        ContractAddress, // fee_token
        u256,           // max_per_transaction
        u256            // max_per_day
    );
    
    /// Check if function is sponsorable
    fn is_function_sponsorable(
        self: @TContractState,
        function_selector: felt252
    ) -> bool;
    
    /// Get subscription pricing
    fn get_subscription_price(
        self: @TContractState,
        tier: SubscriptionTier
    ) -> u256;
    
    /// Get active payment channels for account
    fn get_active_channels(
        self: @TContractState,
        account: ContractAddress
    ) -> Array<felt252>;
}

// ============================================================================
// Events
// ============================================================================

#[derive(Drop, starknet::Event)]
pub struct TransactionSponsored {
    #[key]
    pub account: ContractAddress,
    pub fee_amount: u256,
    pub transaction_hash: felt252,
    pub timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct SubscriptionCreated {
    #[key]
    pub account: ContractAddress,
    pub tier: SubscriptionTier,
    pub expiration: u64,
    pub daily_limit: u256,
}

#[derive(Drop, starknet::Event)]
pub struct SubscriptionCancelled {
    #[key]
    pub account: ContractAddress,
    pub refund_amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct PaymentChannelOpened {
    #[key]
    pub channel_id: felt252,
    #[key]
    pub sender: ContractAddress,
    #[key]
    pub recipient: ContractAddress,
    pub initial_deposit: u256,
    pub expiration: u64,
}

#[derive(Drop, starknet::Event)]
pub struct PaymentChannelClosed {
    #[key]
    pub channel_id: felt252,
    pub final_balance: u256,
    pub refund_amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct ChannelPaymentClaimed {
    #[key]
    pub channel_id: felt252,
    #[key]
    pub recipient: ContractAddress,
    pub amount: u256,
    pub nonce: u64,
}

#[derive(Drop, starknet::Event)]
pub struct JobTransactionSponsored {
    #[key]
    pub job_id: JobId,
    #[key]
    pub worker: ContractAddress,
    pub function_selector: felt252,
    pub fee_amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct RewardDistributionSponsored {
    pub total_amount: u256,
    pub worker_count: u32,
    pub distribution_id: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct AccountAllowlisted {
    #[key]
    pub account: ContractAddress,
    pub gas_limit: u256,
}

#[derive(Drop, starknet::Event)]
pub struct AccountBlacklisted {
    #[key]
    pub account: ContractAddress,
    pub reason: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct RateLimitExceeded {
    #[key]
    pub account: ContractAddress,
    pub current_count: u32,
    pub limit: u32,
}

#[derive(Drop, starknet::Event)]
pub struct EmergencyPaused {
    pub timestamp: u64,
    pub reason: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct OperationsResumed {
    pub timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct FeesWithdrawn {
    #[key]
    pub recipient: ContractAddress,
    pub amount: u256,
}

#[derive(Drop, starknet::Event)]
pub struct ConfigurationUpdated {
    pub parameter: felt252,
    pub old_value: felt252,
    pub new_value: felt252,
} 