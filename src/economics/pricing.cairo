// =============================================================================
// DYNAMIC PRICING CONTRACT - BitSage Network
// =============================================================================
//
// Implements dynamic pricing based on Units of Compute:
//
// - Per-token pricing for each compute model
// - Stability zone (40-60% utilization) - no price change
// - Below 40%: Price decreases to encourage usage
// - Above 60%: Price increases to moderate demand
// - Price elasticity: 5% max change per epoch at extreme utilization
//
// Formula: Price = BasePrice * (1 + Elasticity * UtilizationDeviation)
//
// =============================================================================

use starknet::{ContractAddress, ClassHash};

// =============================================================================
// Constants
// =============================================================================

const STABILITY_ZONE_LOWER_BPS: u16 = 4000;  // 40%
const STABILITY_ZONE_UPPER_BPS: u16 = 6000;  // 60%
const PRICE_ELASTICITY_BPS: u16 = 500;       // 5% max change per epoch
const MIN_PRICE_PER_TOKEN: u256 = 1;         // 1 wei minimum (prevent zero)
const BPS_DENOMINATOR: u256 = 10000;

// =============================================================================
// Data Types
// =============================================================================

/// Pricing configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PricingConfig {
    /// Lower bound of stability zone (basis points, default 4000 = 40%)
    pub stability_lower_bps: u16,
    /// Upper bound of stability zone (basis points, default 6000 = 60%)
    pub stability_upper_bps: u16,
    /// Price elasticity (basis points, default 500 = 5%)
    pub elasticity_bps: u16,
    /// Minimum price per token
    pub min_price: u256,
    /// Base price per token (starting price)
    pub base_price: u256,
    /// Utilization window (epochs to average)
    pub utilization_window_epochs: u64,
    /// Grace period end epoch (free pricing)
    pub grace_period_end_epoch: u64,
}

/// Model pricing information
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ModelPricing {
    /// Current price per token
    pub price_per_token: u256,
    /// Total capacity (tokens per epoch)
    pub capacity: u256,
    /// Tokens processed in current epoch
    pub tokens_processed: u256,
    /// Last epoch price was updated
    pub last_update_epoch: u64,
    /// Historical utilization (basis points)
    pub utilization_bps: u16,
    /// Is model active
    pub is_active: bool,
}

/// Compute model registration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ComputeModel {
    /// Model identifier hash
    pub model_id: felt252,
    /// Human readable name (first 31 chars as felt)
    pub name: felt252,
    /// Units of compute per token (model complexity)
    pub units_per_token: u256,
    /// Base price multiplier (basis points, 10000 = 1x)
    pub price_multiplier_bps: u16,
    /// Minimum stake required to serve this model
    pub min_stake: u256,
    /// Is model active
    pub is_active: bool,
}

/// Global pricing statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PricingStats {
    /// Total models registered
    pub total_models: u64,
    /// Active models
    pub active_models: u64,
    /// Total tokens processed (all time)
    pub total_tokens_processed: u256,
    /// Total revenue generated
    pub total_revenue: u256,
    /// Average utilization (basis points)
    pub avg_utilization_bps: u16,
    /// Current epoch
    pub current_epoch: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IDynamicPricing<TContractState> {
    // === Price Queries ===
    /// Get current price for a model
    fn get_price(self: @TContractState, model_id: felt252) -> u256;
    
    /// Calculate cost for tokens
    fn calculate_cost(self: @TContractState, model_id: felt252, tokens: u256) -> u256;
    
    /// Get model pricing info
    fn get_model_pricing(self: @TContractState, model_id: felt252) -> ModelPricing;
    
    // === Usage Recording ===
    /// Record token usage (called by job manager)
    fn record_usage(ref self: TContractState, model_id: felt252, tokens: u256);
    
    // === Model Management ===
    /// Register a new compute model
    fn register_model(
        ref self: TContractState,
        model_id: felt252,
        name: felt252,
        units_per_token: u256,
        price_multiplier_bps: u16,
        capacity: u256,
        min_stake: u256,
    );
    
    /// Update model capacity
    fn update_capacity(ref self: TContractState, model_id: felt252, capacity: u256);
    
    /// Deactivate model
    fn deactivate_model(ref self: TContractState, model_id: felt252);
    
    // === Price Updates ===
    /// Update prices based on utilization (called at epoch end)
    fn update_prices(ref self: TContractState);
    
    /// Advance to next epoch
    fn advance_epoch(ref self: TContractState);
    
    // === Admin ===
    fn update_config(ref self: TContractState, config: PricingConfig);
    fn set_job_manager(ref self: TContractState, job_manager: ContractAddress);
    
    // === View Functions ===
    fn get_config(self: @TContractState) -> PricingConfig;
    fn get_model(self: @TContractState, model_id: felt252) -> ComputeModel;
    fn get_stats(self: @TContractState) -> PricingStats;
    fn get_current_epoch(self: @TContractState) -> u64;
    fn is_grace_period(self: @TContractState) -> bool;

    // === Upgrade Functions ===
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);
    fn execute_upgrade(ref self: TContractState);
    fn cancel_upgrade(ref self: TContractState);
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64);
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod DynamicPricing {
    use super::{
        IDynamicPricing, PricingConfig, ModelPricing, ComputeModel, PricingStats,
        STABILITY_ZONE_LOWER_BPS, STABILITY_ZONE_UPPER_BPS, PRICE_ELASTICITY_BPS,
        MIN_PRICE_PER_TOKEN, BPS_DENOMINATOR,
    };
    use starknet::{
        ContractAddress, ClassHash, get_caller_address, get_block_timestamp,
        syscalls::replace_class_syscall, SyscallResultTrait,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use core::num::traits::Zero;

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// Job manager (authorized to record usage)
        job_manager: ContractAddress,
        /// Configuration
        config: PricingConfig,
        /// Current epoch
        current_epoch: u64,
        /// Registered models
        models: Map<felt252, ComputeModel>,
        /// Model pricing
        model_pricing: Map<felt252, ModelPricing>,
        /// Model list (for iteration)
        model_list: Map<u64, felt252>,
        /// Model count
        model_count: u64,
        /// Statistics
        stats: PricingStats,
        // Upgrade storage
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ModelRegistered: ModelRegistered,
        PriceUpdated: PriceUpdated,
        UsageRecorded: UsageRecorded,
        EpochAdvanced: EpochAdvanced,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct ModelRegistered {
        #[key]
        model_id: felt252,
        name: felt252,
        units_per_token: u256,
        initial_price: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PriceUpdated {
        #[key]
        model_id: felt252,
        old_price: u256,
        new_price: u256,
        utilization_bps: u16,
    }

    #[derive(Drop, starknet::Event)]
    struct UsageRecorded {
        #[key]
        model_id: felt252,
        tokens: u256,
        cost: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct EpochAdvanced {
        old_epoch: u64,
        new_epoch: u64,
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

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
    ) {
        self.owner.write(owner);
        
        // Default configuration
        self.config.write(PricingConfig {
            stability_lower_bps: STABILITY_ZONE_LOWER_BPS,
            stability_upper_bps: STABILITY_ZONE_UPPER_BPS,
            elasticity_bps: PRICE_ELASTICITY_BPS,
            min_price: MIN_PRICE_PER_TOKEN,
            base_price: 100_000000000000000_u256, // 0.1 SAGE per token
            utilization_window_epochs: 3,
            grace_period_end_epoch: 90, // ~3 months free
        });
        
        self.current_epoch.write(1);
        self.model_count.write(0);
        
        self.stats.write(PricingStats {
            total_models: 0,
            active_models: 0,
            total_tokens_processed: 0,
            total_revenue: 0,
            avg_utilization_bps: 5000, // Start at 50%
            current_epoch: 1,
        });

        // Initialize upgrade delay (2 days in seconds)
        self.upgrade_delay.write(172800);
    }

    // =========================================================================
    // Implementation
    // =========================================================================

    #[abi(embed_v0)]
    impl DynamicPricingImpl of IDynamicPricing<ContractState> {
        fn get_price(self: @ContractState, model_id: felt252) -> u256 {
            // During grace period, price is 0
            if self._is_grace_period() {
                return 0;
            }
            
            let pricing = self.model_pricing.read(model_id);
            if !pricing.is_active {
                return 0;
            }
            
            pricing.price_per_token
        }

        fn calculate_cost(self: @ContractState, model_id: felt252, tokens: u256) -> u256 {
            let price = self.get_price(model_id);
            price * tokens
        }

        fn get_model_pricing(self: @ContractState, model_id: felt252) -> ModelPricing {
            self.model_pricing.read(model_id)
        }

        fn record_usage(ref self: ContractState, model_id: felt252, tokens: u256) {
            let caller = get_caller_address();
            assert(
                caller == self.job_manager.read() || caller == self.owner.read(),
                'Unauthorized'
            );
            
            let mut pricing = self.model_pricing.read(model_id);
            assert(pricing.is_active, 'Model not active');
            
            let cost = pricing.price_per_token * tokens;
            
            pricing.tokens_processed = pricing.tokens_processed + tokens;
            self.model_pricing.write(model_id, pricing);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_tokens_processed = stats.total_tokens_processed + tokens;
            stats.total_revenue = stats.total_revenue + cost;
            self.stats.write(stats);
            
            self.emit(UsageRecorded {
                model_id,
                tokens,
                cost,
            });
        }

        fn register_model(
            ref self: ContractState,
            model_id: felt252,
            name: felt252,
            units_per_token: u256,
            price_multiplier_bps: u16,
            capacity: u256,
            min_stake: u256,
        ) {
            self._only_owner();
            
            // Check not already registered
            let existing = self.models.read(model_id);
            assert(!existing.is_active, 'Model already exists');
            
            // Register model
            let model = ComputeModel {
                model_id,
                name,
                units_per_token,
                price_multiplier_bps,
                min_stake,
                is_active: true,
            };
            self.models.write(model_id, model);
            
            // Calculate initial price
            let config = self.config.read();
            let initial_price = (config.base_price * price_multiplier_bps.into()) / BPS_DENOMINATOR;
            let final_price = if initial_price < config.min_price {
                config.min_price
            } else {
                initial_price
            };
            
            // Initialize pricing
            let pricing = ModelPricing {
                price_per_token: final_price,
                capacity,
                tokens_processed: 0,
                last_update_epoch: self.current_epoch.read(),
                utilization_bps: 5000, // Start at 50%
                is_active: true,
            };
            self.model_pricing.write(model_id, pricing);
            
            // Add to list
            let idx = self.model_count.read();
            self.model_list.write(idx, model_id);
            self.model_count.write(idx + 1);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_models = stats.total_models + 1;
            stats.active_models = stats.active_models + 1;
            self.stats.write(stats);
            
            self.emit(ModelRegistered {
                model_id,
                name,
                units_per_token,
                initial_price: final_price,
            });
        }

        fn update_capacity(ref self: ContractState, model_id: felt252, capacity: u256) {
            self._only_owner();
            
            let mut pricing = self.model_pricing.read(model_id);
            pricing.capacity = capacity;
            self.model_pricing.write(model_id, pricing);
        }

        fn deactivate_model(ref self: ContractState, model_id: felt252) {
            self._only_owner();
            
            let mut model = self.models.read(model_id);
            model.is_active = false;
            self.models.write(model_id, model);
            
            let mut pricing = self.model_pricing.read(model_id);
            pricing.is_active = false;
            self.model_pricing.write(model_id, pricing);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.active_models = stats.active_models - 1;
            self.stats.write(stats);
        }

        fn update_prices(ref self: ContractState) {
            self._only_owner();
            
            let config = self.config.read();
            let model_count = self.model_count.read();
            let mut i: u64 = 0;
            
            loop {
                if i >= model_count {
                    break;
                }
                
                let model_id = self.model_list.read(i);
                let mut pricing = self.model_pricing.read(model_id);
                
                if pricing.is_active && pricing.capacity > 0 {
                    // Calculate utilization
                    let utilization = (pricing.tokens_processed * BPS_DENOMINATOR) / pricing.capacity;
                    let utilization_bps: u16 = if utilization > 10000 {
                        10000
                    } else {
                        utilization.try_into().unwrap()
                    };
                    
                    let old_price = pricing.price_per_token;
                    let new_price = self._calculate_new_price(old_price, utilization_bps, @config);
                    
                    pricing.price_per_token = new_price;
                    pricing.utilization_bps = utilization_bps;
                    pricing.tokens_processed = 0; // Reset for next epoch
                    pricing.last_update_epoch = self.current_epoch.read();
                    
                    self.model_pricing.write(model_id, pricing);
                    
                    self.emit(PriceUpdated {
                        model_id,
                        old_price,
                        new_price,
                        utilization_bps,
                    });
                }
                
                i = i + 1;
            };
        }

        fn advance_epoch(ref self: ContractState) {
            self._only_owner();
            
            // First update prices based on current epoch utilization
            self.update_prices();
            
            // Then advance epoch
            let old_epoch = self.current_epoch.read();
            let new_epoch = old_epoch + 1;
            self.current_epoch.write(new_epoch);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.current_epoch = new_epoch;
            self.stats.write(stats);
            
            self.emit(EpochAdvanced {
                old_epoch,
                new_epoch,
            });
        }

        fn update_config(ref self: ContractState, config: PricingConfig) {
            self._only_owner();
            self.config.write(config);
        }

        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            self._only_owner();
            self.job_manager.write(job_manager);
        }

        fn get_config(self: @ContractState) -> PricingConfig {
            self.config.read()
        }

        fn get_model(self: @ContractState, model_id: felt252) -> ComputeModel {
            self.models.read(model_id)
        }

        fn get_stats(self: @ContractState) -> PricingStats {
            self.stats.read()
        }

        fn get_current_epoch(self: @ContractState) -> u64 {
            self.current_epoch.read()
        }

        fn is_grace_period(self: @ContractState) -> bool {
            self._is_grace_period()
        }

        // === Upgrade Functions ===

        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(pending.is_zero(), "Another upgrade is already pending");
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
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade");

            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let current_time = get_block_timestamp();

            assert!(current_time >= scheduled_at + delay, "Timelock not expired");

            let zero_class: ClassHash = 0.try_into().unwrap();
            self.pending_upgrade.write(zero_class);
            self.upgrade_scheduled_at.write(0);

            replace_class_syscall(pending).unwrap_syscall();

            self.emit(UpgradeExecuted {
                new_class_hash: pending,
                executed_at: current_time,
                executed_by: get_caller_address(),
            });
        }

        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();
            let pending = self.pending_upgrade.read();
            assert!(!pending.is_zero(), "No pending upgrade to cancel");

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
            self._only_owner();
            assert!(delay >= 86400, "Delay must be at least 1 day");
            assert!(delay <= 2592000, "Delay must be at most 30 days");
            self.upgrade_delay.write(delay);
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }

        fn _is_grace_period(self: @ContractState) -> bool {
            let config = self.config.read();
            self.current_epoch.read() <= config.grace_period_end_epoch
        }

        fn _calculate_new_price(
            self: @ContractState,
            current_price: u256,
            utilization_bps: u16,
            config: @PricingConfig,
        ) -> u256 {
            let lower = *config.stability_lower_bps;
            let upper = *config.stability_upper_bps;
            let elasticity = *config.elasticity_bps;
            
            // In stability zone - no change
            if utilization_bps >= lower && utilization_bps <= upper {
                return current_price;
            }
            
            // Below stability zone - decrease price
            if utilization_bps < lower {
                let deficit: u256 = (lower - utilization_bps).into();
                let adjustment = (deficit * elasticity.into()) / BPS_DENOMINATOR;
                let decrease = (current_price * adjustment) / BPS_DENOMINATOR;
                
                let new_price = if current_price > decrease {
                    current_price - decrease
                } else {
                    *config.min_price
                };
                
                if new_price < *config.min_price {
                    return *config.min_price;
                }
                return new_price;
            }
            
            // Above stability zone - increase price
            let excess: u256 = (utilization_bps - upper).into();
            let adjustment = (excess * elasticity.into()) / BPS_DENOMINATOR;
            let increase = (current_price * adjustment) / BPS_DENOMINATOR;
            
            current_price + increase
        }
    }
}

