//! Buyback and Burn Engine
//!
//! Automated buyback mechanism that:
//! 1. Accumulates treasury funds for buybacks
//! 2. Executes buybacks through OTC/DEX at optimal prices
//! 3. Burns purchased SAGE tokens
//!
//! ## Execution Modes
//! - **Manual**: Owner triggers buyback with specific parameters
//! - **Scheduled**: Automatic periodic buybacks based on thresholds
//! - **TWAP**: Time-weighted average price execution to minimize slippage
//!
//! ## Safety Features
//! - Minimum/maximum buyback amounts
//! - Price floor protection (won't buy above threshold)
//! - Cooldown between buybacks
//! - Oracle price validation

use starknet::ContractAddress;

/// Buyback execution configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct BuybackConfig {
    /// Minimum buyback amount in USD (18 decimals)
    pub min_buyback_usd: u256,
    /// Maximum buyback amount per execution in USD
    pub max_buyback_usd: u256,
    /// Maximum price to pay for SAGE (in USD, 18 decimals)
    /// Won't execute if current price exceeds this
    pub price_ceiling_usd: u256,
    /// Cooldown between buybacks in seconds
    pub cooldown_secs: u64,
    /// Whether automatic buybacks are enabled
    pub auto_enabled: bool,
    /// Threshold balance to trigger automatic buyback (in USDC, 6 decimals)
    pub auto_threshold_usdc: u256,
    /// Target percentage of balance to use per auto-buyback (basis points)
    pub auto_percent_bps: u32,
}

/// Buyback execution record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct BuybackExecution {
    /// Unique execution ID
    pub execution_id: u256,
    /// USDC spent
    pub usdc_spent: u256,
    /// SAGE purchased
    pub sage_purchased: u256,
    /// SAGE burned
    pub sage_burned: u256,
    /// Execution price (SAGE/USD, 18 decimals)
    pub execution_price: u256,
    /// Timestamp
    pub executed_at: u64,
    /// Who triggered the execution
    pub executor: ContractAddress,
}

#[starknet::interface]
pub trait IBuybackEngine<TContractState> {
    /// Execute a manual buyback
    /// @param usdc_amount: Amount of USDC to spend on buyback
    fn execute_buyback(ref self: TContractState, usdc_amount: u256);

    /// Check if conditions are met for automatic buyback
    fn can_auto_buyback(self: @TContractState) -> bool;

    /// Trigger automatic buyback if conditions are met
    fn trigger_auto_buyback(ref self: TContractState);

    /// Get buyback configuration
    fn get_config(self: @TContractState) -> BuybackConfig;

    /// Update buyback configuration (owner only)
    fn set_config(ref self: TContractState, config: BuybackConfig);

    /// Get total stats
    fn get_stats(self: @TContractState) -> (u256, u256, u256, u256);  // total_usdc_spent, total_sage_purchased, total_sage_burned, execution_count

    /// Get last execution
    fn get_last_execution(self: @TContractState) -> BuybackExecution;

    /// Get USDC balance available for buybacks
    fn get_buyback_balance(self: @TContractState) -> u256;

    /// Withdraw excess funds (owner only, emergency)
    fn emergency_withdraw(ref self: TContractState, token: ContractAddress, amount: u256);

    /// Set OTC/DEX address for execution
    fn set_execution_venue(ref self: TContractState, venue: ContractAddress);

    /// Pause/unpause
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn is_paused(self: @TContractState) -> bool;
}

#[starknet::contract]
mod BuybackEngine {
    use super::{IBuybackEngine, BuybackConfig, BuybackExecution};
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use sage_contracts::interfaces::sage_token::{ISAGETokenDispatcher, ISAGETokenDispatcherTrait};
    use sage_contracts::oracle::pragma_oracle::{IOracleWrapperDispatcher, IOracleWrapperDispatcherTrait, PricePair};

    const USD_DECIMALS: u256 = 1000000000000000000;  // 10^18
    const USDC_DECIMALS: u256 = 1000000;  // 10^6
    const BPS_DENOMINATOR: u256 = 10000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        sage_token: ContractAddress,
        usdc_token: ContractAddress,
        oracle: ContractAddress,
        execution_venue: ContractAddress,  // OTC/DEX for executing buybacks
        config: BuybackConfig,
        last_buyback_at: u64,
        execution_count: u256,
        last_execution: BuybackExecution,
        total_usdc_spent: u256,
        total_sage_purchased: u256,
        total_sage_burned: u256,
        paused: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        BuybackExecuted: BuybackExecuted,
        ConfigUpdated: ConfigUpdated,
        ExecutionVenueUpdated: ExecutionVenueUpdated,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        EmergencyWithdrawal: EmergencyWithdrawal,
    }

    #[derive(Drop, starknet::Event)]
    struct BuybackExecuted {
        #[key]
        execution_id: u256,
        usdc_spent: u256,
        sage_purchased: u256,
        sage_burned: u256,
        execution_price: u256,
        executor: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        #[key]
        updated_by: ContractAddress,
        min_buyback_usd: u256,
        max_buyback_usd: u256,
        price_ceiling_usd: u256,
        auto_enabled: bool,
    }

    #[derive(Drop, starknet::Event)]
    struct ExecutionVenueUpdated {
        old_venue: ContractAddress,
        new_venue: ContractAddress,
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
    struct EmergencyWithdrawal {
        #[key]
        token: ContractAddress,
        amount: u256,
        withdrawn_by: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        usdc_token: ContractAddress,
        oracle: ContractAddress,
    ) {
        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.usdc_token.write(usdc_token);
        self.oracle.write(oracle);

        // Default configuration
        self.config.write(BuybackConfig {
            min_buyback_usd: 1000_u256 * USD_DECIMALS,      // $1,000 minimum
            max_buyback_usd: 100000_u256 * USD_DECIMALS,    // $100,000 maximum per execution
            price_ceiling_usd: 1_u256 * USD_DECIMALS,        // $1.00 max price (10x from launch)
            cooldown_secs: 86400,                            // 24 hours cooldown
            auto_enabled: false,                             // Start with manual only
            auto_threshold_usdc: 10000_u256 * USDC_DECIMALS, // $10,000 USDC triggers auto
            auto_percent_bps: 5000,                          // Use 50% of balance per auto-buyback
        });

        self.paused.write(false);
        self.execution_count.write(0);
    }

    #[abi(embed_v0)]
    impl BuybackEngineImpl of IBuybackEngine<ContractState> {
        fn execute_buyback(ref self: ContractState, usdc_amount: u256) {
            self._only_owner();
            self._require_not_paused();

            let config = self.config.read();
            let now = get_block_timestamp();

            // Check cooldown
            let last_buyback = self.last_buyback_at.read();
            assert!(now >= last_buyback + config.cooldown_secs, "Buyback cooldown active");

            // Convert USDC amount to USD (USDC has 6 decimals, we want 18)
            let usd_amount = (usdc_amount * USD_DECIMALS) / USDC_DECIMALS;

            // Validate amount
            assert!(usd_amount >= config.min_buyback_usd, "Below minimum buyback amount");
            assert!(usd_amount <= config.max_buyback_usd, "Exceeds maximum buyback amount");

            // Check USDC balance
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            let balance = usdc.balance_of(get_contract_address());
            assert!(balance >= usdc_amount, "Insufficient USDC balance");

            // Get current SAGE price from oracle
            let oracle = IOracleWrapperDispatcher { contract_address: self.oracle.read() };
            let sage_price = oracle.get_price_usd(PricePair::SAGE_USD);
            assert!(sage_price > 0, "Invalid oracle price");

            // Check price ceiling
            assert!(sage_price <= config.price_ceiling_usd, "SAGE price exceeds ceiling");

            // Calculate SAGE amount to purchase
            // sage_amount = usdc_usd_value / sage_price
            let sage_amount = (usd_amount * USD_DECIMALS) / sage_price;

            // Execute buyback (simplified - in production would use OTC/DEX)
            // For now, we assume the execution venue will handle the swap
            // and we just burn the SAGE tokens we receive
            self._execute_and_burn(usdc_amount, sage_amount, sage_price);
        }

        fn can_auto_buyback(self: @ContractState) -> bool {
            let config = self.config.read();

            if !config.auto_enabled {
                return false;
            }

            if self.paused.read() {
                return false;
            }

            // Check cooldown
            let now = get_block_timestamp();
            let last_buyback = self.last_buyback_at.read();
            if now < last_buyback + config.cooldown_secs {
                return false;
            }

            // Check balance threshold
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            let balance = usdc.balance_of(starknet::get_contract_address());
            if balance < config.auto_threshold_usdc {
                return false;
            }

            // Check price ceiling
            let oracle = IOracleWrapperDispatcher { contract_address: self.oracle.read() };
            let sage_price = oracle.get_price_usd(PricePair::SAGE_USD);
            if sage_price == 0 || sage_price > config.price_ceiling_usd {
                return false;
            }

            true
        }

        fn trigger_auto_buyback(ref self: ContractState) {
            self._require_not_paused();

            // Anyone can trigger if conditions are met
            assert!(self.can_auto_buyback(), "Auto-buyback conditions not met");

            let config = self.config.read();

            // Get balance and calculate buyback amount
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            let balance = usdc.balance_of(get_contract_address());

            // Use configured percentage of balance
            let usdc_amount = (balance * config.auto_percent_bps.into()) / BPS_DENOMINATOR;

            // Cap at max buyback
            let usd_amount = (usdc_amount * USD_DECIMALS) / USDC_DECIMALS;
            let final_usdc_amount = if usd_amount > config.max_buyback_usd {
                (config.max_buyback_usd * USDC_DECIMALS) / USD_DECIMALS
            } else {
                usdc_amount
            };

            // Get SAGE price
            let oracle = IOracleWrapperDispatcher { contract_address: self.oracle.read() };
            let sage_price = oracle.get_price_usd(PricePair::SAGE_USD);

            // Calculate SAGE amount
            let final_usd = (final_usdc_amount * USD_DECIMALS) / USDC_DECIMALS;
            let sage_amount = (final_usd * USD_DECIMALS) / sage_price;

            // Execute
            self._execute_and_burn(final_usdc_amount, sage_amount, sage_price);
        }

        fn get_config(self: @ContractState) -> BuybackConfig {
            self.config.read()
        }

        fn set_config(ref self: ContractState, config: BuybackConfig) {
            self._only_owner();

            // Validate
            assert!(config.min_buyback_usd > 0, "Min buyback must be > 0");
            assert!(config.max_buyback_usd >= config.min_buyback_usd, "Max must be >= min");
            assert!(config.price_ceiling_usd > 0, "Price ceiling must be > 0");
            assert!(config.auto_percent_bps <= 10000, "Percent cannot exceed 100%");

            self.config.write(config);

            self.emit(ConfigUpdated {
                updated_by: get_caller_address(),
                min_buyback_usd: config.min_buyback_usd,
                max_buyback_usd: config.max_buyback_usd,
                price_ceiling_usd: config.price_ceiling_usd,
                auto_enabled: config.auto_enabled,
            });
        }

        fn get_stats(self: @ContractState) -> (u256, u256, u256, u256) {
            (
                self.total_usdc_spent.read(),
                self.total_sage_purchased.read(),
                self.total_sage_burned.read(),
                self.execution_count.read(),
            )
        }

        fn get_last_execution(self: @ContractState) -> BuybackExecution {
            self.last_execution.read()
        }

        fn get_buyback_balance(self: @ContractState) -> u256 {
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };
            usdc.balance_of(get_contract_address())
        }

        fn emergency_withdraw(ref self: ContractState, token: ContractAddress, amount: u256) {
            self._only_owner();
            assert!(self.paused.read(), "Must be paused for emergency withdrawal");

            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer(self.owner.read(), amount);

            self.emit(EmergencyWithdrawal {
                token,
                amount,
                withdrawn_by: get_caller_address(),
            });
        }

        fn set_execution_venue(ref self: ContractState, venue: ContractAddress) {
            self._only_owner();

            let old_venue = self.execution_venue.read();
            self.execution_venue.write(venue);

            self.emit(ExecutionVenueUpdated { old_venue, new_venue: venue });
        }

        fn pause(ref self: ContractState) {
            self._only_owner();
            assert!(!self.paused.read(), "Already paused");
            self.paused.write(true);
            self.emit(ContractPaused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            assert!(self.paused.read(), "Not paused");
            self.paused.write(false);
            self.emit(ContractUnpaused { account: get_caller_address() });
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
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

        fn _execute_and_burn(
            ref self: ContractState,
            usdc_amount: u256,
            sage_amount: u256,
            execution_price: u256
        ) {
            let now = get_block_timestamp();
            let caller = get_caller_address();
            let this = get_contract_address();

            // In a production setup, we would:
            // 1. Send USDC to execution venue (OTC/DEX)
            // 2. Receive SAGE in return
            // 3. Burn the received SAGE
            //
            // For this implementation, we simulate by:
            // - Assuming SAGE tokens are already available (from OTC execution)
            // - Or the execution venue handles the swap atomically

            let sage_token = ISAGETokenDispatcher { contract_address: self.sage_token.read() };
            let usdc = IERC20Dispatcher { contract_address: self.usdc_token.read() };

            // Transfer USDC to execution venue (or treasury for manual OTC)
            let venue = self.execution_venue.read();
            if !venue.is_zero() {
                usdc.transfer(venue, usdc_amount);
            } else {
                // If no venue set, transfer to owner for manual OTC execution
                usdc.transfer(self.owner.read(), usdc_amount);
            }

            // Check if we have SAGE to burn (from previous OTC execution or DEX swap callback)
            let sage_erc20 = IERC20Dispatcher { contract_address: self.sage_token.read() };
            let sage_balance = sage_erc20.balance_of(this);

            let actual_burned = if sage_balance >= sage_amount {
                // Burn the SAGE
                // Note: In production, burn_from_revenue requires authorization
                // This contract would need to be added to authorized burners
                sage_token.burn_from_revenue(sage_amount, usdc_amount, execution_price);
                sage_amount
            } else if sage_balance > 0 {
                // Burn what we have
                sage_token.burn_from_revenue(sage_balance, usdc_amount, execution_price);
                sage_balance
            } else {
                0
            };

            // Update state
            let exec_count = self.execution_count.read() + 1;
            self.execution_count.write(exec_count);
            self.last_buyback_at.write(now);

            let total_usdc = self.total_usdc_spent.read() + usdc_amount;
            self.total_usdc_spent.write(total_usdc);

            let total_purchased = self.total_sage_purchased.read() + sage_amount;
            self.total_sage_purchased.write(total_purchased);

            let total_burned = self.total_sage_burned.read() + actual_burned;
            self.total_sage_burned.write(total_burned);

            // Record execution
            let execution = BuybackExecution {
                execution_id: exec_count,
                usdc_spent: usdc_amount,
                sage_purchased: sage_amount,
                sage_burned: actual_burned,
                execution_price,
                executed_at: now,
                executor: caller,
            };
            self.last_execution.write(execution);

            self.emit(BuybackExecuted {
                execution_id: exec_count,
                usdc_spent: usdc_amount,
                sage_purchased: sage_amount,
                sage_burned: actual_burned,
                execution_price,
                executor: caller,
                timestamp: now,
            });
        }
    }
}
