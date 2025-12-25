// =============================================================================
// PRAGMA ORACLE INTEGRATION - BitSage Network
// =============================================================================
//
// Integration with Pragma Oracle for price feeds
//
// =============================================================================

use starknet::ContractAddress;

/// Price data from Pragma
#[derive(Copy, Drop, Serde)]
pub struct PragmaPrice {
    pub price: u128,
    pub decimals: u32,
    pub last_updated: u64,
    pub num_sources: u32,
}

/// Supported price pairs
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum PricePair {
    SAGE_USD,
    USDC_USD,
    ETH_USD,
    STRK_USD,
    BTC_USD,
}

/// Oracle config
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct OracleConfig {
    pub pragma_address: ContractAddress,
    pub max_price_age: u64,
    pub min_sources: u32,
    pub use_fallback: bool,
}

/// Phase 3: Circuit breaker config
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CircuitBreakerConfig {
    /// Maximum allowed price change in basis points (e.g., 2000 = 20%)
    pub max_deviation_bps: u16,
    /// Time window for deviation check in seconds
    pub deviation_window: u64,
    /// Whether circuit breaker is enabled
    pub enabled: bool,
    /// Whether circuit breaker is currently tripped
    pub tripped: bool,
    /// Timestamp when circuit breaker was tripped
    pub tripped_at: u64,
}

#[starknet::interface]
pub trait IPragmaOracle<TContractState> {
    fn get_data_median(self: @TContractState, data_type: felt252, pair_id: felt252) -> (u128, u32, u64, u32);
}

#[starknet::interface]
pub trait IOracleWrapper<TContractState> {
    fn get_price(self: @TContractState, pair: PricePair) -> PragmaPrice;
    fn get_price_usd(self: @TContractState, pair: PricePair) -> u256;
    fn get_sage_price(self: @TContractState) -> u256;
    fn set_pragma_address(ref self: TContractState, address: ContractAddress);
    fn set_fallback_price(ref self: TContractState, pair: PricePair, price: u128);
    fn get_config(self: @TContractState) -> OracleConfig;

    // Phase 3: Circuit breaker functions
    fn get_circuit_breaker_config(self: @TContractState) -> CircuitBreakerConfig;
    fn set_circuit_breaker_config(ref self: TContractState, config: CircuitBreakerConfig);
    fn reset_circuit_breaker(ref self: TContractState);
    fn is_circuit_breaker_tripped(self: @TContractState) -> bool;
}

#[starknet::contract]
mod OracleWrapper {
    use super::{IOracleWrapper, IPragmaOracleDispatcher, IPragmaOracleDispatcherTrait, PragmaPrice, PricePair, OracleConfig, CircuitBreakerConfig};
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, StorageMapReadAccess, StorageMapWriteAccess, Map};
    use core::num::traits::Zero;

    const PAIR_ETH_USD: felt252 = 'ETH/USD';
    const PAIR_USDC_USD: felt252 = 'USDC/USD';
    const PAIR_STRK_USD: felt252 = 'STRK/USD';
    const PAIR_SAGE_USD: felt252 = 'SAGE/USD';
    const PAIR_BTC_USD: felt252 = 'BTC/USD';
    const SPOT_MEDIAN: felt252 = 'SPOT';
    const USD_DECIMALS: u256 = 1000000000000000000;
    const BPS_DENOMINATOR: u256 = 10000;

    // SECURITY: Minimum time before circuit breaker can be manually reset
    // Prevents manipulation during legitimate price volatility
    const MIN_CIRCUIT_BREAKER_RESET_DELAY: u64 = 3600; // 1 hour

    #[storage]
    struct Storage {
        owner: ContractAddress,
        config: OracleConfig,
        fallback_prices: Map<felt252, u128>,
        // Phase 3: Circuit breaker storage
        circuit_breaker: CircuitBreakerConfig,
        last_prices: Map<felt252, u128>,      // pair_id -> last known price
        last_price_times: Map<felt252, u64>,  // pair_id -> timestamp of last price
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        CircuitBreakerTripped: CircuitBreakerTripped,
        CircuitBreakerReset: CircuitBreakerReset,
        PriceUpdated: PriceUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct CircuitBreakerTripped {
        #[key]
        pair_id: felt252,
        old_price: u128,
        new_price: u128,
        deviation_bps: u256,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct CircuitBreakerReset {
        reset_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct PriceUpdated {
        #[key]
        pair_id: felt252,
        price: u128,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, pragma_address: ContractAddress) {
        // Phase 3: Validate constructor parameters
        assert!(!owner.is_zero(), "Invalid owner address");

        self.owner.write(owner);
        let config = OracleConfig {
            pragma_address,
            max_price_age: 3600,    // 1 hour
            min_sources: 3,
            use_fallback: true,
        };
        self.config.write(config);

        // Phase 3: Initialize circuit breaker
        let cb_config = CircuitBreakerConfig {
            max_deviation_bps: 2000,  // 20% max deviation
            deviation_window: 300,    // 5 minute window
            enabled: true,
            tripped: false,
            tripped_at: 0,
        };
        self.circuit_breaker.write(cb_config);

        // Phase 3: Realistic fallback prices (8 decimals)
        // ETH: ~$3,500 = 350000000000 (3500 * 10^8) ✓
        self.fallback_prices.write(PAIR_ETH_USD, 350000000000);
        // USDC: $1.00 = 100000000 (1 * 10^8) ✓
        self.fallback_prices.write(PAIR_USDC_USD, 100000000);
        // STRK: ~$0.50 = 50000000 (0.5 * 10^8)
        self.fallback_prices.write(PAIR_STRK_USD, 50000000);
        // BTC: ~$100,000 = 10000000000000 (100000 * 10^8)
        self.fallback_prices.write(PAIR_BTC_USD, 10000000000000);
        // SAGE: $0.10 launch price = 10000000 (0.10 * 10^8)
        self.fallback_prices.write(PAIR_SAGE_USD, 10000000);
    }

    #[abi(embed_v0)]
    impl OracleWrapperImpl of IOracleWrapper<ContractState> {
        fn get_price(self: @ContractState, pair: PricePair) -> PragmaPrice {
            let config = self.config.read();
            let cb_config = self.circuit_breaker.read();
            let pair_id = self._pair_to_id(pair);
            let now = get_block_timestamp();

            // Phase 3: Check if circuit breaker is tripped
            if cb_config.tripped {
                // Return fallback price when circuit breaker is tripped
                if config.use_fallback {
                    let fallback = self.fallback_prices.read(pair_id);
                    return PragmaPrice { price: fallback, decimals: 8, last_updated: now, num_sources: 0 };
                }
                return PragmaPrice { price: 0, decimals: 8, last_updated: 0, num_sources: 0 };
            }

            let pragma = IPragmaOracleDispatcher { contract_address: config.pragma_address };
            let (price, decimals, last_updated, num_sources) = pragma.get_data_median(SPOT_MEDIAN, pair_id);

            // Check price freshness
            if price > 0 && (now - last_updated) <= config.max_price_age {
                // Phase 3: Check minimum sources
                if num_sources >= config.min_sources {
                    return PragmaPrice { price, decimals, last_updated, num_sources };
                }
            }

            // Use fallback if available
            if config.use_fallback {
                let fallback = self.fallback_prices.read(pair_id);
                return PragmaPrice { price: fallback, decimals: 8, last_updated: now, num_sources: 0 };
            }

            PragmaPrice { price: 0, decimals: 8, last_updated: 0, num_sources: 0 }
        }

        fn get_price_usd(self: @ContractState, pair: PricePair) -> u256 {
            let price_data = self.get_price(pair);
            if price_data.price == 0 { return 0; }
            let price_u256: u256 = price_data.price.into();
            let decimals_u256: u256 = self._pow10(price_data.decimals);
            (price_u256 * USD_DECIMALS) / decimals_u256
        }

        fn get_sage_price(self: @ContractState) -> u256 {
            self.get_price_usd(PricePair::SAGE_USD)
        }

        fn set_pragma_address(ref self: ContractState, address: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            let mut config = self.config.read();
            config.pragma_address = address;
            self.config.write(config);
        }

        fn set_fallback_price(ref self: ContractState, pair: PricePair, price: u128) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            let pair_id = self._pair_to_id(pair);
            self.fallback_prices.write(pair_id, price);
        }

        fn get_config(self: @ContractState) -> OracleConfig {
            self.config.read()
        }

        // Phase 3: Circuit breaker functions
        fn get_circuit_breaker_config(self: @ContractState) -> CircuitBreakerConfig {
            self.circuit_breaker.read()
        }

        fn set_circuit_breaker_config(ref self: ContractState, config: CircuitBreakerConfig) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            self.circuit_breaker.write(config);
        }

        fn reset_circuit_breaker(ref self: ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');

            let cb_config = self.circuit_breaker.read();

            // SECURITY: Require minimum time elapsed before manual reset
            // Prevents manipulation during legitimate price volatility
            if cb_config.tripped {
                let now = get_block_timestamp();
                let time_since_trip = now - cb_config.tripped_at;
                assert!(
                    time_since_trip >= MIN_CIRCUIT_BREAKER_RESET_DELAY,
                    "Circuit breaker reset delay not met (1 hour)"
                );
            }

            let mut new_cb_config = cb_config;
            new_cb_config.tripped = false;
            new_cb_config.tripped_at = 0;
            self.circuit_breaker.write(new_cb_config);

            self.emit(CircuitBreakerReset {
                reset_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        fn is_circuit_breaker_tripped(self: @ContractState) -> bool {
            self.circuit_breaker.read().tripped
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _pair_to_id(self: @ContractState, pair: PricePair) -> felt252 {
            match pair {
                PricePair::SAGE_USD => PAIR_SAGE_USD,
                PricePair::USDC_USD => PAIR_USDC_USD,
                PricePair::ETH_USD => PAIR_ETH_USD,
                PricePair::STRK_USD => PAIR_STRK_USD,
                PricePair::BTC_USD => PAIR_BTC_USD,
            }
        }

        fn _pow10(self: @ContractState, exp: u32) -> u256 {
            let mut result: u256 = 1;
            let mut i: u32 = 0;
            loop {
                if i >= exp { break; }
                result = result * 10;
                i += 1;
            };
            result
        }

        /// Phase 3: Check if price deviation exceeds threshold and trip circuit breaker if needed
        fn _check_price_deviation(
            ref self: ContractState,
            pair_id: felt252,
            new_price: u128
        ) -> bool {
            let cb_config = self.circuit_breaker.read();

            // Skip if circuit breaker disabled or already tripped
            if !cb_config.enabled || cb_config.tripped {
                return false;
            }

            let last_price = self.last_prices.read(pair_id);
            let last_time = self.last_price_times.read(pair_id);
            let now = get_block_timestamp();

            // Skip deviation check if no previous price or outside time window
            if last_price == 0 || (now - last_time) > cb_config.deviation_window {
                // Update last price and return false (no trip)
                self.last_prices.write(pair_id, new_price);
                self.last_price_times.write(pair_id, now);
                return false;
            }

            // Calculate deviation in basis points
            let new_price_u256: u256 = new_price.into();
            let last_price_u256: u256 = last_price.into();

            let deviation_bps = if new_price_u256 > last_price_u256 {
                // Price increased
                ((new_price_u256 - last_price_u256) * BPS_DENOMINATOR) / last_price_u256
            } else {
                // Price decreased
                ((last_price_u256 - new_price_u256) * BPS_DENOMINATOR) / last_price_u256
            };

            // Check if deviation exceeds threshold
            if deviation_bps > cb_config.max_deviation_bps.into() {
                // Trip circuit breaker
                let mut updated_cb = cb_config;
                updated_cb.tripped = true;
                updated_cb.tripped_at = now;
                self.circuit_breaker.write(updated_cb);

                // Emit event
                self.emit(CircuitBreakerTripped {
                    pair_id,
                    old_price: last_price,
                    new_price,
                    deviation_bps,
                    timestamp: now,
                });

                return true;
            }

            // Update last price
            self.last_prices.write(pair_id, new_price);
            self.last_price_times.write(pair_id, now);

            // Emit price update event
            self.emit(PriceUpdated {
                pair_id,
                price: new_price,
                timestamp: now,
            });

            false
        }
    }
}

