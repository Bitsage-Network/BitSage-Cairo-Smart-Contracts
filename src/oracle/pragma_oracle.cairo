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
}

/// Oracle config
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct OracleConfig {
    pub pragma_address: ContractAddress,
    pub max_price_age: u64,
    pub min_sources: u32,
    pub use_fallback: bool,
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
}

#[starknet::contract]
mod OracleWrapper {
    use super::{IOracleWrapper, IPragmaOracleDispatcher, IPragmaOracleDispatcherTrait, PragmaPrice, PricePair, OracleConfig};
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, StorageMapReadAccess, StorageMapWriteAccess, Map};

    const PAIR_ETH_USD: felt252 = 'ETH/USD';
    const PAIR_USDC_USD: felt252 = 'USDC/USD';
    const PAIR_STRK_USD: felt252 = 'STRK/USD';
    const PAIR_SAGE_USD: felt252 = 'SAGE/USD';
    const SPOT_MEDIAN: felt252 = 'SPOT';
    const USD_DECIMALS: u256 = 1000000000000000000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        config: OracleConfig,
        fallback_prices: Map<felt252, u128>,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, pragma_address: ContractAddress) {
        self.owner.write(owner);
        let config = OracleConfig {
            pragma_address,
            max_price_age: 3600,
            min_sources: 3,
            use_fallback: true,
        };
        self.config.write(config);
        self.fallback_prices.write(PAIR_ETH_USD, 350000000000);
        self.fallback_prices.write(PAIR_USDC_USD, 100000000);
        self.fallback_prices.write(PAIR_SAGE_USD, 10000000);
    }

    #[abi(embed_v0)]
    impl OracleWrapperImpl of IOracleWrapper<ContractState> {
        fn get_price(self: @ContractState, pair: PricePair) -> PragmaPrice {
            let config = self.config.read();
            let pair_id = self._pair_to_id(pair);
            let pragma = IPragmaOracleDispatcher { contract_address: config.pragma_address };
            let (price, decimals, last_updated, num_sources) = pragma.get_data_median(SPOT_MEDIAN, pair_id);
            let now = get_block_timestamp();
            
            if price > 0 && (now - last_updated) <= config.max_price_age {
                return PragmaPrice { price, decimals, last_updated, num_sources };
            }
            
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
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _pair_to_id(self: @ContractState, pair: PricePair) -> felt252 {
            match pair {
                PricePair::SAGE_USD => PAIR_SAGE_USD,
                PricePair::USDC_USD => PAIR_USDC_USD,
                PricePair::ETH_USD => PAIR_ETH_USD,
                PricePair::STRK_USD => PAIR_STRK_USD,
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
    }
}

