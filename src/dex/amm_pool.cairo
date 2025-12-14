// =============================================================================
// AMM POOL CONTRACT - BitSage Network
// =============================================================================
//
// Automated Market Maker for SAGE/USDC trading:
// - Constant product formula (x * y = k)
// - LP token minting for liquidity providers
// - 0.3% swap fee (configurable)
// - Native USDC support
//
// =============================================================================

use starknet::ContractAddress;

/// Pool configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PoolConfig {
    pub token0: ContractAddress,
    pub token1: ContractAddress,
    pub fee_bps: u16,
    pub protocol_fee_bps: u16,
    pub is_active: bool,
}

/// Pool reserves
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Reserves {
    pub reserve0: u256,
    pub reserve1: u256,
    pub last_update: u64,
}

/// LP position
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct LPPosition {
    pub liquidity: u256,
    pub token0_deposited: u256,
    pub token1_deposited: u256,
    pub entry_time: u64,
}

#[starknet::interface]
pub trait IAMMPool<TContractState> {
    // === Liquidity Functions ===
    fn add_liquidity(
        ref self: TContractState,
        amount0_desired: u256,
        amount1_desired: u256,
        amount0_min: u256,
        amount1_min: u256,
    ) -> (u256, u256, u256);
    
    fn remove_liquidity(
        ref self: TContractState,
        liquidity: u256,
        amount0_min: u256,
        amount1_min: u256,
    ) -> (u256, u256);
    
    // === Swap Functions ===
    fn swap_exact_input(
        ref self: TContractState,
        amount_in: u256,
        amount_out_min: u256,
        token_in: ContractAddress,
    ) -> u256;
    
    fn swap_exact_output(
        ref self: TContractState,
        amount_out: u256,
        amount_in_max: u256,
        token_out: ContractAddress,
    ) -> u256;
    
    // === View Functions ===
    fn get_reserves(self: @TContractState) -> Reserves;
    fn get_amount_out(self: @TContractState, amount_in: u256, token_in: ContractAddress) -> u256;
    fn get_amount_in(self: @TContractState, amount_out: u256, token_out: ContractAddress) -> u256;
    fn get_lp_balance(self: @TContractState, account: ContractAddress) -> u256;
    fn get_position(self: @TContractState, account: ContractAddress) -> LPPosition;
    fn get_config(self: @TContractState) -> PoolConfig;
    fn get_price(self: @TContractState, token: ContractAddress) -> u256;
    fn total_supply(self: @TContractState) -> u256;
    
    // === Admin ===
    fn set_fee(ref self: TContractState, fee_bps: u16);
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn withdraw_protocol_fees(ref self: TContractState, to: ContractAddress);
}

#[starknet::contract]
mod AMMPool {
    use super::{IAMMPool, PoolConfig, Reserves, LPPosition};
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess, StorageMapReadAccess, StorageMapWriteAccess, Map};
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    const MINIMUM_LIQUIDITY: u256 = 1000;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        config: PoolConfig,
        reserves: Reserves,
        total_lp_supply: u256,
        lp_balances: Map<ContractAddress, u256>,
        positions: Map<ContractAddress, LPPosition>,
        protocol_fees0: u256,
        protocol_fees1: u256,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        LiquidityAdded: LiquidityAdded,
        LiquidityRemoved: LiquidityRemoved,
        Swap: Swap,
        Sync: Sync,
    }

    #[derive(Drop, starknet::Event)]
    struct LiquidityAdded {
        #[key]
        provider: ContractAddress,
        amount0: u256,
        amount1: u256,
        liquidity: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct LiquidityRemoved {
        #[key]
        provider: ContractAddress,
        amount0: u256,
        amount1: u256,
        liquidity: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Swap {
        #[key]
        sender: ContractAddress,
        amount0_in: u256,
        amount1_in: u256,
        amount0_out: u256,
        amount1_out: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct Sync {
        reserve0: u256,
        reserve1: u256,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        token0: ContractAddress,
        token1: ContractAddress,
        fee_bps: u16,
    ) {
        self.owner.write(owner);
        let config = PoolConfig {
            token0,
            token1,
            fee_bps,
            protocol_fee_bps: 5, // 0.05% protocol fee
            is_active: true,
        };
        self.config.write(config);
        self.reserves.write(Reserves { reserve0: 0, reserve1: 0, last_update: 0 });
        self.total_lp_supply.write(0);
    }

    #[abi(embed_v0)]
    impl AMMPoolImpl of IAMMPool<ContractState> {
        fn add_liquidity(
            ref self: ContractState,
            amount0_desired: u256,
            amount1_desired: u256,
            amount0_min: u256,
            amount1_min: u256,
        ) -> (u256, u256, u256) {
            let config = self.config.read();
            assert(config.is_active, 'Pool paused');
            
            let caller = get_caller_address();
            let reserves = self.reserves.read();
            let total_supply = self.total_lp_supply.read();
            
            let (amount0, amount1) = if reserves.reserve0 == 0 && reserves.reserve1 == 0 {
                (amount0_desired, amount1_desired)
            } else {
                let amount1_optimal = (amount0_desired * reserves.reserve1) / reserves.reserve0;
                if amount1_optimal <= amount1_desired {
                    assert(amount1_optimal >= amount1_min, 'Insufficient amount1');
                    (amount0_desired, amount1_optimal)
                } else {
                    let amount0_optimal = (amount1_desired * reserves.reserve0) / reserves.reserve1;
                    assert(amount0_optimal <= amount0_desired, 'Excessive amount0');
                    assert(amount0_optimal >= amount0_min, 'Insufficient amount0');
                    (amount0_optimal, amount1_desired)
                }
            };
            
            // Transfer tokens
            let token0 = IERC20Dispatcher { contract_address: config.token0 };
            let token1 = IERC20Dispatcher { contract_address: config.token1 };
            token0.transfer_from(caller, starknet::get_contract_address(), amount0);
            token1.transfer_from(caller, starknet::get_contract_address(), amount1);
            
            // Calculate liquidity
            let liquidity: u256 = if total_supply == 0 {
                // Use Newton-Raphson approximation for sqrt
                let product = amount0 * amount1;
                let liq: u256 = self._sqrt(product);
                assert(liq > MINIMUM_LIQUIDITY, 'Insufficient initial liquidity');
                liq - MINIMUM_LIQUIDITY
            } else {
                let liq0 = (amount0 * total_supply) / reserves.reserve0;
                let liq1 = (amount1 * total_supply) / reserves.reserve1;
                if liq0 < liq1 { liq0 } else { liq1 }
            };
            
            assert(liquidity > 0, 'Insufficient liquidity minted');
            
            // Mint LP tokens
            let lp_balance = self.lp_balances.read(caller);
            self.lp_balances.write(caller, lp_balance + liquidity);
            self.total_lp_supply.write(total_supply + liquidity);
            
            // Update position
            let mut position = self.positions.read(caller);
            position.liquidity = position.liquidity + liquidity;
            position.token0_deposited = position.token0_deposited + amount0;
            position.token1_deposited = position.token1_deposited + amount1;
            position.entry_time = get_block_timestamp();
            self.positions.write(caller, position);
            
            // Update reserves
            self._update_reserves(reserves.reserve0 + amount0, reserves.reserve1 + amount1);
            
            self.emit(LiquidityAdded { provider: caller, amount0, amount1, liquidity });
            
            (amount0, amount1, liquidity)
        }

        fn remove_liquidity(
            ref self: ContractState,
            liquidity: u256,
            amount0_min: u256,
            amount1_min: u256,
        ) -> (u256, u256) {
            let config = self.config.read();
            let caller = get_caller_address();
            
            let lp_balance = self.lp_balances.read(caller);
            assert(lp_balance >= liquidity, 'Insufficient LP balance');
            
            let total_supply = self.total_lp_supply.read();
            let reserves = self.reserves.read();
            
            let amount0 = (liquidity * reserves.reserve0) / total_supply;
            let amount1 = (liquidity * reserves.reserve1) / total_supply;
            
            assert(amount0 >= amount0_min, 'Insufficient amount0');
            assert(amount1 >= amount1_min, 'Insufficient amount1');
            
            // Burn LP tokens
            self.lp_balances.write(caller, lp_balance - liquidity);
            self.total_lp_supply.write(total_supply - liquidity);
            
            // Update position
            let mut position = self.positions.read(caller);
            position.liquidity = position.liquidity - liquidity;
            self.positions.write(caller, position);
            
            // Transfer tokens
            let token0 = IERC20Dispatcher { contract_address: config.token0 };
            let token1 = IERC20Dispatcher { contract_address: config.token1 };
            token0.transfer(caller, amount0);
            token1.transfer(caller, amount1);
            
            // Update reserves
            self._update_reserves(reserves.reserve0 - amount0, reserves.reserve1 - amount1);
            
            self.emit(LiquidityRemoved { provider: caller, amount0, amount1, liquidity });
            
            (amount0, amount1)
        }

        fn swap_exact_input(
            ref self: ContractState,
            amount_in: u256,
            amount_out_min: u256,
            token_in: ContractAddress,
        ) -> u256 {
            let config = self.config.read();
            assert(config.is_active, 'Pool paused');
            
            let caller = get_caller_address();
            let reserves = self.reserves.read();
            
            let (reserve_in, reserve_out, is_token0) = if token_in == config.token0 {
                (reserves.reserve0, reserves.reserve1, true)
            } else {
                assert(token_in == config.token1, 'Invalid token');
                (reserves.reserve1, reserves.reserve0, false)
            };
            
            // Calculate output with fee
            let amount_in_with_fee = amount_in * (10000 - config.fee_bps.into());
            let numerator = amount_in_with_fee * reserve_out;
            let denominator = (reserve_in * 10000) + amount_in_with_fee;
            let amount_out = numerator / denominator;
            
            assert(amount_out >= amount_out_min, 'Insufficient output');
            assert(amount_out < reserve_out, 'Insufficient liquidity');
            
            // Transfer tokens
            let token_in_contract = IERC20Dispatcher { contract_address: token_in };
            let token_out_addr = if is_token0 { config.token1 } else { config.token0 };
            let token_out_contract = IERC20Dispatcher { contract_address: token_out_addr };
            
            token_in_contract.transfer_from(caller, starknet::get_contract_address(), amount_in);
            token_out_contract.transfer(caller, amount_out);
            
            // Update reserves
            let (new_reserve0, new_reserve1) = if is_token0 {
                (reserve_in + amount_in, reserve_out - amount_out)
            } else {
                (reserve_out - amount_out, reserve_in + amount_in)
            };
            self._update_reserves(new_reserve0, new_reserve1);
            
            // Emit event
            if is_token0 {
                self.emit(Swap { sender: caller, amount0_in: amount_in, amount1_in: 0, amount0_out: 0, amount1_out: amount_out });
            } else {
                self.emit(Swap { sender: caller, amount0_in: 0, amount1_in: amount_in, amount0_out: amount_out, amount1_out: 0 });
            }
            
            amount_out
        }

        fn swap_exact_output(
            ref self: ContractState,
            amount_out: u256,
            amount_in_max: u256,
            token_out: ContractAddress,
        ) -> u256 {
            let config = self.config.read();
            assert(config.is_active, 'Pool paused');
            
            let caller = get_caller_address();
            let reserves = self.reserves.read();
            
            let (reserve_in, reserve_out, is_token0_out) = if token_out == config.token0 {
                (reserves.reserve1, reserves.reserve0, true)
            } else {
                assert(token_out == config.token1, 'Invalid token');
                (reserves.reserve0, reserves.reserve1, false)
            };
            
            assert(amount_out < reserve_out, 'Insufficient liquidity');
            
            // Calculate input with fee
            let numerator = reserve_in * amount_out * 10000;
            let denominator = (reserve_out - amount_out) * (10000 - config.fee_bps.into());
            let amount_in = (numerator / denominator) + 1;
            
            assert(amount_in <= amount_in_max, 'Excessive input');
            
            // Transfer tokens
            let token_in_addr = if is_token0_out { config.token1 } else { config.token0 };
            let token_in_contract = IERC20Dispatcher { contract_address: token_in_addr };
            let token_out_contract = IERC20Dispatcher { contract_address: token_out };
            
            token_in_contract.transfer_from(caller, starknet::get_contract_address(), amount_in);
            token_out_contract.transfer(caller, amount_out);
            
            // Update reserves
            let (new_reserve0, new_reserve1) = if is_token0_out {
                (reserve_out - amount_out, reserve_in + amount_in)
            } else {
                (reserve_in + amount_in, reserve_out - amount_out)
            };
            self._update_reserves(new_reserve0, new_reserve1);
            
            amount_in
        }

        fn get_reserves(self: @ContractState) -> Reserves {
            self.reserves.read()
        }

        fn get_amount_out(self: @ContractState, amount_in: u256, token_in: ContractAddress) -> u256 {
            let config = self.config.read();
            let reserves = self.reserves.read();
            
            let (reserve_in, reserve_out) = if token_in == config.token0 {
                (reserves.reserve0, reserves.reserve1)
            } else {
                (reserves.reserve1, reserves.reserve0)
            };
            
            let amount_in_with_fee = amount_in * (10000 - config.fee_bps.into());
            let numerator = amount_in_with_fee * reserve_out;
            let denominator = (reserve_in * 10000) + amount_in_with_fee;
            numerator / denominator
        }

        fn get_amount_in(self: @ContractState, amount_out: u256, token_out: ContractAddress) -> u256 {
            let config = self.config.read();
            let reserves = self.reserves.read();
            
            let (reserve_in, reserve_out) = if token_out == config.token0 {
                (reserves.reserve1, reserves.reserve0)
            } else {
                (reserves.reserve0, reserves.reserve1)
            };
            
            let numerator = reserve_in * amount_out * 10000;
            let denominator = (reserve_out - amount_out) * (10000 - config.fee_bps.into());
            (numerator / denominator) + 1
        }

        fn get_lp_balance(self: @ContractState, account: ContractAddress) -> u256 {
            self.lp_balances.read(account)
        }

        fn get_position(self: @ContractState, account: ContractAddress) -> LPPosition {
            self.positions.read(account)
        }

        fn get_config(self: @ContractState) -> PoolConfig {
            self.config.read()
        }

        fn get_price(self: @ContractState, token: ContractAddress) -> u256 {
            let config = self.config.read();
            let reserves = self.reserves.read();
            
            if reserves.reserve0 == 0 || reserves.reserve1 == 0 {
                return 0;
            }
            
            if token == config.token0 {
                (reserves.reserve1 * 1000000000000000000) / reserves.reserve0
            } else {
                (reserves.reserve0 * 1000000000000000000) / reserves.reserve1
            }
        }

        fn total_supply(self: @ContractState) -> u256 {
            self.total_lp_supply.read()
        }

        fn set_fee(ref self: ContractState, fee_bps: u16) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            assert(fee_bps <= 1000, 'Fee too high');
            let mut config = self.config.read();
            config.fee_bps = fee_bps;
            self.config.write(config);
        }

        fn pause(ref self: ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            let mut config = self.config.read();
            config.is_active = false;
            self.config.write(config);
        }

        fn unpause(ref self: ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            let mut config = self.config.read();
            config.is_active = true;
            self.config.write(config);
        }

        fn withdraw_protocol_fees(ref self: ContractState, to: ContractAddress) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
            let config = self.config.read();
            
            let fees0 = self.protocol_fees0.read();
            let fees1 = self.protocol_fees1.read();
            
            if fees0 > 0 {
                self.protocol_fees0.write(0);
                let token0 = IERC20Dispatcher { contract_address: config.token0 };
                token0.transfer(to, fees0);
            }
            
            if fees1 > 0 {
                self.protocol_fees1.write(0);
                let token1 = IERC20Dispatcher { contract_address: config.token1 };
                token1.transfer(to, fees1);
            }
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _update_reserves(ref self: ContractState, reserve0: u256, reserve1: u256) {
            self.reserves.write(Reserves {
                reserve0,
                reserve1,
                last_update: get_block_timestamp(),
            });
            self.emit(Sync { reserve0, reserve1 });
        }

        /// Integer square root using Newton-Raphson method
        fn _sqrt(self: @ContractState, x: u256) -> u256 {
            if x == 0 {
                return 0;
            }
            
            let mut z = (x + 1) / 2;
            let mut y = x;
            
            // Newton-Raphson iterations
            loop {
                if z >= y {
                    break;
                }
                y = z;
                z = (x / z + z) / 2;
            };
            
            y
        }
    }
}

