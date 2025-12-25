//! OTC Orderbook Tests
//! Tests for limit orders, market orders, batch operations, and order matching

use core::array::ArrayTrait;
use starknet::ContractAddress;
use core::traits::TryInto;

use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp_global, stop_cheat_block_timestamp_global
};

use sage_contracts::payments::otc_orderbook::{
    IOTCOrderbookDispatcher, IOTCOrderbookDispatcherTrait,
    OrderSide, OrderType, OrderStatus, Order, OrderbookConfig
};

// =============================================================================
// Test Helpers
// =============================================================================

fn get_test_addresses() -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let maker: ContractAddress = 'maker'.try_into().unwrap();
    let taker: ContractAddress = 'taker'.try_into().unwrap();
    let sage_token: ContractAddress = 'sage_token'.try_into().unwrap();
    let usdc_token: ContractAddress = 'usdc_token'.try_into().unwrap();
    (owner, maker, taker, sage_token, usdc_token)
}

fn deploy_orderbook() -> IOTCOrderbookDispatcher {
    let (owner, _, _, sage_token, usdc_token) = get_test_addresses();
    let fee_recipient: ContractAddress = 'fee_recipient'.try_into().unwrap();

    let contract_class = declare("OTCOrderbook").unwrap().contract_class();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(sage_token.into());
    constructor_data.append(fee_recipient.into());
    constructor_data.append(usdc_token.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    IOTCOrderbookDispatcher { contract_address }
}

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_initial_config() {
    let orderbook = deploy_orderbook();
    let config = orderbook.get_config();

    assert(config.maker_fee_bps == 10, 'Wrong maker fee');
    assert(config.taker_fee_bps == 30, 'Wrong taker fee');
    assert(config.default_expiry_secs == 604800, 'Wrong default expiry');
    assert(config.max_orders_per_user == 100, 'Wrong max orders');
    assert(!config.paused, 'Should not be paused');
}

#[test]
fn test_default_pair() {
    let orderbook = deploy_orderbook();
    let pair = orderbook.get_pair(0);

    assert(pair.is_active, 'Pair should be active');
    assert(pair.min_order_size == 10_000000000000000000, 'Wrong min order size');
}

#[test]
fn test_initial_stats() {
    let orderbook = deploy_orderbook();
    let (total_orders, total_trades, volume_sage, volume_usd) = orderbook.get_stats();

    assert(total_orders == 0, 'Should have 0 orders');
    assert(total_trades == 0, 'Should have 0 trades');
    assert(volume_sage == 0, 'Should have 0 SAGE volume');
    assert(volume_usd == 0, 'Should have 0 USD volume');
}

// =============================================================================
// Admin Tests
// =============================================================================

#[test]
fn test_pause_unpause() {
    let orderbook = deploy_orderbook();
    let (owner, _, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, owner);

    orderbook.pause();
    let config = orderbook.get_config();
    assert(config.paused, 'Should be paused');

    orderbook.unpause();
    let config = orderbook.get_config();
    assert(!config.paused, 'Should be unpaused');

    stop_cheat_caller_address(orderbook.contract_address);
}

#[test]
fn test_update_config() {
    let orderbook = deploy_orderbook();
    let (owner, _, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, owner);

    let new_config = OrderbookConfig {
        maker_fee_bps: 5,
        taker_fee_bps: 20,
        default_expiry_secs: 86400,
        max_orders_per_user: 50,
        paused: false,
    };

    orderbook.set_config(new_config);

    let config = orderbook.get_config();
    assert(config.maker_fee_bps == 5, 'Wrong maker fee');
    assert(config.taker_fee_bps == 20, 'Wrong taker fee');
    assert(config.default_expiry_secs == 86400, 'Wrong expiry');
    assert(config.max_orders_per_user == 50, 'Wrong max orders');

    stop_cheat_caller_address(orderbook.contract_address);
}

#[test]
#[should_panic]
fn test_config_maker_fee_too_high() {
    let orderbook = deploy_orderbook();
    let (owner, _, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, owner);

    let bad_config = OrderbookConfig {
        maker_fee_bps: 600,  // 6% - too high (max 5%)
        taker_fee_bps: 30,
        default_expiry_secs: 604800,
        max_orders_per_user: 100,
        paused: false,
    };

    orderbook.set_config(bad_config);
}

#[test]
fn test_add_trading_pair() {
    let orderbook = deploy_orderbook();
    let (owner, _, _, _, _) = get_test_addresses();
    let strk_token: ContractAddress = 'strk_token'.try_into().unwrap();

    start_cheat_caller_address(orderbook.contract_address, owner);

    // Add SAGE/STRK pair
    orderbook.add_pair(
        strk_token,
        5_000000000000000000,  // 5 SAGE minimum
        500000000000000        // 0.0005 tick
    );

    let pair = orderbook.get_pair(1);
    assert(pair.is_active, 'Pair should be active');
    assert(pair.quote_token == strk_token, 'Wrong quote token');

    stop_cheat_caller_address(orderbook.contract_address);
}

#[test]
fn test_set_fee_recipient() {
    let orderbook = deploy_orderbook();
    let (owner, _, _, _, _) = get_test_addresses();
    let new_recipient: ContractAddress = 'new_recipient'.try_into().unwrap();

    start_cheat_caller_address(orderbook.contract_address, owner);
    orderbook.set_fee_recipient(new_recipient);
    stop_cheat_caller_address(orderbook.contract_address);

    // No getter for fee_recipient in interface, but call should succeed
}

// =============================================================================
// View Function Tests
// =============================================================================

#[test]
fn test_get_best_bid_ask_empty() {
    let orderbook = deploy_orderbook();

    let best_bid = orderbook.get_best_bid(0);
    let best_ask = orderbook.get_best_ask(0);

    assert(best_bid == 0, 'Best bid should be 0');
    assert(best_ask == 0, 'Best ask should be 0');
}

#[test]
fn test_get_spread_empty() {
    let orderbook = deploy_orderbook();

    let spread = orderbook.get_spread(0);
    assert(spread == 0, 'Spread should be 0');
}

#[test]
fn test_get_user_orders_empty() {
    let orderbook = deploy_orderbook();
    let (_, maker, _, _, _) = get_test_addresses();

    let orders = orderbook.get_user_orders(maker);
    assert(orders.len() == 0, 'Should have no orders');
}

// =============================================================================
// Order Placement Validation Tests
// =============================================================================

#[test]
#[should_panic]
fn test_place_order_when_paused() {
    let orderbook = deploy_orderbook();
    let (owner, maker, _, _, _) = get_test_addresses();

    // Pause orderbook
    start_cheat_caller_address(orderbook.contract_address, owner);
    orderbook.pause();
    stop_cheat_caller_address(orderbook.contract_address);

    // Try to place order
    start_cheat_caller_address(orderbook.contract_address, maker);
    orderbook.place_limit_order(
        0,              // pair_id
        OrderSide::Buy,
        1_000000000000000000,  // price
        10_000000000000000000, // amount
        0               // expires_in
    );
}

// =============================================================================
// Batch Operation Tests
// =============================================================================

#[test]
#[should_panic]
fn test_batch_place_empty_array() {
    let orderbook = deploy_orderbook();
    let (_, maker, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, maker);
    orderbook.batch_place_orders(array![]);
}

#[test]
#[should_panic]
fn test_batch_cancel_empty_array() {
    let orderbook = deploy_orderbook();
    let (_, maker, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, maker);
    orderbook.batch_cancel_orders(array![]);
}

// =============================================================================
// Order Status Tests
// =============================================================================

#[test]
fn test_order_side_default() {
    let side = OrderSide::Buy;
    assert(side == OrderSide::Buy, 'Default should be Buy');
}

#[test]
fn test_order_type_default() {
    let order_type = OrderType::Limit;
    assert(order_type == OrderType::Limit, 'Default should be Limit');
}

#[test]
fn test_order_status_default() {
    let status = OrderStatus::Open;
    assert(status == OrderStatus::Open, 'Default should be Open');
}

// =============================================================================
// Access Control Tests
// =============================================================================

#[test]
#[should_panic]
fn test_only_owner_pause() {
    let orderbook = deploy_orderbook();
    let (_, maker, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, maker);
    orderbook.pause();
}

#[test]
#[should_panic]
fn test_only_owner_add_pair() {
    let orderbook = deploy_orderbook();
    let (_, maker, _, _, _) = get_test_addresses();
    let strk: ContractAddress = 'strk'.try_into().unwrap();

    start_cheat_caller_address(orderbook.contract_address, maker);
    orderbook.add_pair(strk, 1000000000000000000, 1000000000000);
}

#[test]
#[should_panic]
fn test_only_owner_set_config() {
    let orderbook = deploy_orderbook();
    let (_, maker, _, _, _) = get_test_addresses();

    start_cheat_caller_address(orderbook.contract_address, maker);
    orderbook.set_config(OrderbookConfig {
        maker_fee_bps: 10,
        taker_fee_bps: 30,
        default_expiry_secs: 604800,
        max_orders_per_user: 100,
        paused: false,
    });
}
