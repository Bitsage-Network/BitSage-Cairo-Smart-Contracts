// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Shielded Swap Router Tests
// Tests for privacy-preserving token swaps via Ekubo AMM integration.
// Covers:
// - Struct serialization and deserialization
// - Slippage protection logic
// - Withdrawal recipient validation
// - Pool registry management
// - Swap count tracking

use core::array::ArrayTrait;
use core::traits::TryInto;
use core::option::OptionTrait;
use core::serde::Serde;
use core::num::traits::Zero;
use starknet::ContractAddress;
use starknet::contract_address_const;

// Import ShieldedSwapRouter types
use sage_contracts::obelysk::shielded_swap_router::{
    ShieldedSwapRequest, PoolKey, SwapParameters, i129, Delta,
    ShieldedSwapExecuted, PoolRegistered,
    IShieldedSwapRouterDispatcher, IShieldedSwapRouterDispatcherTrait,
};

// Import Privacy Pools types used in withdrawal proof
use sage_contracts::obelysk::privacy_pools::PPWithdrawalProof;
use sage_contracts::obelysk::lean_imt::{LeanIMTState, LeanIMTProof};
use sage_contracts::obelysk::elgamal::{ECPoint, ec_zero};

// snforge test utilities
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
};

// =============================================================================
// Test Constants
// =============================================================================

const TEST_OWNER: felt252 = 0x1234;
const TEST_EKUBO_CORE: felt252 = 0x5678;
const TEST_TOKEN_A: felt252 = 0xAAAA;
const TEST_TOKEN_B: felt252 = 0xBBBB;
const TEST_POOL_A: felt252 = 0xCCCC;
const TEST_POOL_B: felt252 = 0xDDDD;

// =============================================================================
// Helper Functions
// =============================================================================

fn owner_address() -> ContractAddress {
    contract_address_const::<TEST_OWNER>()
}

fn ekubo_core_address() -> ContractAddress {
    contract_address_const::<TEST_EKUBO_CORE>()
}

fn token_a_address() -> ContractAddress {
    contract_address_const::<TEST_TOKEN_A>()
}

fn token_b_address() -> ContractAddress {
    contract_address_const::<TEST_TOKEN_B>()
}

fn pool_a_address() -> ContractAddress {
    contract_address_const::<TEST_POOL_A>()
}

fn pool_b_address() -> ContractAddress {
    contract_address_const::<TEST_POOL_B>()
}

fn deploy_router() -> IShieldedSwapRouterDispatcher {
    let contract = declare("ShieldedSwapRouter").unwrap().contract_class();
    let mut constructor_calldata = ArrayTrait::new();
    owner_address().serialize(ref constructor_calldata);
    ekubo_core_address().serialize(ref constructor_calldata);

    let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    IShieldedSwapRouterDispatcher { contract_address }
}

// =============================================================================
// Ekubo Type Tests
// =============================================================================

#[test]
fn test_i129_positive() {
    let val = i129 { mag: 1000, sign: false };
    assert!(val.mag == 1000, "Magnitude should be 1000");
    assert!(!val.sign, "Sign should be positive (false)");
}

#[test]
fn test_i129_negative() {
    let val = i129 { mag: 500, sign: true };
    assert!(val.mag == 500, "Magnitude should be 500");
    assert!(val.sign, "Sign should be negative (true)");
}

#[test]
fn test_pool_key_serialization() {
    let pool_key = PoolKey {
        token0: token_a_address(),
        token1: token_b_address(),
        fee: 3000,
        tick_spacing: 60,
        extension: contract_address_const::<0>(),
    };

    let mut output = ArrayTrait::new();
    pool_key.serialize(ref output);
    assert!(output.len() > 0, "PoolKey should serialize to non-empty array");
}

#[test]
fn test_swap_parameters_serialization() {
    let params = SwapParameters {
        amount: i129 { mag: 1000000, sign: false },
        is_token1: true,
        sqrt_ratio_limit: 0,
        skip_ahead: 0,
    };

    let mut output = ArrayTrait::new();
    params.serialize(ref output);
    assert!(output.len() > 0, "SwapParameters should serialize");
}

#[test]
fn test_delta_construction() {
    let delta = Delta {
        amount0: i129 { mag: 1000, sign: false },  // Owe 1000 token0
        amount1: i129 { mag: 999, sign: true },     // Receive 999 token1
    };
    assert!(delta.amount0.mag == 1000, "Amount0 should be 1000");
    assert!(!delta.amount0.sign, "Amount0 should be positive (owed)");
    assert!(delta.amount1.mag == 999, "Amount1 should be 999");
    assert!(delta.amount1.sign, "Amount1 should be negative (received)");
}

// =============================================================================
// Router Deployment Tests
// =============================================================================

#[test]
fn test_deploy_router() {
    let router = deploy_router();
    assert!(router.get_swap_count() == 0, "Initial swap count should be 0");
    assert!(router.get_ekubo_core() == ekubo_core_address(), "Ekubo core should match");
}

#[test]
#[should_panic(expected: "Owner cannot be zero")]
fn test_deploy_router_zero_owner() {
    let contract = declare("ShieldedSwapRouter").unwrap().contract_class();
    let mut calldata = ArrayTrait::new();
    contract_address_const::<0>().serialize(ref calldata); // Zero owner
    ekubo_core_address().serialize(ref calldata);
    contract.deploy(@calldata).unwrap();
}

#[test]
#[should_panic(expected: "Ekubo Core cannot be zero")]
fn test_deploy_router_zero_core() {
    let contract = declare("ShieldedSwapRouter").unwrap().contract_class();
    let mut calldata = ArrayTrait::new();
    owner_address().serialize(ref calldata);
    contract_address_const::<0>().serialize(ref calldata); // Zero core
    contract.deploy(@calldata).unwrap();
}

// =============================================================================
// Pool Registry Tests
// =============================================================================

#[test]
fn test_register_pool() {
    let router = deploy_router();

    // Register as owner
    start_cheat_caller_address(router.contract_address, owner_address());
    router.register_pool(token_a_address(), pool_a_address());
    stop_cheat_caller_address(router.contract_address);

    let pool = router.get_pool(token_a_address());
    assert!(pool == pool_a_address(), "Pool A should be registered for token A");
}

#[test]
fn test_register_multiple_pools() {
    let router = deploy_router();

    start_cheat_caller_address(router.contract_address, owner_address());
    router.register_pool(token_a_address(), pool_a_address());
    router.register_pool(token_b_address(), pool_b_address());
    stop_cheat_caller_address(router.contract_address);

    assert!(router.get_pool(token_a_address()) == pool_a_address(), "Pool A mismatch");
    assert!(router.get_pool(token_b_address()) == pool_b_address(), "Pool B mismatch");
}

#[test]
fn test_register_pool_overwrite() {
    let router = deploy_router();
    let new_pool = contract_address_const::<0xEEEE>();

    start_cheat_caller_address(router.contract_address, owner_address());
    router.register_pool(token_a_address(), pool_a_address());
    router.register_pool(token_a_address(), new_pool); // Overwrite
    stop_cheat_caller_address(router.contract_address);

    assert!(router.get_pool(token_a_address()) == new_pool, "Pool should be overwritten");
}

#[test]
#[should_panic(expected: "Caller is not owner")]
fn test_register_pool_not_owner() {
    let router = deploy_router();
    let non_owner = contract_address_const::<0x9999>();

    start_cheat_caller_address(router.contract_address, non_owner);
    router.register_pool(token_a_address(), pool_a_address());
    stop_cheat_caller_address(router.contract_address);
}

#[test]
#[should_panic(expected: "Token address cannot be zero")]
fn test_register_pool_zero_token() {
    let router = deploy_router();

    start_cheat_caller_address(router.contract_address, owner_address());
    router.register_pool(contract_address_const::<0>(), pool_a_address());
    stop_cheat_caller_address(router.contract_address);
}

#[test]
#[should_panic(expected: "Pool address cannot be zero")]
fn test_register_pool_zero_pool() {
    let router = deploy_router();

    start_cheat_caller_address(router.contract_address, owner_address());
    router.register_pool(token_a_address(), contract_address_const::<0>());
    stop_cheat_caller_address(router.contract_address);
}

// =============================================================================
// Admin Tests
// =============================================================================

#[test]
fn test_set_ekubo_core() {
    let router = deploy_router();
    let new_core = contract_address_const::<0xF00D>();

    start_cheat_caller_address(router.contract_address, owner_address());
    router.set_ekubo_core(new_core);
    stop_cheat_caller_address(router.contract_address);

    assert!(router.get_ekubo_core() == new_core, "Ekubo core should be updated");
}

#[test]
#[should_panic(expected: "Caller is not owner")]
fn test_set_ekubo_core_not_owner() {
    let router = deploy_router();
    let non_owner = contract_address_const::<0x9999>();

    start_cheat_caller_address(router.contract_address, non_owner);
    router.set_ekubo_core(contract_address_const::<0xF00D>());
    stop_cheat_caller_address(router.contract_address);
}

#[test]
#[should_panic(expected: "Core address cannot be zero")]
fn test_set_ekubo_core_zero() {
    let router = deploy_router();

    start_cheat_caller_address(router.contract_address, owner_address());
    router.set_ekubo_core(contract_address_const::<0>());
    stop_cheat_caller_address(router.contract_address);
}

// =============================================================================
// View Function Tests
// =============================================================================

#[test]
fn test_get_pool_unregistered() {
    let router = deploy_router();
    let pool = router.get_pool(token_a_address());
    assert!(pool.is_zero(), "Unregistered token should return zero address");
}

#[test]
fn test_get_swap_count_initial() {
    let router = deploy_router();
    assert!(router.get_swap_count() == 0, "Initial swap count should be 0");
}

// =============================================================================
// Shielded Swap Validation Tests
// These test the entry-point validation without full Ekubo integration.
// Full integration requires mock Ekubo Core and Privacy Pool contracts.
// =============================================================================

fn build_test_withdrawal_proof(recipient: ContractAddress) -> PPWithdrawalProof {
    PPWithdrawalProof {
        global_tree_proof: LeanIMTProof {
            siblings: array![1, 2, 3],
            path_indices: array![false, true, false],
            leaf: 0x12345,
            root: 0xABCDE,
            tree_size: 8,
        },
        deposit_commitment: 0x12345,
        association_set_id: Option::None,
        association_proof: Option::None,
        exclusion_set_id: Option::None,
        exclusion_proof: Option::None,
        nullifier: 0xDEADBEEF,
        amount: 1000000000000000000_u256, // 1 token (18 decimals)
        recipient,
        range_proof_data: array![1, 2, 3, 4].span(),
    }
}

#[test]
#[should_panic(expected: "Withdrawal recipient must be router")]
fn test_shielded_swap_invalid_recipient() {
    let router = deploy_router();
    let wrong_recipient = contract_address_const::<0xBAD>();

    let request = ShieldedSwapRequest {
        source_pool: pool_a_address(),
        withdrawal_proof: build_test_withdrawal_proof(wrong_recipient), // Wrong recipient!
        pool_key: PoolKey {
            token0: token_a_address(),
            token1: token_b_address(),
            fee: 3000,
            tick_spacing: 60,
            extension: contract_address_const::<0>(),
        },
        swap_params: SwapParameters {
            amount: i129 { mag: 1000000000000000000, sign: false },
            is_token1: true,
            sqrt_ratio_limit: 0,
            skip_ahead: 0,
        },
        min_amount_out: 900000000000000000_u256,
        dest_pool: pool_b_address(),
        deposit_commitment: 0xFEED,
        deposit_amount_commitment: ec_zero(),
        deposit_asset_id: 1,
        deposit_range_proof: array![1, 2, 3].span(),
    };

    router.shielded_swap(request);
}

#[test]
#[should_panic(expected: "Source pool is zero")]
fn test_shielded_swap_zero_source_pool() {
    let router = deploy_router();

    let request = ShieldedSwapRequest {
        source_pool: contract_address_const::<0>(), // Zero!
        withdrawal_proof: build_test_withdrawal_proof(router.contract_address),
        pool_key: PoolKey {
            token0: token_a_address(),
            token1: token_b_address(),
            fee: 3000,
            tick_spacing: 60,
            extension: contract_address_const::<0>(),
        },
        swap_params: SwapParameters {
            amount: i129 { mag: 1000000000000000000, sign: false },
            is_token1: true,
            sqrt_ratio_limit: 0,
            skip_ahead: 0,
        },
        min_amount_out: 900000000000000000_u256,
        dest_pool: pool_b_address(),
        deposit_commitment: 0xFEED,
        deposit_amount_commitment: ec_zero(),
        deposit_asset_id: 1,
        deposit_range_proof: array![1, 2, 3].span(),
    };

    router.shielded_swap(request);
}

#[test]
#[should_panic(expected: "Dest pool is zero")]
fn test_shielded_swap_zero_dest_pool() {
    let router = deploy_router();

    let request = ShieldedSwapRequest {
        source_pool: pool_a_address(),
        withdrawal_proof: build_test_withdrawal_proof(router.contract_address),
        pool_key: PoolKey {
            token0: token_a_address(),
            token1: token_b_address(),
            fee: 3000,
            tick_spacing: 60,
            extension: contract_address_const::<0>(),
        },
        swap_params: SwapParameters {
            amount: i129 { mag: 1000000000000000000, sign: false },
            is_token1: true,
            sqrt_ratio_limit: 0,
            skip_ahead: 0,
        },
        min_amount_out: 900000000000000000_u256,
        dest_pool: contract_address_const::<0>(), // Zero!
        deposit_commitment: 0xFEED,
        deposit_amount_commitment: ec_zero(),
        deposit_asset_id: 1,
        deposit_range_proof: array![1, 2, 3].span(),
    };

    router.shielded_swap(request);
}

// =============================================================================
// ShieldedSwapRequest Serialization Tests
// =============================================================================

#[test]
fn test_shielded_swap_request_serialization() {
    let request = ShieldedSwapRequest {
        source_pool: pool_a_address(),
        withdrawal_proof: build_test_withdrawal_proof(contract_address_const::<0x1>()),
        pool_key: PoolKey {
            token0: token_a_address(),
            token1: token_b_address(),
            fee: 3000,
            tick_spacing: 60,
            extension: contract_address_const::<0>(),
        },
        swap_params: SwapParameters {
            amount: i129 { mag: 1000000000000000000, sign: false },
            is_token1: true,
            sqrt_ratio_limit: 0,
            skip_ahead: 0,
        },
        min_amount_out: 900000000000000000_u256,
        dest_pool: pool_b_address(),
        deposit_commitment: 0xFEED,
        deposit_amount_commitment: ec_zero(),
        deposit_asset_id: 1,
        deposit_range_proof: array![1, 2, 3].span(),
    };

    let mut output = ArrayTrait::new();
    request.serialize(ref output);
    assert!(output.len() > 0, "ShieldedSwapRequest should serialize to non-empty array");

    // Verify we can deserialize back
    let mut span = output.span();
    let deserialized = Serde::<ShieldedSwapRequest>::deserialize(ref span);
    assert!(deserialized.is_some(), "Should deserialize back successfully");

    let req = deserialized.unwrap();
    assert!(req.source_pool == pool_a_address(), "Source pool should match");
    assert!(req.dest_pool == pool_b_address(), "Dest pool should match");
    assert!(req.deposit_commitment == 0xFEED, "Deposit commitment should match");
    assert!(req.min_amount_out == 900000000000000000_u256, "Min amount should match");
}

// =============================================================================
// Event Struct Tests
// =============================================================================

#[test]
fn test_shielded_swap_executed_event() {
    let event = ShieldedSwapExecuted {
        swap_id: 1,
        source_pool: pool_a_address(),
        dest_pool: pool_b_address(),
        input_token: token_a_address(),
        output_token: token_b_address(),
        input_amount: 1000000000000000000_u256,
        output_amount: 950000000000000000_u256,
        timestamp: 1706745600,
    };

    assert!(event.swap_id == 1, "Swap ID should be 1");
    assert!(event.input_amount == 1000000000000000000_u256, "Input should be 1e18");
    assert!(event.output_amount == 950000000000000000_u256, "Output should be 0.95e18");
}

#[test]
fn test_pool_registered_event() {
    let event = PoolRegistered {
        token: token_a_address(),
        pool: pool_a_address(),
    };

    assert!(event.token == token_a_address(), "Token should match");
    assert!(event.pool == pool_a_address(), "Pool should match");
}
