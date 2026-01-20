// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Multi-Asset Privacy Tests
// Tests for decimal handling and multi-asset privacy payments

use core::array::ArrayTrait;
use core::traits::TryInto;

// Import decimal utilities from common
use sage_contracts::utils::common::decimals::{
    AssetId, AssetDecimals, STANDARD_DECIMALS, Pow10,
    get_decimals, pow10, normalize_to_18, scale_to_asset,
    convert_decimals, is_valid_amount, split_amount,
};

// Import ElGamal for multi-asset privacy operations
use sage_contracts::obelysk::elgamal::{
    ECPoint, ElGamalCiphertext, EncryptedBalance,
    generator, generator_h, ec_zero, is_zero,
    ec_add, ec_sub, ec_mul,
    derive_public_key, encrypt, decrypt_point,
    homomorphic_add, homomorphic_sub,
    create_encrypted_balance, rollup_balance,
};

// =============================================================================
// Test Constants
// =============================================================================

const TEST_SECRET_KEY: felt252 = 12345678901234567890;
const TEST_RANDOMNESS: felt252 = 111111111111111111;

// =============================================================================
// Decimal Utilities Unit Tests
// =============================================================================

#[test]
fn test_asset_id_constants() {
    // Verify asset IDs are correctly defined
    assert(AssetId::SAGE == 0, 'SAGE should be 0');
    assert(AssetId::USDC == 1, 'USDC should be 1');
    assert(AssetId::STRK == 2, 'STRK should be 2');
    assert(AssetId::BTC == 3, 'BTC should be 3');
    assert(AssetId::ETH == 4, 'ETH should be 4');
}

#[test]
fn test_asset_decimals_constants() {
    // Verify decimal places for each asset
    assert(AssetDecimals::SAGE == 18, 'SAGE should be 18 decimals');
    assert(AssetDecimals::USDC == 6, 'USDC should be 6 decimals');
    assert(AssetDecimals::STRK == 18, 'STRK should be 18 decimals');
    assert(AssetDecimals::BTC == 8, 'BTC should be 8 decimals');
    assert(AssetDecimals::ETH == 18, 'ETH should be 18 decimals');
}

#[test]
fn test_get_decimals_function() {
    // Test get_decimals for all assets
    assert(get_decimals(AssetId::SAGE) == 18, 'SAGE decimals wrong');
    assert(get_decimals(AssetId::USDC) == 6, 'USDC decimals wrong');
    assert(get_decimals(AssetId::STRK) == 18, 'STRK decimals wrong');
    assert(get_decimals(AssetId::BTC) == 8, 'BTC decimals wrong');
    assert(get_decimals(AssetId::ETH) == 18, 'ETH decimals wrong');

    // Unknown asset should return 0
    assert(get_decimals(99) == 0, 'Unknown asset should be 0');
}

#[test]
fn test_pow10_lookup() {
    // Test power of 10 lookup table
    assert(pow10(0) == 1, 'pow10(0) wrong');
    assert(pow10(1) == 10, 'pow10(1) wrong');
    assert(pow10(2) == 100, 'pow10(2) wrong');
    assert(pow10(3) == 1000, 'pow10(3) wrong');
    assert(pow10(6) == 1000000, 'pow10(6) wrong');
    assert(pow10(8) == 100000000, 'pow10(8) wrong');
    assert(pow10(12) == 1000000000000, 'pow10(12) wrong');
    assert(pow10(18) == 1000000000000000000, 'pow10(18) wrong');
}

// =============================================================================
// Decimal Normalization Tests
// =============================================================================

#[test]
fn test_normalize_sage_no_change() {
    // SAGE has 18 decimals - no scaling needed
    let amount: u256 = 1_000_000_000_000_000_000; // 1 SAGE
    let normalized = normalize_to_18(amount, AssetId::SAGE);
    assert(normalized == amount, 'SAGE normalize wrong');
}

#[test]
fn test_normalize_usdc_scale_up() {
    // USDC: 6 decimals -> 18 decimals (scale up by 10^12)
    let amount: u256 = 1_000_000; // 1 USDC (6 decimals)
    let normalized = normalize_to_18(amount, AssetId::USDC);
    let expected: u256 = 1_000_000_000_000_000_000; // 1.0 in 18 decimals
    assert(normalized == expected, 'USDC normalization wrong');
}

#[test]
fn test_normalize_btc_scale_up() {
    // BTC: 8 decimals -> 18 decimals (scale up by 10^10)
    let amount: u256 = 100_000_000; // 1 BTC (8 decimals)
    let normalized = normalize_to_18(amount, AssetId::BTC);
    let expected: u256 = 1_000_000_000_000_000_000; // 1.0 in 18 decimals
    assert(normalized == expected, 'BTC normalization wrong');
}

#[test]
fn test_normalize_strk_no_change() {
    // STRK has 18 decimals - no scaling needed
    let amount: u256 = 5_000_000_000_000_000_000; // 5 STRK
    let normalized = normalize_to_18(amount, AssetId::STRK);
    assert(normalized == amount, 'STRK normalize wrong');
}

#[test]
fn test_normalize_fractional_usdc() {
    // 0.5 USDC = 500_000 (6 decimals)
    let amount: u256 = 500_000;
    let normalized = normalize_to_18(amount, AssetId::USDC);
    let expected: u256 = 500_000_000_000_000_000; // 0.5 in 18 decimals
    assert(normalized == expected, 'Fractional USDC wrong');
}

// =============================================================================
// Scale to Asset Tests
// =============================================================================

#[test]
fn test_scale_to_sage_no_change() {
    // 18 decimals -> 18 decimals (SAGE)
    let amount_18: u256 = 1_000_000_000_000_000_000;
    let scaled = scale_to_asset(amount_18, AssetId::SAGE);
    assert(scaled == amount_18, 'SAGE scale should not change');
}

#[test]
fn test_scale_to_usdc() {
    // 18 decimals -> 6 decimals (USDC)
    let amount_18: u256 = 1_000_000_000_000_000_000; // 1.0 in 18 decimals
    let scaled = scale_to_asset(amount_18, AssetId::USDC);
    let expected: u256 = 1_000_000; // 1 USDC
    assert(scaled == expected, 'Scale to USDC wrong');
}

#[test]
fn test_scale_to_btc() {
    // 18 decimals -> 8 decimals (BTC)
    let amount_18: u256 = 1_000_000_000_000_000_000; // 1.0 in 18 decimals
    let scaled = scale_to_asset(amount_18, AssetId::BTC);
    let expected: u256 = 100_000_000; // 1 BTC
    assert(scaled == expected, 'Scale to BTC wrong');
}

#[test]
fn test_scale_precision_loss_usdc() {
    // Small amounts below USDC precision should truncate to 0
    let amount_18: u256 = 999_999_999_999; // < 10^12 (minimum USDC precision)
    let scaled = scale_to_asset(amount_18, AssetId::USDC);
    assert(scaled == 0, 'Below USDC precision');
}

#[test]
fn test_scale_precision_loss_btc() {
    // Small amounts below BTC precision should truncate to 0
    let amount_18: u256 = 9_999_999_999; // < 10^10 (minimum BTC precision)
    let scaled = scale_to_asset(amount_18, AssetId::BTC);
    assert(scaled == 0, 'Below BTC precision');
}

// =============================================================================
// Cross-Asset Conversion Tests
// =============================================================================

#[test]
fn test_convert_same_asset_no_change() {
    let amount: u256 = 1_000_000;
    let converted = convert_decimals(amount, AssetId::USDC, AssetId::USDC);
    assert(converted == amount, 'Same asset should not change');
}

#[test]
fn test_convert_usdc_to_sage() {
    // 1 USDC (6 decimals) -> SAGE (18 decimals)
    let usdc_amount: u256 = 1_000_000;
    let sage_amount = convert_decimals(usdc_amount, AssetId::USDC, AssetId::SAGE);
    let expected: u256 = 1_000_000_000_000_000_000;
    assert(sage_amount == expected, 'USDC to SAGE wrong');
}

#[test]
fn test_convert_sage_to_usdc() {
    // 1 SAGE (18 decimals) -> USDC (6 decimals)
    let sage_amount: u256 = 1_000_000_000_000_000_000;
    let usdc_amount = convert_decimals(sage_amount, AssetId::SAGE, AssetId::USDC);
    let expected: u256 = 1_000_000;
    assert(usdc_amount == expected, 'SAGE to USDC wrong');
}

#[test]
fn test_convert_btc_to_usdc() {
    // 1 BTC (8 decimals) -> USDC (6 decimals)
    let btc_amount: u256 = 100_000_000; // 1 BTC
    let usdc_amount = convert_decimals(btc_amount, AssetId::BTC, AssetId::USDC);
    let expected: u256 = 1_000_000; // 1 "USDC" (decimal conversion only, not price)
    assert(usdc_amount == expected, 'BTC to USDC decimals wrong');
}

#[test]
fn test_convert_usdc_to_btc() {
    // 1 USDC (6 decimals) -> BTC (8 decimals)
    let usdc_amount: u256 = 1_000_000;
    let btc_amount = convert_decimals(usdc_amount, AssetId::USDC, AssetId::BTC);
    let expected: u256 = 100_000_000; // 1 "BTC" (decimal conversion only)
    assert(btc_amount == expected, 'USDC to BTC decimals wrong');
}

#[test]
fn test_convert_strk_to_eth() {
    // Both 18 decimals - should be unchanged
    let strk_amount: u256 = 5_000_000_000_000_000_000;
    let eth_amount = convert_decimals(strk_amount, AssetId::STRK, AssetId::ETH);
    assert(eth_amount == strk_amount, 'Same decimals unchanged');
}

// =============================================================================
// Amount Validation Tests
// =============================================================================

#[test]
fn test_is_valid_amount_normal_values() {
    // Normal amounts should be valid
    assert(is_valid_amount(1_000_000, AssetId::USDC), 'Normal USDC should be valid');
    assert(is_valid_amount(100_000_000, AssetId::BTC), 'Normal BTC should be valid');
    assert(is_valid_amount(1_000_000_000_000_000_000, AssetId::SAGE), 'Normal SAGE valid');
}

#[test]
fn test_is_valid_amount_zero() {
    // Zero should be valid
    assert(is_valid_amount(0, AssetId::SAGE), 'Zero SAGE should be valid');
    assert(is_valid_amount(0, AssetId::USDC), 'Zero USDC should be valid');
}

#[test]
fn test_is_valid_amount_unknown_asset() {
    // Unknown asset should return false
    assert(!is_valid_amount(1000, 99), 'Unknown asset invalid');
}

// =============================================================================
// Split Amount Tests
// =============================================================================

#[test]
fn test_split_amount_sage() {
    // 1.5 SAGE = 1_500_000_000_000_000_000
    let amount: u256 = 1_500_000_000_000_000_000;
    let (whole, fractional, decimals) = split_amount(amount, AssetId::SAGE);
    assert(whole == 1, 'SAGE whole wrong');
    assert(fractional == 500_000_000_000_000_000, 'SAGE fractional wrong');
    assert(decimals == 18, 'SAGE decimals wrong');
}

#[test]
fn test_split_amount_usdc() {
    // 2.5 USDC = 2_500_000
    let amount: u256 = 2_500_000;
    let (whole, fractional, decimals) = split_amount(amount, AssetId::USDC);
    assert(whole == 2, 'USDC whole wrong');
    assert(fractional == 500_000, 'USDC fractional wrong');
    assert(decimals == 6, 'USDC decimals wrong');
}

#[test]
fn test_split_amount_btc() {
    // 0.5 BTC = 50_000_000
    let amount: u256 = 50_000_000;
    let (whole, fractional, decimals) = split_amount(amount, AssetId::BTC);
    assert(whole == 0, 'BTC whole wrong');
    assert(fractional == 50_000_000, 'BTC fractional wrong');
    assert(decimals == 8, 'BTC decimals wrong');
}

#[test]
fn test_split_amount_unknown_asset() {
    let (whole, fractional, decimals) = split_amount(1000, 99);
    assert(whole == 0, 'Unknown whole should be 0');
    assert(fractional == 0, 'Unknown frac should be 0');
    assert(decimals == 0, 'Unknown decimals should be 0');
}

// =============================================================================
// Multi-Asset Privacy Integration Tests
// =============================================================================

#[test]
fn test_multi_asset_encrypted_balance_usdc() {
    // Test creating encrypted balance for USDC
    let sk = TEST_SECRET_KEY;
    let pk = derive_public_key(sk);

    // 100 USDC in 6 decimals
    let usdc_amount: u256 = 100_000_000;

    // Normalize to 18 decimals for privacy operations
    let normalized = normalize_to_18(usdc_amount, AssetId::USDC);

    // Create encrypted balance with normalized amount
    let balance = create_encrypted_balance(normalized, pk, TEST_RANDOMNESS);

    // Decrypt and verify
    let decrypted = decrypt_point(balance.ciphertext, sk);
    let h = generator_h();
    let expected_felt: felt252 = normalized.try_into().unwrap();
    let expected = ec_mul(expected_felt, h);

    assert(decrypted.x == expected.x, 'USDC encrypted balance wrong');
}

#[test]
fn test_multi_asset_encrypted_balance_btc() {
    // Test creating encrypted balance for BTC
    let sk = TEST_SECRET_KEY;
    let pk = derive_public_key(sk);

    // 0.5 BTC in 8 decimals
    let btc_amount: u256 = 50_000_000;

    // Normalize to 18 decimals
    let normalized = normalize_to_18(btc_amount, AssetId::BTC);

    // Create encrypted balance
    let balance = create_encrypted_balance(normalized, pk, TEST_RANDOMNESS);

    // Decrypt and verify
    let decrypted = decrypt_point(balance.ciphertext, sk);
    let h = generator_h();
    let expected_felt: felt252 = normalized.try_into().unwrap();
    let expected = ec_mul(expected_felt, h);

    assert(decrypted.x == expected.x, 'BTC encrypted balance wrong');
}

#[test]
fn test_multi_asset_homomorphic_add_different_decimals() {
    // Test homomorphic addition with amounts from different decimal bases
    let sk = TEST_SECRET_KEY;
    let pk = derive_public_key(sk);

    // 50 USDC (6 decimals)
    let usdc_amount: u256 = 50_000_000;
    let usdc_normalized = normalize_to_18(usdc_amount, AssetId::USDC);

    // 50 more USDC
    let usdc_amount2: u256 = 50_000_000;
    let usdc_normalized2 = normalize_to_18(usdc_amount2, AssetId::USDC);

    // Encrypt both
    let ct1 = encrypt(usdc_normalized, pk, 111);
    let ct2 = encrypt(usdc_normalized2, pk, 222);

    // Homomorphic add
    let ct_sum = homomorphic_add(ct1, ct2);

    // Decrypt and verify sum equals 100 USDC normalized
    let decrypted = decrypt_point(ct_sum, sk);
    let h = generator_h();
    let expected_sum = usdc_normalized + usdc_normalized2;
    let expected_felt: felt252 = expected_sum.try_into().unwrap();
    let expected = ec_mul(expected_felt, h);

    assert(decrypted.x == expected.x, 'Homo add multi-asset wrong');
}

#[test]
fn test_multi_asset_transfer_with_conversion() {
    // Simulate private transfer with decimal conversion at boundaries
    let alice_sk = TEST_SECRET_KEY;
    let alice_pk = derive_public_key(alice_sk);
    let bob_sk: felt252 = 98765432109876543210;
    let bob_pk = derive_public_key(bob_sk);

    // Alice deposits 100 USDC
    let deposit_usdc: u256 = 100_000_000; // 100 USDC
    let deposit_normalized = normalize_to_18(deposit_usdc, AssetId::USDC);

    let alice_balance = create_encrypted_balance(deposit_normalized, alice_pk, 111);

    // Alice transfers 30 USDC to Bob
    let transfer_usdc: u256 = 30_000_000;
    let transfer_normalized = normalize_to_18(transfer_usdc, AssetId::USDC);

    // Create encrypted transfer for Bob
    let bob_ct = encrypt(transfer_normalized, bob_pk, 222);

    // Create pending_out for Alice
    let alice_pending = encrypt(transfer_normalized, alice_pk, 333);

    // Update Alice's balance
    let alice_after = EncryptedBalance {
        ciphertext: alice_balance.ciphertext,
        pending_in: alice_balance.pending_in,
        pending_out: alice_pending,
        epoch: alice_balance.epoch,
    };
    let alice_final = rollup_balance(alice_after);

    // Update Bob's balance
    let bob_balance = create_encrypted_balance(0, bob_pk, 444);
    let bob_after = EncryptedBalance {
        ciphertext: bob_balance.ciphertext,
        pending_in: bob_ct,
        pending_out: bob_balance.pending_out,
        epoch: bob_balance.epoch,
    };
    let bob_final = rollup_balance(bob_after);

    // Verify Alice has 70 USDC (normalized)
    let alice_dec = decrypt_point(alice_final.ciphertext, alice_sk);
    let h = generator_h();
    let expected_alice = deposit_normalized - transfer_normalized;
    let expected_alice_felt: felt252 = expected_alice.try_into().unwrap();
    let expected_alice_pt = ec_mul(expected_alice_felt, h);
    assert(alice_dec.x == expected_alice_pt.x, 'Alice final wrong');

    // Verify Bob has 30 USDC (normalized)
    let bob_dec = decrypt_point(bob_final.ciphertext, bob_sk);
    let expected_bob_felt: felt252 = transfer_normalized.try_into().unwrap();
    let expected_bob_pt = ec_mul(expected_bob_felt, h);
    assert(bob_dec.x == expected_bob_pt.x, 'Bob final wrong');

    // Verify we can convert back to USDC decimals
    let alice_usdc_final = scale_to_asset(expected_alice, AssetId::USDC);
    assert(alice_usdc_final == 70_000_000, 'Alice USDC conversion wrong');

    let bob_usdc_final = scale_to_asset(transfer_normalized, AssetId::USDC);
    assert(bob_usdc_final == 30_000_000, 'Bob USDC conversion wrong');
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_roundtrip_conversion_usdc() {
    // Convert USDC -> normalized -> USDC should be lossless for whole units
    let original: u256 = 12_345_678; // 12.345678 USDC
    let normalized = normalize_to_18(original, AssetId::USDC);
    let back = scale_to_asset(normalized, AssetId::USDC);
    assert(back == original, 'USDC roundtrip failed');
}

#[test]
fn test_roundtrip_conversion_btc() {
    // Convert BTC -> normalized -> BTC should be lossless
    let original: u256 = 123_456_789; // 1.23456789 BTC
    let normalized = normalize_to_18(original, AssetId::BTC);
    let back = scale_to_asset(normalized, AssetId::BTC);
    assert(back == original, 'BTC roundtrip failed');
}

#[test]
fn test_large_amount_usdc() {
    // Test with 1 billion USDC
    let large_usdc: u256 = 1_000_000_000_000_000; // 1 billion USDC (6 decimals)
    let normalized = normalize_to_18(large_usdc, AssetId::USDC);
    let back = scale_to_asset(normalized, AssetId::USDC);
    assert(back == large_usdc, 'Large USDC roundtrip failed');
}

#[test]
fn test_smallest_unit_btc() {
    // Test with 1 satoshi
    let one_sat: u256 = 1;
    let normalized = normalize_to_18(one_sat, AssetId::BTC);
    let expected: u256 = 10_000_000_000; // 10^10 (scale factor for BTC)
    assert(normalized == expected, '1 sat normalization wrong');

    // Convert back
    let back = scale_to_asset(normalized, AssetId::BTC);
    assert(back == one_sat, '1 sat roundtrip wrong');
}

#[test]
fn test_smallest_unit_usdc() {
    // Test with 1 micro-USDC (0.000001 USDC)
    let one_micro: u256 = 1;
    let normalized = normalize_to_18(one_micro, AssetId::USDC);
    let expected: u256 = 1_000_000_000_000; // 10^12 (scale factor for USDC)
    assert(normalized == expected, 'micro USDC norm wrong');
}

// =============================================================================
// Pow10 Lookup Table Completeness Test
// =============================================================================

#[test]
fn test_pow10_all_values() {
    // Verify all pow10 values match expected powers of 10
    assert(pow10(0) == 1, 'pow10(0)');
    assert(pow10(1) == 10, 'pow10(1)');
    assert(pow10(2) == 100, 'pow10(2)');
    assert(pow10(3) == 1_000, 'pow10(3)');
    assert(pow10(4) == 10_000, 'pow10(4)');
    assert(pow10(5) == 100_000, 'pow10(5)');
    assert(pow10(6) == 1_000_000, 'pow10(6)');
    assert(pow10(7) == 10_000_000, 'pow10(7)');
    assert(pow10(8) == 100_000_000, 'pow10(8)');
    assert(pow10(9) == 1_000_000_000, 'pow10(9)');
    assert(pow10(10) == 10_000_000_000, 'pow10(10)');
    assert(pow10(11) == 100_000_000_000, 'pow10(11)');
    assert(pow10(12) == 1_000_000_000_000, 'pow10(12)');
    assert(pow10(13) == 10_000_000_000_000, 'pow10(13)');
    assert(pow10(14) == 100_000_000_000_000, 'pow10(14)');
    assert(pow10(15) == 1_000_000_000_000_000, 'pow10(15)');
    assert(pow10(16) == 10_000_000_000_000_000, 'pow10(16)');
    assert(pow10(17) == 100_000_000_000_000_000, 'pow10(17)');
    assert(pow10(18) == 1_000_000_000_000_000_000, 'pow10(18)');
}
