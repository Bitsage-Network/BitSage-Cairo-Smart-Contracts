//! Referral System Tests
//! Tests for referrer registration, referrals, tiers, and reward distribution

use core::array::ArrayTrait;
use starknet::ContractAddress;
use core::traits::TryInto;

use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp_global, stop_cheat_block_timestamp_global
};

use sage_contracts::growth::referral_system::{
    IReferralSystemDispatcher, IReferralSystemDispatcherTrait,
    ReferrerTier, ReferrerProfile, ReferredUser, ReferralConfig
};

// =============================================================================
// Test Helpers
// =============================================================================

fn get_test_addresses() -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let referrer: ContractAddress = 'referrer'.try_into().unwrap();
    let user1: ContractAddress = 'user1'.try_into().unwrap();
    let sage_token: ContractAddress = 'sage_token'.try_into().unwrap();
    (owner, referrer, user1, sage_token)
}

fn deploy_referral_system() -> IReferralSystemDispatcher {
    let (owner, _, _, sage_token) = get_test_addresses();

    let contract_class = declare("ReferralSystem").unwrap().contract_class();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(sage_token.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    IReferralSystemDispatcher { contract_address }
}

// =============================================================================
// Configuration Tests
// =============================================================================

#[test]
fn test_initial_config() {
    let referral = deploy_referral_system();
    let config = referral.get_config();

    assert(config.bronze_fee_share_bps == 1000, 'Wrong bronze share');
    assert(config.silver_fee_share_bps == 1500, 'Wrong silver share');
    assert(config.gold_fee_share_bps == 2000, 'Wrong gold share');
    assert(config.platinum_fee_share_bps == 2500, 'Wrong platinum share');
    assert(config.silver_threshold == 10, 'Wrong silver threshold');
    assert(config.gold_threshold == 50, 'Wrong gold threshold');
    assert(config.platinum_threshold == 200, 'Wrong platinum threshold');
    assert(config.block_self_referral, 'Should block self-referral');
    assert(!config.paused, 'Should not be paused');
}

#[test]
fn test_initial_stats() {
    let referral = deploy_referral_system();
    let (total_volume, total_rewards, referrer_count, referred_count) = referral.get_stats();

    assert(total_volume == 0, 'Should have 0 volume');
    assert(total_rewards == 0, 'Should have 0 rewards');
    assert(referrer_count == 0, 'Should have 0 referrers');
    assert(referred_count == 0, 'Should have 0 referred');
}

// =============================================================================
// Referrer Registration Tests
// =============================================================================

#[test]
fn test_register_referrer() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.register_referrer();
    stop_cheat_caller_address(referral.contract_address);

    assert(code != 0, 'Code should not be 0');

    let profile = referral.get_referrer_profile(referrer);
    assert(profile.referral_code == code, 'Wrong referral code');
    assert(profile.tier == ReferrerTier::Bronze, 'Should be Bronze tier');
    assert(profile.total_referrals == 0, 'Should have 0 referrals');
    assert(profile.is_active, 'Should be active');
}

#[test]
fn test_register_referrer_with_custom_code() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    let custom_code: felt252 = 'MYCODE123';

    start_cheat_caller_address(referral.contract_address, referrer);
    let success = referral.register_referrer_with_code(custom_code);
    stop_cheat_caller_address(referral.contract_address);

    assert(success, 'Registration should succeed');

    let profile = referral.get_referrer_profile(referrer);
    assert(profile.referral_code == custom_code, 'Wrong referral code');
}

#[test]
fn test_register_referrer_duplicate_code_fails() {
    let referral = deploy_referral_system();
    let (_, referrer, user1, _) = get_test_addresses();

    let custom_code: felt252 = 'MYCODE123';

    // First registration
    start_cheat_caller_address(referral.contract_address, referrer);
    referral.register_referrer_with_code(custom_code);
    stop_cheat_caller_address(referral.contract_address);

    // Second registration with same code
    start_cheat_caller_address(referral.contract_address, user1);
    let success = referral.register_referrer_with_code(custom_code);
    stop_cheat_caller_address(referral.contract_address);

    assert(!success, 'Should fail - code taken');
}

#[test]
#[should_panic]
fn test_register_referrer_twice() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, referrer);
    referral.register_referrer();
    referral.register_referrer();  // Should panic
}

#[test]
fn test_get_referrer_by_code() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.register_referrer();
    stop_cheat_caller_address(referral.contract_address);

    let found_referrer = referral.get_referrer_by_code(code);
    assert(found_referrer == referrer, 'Wrong referrer');
}

// =============================================================================
// Referral Registration Tests
// =============================================================================

#[test]
fn test_register_with_referral() {
    let referral = deploy_referral_system();
    let (_, referrer, user1, _) = get_test_addresses();

    // Register referrer
    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.register_referrer();
    stop_cheat_caller_address(referral.contract_address);

    // User registers with referral
    start_cheat_caller_address(referral.contract_address, user1);
    referral.register_with_referral(code);
    stop_cheat_caller_address(referral.contract_address);

    // Check user has referrer
    assert(referral.has_referrer(user1), 'User should have referrer');

    let info = referral.get_referral_info(user1);
    assert(info.referrer == referrer, 'Wrong referrer');
    assert(info.total_volume_usd == 0, 'Volume should be 0');

    // Check referrer stats updated
    let profile = referral.get_referrer_profile(referrer);
    assert(profile.total_referrals == 1, 'Should have 1 referral');
}

#[test]
#[should_panic]
fn test_register_with_invalid_code() {
    let referral = deploy_referral_system();
    let (_, _, user1, _) = get_test_addresses();

    let invalid_code: felt252 = 'INVALID';

    start_cheat_caller_address(referral.contract_address, user1);
    referral.register_with_referral(invalid_code);
}

#[test]
#[should_panic]
fn test_register_with_referral_twice() {
    let referral = deploy_referral_system();
    let (_, referrer, user1, _) = get_test_addresses();

    // Register referrer
    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.register_referrer();
    stop_cheat_caller_address(referral.contract_address);

    // User registers with referral twice
    start_cheat_caller_address(referral.contract_address, user1);
    referral.register_with_referral(code);
    referral.register_with_referral(code);  // Should panic
}

#[test]
#[should_panic]
fn test_self_referral_blocked() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    // Register as referrer
    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.register_referrer();

    // Try to refer self
    referral.register_with_referral(code);  // Should panic
}

// =============================================================================
// Tier Tests
// =============================================================================

#[test]
fn test_tier_calculation() {
    let referral = deploy_referral_system();

    // Bronze: 0-9
    assert(referral.calculate_tier(0) == ReferrerTier::Bronze, 'Should be Bronze');
    assert(referral.calculate_tier(9) == ReferrerTier::Bronze, 'Should be Bronze');

    // Silver: 10-49
    assert(referral.calculate_tier(10) == ReferrerTier::Silver, 'Should be Silver');
    assert(referral.calculate_tier(49) == ReferrerTier::Silver, 'Should be Silver');

    // Gold: 50-199
    assert(referral.calculate_tier(50) == ReferrerTier::Gold, 'Should be Gold');
    assert(referral.calculate_tier(199) == ReferrerTier::Gold, 'Should be Gold');

    // Platinum: 200+
    assert(referral.calculate_tier(200) == ReferrerTier::Platinum, 'Should be Platinum');
    assert(referral.calculate_tier(1000) == ReferrerTier::Platinum, 'Should be Platinum');
}

#[test]
fn test_fee_share_by_tier() {
    let referral = deploy_referral_system();

    let bronze_share = referral.get_fee_share(ReferrerTier::Bronze);
    let silver_share = referral.get_fee_share(ReferrerTier::Silver);
    let gold_share = referral.get_fee_share(ReferrerTier::Gold);
    let platinum_share = referral.get_fee_share(ReferrerTier::Platinum);

    assert(bronze_share == 1000, 'Bronze should be 10%');
    assert(silver_share == 1500, 'Silver should be 15%');
    assert(gold_share == 2000, 'Gold should be 20%');
    assert(platinum_share == 2500, 'Platinum should be 25%');
}

// =============================================================================
// Admin Tests
// =============================================================================

#[test]
fn test_pause_unpause() {
    let referral = deploy_referral_system();
    let (owner, _, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, owner);

    referral.pause();
    let config = referral.get_config();
    assert(config.paused, 'Should be paused');

    referral.unpause();
    let config = referral.get_config();
    assert(!config.paused, 'Should be unpaused');

    stop_cheat_caller_address(referral.contract_address);
}

#[test]
fn test_add_authorized_caller() {
    let referral = deploy_referral_system();
    let (owner, _, _, _) = get_test_addresses();
    let orderbook: ContractAddress = 'orderbook'.try_into().unwrap();

    start_cheat_caller_address(referral.contract_address, owner);
    referral.add_authorized_caller(orderbook);
    stop_cheat_caller_address(referral.contract_address);

    // Note: No getter for authorized_callers, but call should succeed
}

#[test]
fn test_update_config() {
    let referral = deploy_referral_system();
    let (owner, _, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, owner);

    let new_config = ReferralConfig {
        bronze_fee_share_bps: 500,
        silver_fee_share_bps: 1000,
        gold_fee_share_bps: 1500,
        platinum_fee_share_bps: 2000,
        silver_threshold: 5,
        gold_threshold: 25,
        platinum_threshold: 100,
        min_active_volume_usd: 50_000000000000000000,
        inactivity_days: 60,
        block_self_referral: false,
        paused: false,
    };

    referral.set_config(new_config);

    let config = referral.get_config();
    assert(config.bronze_fee_share_bps == 500, 'Wrong bronze share');
    assert(config.silver_threshold == 5, 'Wrong silver threshold');
    assert(!config.block_self_referral, 'Should allow self-referral');

    stop_cheat_caller_address(referral.contract_address);
}

#[test]
#[should_panic]
fn test_config_fee_share_too_high() {
    let referral = deploy_referral_system();
    let (owner, _, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, owner);

    let bad_config = ReferralConfig {
        bronze_fee_share_bps: 6000,  // 60% - too high
        silver_fee_share_bps: 1500,
        gold_fee_share_bps: 2000,
        platinum_fee_share_bps: 2500,
        silver_threshold: 10,
        gold_threshold: 50,
        platinum_threshold: 200,
        min_active_volume_usd: 100_000000000000000000,
        inactivity_days: 30,
        block_self_referral: true,
        paused: false,
    };

    referral.set_config(bad_config);
}

#[test]
#[should_panic]
fn test_config_invalid_thresholds() {
    let referral = deploy_referral_system();
    let (owner, _, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, owner);

    let bad_config = ReferralConfig {
        bronze_fee_share_bps: 1000,
        silver_fee_share_bps: 1500,
        gold_fee_share_bps: 2000,
        platinum_fee_share_bps: 2500,
        silver_threshold: 10,
        gold_threshold: 5,  // Less than silver - invalid
        platinum_threshold: 200,
        min_active_volume_usd: 100_000000000000000000,
        inactivity_days: 30,
        block_self_referral: true,
        paused: false,
    };

    referral.set_config(bad_config);
}

// =============================================================================
// Access Control Tests
// =============================================================================

#[test]
#[should_panic]
fn test_only_owner_pause() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, referrer);
    referral.pause();
}

#[test]
#[should_panic]
fn test_only_owner_set_config() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();

    start_cheat_caller_address(referral.contract_address, referrer);
    referral.set_config(ReferralConfig {
        bronze_fee_share_bps: 1000,
        silver_fee_share_bps: 1500,
        gold_fee_share_bps: 2000,
        platinum_fee_share_bps: 2500,
        silver_threshold: 10,
        gold_threshold: 50,
        platinum_threshold: 200,
        min_active_volume_usd: 100_000000000000000000,
        inactivity_days: 30,
        block_self_referral: true,
        paused: false,
    });
}

#[test]
#[should_panic]
fn test_only_owner_add_authorized() {
    let referral = deploy_referral_system();
    let (_, referrer, _, _) = get_test_addresses();
    let some_contract: ContractAddress = 'contract'.try_into().unwrap();

    start_cheat_caller_address(referral.contract_address, referrer);
    referral.add_authorized_caller(some_contract);
}

// =============================================================================
// Paused State Tests
// =============================================================================

#[test]
#[should_panic]
fn test_register_when_paused() {
    let referral = deploy_referral_system();
    let (owner, referrer, _, _) = get_test_addresses();

    // Pause
    start_cheat_caller_address(referral.contract_address, owner);
    referral.pause();
    stop_cheat_caller_address(referral.contract_address);

    // Try to register
    start_cheat_caller_address(referral.contract_address, referrer);
    referral.register_referrer();
}

// =============================================================================
// Has Referrer Tests
// =============================================================================

#[test]
fn test_has_referrer_false() {
    let referral = deploy_referral_system();
    let (_, _, user1, _) = get_test_addresses();

    assert(!referral.has_referrer(user1), 'Should not have referrer');
}

#[test]
fn test_has_referrer_true() {
    let referral = deploy_referral_system();
    let (_, referrer, user1, _) = get_test_addresses();

    // Register referrer
    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.register_referrer();
    stop_cheat_caller_address(referral.contract_address);

    // User registers with referral
    start_cheat_caller_address(referral.contract_address, user1);
    referral.register_with_referral(code);
    stop_cheat_caller_address(referral.contract_address);

    assert(referral.has_referrer(user1), 'Should have referrer');
}

// =============================================================================
// Stats Update Tests
// =============================================================================

#[test]
fn test_stats_after_registrations() {
    let referral = deploy_referral_system();
    let (_, referrer, user1, _) = get_test_addresses();

    // Register referrer
    start_cheat_caller_address(referral.contract_address, referrer);
    referral.register_referrer();
    stop_cheat_caller_address(referral.contract_address);

    let (_, _, referrer_count, _) = referral.get_stats();
    assert(referrer_count == 1, 'Should have 1 referrer');

    // Register referred user
    start_cheat_caller_address(referral.contract_address, referrer);
    let code = referral.get_referrer_profile(referrer).referral_code;
    stop_cheat_caller_address(referral.contract_address);

    start_cheat_caller_address(referral.contract_address, user1);
    referral.register_with_referral(code);
    stop_cheat_caller_address(referral.contract_address);

    let (_, _, _, referred_count) = referral.get_stats();
    assert(referred_count == 1, 'Should have 1 referred');
}
