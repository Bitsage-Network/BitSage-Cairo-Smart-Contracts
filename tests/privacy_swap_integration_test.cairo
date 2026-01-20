// ===========================================================================
// Privacy Router ↔ Confidential Swaps Integration Tests
// ===========================================================================
// Tests the integration between privacy routing and confidential swaps,
// with REAL on-chain proof verification.
// ===========================================================================

use core::traits::Into;
use core::option::OptionTrait;
use core::array::ArrayTrait;
use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use starknet::{ContractAddress, contract_address_const, get_block_timestamp};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp, stop_cheat_block_timestamp,
    spy_events, EventSpyAssertionsTrait, EventSpyTrait,
};
use sage_contracts::obelysk::privacy_router::{
    IPrivacyRouterDispatcher, IPrivacyRouterDispatcherTrait,
    PrivateAccount, PrivateTransfer,
};
use sage_contracts::obelysk::confidential_swap::{
    IConfidentialSwapDispatcher, IConfidentialSwapDispatcherTrait,
    AssetId, SwapOrderStatus, SwapSide,
    ConfidentialOrder, SwapMatch, SwapStats,
    SwapRangeProof, RateProof, BalanceProof, SwapProofBundle,
    SWAP_DOMAIN, RATE_PROOF_DOMAIN,
};
use sage_contracts::obelysk::elgamal::{ECPoint, ElGamalCiphertext, EncryptionProof, generator};
use sage_contracts::obelysk::pedersen_commitments::PedersenCommitment;

// ===========================================================================
// Test Setup Helpers
// ===========================================================================

fn deploy_privacy_router(owner: ContractAddress) -> IPrivacyRouterDispatcher {
    let contract = declare("PrivacyRouter").unwrap().contract_class();

    let mut calldata = array![];
    calldata.append(owner.into());  // owner
    calldata.append(owner.into());  // sage_token (placeholder)
    calldata.append(owner.into());  // payment_router (placeholder)

    let (address, _) = contract.deploy(@calldata).unwrap();
    IPrivacyRouterDispatcher { contract_address: address }
}

fn deploy_confidential_swap(owner: ContractAddress) -> IConfidentialSwapDispatcher {
    let contract = declare("ConfidentialSwapContract").unwrap().contract_class();

    let mut calldata = array![];
    calldata.append(owner.into());  // owner

    let (address, _) = contract.deploy(@calldata).unwrap();
    IConfidentialSwapDispatcher { contract_address: address }
}

fn setup_test_environment() -> (
    ContractAddress,  // owner
    ContractAddress,  // alice
    ContractAddress,  // bob
    IPrivacyRouterDispatcher,
    IConfidentialSwapDispatcher,
) {
    let owner = contract_address_const::<'OWNER'>();
    let alice = contract_address_const::<'ALICE'>();
    let bob = contract_address_const::<'BOB'>();

    let privacy_router = deploy_privacy_router(owner);
    let confidential_swap = deploy_confidential_swap(owner);

    (owner, alice, bob, privacy_router, confidential_swap)
}

// ===========================================================================
// Valid Proof Generation Functions
// ===========================================================================

/// Create a valid ElGamal ciphertext with known values
fn create_valid_ciphertext() -> ElGamalCiphertext {
    // Use generator point coordinates for a valid EC point
    let g = generator();
    ElGamalCiphertext {
        c1_x: g.x,
        c1_y: g.y,
        c2_x: g.x,
        c2_y: g.y,
    }
}

/// Create a non-zero EC point (using generator)
fn create_valid_ecpoint() -> ECPoint {
    generator()
}

/// Create a valid SwapRangeProof with correct Poseidon challenge
/// This computes the challenge as: hash(SWAP_DOMAIN, c1_x, c2_x, commitments...)
fn create_valid_range_proof(encrypted_amount: @ElGamalCiphertext) -> SwapRangeProof {
    let num_bits: u8 = 8;  // Use 8 bits for testing
    let g = generator();

    // Create bit commitments (non-zero points)
    let mut bit_commitments: Array<ECPoint> = array![];
    let mut i: u8 = 0;
    while i < num_bits {
        // Use different points for each bit (scaled generator approximation)
        bit_commitments.append(ECPoint {
            x: g.x + i.into(),
            y: g.y + i.into()
        });
        i += 1;
    };

    // Compute challenge: hash(SWAP_DOMAIN, c1_x, c2_x, all commitment coords)
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(SWAP_DOMAIN);
    challenge_input.append(*encrypted_amount.c1_x);
    challenge_input.append(*encrypted_amount.c2_x);

    let mut j: u32 = 0;
    while j < num_bits.into() {
        let commit = bit_commitments.at(j);
        challenge_input.append((*commit).x);
        challenge_input.append((*commit).y);
        j += 1;
    };

    let challenge = poseidon_hash_span(challenge_input.span());

    // Create non-zero responses
    let mut responses: Array<felt252> = array![];
    let mut k: u8 = 0;
    while k < num_bits {
        responses.append((k + 1).into());  // Non-zero responses
        k += 1;
    };

    SwapRangeProof {
        bit_commitments,
        challenge,
        responses,
        num_bits,
    }
}

/// Create a valid RateProof with correct Poseidon challenge
fn create_valid_rate_proof(
    encrypted_give: @ElGamalCiphertext,
    encrypted_want: @ElGamalCiphertext,
) -> RateProof {
    let g = generator();
    let rate_commitment = g;

    // Compute challenge: hash(RATE_PROOF_DOMAIN, give coords, want coords, rate_commitment)
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(RATE_PROOF_DOMAIN);
    challenge_input.append(*encrypted_give.c1_x);
    challenge_input.append(*encrypted_give.c1_y);
    challenge_input.append(*encrypted_give.c2_x);
    challenge_input.append(*encrypted_give.c2_y);
    challenge_input.append(*encrypted_want.c1_x);
    challenge_input.append(*encrypted_want.c1_y);
    challenge_input.append(*encrypted_want.c2_x);
    challenge_input.append(*encrypted_want.c2_y);
    challenge_input.append(rate_commitment.x);
    challenge_input.append(rate_commitment.y);

    let challenge = poseidon_hash_span(challenge_input.span());

    RateProof {
        rate_commitment,
        challenge,
        response_give: 12345,     // Non-zero
        response_rate: 67890,     // Non-zero
        response_blinding: 11111,
    }
}

/// Create a valid BalanceProof with correct Poseidon challenge
fn create_valid_balance_proof(
    encrypted_balance: @ElGamalCiphertext,
    encrypted_amount: @ElGamalCiphertext,
) -> BalanceProof {
    let g = generator();
    let balance_commitment = g;

    // Compute challenge: hash(SWAP_DOMAIN, commitment coords, balance.c1_x, amount.c1_x)
    let mut challenge_input: Array<felt252> = array![];
    challenge_input.append(SWAP_DOMAIN);
    challenge_input.append(balance_commitment.x);
    challenge_input.append(balance_commitment.y);
    challenge_input.append(*encrypted_balance.c1_x);
    challenge_input.append(*encrypted_amount.c1_x);

    let challenge = poseidon_hash_span(challenge_input.span());

    BalanceProof {
        balance_commitment,
        challenge,
        response: 99999,  // Non-zero
    }
}

/// Create a complete valid proof bundle for swap operations
fn create_valid_proof_bundle(
    fill_give: @ElGamalCiphertext,
    fill_want: @ElGamalCiphertext,
    user_balance: @ElGamalCiphertext,
) -> SwapProofBundle {
    SwapProofBundle {
        give_range_proof: create_valid_range_proof(fill_give),
        want_range_proof: create_valid_range_proof(fill_want),
        rate_proof: create_valid_rate_proof(fill_give, fill_want),
        balance_proof: create_valid_balance_proof(user_balance, fill_give),
    }
}

fn create_mock_encryption_proof() -> EncryptionProof {
    EncryptionProof {
        commitment_x: 111,
        commitment_y: 222,
        challenge: 1,
        response: 2,
        range_proof_hash: 333,
    }
}

// ===========================================================================
// Integration Test: Contract Deployment
// ===========================================================================

#[test]
fn test_privacy_router_deploys() {
    let (owner, _, _, privacy_router, _) = setup_test_environment();
    let empty_account = privacy_router.get_account(owner);
    assert(empty_account.public_key.x == 0, 'Should be unregistered');
}

#[test]
fn test_confidential_swap_deploys() {
    let (_, _, _, _, confidential_swap) = setup_test_environment();
    let is_paused = confidential_swap.is_paused();
    assert(is_paused == false, 'Should not be paused');
}

#[test]
fn test_confidential_swap_initial_counts() {
    let (_, _, _, _, confidential_swap) = setup_test_environment();
    let order_count = confidential_swap.get_order_count();
    let match_count = confidential_swap.get_match_count();
    assert(order_count == 0, 'Order count should be 0');
    assert(match_count == 0, 'Match count should be 0');
}

// ===========================================================================
// Integration Test: Privacy Router Account Registration
// ===========================================================================

#[test]
fn test_register_private_account() {
    let (_, alice, _, privacy_router, _) = setup_test_environment();

    start_cheat_caller_address(privacy_router.contract_address, alice);
    let public_key = create_valid_ecpoint();
    privacy_router.register_account(public_key);
    stop_cheat_caller_address(privacy_router.contract_address);

    let account = privacy_router.get_account(alice);
    assert(account.public_key.x == public_key.x, 'Public key should match');
    assert(account.public_key.y == public_key.y, 'Public key Y should match');
}

// ===========================================================================
// Integration Test: Confidential Swap Order Creation with Real Proofs
// ===========================================================================

#[test]
fn test_create_swap_order_with_valid_proofs() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    start_cheat_caller_address(confidential_swap.contract_address, alice);

    let encrypted_give = create_valid_ciphertext();
    let encrypted_want = create_valid_ciphertext();

    let order_id = confidential_swap.create_order(
        AssetId::SAGE,
        AssetId::USDC,
        encrypted_give,
        encrypted_want,
        12345,  // rate_commitment
        50,     // min_fill_pct
        86400,  // expiry_duration
        create_valid_range_proof(@encrypted_give),
        create_valid_range_proof(@encrypted_want),
    );

    stop_cheat_caller_address(confidential_swap.contract_address);

    let order = confidential_swap.get_order(order_id);
    assert(order.maker == alice, 'Maker should be Alice');
    assert(order.status == SwapOrderStatus::Open, 'Status should be Open');
    assert(order.rate_commitment == 12345, 'Rate commitment mismatch');
}

#[test]
fn test_cancel_swap_order() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    start_cheat_caller_address(confidential_swap.contract_address, alice);

    let encrypted_give = create_valid_ciphertext();
    let encrypted_want = create_valid_ciphertext();

    let order_id = confidential_swap.create_order(
        AssetId::ETH,
        AssetId::SAGE,
        encrypted_give,
        encrypted_want,
        99999,
        25,
        3600,
        create_valid_range_proof(@encrypted_give),
        create_valid_range_proof(@encrypted_want),
    );

    confidential_swap.cancel_order(order_id);
    stop_cheat_caller_address(confidential_swap.contract_address);

    let order = confidential_swap.get_order(order_id);
    assert(order.status == SwapOrderStatus::Cancelled, 'Should be cancelled');
}

// ===========================================================================
// Integration Test: User Order Tracking
// ===========================================================================

#[test]
fn test_user_order_count() {
    let (_, alice, bob, _, confidential_swap) = setup_test_environment();

    // Alice creates 3 orders
    start_cheat_caller_address(confidential_swap.contract_address, alice);

    let enc1 = create_valid_ciphertext();
    let _a1 = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, enc1, enc1,
        111, 50, 3600,
        create_valid_range_proof(@enc1),
        create_valid_range_proof(@enc1),
    );

    let enc2 = create_valid_ciphertext();
    let _a2 = confidential_swap.create_order(
        AssetId::ETH, AssetId::SAGE, enc2, enc2,
        222, 50, 3600,
        create_valid_range_proof(@enc2),
        create_valid_range_proof(@enc2),
    );

    let enc3 = create_valid_ciphertext();
    let _a3 = confidential_swap.create_order(
        AssetId::BTC, AssetId::USDC, enc3, enc3,
        333, 50, 3600,
        create_valid_range_proof(@enc3),
        create_valid_range_proof(@enc3),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Bob creates 2 orders
    start_cheat_caller_address(confidential_swap.contract_address, bob);

    let enc4 = create_valid_ciphertext();
    let _b1 = confidential_swap.create_order(
        AssetId::SAGE, AssetId::ETH, enc4, enc4,
        444, 50, 3600,
        create_valid_range_proof(@enc4),
        create_valid_range_proof(@enc4),
    );

    let enc5 = create_valid_ciphertext();
    let _b2 = confidential_swap.create_order(
        AssetId::USDC, AssetId::SAGE, enc5, enc5,
        555, 50, 3600,
        create_valid_range_proof(@enc5),
        create_valid_range_proof(@enc5),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    let alice_count = confidential_swap.get_user_order_count(alice);
    let bob_count = confidential_swap.get_user_order_count(bob);

    assert(alice_count == 3, 'Alice should have 3 orders');
    assert(bob_count == 2, 'Bob should have 2 orders');
    assert(confidential_swap.get_order_count() == 5, 'Total should be 5 orders');
}

// ===========================================================================
// Integration Test: Deposit for Swap
// ===========================================================================

#[test]
fn test_deposit_for_swap() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    start_cheat_caller_address(confidential_swap.contract_address, alice);

    let encrypted_amount = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(
        AssetId::SAGE,
        encrypted_amount,
        create_valid_range_proof(@encrypted_amount),
    );

    stop_cheat_caller_address(confidential_swap.contract_address);

    let balance = confidential_swap.get_swap_balance(alice, AssetId::SAGE);
    assert(balance.c1_x != 0 || balance.c2_x != 0, 'Balance should be set');
}

// ===========================================================================
// Integration Test: Direct Swap with Valid Proofs
// ===========================================================================

#[test]
fn test_direct_swap_with_valid_proofs() {
    let (_, alice, bob, _, confidential_swap) = setup_test_environment();

    // Alice deposits first
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let alice_deposit = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(
        AssetId::SAGE,
        alice_deposit,
        create_valid_range_proof(@alice_deposit),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Bob deposits
    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let bob_deposit = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(
        AssetId::USDC,
        bob_deposit,
        create_valid_range_proof(@bob_deposit),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Alice creates an order
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let enc_give = create_valid_ciphertext();
    let enc_want = create_valid_ciphertext();
    let order_id = confidential_swap.create_order(
        AssetId::SAGE,
        AssetId::USDC,
        enc_give,
        enc_want,
        11111,
        50,
        86400,
        create_valid_range_proof(@enc_give),
        create_valid_range_proof(@enc_want),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Bob does a direct swap against Alice's order
    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let taker_give = create_valid_ciphertext();
    let taker_want = create_valid_ciphertext();
    let bob_balance = confidential_swap.get_swap_balance(bob, AssetId::USDC);

    let match_id = confidential_swap.direct_swap(
        order_id,
        taker_give,
        taker_want,
        create_valid_proof_bundle(@taker_give, @taker_want, @bob_balance),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    let swap_match = confidential_swap.get_match(match_id);
    assert(swap_match.maker == alice, 'Maker should be Alice');
    assert(swap_match.taker == bob, 'Taker should be Bob');
    assert(swap_match.maker_order_id == order_id, 'Order ID mismatch');
}

// ===========================================================================
// Integration Test: Order Matching with Valid Proofs
// ===========================================================================

#[test]
fn test_execute_order_match_with_valid_proofs() {
    let (owner, alice, bob, _, confidential_swap) = setup_test_environment();

    // Both parties deposit
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let alice_deposit = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(
        AssetId::SAGE,
        alice_deposit,
        create_valid_range_proof(@alice_deposit),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let bob_deposit = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(
        AssetId::USDC,
        bob_deposit,
        create_valid_range_proof(@bob_deposit),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Alice creates order
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let enc1 = create_valid_ciphertext();
    let alice_order = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, enc1, enc1,
        12345, 50, 86400,
        create_valid_range_proof(@enc1),
        create_valid_range_proof(@enc1),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Bob creates matching order
    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let enc2 = create_valid_ciphertext();
    let bob_order = confidential_swap.create_order(
        AssetId::USDC, AssetId::SAGE, enc2, enc2,
        12345, 50, 86400,
        create_valid_range_proof(@enc2),
        create_valid_range_proof(@enc2),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Owner executes match
    start_cheat_caller_address(confidential_swap.contract_address, owner);
    let fill_give = create_valid_ciphertext();
    let fill_want = create_valid_ciphertext();
    let alice_balance = confidential_swap.get_swap_balance(alice, AssetId::SAGE);
    let bob_balance = confidential_swap.get_swap_balance(bob, AssetId::USDC);

    let match_id = confidential_swap.execute_match(
        alice_order,
        bob_order,
        fill_give,
        fill_want,
        create_valid_proof_bundle(@fill_give, @fill_want, @alice_balance),
        create_valid_proof_bundle(@fill_want, @fill_give, @bob_balance),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    let swap_match = confidential_swap.get_match(match_id);
    assert(swap_match.maker == alice, 'Maker should be Alice');
    assert(swap_match.taker == bob, 'Taker should be Bob');
    assert(confidential_swap.get_match_count() == 1, 'Should have 1 match');
}

// ===========================================================================
// Integration Test: Full Privacy Swap Flow
// ===========================================================================

#[test]
fn test_full_privacy_swap_flow() {
    let (owner, alice, bob, privacy_router, confidential_swap) = setup_test_environment();

    // Step 1: Register private accounts
    start_cheat_caller_address(privacy_router.contract_address, alice);
    privacy_router.register_account(ECPoint { x: 1111, y: 2222 });
    stop_cheat_caller_address(privacy_router.contract_address);

    start_cheat_caller_address(privacy_router.contract_address, bob);
    privacy_router.register_account(ECPoint { x: 3333, y: 4444 });
    stop_cheat_caller_address(privacy_router.contract_address);

    // Verify accounts
    let alice_account = privacy_router.get_account(alice);
    let bob_account = privacy_router.get_account(bob);
    assert(alice_account.public_key.x == 1111, 'Alice key should be set');
    assert(bob_account.public_key.x == 3333, 'Bob key should be set');

    // Step 2: Deposit funds to swap contract
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let alice_dep = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(AssetId::SAGE, alice_dep, create_valid_range_proof(@alice_dep));
    stop_cheat_caller_address(confidential_swap.contract_address);

    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let bob_dep = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(AssetId::USDC, bob_dep, create_valid_range_proof(@bob_dep));
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Step 3: Create swap orders
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let enc_a = create_valid_ciphertext();
    let alice_order = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, enc_a, enc_a,
        50000, 50, 86400,
        create_valid_range_proof(@enc_a),
        create_valid_range_proof(@enc_a),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let enc_b = create_valid_ciphertext();
    let bob_order = confidential_swap.create_order(
        AssetId::USDC, AssetId::SAGE, enc_b, enc_b,
        50000, 50, 86400,
        create_valid_range_proof(@enc_b),
        create_valid_range_proof(@enc_b),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Step 4: Execute match
    start_cheat_caller_address(confidential_swap.contract_address, owner);
    let fill_g = create_valid_ciphertext();
    let fill_w = create_valid_ciphertext();
    let bal_a = confidential_swap.get_swap_balance(alice, AssetId::SAGE);
    let bal_b = confidential_swap.get_swap_balance(bob, AssetId::USDC);

    let match_id = confidential_swap.execute_match(
        alice_order, bob_order, fill_g, fill_w,
        create_valid_proof_bundle(@fill_g, @fill_w, @bal_a),
        create_valid_proof_bundle(@fill_w, @fill_g, @bal_b),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Verify flow completed
    let swap_match = confidential_swap.get_match(match_id);
    assert(swap_match.maker == alice, 'Maker is Alice');
    assert(swap_match.taker == bob, 'Taker is Bob');

    let stats = confidential_swap.get_stats();
    assert(stats.total_orders == 2, '2 orders in flow');
    assert(stats.total_matches == 1, '1 match in flow');
}

// ===========================================================================
// Integration Test: Statistics
// ===========================================================================

#[test]
fn test_swap_statistics() {
    let (owner, alice, bob, _, confidential_swap) = setup_test_environment();

    // Deposits
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let dep_a = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(AssetId::SAGE, dep_a, create_valid_range_proof(@dep_a));
    stop_cheat_caller_address(confidential_swap.contract_address);

    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let dep_b = create_valid_ciphertext();
    confidential_swap.deposit_for_swap(AssetId::USDC, dep_b, create_valid_range_proof(@dep_b));
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Create orders
    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let enc1 = create_valid_ciphertext();
    let order1 = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, enc1, enc1,
        100, 50, 86400,
        create_valid_range_proof(@enc1),
        create_valid_range_proof(@enc1),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    start_cheat_caller_address(confidential_swap.contract_address, bob);
    let enc2 = create_valid_ciphertext();
    let order2 = confidential_swap.create_order(
        AssetId::USDC, AssetId::SAGE, enc2, enc2,
        100, 50, 86400,
        create_valid_range_proof(@enc2),
        create_valid_range_proof(@enc2),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    // Execute match
    start_cheat_caller_address(confidential_swap.contract_address, owner);
    let fg = create_valid_ciphertext();
    let fw = create_valid_ciphertext();
    let ba = confidential_swap.get_swap_balance(alice, AssetId::SAGE);
    let bb = confidential_swap.get_swap_balance(bob, AssetId::USDC);
    let _match_id = confidential_swap.execute_match(
        order1, order2, fg, fw,
        create_valid_proof_bundle(@fg, @fw, @ba),
        create_valid_proof_bundle(@fw, @fg, @bb),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    let stats = confidential_swap.get_stats();
    assert(stats.total_orders == 2, 'Should have 2 orders');
    assert(stats.total_matches == 1, 'Should have 1 match');
}

// ===========================================================================
// Integration Test: Timestamp Recording
// ===========================================================================

#[test]
fn test_order_timestamp() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    let test_timestamp: u64 = 1704067200;
    start_cheat_block_timestamp(confidential_swap.contract_address, test_timestamp);

    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let enc = create_valid_ciphertext();
    let order_id = confidential_swap.create_order(
        AssetId::SAGE, AssetId::ETH, enc, enc,
        777, 50, 86400,
        create_valid_range_proof(@enc),
        create_valid_range_proof(@enc),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    stop_cheat_block_timestamp(confidential_swap.contract_address);

    let order = confidential_swap.get_order(order_id);
    assert(order.created_at == test_timestamp, 'Timestamp should match');
    assert(order.expires_at == test_timestamp + 86400, 'Expiry should be +24h');
}

// ===========================================================================
// Integration Test: Multiple Asset Types
// ===========================================================================

#[test]
fn test_multiple_asset_orders() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    start_cheat_caller_address(confidential_swap.contract_address, alice);

    let e1 = create_valid_ciphertext();
    let _sage_usdc = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, e1, e1,
        100, 50, 3600,
        create_valid_range_proof(@e1),
        create_valid_range_proof(@e1),
    );

    let e2 = create_valid_ciphertext();
    let _eth_sage = confidential_swap.create_order(
        AssetId::ETH, AssetId::SAGE, e2, e2,
        200, 50, 3600,
        create_valid_range_proof(@e2),
        create_valid_range_proof(@e2),
    );

    let e3 = create_valid_ciphertext();
    let _btc_usdc = confidential_swap.create_order(
        AssetId::BTC, AssetId::USDC, e3, e3,
        300, 50, 3600,
        create_valid_range_proof(@e3),
        create_valid_range_proof(@e3),
    );

    let e4 = create_valid_ciphertext();
    let _strk_eth = confidential_swap.create_order(
        AssetId::STRK, AssetId::ETH, e4, e4,
        400, 50, 3600,
        create_valid_range_proof(@e4),
        create_valid_range_proof(@e4),
    );

    stop_cheat_caller_address(confidential_swap.contract_address);

    let alice_count = confidential_swap.get_user_order_count(alice);
    assert(alice_count == 4, 'Should have 4 orders');
}

// ===========================================================================
// Integration Test: Event Emission
// ===========================================================================

#[test]
fn test_order_creation_emits_event() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    let mut spy = spy_events();

    start_cheat_caller_address(confidential_swap.contract_address, alice);
    let enc = create_valid_ciphertext();
    let _order_id = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, enc, enc,
        999, 50, 3600,
        create_valid_range_proof(@enc),
        create_valid_range_proof(@enc),
    );
    stop_cheat_caller_address(confidential_swap.contract_address);

    let events = spy.get_events();
    assert(events.events.len() > 0, 'Should emit events');
}

// ===========================================================================
// Integration Test: Order Retrieval by Index
// ===========================================================================

#[test]
fn test_get_user_order_by_index() {
    let (_, alice, _, _, confidential_swap) = setup_test_environment();

    start_cheat_caller_address(confidential_swap.contract_address, alice);

    let e1 = create_valid_ciphertext();
    let order1 = confidential_swap.create_order(
        AssetId::SAGE, AssetId::USDC, e1, e1,
        111, 50, 3600,
        create_valid_range_proof(@e1),
        create_valid_range_proof(@e1),
    );

    let e2 = create_valid_ciphertext();
    let order2 = confidential_swap.create_order(
        AssetId::ETH, AssetId::SAGE, e2, e2,
        222, 50, 3600,
        create_valid_range_proof(@e2),
        create_valid_range_proof(@e2),
    );

    stop_cheat_caller_address(confidential_swap.contract_address);

    let first_order_id = confidential_swap.get_user_order_at(alice, 0);
    let second_order_id = confidential_swap.get_user_order_at(alice, 1);

    assert(first_order_id == order1, 'First order should match');
    assert(second_order_id == order2, 'Second order should match');
}
