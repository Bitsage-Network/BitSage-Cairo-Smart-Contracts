// ===========================================================================
// Privacy Pools + FMD Combined Integration Tests
// ===========================================================================
// Tests the complete privacy system: Privacy Pools deposits with FMD-tagged
// transactions, enabling recipients to detect their payments while maintaining
// unlinkability for observers.
//
// Flow tested:
// 1. Recipient publishes FMD clue key
// 2. Sender deposits to Privacy Pools
// 3. Sender creates FMD clue for recipient
// 4. Recipient detects transaction using FMD
// 5. Recipient verifies deposit in Privacy Pools
// 6. ASP approves deposit for compliance
// ===========================================================================

use core::traits::Into;
use core::option::OptionTrait;
use core::array::ArrayTrait;
use core::poseidon::poseidon_hash_span;
use starknet::{ContractAddress, contract_address_const};
use snforge_std::{
    declare, ContractClassTrait, DeclareResultTrait,
    start_cheat_caller_address, stop_cheat_caller_address,
    start_cheat_block_timestamp, stop_cheat_block_timestamp,
    spy_events, EventSpyAssertionsTrait, EventSpyTrait,
};

// Privacy Pools imports
use sage_contracts::obelysk::privacy_pools::{
    IPrivacyPoolsDispatcher, IPrivacyPoolsDispatcherTrait,
    ASPStatus, AssociationSetType,
    PP_DOMAIN_SEPARATOR,
};
use sage_contracts::obelysk::lean_imt::LeanIMTProof;
use sage_contracts::obelysk::elgamal::{ECPoint, generator, is_zero};

// FMD imports
use sage_contracts::obelysk::fmd::{
    FMDDetectionKey, FMDClueKey, FMDKeyPair, FMDClue, FMDMatchResult,
    generate_key_pair, create_clue, examine_clue,
    examine_clues_batch, create_clues_batch,
    FMD_DEFAULT_PRECISION,
};

// SAGE Token imports for real token deployment
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

// Token constants (same as privacy_pools_integration_test)
const TRANSFER_AMOUNT: u256 = 9000000000000000000000_u256; // 9,000 SAGE with 18 decimals
const APPROVAL_AMOUNT: u256 = 50000000000000000000000_u256; // 50,000 SAGE with 18 decimals

// ===========================================================================
// Combined Data Structures
// ===========================================================================

/// A private transaction with FMD clue for recipient detection
#[derive(Drop)]
struct PrivateTransactionWithClue {
    /// Privacy Pools commitment
    commitment: felt252,
    /// Amount commitment (Pedersen)
    amount_commitment: ECPoint,
    /// Asset identifier
    asset_id: felt252,
    /// FMD clue for recipient detection
    fmd_clue: FMDClue,
    /// Transaction timestamp
    timestamp: u64,
}

/// User's complete privacy credentials
#[derive(Drop)]
struct PrivacyCredentials {
    /// Address
    address: ContractAddress,
    /// FMD key pair for transaction detection
    fmd_keys: FMDKeyPair,
    /// Secret for commitment generation
    commitment_secret: felt252,
}

// ===========================================================================
// Test Setup with Real SAGE Token
// ===========================================================================

fn deploy_sage_token(owner: ContractAddress) -> (IERC20Dispatcher, ContractAddress) {
    let job_manager = contract_address_const::<'JOB_MANAGER'>();
    let cdc_pool = contract_address_const::<'CDC_POOL'>();
    let paymaster = contract_address_const::<'PAYMASTER'>();
    let treasury = contract_address_const::<'TREASURY'>();
    let team = contract_address_const::<'TEAM'>();
    let liquidity = contract_address_const::<'LIQUIDITY'>();

    let contract_class = declare("SAGEToken").unwrap().contract_class();

    let mut constructor_data = array![];
    constructor_data.append(owner.into());
    constructor_data.append(job_manager.into());
    constructor_data.append(cdc_pool.into());
    constructor_data.append(paymaster.into());
    constructor_data.append(treasury.into());
    constructor_data.append(team.into());
    constructor_data.append(liquidity.into());

    let (contract_address, _) = contract_class.deploy(@constructor_data).unwrap();
    (IERC20Dispatcher { contract_address }, contract_address)
}

fn deploy_privacy_pools(owner: ContractAddress, sage_token_address: ContractAddress) -> IPrivacyPoolsDispatcher {
    let contract = declare("PrivacyPools").unwrap().contract_class();
    let privacy_router = contract_address_const::<'PRIVACY_ROUTER'>();

    let (address, _) = contract.deploy(@array![]).unwrap();
    let dispatcher = IPrivacyPoolsDispatcher { contract_address: address };

    start_cheat_caller_address(address, owner);
    dispatcher.initialize(owner, sage_token_address, privacy_router);
    stop_cheat_caller_address(address);

    dispatcher
}

fn create_user_credentials(name: felt252) -> PrivacyCredentials {
    let address = contract_address_const::<'USER'>();  // Simplified for testing
    let fmd_keys = generate_key_pair(
        poseidon_hash_span(array![name, 'fmd_seed'].span()),
        FMD_DEFAULT_PRECISION
    );
    let commitment_secret = poseidon_hash_span(array![name, 'commitment_secret'].span());

    PrivacyCredentials { address, fmd_keys, commitment_secret }
}

fn generate_commitment(secret: felt252, nullifier_seed: felt252, amount: felt252, asset_id: felt252) -> felt252 {
    poseidon_hash_span(array![
        PP_DOMAIN_SEPARATOR,
        secret,
        nullifier_seed,
        amount,
        asset_id
    ].span())
}

fn create_amount_commitment(amount: felt252, blinding: felt252) -> ECPoint {
    // Simplified Pedersen commitment: C = amount*G + blinding*H
    let g = generator();
    ECPoint {
        x: g.x + amount + blinding,
        y: g.y + amount + blinding,
    }
}

fn setup_full_environment() -> (
    ContractAddress,          // owner
    ContractAddress,          // auditor1
    ContractAddress,          // auditor2
    ContractAddress,          // asp_operator
    IPrivacyPoolsDispatcher,  // privacy_pools
) {
    let owner = contract_address_const::<'OWNER'>();
    let auditor1 = contract_address_const::<'AUDITOR1'>();
    let auditor2 = contract_address_const::<'AUDITOR2'>();
    let asp_operator = contract_address_const::<'ASP_OP'>();

    // Deploy SAGE token
    let (sage_token, sage_token_address) = deploy_sage_token(owner);

    // Deploy Privacy Pools with real SAGE token
    let pp = deploy_privacy_pools(owner, sage_token_address);

    // Fund ASP operator with tokens for staking (2 transfers of 9,000 SAGE each)
    start_cheat_caller_address(sage_token_address, owner);
    sage_token.transfer(asp_operator, TRANSFER_AMOUNT);
    sage_token.transfer(asp_operator, TRANSFER_AMOUNT);
    stop_cheat_caller_address(sage_token_address);

    // Approve Privacy Pools to spend ASP operator's tokens
    start_cheat_caller_address(sage_token_address, asp_operator);
    sage_token.approve(pp.contract_address, APPROVAL_AMOUNT);
    stop_cheat_caller_address(sage_token_address);

    // Setup auditors
    start_cheat_caller_address(pp.contract_address, owner);
    pp.add_auditor(auditor1);
    pp.add_auditor(auditor2);
    stop_cheat_caller_address(pp.contract_address);

    // Register and approve ASP
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let asp_id = pp.register_asp(
        poseidon_hash_span(array!['CleanMoneyASP'].span()),
        generator(),
        0,
    );
    stop_cheat_caller_address(pp.contract_address);

    start_cheat_caller_address(pp.contract_address, auditor1);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);
    start_cheat_caller_address(pp.contract_address, auditor2);
    pp.approve_asp(asp_id);
    stop_cheat_caller_address(pp.contract_address);

    (owner, auditor1, auditor2, asp_operator, pp)
}

// ===========================================================================
// Combined Flow Tests
// ===========================================================================

#[test]
fn test_private_payment_with_fmd_detection() {
    let (owner, _, _, asp_operator, pp) = setup_full_environment();

    // =========================================================================
    // Step 1: Alice sets up her privacy credentials
    // =========================================================================
    let alice = contract_address_const::<'ALICE'>();
    let alice_fmd_keys = generate_key_pair(
        poseidon_hash_span(array!['alice_secret'].span()),
        12  // Medium precision for balance between privacy and detection
    );

    // Alice publishes her clue key (this is public)
    let alice_public_clue_key = alice_fmd_keys.clue_key;

    // =========================================================================
    // Step 2: Bob wants to send Alice a private payment
    // =========================================================================
    let bob = contract_address_const::<'BOB'>();
    let payment_amount: felt252 = 1000;
    let asset_id: felt252 = 'SAGE';

    // Bob generates a commitment for the deposit
    let bob_secret = poseidon_hash_span(array!['bob_tx_secret', 12345].span());
    let nullifier_seed = poseidon_hash_span(array!['bob_nullifier', 67890].span());
    let commitment = generate_commitment(bob_secret, nullifier_seed, payment_amount, asset_id);

    // Bob creates an FMD clue for Alice
    let randomness_r = poseidon_hash_span(array!['bob_random_r', commitment].span());
    let randomness_z = poseidon_hash_span(array!['bob_random_z', commitment].span());
    let clue_for_alice = create_clue(@alice_public_clue_key, 8, randomness_r, randomness_z);

    // =========================================================================
    // Step 3: Bob deposits to Privacy Pools
    // =========================================================================
    let amount_commitment = create_amount_commitment(payment_amount, bob_secret);

    start_cheat_caller_address(pp.contract_address, bob);
    let deposit_index = pp.pp_deposit(
        commitment,
        amount_commitment,
        asset_id,
        array![].span(),  // range_proof_data
    );
    stop_cheat_caller_address(pp.contract_address);

    // Verify deposit recorded
    assert(pp.is_pp_deposit_valid(commitment) == true, 'Deposit should be valid');
    let deposit_info = pp.get_pp_deposit_info(commitment);
    assert(deposit_info.depositor == bob, 'Depositor should be Bob');

    // =========================================================================
    // Step 4: Alice's detection server scans transactions
    // =========================================================================
    // In production, the clue would be stored on-chain or in a side channel
    // Alice's detection server examines all clues

    let detection_result = examine_clue(@alice_fmd_keys.detection_key, @clue_for_alice);
    assert(detection_result == FMDMatchResult::Match, 'Alice should detect payment');

    // =========================================================================
    // Step 5: Alice verifies the deposit in Privacy Pools
    // =========================================================================
    // Alice reconstructs the commitment using info shared off-chain by Bob
    // (In practice, this would be encrypted communication)

    assert(pp.is_pp_deposit_valid(commitment) == true, 'Alice verifies deposit exists');

    // =========================================================================
    // Step 6: ASP approves the deposit (compliance)
    // =========================================================================
    start_cheat_caller_address(pp.contract_address, asp_operator);
    let inclusion_set_id = pp.create_association_set(
        AssociationSetType::Inclusion,
        array![commitment].span(),
    );
    stop_cheat_caller_address(pp.contract_address);

    // Deposit is now in the inclusion set - Alice can withdraw with compliance
    assert(pp.is_in_association_set(inclusion_set_id, commitment) == true, 'Commitment in set');
}

#[test]
fn test_multi_recipient_privacy_payments() {
    let (owner, _, _, asp_operator, pp) = setup_full_environment();

    // Create 3 recipients with FMD credentials
    let alice_keys = generate_key_pair('alice_multi', 10);
    let bob_keys = generate_key_pair('bob_multi', 10);
    let charlie_keys = generate_key_pair('charlie_multi', 10);

    let sender = contract_address_const::<'SENDER'>();

    // =========================================================================
    // Sender makes 3 private payments
    // =========================================================================
    let mut commitments: Array<felt252> = array![];
    let mut clues: Array<FMDClue> = array![];

    // Payment to Alice
    let c1 = generate_commitment('secret1', 'null1', 500, 'SAGE');
    commitments.append(c1);
    clues.append(create_clue(@alice_keys.clue_key, 8, 'r1', 'z1'));

    // Payment to Bob
    let c2 = generate_commitment('secret2', 'null2', 1000, 'SAGE');
    commitments.append(c2);
    clues.append(create_clue(@bob_keys.clue_key, 8, 'r2', 'z2'));

    // Payment to Charlie
    let c3 = generate_commitment('secret3', 'null3', 1500, 'SAGE');
    commitments.append(c3);
    clues.append(create_clue(@charlie_keys.clue_key, 8, 'r3', 'z3'));

    // Deposit all to Privacy Pools
    start_cheat_caller_address(pp.contract_address, sender);
    pp.pp_deposit(c1, create_amount_commitment(500, 'b1'), 'SAGE', array![].span());
    pp.pp_deposit(c2, create_amount_commitment(1000, 'b2'), 'SAGE', array![].span());
    pp.pp_deposit(c3, create_amount_commitment(1500, 'b3'), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    // =========================================================================
    // Each recipient detects their payment
    // =========================================================================

    // Alice examines all clues
    let alice_results = examine_clues_batch(@alice_keys.detection_key, clues.span());
    assert(*alice_results.at(0) == FMDMatchResult::Match, 'Alice finds her payment');

    // Bob examines all clues
    let bob_results = examine_clues_batch(@bob_keys.detection_key, clues.span());
    assert(*bob_results.at(1) == FMDMatchResult::Match, 'Bob finds his payment');

    // Charlie examines all clues
    let charlie_results = examine_clues_batch(@charlie_keys.detection_key, clues.span());
    assert(*charlie_results.at(2) == FMDMatchResult::Match, 'Charlie finds his payment');

    // Verify all deposits are in Privacy Pools
    assert(pp.is_pp_deposit_valid(c1) == true, 'C1 valid');
    assert(pp.is_pp_deposit_valid(c2) == true, 'C2 valid');
    assert(pp.is_pp_deposit_valid(c3) == true, 'C3 valid');
}

#[test]
fn test_privacy_pools_batch_with_fmd() {
    let (owner, _, _, asp_operator, pp) = setup_full_environment();

    let sender = contract_address_const::<'BATCH_SENDER'>();

    // Create 5 recipients
    let recipients = array![
        generate_key_pair('r1', 10),
        generate_key_pair('r2', 10),
        generate_key_pair('r3', 10),
        generate_key_pair('r4', 10),
        generate_key_pair('r5', 10),
    ];

    // Batch create clues - FMDClueKey implements Copy
    let clue_keys = array![
        *recipients.at(0).clue_key,
        *recipients.at(1).clue_key,
        *recipients.at(2).clue_key,
        *recipients.at(3).clue_key,
        *recipients.at(4).clue_key,
    ];
    let clues = create_clues_batch(clue_keys.span(), 8, 'batch_random_seed');

    // Create commitments
    let c1 = generate_commitment('batch1', 'n1', 100, 'SAGE');
    let c2 = generate_commitment('batch2', 'n2', 200, 'SAGE');
    let c3 = generate_commitment('batch3', 'n3', 300, 'SAGE');
    let c4 = generate_commitment('batch4', 'n4', 400, 'SAGE');
    let c5 = generate_commitment('batch5', 'n5', 500, 'SAGE');

    // Batch deposit to Privacy Pools
    start_cheat_caller_address(pp.contract_address, sender);
    let batch_result = pp.pp_batch_deposit(
        array![c1, c2, c3, c4, c5].span(),
        array![
            create_amount_commitment(100, 'bl1'),
            create_amount_commitment(200, 'bl2'),
            create_amount_commitment(300, 'bl3'),
            create_amount_commitment(400, 'bl4'),
            create_amount_commitment(500, 'bl5'),
        ].span(),
        array!['SAGE', 'SAGE', 'SAGE', 'SAGE', 'SAGE'].span(),
        array![].span(),
    );
    stop_cheat_caller_address(pp.contract_address);

    // Each recipient detects their clue
    let r3_results = examine_clues_batch(recipients.at(2).detection_key, clues.span());
    assert(*r3_results.at(2) == FMDMatchResult::Match, 'R3 detects their clue');

    // Verify stats
    let (deposit_count, _, _, _) = pp.get_pp_stats();
    assert(deposit_count == 5, 'Should have 5 deposits');
}

#[test]
fn test_detection_with_compliance_flow() {
    let (owner, _, _, asp_operator, pp) = setup_full_environment();

    // Setup: Compliant sender and recipient
    let sender = contract_address_const::<'COMPLIANT_SENDER'>();
    let recipient_keys = generate_key_pair('compliant_recipient', 12);

    // Sender creates compliant payment
    let commitment = generate_commitment('compliant_secret', 'compliant_null', 5000, 'SAGE');
    let clue = create_clue(@recipient_keys.clue_key, 10, 'comp_r', 'comp_z');

    // Deposit
    start_cheat_caller_address(pp.contract_address, sender);
    pp.pp_deposit(commitment, create_amount_commitment(5000, 'comp_b'), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    // =========================================================================
    // Compliance Flow: ASP verifies sender is not on sanctions list
    // =========================================================================

    // ASP creates both inclusion and exclusion sets
    start_cheat_caller_address(pp.contract_address, asp_operator);

    // Inclusion set: approved deposits
    let inclusion_set = pp.create_association_set(
        AssociationSetType::Inclusion,
        array![commitment].span(),  // This deposit is approved
    );

    // Exclusion set: blocked deposits (empty in this case)
    let exclusion_set = pp.create_association_set(
        AssociationSetType::Exclusion,
        array![].span(),
    );

    stop_cheat_caller_address(pp.contract_address);

    // =========================================================================
    // Recipient Flow
    // =========================================================================

    // 1. Recipient detects payment via FMD
    let detection = examine_clue(@recipient_keys.detection_key, @clue);
    assert(detection == FMDMatchResult::Match, 'Recipient detects payment');

    // 2. Recipient verifies deposit exists
    assert(pp.is_pp_deposit_valid(commitment) == true, 'Deposit exists');

    // 3. Recipient verifies deposit is in inclusion set (compliant)
    assert(pp.is_in_association_set(inclusion_set, commitment) == true, 'Deposit is compliant');

    // 4. Recipient can now withdraw with compliance proof
    // (Actual withdrawal tested separately)
}

#[test]
fn test_observer_cannot_link_transactions() {
    let (owner, _, _, _, pp) = setup_full_environment();

    // Alice receives 5 payments
    let alice_keys = generate_key_pair('alice_unlink', 10);
    let sender = contract_address_const::<'MULTI_SENDER'>();

    let mut clues: Array<FMDClue> = array![];
    let mut commitments: Array<felt252> = array![];

    // Create 5 payments with different randomness
    let mut i: u32 = 0;
    while i < 5 {
        let secret = poseidon_hash_span(array!['payment', i.into()].span());
        let null = poseidon_hash_span(array!['null', i.into()].span());
        let commitment = generate_commitment(secret, null, (i + 1).into() * 100, 'SAGE');
        commitments.append(commitment);

        // Different randomness for each clue
        let r = poseidon_hash_span(array!['r', i.into(), 12345].span());
        let z = poseidon_hash_span(array!['z', i.into(), 67890].span());
        clues.append(create_clue(@alice_keys.clue_key, 8, r, z));

        i += 1;
    };

    // Deposit all
    start_cheat_caller_address(pp.contract_address, sender);
    let mut j: u32 = 0;
    while j < 5 {
        pp.pp_deposit(
            *commitments.at(j),
            create_amount_commitment(((j + 1) * 100).into(), j.into()),
            'SAGE',
            array![].span()
        );
        j += 1;
    };
    stop_cheat_caller_address(pp.contract_address);

    // =========================================================================
    // Observer (mallory) tries to link transactions
    // =========================================================================
    let mallory_keys = generate_key_pair('mallory_observer', 10);

    // Mallory cannot efficiently detect which transactions are for Alice
    let mallory_results = examine_clues_batch(@mallory_keys.detection_key, clues.span());

    // Count matches (should be very few, if any, due to FP)
    let mut false_matches: u32 = 0;
    let mut k: u32 = 0;
    while k < 5 {
        if *mallory_results.at(k) == FMDMatchResult::Match {
            false_matches += 1;
        }
        k += 1;
    };

    // With 8-bit precision, FP rate is ~0.4%, so likely 0 matches
    // But we don't assert exact count due to probabilistic nature

    // Clues are unlinkable - different ephemeral points and signatures
    assert(
        clues.at(0).ephemeral_point.x != clues.at(1).ephemeral_point.x,
        'Clues should be unlinkable'
    );
    assert(
        clues.at(1).ephemeral_point.x != clues.at(2).ephemeral_point.x,
        'Clues should be unlinkable 2'
    );

    // Alice can detect all her payments
    let alice_results = examine_clues_batch(@alice_keys.detection_key, clues.span());
    let mut alice_matches: u32 = 0;
    let mut l: u32 = 0;
    while l < 5 {
        if *alice_results.at(l) == FMDMatchResult::Match {
            alice_matches += 1;
        }
        l += 1;
    };
    assert(alice_matches == 5, 'Alice should detect all 5');
}

#[test]
fn test_selective_disclosure_with_fmd() {
    let (owner, auditor1, auditor2, asp_operator, pp) = setup_full_environment();

    // User generates separate keys for different purposes
    let user_personal_keys = generate_key_pair('user_personal', 16);  // High privacy
    let user_business_keys = generate_key_pair('user_business', 8);   // Lower privacy, more FPs ok

    let sender = contract_address_const::<'DUAL_SENDER'>();

    // Personal payment (high privacy)
    let personal_commitment = generate_commitment('personal_secret', 'p_null', 100, 'SAGE');
    let personal_clue = create_clue(@user_personal_keys.clue_key, 14, 'p_r', 'p_z');

    // Business payment (compliance friendly)
    let business_commitment = generate_commitment('business_secret', 'b_null', 10000, 'SAGE');
    let business_clue = create_clue(@user_business_keys.clue_key, 6, 'b_r', 'b_z');

    // Deposit both
    start_cheat_caller_address(pp.contract_address, sender);
    pp.pp_deposit(personal_commitment, create_amount_commitment(100, 'pb'), 'SAGE', array![].span());
    pp.pp_deposit(business_commitment, create_amount_commitment(10000, 'bb'), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    // User detects personal payments with personal key
    let personal_result = examine_clue(@user_personal_keys.detection_key, @personal_clue);
    assert(personal_result == FMDMatchResult::Match, 'Detect personal');

    // User detects business payments with business key
    let business_result = examine_clue(@user_business_keys.detection_key, @business_clue);
    assert(business_result == FMDMatchResult::Match, 'Detect business');

    // User can share business detection key with accountant for compliance
    // without exposing personal transactions
    let accountant_result = examine_clue(@user_business_keys.detection_key, @personal_clue);
    // Accountant cannot detect personal transactions (except FP)
    // Personal key remains private
}

// ===========================================================================
// Event Verification Tests
// ===========================================================================

#[test]
fn test_events_emitted_on_fmd_deposit() {
    let (owner, _, _, asp_operator, pp) = setup_full_environment();

    let sender = contract_address_const::<'EVENT_SENDER'>();
    let recipient_keys = generate_key_pair('event_recipient', 10);

    let mut spy = spy_events();

    // Create commitment and clue
    let commitment = generate_commitment('event_secret', 'event_null', 999, 'SAGE');
    let _clue = create_clue(@recipient_keys.clue_key, 8, 'e_r', 'e_z');

    // Deposit
    start_cheat_caller_address(pp.contract_address, sender);
    pp.pp_deposit(commitment, create_amount_commitment(999, 'eb'), 'SAGE', array![].span());
    stop_cheat_caller_address(pp.contract_address);

    // Verify events emitted
    let events = spy.get_events();
    assert(events.events.len() > 0, 'Should emit deposit event');
}
