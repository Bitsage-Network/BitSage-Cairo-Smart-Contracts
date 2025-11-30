//! Treasury Timelock Integration Tests
//! Tests the complete governance flow between Treasury Timelock and Governance Treasury

use starknet::{ContractAddress, contract_address_const, get_block_timestamp};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address, stop_cheat_caller_address, start_cheat_block_timestamp, stop_cheat_block_timestamp};

use ciro_contracts::vesting::treasury_timelock::{
    ITreasuryTimelockDispatcher, ITreasuryTimelockDispatcherTrait
};
use ciro_contracts::governance::governance_treasury::{
    IGovernanceTreasuryDispatcher, IGovernanceTreasuryDispatcherTrait
};

// Test addresses
fn admin() -> ContractAddress {
    contract_address_const::<'admin'>()
}

fn multisig_member_1() -> ContractAddress {
    contract_address_const::<'member1'>()
}

fn multisig_member_2() -> ContractAddress {
    contract_address_const::<'member2'>()
}

fn emergency_member() -> ContractAddress {
    contract_address_const::<'emergency'>()
}

fn treasury_address() -> ContractAddress {
    contract_address_const::<'treasury'>()
}

fn token_address() -> ContractAddress {
    contract_address_const::<'token'>()
}

// Helper function to deploy Treasury Timelock
fn deploy_treasury_timelock() -> ITreasuryTimelockDispatcher {
    let contract = declare("TreasuryTimelock").unwrap().contract_class();
    
    // Prepare constructor arguments
    let mut multisig_members = ArrayTrait::new();
    multisig_members.append(admin());
    multisig_members.append(multisig_member_1());
    multisig_members.append(multisig_member_2());
    
    let mut emergency_members = ArrayTrait::new();
    emergency_members.append(admin());
    emergency_members.append(emergency_member());
    
    let threshold: u32 = 2;
    let timelock_delay: u64 = 86400; // 24 hours
    
    let mut constructor_calldata = ArrayTrait::new();
    
    // Serialize multisig_members array
    constructor_calldata.append(multisig_members.len().into());
    let mut i = 0;
    loop {
        if i >= multisig_members.len() {
            break;
        }
        constructor_calldata.append((*multisig_members.at(i)).into());
        i += 1;
    };
    
    // Add threshold, timelock_delay, admin
    constructor_calldata.append(threshold.into());
    constructor_calldata.append(timelock_delay.into());
    constructor_calldata.append(admin().into());
    
    // Serialize emergency_members array
    constructor_calldata.append(emergency_members.len().into());
    let mut j = 0;
    loop {
        if j >= emergency_members.len() {
            break;
        }
        constructor_calldata.append((*emergency_members.at(j)).into());
        j += 1;
    };
    
    let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    ITreasuryTimelockDispatcher { contract_address }
}

// Helper function to deploy Governance Treasury
fn deploy_governance_treasury() -> IGovernanceTreasuryDispatcher {
    let contract = declare("GovernanceTreasury").unwrap().contract_class();
    
    let mut constructor_calldata = ArrayTrait::new();
    constructor_calldata.append(admin().into());
    constructor_calldata.append(token_address().into());
    
    let (contract_address, _) = contract.deploy(@constructor_calldata).unwrap();
    IGovernanceTreasuryDispatcher { contract_address }
}

#[test]
fn test_treasury_timelock_deployment() {
    let timelock = deploy_treasury_timelock();
    
    // Test basic configuration
    assert(timelock.get_required_approvals() == 2, 'Wrong threshold');
    assert(timelock.is_multisig_member(admin()), 'Admin not member');
    assert(timelock.is_multisig_member(multisig_member_1()), 'Member1 not in');
    assert(timelock.is_multisig_member(multisig_member_2()), 'Member2 not in');
    assert(!timelock.is_paused(), 'Should not pause');
}

#[test]
fn test_propose_transaction() {
    let timelock = deploy_treasury_timelock();
    
    // Test proposing a transaction as multisig member
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000; // 1 token
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test treasury transfer';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    
    assert(tx_id == 1, 'Wrong transaction ID');
    
    let tx = timelock.get_transaction(tx_id);
    assert(tx.tx_id == 1, 'Wrong tx ID in struct');
    assert(tx.proposer == admin(), 'Wrong proposer');
    assert(tx.target == target, 'Wrong target');
    assert(tx.value == value, 'Wrong value');
    assert(tx.description == description, 'Wrong description');
    assert(tx.approvals == 1, 'Wrong initial approvals');
    assert(!tx.executed, 'Not executed');
    assert(!tx.cancelled, 'Not cancelled');
    
    stop_cheat_caller_address(timelock.contract_address);
}

#[test]
fn test_approve_transaction() {
    let timelock = deploy_treasury_timelock();
    
    // Propose transaction as admin
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test treasury transfer';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Approve as different multisig member
    start_cheat_caller_address(timelock.contract_address, multisig_member_1());
    timelock.approve_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    let tx = timelock.get_transaction(tx_id);
    assert(tx.approvals == 2, 'Wrong approval count');
    
    // Check that the transaction can now be executed (after timelock)
    assert(timelock.can_execute(tx_id) == false, 'Not executable yet'); // Timelock not expired
}

#[test]
fn test_execute_transaction_after_timelock() {
    let timelock = deploy_treasury_timelock();
    
    // Propose and approve transaction
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test treasury transfer';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Get second approval
    start_cheat_caller_address(timelock.contract_address, multisig_member_1());
    timelock.approve_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Fast forward time past timelock delay
    let current_time = get_block_timestamp();
    let future_time = current_time + 86400 + 1; // 24 hours + 1 second
    start_cheat_block_timestamp(timelock.contract_address, future_time);
    
    // Now should be executable
    assert(timelock.can_execute(tx_id), 'Should execute');
    
    // Execute the transaction
    start_cheat_caller_address(timelock.contract_address, admin());
    timelock.execute_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    let tx = timelock.get_transaction(tx_id);
    assert(tx.executed, 'Should execute');
    
    stop_cheat_block_timestamp(timelock.contract_address);
}

#[test]
fn test_cancel_transaction() {
    let timelock = deploy_treasury_timelock();
    
    // Propose transaction
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test treasury transfer';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    
    // Cancel the transaction
    timelock.cancel_transaction(tx_id);
    
    let tx = timelock.get_transaction(tx_id);
    assert(tx.cancelled, 'Should cancel');
    assert(!timelock.can_execute(tx_id), 'Not executable');
    
    stop_cheat_caller_address(timelock.contract_address);
}

#[test]
fn test_emergency_pause() {
    let timelock = deploy_treasury_timelock();
    
    // Test emergency pause
    start_cheat_caller_address(timelock.contract_address, admin());
    timelock.emergency_pause('Security incident');
    
    assert(timelock.is_paused(), 'Should pause');
    
    // Test unpause
    timelock.emergency_unpause();
    assert(!timelock.is_paused(), 'Should unpause');
    
    stop_cheat_caller_address(timelock.contract_address);
}

#[test]
fn test_multisig_member_management() {
    let timelock = deploy_treasury_timelock();
    
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let new_member = contract_address_const::<'new_member'>();
    
    // Add new multisig member
    timelock.add_multisig_member(new_member);
    assert(timelock.is_multisig_member(new_member), 'Member not added');
    
    // Remove multisig member
    timelock.remove_multisig_member(new_member);
    assert(!timelock.is_multisig_member(new_member), 'Not removed');
    
    stop_cheat_caller_address(timelock.contract_address);
}

#[test]
fn test_treasury_timelock_governance_integration() {
    let timelock = deploy_treasury_timelock();
    let treasury = deploy_governance_treasury();
    
    // Test scenario: Timelock proposes to update treasury configuration
    start_cheat_caller_address(timelock.contract_address, admin());
    
    // Propose a treasury operation through timelock
    let target = treasury.contract_address;
    let value: u256 = 0; // No value transfer, just function call
    let mut data = ArrayTrait::new();
    data.append('update_fee_rate'); // Mock function call data
    data.append(250); // 2.5% fee rate
    let description = 'Update treasury fee rate';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Get approval from second multisig member
    start_cheat_caller_address(timelock.contract_address, multisig_member_1());
    timelock.approve_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Fast forward past timelock delay
    let current_time = get_block_timestamp();
    let future_time = current_time + 86400 + 1;
    start_cheat_block_timestamp(timelock.contract_address, future_time);
    
    // Verify transaction is ready for execution
    assert(timelock.can_execute(tx_id), 'Should execute');
    
    // Execute the treasury operation
    start_cheat_caller_address(timelock.contract_address, admin());
    timelock.execute_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    let tx = timelock.get_transaction(tx_id);
    assert(tx.executed, 'Should execute');
    
    stop_cheat_block_timestamp(timelock.contract_address);
}

#[test]
fn test_pending_transactions_list() {
    let timelock = deploy_treasury_timelock();
    
    start_cheat_caller_address(timelock.contract_address, admin());
    
    // Propose multiple transactions
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    
    let _tx_id_1 = timelock.propose_transaction(target, value, data.clone(), 'Transaction 1');
    let tx_id_2 = timelock.propose_transaction(target, value, data.clone(), 'Transaction 2');
    let _tx_id_3 = timelock.propose_transaction(target, value, data.clone(), 'Transaction 3');
    
    // Cancel one transaction
    timelock.cancel_transaction(tx_id_2);
    
    let pending_txs = timelock.get_pending_transactions();
    assert(pending_txs.len() == 2, 'Wrong pending count');
    
    // Check that cancelled transaction is not in pending list
    let mut found_cancelled = false;
    let mut i = 0;
    loop {
        if i >= pending_txs.len() {
            break;
        }
        if *pending_txs.at(i) == tx_id_2 {
            found_cancelled = true;
            break;
        }
        i += 1;
    };
    assert(!found_cancelled, 'Found cancelled');
    
    stop_cheat_caller_address(timelock.contract_address);
}

#[test]
#[should_panic(expected: ('Only multisig',))]
fn test_unauthorized_proposal() {
    let timelock = deploy_treasury_timelock();
    
    let unauthorized = contract_address_const::<'unauthorized'>();
    start_cheat_caller_address(timelock.contract_address, unauthorized);
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Unauthorized proposal';
    
    // This should panic
    timelock.propose_transaction(target, value, data, description);
}

#[test]
#[should_panic(expected: ('Already approved',))]
fn test_double_approval() {
    let timelock = deploy_treasury_timelock();
    
    // Propose transaction
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test transaction';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    
    // Try to approve the same transaction twice as the same member
    // This should panic
    timelock.approve_transaction(tx_id);
}

#[test]
#[should_panic(expected: ('Timelock not expired',))]
fn test_premature_execution() {
    let timelock = deploy_treasury_timelock();
    
    // Propose and approve transaction
    start_cheat_caller_address(timelock.contract_address, admin());
    
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test transaction';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Get second approval
    start_cheat_caller_address(timelock.contract_address, multisig_member_1());
    timelock.approve_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Try to execute immediately (before timelock expires)
    start_cheat_caller_address(timelock.contract_address, admin());
    
    // This should panic
    timelock.execute_transaction(tx_id);
}

#[test]
fn test_timelock_delay_configuration() {
    let timelock = deploy_treasury_timelock();
    
    start_cheat_caller_address(timelock.contract_address, admin());
    
    // Update timelock delay
    let new_delay: u64 = 172800; // 48 hours
    timelock.update_timelock_delay(new_delay);
    
    // Propose a new transaction to test new delay
    let target = treasury_address();
    let value: u256 = 1000000000000000000;
    let mut data = ArrayTrait::new();
    data.append('transfer_call');
    let description = 'Test new delay';
    
    let tx_id = timelock.propose_transaction(target, value, data, description);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Get second approval
    start_cheat_caller_address(timelock.contract_address, multisig_member_1());
    timelock.approve_transaction(tx_id);
    stop_cheat_caller_address(timelock.contract_address);
    
    // Fast forward by old delay (24 hours) - should not be executable
    let current_time = get_block_timestamp();
    let old_delay_time = current_time + 86400 + 1;
    start_cheat_block_timestamp(timelock.contract_address, old_delay_time);
    
    assert(!timelock.can_execute(tx_id), 'Old delay fails');
    
    // Fast forward by new delay (48 hours) - should be executable
    let new_delay_time = current_time + 172800 + 1;
    start_cheat_block_timestamp(timelock.contract_address, new_delay_time);
    
    assert(timelock.can_execute(tx_id), 'New delay works');
    
    stop_cheat_block_timestamp(timelock.contract_address);
}