// CIRO Network Governance Module
// Basic proposal and voting mechanisms for decentralized governance

use starknet::ContractAddress;

/// Governance structures
#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct Proposal {
    pub id: u256,
    pub proposer: ContractAddress,
    pub title: felt252,
    pub description: felt252,
    pub proposal_type: ProposalType,
    pub voting_start: u64,
    pub voting_end: u64,
    pub votes_for: u256,
    pub votes_against: u256,
    pub votes_abstain: u256,
    pub executed: bool,
    pub cancelled: bool,
    pub quorum_reached: bool,
}

#[derive(Drop, Serde, starknet::Store, Copy, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum ProposalType {
    Parameter, // Change protocol parameters
    Treasury,  // Treasury fund allocation  
    Upgrade,   // Contract upgrades
    Emergency, // Emergency actions
}

#[derive(Drop, Serde, starknet::Store, Copy)]
#[allow(starknet::store_no_default_variant)]
pub enum VoteChoice {
    For,
    Against,
    Abstain,
}

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct Vote {
    pub voter: ContractAddress,
    pub proposal_id: u256,
    pub choice: VoteChoice,
    pub voting_power: u256,
    pub timestamp: u64,
}

#[derive(Drop, Serde, starknet::Store, Copy)]
pub struct GovernanceConfig {
    pub voting_delay: u64,        // Time before voting starts
    pub voting_period: u64,       // Duration of voting
    pub proposal_threshold: u256, // Min tokens to create proposal
    pub quorum_percentage: u32,   // Required participation (basis points)
    pub execution_delay: u64,     // Time between approval and execution
}

/// Governance Events
#[derive(Drop, starknet::Event)]
pub struct ProposalCreated {
    pub proposal_id: u256,
    pub proposer: ContractAddress,
    pub title: felt252,
    pub voting_start: u64,
    pub voting_end: u64,
}

#[derive(Drop, starknet::Event)]
pub struct VoteCast {
    pub proposal_id: u256,
    pub voter: ContractAddress,
    pub choice: VoteChoice,
    pub voting_power: u256,
    pub reason: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct ProposalExecuted {
    pub proposal_id: u256,
    pub executor: ContractAddress,
    pub execution_result: bool,
}

#[derive(Drop, starknet::Event)]
pub struct ProposalCancelled {
    pub proposal_id: u256,
    pub reason: felt252,
}

#[derive(Drop, starknet::Event)]
pub struct QuorumReached {
    pub proposal_id: u256,
    pub total_votes: u256,
    pub required_quorum: u256,
}

/// Utility functions for governance

/// Calculate voting power multiplier based on holding duration
pub fn calculate_voting_power_multiplier(holding_duration: u64) -> u32 {
    let one_year = 365 * 24 * 3600;
    let two_years = 2 * one_year;
    
    if holding_duration >= two_years {
        150 // 1.5x for 2+ years
    } else if holding_duration >= one_year {
        120 // 1.2x for 1+ year
    } else {
        100 // 1.0x for < 1 year
    }
}

/// Get proposal type name as felt252
pub fn get_proposal_type_name(proposal_type: ProposalType) -> felt252 {
    match proposal_type {
        ProposalType::Parameter => 'parameter',
        ProposalType::Treasury => 'treasury',
        ProposalType::Upgrade => 'upgrade',
        ProposalType::Emergency => 'emergency',
    }
}

/// Check if proposal is currently active
pub fn is_proposal_active(proposal: Proposal, current_time: u64) -> bool {
    !proposal.executed && 
    !proposal.cancelled && 
    current_time >= proposal.voting_start && 
    current_time <= proposal.voting_end
}

/// Calculate proposal voting result
pub fn calculate_proposal_result(votes_for: u256, votes_against: u256, votes_abstain: u256) -> (bool, u32) {
    let total_votes = votes_for + votes_against + votes_abstain;
    if total_votes == 0 {
        return (false, 0);
    }
    
    let approval_rate = ((votes_for * 10000) / total_votes).try_into().unwrap();
    let passed = votes_for > votes_against;
    
    (passed, approval_rate)
}

/// Calculate required quorum for a proposal
pub fn calculate_required_quorum(total_supply: u256, quorum_percentage: u32) -> u256 {
    (total_supply * quorum_percentage.into()) / 10000
}

/// Validate proposal timing parameters
pub fn validate_proposal_timing(voting_delay: u64, voting_period: u64, execution_delay: u64) -> bool {
    let min_voting_period = 3600; // 1 hour minimum
    let max_voting_period = 14 * 24 * 3600; // 14 days maximum
    let min_delay = 0; // No minimum delay for emergency proposals
    let max_delay = 30 * 24 * 3600; // 30 days maximum
    
    voting_period >= min_voting_period &&
    voting_period <= max_voting_period &&
    voting_delay >= min_delay &&
    voting_delay <= max_delay &&
    execution_delay >= min_delay &&
    execution_delay <= max_delay
}

/// Check if address has sufficient voting power for proposal creation
pub fn can_create_proposal(voting_power: u256, threshold: u256) -> bool {
    voting_power >= threshold
}

/// Calculate proposal execution deadline
pub fn calculate_execution_deadline(voting_end: u64, execution_delay: u64) -> u64 {
    voting_end + execution_delay
}

/// Validate vote choice
pub fn is_valid_vote_choice(choice: VoteChoice) -> bool {
    match choice {
        VoteChoice::For => true,
        VoteChoice::Against => true,
        VoteChoice::Abstain => true,
    }
}

/// Get vote choice as felt252 for logging
pub fn get_vote_choice_name(choice: VoteChoice) -> felt252 {
    match choice {
        VoteChoice::For => 'for',
        VoteChoice::Against => 'against',
        VoteChoice::Abstain => 'abstain',
    }
}

/// Check if proposal has enough votes to pass
pub fn has_sufficient_votes(votes_for: u256, votes_against: u256, total_supply: u256, min_approval_rate: u32) -> bool {
    if votes_for <= votes_against {
        return false;
    }
    
    let total_votes = votes_for + votes_against;
    if total_votes == 0 {
        return false;
    }
    
    let approval_rate = ((votes_for * 10000) / total_votes).try_into().unwrap();
    approval_rate >= min_approval_rate
}

/// Calculate governance participation rate
pub fn calculate_participation_rate(total_votes: u256, total_supply: u256) -> u32 {
    if total_supply == 0 {
        return 0;
    }
    
    ((total_votes * 10000) / total_supply).try_into().unwrap()
}

/// Get default governance configuration
pub fn get_default_governance_config() -> GovernanceConfig {
    GovernanceConfig {
        voting_delay: 3600,        // 1 hour
        voting_period: 7 * 24 * 3600, // 7 days
        proposal_threshold: 1000000,  // 1M tokens
        quorum_percentage: 1000,      // 10% (1000 basis points)
        execution_delay: 2 * 24 * 3600, // 2 days
    }
}

/// Validate governance configuration
pub fn validate_governance_config(config: GovernanceConfig) -> bool {
    validate_proposal_timing(config.voting_delay, config.voting_period, config.execution_delay) &&
    config.proposal_threshold > 0 &&
    config.quorum_percentage > 0 &&
    config.quorum_percentage <= 10000 // Max 100%
}

/// Calculate time remaining for proposal phase
pub fn get_time_remaining(current_time: u64, deadline: u64) -> u64 {
    if current_time >= deadline {
        0
    } else {
        deadline - current_time
    }
}

/// Check if proposal is in voting phase
pub fn is_in_voting_phase(proposal: Proposal, current_time: u64) -> bool {
    current_time >= proposal.voting_start && current_time <= proposal.voting_end
}

/// Check if proposal is ready for execution
pub fn is_ready_for_execution(proposal: Proposal, current_time: u64, execution_delay: u64) -> bool {
    !proposal.executed &&
    !proposal.cancelled &&
    current_time > proposal.voting_end &&
    proposal.quorum_reached &&
    proposal.votes_for > proposal.votes_against &&
    current_time >= proposal.voting_end + execution_delay
}

/// Calculate effective voting power with time-based multipliers
pub fn calculate_effective_voting_power(
    base_balance: u256,
    lock_duration: u64,
    reputation_score: u32
) -> u256 {
    let time_multiplier = calculate_voting_power_multiplier(lock_duration);
    let reputation_bonus = if reputation_score > 800 { 110 } else { 100 }; // 10% bonus for high reputation
    
    let enhanced_power = (base_balance * time_multiplier.into()) / 100;
    (enhanced_power * reputation_bonus.into()) / 100
}

/// Governance constants
pub const MIN_PROPOSAL_THRESHOLD: u256 = 100; // Minimum tokens required
pub const MAX_PROPOSAL_THRESHOLD: u256 = 10000000; // Maximum tokens required
pub const MIN_QUORUM_PERCENTAGE: u32 = 100; // 1% minimum
pub const MAX_QUORUM_PERCENTAGE: u32 = 5000; // 50% maximum
pub const EMERGENCY_VOTING_PERIOD: u64 = 3600; // 1 hour for emergency proposals
pub const STANDARD_VOTING_PERIOD: u64 = 7 * 24 * 3600; // 7 days for standard proposals 