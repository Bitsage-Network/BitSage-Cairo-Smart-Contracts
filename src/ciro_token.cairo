// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 CIRO Network Foundation
//
// This file is part of CIRO Network.
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//     https://github.com/Ciro-AI-Labs/ciro-network/blob/main/LICENSE-BSL
//
// Change Date: January 1, 2029
// Change License: Apache License, Version 2.0
//
// For more information see: https://github.com/Ciro-AI-Labs/ciro-network/blob/main/WHY_BSL_FOR_CIRO.md

#[starknet::contract]
pub mod CIROToken {
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp
    };
    // Add the missing storage access traits
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::traits::Into;
    use core::array::ArrayTrait;
    use core::num::traits::zero::Zero;
    
    use ciro_contracts::interfaces::ciro_token::{
        ICIROToken, GovernanceProposal, BurnEvent, GovernanceRights, GovernanceStats,
        SecurityBudget, RateLimitInfo, EmergencyOperation, PendingTransfer,
        ProposalStatus
    };
    use openzeppelin::security::pausable::PausableComponent;
    use ciro_contracts::utils::constants::{
        TOTAL_SUPPLY, PHASE_BOOTSTRAP,
        VETERAN_HOLDER_MINIMUM_PERIOD, LONG_TERM_HOLDER_MINIMUM_PERIOD,
        VOTING_POWER_MULTIPLIER_LONG_TERM, VOTING_POWER_MULTIPLIER_VETERAN,
        GOVERNANCE_MINOR_THRESHOLD, GOVERNANCE_MAJOR_THRESHOLD, 
        GOVERNANCE_PROTOCOL_THRESHOLD, GOVERNANCE_EMERGENCY_THRESHOLD,
        GOVERNANCE_STRATEGIC_THRESHOLD, QUORUM_PERCENTAGE
    };

    /// Contract constants based on v3.0 tokenomics
    const INITIAL_CIRCULATING: u256 = 50_000_000_000_000_000_000_000_000; // 50M tokens
    const DECIMALS: u8 = 18;
    const NAME: felt252 = 'CIRO Network Token';
    const SYMBOL: felt252 = 'CIRO';
    
    /// Security and governance constants (v3.1)
    const MIN_SECURITY_BUDGET_USD: u256 = 2_000_000; // $2M minimum
    const MAX_INFLATION_CHANGE: u32 = 1000; // 10% in basis points
    const MAX_BURN_RATE_CHANGE: u32 = 1500; // 15% in basis points
    const VOTING_PERIOD: u64 = 604800; // 7 days in seconds
    const GUARD_BAND_INFLATION: u32 = 300; // 3% in basis points
    
    /// Local constants not imported from utils
    const PROPOSAL_COOLDOWN_PERIOD: u64 = 86400; // 24 hours between proposals from same address
    const SUPERMAJORITY_THRESHOLD: u32 = 6700; // 67% for critical proposals
    const MAX_PROPOSALS_PER_USER: u32 = 3; // Maximum active proposals per user

    #[storage]
    struct Storage {
        /// ERC20 Standard Storage
        balances: Map<ContractAddress, u256>,
        allowances: Map<(ContractAddress, ContractAddress), u256>,
        total_supply: u256,
        
        /// Token Metadata
        name: felt252,
        symbol: felt252,
        decimals: u8,
        
        /// Tokenomics Storage
        total_burned: u256,
        current_inflation_rate: u32,    // Basis points (100 = 1%)
        current_burn_rate: u32,         // Basis points (100 = 1%)
        last_inflation_update: u64,
        
        /// Security Budget
        security_budget: SecurityBudget,
        annual_security_budget_usd: u256,
        security_reserves: u256,
        guard_band_active: bool,
        
        /// Governance Storage (Enhanced v3.1)
        governance_proposals: Map<u256, GovernanceProposal>,
        proposal_count: u256,
        voted_proposals: Map<(ContractAddress, u256), bool>,
        voting_power: Map<ContractAddress, u256>,
        
        /// Progressive Governance Rights Storage
        token_lock_start: Map<ContractAddress, u64>, // Track when user first acquired tokens
        last_proposal_time: Map<ContractAddress, u64>, // Prevent proposal spam
        active_proposals_count: Map<ContractAddress, u32>, // Track active proposals per user
        
        /// Enhanced Security Storage
        proposal_quorum_achieved: Map<u256, bool>, // Track if proposal achieved quorum
        governance_pause_count: u32, // Track emergency governance pauses
        last_governance_pause: u64, // Prevent governance pause spam
        governance_paused: bool, // Emergency governance pause state
        governance_pause_ends: u64, // When governance pause ends
        
        /// Revenue and Burn Tracking
        burn_history: Map<u32, BurnEvent>,
        burn_history_count: u32,
        total_revenue_collected: u256,
        monthly_revenue: u256,
        last_revenue_reset: u64,
        
        /// Contract Management
        paused: bool,
        owner: ContractAddress,
        emergency_council: Map<ContractAddress, bool>,
        
        /// Contract Integration Addresses
        job_manager_address: ContractAddress,
        cdc_pool_address: ContractAddress,
        paymaster_address: ContractAddress,
        
        /// Launch and Phase Tracking
        launch_timestamp: u64,
        network_phase: felt252,
        
        // Add after the existing storage
        // Rate limiting for inflation adjustments
        inflation_adjustment_last_time: u64,
        max_inflation_adjustment_per_month: u32,
        current_month_adjustments: u32,
        
        // Upgradability and security features
        contract_version: felt252,
        upgrade_authorization: Map<ContractAddress, bool>,
        critical_operations_timelock: Map<ContractAddress, u64>,
        
        // Gas optimization tracking
        gas_optimization_enabled: bool,
        batch_operation_limit: u32,
        
        // Security monitoring
        suspicious_activity_count: u32,
        security_alert_threshold: u32,
        last_security_review: u64,
        
        // Emergency security features
        emergency_withdrawal_enabled: bool,
        emergency_council_multisig: ContractAddress,
        emergency_operations_log: Map<u256, EmergencyOperation>,
        emergency_log_count: u256,
        
        // Audit tracking
        last_audit_timestamp: u64,
        audit_findings_count: u32,
        security_score: u32,
        
        // Additional rate limiting
        transfer_rate_limit: u256,
        transfer_rate_window: u64,
        user_transfer_history: Map<(ContractAddress, u64), u256>,
        
        // Anti-manipulation features
        large_transfer_threshold: u256,
        large_transfer_delay: u64,
        pending_large_transfers: Map<u256, PendingTransfer>,
        large_transfer_queue_count: u256,
        large_transfer_counter: u256,
        
        // Pausable component storage
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
        
        // Security features
        blacklisted_addresses: Map<ContractAddress, bool>,
        max_inflation_rate: u256,
        // Rate limiting
        daily_transfer_amount: u256,
        rate_limit_window_start: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Transfer: Transfer,
        Approval: Approval,
        Mint: Mint,
        Burn: Burn,
        InflationRateChanged: InflationRateChanged,
        BurnRateChanged: BurnRateChanged,
        SecurityBudgetReplenished: SecurityBudgetReplenished,
        EmergencyMint: EmergencyMint,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        RevenueCollected: RevenueCollected,
        PhaseTransition: PhaseTransition,
        /// Governance Events (Enhanced v3.1)
        ProposalCreated: ProposalCreated,
        ProposalVoted: ProposalVoted,
        ProposalExecuted: ProposalExecuted,
        ProposalQuorumAchieved: ProposalQuorumAchieved,
        GovernanceRightsUpgraded: GovernanceRightsUpgraded,
        GovernancePaused: GovernancePaused,
        GovernanceResumed: GovernanceResumed,
        VotingPowerUpdated: VotingPowerUpdated,
        // Security Events (v3.1 Enhanced)
        SecurityAuditSubmitted: SecurityAuditSubmitted,
        RateLimitExceeded: RateLimitExceeded,
        LargeTransferInitiated: LargeTransferInitiated,
        LargeTransferExecuted: LargeTransferExecuted,
        EmergencyOperationLogged: EmergencyOperationLogged,
        SuspiciousActivityReported: SuspiciousActivityReported,
        GasOptimizationToggled: GasOptimizationToggled,
        BatchTransferCompleted: BatchTransferCompleted,
        UpgradeAuthorized: UpgradeAuthorized,
        EmergencyWithdrawal: EmergencyWithdrawal,
        SecurityThresholdChanged: SecurityThresholdChanged,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Transfer {
        pub from: ContractAddress,
        pub to: ContractAddress,
        pub value: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Approval {
        pub owner: ContractAddress,
        pub spender: ContractAddress,
        pub value: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Mint {
        pub to: ContractAddress,
        pub amount: u256,
        pub reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Burn {
        pub amount: u256,
        pub revenue_source: u256,
        pub execution_price: u256,
        pub burn_rate: u32,
    }

    #[derive(Drop, starknet::Event)]
    pub struct InflationRateChanged {
        pub old_rate: u32,
        pub new_rate: u32,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct BurnRateChanged {
        pub old_rate: u32,
        pub new_rate: u32,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct SecurityBudgetReplenished {
        pub amount: u256,
        pub new_total: u256,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct EmergencyMint {
        pub amount: u256,
        pub justification: felt252,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContractPaused {
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ContractUnpaused {
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RevenueCollected {
        pub amount: u256,
        pub source: felt252,
        pub timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PhaseTransition {
        pub old_phase: felt252,
        pub new_phase: felt252,
        pub timestamp: u64,
    }

    /// Enhanced Governance Events (v3.1)
    #[derive(Drop, starknet::Event)]
    struct ProposalCreated {
        proposal_id: u256,
        proposer: ContractAddress,
        proposal_type: u32,
        description: felt252,
        voting_ends_at: u64,
        quorum_required: u256,
        supermajority_required: bool,
    }
    
    #[derive(Drop, starknet::Event)]
    struct ProposalVoted {
        proposal_id: u256,
        voter: ContractAddress,
        vote_for: bool,
        voting_power: u256,
        total_votes_for: u256,
        total_votes_against: u256,
    }
    
    #[derive(Drop, starknet::Event)]
    struct ProposalExecuted {
        proposal_id: u256,
        result: bool,
        votes_for: u256,
        votes_against: u256,
        execution_timestamp: u64,
    }
    
    #[derive(Drop, starknet::Event)]
    struct ProposalQuorumAchieved {
        proposal_id: u256,
        total_votes: u256,
        quorum_requirement: u256,
        timestamp: u64,
    }
    
    #[derive(Drop, starknet::Event)]
    struct GovernanceRightsUpgraded {
        account: ContractAddress,
        old_tier: u32,
        new_tier: u32,
        new_voting_power: u256,
        timestamp: u64,
    }
    
    #[derive(Drop, starknet::Event)]
    struct GovernancePaused {
        duration: u64,
        reason: felt252,
        timestamp: u64,
    }
    
    #[derive(Drop, starknet::Event)]
    struct GovernanceResumed {
        #[key]
        pause_duration: u64,
        timestamp: u64,
    }
    
    #[derive(Drop, starknet::Event)]
    struct VotingPowerUpdated {
        #[key]
        account: ContractAddress,
        old_power: u256,
        new_power: u256,
        multiplier_applied: u32,
        timestamp: u64,
    }

    // Security Events (v3.1 Enhanced)
    
    #[derive(Drop, starknet::Event)]
    struct SecurityAuditSubmitted {
        #[key]
        audit_id: u256,
        #[key]
        auditor: ContractAddress,
        findings_count: u32,
        security_score: u32,
        critical_issues: u32,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct RateLimitExceeded {
        #[key]
        user: ContractAddress,
        operation_type: felt252,
        attempted_amount: u256,
        current_limit: u256,
        window_reset_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct LargeTransferInitiated {
        #[key]
        transfer_id: u256,
        #[key]
        from: ContractAddress,
        #[key]
        to: ContractAddress,
        amount: u256,
        execute_after: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct LargeTransferExecuted {
        #[key]
        transfer_id: u256,
        #[key]
        from: ContractAddress,
        #[key]
        to: ContractAddress,
        amount: u256,
        execution_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyOperationLogged {
        #[key]
        operation_id: u256,
        #[key]
        executor: ContractAddress,
        operation_type: felt252,
        details: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SuspiciousActivityReported {
        #[key]
        reporter: ContractAddress,
        activity_type: felt252,
        severity: u32,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct GasOptimizationToggled {
        enabled: bool,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct BatchTransferCompleted {
        #[key]
        sender: ContractAddress,
        transfer_count: u32,
        total_amount: u256,
        gas_saved: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeAuthorized {
        #[key]
        new_implementation: ContractAddress,
        #[key]
        authorized_by: ContractAddress,
        timelock_duration: u64,
        execute_after: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyWithdrawal {
        #[key]
        executor: ContractAddress,
        amount: u256,
        justification: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SecurityThresholdChanged {
        old_threshold: u32,
        new_threshold: u32,
        changed_by: ContractAddress,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        job_manager: ContractAddress,
        cdc_pool: ContractAddress,
        paymaster: ContractAddress
    ) {
        // Initialize ERC20 metadata
        self.name.write(NAME);
        self.symbol.write(SYMBOL);
        self.decimals.write(DECIMALS);
        self.total_supply.write(TOTAL_SUPPLY);
        
        // Set initial balances (treasury holds most tokens)
        self.balances.write(owner, INITIAL_CIRCULATING);
        
        // Initialize tokenomics parameters (v3.0 schedule)
        self.current_inflation_rate.write(800); // 8% initial inflation
        self.current_burn_rate.write(3000); // 30% initial burn rate
        self.last_inflation_update.write(get_block_timestamp());
        
        // Initialize security budget
        let security_budget = SecurityBudget {
            annual_budget_usd: MIN_SECURITY_BUDGET_USD,
            current_reserves: 0,
            last_replenishment: get_block_timestamp(),
            guard_band_active: true,
        };
        self.security_budget.write(security_budget);
        self.annual_security_budget_usd.write(MIN_SECURITY_BUDGET_USD);
        self.guard_band_active.write(true);
        
        // Initialize governance
        self.proposal_count.write(0);
        
        // Initialize tracking
        self.burn_history_count.write(0);
        self.total_revenue_collected.write(0);
        self.monthly_revenue.write(0);
        self.last_revenue_reset.write(get_block_timestamp());
        
        // Set contract addresses
        self.owner.write(owner);
        self.job_manager_address.write(job_manager);
        self.cdc_pool_address.write(cdc_pool);
        self.paymaster_address.write(paymaster);
        
        // Initialize phase tracking
        self.launch_timestamp.write(get_block_timestamp());
        self.network_phase.write(PHASE_BOOTSTRAP);
        
        // Contract starts unpaused
        self.paused.write(false);
        
        // Emit initial transfer event
        self.emit(Transfer {
            from: 0.try_into().unwrap(),
            to: owner,
            value: INITIAL_CIRCULATING,
        });

        // Initialize security defaults for Task 26.5
        self._initialize_security_defaults();
    }

    #[abi(embed_v0)]
    impl CIROTokenImpl of ICIROToken<ContractState> {
        /// ERC20 Standard Functions
        
        fn name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn symbol(self: @ContractState) -> felt252 {
            self.symbol.read()
        }

        fn decimals(self: @ContractState) -> u8 {
            self.decimals.read()
        }

        fn total_supply(self: @ContractState) -> u256 {
            self.total_supply.read()
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.balances.read(account)
        }

        fn allowance(self: @ContractState, owner: ContractAddress, spender: ContractAddress) -> u256 {
            self.allowances.read((owner, spender))
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            self._not_paused();
            let caller = get_caller_address();
            
            // Check if this is a large transfer that needs special handling
            let threshold = self.large_transfer_threshold.read();
            if amount >= threshold {
                // Large transfers must use the initiate_large_transfer function
                assert(false, 'Use initiate_large_transfer');
            }
            
            // Check rate limits for regular transfers
            self._check_and_update_rate_limit(amount);
            
            // Proceed with normal transfer
            self._transfer(caller, recipient, amount);
            
            true
        }

        fn transfer_from(
            ref self: ContractState,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) -> bool {
            let caller = get_caller_address();
            let current_allowance = self.allowances.read((sender, caller));
            
            assert(current_allowance >= amount, 'Insufficient allowance');
            
            self.allowances.write((sender, caller), current_allowance - amount);
            self._transfer(sender, recipient, amount);
            true
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: u256) -> bool {
            let owner = get_caller_address();
            self.allowances.write((owner, spender), amount);
            
            self.emit(Approval {
                owner,
                spender,
                value: amount,
            });
            true
        }

        fn increase_allowance(ref self: ContractState, spender: ContractAddress, added_value: u256) -> bool {
            let owner = get_caller_address();
            let current_allowance = self.allowances.read((owner, spender));
            let new_allowance = current_allowance + added_value;
            
            self.allowances.write((owner, spender), new_allowance);
            
            self.emit(Approval {
                owner,
                spender,
                value: new_allowance,
            });
            true
        }

        fn decrease_allowance(ref self: ContractState, spender: ContractAddress, subtracted_value: u256) -> bool {
            let owner = get_caller_address();
            let current_allowance = self.allowances.read((owner, spender));
            
            assert(current_allowance >= subtracted_value, 'Allowance below zero');
            
            let new_allowance = current_allowance - subtracted_value;
            self.allowances.write((owner, spender), new_allowance);
            
            self.emit(Approval {
                owner,
                spender,
                value: new_allowance,
            });
            true
        }

        /// Tokenomics Functions

        fn mint(ref self: ContractState, to: ContractAddress, amount: u256, reason: felt252) {
            self._only_authorized();
            self._not_paused();
            
            // Check if this is within governance parameters or emergency
            if reason != 'emergency' {
                self._check_inflation_limits(amount);
            }
            
            let current_supply = self.total_supply.read();
            let new_supply = current_supply + amount;
            
            self.total_supply.write(new_supply);
            let current_balance = self.balances.read(to);
            self.balances.write(to, current_balance + amount);
            
            self.emit(Mint { to, amount, reason });
            self.emit(Transfer {
                from: 0.try_into().unwrap(),
                to,
                value: amount,
            });
        }

        fn burn_from_revenue(ref self: ContractState, amount: u256, revenue_source: u256, execution_price: u256) {
            self._only_authorized();
            self._not_paused();
            
            let current_supply = self.total_supply.read();
            assert(current_supply >= amount, 'Insufficient supply to burn');
            
            // Update supply
            self.total_supply.write(current_supply - amount);
            let burned = self.total_burned.read();
            self.total_burned.write(burned + amount);
            
            // Record burn event
            let burn_rate = self.current_burn_rate.read();
            let burn_event = BurnEvent {
                amount,
                reason: 'revenue_burn',
                timestamp: get_block_timestamp(),
                burn_rate,
                network_phase: 1, // Fixed: use felt252 instead of function call
                total_supply_after: current_supply - amount,
            };
            
            let count = self.burn_history_count.read();
            self.burn_history.write(count, burn_event);
            self.burn_history_count.write(count + 1);
            
            // Update revenue tracking
            self._update_revenue_tracking(revenue_source);
            
            self.emit(Burn { amount, revenue_source, execution_price, burn_rate });
        }

        fn get_inflation_rate(self: @ContractState) -> u32 {
            self._get_current_inflation_rate()
        }

        fn get_burn_rate(self: @ContractState) -> u32 {
            self._get_current_burn_rate()
        }

        fn get_total_burned(self: @ContractState) -> u256 {
            self.total_burned.read()
        }

        fn get_security_budget(self: @ContractState) -> SecurityBudget {
            self.security_budget.read()
        }

        /// Enhanced Governance Functions (v3.1)
        
        fn create_typed_proposal(
            ref self: ContractState,
            description: felt252,
            proposal_type: u32,
            inflation_change: i32,
            burn_rate_change: i32
        ) -> u256 {
            self._not_paused();
            let caller = get_caller_address();
            
            // Check if caller has minimum voting power for this proposal type
            assert(self._check_proposal_threshold(caller, proposal_type), 'Insufficient voting power');
            
            // Check proposal cooldown period
            let last_proposal_time = self.last_proposal_time.read(caller);
            let current_time = get_block_timestamp();
            assert(current_time - last_proposal_time >= PROPOSAL_COOLDOWN_PERIOD, 'Proposal cooldown active');
            
            // Check active proposals limit
            let active_proposals = self.active_proposals_count.read(caller);
            assert(active_proposals < MAX_PROPOSALS_PER_USER, 'Too many active proposals');
            
            // Create proposal
            let proposal_id = self.proposal_count.read() + 1;
            self.proposal_count.write(proposal_id);
            
            let voting_ends_at = current_time + VOTING_PERIOD;
            let quorum_required = self._calculate_quorum_requirement();
            let supermajority_required = self._requires_supermajority(proposal_type);
            
            let proposal = GovernanceProposal {
                id: proposal_id,
                proposer: caller,
                title: description, // Use description as title for now
                description,
                proposal_type,
                inflation_change,
                burn_rate_change,
                voting_start: current_time,
                voting_end: voting_ends_at,
                voting_starts: current_time, // Alias for compatibility
                voting_ends: voting_ends_at,   // Alias for compatibility
                execution_delay: 86400, // 24 hours
                votes_for: 0,
                votes_against: 0,
                for_votes: 0,    // Alias for compatibility
                against_votes: 0, // Alias for compatibility
                total_voting_power: self.total_supply.read(),
                quorum_threshold: quorum_required,
                execution_deadline: voting_ends_at + 86400, // 24 hours after voting ends
                status: ProposalStatus::Active,
                created_at: current_time,
                executed_at: 0,
            };
            
            self.governance_proposals.write(proposal_id, proposal);
            self.last_proposal_time.write(caller, current_time);
            self.active_proposals_count.write(caller, active_proposals + 1);
            
            self.emit(ProposalCreated {
                proposal_id,
                proposer: caller,
                proposal_type,
                description,
                voting_ends_at,
                quorum_required,
                supermajority_required,
            });
            
            proposal_id
        }
        
        fn create_proposal(
            ref self: ContractState,
            description: felt252,
            inflation_change: i32,
            burn_rate_change: i32
        ) -> u256 {
            // Legacy function - default to major change type
            self.create_typed_proposal(description, 1, inflation_change, burn_rate_change)
        }
        
        fn get_governance_rights(self: @ContractState, account: ContractAddress) -> GovernanceRights {
            let _base_voting_power = self.balances.read(account);
            let multiplied_voting_power = self._calculate_voting_power(account);
            let governance_tier = self._get_governance_tier(account);
            
            // Check which proposal thresholds they meet
            let mut proposal_threshold_met = 0;
            if multiplied_voting_power >= GOVERNANCE_MINOR_THRESHOLD {
                proposal_threshold_met = 1;
            }
            if multiplied_voting_power >= GOVERNANCE_MAJOR_THRESHOLD {
                proposal_threshold_met = 2;
            }
            if multiplied_voting_power >= GOVERNANCE_PROTOCOL_THRESHOLD {
                proposal_threshold_met = 3;
            }
            if multiplied_voting_power >= GOVERNANCE_EMERGENCY_THRESHOLD {
                proposal_threshold_met = 4;
            }
            if multiplied_voting_power >= GOVERNANCE_STRATEGIC_THRESHOLD {
                proposal_threshold_met = 5;
            }
            
            GovernanceRights {
                voting_power: multiplied_voting_power,
                proposal_threshold: GOVERNANCE_MINOR_THRESHOLD,
                governance_tier,
                can_create_proposals: proposal_threshold_met != 0,
            }
        }
        
        fn get_governance_stats(self: @ContractState) -> GovernanceStats {
            let total_proposals = self.proposal_count.read();
            
            // Calculate successful proposals (simplified)
            let mut successful_proposals = 0;
            let mut i = 1;
            while i != total_proposals + 1 {
                let proposal = self.governance_proposals.read(i);
                if proposal.status == ProposalStatus::Executed && proposal.votes_for > proposal.votes_against {
                    successful_proposals += 1;
                }
                i += 1;
            };
            
            GovernanceStats {
                total_proposals,
                active_proposals: 0, // Would need to count active proposals
                executed_proposals: successful_proposals,
                total_voters: 0, // Would need to track total voters
                average_participation: 0, // Could be calculated from historical data
                total_voting_power: self.total_supply.read(),
            }
        }
        
        fn can_create_proposal_type(self: @ContractState, account: ContractAddress, proposal_type: u32) -> bool {
            self._check_proposal_threshold(account, proposal_type)
        }
        
        fn emergency_governance_pause(ref self: ContractState, duration: u64) {
            self._only_emergency_council();
            
            // Prevent abuse by limiting governance pauses
            let current_time = get_block_timestamp();
            let last_pause = self.last_governance_pause.read();
            assert(current_time - last_pause >= 86400, 'Governance pause cooldown'); // 24 hours
            
            self.governance_paused.write(true);
            self.governance_pause_ends.write(current_time + duration);
            self.last_governance_pause.write(current_time);
            self.governance_pause_count.write(self.governance_pause_count.read() + 1);
            
            self.emit(Event::GovernancePaused(GovernancePaused {
                duration,
                reason: 'Emergency pause',
                timestamp: current_time,
            }));
        }
        
        fn resume_governance(ref self: ContractState) {
            self._only_emergency_council();
            
            let current_time = get_block_timestamp();
            let pause_duration = current_time - self.last_governance_pause.read();
            
            self.governance_paused.write(false);
            self.governance_pause_ends.write(0);
            
            self.emit(Event::GovernanceResumed(GovernanceResumed {
                pause_duration,
                timestamp: current_time,
            }));
        }

        /// Governance Functions

        fn vote_on_proposal(
            ref self: ContractState,
            proposal_id: u256,
            vote_for: bool,
            voting_power: u256
        ) {
            self._not_paused();
            
            // Check if governance is paused
            assert(!self.governance_paused.read(), 'Governance is paused');
            
            let proposal = self.governance_proposals.read(proposal_id);
            assert(proposal.status != ProposalStatus::Executed, 'Proposal already executed');
            assert(get_block_timestamp() <= proposal.voting_end, 'Voting period ended');
            
            let caller = get_caller_address();
            let caller_voting_power = self._calculate_voting_power(caller);
            assert(caller_voting_power >= voting_power, 'Insufficient voting power');
            
            // Record vote
            assert(!self.voted_proposals.read((caller, proposal_id)), 'Already voted');
            self.voted_proposals.write((caller, proposal_id), true);
            
            // Update proposal vote counts
            let mut updated_proposal = proposal;
            if vote_for {
                updated_proposal.votes_for += voting_power;
            } else {
                updated_proposal.votes_against += voting_power;
            }
            
            // Check if quorum is achieved
            let total_votes = updated_proposal.votes_for + updated_proposal.votes_against;
            let quorum_requirement = self._calculate_quorum_requirement();
            
            if total_votes >= quorum_requirement && updated_proposal.status == ProposalStatus::Active {
                // Update proposal status if needed
                updated_proposal.status = ProposalStatus::Active; // Keep active until voting ends
            }
            
            self.governance_proposals.write(proposal_id, updated_proposal);
            
            self.emit(Event::ProposalVoted(ProposalVoted {
                proposal_id,
                voter: caller,
                vote_for,
                voting_power,
                total_votes_for: updated_proposal.votes_for,
                total_votes_against: updated_proposal.votes_against,
            }));
        }
        
        fn execute_proposal(ref self: ContractState, proposal_id: u256) {
            self._not_paused();
            let proposal = self.governance_proposals.read(proposal_id);
            assert(proposal.status != ProposalStatus::Executed, 'Proposal already executed');
            assert(get_block_timestamp() > proposal.voting_end, 'Voting period active');
            
            // Check if proposal passed
            let total_votes = proposal.votes_for + proposal.votes_against;
            let quorum_requirement = self._calculate_quorum_requirement();
            assert(total_votes >= quorum_requirement, 'Quorum not achieved');
            
            let required_percentage = if self._requires_supermajority(proposal.proposal_type) {
                70 // 70% supermajority
            } else {
                51 // Simple majority
            };
            
            let votes_for_percentage = (proposal.votes_for * 100) / total_votes;
            let proposal_passed = votes_for_percentage >= required_percentage.into();
            
            if proposal_passed {
                // Execute the proposal
                if proposal.inflation_change != 0 {
                    // Update inflation rate (implementation would go here)
                    // For now, we'll just track that it was approved
                }
                
                if proposal.burn_rate_change != 0 {
                    // Update burn rate (implementation would go here)
                    // For now, we'll just track that it was approved
                }
            }
            
            // Mark as executed
            let mut updated_proposal = proposal;
            updated_proposal.status = ProposalStatus::Executed;
            updated_proposal.executed_at = get_block_timestamp();
            self.governance_proposals.write(proposal_id, updated_proposal);
            
            // Decrease active proposals count for proposer
            let proposer = proposal.proposer;
            let current_count = self.active_proposals_count.read(proposer);
            if current_count > 0 {
                self.active_proposals_count.write(proposer, current_count - 1);
            }
            
            self.emit(Event::ProposalExecuted(ProposalExecuted {
                proposal_id,
                result: proposal_passed,
                votes_for: proposal.votes_for,
                votes_against: proposal.votes_against,
                execution_timestamp: get_block_timestamp(),
            }));
        }

        fn get_proposal(self: @ContractState, proposal_id: u256) -> GovernanceProposal {
            self.governance_proposals.read(proposal_id)
        }

        fn get_voting_power(self: @ContractState, account: ContractAddress) -> u256 {
            self._calculate_voting_power(account)
        }

        /// Contract Integration Functions

        fn collect_job_fee(ref self: ContractState, amount: u256, job_id: u256) {
            let caller = get_caller_address();
            assert(caller == self.job_manager_address.read(), 'Only JobManager');
            
            // Burn percentage of fee according to current burn rate
            let burn_rate = self.current_burn_rate.read();
            let burn_amount = (amount * burn_rate.into()) / 10000; // Convert from basis points
            
            if burn_amount > 0 {
                self.burn_from_revenue(burn_amount, amount, 0); // Price will be updated by oracle
            }
            
            self.emit(Event::RevenueCollected(RevenueCollected {
                amount,
                source: 'job_fee',
                timestamp: get_block_timestamp(),
            }));
        }

        fn distribute_pool_rewards(ref self: ContractState, pool_address: ContractAddress, amount: u256) {
            self._only_authorized();
            self._not_paused();
            
            // Mint rewards for CDC Pool
            self.mint(pool_address, amount, 'pool_rewards');
        }

        fn pay_gas_fee(ref self: ContractState, user: ContractAddress, gas_cost: u256) -> bool {
            let caller = get_caller_address();
            assert(caller == self.paymaster_address.read(), 'Only Paymaster');
            
            let balance = self.balances.read(user);
            if balance >= gas_cost {
                self.balances.write(user, balance - gas_cost);
                // Gas fee can be burned or sent to treasury
                self.total_supply.write(self.total_supply.read() - gas_cost);
                true
            } else {
                false
            }
        }

        fn replenish_security_budget(ref self: ContractState, amount: u256) {
            self._only_authorized();
            
            let mut security_budget = self.security_budget.read();
            security_budget.current_reserves += amount;
            security_budget.last_replenishment = get_block_timestamp();
            
            self.security_budget.write(security_budget);
            
            self.emit(Event::SecurityBudgetReplenished(SecurityBudgetReplenished {
                amount,
                new_total: security_budget.current_reserves,
                timestamp: get_block_timestamp(),
            }));
        }

        /// Emergency Functions

        fn pause(ref self: ContractState) {
            self._only_emergency_council();
            self.paused.write(true);
            self.emit(Event::ContractPaused(ContractPaused { timestamp: get_block_timestamp() }));
        }

        fn unpause(ref self: ContractState) {
            self._only_emergency_council();
            self.paused.write(false);
            self.emit(Event::ContractUnpaused(ContractUnpaused { timestamp: get_block_timestamp() }));
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn emergency_mint(ref self: ContractState, amount: u256, justification: felt252) {
            self._only_emergency_council();
            
            // Emergency mint for security budget protection
            let owner = self.owner.read();
            self.mint(owner, amount, 'emergency');
            
            self.emit(Event::EmergencyMint(EmergencyMint {
                amount,
                justification,
                timestamp: get_block_timestamp(),
            }));
        }

        /// View Functions

        fn get_burn_history(self: @ContractState, offset: u32, limit: u32) -> Array<BurnEvent> {
            let mut result = ArrayTrait::new();
            let total_burns = self.burn_history_count.read();
            let mut i = offset;
            let end = if offset + limit > total_burns { total_burns } else { offset + limit };
            
            while i != end {
                result.append(self.burn_history.read(i));
                i += 1;
            };
            
            result
        }

        fn get_network_phase(self: @ContractState) -> felt252 {
            self.network_phase.read()
        }

        fn get_revenue_stats(self: @ContractState) -> (u256, u256, u32) {
            let total_revenue = self.total_revenue_collected.read();
            let monthly_revenue = self._get_monthly_revenue();
            let burn_efficiency = self._calculate_burn_efficiency();
            
            (total_revenue, monthly_revenue, burn_efficiency)
        }

        fn check_inflation_adjustment_rate_limit(self: @ContractState) -> (bool, u64, u32) {
            let current_time = get_block_timestamp();
            let last_adjustment = self.inflation_adjustment_last_time.read();
            let monthly_limit = self.max_inflation_adjustment_per_month.read();
            let current_adjustments = self.current_month_adjustments.read();
            
            // Check if we're in a new month
            let one_month = 30 * 24 * 3600; // 30 days in seconds
            let time_since_last = current_time - last_adjustment;
            
            if time_since_last >= one_month {
                // New month, reset counter
                return (true, 0, monthly_limit);
            }
            
            let can_adjust = current_adjustments < monthly_limit;
            let next_available = if can_adjust { 0 } else { last_adjustment + one_month };
            let adjustments_remaining = if can_adjust { monthly_limit - current_adjustments } else { 0 };
            
            (can_adjust, next_available, adjustments_remaining)
        }

        fn submit_security_audit(
            ref self: ContractState,
            findings_count: u32,
            security_score: u32,
            critical_issues: u32,
            recommendations: felt252
        ) {
            // Only authorized auditors can submit reports
            let caller = get_caller_address();
            assert(
                caller == self.owner.read() || 
                self.upgrade_authorization.read(caller),
                'Unauthorized auditor'
            );
            
            let current_time = get_block_timestamp();
            let audit_id = self.audit_findings_count.read() + 1;
            
            self.last_audit_timestamp.write(current_time);
            self.audit_findings_count.write(findings_count);
            self.security_score.write(security_score);
            
            self.emit(Event::SecurityAuditSubmitted(SecurityAuditSubmitted {
                audit_id: audit_id.into(),
                auditor: caller,
                findings_count,
                security_score,
                critical_issues,
                timestamp: current_time,
            }));
        }

        fn get_security_audit_status(self: @ContractState) -> (u64, u32, u32) {
            let last_audit = self.last_audit_timestamp.read();
            let findings_count = self.audit_findings_count.read();
            let security_score = self.security_score.read();
            
            (last_audit, findings_count, security_score)
        }

        /// Large Transfer Management
        fn initiate_large_transfer(ref self: ContractState, to: ContractAddress, amount: u256) -> u256 {
            self._not_paused();
            let caller = get_caller_address();
            
            // Check balance
            let balance = self.balances.read(caller);
            assert(balance >= amount, 'Insufficient balance');
            
            // Check if amount qualifies as large transfer
            let threshold = self.large_transfer_threshold.read();
            assert(amount >= threshold, 'Not a large transfer');
            
            // Create pending transfer
            let transfer_id = self.large_transfer_queue_count.read();
            self.large_transfer_queue_count.write(transfer_id + 1);
            
            let pending_transfer = PendingTransfer {
                id: transfer_id,
                transfer_id: transfer_id, // Alias for compatibility
                from: caller,
                to,
                amount,
                timestamp: get_block_timestamp(),
                initiated_at: get_block_timestamp(), // Alias for compatibility
                execute_after: get_block_timestamp() + self.large_transfer_delay.read(),
                execution_time: 0, // Alias for compatibility
                approved_by_council: false,
                is_executed: false,
            };
            
            self.pending_large_transfers.write(transfer_id, pending_transfer);
            
            // Lock the funds
            self.balances.write(caller, balance - amount);
            
            self.emit(Event::LargeTransferInitiated(LargeTransferInitiated {
                transfer_id,
                from: caller,
                to,
                amount,
                execute_after: pending_transfer.execute_after,
            }));
            
            transfer_id
        }

        fn execute_large_transfer(ref self: ContractState, transfer_id: u256) {
            self._not_paused();
            let pending_transfer = self.pending_large_transfers.read(transfer_id);
            assert(!pending_transfer.is_executed, 'Transfer already executed');
            assert(get_block_timestamp() >= pending_transfer.execute_after, 'Timelock not expired');
            
            // Execute the transfer
            let from = pending_transfer.from;
            let to = pending_transfer.to;
            let amount = pending_transfer.amount;
            
            self._transfer(from, to, amount);
            
            // Mark as executed
            let mut updated_transfer = pending_transfer;
            updated_transfer.is_executed = true;
            updated_transfer.execution_time = get_block_timestamp();
            self.pending_large_transfers.write(transfer_id, updated_transfer);
            
            self.emit(Event::LargeTransferExecuted(LargeTransferExecuted {
                transfer_id,
                from,
                to,
                amount,
                execution_time: get_block_timestamp(),
            }));
            
            self.emit(Event::Transfer(Transfer {
                from: pending_transfer.from,
                to: pending_transfer.to,
                value: pending_transfer.amount,
            }));
        }

        fn get_pending_transfer(self: @ContractState, transfer_id: u256) -> PendingTransfer {
            self.pending_large_transfers.read(transfer_id)
        }

        fn check_transfer_rate_limit(self: @ContractState, user: ContractAddress, amount: u256) -> (bool, RateLimitInfo) {
            let current_time = get_block_timestamp();
            let window_duration = self.transfer_rate_window.read();
            let current_limit = self.transfer_rate_limit.read();
            
            let window_start = (current_time / window_duration) * window_duration;
            let current_usage = self.user_transfer_history.read((user, window_start));
            
            let allowed = current_usage + amount <= current_limit;
            let _remaining_capacity = if allowed { current_limit - current_usage - amount } else { 0 };
            
            let rate_limit_info = if allowed {
                RateLimitInfo {
                    current_limit: current_limit,
                    current_usage: current_usage + amount,
                    window_start: window_start,
                    window_duration: window_duration,
                    next_reset: window_start + window_duration,
                }
            } else {
                RateLimitInfo {
                    current_limit: current_limit,
                    current_usage: current_usage + amount,
                    window_start: window_start,
                    window_duration: window_duration,
                    next_reset: window_start + window_duration,
                }
            };
            
            (allowed, rate_limit_info)
        }

        fn set_gas_optimization(ref self: ContractState, enabled: bool) {
            self._only_authorized();
            self.gas_optimization_enabled.write(enabled);
            
            self.emit(Event::GasOptimizationToggled(GasOptimizationToggled {
                enabled,
                timestamp: get_block_timestamp(),
            }));
        }

        fn get_contract_info(self: @ContractState) -> (felt252, bool, u64) {
            let version = self.contract_version.read();
            let upgrade_authorized = self.upgrade_authorization.read(get_caller_address());
            let timelock_remaining = self.critical_operations_timelock.read(get_caller_address());
            
            (version, upgrade_authorized, timelock_remaining)
        }

        fn log_emergency_operation(ref self: ContractState, operation_type: felt252, details: felt252) {
            self._only_emergency_council();
            
            let operation_id = self.emergency_log_count.read();
            self.emergency_log_count.write(operation_id + 1);
            
            let emergency_operation = EmergencyOperation {
                operation_id: operation_id,
                operation_type,
                authorized_by: get_caller_address(),
                justification: details,
                timestamp: get_block_timestamp(),
                amount_affected: 0, // Default for non-financial operations
            };
            
            self.emergency_operations_log.write(operation_id, emergency_operation);
            
            self.emit(Event::EmergencyOperationLogged(EmergencyOperationLogged {
                operation_id,
                operation_type,
                details,
                executor: get_caller_address(),
                timestamp: get_block_timestamp(),
            }));
        }

        fn get_emergency_operation(self: @ContractState, operation_id: u256) -> EmergencyOperation {
            self.emergency_operations_log.read(operation_id)
        }

        fn batch_transfer(ref self: ContractState, recipients: Array<ContractAddress>, amounts: Array<u256>) -> bool {
            self._not_paused();
            let caller = get_caller_address();
            
            assert(recipients.len() == amounts.len(), 'Arrays length mismatch');
            assert(recipients.len() <= self.batch_operation_limit.read(), 'Batch size too large');
            
            let mut total_amount = 0;
            let mut i = 0;
            
            // Calculate total amount first
            while i != amounts.len() {
                total_amount += *amounts.at(i);
                i += 1;
            };
            
            // Check balance
            let balance = self.balances.read(caller);
            assert(balance >= total_amount, 'Insufficient balance');
            
            // Execute transfers
            i = 0;
            while i != recipients.len() {
                let recipient = *recipients.at(i);
                let amount = *amounts.at(i);
                
                let recipient_balance = self.balances.read(recipient);
                self.balances.write(recipient, recipient_balance + amount);
                
                self.emit(Event::Transfer(Transfer {
                    from: caller,
                    to: recipient,
                    value: amount,
                }));
                
                i += 1;
            };
            
            // Update sender balance
            self.balances.write(caller, balance - total_amount);
            
            self.emit(Event::BatchTransferCompleted(BatchTransferCompleted {
                sender: caller,
                transfer_count: recipients.len().into(),
                total_amount,
                gas_saved: 0, // Would calculate actual gas savings
            }));
            
            true
        }

        fn report_suspicious_activity(ref self: ContractState, activity_type: felt252, severity: u32) {
            let caller = get_caller_address();
            let report_id = self.suspicious_activity_count.read();
            self.suspicious_activity_count.write(report_id + 1);
            
            self.emit(Event::SuspiciousActivityReported(SuspiciousActivityReported {
                reporter: caller,
                activity_type,
                severity,
                timestamp: get_block_timestamp(),
            }));
            
            // Trigger security review if threshold exceeded
            let threshold = self.security_alert_threshold.read();
            if threshold > 0 {
                let next_report_id = report_id + 1;
                if threshold <= next_report_id {
                    self.last_security_review.write(get_block_timestamp());
                }
            }
        }

        fn get_security_monitoring_status(self: @ContractState) -> (u32, u32, u64) {
            let suspicious_count = self.suspicious_activity_count.read();
            let alert_threshold = self.security_alert_threshold.read();
            let last_review = self.last_security_review.read();
            
            (suspicious_count, alert_threshold, last_review)
        }

        fn emergency_withdraw(ref self: ContractState, amount: u256, justification: felt252) {
            self._only_emergency_council();
            
            let owner = self.owner.read();
            let balance = self.balances.read(owner);
            assert(balance >= amount, 'Insufficient balance');
            
            // Transfer to emergency council multisig
            let emergency_address = self.emergency_council_multisig.read();
            self.balances.write(owner, balance - amount);
            let emergency_balance = self.balances.read(emergency_address);
            self.balances.write(emergency_address, emergency_balance + amount);
            
            self.emit(Event::EmergencyWithdrawal(EmergencyWithdrawal {
                executor: get_caller_address(),
                amount,
                justification,
                timestamp: get_block_timestamp(),
            }));
            
            self.emit(Event::Transfer(Transfer {
                from: owner,
                to: emergency_address,
                value: amount,
            }));
        }

        fn authorize_upgrade(ref self: ContractState, new_implementation: ContractAddress, timelock_duration: u64) {
            self._only_emergency_council();
            
            let current_time = get_block_timestamp();
            let upgrade_time = current_time + timelock_duration;
            
            self.upgrade_authorization.write(new_implementation, true);
            self.critical_operations_timelock.write(new_implementation, upgrade_time);
            
            self.emit(Event::UpgradeAuthorized(UpgradeAuthorized {
                new_implementation,
                authorized_by: get_caller_address(),
                timelock_duration,
                execute_after: upgrade_time,
            }));
        }
    }

    /// Internal Implementation Functions
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _transfer(ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: u256) {
            self._not_paused();
            assert(!sender.is_zero(), 'Transfer from zero address');
            assert(!recipient.is_zero(), 'Transfer to zero address');
            
            let sender_balance = self.balances.read(sender);
            assert(sender_balance >= amount, 'Insufficient balance');
            
            self.balances.write(sender, sender_balance - amount);
            let recipient_balance = self.balances.read(recipient);
            self.balances.write(recipient, recipient_balance + amount);
            
            // Track when users first acquire tokens for progressive governance rights
            if recipient_balance == 0 {
                self._update_token_lock_start(recipient);
            }
            
            self.emit(Event::Transfer(Transfer {
                from: sender,
                to: recipient,
                value: amount,
            }));
        }

        fn _only_authorized(self: @ContractState) {
            let caller = get_caller_address();
            assert(
                caller == self.owner.read() || 
                self.emergency_council.read(caller),
                'Unauthorized caller'
            );
        }
        
        fn _only_emergency_council(self: @ContractState) {
            let caller = get_caller_address();
            assert(
                caller == self.owner.read() || 
                self.emergency_council.read(caller) ||
                caller == self.emergency_council_multisig.read(),
                'Not emergency council'
            );
        }

        fn _not_paused(self: @ContractState) {
            assert(!self.paused.read(), 'Contract is paused');
        }

        fn _check_inflation_limits(self: @ContractState, amount: u256) {
            // Implement inflation rate checking logic here
            // This would verify that the mint amount doesn't exceed governance-set limits
        }

        fn _calculate_voting_power(self: @ContractState, account: ContractAddress) -> u256 {
            let base_voting_power = self.balances.read(account);
            
            // Get governance tier and apply multiplier
            let governance_tier = self._get_governance_tier(account);
            let multiplier = self._get_voting_multiplier(governance_tier);
            
            // Calculate enhanced voting power
            let enhanced_power = (base_voting_power * multiplier.into()) / 100;
            
            enhanced_power
        }
        
        fn _get_governance_tier(self: @ContractState, account: ContractAddress) -> u32 {
            let token_lock_start = self.token_lock_start.read(account);
            let current_time = get_block_timestamp();
            
            if token_lock_start == 0 {
                return 0; // Basic tier - no holding history
            }
            
            let holding_duration = current_time - token_lock_start;
            
            if holding_duration >= VETERAN_HOLDER_MINIMUM_PERIOD {
                2 // Veteran tier (2+ years)
            } else if holding_duration >= LONG_TERM_HOLDER_MINIMUM_PERIOD {
                1 // Long-term tier (1+ years)
            } else {
                0 // Basic tier
            }
        }
        
        fn _get_voting_multiplier(self: @ContractState, governance_tier: u32) -> u32 {
            match governance_tier {
                0 => 100, // 1.0x - basic
                1 => VOTING_POWER_MULTIPLIER_LONG_TERM, // 1.2x - long-term
                2 => VOTING_POWER_MULTIPLIER_VETERAN, // 1.5x - veteran
                _ => 100, // Default to basic
            }
        }
        
        fn _check_proposal_threshold(self: @ContractState, account: ContractAddress, proposal_type: u32) -> bool {
            let voting_power = self._calculate_voting_power(account);
            
            let required_threshold = match proposal_type {
                0 => GOVERNANCE_MINOR_THRESHOLD,
                1 => GOVERNANCE_MAJOR_THRESHOLD,
                2 => GOVERNANCE_PROTOCOL_THRESHOLD,
                3 => GOVERNANCE_EMERGENCY_THRESHOLD,
                4 => GOVERNANCE_STRATEGIC_THRESHOLD,
                _ => GOVERNANCE_STRATEGIC_THRESHOLD, // Default to highest
            };
            
            voting_power >= required_threshold
        }
        
        fn _update_token_lock_start(ref self: ContractState, account: ContractAddress) {
            let current_lock_start = self.token_lock_start.read(account);
            if current_lock_start == 0 {
                // First time acquiring tokens
                self.token_lock_start.write(account, get_block_timestamp());
            }
        }
        
        fn _calculate_quorum_requirement(self: @ContractState) -> u256 {
            let total_supply = self.total_supply.read();
            (total_supply * QUORUM_PERCENTAGE.into()) / 10000
        }
        
        fn _requires_supermajority(self: @ContractState, proposal_type: u32) -> bool {
            // Critical proposals require supermajority
            proposal_type >= 2 // Protocol upgrades, emergency, strategic
        }

        fn _get_current_inflation_rate(self: @ContractState) -> u32 {
            // Update inflation rate based on network phase
            let phase = self._determine_current_phase();
            
            match phase {
                0 => 800, // 8% - Bootstrap phase
                1 => 500, // 5% - Growth phase  
                2 => 300, // 3% - Transition phase
                _ => 100,               // 1% for mature
            }
        }

        fn _get_current_burn_rate(self: @ContractState) -> u32 {
            let launch_time = self.launch_timestamp.read();
            let current_time = get_block_timestamp();
            let months_since_launch = (current_time - launch_time) / (30 * 24 * 3600); // Approximate months
            
            if months_since_launch <= 12 {
                3000 // 30%
            } else if months_since_launch <= 36 {
                5000 // 50%
            } else if months_since_launch <= 60 {
                7000 // 70%
            } else {
                8000 // 80%
            }
        }

        fn _determine_current_phase(self: @ContractState) -> u32 {
            let launch_time = self.launch_timestamp.read();
            let current_time = get_block_timestamp();
            let years_since_launch = (current_time - launch_time) / (365 * 24 * 3600);
            
            if years_since_launch <= 2 {
                0 // Bootstrap phase
            } else if years_since_launch <= 3 {
                1 // Growth phase
            } else if years_since_launch <= 4 {
                2 // Transition phase
            } else {
                3 // Mature phase
            }
        }

        fn _update_revenue_tracking(ref self: ContractState, revenue_amount: u256) {
            let current_total = self.total_revenue_collected.read();
            self.total_revenue_collected.write(current_total + revenue_amount);
            
            // Reset monthly revenue if needed
            let last_reset = self.last_revenue_reset.read();
            let current_time = get_block_timestamp();
            
            if current_time - last_reset > (30 * 24 * 3600) { // 30 days
                self.monthly_revenue.write(revenue_amount);
                self.last_revenue_reset.write(current_time);
            } else {
                let current_monthly = self.monthly_revenue.read();
                self.monthly_revenue.write(current_monthly + revenue_amount);
            }
        }

        fn _get_monthly_revenue(self: @ContractState) -> u256 {
            let last_reset = self.last_revenue_reset.read();
            let current_time = get_block_timestamp();
            
            if current_time - last_reset > (30 * 24 * 3600) {
                0 // Reset needed
            } else {
                self.monthly_revenue.read()
            }
        }

        fn _calculate_burn_efficiency(self: @ContractState) -> u32 {
            // Simple burn efficiency calculation
            // This could be enhanced with more sophisticated metrics
            let total_burned = self.total_burned.read();
            let total_supply = TOTAL_SUPPLY;
            
            ((total_burned * 10000) / total_supply).try_into().unwrap_or(0)
        }

        fn _initialize_security_defaults(ref self: ContractState) {
            // Initialize default security settings
            self.security_score.write(100); // Perfect security score initially
            self.audit_findings_count.write(0);
            self.last_audit_timestamp.write(get_block_timestamp());
            
            // Initialize large transfer threshold - 10,000 tokens (1% of initial circulation)
            // This allows normal transfers while flagging large movements that need extra security
            self.large_transfer_threshold.write(10_000_000_000_000_000_000_000); // 10,000 CIRO tokens
        }

        fn _check_and_update_rate_limit(ref self: ContractState, amount: u256) {
            let current_time = get_block_timestamp();
            let window_duration = 86400; // 24 hours
            
            // Get current rate limit data
            let current_usage = self.daily_transfer_amount.read();
            let window_start = self.rate_limit_window_start.read();
            
            // Check if we need to reset the window
            if current_time >= window_start + window_duration {
                // Reset window
                self.daily_transfer_amount.write(amount);
                self.rate_limit_window_start.write(current_time);
            } else {
                // Update current window
                self.daily_transfer_amount.write(current_usage + amount);
            }
        }
    }
} 