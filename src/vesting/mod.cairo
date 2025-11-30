//! CIRO Network Vesting System
//! Complete production-ready vesting and tokenomics management
//! 
//! This module implements the sophisticated vesting system designed for CIRO Network's
//! market-tested tokenomics with the following components:
//!
//! ## Core Vesting Contracts
//! - **LinearVestingWithCliff**: Team, Private, Seed, Development allocations
//! - **MilestoneVesting**: Advisor allocations with KPI tracking
//! - **BurnManager**: Hybrid burning system (automatic + DAO-triggered)
//! - **TreasuryTimelock**: Multi-sig treasury management
//!
//! ## Security Features
//! - Multi-signature approvals with configurable thresholds
//! - Timelock delays for sensitive operations
//! - Role-based access controls with OpenZeppelin components
//! - Reentrancy protection and pausable mechanisms
//! - Complete audit trail with comprehensive event emissions
//!
//! ## Compliance & Legal
//! - KYC/AML integration hooks
//! - SAFT compliance features
//! - Schedule flagging and approval workflows
//! - Regulatory reporting capabilities
//!
//! ## Architecture Highlights
//! - Zero single-point-of-failure design
//! - Treasury-only source protection for burns
//! - Daily limits with rolling windows
//! - Challenge systems for governance oversight
//! - Performance tracking for milestone-based vesting
//!
//! ## Deployment Readiness
//! - Production-ready contracts with comprehensive testing
//! - Upgrade-safe implementations
//! - Emergency controls and pause mechanisms
//! - Complete integration with CIRO token ecosystem

// Re-export all vesting contracts for external access
pub mod linear_vesting_with_cliff;
pub mod milestone_vesting;
pub mod burn_manager;
pub mod treasury_timelock;

// Re-export key interfaces and types
pub use linear_vesting_with_cliff::{
    ILinearVestingWithCliff, ILinearVestingWithCliffDispatcher, ILinearVestingWithCliffDispatcherTrait,
    LinearVestingWithCliff, VestingSchedule, MultiSigProposal
};

pub use milestone_vesting::{
    IMilestoneVesting, IMilestoneVestingDispatcher, IMilestoneVestingDispatcherTrait,
    MilestoneVesting, MilestoneSchedule, Milestone, MilestoneStatus, Challenge
};

pub use burn_manager::{
    IBurnManager, IBurnManagerDispatcher, IBurnManagerDispatcherTrait,
    BurnManager, BurnStatistics, KPIBurnProposal, KPIMilestone, ProposalStatus, DailyBurnData
};

pub use treasury_timelock::{
    ITreasuryTimelock, ITreasuryTimelockDispatcher, ITreasuryTimelockDispatcherTrait,
    TreasuryTimelock, TimelockTransaction
};

//! ## Integration Notes
//! 
//! ### Deployment Sequence
//! 1. Deploy LinearVestingWithCliff contract
//! 2. Deploy MilestoneVesting contract  
//! 3. Deploy TreasuryTimelock contract
//! 4. Deploy BurnManager contract
//! 5. Configure cross-contract permissions
//! 6. Transfer initial token allocations
//! 7. Initialize vesting schedules
//!
//! ### Configuration Requirements
//! - Multi-sig member addresses for each contract
//! - Timelock delays (recommended: 24h for normal ops, 7d for critical changes)
//! - Daily burn limits aligned with tokenomics model
//! - KPI milestone definitions with oracle addresses
//! - Compliance officer addresses for KYC/AML workflows
//!
//! ### Cross-Contract Dependencies
//! - BurnManager requires BURN_AUTHORITY_ROLE on CIRO token
//! - Vesting contracts require token allowances for releases
//! - TreasuryTimelock manages treasury contract permissions
//! - All contracts integrate with AccessControl hierarchy
//!
//! ### Security Considerations
//! - Verify all multi-sig thresholds match governance requirements
//! - Ensure emergency roles are distributed across trusted parties  
//! - Test all timelock delays in staging environment
//! - Validate burn limits prevent excessive token destruction
//! - Confirm compliance workflows meet regulatory requirements 