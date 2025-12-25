// SAGE Network Smart Contracts
// Main library file for Cairo 2.x smart contracts

pub mod cdc_pool;
pub mod sage_token;
pub mod job_manager;
pub mod reputation_manager;
pub mod simple_events;

pub mod interfaces {
    pub mod cdc_pool;
    pub mod sage_token;
    pub mod job_manager;
    pub mod proof_verifier;
    pub mod reputation_manager;
    // TODO: Create these interface files when needed
    // mod task_allocator;
}

pub mod utils {
    pub mod constants;
    pub mod types;
    pub mod security;
    pub mod interactions;
    pub mod governance;
    pub mod upgradability;
    // Cairo 2.12.0: Code deduplication utilities
    pub mod common;
}

pub mod vesting {
    pub mod linear_vesting_with_cliff;
    pub mod milestone_vesting;
    pub mod burn_manager;
    pub mod treasury_timelock;
}

pub mod governance {
    pub mod governance_treasury;
}

pub mod contracts {
    pub mod proof_verifier;
    pub mod staking;
    pub mod gamification;
    pub mod fraud_proof;
    pub mod achievement_nft;
}

pub mod obelysk;

// Prover staking for GPU workers
pub mod staking;

// Testnet faucet for token distribution
pub mod faucet;

// Address registry for human-readable names (obelysk:, sage:, bitsage:)
pub mod registry;

// Oracle - Pragma price feed integration
pub mod oracle;

// Economics (based on BitSage Financial Model v2)
// - Fee Management (20% protocol fee, 70/20/10 split)
// - Collateral System
// - Escrow for job payments
pub mod economics;

// Tokenomics - Official SAGE Token Distribution & Vesting Schedules
// Distribution: Ecosystem 30%, Treasury 15%, Team 15%, Liquidity 10%,
//               Pre-Seed 7.5%, Code Dev 5%, Public Sale 5%, Strategic 5%,
//               Seed 5%, Advisors 2.5%
// Vesting: Team (12Mo cliff + 36Mo), Investors (12-24Mo), Treasury (48Mo),
//          Ecosystem (5-Year Emission)
pub mod tokenomics;

// Payment Router - Multi-token payment system
// Accepts: USDC, STRK, wBTC, SAGE with tiered discounts
// Features: OTC desk (no AMM dependency), staked SAGE credits, privacy payments
pub mod payments;

// Growth - Adoption and referral tools
// Features: Tiered referral rewards, affiliate tracking
pub mod growth;

// Tests are located in the tests/ directory and managed by snforge