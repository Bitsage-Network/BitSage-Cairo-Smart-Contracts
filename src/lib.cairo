// CIRO Network Smart Contracts
// Main library file for Cairo 2.x smart contracts

pub mod cdc_pool;
pub mod ciro_token;
pub mod job_manager;
pub mod reputation_manager;
pub mod simple_events;

pub mod interfaces {
    pub mod cdc_pool;
    pub mod ciro_token;
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
}

pub mod obelysk;

// Prover staking for GPU workers
pub mod staking;

// Testnet faucet for token distribution
pub mod faucet;

// Economics (based on BitSage Financial Model v2)
// - Fee Management (20% protocol fee, 70/20/10 split)
// - Collateral System
// - Escrow for job payments
pub mod economics;

// Tests are located in the tests/ directory and managed by snforge