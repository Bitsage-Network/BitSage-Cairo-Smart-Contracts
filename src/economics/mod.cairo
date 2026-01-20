//! BitSage Network Economics System
//! Based on BitSage Financial Model v2
//!
//! ## Core Economics
//! - **Protocol Fee**: 20% of GMV (85% worker / 15% protocol)
//! - **Fee Split**: 70% burned / 20% treasury / 10% stakers
//! - **Real Yield**: Staking rewards from actual fees (not inflationary)
//! - **Break-even GMV**: ~$1.875M/month at $75K/month OpEx
//!
//! ## Mining Rewards (Work-First Model)
//! - **Per-Job Rewards**: 2 SAGE base per valid proof (Year 1)
//! - **Daily Caps**: 100-500 SAGE/day based on staking tier
//! - **GPU Multipliers**: 1.0x (Consumer) to 2.5x (Frontier)
//! - **Halvening**: Annual reduction over 5 years
//! - **Pool**: 300M SAGE total allocation
//!
//! ## Contracts
//! - **FeeManager**: Core fee processing and distribution
//! - **Collateral**: Gonka-inspired collateral-backed weight system
//! - **Escrow**: Job payment escrow with refund mechanism
//! - **MiningRewards**: Per-job mining reward distribution with daily caps
//!
//! ## Inspired By
//! - Gonka Protocol (collateral, vesting, dynamic pricing)
//! - Cocoon Protocol (TEE attestation marketplace)
//! - BitSage Financial Model v2 (fee economics)

pub mod fee_manager;
pub mod collateral;
pub mod escrow;
pub mod mining_rewards;

// Re-export mining rewards types for convenience
pub use mining_rewards::{
    StakeTier, DailyStats, WorkerMiningStats, MiningConfig, RewardResult,
    IMiningRewards, IMiningRewardsDispatcher, IMiningRewardsDispatcherTrait,
};
