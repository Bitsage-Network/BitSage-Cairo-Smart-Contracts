//! BitSage Network Tokenomics
//! Official SAGE Token Distribution & Vesting Schedules
//!
//! Total Supply: 1,000,000,000 SAGE (1 Billion)
//!
//! ## Distribution Pools
//! | Pool               | Allocation | Tokens      | Vesting                          |
//! |--------------------|------------|-------------|----------------------------------|
//! | Ecosystem Rewards  | 30.0%      | 300,000,000 | 5-Year Emission Schedule         |
//! | Treasury           | 15.0%      | 150,000,000 | 48-Month Linear Unlocks          |
//! | Team               | 15.0%      | 150,000,000 | 12-Month Cliff + 36-Month Linear |
//! | Market Liquidity   | 10.0%      | 100,000,000 | Immediate (DEX/CEX)              |
//! | Pre-Seed           | 7.5%       | 75,000,000  | 12-Month Linear Vesting          |
//! | Code Dev & Infra   | 5.0%       | 50,000,000  | 36-Month Linear Vesting          |
//! | Public Sale        | 5.0%       | 50,000,000  | TGE Unlock + 6-Month Linear      |
//! | Strategic Partners | 5.0%       | 50,000,000  | 24-Month Linear Vesting          |
//! | Seed               | 5.0%       | 50,000,000  | 24-Month Linear Vesting          |
//! | Advisors           | 2.5%       | 25,000,000  | 12-Month Cliff + 24-Month Linear |
//!
//! ## Investor Category Breakdown (17.5% Total)
//! - Pre-Seed: 7.5% (75M) - 12-Month Linear
//! - Seed: 5.0% (50M) - 24-Month Linear
//! - Strategic Partners: 5.0% (50M) - 24-Month Linear
//!
//! ## Vesting Summary
//! - Team: 12-Month Cliff → 36-Month Linear (Total: 48 months)
//! - Investors: 12-24 Month Linear Vesting
//! - Treasury: 48-Month Linear Unlocks
//! - Ecosystem: 5-Year Emission Schedule (60 months)

// ============================================================================
// TOTAL SUPPLY
// ============================================================================

/// Total token supply: 1 Billion SAGE with 18 decimals
pub const TOTAL_SUPPLY: u256 = 1_000_000_000_000_000_000_000_000_000;

/// Decimal scale (10^18)
pub const DECIMALS_SCALE: u256 = 1_000_000_000_000_000_000;

/// Basis points scale (10000 = 100%)
pub const BPS_SCALE: u256 = 10000;

// ============================================================================
// DISTRIBUTION ALLOCATIONS (Basis Points - 10000 = 100%)
// ============================================================================

/// Ecosystem Rewards: 30% - Network incentives, staking rewards, community programs
pub const ALLOCATION_ECOSYSTEM_BPS: u256 = 3000;

/// Treasury: 15% - Protocol development, operations, security budget
pub const ALLOCATION_TREASURY_BPS: u256 = 1500;

/// Team: 15% - Core team and founders
pub const ALLOCATION_TEAM_BPS: u256 = 1500;

/// Market Liquidity: 10% - DEX/CEX liquidity, market making
pub const ALLOCATION_LIQUIDITY_BPS: u256 = 1000;

/// Pre-Seed: 7.5% - Early investors
pub const ALLOCATION_PRE_SEED_BPS: u256 = 750;

/// Code Development & Infrastructure: 5% - Developer grants, infrastructure
pub const ALLOCATION_CODE_DEV_BPS: u256 = 500;

/// Public Sale: 5% - Community token sale
pub const ALLOCATION_PUBLIC_SALE_BPS: u256 = 500;

/// Strategic Partners: 5% - Key ecosystem partners
pub const ALLOCATION_STRATEGIC_BPS: u256 = 500;

/// Seed: 5% - Seed round investors
pub const ALLOCATION_SEED_BPS: u256 = 500;

/// Advisors: 2.5% - Advisory board
pub const ALLOCATION_ADVISORS_BPS: u256 = 250;

// ============================================================================
// TOKEN AMOUNTS (with 18 decimals)
// ============================================================================

/// Ecosystem Rewards: 300,000,000 SAGE
pub const TOKENS_ECOSYSTEM: u256 = 300_000_000_000_000_000_000_000_000;

/// Treasury: 150,000,000 SAGE
pub const TOKENS_TREASURY: u256 = 150_000_000_000_000_000_000_000_000;

/// Team: 150,000,000 SAGE
pub const TOKENS_TEAM: u256 = 150_000_000_000_000_000_000_000_000;

/// Market Liquidity: 100,000,000 SAGE
pub const TOKENS_LIQUIDITY: u256 = 100_000_000_000_000_000_000_000_000;

/// Pre-Seed: 75,000,000 SAGE
pub const TOKENS_PRE_SEED: u256 = 75_000_000_000_000_000_000_000_000;

/// Code Development & Infrastructure: 50,000,000 SAGE
pub const TOKENS_CODE_DEV: u256 = 50_000_000_000_000_000_000_000_000;

/// Public Sale: 50,000,000 SAGE
pub const TOKENS_PUBLIC_SALE: u256 = 50_000_000_000_000_000_000_000_000;

/// Strategic Partners: 50,000,000 SAGE
pub const TOKENS_STRATEGIC: u256 = 50_000_000_000_000_000_000_000_000;

/// Seed: 50,000,000 SAGE
pub const TOKENS_SEED: u256 = 50_000_000_000_000_000_000_000_000;

/// Advisors: 25,000,000 SAGE
pub const TOKENS_ADVISORS: u256 = 25_000_000_000_000_000_000_000_000;

// ============================================================================
// INVESTOR CATEGORY AGGREGATES (17.5% Total)
// ============================================================================

/// Total Investor Allocation: Pre-Seed + Seed + Strategic = 17.5%
pub const ALLOCATION_INVESTORS_TOTAL_BPS: u256 = 1750;

/// Total Investor Tokens: 175,000,000 SAGE
pub const TOKENS_INVESTORS_TOTAL: u256 = 175_000_000_000_000_000_000_000_000;

// ============================================================================
// VESTING SCHEDULES (Time in Seconds)
// ============================================================================

/// Seconds per month (30 days approximation)
pub const SECONDS_PER_MONTH: u64 = 2_592_000;

/// Seconds per year (365 days)
pub const SECONDS_PER_YEAR: u64 = 31_536_000;

// --- Team Vesting ---
/// Team cliff duration: 12 months
pub const TEAM_CLIFF_DURATION: u64 = 31_536_000; // 12 months

/// Team vesting duration after cliff: 36 months
pub const TEAM_VESTING_DURATION: u64 = 93_312_000; // 36 months

/// Team total vesting period: 48 months
pub const TEAM_TOTAL_DURATION: u64 = 124_848_000; // 48 months

// --- Pre-Seed Vesting ---
/// Pre-Seed cliff duration: 0 (no cliff)
pub const PRE_SEED_CLIFF_DURATION: u64 = 0;

/// Pre-Seed vesting duration: 12 months linear
pub const PRE_SEED_VESTING_DURATION: u64 = 31_536_000; // 12 months

// --- Seed Vesting ---
/// Seed cliff duration: 0 (no cliff)
pub const SEED_CLIFF_DURATION: u64 = 0;

/// Seed vesting duration: 24 months linear
pub const SEED_VESTING_DURATION: u64 = 63_072_000; // 24 months

// --- Strategic Partners Vesting ---
/// Strategic Partners cliff duration: 0 (no cliff)
pub const STRATEGIC_CLIFF_DURATION: u64 = 0;

/// Strategic Partners vesting duration: 24 months linear
pub const STRATEGIC_VESTING_DURATION: u64 = 63_072_000; // 24 months

// --- Advisors Vesting ---
/// Advisors cliff duration: 12 months
pub const ADVISORS_CLIFF_DURATION: u64 = 31_536_000; // 12 months

/// Advisors vesting duration after cliff: 24 months
pub const ADVISORS_VESTING_DURATION: u64 = 63_072_000; // 24 months

/// Advisors total vesting period: 36 months
pub const ADVISORS_TOTAL_DURATION: u64 = 94_608_000; // 36 months

// --- Treasury Vesting ---
/// Treasury cliff duration: 0 (no cliff, but linear unlock)
pub const TREASURY_CLIFF_DURATION: u64 = 0;

/// Treasury vesting duration: 48 months linear unlocks
pub const TREASURY_VESTING_DURATION: u64 = 124_848_000; // 48 months

// --- Code Dev & Infrastructure Vesting ---
/// Code Dev cliff duration: 0
pub const CODE_DEV_CLIFF_DURATION: u64 = 0;

/// Code Dev vesting duration: 36 months linear
pub const CODE_DEV_VESTING_DURATION: u64 = 93_312_000; // 36 months

// --- Public Sale Vesting ---
/// Public Sale TGE unlock percentage: 20% (in basis points)
pub const PUBLIC_SALE_TGE_UNLOCK_BPS: u256 = 2000;

/// Public Sale cliff duration: 0 (TGE unlock)
pub const PUBLIC_SALE_CLIFF_DURATION: u64 = 0;

/// Public Sale vesting duration: 6 months for remaining 80%
pub const PUBLIC_SALE_VESTING_DURATION: u64 = 15_768_000; // 6 months

// --- Ecosystem Emission Schedule ---
/// Ecosystem emission duration: 5 years (60 months)
pub const ECOSYSTEM_EMISSION_DURATION: u64 = 157_680_000; // 5 years

/// Ecosystem emission epochs: 60 months
pub const ECOSYSTEM_EMISSION_EPOCHS: u64 = 60;

// ============================================================================
// VESTING SCHEDULE TYPES
// ============================================================================

/// Allocation pool identifier
#[derive(Drop, Copy, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum AllocationPool {
    Ecosystem,
    Treasury,
    Team,
    Liquidity,
    PreSeed,
    CodeDev,
    PublicSale,
    Strategic,
    Seed,
    Advisors,
}

/// Vesting type for different unlock mechanisms
#[derive(Drop, Copy, Serde, starknet::Store, PartialEq)]
#[allow(starknet::store_no_default_variant)]
pub enum VestingType {
    /// Linear vesting with optional cliff
    LinearWithCliff,
    /// Emission schedule (for ecosystem rewards)
    EmissionSchedule,
    /// TGE unlock + linear vesting
    TGEPlusLinear,
    /// Immediate unlock (no vesting)
    Immediate,
    /// Milestone-based vesting
    Milestone,
}

/// Complete vesting configuration for a pool
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct VestingConfig {
    pub pool: AllocationPool,
    pub total_allocation_bps: u256,
    pub total_tokens: u256,
    pub cliff_duration: u64,
    pub vesting_duration: u64,
    pub vesting_type: VestingType,
    pub tge_unlock_bps: u256, // For TGEPlusLinear type
}

/// Ecosystem emission schedule configuration
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct EmissionSchedule {
    pub total_tokens: u256,
    pub duration_months: u64,
    pub start_timestamp: u64,
    pub tokens_emitted: u256,
    pub last_emission_timestamp: u64,
}

/// Monthly emission rate for ecosystem rewards
#[derive(Drop, Copy, Serde, starknet::Store)]
pub struct MonthlyEmission {
    pub month: u64,
    pub emission_rate_bps: u256, // Percentage of remaining tokens
    pub tokens_released: u256,
}

// ============================================================================
// ECOSYSTEM EMISSION SCHEDULE (5-Year Decay)
// ============================================================================

/// Year 1 emission rate: Higher initial distribution
pub const EMISSION_YEAR_1_MONTHLY_BPS: u256 = 300; // 3% of remaining per month

/// Year 2 emission rate
pub const EMISSION_YEAR_2_MONTHLY_BPS: u256 = 250; // 2.5% of remaining per month

/// Year 3 emission rate
pub const EMISSION_YEAR_3_MONTHLY_BPS: u256 = 200; // 2% of remaining per month

/// Year 4 emission rate
pub const EMISSION_YEAR_4_MONTHLY_BPS: u256 = 150; // 1.5% of remaining per month

/// Year 5 emission rate
pub const EMISSION_YEAR_5_MONTHLY_BPS: u256 = 100; // 1% of remaining per month

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Get vesting configuration for a specific pool
pub fn get_vesting_config(pool: AllocationPool) -> VestingConfig {
    match pool {
        AllocationPool::Ecosystem => VestingConfig {
            pool: AllocationPool::Ecosystem,
            total_allocation_bps: ALLOCATION_ECOSYSTEM_BPS,
            total_tokens: TOKENS_ECOSYSTEM,
            cliff_duration: 0,
            vesting_duration: ECOSYSTEM_EMISSION_DURATION,
            vesting_type: VestingType::EmissionSchedule,
            tge_unlock_bps: 0,
        },
        AllocationPool::Treasury => VestingConfig {
            pool: AllocationPool::Treasury,
            total_allocation_bps: ALLOCATION_TREASURY_BPS,
            total_tokens: TOKENS_TREASURY,
            cliff_duration: TREASURY_CLIFF_DURATION,
            vesting_duration: TREASURY_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
        AllocationPool::Team => VestingConfig {
            pool: AllocationPool::Team,
            total_allocation_bps: ALLOCATION_TEAM_BPS,
            total_tokens: TOKENS_TEAM,
            cliff_duration: TEAM_CLIFF_DURATION,
            vesting_duration: TEAM_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
        AllocationPool::Liquidity => VestingConfig {
            pool: AllocationPool::Liquidity,
            total_allocation_bps: ALLOCATION_LIQUIDITY_BPS,
            total_tokens: TOKENS_LIQUIDITY,
            cliff_duration: 0,
            vesting_duration: 0,
            vesting_type: VestingType::Immediate,
            tge_unlock_bps: 10000, // 100% at TGE
        },
        AllocationPool::PreSeed => VestingConfig {
            pool: AllocationPool::PreSeed,
            total_allocation_bps: ALLOCATION_PRE_SEED_BPS,
            total_tokens: TOKENS_PRE_SEED,
            cliff_duration: PRE_SEED_CLIFF_DURATION,
            vesting_duration: PRE_SEED_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
        AllocationPool::CodeDev => VestingConfig {
            pool: AllocationPool::CodeDev,
            total_allocation_bps: ALLOCATION_CODE_DEV_BPS,
            total_tokens: TOKENS_CODE_DEV,
            cliff_duration: CODE_DEV_CLIFF_DURATION,
            vesting_duration: CODE_DEV_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
        AllocationPool::PublicSale => VestingConfig {
            pool: AllocationPool::PublicSale,
            total_allocation_bps: ALLOCATION_PUBLIC_SALE_BPS,
            total_tokens: TOKENS_PUBLIC_SALE,
            cliff_duration: PUBLIC_SALE_CLIFF_DURATION,
            vesting_duration: PUBLIC_SALE_VESTING_DURATION,
            vesting_type: VestingType::TGEPlusLinear,
            tge_unlock_bps: PUBLIC_SALE_TGE_UNLOCK_BPS,
        },
        AllocationPool::Strategic => VestingConfig {
            pool: AllocationPool::Strategic,
            total_allocation_bps: ALLOCATION_STRATEGIC_BPS,
            total_tokens: TOKENS_STRATEGIC,
            cliff_duration: STRATEGIC_CLIFF_DURATION,
            vesting_duration: STRATEGIC_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
        AllocationPool::Seed => VestingConfig {
            pool: AllocationPool::Seed,
            total_allocation_bps: ALLOCATION_SEED_BPS,
            total_tokens: TOKENS_SEED,
            cliff_duration: SEED_CLIFF_DURATION,
            vesting_duration: SEED_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
        AllocationPool::Advisors => VestingConfig {
            pool: AllocationPool::Advisors,
            total_allocation_bps: ALLOCATION_ADVISORS_BPS,
            total_tokens: TOKENS_ADVISORS,
            cliff_duration: ADVISORS_CLIFF_DURATION,
            vesting_duration: ADVISORS_VESTING_DURATION,
            vesting_type: VestingType::LinearWithCliff,
            tge_unlock_bps: 0,
        },
    }
}

/// Calculate vested amount for linear vesting with cliff
/// Returns the amount of tokens that have vested at the given timestamp
pub fn calculate_linear_vested_amount(
    total_amount: u256,
    start_time: u64,
    cliff_duration: u64,
    vesting_duration: u64,
    current_time: u64,
) -> u256 {
    // Before cliff: nothing vested
    if current_time < start_time + cliff_duration {
        return 0;
    }

    // After full vesting: everything vested
    let vesting_end = start_time + cliff_duration + vesting_duration;
    if current_time >= vesting_end {
        return total_amount;
    }

    // During vesting: linear calculation
    let time_since_cliff = current_time - (start_time + cliff_duration);
    let vested = (total_amount * time_since_cliff.into()) / vesting_duration.into();

    vested
}

/// Calculate vested amount for TGE + Linear vesting
pub fn calculate_tge_plus_linear_vested_amount(
    total_amount: u256,
    tge_unlock_bps: u256,
    start_time: u64,
    vesting_duration: u64,
    current_time: u64,
) -> u256 {
    // TGE unlock immediately available
    let tge_amount = (total_amount * tge_unlock_bps) / BPS_SCALE;

    if current_time < start_time {
        return 0;
    }

    // If TGE only (no vesting duration), return TGE amount
    if vesting_duration == 0 {
        return tge_amount;
    }

    // Calculate linear vesting of remaining amount
    let remaining_amount = total_amount - tge_amount;
    let vesting_end = start_time + vesting_duration;

    if current_time >= vesting_end {
        return total_amount;
    }

    let time_elapsed: u256 = (current_time - start_time).into();
    let linear_vested = (remaining_amount * time_elapsed) / vesting_duration.into();

    tge_amount + linear_vested
}

/// Get ecosystem emission rate for a given month (1-60)
pub fn get_ecosystem_monthly_emission_rate(month: u64) -> u256 {
    if month <= 12 {
        EMISSION_YEAR_1_MONTHLY_BPS
    } else if month <= 24 {
        EMISSION_YEAR_2_MONTHLY_BPS
    } else if month <= 36 {
        EMISSION_YEAR_3_MONTHLY_BPS
    } else if month <= 48 {
        EMISSION_YEAR_4_MONTHLY_BPS
    } else {
        EMISSION_YEAR_5_MONTHLY_BPS
    }
}

/// Calculate ecosystem tokens to emit for a given month
/// Uses a decay model where emission rate is applied to remaining tokens
pub fn calculate_ecosystem_monthly_emission(
    remaining_tokens: u256,
    month: u64,
) -> u256 {
    let rate = get_ecosystem_monthly_emission_rate(month);
    (remaining_tokens * rate) / BPS_SCALE
}

/// Verify total allocation equals 100% (10000 bps)
pub fn verify_allocation_sum() -> bool {
    let total = ALLOCATION_ECOSYSTEM_BPS
        + ALLOCATION_TREASURY_BPS
        + ALLOCATION_TEAM_BPS
        + ALLOCATION_LIQUIDITY_BPS
        + ALLOCATION_PRE_SEED_BPS
        + ALLOCATION_CODE_DEV_BPS
        + ALLOCATION_PUBLIC_SALE_BPS
        + ALLOCATION_STRATEGIC_BPS
        + ALLOCATION_SEED_BPS
        + ALLOCATION_ADVISORS_BPS;

    total == BPS_SCALE
}

/// Get all allocation pools as an array
pub fn get_all_pools() -> Array<AllocationPool> {
    array![
        AllocationPool::Ecosystem,
        AllocationPool::Treasury,
        AllocationPool::Team,
        AllocationPool::Liquidity,
        AllocationPool::PreSeed,
        AllocationPool::CodeDev,
        AllocationPool::PublicSale,
        AllocationPool::Strategic,
        AllocationPool::Seed,
        AllocationPool::Advisors,
    ]
}

// ============================================================================
// TOKENOMICS SUMMARY
// ============================================================================
//
// ┌─────────────────────────────────────────────────────────────────────────────┐
// │                    SAGE TOKEN DISTRIBUTION (1 BILLION)                      │
// ├─────────────────────────────────────────────────────────────────────────────┤
// │                                                                             │
// │   POOL                  │ ALLOCATION │   TOKENS      │ VESTING              │
// │   ──────────────────────┼────────────┼───────────────┼───────────────────── │
// │   Ecosystem Rewards     │   30.0%    │  300,000,000  │ 5-Year Emission      │
// │   Treasury              │   15.0%    │  150,000,000  │ 48-Month Linear      │
// │   Team                  │   15.0%    │  150,000,000  │ 12Mo Cliff + 36Mo    │
// │   Market Liquidity      │   10.0%    │  100,000,000  │ Immediate            │
// │   Pre-Seed              │    7.5%    │   75,000,000  │ 12-Month Linear      │
// │   Code Dev & Infra      │    5.0%    │   50,000,000  │ 36-Month Linear      │
// │   Public Sale           │    5.0%    │   50,000,000  │ 20% TGE + 6Mo        │
// │   Strategic Partners    │    5.0%    │   50,000,000  │ 24-Month Linear      │
// │   Seed                  │    5.0%    │   50,000,000  │ 24-Month Linear      │
// │   Advisors              │    2.5%    │   25,000,000  │ 12Mo Cliff + 24Mo    │
// │   ──────────────────────┼────────────┼───────────────┼───────────────────── │
// │   TOTAL                 │  100.0%    │ 1,000,000,000 │                      │
// │                                                                             │
// ├─────────────────────────────────────────────────────────────────────────────┤
// │                         INVESTOR BREAKDOWN (17.5%)                          │
// │   Pre-Seed: 7.5% │ Seed: 5.0% │ Strategic: 5.0%                             │
// │   Vesting Range: 12-24 Months Linear                                        │
// ├─────────────────────────────────────────────────────────────────────────────┤
// │                      ECOSYSTEM EMISSION SCHEDULE                            │
// │   Year 1: 3.0%/month of remaining  │  Year 4: 1.5%/month of remaining       │
// │   Year 2: 2.5%/month of remaining  │  Year 5: 1.0%/month of remaining       │
// │   Year 3: 2.0%/month of remaining  │                                        │
// └─────────────────────────────────────────────────────────────────────────────┘
