// CIRO Network Constants
// System-wide constants for gas optimization and configuration

/// Security and access control constants
pub const DEFAULT_ADMIN_ROLE: felt252 = 0x0; // OpenZeppelin default admin role
pub const ADMIN_ROLE: felt252 = 'ADMIN_ROLE'; // Admin role for job manager
pub const WORKER_ROLE: felt252 = 'WORKER_ROLE'; // Worker role
pub const CLIENT_ROLE: felt252 = 'CLIENT_ROLE'; // Client role

/// API and pagination constants
pub const PAGINATION_LIMIT: u32 = 100; // Maximum results per page

/// Tokenomics Constants (CIRO Token)
pub const TOTAL_SUPPLY: u256 = 1_000_000_000_000_000_000_000_000_000; // 1B tokens with 18 decimals
pub const MAX_MINT_PERCENTAGE: u32 = 1000; // 10% max mint percentage in basis points
pub const SCALE: u256 = 1_000_000_000_000_000_000; // 18 decimal scale
pub const SECONDS_PER_YEAR: u64 = 31536000; // 365 days in seconds
pub const SECONDS_PER_MONTH: u64 = 2592000; // 30 days in seconds

/// Worker Tier Thresholds (CIRO tokens with 18 decimals)
pub const BASIC_WORKER_THRESHOLD: u256 = 100_000_000_000_000_000_000; // 100 CIRO
pub const PREMIUM_WORKER_THRESHOLD: u256 = 500_000_000_000_000_000_000; // 500 CIRO
pub const ENTERPRISE_WORKER_THRESHOLD: u256 = 2500_000_000_000_000_000_000; // 2,500 CIRO
pub const INFRASTRUCTURE_WORKER_THRESHOLD: u256 = 10000_000_000_000_000_000_000; // 10,000 CIRO
pub const FLEET_WORKER_THRESHOLD: u256 = 50000_000_000_000_000_000_000; // 50,000 CIRO
pub const DATACENTER_WORKER_THRESHOLD: u256 = 100000_000_000_000_000_000_000; // 100,000 CIRO
pub const HYPERSCALE_WORKER_THRESHOLD: u256 = 250000_000_000_000_000_000_000; // 250,000 CIRO
pub const INSTITUTIONAL_WORKER_THRESHOLD: u256 = 500000_000_000_000_000_000_000; // 500,000 CIRO

/// Storage optimization constants
pub const MAX_JOBS_PER_WORKER: u32 = 100;
pub const MAX_WORKERS_PER_POOL: u32 = 10000;
pub const MAX_MODELS_PER_REGISTRY: u32 = 1000;

/// Worker capability flags (bitfield)
pub const CAPABILITY_CUDA: u64 = 1;           // CUDA support
pub const CAPABILITY_OPENCL: u64 = 2;         // OpenCL support  
pub const CAPABILITY_FP16: u64 = 4;           // Half precision support
pub const CAPABILITY_INT8: u64 = 8;           // INT8 quantization
pub const CAPABILITY_NVLINK: u64 = 16;        // NVLink support
pub const CAPABILITY_INFINIBAND: u64 = 32;    // InfiniBand networking
pub const CAPABILITY_TENSOR_CORES: u64 = 64;  // Tensor core support
pub const CAPABILITY_MULTI_GPU: u64 = 128;     // Multi-GPU support
pub const CAPABILITY_DISTRIBUTED: u64 = 0x100;  // Distributed computing
pub const CAPABILITY_CUSTOM: u64 = 0x200;       // Custom model support

/// Worker status flags (bitfield)
pub const WORKER_STATUS_ACTIVE: u8 = 0x1;       // Worker is active
pub const WORKER_STATUS_VERIFIED: u8 = 0x2;     // Worker is verified
pub const WORKER_STATUS_PENALIZED: u8 = 0x4;    // Worker is penalized
pub const WORKER_STATUS_PREMIUM: u8 = 0x8;      // Premium worker
pub const WORKER_STATUS_ENTERPRISE: u8 = 0x10;  // Enterprise worker

/// Job priority levels
pub const JOB_PRIORITY_LOW: u8 = 1;
pub const JOB_PRIORITY_NORMAL: u8 = 2;
pub const JOB_PRIORITY_HIGH: u8 = 3;
pub const JOB_PRIORITY_URGENT: u8 = 4;

/// Staking and economic constants
pub const MIN_STAKE_AMOUNT: u256 = 1000_000_000_000_000_000; // 1 CIRO token (legacy)

/// USD-Denominated Worker Staking Tiers (v3.1 - Realistic Capital Deployment)
pub const WORKER_BASIC_USD: u256 = 100_000; // $100 - entry level 
pub const WORKER_PREMIUM_USD: u256 = 500_000; // $500 - serious commitment
pub const WORKER_ENTERPRISE_USD: u256 = 2500_000; // $2,500 - business tier
pub const WORKER_INFRASTRUCTURE_USD: u256 = 10000_000; // $10,000 - data center tier

/// Extended Worker Tiers for Large Capital Deployment
pub const WORKER_FLEET_USD: u256 = 5000000; // $50,000 - small fleet operators
pub const WORKER_DATACENTER_USD: u256 = 10000000; // $100,000 - major operators  
pub const WORKER_HYPERSCALE_USD: u256 = 25000000; // $250,000 - hyperscale operators
pub const WORKER_INSTITUTIONAL_USD: u256 = 50000000; // $500,000 - institutional grade

/// Worker Tier Benefits (Job Allocation & Rewards)
pub const WORKER_BASIC_ALLOCATION_PRIORITY: u256 = 100; // 1.0x base allocation
pub const WORKER_PREMIUM_ALLOCATION_PRIORITY: u256 = 120; // 1.2x allocation boost
pub const WORKER_ENTERPRISE_ALLOCATION_PRIORITY: u256 = 150; // 1.5x allocation boost
pub const WORKER_INFRASTRUCTURE_ALLOCATION_PRIORITY: u256 = 200; // 2.0x allocation boost
pub const WORKER_FLEET_ALLOCATION_PRIORITY: u256 = 250; // 2.5x allocation boost
pub const WORKER_DATACENTER_ALLOCATION_PRIORITY: u256 = 300; // 3.0x allocation boost
pub const WORKER_HYPERSCALE_ALLOCATION_PRIORITY: u256 = 400; // 4.0x allocation boost
pub const WORKER_INSTITUTIONAL_ALLOCATION_PRIORITY: u256 = 500; // 5.0x allocation boost

/// Worker Tier Performance Bonus Rates (in basis points)
pub const WORKER_BASIC_BONUS_BPS: u256 = 500;     // 5% bonus
pub const WORKER_PREMIUM_BONUS_BPS: u256 = 1000;  // 10% bonus
pub const WORKER_ENTERPRISE_BONUS_BPS: u256 = 1500; // 15% bonus
pub const WORKER_INFRASTRUCTURE_BONUS_BPS: u256 = 2500; // 25% bonus
pub const WORKER_FLEET_BONUS_BPS: u256 = 3000; // 30% bonus
pub const WORKER_DATACENTER_BONUS_BPS: u256 = 3500; // 35% bonus
pub const WORKER_HYPERSCALE_BONUS_BPS: u256 = 4000; // 40% bonus
pub const WORKER_INSTITUTIONAL_BONUS_BPS: u256 = 5000; // 50% bonus

/// Large Holder Tier Thresholds (CIRO tokens) - Realistic Whale Levels
pub const WHALE_TIER_THRESHOLD: u256 = 5000000_000_000_000_000_000_000; // 5M CIRO (~0.5% supply, $2.5M at launch)
pub const INSTITUTION_TIER_THRESHOLD: u256 = 25000000_000_000_000_000_000_000; // 25M CIRO (~2.5% supply, $12.5M at launch)
pub const HYPERWHALE_TIER_THRESHOLD: u256 = 100000000_000_000_000_000_000_000; // 100M CIRO (~10% supply, $50M at launch)

/// USD Floor Requirements for Governance Tiers (in cents)
pub const WHALE_USD_FLOOR: u256 = 200000000; // $2M minimum
pub const INSTITUTION_USD_FLOOR: u256 = 1000000000; // $10M minimum  
pub const HYPERWHALE_USD_FLOOR: u256 = 5000000000; // $50M minimum

/// Governance Proposal Thresholds (CIRO tokens) - Adjusted for Supply Scale
pub const GOVERNANCE_MINOR_THRESHOLD: u256 = 50000_000_000_000_000_000_000; // 50K CIRO (minor changes)
pub const GOVERNANCE_MAJOR_THRESHOLD: u256 = 250000_000_000_000_000_000_000; // 250K CIRO (major changes)
pub const GOVERNANCE_PROTOCOL_THRESHOLD: u256 = 1000000_000_000_000_000_000_000; // 1M CIRO (protocol upgrades)
pub const GOVERNANCE_EMERGENCY_THRESHOLD: u256 = 5000000_000_000_000_000_000_000; // 5M CIRO (emergency actions)

/// Whale Tier Benefits (Fee Discounts in Basis Points)
pub const WHALE_FEE_DISCOUNT_BPS: u256 = 4000; // 40% fee discount
pub const INSTITUTION_FEE_DISCOUNT_BPS: u256 = 7500; // 75% fee discount

/// Price Adjustment Parameters
pub const WORKER_PRICE_ADJUSTMENT_WINDOW: u64 = 604800; // 7 days in seconds
pub const WORKER_MAX_ADJUSTMENT_PER_WEEK: u256 = 2500; // 25% max change per week
pub const GOVERNANCE_PRICE_ADJUSTMENT_WINDOW: u64 = 2592000; // 30 days in seconds  
pub const GOVERNANCE_MAX_ADJUSTMENT_PER_MONTH: u256 = 1000; // 10% max change per month

/// Slash percentages based on tokenomics
pub const SLASH_PERCENTAGE_MINOR: u8 = 5;   // 5% slash for minor violations
pub const SLASH_PERCENTAGE_MAJOR: u8 = 25;  // 25% slash for major violations
pub const SLASH_PERCENTAGE_SEVERE: u8 = 50; // 50% slash for severe violations

/// Time constants (in seconds)
pub const UNSTAKE_DELAY: u64 = 604800;      // 7 days
pub const JOB_TIMEOUT: u64 = 3600;          // 1 hour
pub const HEARTBEAT_INTERVAL: u64 = 300;    // 5 minutes
pub const DISPUTE_PERIOD: u64 = 259200;     // 3 days

/// Gas optimization constants
pub const BATCH_SIZE_LIMIT: u32 = 50;       // Maximum batch size for operations

/// Reputation scoring constants
pub const REPUTATION_SCALE: u16 = 1000;     // Maximum reputation score
pub const REPUTATION_INITIAL: u16 = 500;    // Initial reputation for new workers
pub const REPUTATION_INITIAL_U64: u64 = 500; // Initial reputation as u64 for compatibility
pub const REPUTATION_MAX: u64 = 1000;       // Maximum reputation score as u64
pub const REPUTATION_MIN: u64 = 0;          // Minimum reputation score as u64
pub const REPUTATION_BONUS_COMPLETION: u16 = 10; // Bonus for job completion
pub const REPUTATION_PENALTY_TIMEOUT: u16 = 50;  // Penalty for timeout
pub const REPUTATION_PENALTY_DISPUTE: u16 = 100; // Penalty for dispute loss

// Governance Constants
pub const PROPOSAL_DELAY: u64 = 3600; // 1 hour delay before voting starts
pub const PROPOSAL_EXPIRY_PERIOD: u64 = 2592000; // 30 days after execution_eta
pub const MIN_VOTING_PERIOD: u64 = 3600; // 1 hour minimum
pub const MAX_VOTING_PERIOD: u64 = 1209600; // 14 days maximum
pub const MIN_TIMELOCK_DELAY: u64 = 0; // Emergency proposals
pub const MAX_TIMELOCK_DELAY: u64 = 2592000; // 30 days maximum

// Proposal Type Voting Periods
pub const EMERGENCY_VOTING_PERIOD: u64 = 3600; // 1 hour
pub const CRITICAL_VOTING_PERIOD: u64 = 86400; // 24 hours
pub const STANDARD_VOTING_PERIOD: u64 = 604800; // 7 days
pub const PARAMETER_VOTING_PERIOD: u64 = 259200; // 3 days
pub const UPGRADE_VOTING_PERIOD: u64 = 604800; // 7 days

// Proposal Type Timelock Delays
pub const EMERGENCY_TIMELOCK_DELAY: u64 = 0; // No delay
pub const CRITICAL_TIMELOCK_DELAY: u64 = 86400; // 24 hours
pub const STANDARD_TIMELOCK_DELAY: u64 = 604800; // 7 days
pub const PARAMETER_TIMELOCK_DELAY: u64 = 259200; // 3 days
pub const UPGRADE_TIMELOCK_DELAY: u64 = 1209600; // 14 days

// Quorum Thresholds (basis points - 10000 = 100%)
pub const EMERGENCY_QUORUM_BPS: u256 = 1000; // 10%
pub const CRITICAL_QUORUM_BPS: u256 = 2000; // 20%
pub const STANDARD_QUORUM_BPS: u256 = 2500; // 25%
pub const PARAMETER_QUORUM_BPS: u256 = 1667; // 16.67%
pub const UPGRADE_QUORUM_BPS: u256 = 3333; // 33.33%

// Voting Power Calculation
pub const VOTING_POWER_SCALE: u256 = 10000; // Scale for percentage calculations
pub const STAKE_BONUS_BPS: u256 = 5000; // 50% bonus for staking
pub const REPUTATION_BONUS_SCALE: u256 = 1000; // Scale for reputation bonus
pub const LOCK_BONUS_1_YEAR_BPS: u256 = 5000; // 50% bonus for 1 year lock
pub const LOCK_BONUS_6_MONTH_BPS: u256 = 2500; // 25% bonus for 6 month lock
pub const LOCK_DURATION_1_YEAR: u64 = 31536000; // 1 year in seconds
pub const LOCK_DURATION_6_MONTH: u64 = 15768000; // 6 months in seconds

// Governance Limits
pub const MAX_OPERATIONS_PER_PROPOSAL: u8 = 20;
pub const MAX_DESCRIPTION_LENGTH: u32 = 1000;
pub const MAX_TITLE_LENGTH: u32 = 100;
pub const MIN_PROPOSAL_THRESHOLD: u256 = 1000; // Minimum tokens to propose
pub const MAX_PROPOSAL_THRESHOLD: u256 = 10000000; // Maximum tokens to propose

// Upgradability Constants
pub const DEFAULT_GRACE_PERIOD: u64 = 3600; // 1 hour
pub const DEFAULT_MAX_UPGRADE_DELAY: u64 = 604800; // 7 days
pub const EMERGENCY_UPGRADE_DELAY: u64 = 0; // Immediate
pub const STANDARD_UPGRADE_DELAY: u64 = 86400; // 24 hours
pub const CRITICAL_UPGRADE_DELAY: u64 = 3600; // 1 hour
pub const MAX_UPGRADE_DELAY_LIMIT: u64 = 2592000; // 30 days absolute maximum

// Job-Aware Upgrade Constants
pub const JOB_COMPLETION_GRACE_PERIOD: u64 = 1800; // 30 minutes
pub const MAX_ACTIVE_JOBS_FOR_UPGRADE: u256 = 0; // No active jobs allowed
pub const UPGRADE_WINDOW_DURATION: u64 = 3600; // 1 hour upgrade window
pub const MAINTENANCE_MODE_MAX_DURATION: u64 = 86400; // 24 hours max maintenance

// Proxy Pattern Constants
pub const UUPS_INTERFACE_ID: felt252 = 0x1822e7b8; // UUPS interface ID
pub const TRANSPARENT_PROXY_INTERFACE_ID: felt252 = 0x50c5bb4f; // Transparent proxy interface ID
pub const DIAMOND_INTERFACE_ID: felt252 = 0x48e2b093; // Diamond interface ID
pub const ERC165_INTERFACE_ID: felt252 = 0x01ffc9a7; // ERC-165 interface ID

// Diamond Pattern Constants
pub const MAX_FACETS_PER_DIAMOND: u32 = 256;
pub const MAX_SELECTORS_PER_FACET: u32 = 1000;
pub const DIAMOND_CUT_INTERFACE_ID: felt252 = 0x1f931c1c; // DiamondCut interface ID
pub const DIAMOND_LOUPE_INTERFACE_ID: felt252 = 0x48e2b093; // DiamondLoupe interface ID

// Security Constants for Governance
pub const EMERGENCY_COUNCIL_MAX_SIZE: u32 = 10;
pub const MULTISIG_MIN_CONFIRMATIONS: u32 = 3;
pub const MULTISIG_MAX_OWNERS: u32 = 20;
pub const PROPOSAL_VALIDATION_TIMEOUT: u64 = 300; // 5 minutes
pub const EXECUTION_RETRY_DELAY: u64 = 3600; // 1 hour between retries
pub const MAX_EXECUTION_RETRIES: u32 = 3;

// Version Control Constants
pub const GOVERNANCE_VERSION: felt252 = 0x010000; // Version 1.0.0
pub const UPGRADABILITY_VERSION: felt252 = 0x010000; // Version 1.0.0
pub const COMPATIBILITY_VERSION: felt252 = 0x010000; // Minimum compatible version

// Event Constants
pub const GOVERNANCE_EVENT_VERSION: u8 = 1;
pub const UPGRADE_EVENT_VERSION: u8 = 1;
pub const SECURITY_EVENT_VERSION: u8 = 1;

// Gas Optimization Constants
pub const BATCH_OPERATION_LIMIT: u32 = 50;
pub const STORAGE_SLOT_OPTIMIZATION: u32 = 32;
pub const MEMORY_ALLOCATION_LIMIT: u32 = 1024; 

/// Rate limiting information for transfers
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RateLimitInfo {
    pub current_limit: u256,
    pub current_usage: u256,
    pub window_start: u64,
    pub window_duration: u64,
}

/// Mathematical and scaling constants (SCALE already defined earlier)
pub const BASIS_POINTS_SCALE: u32 = 10000;   // For percentage calculations (100% = 10000 bp)

/// Network phase constants
pub const PHASE_BOOTSTRAP: felt252 = 'bootstrap';
pub const PHASE_GROWTH: felt252 = 'growth';
pub const PHASE_TRANSITION: felt252 = 'transition';
pub const PHASE_MATURE: felt252 = 'mature';

/// Token holder tier requirements
pub const VETERAN_HOLDER_MINIMUM_PERIOD: u64 = 63072000; // 2 years in seconds
pub const LONG_TERM_HOLDER_MINIMUM_PERIOD: u64 = 31536000; // 1 year in seconds

/// Voting power multipliers (basis points)
pub const VOTING_POWER_MULTIPLIER_LONG_TERM: u32 = 120; // 1.2x
pub const VOTING_POWER_MULTIPLIER_VETERAN: u32 = 150;   // 1.5x

/// Additional governance proposal thresholds (MINOR/MAJOR already defined earlier)
pub const GOVERNANCE_STRATEGIC_THRESHOLD: u256 = 100000000000000000000000; // 100,000 tokens

/// Governance participation requirements
pub const QUORUM_PERCENTAGE: u32 = 2000; // 20% in basis points 