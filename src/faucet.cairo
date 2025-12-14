// =============================================================================
// TESTNET FAUCET CONTRACT - BitSage Network
// =============================================================================
//
// Allows users to claim testnet CIRO tokens for development and testing.
//
// Features:
// - Rate limiting (1 claim per address per cooldown period)
// - Configurable drip amount
// - Admin controls (refill, pause, adjust parameters)
// - Anti-abuse mechanisms
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Constants
// =============================================================================

const DEFAULT_DRIP_AMOUNT: u256 = 1000_000000000000000000; // 1,000 CIRO
const DEFAULT_COOLDOWN: u64 = 86400; // 24 hours in seconds
const MAX_DRIP_AMOUNT: u256 = 10000_000000000000000000; // 10,000 CIRO max

// =============================================================================
// Data Types
// =============================================================================

/// Faucet configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FaucetConfig {
    /// Amount to drip per claim
    pub drip_amount: u256,
    /// Cooldown period between claims (seconds)
    pub cooldown_secs: u64,
    /// Maximum claims per address (0 = unlimited)
    pub max_claims_per_address: u64,
    /// Is faucet active
    pub is_active: bool,
}

/// User claim info
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ClaimInfo {
    /// Timestamp of last claim
    pub last_claim: u64,
    /// Total number of claims
    pub claim_count: u64,
    /// Total amount claimed
    pub total_claimed: u256,
}

/// Faucet statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct FaucetStats {
    /// Total tokens distributed
    pub total_distributed: u256,
    /// Number of unique claimants
    pub unique_claimants: u64,
    /// Total claims processed
    pub total_claims: u64,
    /// Current balance
    pub balance: u256,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IFaucet<TContractState> {
    // === User Functions ===
    /// Claim tokens from faucet
    fn claim(ref self: TContractState);
    
    /// Check if user can claim
    fn can_claim(self: @TContractState, user: ContractAddress) -> bool;
    
    /// Get time until next claim is available
    fn time_until_claim(self: @TContractState, user: ContractAddress) -> u64;
    
    // === Admin Functions ===
    /// Refill faucet with tokens
    fn refill(ref self: TContractState, amount: u256);
    
    /// Update configuration
    fn update_config(ref self: TContractState, config: FaucetConfig);
    
    /// Pause faucet
    fn pause(ref self: TContractState);
    
    /// Unpause faucet
    fn unpause(ref self: TContractState);
    
    /// Emergency withdraw all tokens
    fn emergency_withdraw(ref self: TContractState, to: ContractAddress);
    
    // === View Functions ===
    fn get_config(self: @TContractState) -> FaucetConfig;
    fn get_claim_info(self: @TContractState, user: ContractAddress) -> ClaimInfo;
    fn get_stats(self: @TContractState) -> FaucetStats;
    fn get_balance(self: @TContractState) -> u256;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod Faucet {
    use super::{
        IFaucet, FaucetConfig, ClaimInfo, FaucetStats,
        DEFAULT_DRIP_AMOUNT, DEFAULT_COOLDOWN, MAX_DRIP_AMOUNT,
    };
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// CIRO token address
        ciro_token: ContractAddress,
        /// Configuration
        config: FaucetConfig,
        /// User claim info
        claims: Map<ContractAddress, ClaimInfo>,
        /// Unique claimant count
        unique_claimants: u64,
        /// Total claims
        total_claims: u64,
        /// Total distributed
        total_distributed: u256,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TokensClaimed: TokensClaimed,
        FaucetRefilled: FaucetRefilled,
        ConfigUpdated: ConfigUpdated,
        FaucetPaused: FaucetPaused,
        FaucetUnpaused: FaucetUnpaused,
        EmergencyWithdraw: EmergencyWithdraw,
    }

    #[derive(Drop, starknet::Event)]
    struct TokensClaimed {
        #[key]
        user: ContractAddress,
        amount: u256,
        claim_number: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FaucetRefilled {
        #[key]
        by: ContractAddress,
        amount: u256,
        new_balance: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        drip_amount: u256,
        cooldown_secs: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct FaucetPaused {
        by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct FaucetUnpaused {
        by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct EmergencyWithdraw {
        to: ContractAddress,
        amount: u256,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        ciro_token: ContractAddress,
    ) {
        self.owner.write(owner);
        self.ciro_token.write(ciro_token);
        
        // Default configuration
        self.config.write(FaucetConfig {
            drip_amount: DEFAULT_DRIP_AMOUNT,
            cooldown_secs: DEFAULT_COOLDOWN,
            max_claims_per_address: 0, // Unlimited
            is_active: true,
        });
        
        self.unique_claimants.write(0);
        self.total_claims.write(0);
        self.total_distributed.write(0);
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl FaucetImpl of IFaucet<ContractState> {
        fn claim(ref self: ContractState) {
            let caller = get_caller_address();
            let config = self.config.read();
            
            // Check faucet is active
            assert(config.is_active, 'Faucet is paused');
            
            // Check balance
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            let balance = token.balance_of(starknet::get_contract_address());
            assert(balance >= config.drip_amount, 'Faucet empty');
            
            // Check cooldown
            let mut claim_info = self.claims.read(caller);
            let now = get_block_timestamp();
            
            if claim_info.claim_count > 0 {
                let time_since_last = now - claim_info.last_claim;
                assert(time_since_last >= config.cooldown_secs, 'Cooldown not expired');
            }
            
            // Check max claims
            if config.max_claims_per_address > 0 {
                assert(
                    claim_info.claim_count < config.max_claims_per_address,
                    'Max claims reached'
                );
            }
            
            // Update claim info
            let is_first_claim = claim_info.claim_count == 0;
            claim_info.last_claim = now;
            claim_info.claim_count = claim_info.claim_count + 1;
            claim_info.total_claimed = claim_info.total_claimed + config.drip_amount;
            self.claims.write(caller, claim_info);
            
            // Update stats
            if is_first_claim {
                let count = self.unique_claimants.read();
                self.unique_claimants.write(count + 1);
            }
            let total_claims = self.total_claims.read() + 1;
            self.total_claims.write(total_claims);
            let total_dist = self.total_distributed.read() + config.drip_amount;
            self.total_distributed.write(total_dist);
            
            // Transfer tokens
            token.transfer(caller, config.drip_amount);
            
            self.emit(TokensClaimed {
                user: caller,
                amount: config.drip_amount,
                claim_number: claim_info.claim_count,
            });
        }

        fn can_claim(self: @ContractState, user: ContractAddress) -> bool {
            let config = self.config.read();
            
            if !config.is_active {
                return false;
            }
            
            // Check balance
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            let balance = token.balance_of(starknet::get_contract_address());
            if balance < config.drip_amount {
                return false;
            }
            
            // Check cooldown
            let claim_info = self.claims.read(user);
            if claim_info.claim_count > 0 {
                let now = get_block_timestamp();
                let time_since_last = now - claim_info.last_claim;
                if time_since_last < config.cooldown_secs {
                    return false;
                }
            }
            
            // Check max claims
            if config.max_claims_per_address > 0 
                && claim_info.claim_count >= config.max_claims_per_address {
                return false;
            }
            
            true
        }

        fn time_until_claim(self: @ContractState, user: ContractAddress) -> u64 {
            let config = self.config.read();
            let claim_info = self.claims.read(user);
            
            if claim_info.claim_count == 0 {
                return 0;
            }
            
            let now = get_block_timestamp();
            let time_since_last = now - claim_info.last_claim;
            
            if time_since_last >= config.cooldown_secs {
                return 0;
            }
            
            config.cooldown_secs - time_since_last
        }

        fn refill(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            
            // Transfer tokens to faucet
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.transfer_from(caller, starknet::get_contract_address(), amount);
            
            let new_balance = token.balance_of(starknet::get_contract_address());
            
            self.emit(FaucetRefilled {
                by: caller,
                amount,
                new_balance,
            });
        }

        fn update_config(ref self: ContractState, config: FaucetConfig) {
            self._only_owner();
            
            // Validate drip amount
            assert(config.drip_amount <= MAX_DRIP_AMOUNT, 'Drip amount too high');
            
            self.config.write(config);
            
            self.emit(ConfigUpdated {
                drip_amount: config.drip_amount,
                cooldown_secs: config.cooldown_secs,
            });
        }

        fn pause(ref self: ContractState) {
            self._only_owner();
            let mut config = self.config.read();
            config.is_active = false;
            self.config.write(config);
            
            self.emit(FaucetPaused { by: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            let mut config = self.config.read();
            config.is_active = true;
            self.config.write(config);
            
            self.emit(FaucetUnpaused { by: get_caller_address() });
        }

        fn emergency_withdraw(ref self: ContractState, to: ContractAddress) {
            self._only_owner();
            
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            let balance = token.balance_of(starknet::get_contract_address());
            
            token.transfer(to, balance);
            
            self.emit(EmergencyWithdraw { to, amount: balance });
        }

        fn get_config(self: @ContractState) -> FaucetConfig {
            self.config.read()
        }

        fn get_claim_info(self: @ContractState, user: ContractAddress) -> ClaimInfo {
            self.claims.read(user)
        }

        fn get_stats(self: @ContractState) -> FaucetStats {
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            let balance = token.balance_of(starknet::get_contract_address());
            
            FaucetStats {
                total_distributed: self.total_distributed.read(),
                unique_claimants: self.unique_claimants.read(),
                total_claims: self.total_claims.read(),
                balance,
            }
        }

        fn get_balance(self: @ContractState) -> u256 {
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.balance_of(starknet::get_contract_address())
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }
    }
}

