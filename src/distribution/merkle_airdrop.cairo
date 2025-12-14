// =============================================================================
// MERKLE AIRDROP CONTRACT - BitSage Network
// =============================================================================
//
// Gas-efficient airdrop using Merkle proofs:
// - Single root hash stores entire distribution
// - Users claim with proof → O(log n) verification
// - Supports vesting schedules for locked airdrops
// - Snapshot-based eligibility
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Data Types
// =============================================================================

/// Airdrop configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AirdropConfig {
    /// Merkle root of the distribution
    pub merkle_root: felt252,
    /// Token being distributed
    pub token: ContractAddress,
    /// Total tokens allocated
    pub total_allocation: u256,
    /// Tokens already claimed
    pub total_claimed: u256,
    /// Start timestamp (claims open)
    pub start_time: u64,
    /// End timestamp (claims close)
    pub end_time: u64,
    /// Vesting duration (0 = immediate)
    pub vesting_duration: u64,
    /// Cliff duration before vesting starts
    pub cliff_duration: u64,
    /// Is airdrop active
    pub is_active: bool,
}

/// Individual claim info
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ClaimInfo {
    /// Total amount allocated
    pub total_amount: u256,
    /// Amount already claimed
    pub claimed_amount: u256,
    /// Timestamp of first claim
    pub first_claim_time: u64,
    /// Has user verified their allocation
    pub is_verified: bool,
}

/// Vesting schedule for locked airdrops
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VestingSchedule {
    /// Total vesting amount
    pub total: u256,
    /// Amount released
    pub released: u256,
    /// Vesting start time
    pub start_time: u64,
    /// Cliff end time
    pub cliff_time: u64,
    /// Vesting end time
    pub end_time: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IMerkleAirdrop<TContractState> {
    // === User Functions ===
    /// Claim airdrop with Merkle proof
    fn claim(
        ref self: TContractState,
        amount: u256,
        proof: Array<felt252>,
    );
    
    /// Claim vested tokens (for locked airdrops)
    fn claim_vested(ref self: TContractState);
    
    /// Verify eligibility without claiming
    fn verify_eligibility(
        self: @TContractState,
        account: ContractAddress,
        amount: u256,
        proof: Array<felt252>,
    ) -> bool;
    
    /// Get claimable amount (considering vesting)
    fn get_claimable(self: @TContractState, account: ContractAddress) -> u256;
    
    // === Admin Functions ===
    /// Create a new airdrop
    fn create_airdrop(
        ref self: TContractState,
        merkle_root: felt252,
        token: ContractAddress,
        total_allocation: u256,
        start_time: u64,
        end_time: u64,
        vesting_duration: u64,
        cliff_duration: u64,
    );
    
    /// Update merkle root (before claims start)
    fn update_merkle_root(ref self: TContractState, new_root: felt252);
    
    /// Pause/unpause airdrop
    fn set_active(ref self: TContractState, active: bool);
    
    /// Withdraw unclaimed tokens after end
    fn withdraw_unclaimed(ref self: TContractState, to: ContractAddress);
    
    // === View Functions ===
    fn get_config(self: @TContractState) -> AirdropConfig;
    fn get_claim_info(self: @TContractState, account: ContractAddress) -> ClaimInfo;
    fn get_vesting_schedule(self: @TContractState, account: ContractAddress) -> VestingSchedule;
    fn has_claimed(self: @TContractState, account: ContractAddress) -> bool;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod MerkleAirdrop {
    use super::{IMerkleAirdrop, AirdropConfig, ClaimInfo, VestingSchedule};
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use core::poseidon::poseidon_hash_span;

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// Airdrop configuration
        config: AirdropConfig,
        /// Claim info per user
        claims: Map<ContractAddress, ClaimInfo>,
        /// Vesting schedules
        vesting: Map<ContractAddress, VestingSchedule>,
        /// Total unique claimants
        total_claimants: u64,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AirdropCreated: AirdropCreated,
        TokensClaimed: TokensClaimed,
        VestedTokensClaimed: VestedTokensClaimed,
        MerkleRootUpdated: MerkleRootUpdated,
        UnclaimedWithdrawn: UnclaimedWithdrawn,
    }

    #[derive(Drop, starknet::Event)]
    struct AirdropCreated {
        merkle_root: felt252,
        token: ContractAddress,
        total_allocation: u256,
        start_time: u64,
        end_time: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct TokensClaimed {
        #[key]
        account: ContractAddress,
        amount: u256,
        total_claimed: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct VestedTokensClaimed {
        #[key]
        account: ContractAddress,
        amount: u256,
        remaining: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct MerkleRootUpdated {
        old_root: felt252,
        new_root: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct UnclaimedWithdrawn {
        to: ContractAddress,
        amount: u256,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
        self.total_claimants.write(0);
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl MerkleAirdropImpl of IMerkleAirdrop<ContractState> {
        fn claim(
            ref self: ContractState,
            amount: u256,
            proof: Array<felt252>,
        ) {
            let caller = get_caller_address();
            let config = self.config.read();
            let now = get_block_timestamp();
            
            // Validate timing
            assert(config.is_active, 'Airdrop not active');
            assert(now >= config.start_time, 'Airdrop not started');
            assert(now <= config.end_time, 'Airdrop ended');
            
            // Check not already claimed (for immediate airdrops)
            let mut claim_info = self.claims.read(caller);
            if config.vesting_duration == 0 {
                assert(!claim_info.is_verified, 'Already claimed');
            }
            
            // Verify Merkle proof
            assert(self._verify_proof(caller, amount, proof.span()), 'Invalid proof');
            
            // Handle immediate vs vested airdrop
            if config.vesting_duration == 0 {
                // Immediate: transfer full amount
                let token = IERC20Dispatcher { contract_address: config.token };
                token.transfer(caller, amount);
                
                claim_info.total_amount = amount;
                claim_info.claimed_amount = amount;
                claim_info.first_claim_time = now;
                claim_info.is_verified = true;
                
                // Update config
                let mut cfg = self.config.read();
                cfg.total_claimed = cfg.total_claimed + amount;
                self.config.write(cfg);
                
                self.emit(TokensClaimed {
                    account: caller,
                    amount,
                    total_claimed: amount,
                });
            } else {
                // Vested: setup vesting schedule
                if !claim_info.is_verified {
                    let vesting = VestingSchedule {
                        total: amount,
                        released: 0,
                        start_time: now,
                        cliff_time: now + config.cliff_duration,
                        end_time: now + config.vesting_duration,
                    };
                    self.vesting.write(caller, vesting);
                    
                    claim_info.total_amount = amount;
                    claim_info.claimed_amount = 0;
                    claim_info.first_claim_time = now;
                    claim_info.is_verified = true;
                    
                    let count = self.total_claimants.read();
                    self.total_claimants.write(count + 1);
                }
                
                // Claim any vested amount
                self._claim_vested_internal(caller);
            }
            
            self.claims.write(caller, claim_info);
        }

        fn claim_vested(ref self: ContractState) {
            let caller = get_caller_address();
            let claim_info = self.claims.read(caller);
            assert(claim_info.is_verified, 'Not eligible');
            
            self._claim_vested_internal(caller);
        }

        fn verify_eligibility(
            self: @ContractState,
            account: ContractAddress,
            amount: u256,
            proof: Array<felt252>,
        ) -> bool {
            self._verify_proof(account, amount, proof.span())
        }

        fn get_claimable(self: @ContractState, account: ContractAddress) -> u256 {
            let claim_info = self.claims.read(account);
            
            if !claim_info.is_verified {
                return 0;
            }
            
            let config = self.config.read();
            
            if config.vesting_duration == 0 {
                // Immediate airdrop
                return claim_info.total_amount - claim_info.claimed_amount;
            }
            
            // Vested airdrop
            let vesting = self.vesting.read(account);
            let now = get_block_timestamp();
            
            // Before cliff
            if now < vesting.cliff_time {
                return 0;
            }
            
            // Calculate vested amount
            let vested = if now >= vesting.end_time {
                vesting.total
            } else {
                let elapsed = now - vesting.start_time;
                let total_duration = vesting.end_time - vesting.start_time;
                (vesting.total * elapsed.into()) / total_duration.into()
            };
            
            // Claimable = vested - already released
            if vested > vesting.released {
                vested - vesting.released
            } else {
                0
            }
        }

        fn create_airdrop(
            ref self: ContractState,
            merkle_root: felt252,
            token: ContractAddress,
            total_allocation: u256,
            start_time: u64,
            end_time: u64,
            vesting_duration: u64,
            cliff_duration: u64,
        ) {
            self._only_owner();
            
            // Validate parameters
            assert(start_time < end_time, 'Invalid time range');
            assert(cliff_duration <= vesting_duration, 'Cliff > vesting');
            
            let config = AirdropConfig {
                merkle_root,
                token,
                total_allocation,
                total_claimed: 0,
                start_time,
                end_time,
                vesting_duration,
                cliff_duration,
                is_active: true,
            };
            
            self.config.write(config);
            
            // Transfer tokens to contract
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer_from(
                get_caller_address(),
                starknet::get_contract_address(),
                total_allocation
            );
            
            self.emit(AirdropCreated {
                merkle_root,
                token,
                total_allocation,
                start_time,
                end_time,
            });
        }

        fn update_merkle_root(ref self: ContractState, new_root: felt252) {
            self._only_owner();
            
            let mut config = self.config.read();
            let now = get_block_timestamp();
            
            // Can only update before start
            assert(now < config.start_time, 'Airdrop already started');
            
            let old_root = config.merkle_root;
            config.merkle_root = new_root;
            self.config.write(config);
            
            self.emit(MerkleRootUpdated { old_root, new_root });
        }

        fn set_active(ref self: ContractState, active: bool) {
            self._only_owner();
            let mut config = self.config.read();
            config.is_active = active;
            self.config.write(config);
        }

        fn withdraw_unclaimed(ref self: ContractState, to: ContractAddress) {
            self._only_owner();
            
            let config = self.config.read();
            let now = get_block_timestamp();
            
            // Can only withdraw after end
            assert(now > config.end_time, 'Airdrop not ended');
            
            let unclaimed = config.total_allocation - config.total_claimed;
            
            if unclaimed > 0 {
                let token = IERC20Dispatcher { contract_address: config.token };
                token.transfer(to, unclaimed);
                
                self.emit(UnclaimedWithdrawn { to, amount: unclaimed });
            }
        }

        fn get_config(self: @ContractState) -> AirdropConfig {
            self.config.read()
        }

        fn get_claim_info(self: @ContractState, account: ContractAddress) -> ClaimInfo {
            self.claims.read(account)
        }

        fn get_vesting_schedule(self: @ContractState, account: ContractAddress) -> VestingSchedule {
            self.vesting.read(account)
        }

        fn has_claimed(self: @ContractState, account: ContractAddress) -> bool {
            self.claims.read(account).is_verified
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

        fn _verify_proof(
            self: @ContractState,
            account: ContractAddress,
            amount: u256,
            proof: Span<felt252>,
        ) -> bool {
            let config = self.config.read();
            
            // Compute leaf: hash(account, amount)
            let account_felt: felt252 = account.into();
            let amount_low: felt252 = (amount & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256).try_into().unwrap();
            let amount_high: felt252 = ((amount / 0x100000000000000000000000000000000_u256) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF_u256).try_into().unwrap();
            
            let mut leaf_data: Array<felt252> = array![account_felt, amount_low, amount_high];
            let mut leaf = poseidon_hash_span(leaf_data.span());
            
            // Traverse proof
            let mut i: u32 = 0;
            let proof_len = proof.len();
            
            loop {
                if i >= proof_len {
                    break;
                }
                
                let sibling = *proof.at(i);
                
                // Hash pair in canonical order (use XOR for ordering)
                let leaf_u256: u256 = leaf.into();
                let sibling_u256: u256 = sibling.into();
                let hash_input = if leaf_u256 < sibling_u256 {
                    array![leaf, sibling]
                } else {
                    array![sibling, leaf]
                };
                
                leaf = poseidon_hash_span(hash_input.span());
                i += 1;
            };
            
            // Check against root
            leaf == config.merkle_root
        }

        fn _claim_vested_internal(ref self: ContractState, account: ContractAddress) {
            let claimable = self.get_claimable(account);
            
            if claimable > 0 {
                let config = self.config.read();
                let mut vesting = self.vesting.read(account);
                let mut claim_info = self.claims.read(account);
                
                // Update vesting
                vesting.released = vesting.released + claimable;
                self.vesting.write(account, vesting);
                
                // Update claim info
                claim_info.claimed_amount = claim_info.claimed_amount + claimable;
                self.claims.write(account, claim_info);
                
                // Update config
                let mut cfg = self.config.read();
                cfg.total_claimed = cfg.total_claimed + claimable;
                self.config.write(cfg);
                
                // Transfer tokens
                let token = IERC20Dispatcher { contract_address: config.token };
                token.transfer(account, claimable);
                
                self.emit(VestedTokensClaimed {
                    account,
                    amount: claimable,
                    remaining: vesting.total - vesting.released,
                });
            }
        }
    }
}

