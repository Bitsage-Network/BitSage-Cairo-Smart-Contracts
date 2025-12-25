//! Achievement NFT Contract for BitSage Network
//!
//! This contract implements ERC721 NFTs for worker achievements in the gamification system.
//! Each achievement type has a unique visual representation and is non-transferable (soulbound).
//!
//! Achievement Types:
//! 0 - FirstJob: Complete first job
//! 1 - Dedicated: 30 days uptime
//! 2 - SpeedDemon: Top 1% speed
//! 3 - ConfidentialExpert: 100 TEE jobs
//! 4 - NetworkGuardian: Submit valid fraud proof
//! 5 - Century: 100 perfect jobs
//! 6 - LegendStatus: Reach Legend level

use starknet::ContractAddress;

/// Achievement metadata stored on-chain
#[derive(Drop, Serde, Copy, PartialEq)]
pub struct AchievementMetadata {
    /// The achievement type (0-6 for different achievements)
    pub achievement_type: u8,
    /// Worker ID who earned this achievement
    pub worker_id: felt252,
    /// Timestamp when the achievement was earned
    pub earned_at: u64,
    /// Associated reward amount in SAGE tokens
    pub reward_amount: u256,
}

#[starknet::interface]
pub trait IAchievementNFT<TContractState> {
    fn mint_achievement(
        ref self: TContractState,
        to: ContractAddress,
        token_id: u256,
        metadata: AchievementMetadata
    );
    fn get_achievement_type(self: @TContractState, token_id: u256) -> u8;
    fn get_worker_id(self: @TContractState, token_id: u256) -> felt252;
    fn worker_has_achievement(self: @TContractState, worker_id: felt252, achievement_type: u8) -> bool;
    fn total_supply(self: @TContractState) -> u256;
    fn set_gamification_contract(ref self: TContractState, gamification: ContractAddress);

    // Two-step ownership
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn accept_ownership(ref self: TContractState);
    fn owner(self: @TContractState) -> ContractAddress;
    fn pending_owner(self: @TContractState) -> ContractAddress;

    // Pausable
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    fn is_paused(self: @TContractState) -> bool;
}

#[starknet::contract]
pub mod AchievementNFT {
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;
    use openzeppelin::token::erc721::ERC721Component;
    use openzeppelin::introspection::src5::SRC5Component;
    use super::{IAchievementNFT, AchievementMetadata};

    component!(path: ERC721Component, storage: erc721, event: ERC721Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    // ERC721 Hooks implementation - makes NFTs soulbound (non-transferable)
    impl ERC721HooksImpl of ERC721Component::ERC721HooksTrait<ContractState> {
        fn before_update(
            ref self: ERC721Component::ComponentState<ContractState>,
            to: ContractAddress,
            token_id: u256,
            auth: ContractAddress,
        ) {
            let contract_state = ERC721Component::HasComponent::get_contract(@self);
            // Get the current owner - if not zero, this is a transfer (not mint)
            let current_owner = self.owner_of(token_id);
            // Allow minting (owner is zero) but prevent transfers
            if !current_owner.is_zero() {
                panic!("Achievement NFTs are soulbound and cannot be transferred");
            }
        }

        fn after_update(
            ref self: ERC721Component::ComponentState<ContractState>,
            to: ContractAddress,
            token_id: u256,
            auth: ContractAddress,
        ) {
            // No additional logic needed after update
        }
    }

    // ERC721 implementation
    #[abi(embed_v0)]
    impl ERC721Impl = ERC721Component::ERC721Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721MetadataImpl = ERC721Component::ERC721MetadataImpl<ContractState>;
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    impl ERC721InternalImpl = ERC721Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        // Admin
        owner: ContractAddress,
        pending_owner: ContractAddress,  // Two-step ownership
        paused: bool,                     // Pausable
        // Gamification contract (only this can mint)
        gamification_contract: ContractAddress,
        // Achievement metadata per token (stored as separate fields for Store trait)
        token_achievement_type: Map<u256, u8>,
        token_worker_id: Map<u256, felt252>,
        token_earned_at: Map<u256, u64>,
        token_reward_amount: Map<u256, u256>,
        // Track if worker has specific achievement type
        worker_achievements: Map<(felt252, u8), bool>,
        // Total supply
        total_supply: u256,
        // ERC721 and SRC5 components
        #[substorage(v0)]
        erc721: ERC721Component::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AchievementMinted: AchievementMinted,
        OwnershipTransferStarted: OwnershipTransferStarted,
        OwnershipTransferred: OwnershipTransferred,
        ContractPaused: ContractPaused,
        ContractUnpaused: ContractUnpaused,
        #[flat]
        ERC721Event: ERC721Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct AchievementMinted {
        #[key]
        token_id: u256,
        #[key]
        to: ContractAddress,
        #[key]
        worker_id: felt252,
        achievement_type: u8,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferStarted {
        #[key]
        previous_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct OwnershipTransferred {
        #[key]
        previous_owner: ContractAddress,
        #[key]
        new_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractPaused {
        account: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct ContractUnpaused {
        account: ContractAddress,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        name: ByteArray,
        symbol: ByteArray,
        base_uri: ByteArray,
    ) {
        // Initialize ERC721
        self.erc721.initializer(name, symbol, base_uri);

        self.owner.write(owner);
        self.total_supply.write(0);
    }

    #[abi(embed_v0)]
    impl AchievementNFTImpl of IAchievementNFT<ContractState> {
        fn mint_achievement(
            ref self: ContractState,
            to: ContractAddress,
            token_id: u256,
            metadata: AchievementMetadata
        ) {
            // SECURITY: Pause check
            assert!(!self.paused.read(), "Contract is paused");

            // Only gamification contract can mint
            let caller = get_caller_address();
            let gamification = self.gamification_contract.read();
            assert!(!gamification.is_zero(), "Gamification contract not set");
            assert!(caller == gamification, "Only gamification contract can mint");

            // Check achievement type is valid
            assert!(metadata.achievement_type <= 6, "Invalid achievement type");

            // Check worker doesn't already have this achievement
            assert!(
                !self.worker_achievements.read((metadata.worker_id, metadata.achievement_type)),
                "Worker already has this achievement"
            );

            // Mint the NFT
            self.erc721.mint(to, token_id);

            // Store metadata in separate fields
            self.token_achievement_type.write(token_id, metadata.achievement_type);
            self.token_worker_id.write(token_id, metadata.worker_id);
            self.token_earned_at.write(token_id, metadata.earned_at);
            self.token_reward_amount.write(token_id, metadata.reward_amount);

            // Mark worker as having this achievement
            self.worker_achievements.write((metadata.worker_id, metadata.achievement_type), true);

            // Update total supply
            let new_supply = self.total_supply.read() + 1;
            self.total_supply.write(new_supply);

            // Emit event
            self.emit(AchievementMinted {
                token_id,
                to,
                worker_id: metadata.worker_id,
                achievement_type: metadata.achievement_type,
                timestamp: get_block_timestamp(),
            });
        }

        fn get_achievement_type(self: @ContractState, token_id: u256) -> u8 {
            self.token_achievement_type.read(token_id)
        }

        fn get_worker_id(self: @ContractState, token_id: u256) -> felt252 {
            self.token_worker_id.read(token_id)
        }

        fn worker_has_achievement(
            self: @ContractState,
            worker_id: felt252,
            achievement_type: u8
        ) -> bool {
            self.worker_achievements.read((worker_id, achievement_type))
        }

        fn total_supply(self: @ContractState) -> u256 {
            self.total_supply.read()
        }

        fn set_gamification_contract(ref self: ContractState, gamification: ContractAddress) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            self.gamification_contract.write(gamification);
        }

        // =========================================================================
        // Two-Step Ownership Transfer
        // =========================================================================

        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");
            assert!(!new_owner.is_zero(), "New owner cannot be zero");

            let previous_owner = self.owner.read();
            self.pending_owner.write(new_owner);

            self.emit(OwnershipTransferStarted {
                previous_owner,
                new_owner,
            });
        }

        fn accept_ownership(ref self: ContractState) {
            let caller = get_caller_address();
            let pending = self.pending_owner.read();
            assert!(caller == pending, "Caller is not pending owner");

            let previous_owner = self.owner.read();
            let zero: ContractAddress = 0.try_into().unwrap();

            self.owner.write(caller);
            self.pending_owner.write(zero);

            self.emit(OwnershipTransferred {
                previous_owner,
                new_owner: caller,
            });
        }

        fn owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn pending_owner(self: @ContractState) -> ContractAddress {
            self.pending_owner.read()
        }

        // =========================================================================
        // Pausable
        // =========================================================================

        fn pause(ref self: ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            assert!(!self.paused.read(), "Already paused");
            self.paused.write(true);
            self.emit(ContractPaused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
            assert!(self.paused.read(), "Not paused");
            self.paused.write(false);
            self.emit(ContractUnpaused { account: get_caller_address() });
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }
    }
}
