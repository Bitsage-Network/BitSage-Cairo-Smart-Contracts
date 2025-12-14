// =============================================================================
// OBELYSK PROVER REGISTRY - BitSage Network
// =============================================================================
//
// Decentralized GPU prover marketplace for the Obelysk Protocol.
//
// This contract maintains:
// 1. Registry of allowed GPU prover image hashes (TEE measurements)
// 2. Registry of verified provers with attestation
// 3. Pricing configuration for proof generation
// 4. Proof verification integration with stwo-cairo-verifier
//
// Architecture:
//   Client → submit_proof_request() → Registry → assign_to_prover()
//   Prover → generate_proof(GPU) → submit_proof() → verify_on_chain()
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Data Types
// =============================================================================

/// TEE attestation data (TDX/SEV-SNP/H100-CC measurements)
/// Uses fixed-size representation for storage compatibility
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct TeeAttestation {
    /// MRTD - Primary measurement hash (first 32 bytes of 48-byte measurement)
    pub mrtd_high: felt252,
    pub mrtd_low: felt252,
    /// Image hash of the prover binary (32 bytes as 2 felt252)
    pub image_hash_high: felt252,
    pub image_hash_low: felt252,
    /// TEE type: 0 = Intel TDX, 1 = AMD SEV-SNP, 2 = NVIDIA H100 CC
    pub tee_type: u8,
    /// Timestamp of attestation
    pub timestamp: u64,
}

/// Registered prover information
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProverInfo {
    /// Prover's Starknet address
    pub address: ContractAddress,
    /// GPU type: 0 = H100, 1 = H200, 2 = A100, 3 = RTX4090
    pub gpu_type: u8,
    /// Number of GPUs
    pub gpu_count: u8,
    /// TEE attestation
    pub attestation: TeeAttestation,
    /// Reputation score (0-10000, basis points)
    pub reputation: u16,
    /// Total proofs generated
    pub proofs_generated: u64,
    /// Is currently active
    pub is_active: bool,
    /// Stake amount in CIRO tokens
    pub stake: u256,
}

/// Pricing configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PricingConfig {
    /// Base price per proof in CIRO (18 decimals)
    pub base_price_per_proof: u256,
    /// Price multiplier for larger proofs (basis points, 10000 = 1x)
    pub size_multiplier: u16,
    /// Platform fee (basis points, e.g., 500 = 5%)
    pub platform_fee_bps: u16,
    /// Minimum stake required for provers
    pub min_stake: u256,
}

/// Proof request from client
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofRequest {
    pub client: ContractAddress,
    pub proof_size_log: u8,
    pub price: u256,
    pub assigned_prover: ContractAddress,
    pub status: u8, // 0 = pending, 1 = assigned, 2 = completed, 3 = failed
    pub created_at: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IObelyskProverRegistry<TContractState> {
    // === Admin Functions ===
    fn add_allowed_image_hash(ref self: TContractState, image_hash_high: felt252, image_hash_low: felt252);
    fn remove_allowed_image_hash(ref self: TContractState, image_hash_high: felt252);
    fn update_pricing(ref self: TContractState, config: PricingConfig);
    fn set_verifier_address(ref self: TContractState, verifier: ContractAddress);
    
    // === Prover Functions ===
    fn register_prover(
        ref self: TContractState,
        gpu_type: u8,
        gpu_count: u8,
        attestation: TeeAttestation,
    );
    fn deregister_prover(ref self: TContractState);
    fn update_attestation(ref self: TContractState, attestation: TeeAttestation);
    fn stake(ref self: TContractState, amount: u256);
    fn unstake(ref self: TContractState, amount: u256);
    
    // === Client Functions ===
    fn submit_proof_request(
        ref self: TContractState,
        proof_size_log: u8,
        max_price: u256,
    ) -> u256; // Returns request_id
    
    fn submit_proof(
        ref self: TContractState,
        request_id: u256,
        proof_commitment: felt252,
    );
    
    // === View Functions ===
    fn is_image_hash_allowed(self: @TContractState, image_hash_high: felt252) -> bool;
    fn get_prover_info(self: @TContractState, prover: ContractAddress) -> ProverInfo;
    fn get_pricing(self: @TContractState) -> PricingConfig;
    fn get_proof_price(self: @TContractState, proof_size_log: u8) -> u256;
    fn get_active_provers(self: @TContractState) -> Array<ContractAddress>;
    fn get_verifier_address(self: @TContractState) -> ContractAddress;
    fn get_request(self: @TContractState, request_id: u256) -> ProofRequest;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
pub mod ObelyskProverRegistry {
    use super::{
        TeeAttestation, ProverInfo, PricingConfig, ProofRequest, 
        IObelyskProverRegistry
    };
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp};
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess,
        StoragePointerReadAccess, StoragePointerWriteAccess
    };
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::traits::Into;

    // =========================================================================
    // Storage
    // =========================================================================
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        
        /// Allowed image hashes (hash -> is_allowed)
        allowed_image_hashes: Map<felt252, bool>,
        
        /// Registered provers (address -> info)
        provers: Map<ContractAddress, ProverInfo>,
        
        /// Active prover list
        active_prover_count: u32,
        active_provers: Map<u32, ContractAddress>,
        
        /// Pricing configuration
        pricing: PricingConfig,
        
        /// stwo-cairo-verifier contract address
        verifier_address: ContractAddress,
        
        /// CIRO token address for payments
        ciro_token: ContractAddress,
        
        /// Proof requests
        next_request_id: u256,
        proof_requests: Map<u256, ProofRequest>,
        
        /// Treasury for platform fees
        treasury: ContractAddress,
    }

    // =========================================================================
    // Events
    // =========================================================================
    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ImageHashAdded: ImageHashAdded,
        ImageHashRemoved: ImageHashRemoved,
        ProverRegistered: ProverRegistered,
        ProverDeregistered: ProverDeregistered,
        ProverStaked: ProverStaked,
        ProverUnstaked: ProverUnstaked,
        ProofRequested: ProofRequested,
        ProofSubmitted: ProofSubmitted,
        ProofVerified: ProofVerified,
        ReputationUpdated: ReputationUpdated,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ImageHashAdded {
        #[key]
        pub hash_prefix: felt252,
        pub added_by: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ImageHashRemoved {
        #[key]
        pub hash_prefix: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProverRegistered {
        #[key]
        pub prover: ContractAddress,
        pub gpu_type: u8,
        pub gpu_count: u8,
        pub tee_type: u8,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProverDeregistered {
        #[key]
        pub prover: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProverStaked {
        #[key]
        pub prover: ContractAddress,
        pub amount: u256,
        pub total_stake: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProverUnstaked {
        #[key]
        pub prover: ContractAddress,
        pub amount: u256,
        pub remaining_stake: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProofRequested {
        #[key]
        pub request_id: u256,
        pub client: ContractAddress,
        pub proof_size_log: u8,
        pub price: u256,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProofSubmitted {
        #[key]
        pub request_id: u256,
        pub prover: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProofVerified {
        #[key]
        pub request_id: u256,
        pub success: bool,
        pub prover: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ReputationUpdated {
        #[key]
        pub prover: ContractAddress,
        pub old_reputation: u16,
        pub new_reputation: u16,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        verifier: ContractAddress,
        ciro_token: ContractAddress,
        treasury: ContractAddress,
    ) {
        self.owner.write(owner);
        self.verifier_address.write(verifier);
        self.ciro_token.write(ciro_token);
        self.treasury.write(treasury);
        self.next_request_id.write(1);
        
        // Default pricing (in CIRO, 18 decimals)
        self.pricing.write(PricingConfig {
            base_price_per_proof: 100_000_000_000_000_000_u256, // 0.1 CIRO
            size_multiplier: 10000, // 1x base
            platform_fee_bps: 500,  // 5%
            min_stake: 1000_000_000_000_000_000_000_u256, // 1000 CIRO
        });
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    #[abi(embed_v0)]
    impl ObelyskProverRegistryImpl of IObelyskProverRegistry<ContractState> {
        // === Admin Functions ===
        
        fn add_allowed_image_hash(ref self: ContractState, image_hash_high: felt252, image_hash_low: felt252) {
            self._only_owner();
            // Use high part as the key for lookup
            self.allowed_image_hashes.write(image_hash_high, true);
            self.emit(ImageHashAdded { 
                hash_prefix: image_hash_high,
                added_by: get_caller_address(),
            });
        }

        fn remove_allowed_image_hash(ref self: ContractState, image_hash_high: felt252) {
            self._only_owner();
            self.allowed_image_hashes.write(image_hash_high, false);
            self.emit(ImageHashRemoved { hash_prefix: image_hash_high });
        }

        fn update_pricing(ref self: ContractState, config: PricingConfig) {
            self._only_owner();
            self.pricing.write(config);
        }

        fn set_verifier_address(ref self: ContractState, verifier: ContractAddress) {
            self._only_owner();
            self.verifier_address.write(verifier);
        }

        // === Prover Functions ===
        
        fn register_prover(
            ref self: ContractState,
            gpu_type: u8,
            gpu_count: u8,
            attestation: TeeAttestation,
        ) {
            let caller = get_caller_address();
            
            // Verify attestation image hash is allowed
            assert(self.allowed_image_hashes.read(attestation.image_hash_high), 'Image hash not allowed');
            
            let tee_type = attestation.tee_type;
            
            // Create prover info
            let prover_info = ProverInfo {
                address: caller,
                gpu_type,
                gpu_count,
                attestation,
                reputation: 5000, // Start at 50%
                proofs_generated: 0,
                is_active: true,
                stake: 0_u256,
            };
            
            self.provers.write(caller, prover_info);
            
            // Add to active list
            let idx = self.active_prover_count.read();
            self.active_provers.write(idx, caller);
            self.active_prover_count.write(idx + 1);
            
            self.emit(ProverRegistered { 
                prover: caller, 
                gpu_type, 
                gpu_count,
                tee_type,
            });
        }

        fn deregister_prover(ref self: ContractState) {
            let caller = get_caller_address();
            let mut info = self.provers.read(caller);
            
            // Return stake before deregistering
            assert(info.stake == 0_u256, 'Unstake before deregistering');
            
            info.is_active = false;
            self.provers.write(caller, info);
            self.emit(ProverDeregistered { prover: caller });
        }

        fn update_attestation(ref self: ContractState, attestation: TeeAttestation) {
            let caller = get_caller_address();
            
            // Verify new attestation is allowed
            assert(self.allowed_image_hashes.read(attestation.image_hash_high), 'Image hash not allowed');
            
            let mut info = self.provers.read(caller);
            info.attestation = attestation;
            self.provers.write(caller, info);
        }

        fn stake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut info = self.provers.read(caller);
            assert(info.is_active, 'Prover not registered');
            
            let new_total = info.stake + amount;
            info.stake = new_total;
            self.provers.write(caller, info);
            
            // TODO: Transfer CIRO tokens from caller to contract
            // ICiroToken::transfer_from(self.ciro_token.read(), caller, contract_address, amount)
            
            self.emit(ProverStaked { 
                prover: caller, 
                amount, 
                total_stake: new_total,
            });
        }

        fn unstake(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let mut info = self.provers.read(caller);
            assert(info.stake >= amount, 'Insufficient stake');
            
            let remaining = info.stake - amount;
            info.stake = remaining;
            self.provers.write(caller, info);
            
            // TODO: Transfer CIRO tokens back to prover
            // ICiroToken::transfer(self.ciro_token.read(), caller, amount)
            
            self.emit(ProverUnstaked { 
                prover: caller, 
                amount, 
                remaining_stake: remaining,
            });
        }

        // === Client Functions ===
        
        fn submit_proof_request(
            ref self: ContractState,
            proof_size_log: u8,
            max_price: u256,
        ) -> u256 {
            let caller = get_caller_address();
            let price = self.get_proof_price(proof_size_log);
            assert(price <= max_price, 'Price exceeds max');
            
            let request_id = self.next_request_id.read();
            self.next_request_id.write(request_id + 1);
            
            let zero_address: ContractAddress = 0.try_into().unwrap();
            let request = ProofRequest {
                client: caller,
                proof_size_log,
                price,
                assigned_prover: zero_address,
                status: 0, // pending
                created_at: get_block_timestamp(),
            };
            
            self.proof_requests.write(request_id, request);
            
            // TODO: Lock CIRO payment from client
            // ICiroToken::transfer_from(self.ciro_token.read(), caller, contract_address, price)
            
            self.emit(ProofRequested { 
                request_id, 
                client: caller, 
                proof_size_log, 
                price,
            });
            
            request_id
        }

        fn submit_proof(
            ref self: ContractState,
            request_id: u256,
            proof_commitment: felt252,
        ) {
            let caller = get_caller_address();
            let mut request = self.proof_requests.read(request_id);
            
            assert(request.status == 0 || request.status == 1, 'Invalid request status');
            
            // Verify prover is registered and staked
            let prover_info = self.provers.read(caller);
            assert(prover_info.is_active, 'Prover not active');
            
            let pricing = self.pricing.read();
            assert(prover_info.stake >= pricing.min_stake, 'Insufficient stake');
            
            // TODO: Call stwo-cairo-verifier to verify proof
            // let verifier = self.verifier_address.read();
            // let verified = IStwoVerifier::verify(verifier, proof_commitment);
            // assert(verified, 'Proof verification failed');
            
            self.emit(ProofSubmitted { request_id, prover: caller });
            
            // Update request
            request.assigned_prover = caller;
            request.status = 2; // completed
            self.proof_requests.write(request_id, request);
            
            // Update prover stats
            let mut info = self.provers.read(caller);
            info.proofs_generated = info.proofs_generated + 1;
            
            // Increase reputation on success (capped at 10000)
            let old_rep = info.reputation;
            let new_rep = if old_rep < 9900 { old_rep + 100 } else { 10000 };
            info.reputation = new_rep;
            
            self.provers.write(caller, info);
            
            // TODO: Pay prover (minus platform fee)
            // let platform_fee = request.price * pricing.platform_fee_bps / 10000;
            // let prover_payment = request.price - platform_fee;
            // ICiroToken::transfer(self.ciro_token.read(), caller, prover_payment)
            // ICiroToken::transfer(self.ciro_token.read(), self.treasury.read(), platform_fee)
            
            self.emit(ProofVerified { request_id, success: true, prover: caller });
            self.emit(ReputationUpdated { 
                prover: caller, 
                old_reputation: old_rep, 
                new_reputation: new_rep,
            });
        }

        // === View Functions ===
        
        fn is_image_hash_allowed(self: @ContractState, image_hash_high: felt252) -> bool {
            self.allowed_image_hashes.read(image_hash_high)
        }

        fn get_prover_info(self: @ContractState, prover: ContractAddress) -> ProverInfo {
            self.provers.read(prover)
        }

        fn get_pricing(self: @ContractState) -> PricingConfig {
            self.pricing.read()
        }

        fn get_proof_price(self: @ContractState, proof_size_log: u8) -> u256 {
            let pricing = self.pricing.read();
            let base = pricing.base_price_per_proof;
            
            // Price scales with proof size: 2^(log-16) multiplier for log > 16
            let size_factor: u256 = if proof_size_log > 16 {
                let shift: u256 = (proof_size_log - 16).into();
                shift + 1
            } else {
                1_u256
            };
            
            base * size_factor
        }

        fn get_active_provers(self: @ContractState) -> Array<ContractAddress> {
            let count = self.active_prover_count.read();
            let mut provers: Array<ContractAddress> = ArrayTrait::new();
            
            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }
                let addr = self.active_provers.read(i);
                let info = self.provers.read(addr);
                if info.is_active {
                    provers.append(addr);
                }
                i += 1;
            };
            
            provers
        }

        fn get_verifier_address(self: @ContractState) -> ContractAddress {
            self.verifier_address.read()
        }

        fn get_request(self: @ContractState, request_id: u256) -> ProofRequest {
            self.proof_requests.read(request_id)
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn _only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'Only owner');
        }
    }
}

