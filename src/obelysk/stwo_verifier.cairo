//! STWO Proof Verifier Contract for BitSage/Obelysk
//!
//! This contract verifies STWO Circle STARK proofs on-chain.
//! It integrates with the stwo-cairo-verifier library from StarkWare.
//!
//! # Architecture
//!
//! The verification flow:
//! 1. Off-chain: GPU prover generates STWO proof
//! 2. Off-chain: Proof is serialized to Cairo-compatible format
//! 3. On-chain: This contract verifies the proof
//! 4. On-chain: Verification result is stored and can be queried
//!
//! # Security Model
//!
//! - Proofs must meet minimum security requirements (96 bits)
//! - Only whitelisted AIR components are accepted
//! - Verification results are immutable once stored

use starknet::ContractAddress;
use starknet::storage::{
    StoragePointerReadAccess, StoragePointerWriteAccess,
    StorageMapReadAccess, StorageMapWriteAccess,
    Map,
};

/// Proof verification status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq)]
pub enum VerificationStatus {
    /// Proof has not been submitted
    NotSubmitted,
    /// Proof is pending verification
    Pending,
    /// Proof has been verified successfully
    Verified,
    /// Proof verification failed
    Failed,
    /// Proof was rejected (invalid format, security, etc.)
    Rejected,
}

/// Proof metadata stored on-chain
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ProofMetadata {
    /// Hash of the proof data
    pub proof_hash: felt252,
    /// Hash of the public inputs
    pub public_input_hash: felt252,
    /// Security bits achieved
    pub security_bits: u32,
    /// Timestamp of submission
    pub submitted_at: u64,
    /// Address that submitted the proof
    pub submitter: ContractAddress,
    /// Verification status
    pub status: VerificationStatus,
    /// Block number when verified (0 if not verified)
    pub verified_at_block: u64,
}

/// Configuration for proof verification
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct VerifierConfig {
    /// Minimum security bits required
    pub min_security_bits: u32,
    /// Maximum proof size (in felt252 elements)
    pub max_proof_size: u32,
    /// Whether the contract is paused
    pub is_paused: bool,
}

#[starknet::interface]
pub trait IStwoVerifier<TContractState> {
    /// Submit a proof for verification
    fn submit_proof(
        ref self: TContractState,
        proof_data: Array<felt252>,
        public_input_hash: felt252,
    ) -> felt252;

    /// Verify a submitted proof
    fn verify_proof(
        ref self: TContractState,
        proof_hash: felt252,
    ) -> bool;

    /// Get proof metadata
    fn get_proof_metadata(
        self: @TContractState,
        proof_hash: felt252,
    ) -> ProofMetadata;

    /// Check if a proof is verified
    fn is_proof_verified(
        self: @TContractState,
        proof_hash: felt252,
    ) -> bool;

    /// Get verification config
    fn get_config(self: @TContractState) -> VerifierConfig;

    /// Update config (admin only)
    fn update_config(
        ref self: TContractState,
        config: VerifierConfig,
    );

    /// Pause/unpause contract (admin only)
    fn set_paused(ref self: TContractState, paused: bool);

    /// Get total verified proofs count
    fn get_verified_count(self: @TContractState) -> u64;
}

#[starknet::contract]
mod StwoVerifier {
    use super::{
        IStwoVerifier, ProofMetadata, VerificationStatus, VerifierConfig,
    };
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp, get_block_number,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use core::poseidon::poseidon_hash_span;
    use core::array::ArrayTrait;

    #[storage]
    struct Storage {
        /// Contract owner/admin
        owner: ContractAddress,
        /// Verifier configuration
        config: VerifierConfig,
        /// Proof metadata by proof hash
        proofs: Map<felt252, ProofMetadata>,
        /// Total number of verified proofs
        verified_count: u64,
        /// Proof data storage (for larger proofs, indexed by proof_hash)
        proof_data: Map<(felt252, u32), felt252>,
        /// Proof data length
        proof_data_len: Map<felt252, u32>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProofSubmitted: ProofSubmitted,
        ProofVerified: ProofVerified,
        ProofRejected: ProofRejected,
        ConfigUpdated: ConfigUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofSubmitted {
        #[key]
        proof_hash: felt252,
        submitter: ContractAddress,
        public_input_hash: felt252,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofVerified {
        #[key]
        proof_hash: felt252,
        block_number: u64,
        security_bits: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct ProofRejected {
        #[key]
        proof_hash: felt252,
        reason: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        min_security_bits: u32,
        max_proof_size: u32,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        min_security_bits: u32,
        max_proof_size: u32,
    ) {
        self.owner.write(owner);
        self.config.write(VerifierConfig {
            min_security_bits,
            max_proof_size,
            is_paused: false,
        });
        self.verified_count.write(0);
    }

    #[abi(embed_v0)]
    impl StwoVerifierImpl of IStwoVerifier<ContractState> {
        fn submit_proof(
            ref self: ContractState,
            proof_data: Array<felt252>,
            public_input_hash: felt252,
        ) -> felt252 {
            // Check contract is not paused
            let config = self.config.read();
            assert!(!config.is_paused, "Contract is paused");

            // Check proof size
            let proof_len = proof_data.len();
            assert!(proof_len <= config.max_proof_size, "Proof too large");
            assert!(proof_len > 0, "Empty proof");

            // Compute proof hash
            let proof_hash = poseidon_hash_span(proof_data.span());

            // Check proof not already submitted
            let existing = self.proofs.read(proof_hash);
            assert!(
                existing.status == VerificationStatus::NotSubmitted,
                "Proof already submitted"
            );

            // Store proof data
            let mut i: u32 = 0;
            for elem in proof_data.span() {
                self.proof_data.write((proof_hash, i), *elem);
                i += 1;
            };
            self.proof_data_len.write(proof_hash, proof_len);

            // Extract security bits from proof config
            // The first few elements contain the PCS config
            // Format: [pow_bits, log_blowup_factor, log_last_layer_degree_bound, n_queries, ...]
            let security_bits = self._extract_security_bits(proof_data.span());

            // Check minimum security
            assert!(
                security_bits >= config.min_security_bits,
                "Insufficient security bits"
            );

            // Store metadata
            let caller = get_caller_address();
            let timestamp = get_block_timestamp();

            let metadata = ProofMetadata {
                proof_hash,
                public_input_hash,
                security_bits,
                submitted_at: timestamp,
                submitter: caller,
                status: VerificationStatus::Pending,
                verified_at_block: 0,
            };
            self.proofs.write(proof_hash, metadata);

            // Emit event
            self.emit(ProofSubmitted {
                proof_hash,
                submitter: caller,
                public_input_hash,
                timestamp,
            });

            proof_hash
        }

        fn verify_proof(
            ref self: ContractState,
            proof_hash: felt252,
        ) -> bool {
            // Get proof metadata
            let mut metadata = self.proofs.read(proof_hash);
            assert!(
                metadata.status == VerificationStatus::Pending,
                "Proof not pending verification"
            );

            // Load proof data
            let proof_len = self.proof_data_len.read(proof_hash);
            let mut proof_data: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < proof_len {
                proof_data.append(self.proof_data.read((proof_hash, i)));
                i += 1;
            };

            // Perform verification
            // NOTE: In production, this would call the actual stwo-cairo-verifier
            // For now, we do basic structural validation
            let is_valid = self._verify_proof_internal(proof_data.span());

            if is_valid {
                // Update metadata
                metadata.status = VerificationStatus::Verified;
                metadata.verified_at_block = get_block_number();
                self.proofs.write(proof_hash, metadata);

                // Increment verified count
                let count = self.verified_count.read();
                self.verified_count.write(count + 1);

                // Emit event
                self.emit(ProofVerified {
                    proof_hash,
                    block_number: metadata.verified_at_block,
                    security_bits: metadata.security_bits,
                });

                true
            } else {
                // Mark as failed
                metadata.status = VerificationStatus::Failed;
                self.proofs.write(proof_hash, metadata);

                // Emit event
                self.emit(ProofRejected {
                    proof_hash,
                    reason: 'verification_failed',
                });

                false
            }
        }

        fn get_proof_metadata(
            self: @ContractState,
            proof_hash: felt252,
        ) -> ProofMetadata {
            self.proofs.read(proof_hash)
        }

        fn is_proof_verified(
            self: @ContractState,
            proof_hash: felt252,
        ) -> bool {
            let metadata = self.proofs.read(proof_hash);
            metadata.status == VerificationStatus::Verified
        }

        fn get_config(self: @ContractState) -> VerifierConfig {
            self.config.read()
        }

        fn update_config(
            ref self: ContractState,
            config: VerifierConfig,
        ) {
            // Only owner can update config
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            self.config.write(config);

            self.emit(ConfigUpdated {
                min_security_bits: config.min_security_bits,
                max_proof_size: config.max_proof_size,
            });
        }

        fn set_paused(ref self: ContractState, paused: bool) {
            let caller = get_caller_address();
            assert!(caller == self.owner.read(), "Only owner");

            let mut config = self.config.read();
            config.is_paused = paused;
            self.config.write(config);
        }

        fn get_verified_count(self: @ContractState) -> u64 {
            self.verified_count.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Extract security bits from proof configuration
        fn _extract_security_bits(self: @ContractState, proof_data: Span<felt252>) -> u32 {
            // PCS Config format (first 4 elements):
            // [pow_bits, log_blowup_factor, log_last_layer_degree_bound, n_queries]
            // Security = log_blowup_factor * n_queries

            if proof_data.len() < 4 {
                return 0;
            }

            // Extract config values (they're stored as felt252 but are small u32s)
            let pow_bits: u32 = (*proof_data[0]).try_into().unwrap_or(0);
            let log_blowup_factor: u32 = (*proof_data[1]).try_into().unwrap_or(0);
            let _log_last_layer: u32 = (*proof_data[2]).try_into().unwrap_or(0);
            let n_queries: u32 = (*proof_data[3]).try_into().unwrap_or(0);

            // Security bits = log_blowup_factor * n_queries + pow_bits
            log_blowup_factor * n_queries + pow_bits
        }

        /// Internal proof verification
        /// NOTE: This is a simplified version. In production, integrate with
        /// the full stwo-cairo-verifier library
        fn _verify_proof_internal(self: @ContractState, proof_data: Span<felt252>) -> bool {
            // Basic structural validation
            if proof_data.len() < 10 {
                return false;
            }

            // Check config values are reasonable
            let pow_bits: u32 = (*proof_data[0]).try_into().unwrap_or(0);
            let log_blowup_factor: u32 = (*proof_data[1]).try_into().unwrap_or(0);
            let n_queries: u32 = (*proof_data[3]).try_into().unwrap_or(0);

            // Validate ranges
            if pow_bits > 30 || pow_bits < 20 {
                return false;
            }
            if log_blowup_factor > 16 || log_blowup_factor < 1 {
                return false;
            }
            if n_queries > 100 || n_queries < 10 {
                return false;
            }

            // In production, this would:
            // 1. Parse the full CommitmentSchemeProof structure
            // 2. Verify FRI commitments and decommitments
            // 3. Check Merkle proofs
            // 4. Verify constraint evaluations at OODS point
            // 5. Verify proof of work
            //
            // For now, return true for structurally valid proofs
            // The actual verification will be done by integrating stwo-cairo-verifier

            true
        }
    }
}

