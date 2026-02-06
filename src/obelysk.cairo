pub mod optimistic_tee;
pub mod stwo_verifier;
pub mod prover_registry;
pub mod validator_registry;

// Proof Verification & Aggregation
pub mod fri_verifier;
pub mod batch_verifier;
pub mod proof_aggregator;

// Privacy Layer (Zether-inspired ElGamal encryption)
pub mod elgamal;
pub mod pedersen_commitments;
pub mod privacy_router;
pub mod mixing_router;
pub mod steganographic_router;
pub mod worker_privacy;
pub mod same_encryption;
pub mod bit_proofs;
pub mod lean_imt;

// Privacy Pools (Vitalik Buterin's compliance-compatible privacy protocol)
pub mod privacy_pools;

// Fuzzy Message Detection (privacy-preserving transaction filtering)
pub mod fmd;

// Confidential Swaps (private atomic asset exchanges)
pub mod confidential_swap;

// Confidential Transfers (Tongo-style private balance transfers)
pub mod confidential_transfer;

// Fully Homomorphic Encryption (FHE) verification
pub mod fhe_verifier;

// Shielded Swap Router — Private token swaps via Ekubo AMM (ILocker pattern)
pub mod shielded_swap_router;

// Stealth Address Registry (TODO: fix stealth_payments dependency)
// pub mod stealth_registry;
