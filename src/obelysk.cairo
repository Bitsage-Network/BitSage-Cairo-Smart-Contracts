pub mod optimistic_tee;
pub mod stwo_verifier;
pub mod prover_registry;
pub mod validator_registry;

// Production TEE Attestation Verification
// Supports Intel TDX, AMD SEV-SNP, NVIDIA Confidential Computing
pub mod tee_attestation;

// Privacy Layer (Zether-inspired ElGamal encryption)
pub mod elgamal;
pub mod privacy_router;
pub mod worker_privacy;
