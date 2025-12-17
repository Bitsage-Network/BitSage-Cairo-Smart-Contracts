//! Address Registry Module - BitSage Network
//!
//! Human-readable naming system for Obelysk Protocol addresses:
//!
//! Examples:
//!   obelysk:prover-registry  → 0x04736828c69fda...
//!   obelysk:validator        → 0x0737c361e784...
//!   sage:token               → 0x0662c81332894...
//!   bitsage:treasury         → 0x04736828c69fda...

pub mod address_registry;

/// Enclave Registry - Central whitelist for TEE enclave measurements
/// Used by both proof_verifier and stwo_verifier for consistent enclave management
pub mod enclave_registry;

