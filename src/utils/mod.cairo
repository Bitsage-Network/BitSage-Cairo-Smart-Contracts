//! Utilities Module for SAGE Network Contracts
//! Cairo 2.12.0 Code Deduplication & Optimization

pub mod common;

/// Shared STWO verification utilities used by proof_verifier and stwo_verifier
/// Provides: hash functions, M31 validation, PoW verification, PCS config extraction
pub mod verification;