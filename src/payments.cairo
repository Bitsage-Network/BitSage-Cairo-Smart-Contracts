//! Payment Router - Multi-token payment system with OTC desk
//! Accepts: USDC, STRK, wBTC, SAGE with tiered discounts
pub mod payment_router;

//! Proof-Gated Payment System
//! Connects ProofVerifier → PaymentRouter
//! Payments only flow after proof verification (STWO or TEE)
pub mod proof_gated_payment;

//! Metered Billing - Hourly GPU Compute Tracking
//! Each hour of compute generates a proof checkpoint for billing
//! Supports STWO proofs and TEE attestations
pub mod metered_billing;
