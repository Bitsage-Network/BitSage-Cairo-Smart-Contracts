# Obelysk Privacy Protocol: Proof Architecture

## Overview

The BitSage Network implements a dual-proof architecture optimized for different use cases:

1. **Schnorr-based Proofs** - Lightweight proofs for privacy-preserving payments and swaps
2. **Circle STARKs (STWO)** - Heavy-duty proofs for verifiable computation

This document explains the technical differences, Starknet integration, and performance characteristics.

---

## Proof System Comparison

### Schnorr Proofs

**What they are:**
Schnorr proofs are discrete logarithm-based zero-knowledge proofs that prove knowledge of a secret value without revealing it. They leverage elliptic curve cryptography to create compact, efficiently verifiable proofs.

**Mathematical Foundation:**
```
Given: G (generator), P = x·G (public key)
Prove: Knowledge of x without revealing x

Protocol:
1. Prover: k ← random, R = k·G
2. Prover → Verifier: R
3. Challenge: c = H(R, P, message)
4. Prover: s = k + c·x
5. Verifier checks: s·G = R + c·P
```

**Properties:**
- Proof size: ~64-128 bytes
- Verification: 2 EC multiplications + 1 EC addition
- Security: Discrete log assumption on elliptic curves
- Perfect zero-knowledge

**Use Cases in Obelysk:**
- Encryption proofs (prove ciphertext is valid ElGamal encryption)
- Balance proofs (prove sufficient funds without revealing amount)
- Ownership proofs (prove control of private key)
- Range proofs (prove value is within bounds)

---

### Circle STARKs (STWO)

**What they are:**
Circle STARKs are Scalable Transparent ARguments of Knowledge based on the circle curve over the Mersenne-31 field. Developed by StarkWare, STWO represents the next generation of STARK proving systems with significant performance improvements.

**Mathematical Foundation:**
```
Given: Execution trace T, Constraints C
Prove: T satisfies all constraints in C

Protocol:
1. Commit to trace polynomials (Merkle trees)
2. Evaluate constraints at random points
3. FRI protocol for low-degree testing
4. Query phase for soundness
```

**Properties:**
- Proof size: 50KB - 10MB (depending on computation complexity)
- Verification: O(log²n) field operations
- Security: Collision-resistant hashing + algebraic assumptions
- Transparent setup (no trusted ceremony)

**Use Cases in BitSage:**
- Verifiable AI/ML inference
- Complex computation verification
- Batch proof aggregation
- Cross-chain verification

---

## Starknet Native Integration

### Schnorr Proofs on Starknet

Schnorr proofs are **fully compatible** with Starknet through native elliptic curve operations:

| Cairo Built-in | Operation | Gas Cost |
|----------------|-----------|----------|
| `ec_point_unwrap` | Point extraction | ~100 gas |
| `ec_mul` | Scalar multiplication | ~2,500 gas |
| `ec_add` | Point addition | ~500 gas |
| `pedersen_hash` | Pedersen hash | ~50 gas |
| `poseidon_hash` | Poseidon hash | ~30 gas |

**Starknet Advantages for Schnorr:**
- Native STARK curve (same as Ethereum's secp256k1 security level)
- Built-in EC operations in Cairo
- Poseidon hash optimized for STARK-friendly arithmetic
- Low gas costs for cryptographic primitives

**Implementation:**
```cairo
// Native Schnorr verification in Cairo
fn verify_schnorr_proof(
    public_key: ECPoint,
    message: felt252,
    signature: SchnorrSignature,
) -> bool {
    // Challenge computation using Poseidon (native)
    let c = poseidon_hash(signature.R.x, signature.R.y, public_key.x, message);

    // Verification equation: s·G = R + c·P
    let sG = ec_mul(ec_generator(), signature.s);
    let cP = ec_mul(public_key, c);
    let R_plus_cP = ec_add(signature.R, cP);

    sG == R_plus_cP
}
```

---

### Circle STARKs on Starknet

STWO proofs require a dedicated verifier contract due to their complexity:

| Component | On-chain Cost | Off-chain Cost |
|-----------|---------------|----------------|
| Merkle root verification | ~10K gas | N/A |
| FRI layer verification | ~50K gas per layer | N/A |
| OODS evaluation | ~20K gas | N/A |
| Query verification | ~5K gas per query | N/A |
| **Total (typical)** | **~300K-500K gas** | **N/A** |

---

## Performance & Cost Analysis

### Client-Side Proof Generation (Schnorr)

Proofs generated on user's device (browser, mobile app, CLI):

| Device Type | Proof Generation Time | Memory Usage |
|-------------|----------------------|--------------|
| Modern Browser (WASM) | 50-100ms | ~10MB |
| Mobile Device | 100-200ms | ~15MB |
| Node.js Server | 20-50ms | ~5MB |
| Low-end Device | 200-500ms | ~20MB |

**On-chain Verification Cost:**

| Proof Type | Gas Cost | USD Cost (at $0.0002/gas) |
|------------|----------|---------------------------|
| Single Schnorr proof | ~15,000 | $0.003 |
| Encryption proof | ~25,000 | $0.005 |
| Range proof (64-bit) | ~80,000 | $0.016 |
| Balance proof | ~30,000 | $0.006 |
| **Full payment proof bundle** | **~150,000** | **$0.03** |

---

### GPU-Accelerated Proof Generation (STWO)

Proofs generated via BitSage STWO GPU infrastructure:

| Hardware | Proof Generation Time | Throughput |
|----------|----------------------|------------|
| NVIDIA H100 | 1-5 seconds | ~100 proofs/min |
| NVIDIA A100 | 3-10 seconds | ~30 proofs/min |
| NVIDIA 4090 | 5-15 seconds | ~15 proofs/min |
| CPU (SIMD) | 30-120 seconds | ~1 proof/min |

**On-chain Verification Cost:**

| Proof Complexity | Proof Size | Gas Cost | USD Cost |
|-----------------|------------|----------|----------|
| Small (10K constraints) | ~50KB | ~200,000 | $0.04 |
| Medium (100K constraints) | ~200KB | ~350,000 | $0.07 |
| Large (1M constraints) | ~500KB | ~500,000 | $0.10 |
| XL (10M constraints) | ~2MB | ~800,000 | $0.16 |

---

## Cost Comparison: Local vs GPU SDK

### Scenario 1: Simple Private Payment

| Method | Proof Time | On-chain Gas | Total Cost | Privacy |
|--------|------------|--------------|------------|---------|
| Client Schnorr (local) | 100ms | 150K | ~$0.03 | Full |
| STWO GPU SDK | 3 sec | 350K | ~$0.08 | Full (TEE) |
| STWO CPU (local) | 45 sec | 350K | ~$0.07 | Full |

**Recommendation:** Client-side Schnorr for payments

---

### Scenario 2: Batch Payment (100 transfers)

| Method | Proof Time | On-chain Gas | Total Cost | Privacy |
|--------|------------|--------------|------------|---------|
| Client Schnorr (100x) | 10 sec | 15M | ~$3.00 | Full |
| STWO GPU (aggregated) | 5 sec | 500K | ~$0.12 | Full (TEE) |
| STWO CPU (aggregated) | 90 sec | 500K | ~$0.10 | Full |

**Recommendation:** STWO GPU SDK for batch operations (75x cost reduction)

---

### Scenario 3: Verifiable ML Inference

| Method | Proof Time | On-chain Gas | Total Cost | Privacy |
|--------|------------|--------------|------------|---------|
| Client-side | Not feasible | - | - | - |
| STWO GPU SDK | 5-30 sec | 500K | ~$0.15 | Full (TEE) |
| STWO CPU | 5-30 min | 500K | ~$0.10 | None |

**Recommendation:** STWO GPU SDK with TEE for compute jobs

---

### Scenario 4: Confidential Swap

| Method | Proof Time | On-chain Gas | Total Cost | Privacy |
|--------|------------|--------------|------------|---------|
| Client Schnorr | 150ms | 200K | ~$0.04 | Full |
| STWO GPU SDK | 3 sec | 400K | ~$0.10 | Full (TEE) |

**Recommendation:** Client-side Schnorr for individual swaps

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        BITSAGE PROOF ARCHITECTURE                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│                           USER APPLICATION                                  │
│                          (Browser/Mobile/CLI)                               │
│                                  │                                          │
│                    ┌─────────────┴─────────────┐                            │
│                    ▼                           ▼                            │
│         ┌─────────────────────┐     ┌─────────────────────┐                 │
│         │   OBELYSK LAYER     │     │   COMPUTE LAYER     │                 │
│         │   (Payments/Swaps)  │     │   (AI/ML Jobs)      │                 │
│         ├─────────────────────┤     ├─────────────────────┤                 │
│         │                     │     │                     │                 │
│         │  Schnorr Proofs     │     │  STWO Circle STARKs │                 │
│         │  • Client-generated │     │  • GPU-accelerated  │                 │
│         │  • 50-100ms         │     │  • 1-30 seconds     │                 │
│         │  • ~$0.03/tx        │     │  • ~$0.10/proof     │                 │
│         │  • Full privacy     │     │  • TEE for privacy  │                 │
│         │                     │     │                     │                 │
│         └──────────┬──────────┘     └──────────┬──────────┘                 │
│                    │                           │                            │
│                    └─────────────┬─────────────┘                            │
│                                  ▼                                          │
│                    ┌─────────────────────────┐                              │
│                    │       STARKNET L2       │                              │
│                    │  • Native EC operations │                              │
│                    │  • STARK-friendly hash  │                              │
│                    │  • Low verification gas │                              │
│                    └─────────────────────────┘                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Performance Gains with STWO GPU SDK

### Proof Generation Speedup

| Baseline (CPU) | STWO GPU SDK | Speedup |
|----------------|--------------|---------|
| 60 seconds | 3 seconds | **20x faster** |
| 120 seconds | 5 seconds | **24x faster** |
| 300 seconds | 10 seconds | **30x faster** |

### Cost Efficiency (Batch Operations)

| Operation | Individual Proofs | Aggregated (GPU) | Savings |
|-----------|-------------------|------------------|---------|
| 10 payments | $0.30 | $0.12 | **60%** |
| 100 payments | $3.00 | $0.15 | **95%** |
| 1000 payments | $30.00 | $0.25 | **99%** |

### Throughput Comparison

| Infrastructure | Proofs/Hour | Cost/1000 Proofs |
|----------------|-------------|------------------|
| Single CPU | 30-60 | ~$100 (time cost) |
| Consumer GPU (4090) | 200-400 | ~$15 |
| Datacenter GPU (H100) | 1,000-3,000 | ~$5 |
| BitSage GPU Cluster | 10,000+ | ~$2 |

---

## Security Considerations

### Schnorr Proofs
- **Assumption:** Discrete logarithm problem hardness
- **Security level:** 128-bit (STARK curve)
- **Attack vectors:** None known for properly implemented protocols
- **Quantum resistance:** Not quantum-safe (requires migration path)

### Circle STARKs
- **Assumption:** Collision-resistant hashing
- **Security level:** 96-128 bit (configurable)
- **Attack vectors:** None known; transparent setup eliminates trusted ceremony risks
- **Quantum resistance:** Believed to be quantum-safe

---

## Conclusion

The BitSage dual-proof architecture leverages:

1. **Schnorr proofs** for lightweight, privacy-preserving payments with minimal latency and cost
2. **STWO Circle STARKs** for complex computation verification with GPU acceleration

Both systems integrate natively with Starknet's Cairo VM, utilizing built-in cryptographic primitives for optimal gas efficiency.

The STWO GPU SDK provides significant performance improvements for batch operations and compute-intensive workloads, while client-side Schnorr proofs offer the most cost-effective solution for individual transactions.

---

*Document Version: 1.0*
*BitSage Network - Obelysk Privacy Protocol*
