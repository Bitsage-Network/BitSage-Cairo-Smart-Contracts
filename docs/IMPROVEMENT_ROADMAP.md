# Obelysk Privacy Improvement Roadmap
## Learning from Tongo & Privacy Pools

Based on comprehensive analysis of Tongo's SHE (Somewhat Homomorphic Encryption) library and Privacy Pools implementation, this document outlines high-impact improvements for Obelysk.

---

## Executive Summary

| Priority | Feature | Impact | Effort | Status |
|----------|---------|--------|--------|--------|
| P0 | Same Encryption Proofs | Critical | Medium | Not Started |
| P0 | Proper Range Proofs (Bit Decomposition) | Critical | High | Partial |
| P1 | Multi-Signature Auditing | High | Medium | Not Started |
| P1 | Ex-Post Proving | High | Medium | Not Started |
| P2 | Viewing Keys (Granular Disclosure) | Medium | Low | Not Started |
| P2 | LeanIMT Optimization | Medium | Medium | Not Started |
| P3 | Threshold Compliance Proofs | Low | High | Not Started |

---

## P0: Critical Security Improvements

### 1. Same Encryption Proofs

**Current Gap**: Obelysk creates separate encryptions for sender, receiver, and auditor but doesn't cryptographically prove they encrypt the same amount.

**Why Critical**: Without this proof, a malicious user could:
- Encrypt different amounts for receiver vs sender
- Create balance discrepancies
- Bypass auditor tracking

**Tongo Solution**:
```
Statement: Prove (L1, R1) and (L2, R2) encrypt same message b
Key insight: Both proofs share the same sb response

Protocol:
1. Prover creates commitments: AL1, AR1, AL2, AR2
2. Challenge: c = Hash(prefix, AL1, AR1, AL2, AR2)
3. Responses: sb (SHARED), sr1, sr2
4. Verification uses same sb for both ciphertexts
```

**Implementation Plan**:
```cairo
// src/obelysk/same_encryption.cairo

/// Proof that two ElGamal ciphertexts encrypt the same value
pub struct SameEncryptionProof {
    /// Commitments for first ciphertext
    pub al1_x: felt252,
    pub al1_y: felt252,
    pub ar1_x: felt252,
    pub ar1_y: felt252,
    /// Commitments for second ciphertext
    pub al2_x: felt252,
    pub al2_y: felt252,
    pub ar2_x: felt252,
    pub ar2_y: felt252,
    /// Shared message response (proves same amount!)
    pub sb: felt252,
    /// Individual randomness responses
    pub sr1: felt252,
    pub sr2: felt252,
}

/// Verify two ciphertexts encrypt the same value
pub fn verify_same_encryption(
    ct1: ElGamalCiphertext,
    ct2: ElGamalCiphertext,
    pk1: ECPoint,
    pk2: ECPoint,
    proof: SameEncryptionProof
) -> bool {
    // Recompute challenge
    let c = poseidon_hash(proof.al1_x, proof.al1_y, ...);

    // Verify ElGamal 1: g^sb * pk1^sr1 == AL1 * L1^c
    let lhs1 = ec_add(ec_mul(sb, G), ec_mul(sr1, pk1));
    let rhs1 = ec_add(AL1, ec_mul(c, ct1.L));

    // Verify ElGamal 2: g^sb * pk2^sr2 == AL2 * L2^c
    // CRITICAL: Same sb proves same amount!
    let lhs2 = ec_add(ec_mul(sb, G), ec_mul(sr2, pk2));
    let rhs2 = ec_add(AL2, ec_mul(c, ct2.L));

    lhs1 == rhs1 && lhs2 == rhs2
}
```

**Files to Create/Modify**:
- `src/obelysk/same_encryption.cairo` (new)
- `src/obelysk/privacy_router.cairo` (require proof in transfers)
- `src/obelysk/elgamal.cairo` (add helper functions)

---

### 2. Proper Range Proofs (Bit Decomposition)

**Current Gap**: Obelysk has range proof structure but uses simplified verification. Tongo uses proper bit decomposition with OR proofs.

**Why Critical**: Range proofs prevent:
- Negative balance attacks (underflow)
- Amount overflow exploits
- Hidden value manipulation

**Tongo's Approach**:
```
1. Decompose value to bits: b = Σ b_i * 2^i
2. Commit to each bit: V_i = g^{b_i} * h^{r_i}
3. Prove each V_i is commitment to 0 or 1 (OR proof)
4. Verify consistency: Π V_i^{2^i} = g^b * h^r
```

**Bit Proof (OR Construction)**:
```
For b=0: Real proof for V = h^r, Simulated for V/g
For b=1: Simulated for V = h^r, Real proof for V/g
Challenge split: c = c_real ⊕ c_simulated
```

**Implementation Enhancement**:
```cairo
// src/obelysk/bit_proofs.cairo

/// OR proof that commitment contains 0 or 1
pub struct BitProof {
    // Commitment for V = g^0 * h^r (if b=0, this is real)
    pub a0_x: felt252,
    pub a0_y: felt252,
    pub c0: felt252,
    pub s0: felt252,
    // Commitment for V/g = g^0 * h^r (if b=1, this is real)
    pub a1_x: felt252,
    pub a1_y: felt252,
    pub c1: felt252,
    pub s1: felt252,
}

/// Full range proof using bit decomposition
pub struct RangeProof32 {
    /// 32 bit commitments
    pub bit_commitments: Array<ECPoint>,
    /// 32 bit proofs
    pub bit_proofs: Array<BitProof>,
    /// Total randomness for consistency check
    pub total_randomness: felt252,
}

pub fn verify_range_proof_32(
    value_commitment: ECPoint,  // V = g^b * h^r
    proof: RangeProof32
) -> bool {
    // 1. Verify each bit proof
    for i in 0..32 {
        if !verify_bit_proof(proof.bit_commitments[i], proof.bit_proofs[i]) {
            return false;
        }
    }

    // 2. Verify consistency: Π V_i^{2^i} = V
    let mut reconstructed = ec_zero();
    for i in 0..32 {
        let power = pow2(i);
        reconstructed = ec_add(reconstructed, ec_mul(power, proof.bit_commitments[i]));
    }

    reconstructed == value_commitment
}
```

---

## P1: High-Impact Features

### 3. Multi-Signature Auditing

**Current Gap**: Single auditor key. If compromised, all transaction privacy is lost.

**Tongo Solution**: Distributed auditor keys with threshold decryption.

```
y_a = g^{a1 + a2} = y_a1 * y_a2

Decryption requires both parties:
- Auditor 1: R^{a1}
- Auditor 2: R^{a2}
- Combined: g^b = L / (R^{a1} * R^{a2})
```

**Implementation**:
```cairo
// src/obelysk/threshold_audit.cairo

/// Threshold auditor configuration
pub struct ThresholdAuditor {
    /// Combined public key (product of individual keys)
    pub combined_key: ECPoint,
    /// Individual auditor public keys
    pub auditor_keys: Array<ECPoint>,
    /// Threshold required (t of n)
    pub threshold: u8,
    pub total_auditors: u8,
}

/// Partial decryption share from one auditor
pub struct DecryptionShare {
    pub auditor_index: u8,
    pub share: ECPoint,  // R^{a_i}
    pub proof: SchnorrProof,  // Prove knowledge of a_i
}

/// Combine shares to decrypt
pub fn combine_decryption_shares(
    ciphertext: ElGamalCiphertext,
    shares: Array<DecryptionShare>,
    threshold: u8
) -> Option<ECPoint> {
    if shares.len() < threshold {
        return None;
    }

    // Combine: R^{a1} * R^{a2} * ... * R^{at}
    let mut combined_blinding = ec_zero();
    for share in shares {
        combined_blinding = ec_add(combined_blinding, share.share);
    }

    // Decrypt: g^b = L / combined_blinding
    Some(ec_sub(ciphertext.L, combined_blinding))
}
```

---

### 4. Ex-Post Proving

**Current Gap**: No mechanism for retroactive transaction disclosure without revealing private keys.

**Why Important**:
- Legal compliance requests
- Dispute resolution
- Tax reporting

**Tongo Protocol**:
```
Given completed transfer (TL, TR) = Enc[y](b0, r0):

1. Create new encryption: (L, R) = Enc[y](b, r)
2. Create third-party encryption: (L_bar, R) = Enc[y_bar](b, r)
3. Prove consistency: TL/L = (TR/R)^x

This proves b = b0 without revealing x or the original randomness.
```

**Implementation**:
```cairo
// src/obelysk/ex_post_proof.cairo

/// Proof for retroactive amount disclosure
pub struct ExPostProof {
    /// New encryption of claimed amount
    pub new_ciphertext: ElGamalCiphertext,
    /// Encryption for third party
    pub third_party_ciphertext: ElGamalCiphertext,
    /// Ownership proof (POE for private key)
    pub ownership_proof: SchnorrProof,
    /// Consistency proof: TL/L = (TR/R)^x
    pub consistency_proof: ConsistencyProof,
    /// Reference to original transaction
    pub original_tx_hash: felt252,
}

pub fn verify_ex_post_disclosure(
    original_ciphertext: ElGamalCiphertext,
    third_party_key: ECPoint,
    proof: ExPostProof
) -> bool {
    // 1. Verify ownership of original key

    // 2. Verify consistency: proves same amount
    // TL/L should equal (TR/R)^x
    let ratio_L = ec_sub(original_ciphertext.L, proof.new_ciphertext.L);
    let ratio_R = ec_sub(original_ciphertext.R, proof.new_ciphertext.R);

    // Verify the relationship holds
    verify_consistency(ratio_L, ratio_R, proof.consistency_proof)
}
```

---

## P2: Medium-Impact Improvements

### 5. Viewing Keys (Granular Disclosure)

**Current**: Global auditor only.

**Enhancement**: Per-transaction viewing key support.

```cairo
struct Transfer {
    // ... existing fields ...
    /// Optional additional viewing keys
    viewing_keys: Option<Array<ViewingKeyEncryption>>,
}

struct ViewingKeyEncryption {
    viewer_pubkey: ECPoint,
    encrypted_amount: ElGamalCiphertext,
    same_encryption_proof: SameEncryptionProof,
}
```

---

### 6. LeanIMT Optimization

**Current**: Standard Merkle tree for nullifiers.

**Privacy Pools Optimization**:
- Single-child nodes propagate without hashing
- Dynamic tree depth
- Circular buffer for recent roots (30 entries)

```cairo
// Optimized nullifier tree insertion
fn insert_nullifier_lean(ref tree: LeanIMT, nullifier: felt252) {
    let mut current = nullifier;
    let mut depth = 0;

    while depth < tree.depth {
        let sibling = tree.get_sibling(depth);
        if sibling.is_none() {
            // Single child - propagate without hashing
            tree.set_node(depth, current);
            break;
        }
        current = poseidon_hash(current, sibling.unwrap());
        depth += 1;
    }

    // Update circular root buffer
    tree.root_buffer[(tree.root_index + 1) % 30] = current;
}
```

---

## P3: Future Enhancements

### 7. Threshold Compliance Proofs

Prove compliance properties without revealing amounts:
- Range compliance: amount < threshold
- Velocity limits: cumulative amounts within bounds
- Whitelist compliance: recipient authorization

---

## Implementation Priority

### Phase 1 (Critical - 2-3 weeks)
1. Same Encryption Proofs
2. Enhanced Range Proofs with Bit Decomposition

### Phase 2 (High Impact - 2 weeks)
3. Multi-Signature Auditing
4. Ex-Post Proving

### Phase 3 (Medium Impact - 1-2 weeks)
5. Viewing Keys
6. LeanIMT Optimization

### Phase 4 (Future)
7. Threshold Compliance Proofs

---

## Testing Requirements

Each feature requires:
1. Unit tests for cryptographic primitives
2. Integration tests with privacy_router
3. Gas/step benchmarking
4. Security audit focus areas

---

## Security Considerations

### Same Encryption Proofs
- Challenge must include all commitments
- Responses must be computed mod curve order
- Domain separation for different proof contexts

### Range Proofs
- Bit proofs must use different prefixes
- Challenge split must be verifiable
- Consistency check is critical

### Multi-Sig Auditing
- Key generation ceremony required
- Share verification prevents malicious shares
- Threshold must be >50% for security

---

## References

- Tongo SHE Library: `/specs/Tongo/tongo-docs/src/she/`
- Privacy Pools: `/specs/Tongo/privacy-pools-core/`
- Zether Protocol: Original inspiration
- Bulletproofs: Alternative range proof construction
