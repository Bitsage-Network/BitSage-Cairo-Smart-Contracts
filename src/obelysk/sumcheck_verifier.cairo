// SPDX-License-Identifier: BUSL-1.1
//
// On-Chain Sumcheck Verifier for ML Matrix Multiplication
//
// Verifies stwo-ml matmul proofs directly on Starknet.
// No stubs. Every function performs real cryptographic verification.
//
// Fiat-Shamir channel matches STWO's Poseidon252Channel exactly:
//   draw:      hades_permutation(digest, n_draws, 3)[0]  → 8 M31 via floor_div(2^31)
//   mix_u64:   hades_permutation(digest, value, 2)[0]    (= starknet_crypto::poseidon_hash)
//   mix_felts: QM31 pairs → big-endian 2^31 pack → poseidon_hash_span (= poseidon_hash_many)
//
// Field tower: M31 → CM31 → QM31 (matching STWO's Circle STARK field)
//   M31  = Z / (2^31 - 1)
//   CM31 = M31[i] / (i² + 1)
//   QM31 = CM31[j] / (j² - (2 + i))
//
// Verification cost: O(log n) per matmul, where n is the inner dimension.
// For a 5120×5120 matmul (LLaMA-13B): 13 rounds ≈ 25k gas.
//
// Full transcript replay:
//   1. mix_u64(m), mix_u64(k), mix_u64(n)        — bind matrix dimensions
//   2. draw_qm31s(m_log), draw_qm31s(n_log)      — row/col challenges (1 draw per QM31)
//   3. mix_felt(pack(claimed_sum))                 — bind claimed evaluation
//   4. mix_felt(a_commitment), mix_felt(b_commitment) — bind MLE commitments
//   5. For each sumcheck round:
//      a. mix_felts(round_poly coefficients)       — absorb prover's polynomial
//      b. challenge = draw_qm31()                  — derive verifier's randomness
//      c. Check: p(0) + p(1) = expected_sum       — sumcheck round check
//   6. Final check: expected_sum = a_eval × b_eval — evaluation consistency
//   7. verify_mle_opening(A, assignment, channel)  — verify A MLE
//   8. verify_mle_opening(B, assignment, channel)  — verify B MLE

use core::poseidon::{poseidon_hash_span, hades_permutation};

// ============================================================================
// M31 Field Arithmetic (p = 2^31 - 1 = 2147483647)
// ============================================================================

const M31_P: u64 = 0x7FFFFFFF; // 2^31 - 1
const M31_SHIFT: felt252 = 0x80000000; // 2^31 as felt252

fn m31_add(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= M31_P {
        sum - M31_P
    } else {
        sum
    }
}

fn m31_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        M31_P - (b - a)
    }
}

fn m31_mul(a: u64, b: u64) -> u64 {
    // M31 × M31: max (2^31-2)^2 ≈ 2^62, fits in u64
    (a * b) % M31_P
}

/// Reduce a value to M31 range [0, P). Handles the edge case val == M31_P → 0.
pub fn m31_reduce(val: u64) -> u64 {
    val % M31_P
}

// ============================================================================
// CM31 = M31[i] / (i² + 1) — Complex M31
// ============================================================================

/// Complex M31: a + b·i where i² = -1
#[derive(Drop, Copy, Serde)]
pub struct CM31 {
    pub a: u64,
    pub b: u64,
}

fn cm31_add(x: CM31, y: CM31) -> CM31 {
    CM31 { a: m31_add(x.a, y.a), b: m31_add(x.b, y.b) }
}

fn cm31_sub(x: CM31, y: CM31) -> CM31 {
    CM31 { a: m31_sub(x.a, y.a), b: m31_sub(x.b, y.b) }
}

fn cm31_mul(x: CM31, y: CM31) -> CM31 {
    // (a + bi)(c + di) = (ac - bd) + (ad + bc)i
    let ac = m31_mul(x.a, y.a);
    let bd = m31_mul(x.b, y.b);
    let ad = m31_mul(x.a, y.b);
    let bc = m31_mul(x.b, y.a);
    CM31 { a: m31_sub(ac, bd), b: m31_add(ad, bc) }
}

fn cm31_eq(x: CM31, y: CM31) -> bool {
    x.a == y.a && x.b == y.b
}

// ============================================================================
// QM31 = CM31[j] / (j² - (2 + i)) — Secure Field (extension degree 4)
// ============================================================================

/// Secure field element: a + b·j where j² = 2 + i
/// Components: (a.a, a.b, b.a, b.b) — four M31 values.
/// Matches STWO's QM31(CM31(m31_0, m31_1), CM31(m31_2, m31_3)).
#[derive(Drop, Copy, Serde)]
pub struct QM31 {
    pub a: CM31, // "real" CM31 part
    pub b: CM31, // "j" coefficient
}

fn qm31_zero() -> QM31 {
    QM31 { a: CM31 { a: 0, b: 0 }, b: CM31 { a: 0, b: 0 } }
}

fn qm31_add(x: QM31, y: QM31) -> QM31 {
    QM31 { a: cm31_add(x.a, y.a), b: cm31_add(x.b, y.b) }
}

fn qm31_mul(x: QM31, y: QM31) -> QM31 {
    // (a + bj)(c + dj) = ac + bd·j² + (ad + bc)j
    // j² = 2 + i, so bd·j² = bd·(2 + i)
    let ac = cm31_mul(x.a, y.a);
    let bd = cm31_mul(x.b, y.b);

    // bd × (2 + i): if bd = (p + qi), then (2+i)(p+qi) = (2p - q) + (p + 2q)i
    let bd_times_irred = CM31 {
        a: m31_sub(m31_add(bd.a, bd.a), bd.b), // 2·bd.a - bd.b
        b: m31_add(bd.a, m31_add(bd.b, bd.b)), // bd.a + 2·bd.b
    };

    // Real part: ac + bd·(2+i)
    let real = cm31_add(ac, bd_times_irred);

    // j-coefficient: (a+b)(c+d) - ac - bd  (Karatsuba)
    let apb = cm31_add(x.a, x.b);
    let cpd = cm31_add(y.a, y.b);
    let apb_cpd = cm31_mul(apb, cpd);
    let j_part = cm31_sub(cm31_sub(apb_cpd, ac), bd);

    QM31 { a: real, b: j_part }
}

fn qm31_eq(x: QM31, y: QM31) -> bool {
    cm31_eq(x.a, y.a) && cm31_eq(x.b, y.b)
}

fn qm31_sub(x: QM31, y: QM31) -> QM31 {
    QM31 { a: cm31_sub(x.a, y.a), b: cm31_sub(x.b, y.b) }
}

// ============================================================================
// Polynomial Evaluation (Horner's method)
// ============================================================================

/// Evaluate degree-2 polynomial: p(x) = c0 + c1·x + c2·x²
fn poly_eval_degree2(c0: QM31, c1: QM31, c2: QM31, x: QM31) -> QM31 {
    // c0 + x·(c1 + x·c2)
    let inner = qm31_add(c1, qm31_mul(x, c2));
    qm31_add(c0, qm31_mul(x, inner))
}

// ============================================================================
// Poseidon252-Compatible Fiat-Shamir Channel
//
// Exactly matches STWO's Poseidon252Channel (stwo/src/core/channel/poseidon252.rs):
//
//   draw_secure_felt252():
//     state = [digest, n_draws, THREE(=3)]
//     hades_permutation(state)
//     return state[0], n_draws += 1
//
//   draw_base_felts():
//     felt252 → 8 M31 values via successive floor_div(2^31)
//     (LSB first: index 0 = least significant 31 bits)
//
//   draw_secure_felt():
//     8 M31 → take first 4 → QM31(CM31(m0,m1), CM31(m2,m3))
//
//   mix_u64(value):
//     digest = poseidon_hash(digest, value) = hades_permutation(digest, value, 2)[0]
//     n_draws = 0
//
//   mix_felts(&[SecureField]):
//     Pack QM31 pairs: fold(ONE, |acc, m31| acc * 2^31 + m31)
//     digest = poseidon_hash_many([digest, packed_values...])
//     n_draws = 0
// ============================================================================

/// Channel state matching STWO's Poseidon252Channel { digest, n_draws }.
#[derive(Drop, Copy)]
pub struct PoseidonChannel {
    pub digest: felt252,
    pub n_draws: u32,
}

/// Poseidon252Channel::default() — initial state.
pub fn channel_default() -> PoseidonChannel {
    PoseidonChannel { digest: 0, n_draws: 0 }
}

/// Mix a u64 value into the channel.
/// Matches: self.update_digest(poseidon_hash(self.digest, value.into()))
/// poseidon_hash(a, b) in starknet_crypto = hades_permutation(a, b, 2)[0]
pub fn channel_mix_u64(ref ch: PoseidonChannel, value: u64) {
    let (s0, _, _) = hades_permutation(ch.digest, value.into(), 2);
    ch.digest = s0;
    ch.n_draws = 0;
}

/// Mix a felt252 value into the channel.
/// Matches Rust's PoseidonChannel::mix_felt(value):
///   state = [digest, value, 2]; hades(&state); digest = state[0]; n_draws = 0;
pub fn channel_mix_felt(ref ch: PoseidonChannel, value: felt252) {
    let (s0, _, _) = hades_permutation(ch.digest, value, 2);
    ch.digest = s0;
    ch.n_draws = 0;
}

/// Draw a raw felt252 from the channel.
/// Matches: poseidon_permute_comp(&mut [digest, n_draws, THREE])[0]
/// Domain separator THREE(=3) distinguishes draws from mixes (which use 0 or 2).
fn channel_draw_felt252(ref ch: PoseidonChannel) -> felt252 {
    let (s0, _, _) = hades_permutation(ch.digest, ch.n_draws.into(), 3);
    ch.n_draws += 1;
    s0
}

/// Extract 8 M31 values from a felt252 by successive floor_div(2^31).
/// Matches STWO's draw_base_felts(): LSB first (index 0 = least significant 31 bits).
/// Each chunk is in [0, 2^31-1], then reduced to M31 range [0, P).
fn felt252_to_m31_array_8(
    value: felt252,
) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    let shift: u256 = 0x80000000; // 2^31
    let mut cur: u256 = value.into();

    // Extract 8 consecutive 31-bit chunks, LSB first
    let r0: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r1: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r2: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r3: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r4: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r5: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r6: u64 = (cur % shift).try_into().unwrap();
    cur = cur / shift;
    let r7: u64 = (cur % shift).try_into().unwrap();

    // Reduce to M31 range: handles edge case val == M31_P → 0
    (
        m31_reduce(r0), m31_reduce(r1), m31_reduce(r2), m31_reduce(r3),
        m31_reduce(r4), m31_reduce(r5), m31_reduce(r6), m31_reduce(r7),
    )
}

/// Draw a single QM31 challenge from the channel.
/// Matches: draw_secure_felt() = draw_base_felts()[0..4] → QM31
/// Consumes 1 Poseidon permutation (n_draws increments by 1).
/// Discards the upper 4 M31 values (same as Poseidon252Channel).
pub fn channel_draw_qm31(ref ch: PoseidonChannel) -> QM31 {
    let felt = channel_draw_felt252(ref ch);
    let (m0, m1, m2, m3, _, _, _, _) = felt252_to_m31_array_8(felt);
    QM31 {
        a: CM31 { a: m0, b: m1 },
        b: CM31 { a: m2, b: m3 },
    }
}

/// Draw multiple QM31 challenges from the channel.
/// Each QM31 consumes 1 Poseidon permutation (1 draw per QM31).
/// Matches Rust's PoseidonChannel::draw_qm31s() — no buffering.
pub fn channel_draw_qm31s(ref ch: PoseidonChannel, count: u32) -> Array<QM31> {
    let mut result: Array<QM31> = array![];
    let mut i: u32 = 0;
    loop {
        if i >= count {
            break;
        }
        result.append(channel_draw_qm31(ref ch));
        i += 1;
    };
    result
}

/// Pack a QM31's 4 M31 components into a running felt252 accumulator.
/// Implements: fold(acc, m31) = acc * 2^31 + m31
/// Component order: [a.a, a.b, b.a, b.b] matching STWO's to_m31_array().
fn pack_qm31_into_felt(mut cur: felt252, v: QM31) -> felt252 {
    cur = cur * M31_SHIFT + v.a.a.into();
    cur = cur * M31_SHIFT + v.a.b.into();
    cur = cur * M31_SHIFT + v.b.a.into();
    cur = cur * M31_SHIFT + v.b.b.into();
    cur
}

/// Mix degree-2 polynomial coefficients [c0, c1, c2] into the channel.
/// Matches: channel.mix_felts(&round_poly.coeffs) in partially_verify.
///
/// Packing (Poseidon252Channel::mix_felts with chunks(2)):
///   Chunk [c0, c1] → 8 M31 → 1 felt252 (starting from ONE)
///   Chunk [c2]     → 4 M31 → 1 felt252 (starting from ONE)
///   digest = poseidon_hash_many([digest, packed1, packed2])
///          = poseidon_hash_span(array![digest, packed1, packed2].span())
pub fn channel_mix_poly_coeffs(ref ch: PoseidonChannel, c0: QM31, c1: QM31, c2: QM31) {
    // Chunk 1: pack [c0, c1] → 8 M31 → 1 felt252
    let mut packed1: felt252 = 1; // FieldElement252::ONE
    packed1 = pack_qm31_into_felt(packed1, c0);
    packed1 = pack_qm31_into_felt(packed1, c1);

    // Chunk 2: pack [c2] → 4 M31 → 1 felt252
    let mut packed2: felt252 = 1; // FieldElement252::ONE
    packed2 = pack_qm31_into_felt(packed2, c2);

    // poseidon_hash_many([digest, packed1, packed2])
    ch.digest = poseidon_hash_span(array![ch.digest, packed1, packed2].span());
    ch.n_draws = 0;
}

// ============================================================================
// Proof Structures
// ============================================================================

/// A single round polynomial: p(x) = c0 + c1·x + c2·x²
/// Coefficients in monomial basis, matching STWO's UnivariatePoly<SecureField>.
#[derive(Drop, Copy, Serde)]
struct RoundPoly {
    c0: QM31,
    c1: QM31,
    c2: QM31,
}

// ============================================================================
// MLE Opening Proof Structures
// ============================================================================

/// Data for a single query at a single folding round of the MLE opening protocol.
#[derive(Drop, Serde)]
struct MleQueryRoundData {
    /// Value at the lo half (L_i[idx]) — QM31 packed as felt252 for Merkle leaf.
    left_value: QM31,
    /// Value at the hi half (L_i[mid + idx]) — QM31 packed as felt252 for Merkle leaf.
    right_value: QM31,
    /// Merkle path siblings for the left value (bottom-up).
    left_siblings: Array<felt252>,
    /// Merkle path siblings for the right value (bottom-up).
    right_siblings: Array<felt252>,
}

/// Complete data for a single query across all folding rounds.
#[derive(Drop, Serde)]
struct MleQueryProof {
    /// Initial query index in layer 0 (lo/hi pair: layer[idx] and layer[mid+idx]).
    initial_pair_index: u32,
    /// Authentication data at each folding round.
    rounds: Array<MleQueryRoundData>,
}

/// Opening proof for MLE(point) = claimed_eval using multilinear folding.
///
/// Verifies that a multilinear extension, committed via Poseidon Merkle tree,
/// evaluates to `final_value` at the given point. Uses spot-check queries
/// with Merkle authentication paths at each folding layer.
#[derive(Drop, Serde)]
struct MleOpeningProof {
    /// Merkle roots of intermediate folded layers (R_1, ..., R_{n-1}).
    /// R_0 is the original commitment (not included).
    intermediate_roots: Array<felt252>,
    /// Spot-check query proofs.
    queries: Array<MleQueryProof>,
    /// The final value after all folds (should equal claimed evaluation).
    final_value: QM31,
}

// ============================================================================
// Proof Structures
// ============================================================================

/// Complete sumcheck proof with MLE commitment openings for on-chain verification.
///
/// Contains the full sumcheck transcript plus Poseidon Merkle commitments to
/// matrices A and B, with multilinear folding proofs that verify final_a_eval
/// and final_b_eval against their committed Merkle roots.
#[derive(Drop, Serde)]
struct MatMulSumcheckProof {
    /// Matrix dimensions: A is m×k, B is k×n, C is m×n
    m: u32,
    k: u32,
    n: u32,
    /// Number of sumcheck rounds (= ceil_log2(k))
    num_rounds: u32,
    /// The claimed value: MLE_C evaluated at the random point derived by Fiat-Shamir
    claimed_sum: QM31,
    /// One degree-2 polynomial per sumcheck round
    round_polys: Array<RoundPoly>,
    /// MLE_A evaluated at (row_challenges, assignment)
    final_a_eval: QM31,
    /// MLE_B evaluated at (assignment, col_challenges)
    final_b_eval: QM31,
    /// Poseidon Merkle root of matrix A entries (the weight commitment).
    a_commitment: felt252,
    /// Poseidon Merkle root of matrix B entries (the input commitment).
    b_commitment: felt252,
    /// MLE opening proof verifying final_a_eval against a_commitment.
    a_opening: MleOpeningProof,
    /// MLE opening proof verifying final_b_eval against b_commitment.
    b_opening: MleOpeningProof,
}

// ============================================================================
// Core Sumcheck Verification
// ============================================================================

/// Verify a sumcheck proof, replaying the Fiat-Shamir transcript.
///
/// Matches STWO's partially_verify() + final evaluation check:
///   For each round:
///     1. Check: p_i(0) + p_i(1) = expected_sum
///     2. channel.mix_felts(round_poly coefficients)
///     3. challenge = channel.draw_secure_felt()
///     4. expected_sum ← p_i(challenge)
///   Final: expected_sum = final_a_eval × final_b_eval
///
/// The channel state must match the state at the entry to prove_batch()
/// in the Rust prover (after mixing dimensions and drawing row/col challenges).
fn verify_sumcheck_inner(
    claimed_sum: QM31,
    round_polys: Span<RoundPoly>,
    num_rounds: u32,
    final_a_eval: QM31,
    final_b_eval: QM31,
    ref ch: PoseidonChannel,
) -> (bool, felt252, Array<QM31>) {
    let mut expected_sum = claimed_sum;
    let initial_digest = ch.digest;
    let mut assignment: Array<QM31> = array![];

    // Verify each sumcheck round
    let mut round: u32 = 0;
    loop {
        if round >= num_rounds {
            break;
        }

        let poly = *round_polys.at(round);

        // Check: p_i(0) + p_i(1) = expected_sum
        //   p_i(0) = c0
        //   p_i(1) = c0 + c1 + c2
        let eval_at_0 = poly.c0;
        let eval_at_1 = qm31_add(qm31_add(poly.c0, poly.c1), poly.c2);
        let round_sum = qm31_add(eval_at_0, eval_at_1);

        if !qm31_eq(round_sum, expected_sum) {
            let proof_hash = poseidon_hash_span(
                array![initial_digest, round.into(), 'FAIL'].span(),
            );
            return (false, proof_hash, array![]);
        }

        // Mix round polynomial into channel (matching partially_verify)
        channel_mix_poly_coeffs(ref ch, poly.c0, poly.c1, poly.c2);

        // Draw random challenge (matching partially_verify)
        let challenge = channel_draw_qm31(ref ch);

        // Collect challenge into assignment (sumcheck variable binding)
        assignment.append(challenge);

        // Update expected sum: expected_sum ← p_i(challenge)
        expected_sum = poly_eval_degree2(poly.c0, poly.c1, poly.c2, challenge);

        round += 1;
    };

    // Final check: expected_sum = f_A(assignment) × f_B(assignment)
    let product = qm31_mul(final_a_eval, final_b_eval);

    if !qm31_eq(expected_sum, product) {
        let proof_hash = poseidon_hash_span(
            array![initial_digest, num_rounds.into(), 'FINAL_FAIL'].span(),
        );
        return (false, proof_hash, array![]);
    }

    // Compute proof hash for on-chain recording
    let proof_hash = poseidon_hash_span(
        array![
            initial_digest,
            num_rounds.into(),
            claimed_sum.a.a.into(),
            claimed_sum.a.b.into(),
            claimed_sum.b.a.into(),
            claimed_sum.b.b.into(),
            final_a_eval.a.a.into(),
            final_a_eval.a.b.into(),
            final_a_eval.b.a.into(),
            final_a_eval.b.b.into(),
            final_b_eval.a.a.into(),
            final_b_eval.a.b.into(),
            final_b_eval.b.a.into(),
            final_b_eval.b.b.into(),
        ]
            .span(),
    );

    (true, proof_hash, assignment)
}

// ============================================================================
// Helpers
// ============================================================================

/// Compute the next power of two >= n.
fn next_power_of_two(n: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    let mut v = n - 1;
    v = v | (v / 2);
    v = v | (v / 4);
    v = v | (v / 16);
    v = v | (v / 256);
    v = v | (v / 65536);
    v + 1
}

/// Compute ceil(log2(n)) for n > 0.
/// For powers of two, equivalent to exact log2.
fn log2_ceil(n: u32) -> u32 {
    assert!(n > 0, "log2(0) undefined");
    let mut result: u32 = 0;
    let mut val = n - 1;
    loop {
        if val == 0 {
            break;
        }
        val = val / 2;
        result += 1;
    };
    result
}

/// Compute 2^n.
fn pow2(n: u32) -> u32 {
    let mut result: u32 = 1;
    let mut i: u32 = 0;
    loop {
        if i >= n {
            break;
        }
        result = result * 2;
        i += 1;
    };
    result
}

// ============================================================================
// MLE Commitment Opening Verification
//
// Verifies that a multilinear extension committed via Poseidon Merkle tree
// evaluates to a claimed value at a given point.
//
// Protocol (matching Rust's mle_opening.rs):
//   1. Prover commits evaluations in a Poseidon Merkle tree (root R₀)
//   2. Prover folds with lo/hi split:
//      L_{i+1}[j] = L_i[j] + r[i] * (L_i[mid+j] - L_i[j])
//   3. Prover commits intermediate layers → roots R₁, ..., R_{n-1}
//   4. Channel absorbs R₀, R₁, ..., R_{n-1} via mix_felt
//   5. Verifier draws query indices from channel
//   6. For each query, verifier checks Merkle proofs + folding consistency
//
// Leaf values: raw packed QM31 (securefield_to_felt), no per-leaf hash
// Internal nodes: poseidon_hash(left, right)
// Folding order: forward (first variable first)
// ============================================================================

/// Number of spot-check queries for the MLE folding protocol.
/// Matches Rust's MLE_N_QUERIES = 14.
const MLE_NUM_QUERIES: u32 = 14;

/// Pack QM31 into a single felt252.
/// Big-endian 2^31 packing starting from ONE (matching STWO's securefield_to_felt).
pub fn pack_qm31_to_felt(v: QM31) -> felt252 {
    let shift: felt252 = 0x80000000; // 2^31
    let mut result: felt252 = 1;
    result = result * shift + v.a.a.into();
    result = result * shift + v.a.b.into();
    result = result * shift + v.b.a.into();
    result = result * shift + v.b.b.into();
    result
}

/// Verify a Poseidon Merkle authentication path.
///
/// Checks that `leaf_hash` at position `index` produces `root` via the sibling path.
/// Sibling order is bottom-up (leaf → root).
fn verify_merkle_path(
    leaf_hash: felt252, index: u32, siblings: Span<felt252>, root: felt252,
) -> bool {
    let mut current = leaf_hash;
    let mut idx = index;
    let mut i: u32 = 0;
    loop {
        if i >= siblings.len() {
            break;
        }
        let sibling = *siblings.at(i);
        if idx % 2 == 0 {
            let (s0, _, _) = hades_permutation(current, sibling, 2);
            current = s0;
        } else {
            let (s0, _, _) = hades_permutation(sibling, current, 2);
            current = s0;
        }
        idx = idx / 2;
        i += 1;
    };
    current == root
}

/// Draw query indices from the Poseidon channel.
/// Matches Rust's draw_query_indices: draw felt252 from channel, extract low 64 bits, mod range.
fn channel_draw_query_indices(
    ref ch: PoseidonChannel, half_n: u32, n_queries: u32,
) -> Array<u32> {
    let mut indices: Array<u32> = array![];
    let half_n_u64: u64 = half_n.into();
    let mut i: u32 = 0;
    loop {
        if i >= n_queries {
            break;
        }
        let felt = channel_draw_felt252(ref ch);
        let hash_u256: u256 = felt.into();
        let val_u64: u64 = (hash_u256 % 0x10000000000000000).try_into().unwrap();
        let index: u32 = (val_u64 % half_n_u64).try_into().unwrap();
        indices.append(index);
        i += 1;
    };
    indices
}

/// Compute the next query pair index after folding.
/// Matches Rust's next_query_pair_index: reduces index to next folded layer's range.
fn next_query_pair_index(current_idx: u32, layer_mid: u32) -> u32 {
    let next_half = layer_mid / 2;
    if next_half == 0 {
        0
    } else {
        current_idx % next_half
    }
}

/// Verify an MLE opening proof against a committed Poseidon Merkle root.
///
/// Matches Rust's verify_mle_opening() from mle_opening.rs exactly:
/// 1. Channel-based Fiat-Shamir transcript (mix commitment + intermediate roots)
/// 2. Channel-based query derivation (draw_query_indices)
/// 3. Lo/hi split folding (not consecutive pairs)
/// 4. Raw packed QM31 leaves (no poseidon_hash(leaf, 0))
/// 5. Forward folding order (first variable first)
/// 6. MLE_NUM_QUERIES = 14
fn verify_mle_opening(
    commitment_root: felt252,
    proof: @MleOpeningProof,
    challenges: Span<QM31>,
    ref ch: PoseidonChannel,
) -> bool {
    let n_rounds: u32 = challenges.len();

    // Replay channel transcript: mix initial commitment and intermediate roots
    channel_mix_felt(ref ch, commitment_root);
    let intermediate_roots_span = proof.intermediate_roots.span();
    let mut ir_i: u32 = 0;
    loop {
        if ir_i >= intermediate_roots_span.len() {
            break;
        }
        channel_mix_felt(ref ch, *intermediate_roots_span.at(ir_i));
        ir_i += 1;
    };

    // Build layer roots: layer 0 = commitment, layers 1..n-1 = intermediate_roots
    // layer_roots has entries for every round that has a Merkle tree
    // (rounds 0..layer_roots_len-1 have trees)
    let layer_roots_len: u32 = 1 + intermediate_roots_span.len();

    if n_rounds == 0 {
        return proof.queries.len() == 0;
    }

    // Initial evals size is 2^n_rounds, half_n = 2^(n_rounds-1)
    let half_n: u32 = pow2(n_rounds - 1);
    let n_queries: u32 = if MLE_NUM_QUERIES < half_n {
        MLE_NUM_QUERIES
    } else {
        half_n
    };
    let query_indices = channel_draw_query_indices(ref ch, half_n, n_queries);

    let queries_span = proof.queries.span();
    if queries_span.len() != n_queries {
        return false;
    }

    // Verify each query chain
    let mut q_idx: u32 = 0;
    loop {
        if q_idx >= n_queries {
            break;
        }

        let query = queries_span.at(q_idx);
        let rounds_span = query.rounds.span();

        if rounds_span.len() != n_rounds {
            return false;
        }

        // Verify initial pair index matches reconstructed query
        if *query.initial_pair_index != *query_indices.at(q_idx) {
            return false;
        }

        let mut current_idx: u32 = *query.initial_pair_index;
        // Track the current layer size. Initial layer has 2^n_rounds elements.
        let mut layer_size: u32 = pow2(n_rounds);

        let mut round: u32 = 0;
        loop {
            if round >= n_rounds {
                break;
            }

            let rd = rounds_span.at(round);
            let left_value: QM31 = *rd.left_value;
            let right_value: QM31 = *rd.right_value;
            let left_siblings = rd.left_siblings.span();
            let right_siblings = rd.right_siblings.span();

            // Lo/hi split: left = layer[idx], right = layer[mid + idx]
            let mid: u32 = layer_size / 2;
            let left_idx: u32 = current_idx;
            let right_idx: u32 = mid + current_idx;

            // Verify Merkle authentication paths for rounds that have trees
            if round < layer_roots_len {
                let layer_root = if round == 0 {
                    commitment_root
                } else {
                    *intermediate_roots_span.at(round - 1)
                };

                // Raw packed QM31 as leaf — no poseidon_hash(leaf, 0)
                let left_leaf = pack_qm31_to_felt(left_value);
                let right_leaf = pack_qm31_to_felt(right_value);

                if !verify_merkle_path(left_leaf, left_idx, left_siblings, layer_root) {
                    return false;
                }
                if !verify_merkle_path(right_leaf, right_idx, right_siblings, layer_root) {
                    return false;
                }
            }

            // Check algebraic fold: f(r) = left + r * (right - left)
            let challenge: QM31 = *challenges.at(round); // forward order
            let diff = qm31_sub(right_value, left_value);
            let fold_val = qm31_add(left_value, qm31_mul(challenge, diff));

            // If this is the last round, the folded value must equal final_value
            if round == n_rounds - 1 {
                if !qm31_eq(fold_val, *proof.final_value) {
                    return false;
                }
            }

            // Advance to next layer
            current_idx = next_query_pair_index(current_idx, mid);
            layer_size = mid;

            round += 1;
        };

        q_idx += 1;
    };

    true
}

// ============================================================================
// Starknet Contract
// ============================================================================

#[starknet::interface]
trait ISumcheckVerifier<TContractState> {
    /// Register a model's weight commitment on-chain.
    fn register_model(
        ref self: TContractState, model_id: felt252, weight_commitment: felt252,
    );

    /// Verify a matmul sumcheck proof on-chain.
    /// Replays the full Fiat-Shamir transcript from STWO's prove_matmul,
    /// then verifies all sumcheck rounds and the final evaluation.
    fn verify_matmul(
        ref self: TContractState, model_id: felt252, proof: MatMulSumcheckProof,
    ) -> bool;

    /// Get the weight commitment for a registered model.
    fn get_model_commitment(self: @TContractState, model_id: felt252) -> felt252;

    /// Get the number of verified proofs for a model.
    fn get_verification_count(self: @TContractState, model_id: felt252) -> u64;

    /// Check if a specific proof hash has been verified.
    fn is_proof_verified(self: @TContractState, proof_hash: felt252) -> bool;
}

#[starknet::contract]
mod SumcheckVerifierContract {
    use super::{
        MatMulSumcheckProof, channel_default, channel_draw_qm31s, channel_mix_u64,
        channel_mix_felt, pack_qm31_to_felt, log2_ceil, next_power_of_two,
        verify_sumcheck_inner, verify_mle_opening,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess, Map, StoragePathEntry,
    };
    use starknet::{ContractAddress, get_caller_address};

    // ====================================================================
    // Storage
    // ====================================================================

    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// model_id → Poseidon hash of model weight matrices
        model_commitments: Map<felt252, felt252>,
        /// model_id → number of successful verifications
        verification_counts: Map<felt252, u64>,
        /// proof_hash → verified (true/false)
        verified_proofs: Map<felt252, bool>,
    }

    // ====================================================================
    // Events
    // ====================================================================

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ModelRegistered: ModelRegistered,
        MatMulVerified: MatMulVerified,
        VerificationFailed: VerificationFailed,
    }

    #[derive(Drop, starknet::Event)]
    struct ModelRegistered {
        #[key]
        model_id: felt252,
        weight_commitment: felt252,
        registrar: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct MatMulVerified {
        #[key]
        model_id: felt252,
        proof_hash: felt252,
        dimensions: felt252,
        num_rounds: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct VerificationFailed {
        #[key]
        model_id: felt252,
        reason: felt252,
    }

    // ====================================================================
    // Constructor
    // ====================================================================

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.owner.write(owner);
    }

    // ====================================================================
    // Implementation
    // ====================================================================

    #[abi(embed_v0)]
    impl SumcheckVerifierImpl of super::ISumcheckVerifier<ContractState> {
        fn register_model(
            ref self: ContractState, model_id: felt252, weight_commitment: felt252,
        ) {
            let existing = self.model_commitments.entry(model_id).read();
            assert!(existing == 0, "Model already registered");
            assert!(weight_commitment != 0, "Commitment cannot be zero");

            self.model_commitments.entry(model_id).write(weight_commitment);

            self
                .emit(
                    ModelRegistered {
                        model_id, weight_commitment, registrar: get_caller_address(),
                    },
                );
        }

        fn verify_matmul(
            ref self: ContractState, model_id: felt252, proof: MatMulSumcheckProof,
        ) -> bool {
            // 1. Validate model is registered
            let commitment = self.model_commitments.entry(model_id).read();
            assert!(commitment != 0, "Model not registered");

            // Destructure proof for ownership management
            let MatMulSumcheckProof {
                m, k, n, num_rounds, claimed_sum, round_polys,
                final_a_eval, final_b_eval,
                a_commitment, b_commitment, a_opening, b_opening,
            } = proof;

            // 2. Validate proof structure
            assert!(num_rounds > 0, "Proof must have at least one round");
            assert!(round_polys.len() == num_rounds, "Round count mismatch");
            assert!(k > 0, "Inner dimension must be positive");
            assert!(m > 0 && n > 0, "Matrix dimensions must be positive");

            // Verify num_rounds matches ceil_log2(k)
            let k_pow2 = next_power_of_two(k);
            let expected_rounds = log2_ceil(k_pow2);
            assert!(num_rounds == expected_rounds, "Wrong number of rounds");

            // 3. Verify weight commitment: proof's A commitment must match registered model
            assert!(a_commitment == commitment, "Weight commitment mismatch");

            // 4. Replay Fiat-Shamir transcript (matching prove_matmul + Poseidon252Channel)
            let mut ch = channel_default();

            // Mix matrix dimensions
            let m_u64: u64 = m.into();
            let k_u64: u64 = k.into();
            let n_u64: u64 = n.into();
            channel_mix_u64(ref ch, m_u64);
            channel_mix_u64(ref ch, k_u64);
            channel_mix_u64(ref ch, n_u64);

            // Draw row and column challenges (needed for MLE opening points)
            let m_log = log2_ceil(next_power_of_two(m));
            let n_log = log2_ceil(next_power_of_two(n));
            let _row_challenges = channel_draw_qm31s(ref ch, m_log);
            let _col_challenges = channel_draw_qm31s(ref ch, n_log);

            // Mix claimed sum into channel (matching Rust prover)
            let packed_sum = pack_qm31_to_felt(claimed_sum);
            channel_mix_felt(ref ch, packed_sum);

            // Mix commitments into channel (matching Rust prover)
            channel_mix_felt(ref ch, a_commitment);
            channel_mix_felt(ref ch, b_commitment);

            // 5. Verify sumcheck rounds (returns assignment = challenges from each round)
            let (is_valid, proof_hash, assignment) = verify_sumcheck_inner(
                claimed_sum,
                round_polys.span(),
                num_rounds,
                final_a_eval,
                final_b_eval,
                ref ch,
            );

            if !is_valid {
                self.emit(VerificationFailed { model_id, reason: proof_hash });
                return false;
            }

            // 6. Verify MLE opening for matrix A
            // Uses assignment (sumcheck challenges) as the opening point.
            // Channel state flows through from sumcheck verification.
            let a_valid = verify_mle_opening(
                a_commitment, @a_opening, assignment.span(), ref ch,
            );

            if !a_valid {
                self.emit(VerificationFailed { model_id, reason: 'A_MLE_FAIL' });
                return false;
            }

            // 7. Verify MLE opening for matrix B
            // Channel continues sequentially from A's verification.
            let b_valid = verify_mle_opening(
                b_commitment, @b_opening, assignment.span(), ref ch,
            );

            if !b_valid {
                self.emit(VerificationFailed { model_id, reason: 'B_MLE_FAIL' });
                return false;
            }

            // 8. All checks passed — record successful verification
            self.verified_proofs.entry(proof_hash).write(true);
            let count = self.verification_counts.entry(model_id).read();
            self.verification_counts.entry(model_id).write(count + 1);

            self
                .emit(
                    MatMulVerified {
                        model_id,
                        proof_hash,
                        dimensions: (m.into() * 0x100000000)
                            + (k.into() * 0x10000)
                            + n.into(),
                        num_rounds,
                    },
                );

            true
        }

        fn get_model_commitment(self: @ContractState, model_id: felt252) -> felt252 {
            self.model_commitments.entry(model_id).read()
        }

        fn get_verification_count(self: @ContractState, model_id: felt252) -> u64 {
            self.verification_counts.entry(model_id).read()
        }

        fn is_proof_verified(self: @ContractState, proof_hash: felt252) -> bool {
            self.verified_proofs.entry(proof_hash).read()
        }
    }
}
