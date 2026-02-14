// Cross-language test vectors for the sumcheck verifier.
//
// These tests validate that the Cairo channel implementation produces
// identical values to the Rust PoseidonChannel at each protocol step.
//
// The test values here are derived from the Rust test:
//   cargo test -p stwo-ml generate_cross_language_vectors -- --nocapture
//
// After running the Rust test, copy the printed values into the assertions below.

use core::poseidon::{poseidon_hash_span, hades_permutation};
use sage_contracts::obelysk::sumcheck_verifier::{
    PoseidonChannel, QM31, CM31,
    channel_default, channel_mix_u64, channel_mix_felt,
    channel_draw_qm31, channel_draw_qm31s,
    channel_mix_poly_coeffs, pack_qm31_to_felt,
    m31_reduce,
};

// ============================================================================
// Channel Basics
// ============================================================================

#[test]
fn test_channel_initial_state() {
    // Channel starts with digest=0, n_draws=0
    let ch = channel_default();
    assert!(ch.digest == 0, "initial digest should be 0");
    assert!(ch.n_draws == 0, "initial n_draws should be 0");
}

#[test]
fn test_channel_mix_u64_deterministic() {
    // Two channels with same operations must produce same digest
    let mut ch1 = channel_default();
    let mut ch2 = channel_default();

    channel_mix_u64(ref ch1, 42);
    channel_mix_u64(ref ch2, 42);

    assert!(ch1.digest == ch2.digest, "same mix should produce same digest");
    assert!(ch1.digest != 0, "digest should not be zero after mix");
}

#[test]
fn test_channel_draw_qm31_valid_range() {
    // All 4 M31 components of a drawn QM31 must be < 2^31 - 1
    let mut ch = channel_default();
    channel_mix_u64(ref ch, 123);

    let q = channel_draw_qm31(ref ch);
    let p: u64 = 0x7FFFFFFF; // 2^31 - 1
    assert!(q.a.a < p, "v0 out of M31 range");
    assert!(q.a.b < p, "v1 out of M31 range");
    assert!(q.b.a < p, "v2 out of M31 range");
    assert!(q.b.b < p, "v3 out of M31 range");
}

#[test]
fn test_channel_draw_qm31s_no_buffering() {
    // draw_qm31s(N) must produce the same values as N calls to draw_qm31
    let mut ch_batch = channel_default();
    channel_mix_u64(ref ch_batch, 99);

    let mut ch_single = channel_default();
    channel_mix_u64(ref ch_single, 99);

    let batch = channel_draw_qm31s(ref ch_batch, 3);

    let s0 = channel_draw_qm31(ref ch_single);
    let s1 = channel_draw_qm31(ref ch_single);
    let s2 = channel_draw_qm31(ref ch_single);

    // Each element from batch must match single draws
    let b0 = *batch.at(0);
    let b1 = *batch.at(1);
    let b2 = *batch.at(2);

    assert!(b0.a.a == s0.a.a && b0.a.b == s0.a.b && b0.b.a == s0.b.a && b0.b.b == s0.b.b,
        "batch[0] must match single draw 0");
    assert!(b1.a.a == s1.a.a && b1.a.b == s1.a.b && b1.b.a == s1.b.a && b1.b.b == s1.b.b,
        "batch[1] must match single draw 1");
    assert!(b2.a.a == s2.a.a && b2.a.b == s2.a.b && b2.b.a == s2.b.a && b2.b.b == s2.b.b,
        "batch[2] must match single draw 2");

    // Channel state must be identical after both paths
    assert!(ch_batch.digest == ch_single.digest, "digests must match");
    assert!(ch_batch.n_draws == ch_single.n_draws, "n_draws must match");
}

// ============================================================================
// Transcript Replay: Match Rust prover step by step
// ============================================================================

#[test]
fn test_transcript_dimensions_phase() {
    // Replay: mix_u64(2), mix_u64(2), mix_u64(2) for m=2, k=2, n=2
    let mut ch = channel_default();

    channel_mix_u64(ref ch, 2); // m
    let digest_m = ch.digest;
    assert!(digest_m != 0, "digest after mix(m) should be non-zero");

    channel_mix_u64(ref ch, 2); // k
    let digest_k = ch.digest;
    assert!(digest_k != digest_m, "digest should change after mix(k)");

    channel_mix_u64(ref ch, 2); // n
    let digest_n = ch.digest;
    assert!(digest_n != digest_k, "digest should change after mix(n)");
}

#[test]
fn test_transcript_challenge_draw_phase() {
    // After dimensions, draw log2(m)=1 row challenge and log2(n)=1 col challenge
    let mut ch = channel_default();
    channel_mix_u64(ref ch, 2);
    channel_mix_u64(ref ch, 2);
    channel_mix_u64(ref ch, 2);

    // Draw 1 row challenge
    let row_ch = channel_draw_qm31s(ref ch, 1);
    assert!(row_ch.len() == 1, "should draw 1 row challenge");
    let r0 = *row_ch.at(0);

    // Draw 1 col challenge
    let col_ch = channel_draw_qm31s(ref ch, 1);
    assert!(col_ch.len() == 1, "should draw 1 col challenge");
    let c0 = *col_ch.at(0);

    // Row and col challenges should differ (different n_draws values)
    assert!(
        !(r0.a.a == c0.a.a && r0.a.b == c0.a.b && r0.b.a == c0.b.a && r0.b.b == c0.b.b),
        "row and col challenges should differ"
    );
}

#[test]
fn test_mix_felt_deterministic() {
    let mut ch1 = channel_default();
    let mut ch2 = channel_default();

    // Mix a known felt value
    let val: felt252 = 0x12345678;
    channel_mix_felt(ref ch1, val);
    channel_mix_felt(ref ch2, val);

    assert!(ch1.digest == ch2.digest, "same mix_felt should produce same digest");
    assert!(ch1.n_draws == 0, "n_draws should reset to 0 after mix");
}

#[test]
fn test_pack_qm31_to_felt() {
    // Pack QM31(CM31(1, 2), CM31(3, 4)) into felt252
    // Expected: 1 * (2^31)^4 + 1 * (2^31)^3 + 2 * (2^31)^2 + 3 * (2^31) + 4
    // The sentinel 1 at the start distinguishes from leading zeros.
    let v = QM31 {
        a: CM31 { a: 1, b: 2 },
        b: CM31 { a: 3, b: 4 },
    };
    let packed = pack_qm31_to_felt(v);
    assert!(packed != 0, "packed value should be non-zero");

    // Verify round-trip: pack and check components can be extracted
    // (packing is big-endian: result = 1 * 2^124 + 1*2^93 + 2*2^62 + 3*2^31 + 4)
    let packed_u256: u256 = packed.into();
    let shift: u256 = 0x80000000; // 2^31

    let v3: u64 = (packed_u256 % shift).try_into().unwrap();
    let rem1 = packed_u256 / shift;
    let v2: u64 = (rem1 % shift).try_into().unwrap();
    let rem2 = rem1 / shift;
    let v1: u64 = (rem2 % shift).try_into().unwrap();
    let rem3 = rem2 / shift;
    let v0: u64 = (rem3 % shift).try_into().unwrap();

    assert!(v0 == 1, "component 0 should be 1");
    assert!(v1 == 2, "component 1 should be 2");
    assert!(v2 == 3, "component 2 should be 3");
    assert!(v3 == 4, "component 3 should be 4");
}

// ============================================================================
// Full Protocol Replay (without proof data — just channel alignment)
// ============================================================================

#[test]
fn test_full_channel_replay_2x2() {
    // Replays the exact same PoseidonChannel sequence as the Rust prover
    // for a 2×2 matmul (m=2, k=2, n=2, log_m=1, log_k=1, log_n=1).
    //
    // Steps:
    //   1. mix_u64(2), mix_u64(2), mix_u64(2)
    //   2. draw_qm31() × 1 (row challenges)
    //   3. draw_qm31() × 1 (col challenges)
    //   4. mix_felt(packed_claimed_sum)  — would need actual value from Rust
    //   5. mix_felt(a_commitment)        — would need actual value from Rust
    //   6. mix_felt(b_commitment)        — would need actual value from Rust
    //
    // This test only validates the channel up to step 3 (deterministic part).

    let mut ch = channel_default();
    channel_mix_u64(ref ch, 2);
    channel_mix_u64(ref ch, 2);
    channel_mix_u64(ref ch, 2);

    let row_challenges = channel_draw_qm31s(ref ch, 1);
    let col_challenges = channel_draw_qm31s(ref ch, 1);

    // Validate that we got challenges with valid M31 components
    let r = *row_challenges.at(0);
    let c = *col_challenges.at(0);
    let p: u64 = 0x7FFFFFFF;

    assert!(r.a.a < p && r.a.b < p && r.b.a < p && r.b.b < p,
        "row challenge components must be valid M31");
    assert!(c.a.a < p && c.a.b < p && c.b.a < p && c.b.b < p,
        "col challenge components must be valid M31");

    // The channel digest at this point is deterministic and must match
    // the Rust PoseidonChannel's digest after the same operations.
    // To fill in the exact value, run the Rust test and copy it here:
    // assert!(ch.digest == EXPECTED_DIGEST_FROM_RUST, "digest mismatch");
}

// ============================================================================
// Poly Coefficient Mixing
// ============================================================================

#[test]
fn test_mix_poly_coeffs_deterministic() {
    let c0 = QM31 { a: CM31 { a: 1, b: 2 }, b: CM31 { a: 3, b: 4 } };
    let c1 = QM31 { a: CM31 { a: 5, b: 6 }, b: CM31 { a: 7, b: 8 } };
    let c2 = QM31 { a: CM31 { a: 9, b: 10 }, b: CM31 { a: 11, b: 12 } };

    let mut ch1 = channel_default();
    let mut ch2 = channel_default();

    channel_mix_poly_coeffs(ref ch1, c0, c1, c2);
    channel_mix_poly_coeffs(ref ch2, c0, c1, c2);

    assert!(ch1.digest == ch2.digest, "same poly coeffs should produce same digest");
    assert!(ch1.n_draws == 0, "n_draws should reset after mix_poly_coeffs");
}
