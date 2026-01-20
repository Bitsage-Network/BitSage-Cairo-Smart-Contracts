// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// LeanIMT Integration Tests
// Tests for Lean Incremental Merkle Tree implementation including:
// - Module-level helper function tests
// - Depth calculation verification
// - Proof generation and verification
// - Batch operations

use core::array::ArrayTrait;

// Import LeanIMT types and functions from the module
use sage_contracts::obelysk::lean_imt::{
    LeanIMTState, LeanIMTProof, LeanIMTBatchResult,
    LEAN_IMT_MAX_DEPTH, LEAN_IMT_DOMAIN,
    calculate_depth, needs_depth_increase, hash_pair, verify_proof,
    get_sibling_index, get_parent_index, is_left_child, is_right_child,
    max_leaves_for_depth, get_path_indices, compute_root_from_proof,
    empty_root, is_empty_root,
};

// =============================================================================
// State and Proof Structure Tests
// =============================================================================

#[test]
fn test_lean_imt_state_initial() {
    let state = LeanIMTState {
        root: 0,
        size: 0,
        depth: 0,
    };

    assert!(state.root == 0, "Initial root should be 0");
    assert!(state.size == 0, "Initial size should be 0");
    assert!(state.depth == 0, "Initial depth should be 0");
}

#[test]
fn test_lean_imt_state_after_insert() {
    // Simulate state after one insertion
    let leaf_hash = hash_pair(12345, 0); // Simplified
    let state = LeanIMTState {
        root: leaf_hash,
        size: 1,
        depth: 1,
    };

    assert!(state.size == 1, "Size should be 1");
    assert!(state.depth == 1, "Depth should be 1");
    assert!(state.root != 0, "Root should not be zero");
}

#[test]
fn test_lean_imt_proof_single_leaf() {
    // Single leaf tree: leaf is root, no siblings needed
    let leaf = 12345;
    let proof = LeanIMTProof {
        siblings: array![],
        path_indices: array![],
        leaf,
        root: leaf, // In single-leaf tree, leaf is root
        tree_size: 1,
    };

    assert!(proof.siblings.len() == 0, "Should have no siblings");
    assert!(proof.path_indices.len() == 0, "Should have no indices");
    assert!(proof.leaf == proof.root, "Leaf should equal root");
    assert!(proof.tree_size == 1, "Tree size should be 1");
}

// =============================================================================
// Depth Calculation Comprehensive Tests
// =============================================================================

#[test]
fn test_depth_boundary_powers_of_two() {
    // Test at powers of 2 boundaries
    assert!(calculate_depth(1) == 1, "2^0 = 1 leaf -> depth 1");
    assert!(calculate_depth(2) == 1, "2^1 = 2 leaves -> depth 1");
    assert!(calculate_depth(4) == 2, "2^2 = 4 leaves -> depth 2");
    assert!(calculate_depth(8) == 3, "2^3 = 8 leaves -> depth 3");
    assert!(calculate_depth(16) == 4, "2^4 = 16 leaves -> depth 4");
    assert!(calculate_depth(32) == 5, "2^5 = 32 leaves -> depth 5");
    assert!(calculate_depth(64) == 6, "2^6 = 64 leaves -> depth 6");
    assert!(calculate_depth(128) == 7, "2^7 = 128 leaves -> depth 7");
    assert!(calculate_depth(256) == 8, "2^8 = 256 leaves -> depth 8");
}

#[test]
fn test_depth_just_over_power_of_two() {
    // Just over each power of 2 should increase depth
    assert!(calculate_depth(3) == 2, "3 leaves -> depth 2");
    assert!(calculate_depth(5) == 3, "5 leaves -> depth 3");
    assert!(calculate_depth(9) == 4, "9 leaves -> depth 4");
    assert!(calculate_depth(17) == 5, "17 leaves -> depth 5");
    assert!(calculate_depth(33) == 6, "33 leaves -> depth 6");
    assert!(calculate_depth(65) == 7, "65 leaves -> depth 7");
    assert!(calculate_depth(129) == 8, "129 leaves -> depth 8");
}

#[test]
fn test_depth_large_values() {
    // Test larger values
    assert!(calculate_depth(1000) == 10, "1000 leaves");
    assert!(calculate_depth(1024) == 10, "1024 = 2^10 leaves");
    assert!(calculate_depth(1025) == 11, "1025 leaves");
    assert!(calculate_depth(10000) == 14, "10000 leaves");
    assert!(calculate_depth(100000) == 17, "100000 leaves");
    assert!(calculate_depth(1000000) == 20, "1000000 leaves");
}

// =============================================================================
// Needs Depth Increase Tests
// =============================================================================

#[test]
fn test_needs_depth_increase_transitions() {
    // Depth should increase when size exceeds power of 2
    assert!(needs_depth_increase(0), "0 -> 1 increases (depth 0->1)");
    assert!(!needs_depth_increase(1), "1 -> 2 doesn't increase (both depth 1)");
    assert!(needs_depth_increase(2), "2 -> 3 increases (depth 1->2)");
    assert!(!needs_depth_increase(3), "3 -> 4 doesn't increase (both depth 2)");
    assert!(needs_depth_increase(4), "4 -> 5 increases (depth 2->3)");
    assert!(!needs_depth_increase(5), "5 -> 6 doesn't increase");
    assert!(!needs_depth_increase(6), "6 -> 7 doesn't increase");
    assert!(!needs_depth_increase(7), "7 -> 8 doesn't increase");
    assert!(needs_depth_increase(8), "8 -> 9 increases (depth 3->4)");
}

#[test]
fn test_needs_depth_increase_larger() {
    assert!(needs_depth_increase(16), "16 -> 17 increases");
    assert!(!needs_depth_increase(17), "17 -> 18 doesn't");
    assert!(needs_depth_increase(32), "32 -> 33 increases");
    assert!(needs_depth_increase(64), "64 -> 65 increases");
    assert!(needs_depth_increase(128), "128 -> 129 increases");
}

// =============================================================================
// Hash Function Tests
// =============================================================================

#[test]
fn test_hash_pair_consistency() {
    let h1 = hash_pair(100, 200);
    let h2 = hash_pair(100, 200);
    assert!(h1 == h2, "Same inputs should produce same hash");
}

#[test]
fn test_hash_pair_different_inputs() {
    let h1 = hash_pair(100, 200);
    let h2 = hash_pair(200, 100);
    let h3 = hash_pair(100, 201);

    assert!(h1 != h2, "Order should matter");
    assert!(h1 != h3, "Different values should produce different hash");
    assert!(h2 != h3, "All hashes should be different");
}

#[test]
fn test_hash_pair_non_zero() {
    let h = hash_pair(0, 0);
    // Even (0,0) should produce a non-zero hash due to domain separator
    assert!(h != 0, "Hash should not be zero");
}

// =============================================================================
// Tree Navigation Helper Tests
// =============================================================================

#[test]
fn test_sibling_index_even_odd() {
    assert!(get_sibling_index(0) == 1, "Sibling of 0 is 1");
    assert!(get_sibling_index(1) == 0, "Sibling of 1 is 0");
    assert!(get_sibling_index(2) == 3, "Sibling of 2 is 3");
    assert!(get_sibling_index(3) == 2, "Sibling of 3 is 2");
    assert!(get_sibling_index(100) == 101, "Sibling of 100 is 101");
    assert!(get_sibling_index(101) == 100, "Sibling of 101 is 100");
}

#[test]
fn test_parent_index_formula() {
    assert!(get_parent_index(0) == 0, "Parent of 0 is 0");
    assert!(get_parent_index(1) == 0, "Parent of 1 is 0");
    assert!(get_parent_index(2) == 1, "Parent of 2 is 1");
    assert!(get_parent_index(3) == 1, "Parent of 3 is 1");
    assert!(get_parent_index(4) == 2, "Parent of 4 is 2");
    assert!(get_parent_index(5) == 2, "Parent of 5 is 2");
}

#[test]
fn test_is_left_right_child_consistency() {
    // Every index is either left or right, not both
    let mut i: u64 = 0;
    loop {
        if i > 20 {
            break;
        }
        let is_left = is_left_child(i);
        let is_right = is_right_child(i);
        assert!(is_left != is_right, "Must be exactly one");
        i += 1;
    };
}

// =============================================================================
// Max Leaves Tests
// =============================================================================

#[test]
fn test_max_leaves_values() {
    assert!(max_leaves_for_depth(0) == 0, "Depth 0 = 0 leaves");
    assert!(max_leaves_for_depth(1) == 2, "Depth 1 = 2 leaves");
    assert!(max_leaves_for_depth(2) == 4, "Depth 2 = 4 leaves");
    assert!(max_leaves_for_depth(3) == 8, "Depth 3 = 8 leaves");
    assert!(max_leaves_for_depth(10) == 1024, "Depth 10 = 1024 leaves");
    assert!(max_leaves_for_depth(20) == 1048576, "Depth 20 = ~1M leaves");
}

// =============================================================================
// Path Indices Tests
// =============================================================================

#[test]
fn test_get_path_indices_index_0() {
    let indices = get_path_indices(0, 3);
    assert!(indices.len() == 3, "Should have 3 indices");
    assert!(*indices.at(0) == false, "Level 0: left");
    assert!(*indices.at(1) == false, "Level 1: left");
    assert!(*indices.at(2) == false, "Level 2: left");
}

#[test]
fn test_get_path_indices_index_7() {
    let indices = get_path_indices(7, 3);
    assert!(indices.len() == 3, "Should have 3 indices");
    // 7 in binary is 111 (from LSB to MSB: right, right, right)
    assert!(*indices.at(0) == true, "Level 0: right (7 % 2 = 1)");
    assert!(*indices.at(1) == true, "Level 1: right (3 % 2 = 1)");
    assert!(*indices.at(2) == true, "Level 2: right (1 % 2 = 1)");
}

#[test]
fn test_get_path_indices_index_5() {
    let indices = get_path_indices(5, 3);
    // 5 in binary is 101 (from LSB: right, left, right)
    assert!(*indices.at(0) == true, "Level 0: right");
    assert!(*indices.at(1) == false, "Level 1: left");
    assert!(*indices.at(2) == true, "Level 2: right");
}

// =============================================================================
// Proof Verification Tests
// =============================================================================

#[test]
fn test_verify_proof_single_leaf() {
    let leaf = 12345;
    let proof = LeanIMTProof {
        siblings: array![],
        path_indices: array![],
        leaf,
        root: leaf,
        tree_size: 1,
    };

    assert!(verify_proof(@proof), "Single leaf proof should verify");
}

#[test]
fn test_verify_proof_two_leaves_left() {
    let left_leaf = 111;
    let right_leaf = 222;
    let root = hash_pair(left_leaf, right_leaf);

    // Proof for left leaf (index 0)
    let proof = LeanIMTProof {
        siblings: array![right_leaf],
        path_indices: array![false], // Left child
        leaf: left_leaf,
        root,
        tree_size: 2,
    };

    assert!(verify_proof(@proof), "Left leaf proof should verify");
}

#[test]
fn test_verify_proof_two_leaves_right() {
    let left_leaf = 111;
    let right_leaf = 222;
    let root = hash_pair(left_leaf, right_leaf);

    // Proof for right leaf (index 1)
    let proof = LeanIMTProof {
        siblings: array![left_leaf],
        path_indices: array![true], // Right child
        leaf: right_leaf,
        root,
        tree_size: 2,
    };

    assert!(verify_proof(@proof), "Right leaf proof should verify");
}

#[test]
fn test_verify_proof_wrong_root_fails() {
    let left_leaf = 111;
    let right_leaf = 222;
    let correct_root = hash_pair(left_leaf, right_leaf);
    let wrong_root = hash_pair(333, 444);

    let proof = LeanIMTProof {
        siblings: array![right_leaf],
        path_indices: array![false],
        leaf: left_leaf,
        root: wrong_root,
        tree_size: 2,
    };

    assert!(!verify_proof(@proof), "Wrong root should fail");
}

#[test]
fn test_verify_proof_wrong_sibling_fails() {
    let left_leaf = 111;
    let right_leaf = 222;
    let root = hash_pair(left_leaf, right_leaf);

    let proof = LeanIMTProof {
        siblings: array![999], // Wrong sibling
        path_indices: array![false],
        leaf: left_leaf,
        root,
        tree_size: 2,
    };

    assert!(!verify_proof(@proof), "Wrong sibling should fail");
}

#[test]
fn test_verify_proof_mismatched_lengths_fails() {
    let proof = LeanIMTProof {
        siblings: array![1, 2, 3],
        path_indices: array![false, true], // Different length!
        leaf: 100,
        root: 999,
        tree_size: 8,
    };

    assert!(!verify_proof(@proof), "Mismatched lengths should fail");
}

// =============================================================================
// Empty Root Tests
// =============================================================================

#[test]
fn test_empty_root_is_zero() {
    assert!(empty_root() == 0, "Empty root should be 0");
}

#[test]
fn test_is_empty_root_detection() {
    assert!(is_empty_root(0), "0 is empty root");
    assert!(!is_empty_root(1), "1 is not empty root");
    assert!(!is_empty_root(hash_pair(1, 2)), "Hash is not empty root");
}

// =============================================================================
// Compute Root From Proof Tests
// =============================================================================

#[test]
fn test_compute_root_single_leaf() {
    let leaf = 12345;
    let siblings: Array<felt252> = array![];
    let path_indices: Array<bool> = array![];

    let computed = compute_root_from_proof(leaf, siblings.span(), path_indices.span());
    assert!(computed == leaf, "Single leaf is its own root");
}

#[test]
fn test_compute_root_two_leaves() {
    let left = 100;
    let right = 200;
    let expected_root = hash_pair(left, right);

    // From left leaf
    let computed_from_left = compute_root_from_proof(
        left,
        array![right].span(),
        array![false].span()
    );
    assert!(computed_from_left == expected_root, "Root from left");

    // From right leaf
    let computed_from_right = compute_root_from_proof(
        right,
        array![left].span(),
        array![true].span()
    );
    assert!(computed_from_right == expected_root, "Root from right");
}

#[test]
fn test_compute_root_four_leaves() {
    // Build a 4-leaf tree:
    //          root
    //         /    \
    //       h01     h23
    //      /   \   /   \
    //     0    1  2     3

    let leaf0 = 10;
    let leaf1 = 20;
    let leaf2 = 30;
    let leaf3 = 40;

    let h01 = hash_pair(leaf0, leaf1);
    let h23 = hash_pair(leaf2, leaf3);
    let root = hash_pair(h01, h23);

    // Verify from leaf0 (index 0: left, left)
    let computed = compute_root_from_proof(
        leaf0,
        array![leaf1, h23].span(),
        array![false, false].span()
    );
    assert!(computed == root, "Root from leaf0");

    // Verify from leaf3 (index 3: right, right)
    let computed3 = compute_root_from_proof(
        leaf3,
        array![leaf2, h01].span(),
        array![true, true].span()
    );
    assert!(computed3 == root, "Root from leaf3");
}

// =============================================================================
// Constants Tests
// =============================================================================

#[test]
fn test_lean_imt_max_depth_value() {
    assert!(LEAN_IMT_MAX_DEPTH == 32, "Max depth should be 32");
}

#[test]
fn test_lean_imt_domain_non_zero() {
    assert!(LEAN_IMT_DOMAIN != 0, "Domain separator should not be zero");
}

// =============================================================================
// Batch Result Structure Tests
// =============================================================================

#[test]
fn test_batch_result_structure() {
    let result = LeanIMTBatchResult {
        new_root: 12345,
        new_size: 100,
        new_depth: 7,
        start_index: 90,
        inserted_count: 10,
    };

    assert!(result.new_root == 12345, "Root field");
    assert!(result.new_size == 100, "Size field");
    assert!(result.new_depth == 7, "Depth field");
    assert!(result.start_index == 90, "Start index field");
    assert!(result.inserted_count == 10, "Count field");
}
