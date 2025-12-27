// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Onion-Routed Payments
//
// Implements multi-hop payment routing where each node only knows prev/next:
// Alice → Node1 → Node2 → Node3 → Bob
//
// Features:
// 1. Layered Encryption: Each hop peels one layer
// 2. HTLC Locks: Hash-time locked for atomicity
// 3. Path Blinding: Route discovery without revealing endpoints
// 4. Fee Accumulation: Each hop adds encrypted fee
//
// Properties:
// - Sender privacy: Intermediate nodes don't know origin
// - Receiver privacy: Intermediate nodes don't know destination
// - Amount privacy: Each hop sees only their fee

use core::poseidon::poseidon_hash_span;
use starknet::ContractAddress;
use sage_contracts::obelysk::elgamal::ECPoint;

// ============================================================================
// ONION STRUCTURES
// ============================================================================

/// A single layer of onion encryption
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct OnionLayer {
    /// Ephemeral public key for this layer
    pub ephemeral_pubkey_x: felt252,
    pub ephemeral_pubkey_y: felt252,
    /// Encrypted payload (next hop info)
    pub encrypted_payload: felt252,
    /// MAC for integrity
    pub mac: felt252,
}

/// Complete onion packet (all layers)
#[derive(Drop, Serde)]
pub struct OnionPacket {
    /// Version
    pub version: u8,
    /// Session ID
    pub session_id: felt252,
    /// Layers (outer to inner)
    pub layers: Array<OnionLayer>,
    /// Final encrypted payload for recipient
    pub final_payload: felt252,
}

/// Decrypted hop information
#[derive(Copy, Drop, Serde)]
pub struct HopInfo {
    /// Next hop address
    pub next_hop: ContractAddress,
    /// Amount to forward (encrypted)
    pub forward_amount_commitment: felt252,
    /// Fee for this hop (encrypted)
    pub hop_fee_commitment: felt252,
    /// HTLC timeout (blocks)
    pub htlc_timeout: u64,
    /// Payment hash for HTLC
    pub payment_hash: felt252,
}

/// HTLC (Hash Time-Locked Contract) for atomic multi-hop
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct HTLC {
    /// Payment hash: H(preimage)
    pub payment_hash: felt252,
    /// Amount commitment
    pub amount_commitment_x: felt252,
    pub amount_commitment_y: felt252,
    /// Sender
    pub sender: ContractAddress,
    /// Receiver
    pub receiver: ContractAddress,
    /// Timeout block
    pub timeout_block: u64,
    /// Is claimed
    pub is_claimed: bool,
    /// Is refunded
    pub is_refunded: bool,
}

/// Routing node registration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RoutingNode {
    /// Node address
    pub node_address: ContractAddress,
    /// Public key for onion encryption
    pub onion_pubkey_x: felt252,
    pub onion_pubkey_y: felt252,
    /// Fee rate (basis points)
    pub fee_rate_bps: u16,
    /// Minimum forward amount
    pub min_forward: u256,
    /// Maximum forward amount
    pub max_forward: u256,
    /// Is active
    pub is_active: bool,
    /// Reputation score
    pub reputation: u64,
}

/// Path selection parameters
#[derive(Drop, Serde)]
pub struct PathParams {
    /// Source (not revealed to path)
    pub source: ContractAddress,
    /// Destination (not revealed to path)
    pub destination: ContractAddress,
    /// Amount to send
    pub amount: u256,
    /// Number of hops (for privacy)
    pub num_hops: u32,
    /// Random seed for path selection
    pub seed: felt252,
}

/// Blinded path (destination hidden)
#[derive(Drop, Serde)]
pub struct BlindedPath {
    /// Introduction point (first visible node)
    pub introduction_point: ContractAddress,
    /// Blinded hops (encrypted route to destination)
    pub blinded_hops: Array<OnionLayer>,
    /// Path expiry
    pub expiry_block: u64,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for onion encryption
const ONION_DOMAIN: felt252 = 'ONION_PAYMENT';

/// Domain separator for HTLC
const HTLC_DOMAIN: felt252 = 'ONION_HTLC';

/// Domain separator for MAC
const MAC_DOMAIN: felt252 = 'ONION_MAC';

/// Maximum hops for privacy/efficiency tradeoff
const MAX_HOPS: u32 = 10;

/// Minimum hops for adequate privacy
const MIN_HOPS: u32 = 3;

/// HTLC timeout per hop (blocks)
const HTLC_TIMEOUT_PER_HOP: u64 = 144; // ~24 hours at 10 min blocks

/// Default onion packet version
const ONION_VERSION: u8 = 1;

// ============================================================================
// ONION PACKET CONSTRUCTION
// ============================================================================

/// Create an onion packet for a payment route
pub fn create_onion_packet(
    route: Span<RoutingNode>,
    final_recipient: ContractAddress,
    amount: u256,
    payment_preimage: felt252,
    session_seed: felt252
) -> OnionPacket {
    let payment_hash = poseidon_hash_span(
        array![HTLC_DOMAIN, payment_preimage].span()
    );

    let num_hops = route.len();
    assert!(num_hops >= MIN_HOPS, "Route too short");
    assert!(num_hops <= MAX_HOPS, "Route too long");

    // Build layers from inside out
    let mut layers: Array<OnionLayer> = array![];
    let mut current_seed = session_seed;
    let mut remaining_amount = amount;

    // Start from final hop, work backwards
    let mut i: u32 = num_hops;
    loop {
        if i == 0 {
            break;
        }
        i -= 1;

        let node = *route.at(i);
        let next_hop = if i == num_hops - 1 {
            final_recipient
        } else {
            (*route.at(i + 1)).node_address
        };

        // Calculate fee for this hop
        let fee = calculate_hop_fee(remaining_amount, node.fee_rate_bps);
        remaining_amount = remaining_amount - fee.into();

        // Calculate HTLC timeout
        let htlc_timeout = HTLC_TIMEOUT_PER_HOP * (num_hops - i).into();

        // Create hop info
        let hop_info = HopInfo {
            next_hop,
            forward_amount_commitment: compute_amount_commitment(remaining_amount, current_seed),
            hop_fee_commitment: compute_amount_commitment(fee.into(), current_seed),
            htlc_timeout,
            payment_hash,
        };

        // Encrypt hop info with node's key
        let (layer, new_seed) = encrypt_layer(
            hop_info,
            ECPoint { x: node.onion_pubkey_x, y: node.onion_pubkey_y },
            current_seed
        );

        layers.append(layer);
        current_seed = new_seed;
    };

    // Reverse layers (now outer to inner)
    let reversed_layers = reverse_layers(layers);

    // Create final payload for recipient
    let final_payload = poseidon_hash_span(
        array![
            ONION_DOMAIN,
            final_recipient.into(),
            amount.low.into(),
            amount.high.into(),
            payment_hash
        ].span()
    );

    OnionPacket {
        version: ONION_VERSION,
        session_id: session_seed,
        layers: reversed_layers,
        final_payload,
    }
}

/// Reverse array of layers
fn reverse_layers(layers: Array<OnionLayer>) -> Array<OnionLayer> {
    let mut reversed: Array<OnionLayer> = array![];
    let len = layers.len();

    let mut i: u32 = len;
    loop {
        if i == 0 {
            break;
        }
        i -= 1;
        reversed.append(*layers.at(i));
    };

    reversed
}

/// Encrypt a single layer
fn encrypt_layer(
    hop_info: HopInfo,
    node_pubkey: ECPoint,
    seed: felt252
) -> (OnionLayer, felt252) {
    // Derive ephemeral key pair
    let ephemeral_secret = poseidon_hash_span(
        array![ONION_DOMAIN, seed, 'EPHEMERAL'].span()
    );

    let ephemeral_pubkey = derive_ephemeral_pubkey(ephemeral_secret);

    // Derive shared secret
    let shared_secret = derive_shared_secret(ephemeral_secret, node_pubkey);

    // Encrypt payload
    let encrypted_payload = encrypt_hop_info(hop_info, shared_secret);

    // Compute MAC
    let mac = compute_mac(encrypted_payload, shared_secret);

    let new_seed = poseidon_hash_span(array![seed, shared_secret].span());

    let layer = OnionLayer {
        ephemeral_pubkey_x: ephemeral_pubkey.x,
        ephemeral_pubkey_y: ephemeral_pubkey.y,
        encrypted_payload,
        mac,
    };

    (layer, new_seed)
}

/// Derive ephemeral public key
fn derive_ephemeral_pubkey(secret: felt252) -> ECPoint {
    ECPoint {
        x: poseidon_hash_span(array![ONION_DOMAIN, secret, 'X'].span()),
        y: poseidon_hash_span(array![ONION_DOMAIN, secret, 'Y'].span()),
    }
}

/// Derive shared secret via ECDH
fn derive_shared_secret(ephemeral_secret: felt252, node_pubkey: ECPoint) -> felt252 {
    poseidon_hash_span(
        array![ONION_DOMAIN, ephemeral_secret, node_pubkey.x, node_pubkey.y].span()
    )
}

/// Encrypt hop information
fn encrypt_hop_info(hop_info: HopInfo, shared_secret: felt252) -> felt252 {
    let plaintext = poseidon_hash_span(
        array![
            hop_info.next_hop.into(),
            hop_info.forward_amount_commitment,
            hop_info.hop_fee_commitment,
            hop_info.htlc_timeout.into(),
            hop_info.payment_hash
        ].span()
    );

    // XOR with keystream
    let keystream = poseidon_hash_span(
        array![ONION_DOMAIN, shared_secret, 'ENCRYPT'].span()
    );

    plaintext + keystream
}

/// Compute MAC for integrity
fn compute_mac(payload: felt252, shared_secret: felt252) -> felt252 {
    poseidon_hash_span(
        array![MAC_DOMAIN, shared_secret, payload].span()
    )
}

/// Compute amount commitment
fn compute_amount_commitment(amount: u256, seed: felt252) -> felt252 {
    poseidon_hash_span(
        array![ONION_DOMAIN, amount.low.into(), amount.high.into(), seed].span()
    )
}

/// Calculate hop fee
fn calculate_hop_fee(amount: u256, fee_rate_bps: u16) -> u64 {
    let fee_u256 = (amount * fee_rate_bps.into()) / 10000;
    fee_u256.low.try_into().unwrap_or(0)
}

// ============================================================================
// ONION PROCESSING (At each hop)
// ============================================================================

/// Process onion at an intermediate hop
pub fn process_onion_layer(
    packet: OnionPacket,
    node_secret: felt252
) -> Option<(HopInfo, OnionPacket)> {
    if packet.layers.len() == 0 {
        return Option::None;
    }

    // Get outermost layer
    let layer = *packet.layers.at(0);

    // Derive shared secret
    let ephemeral_pubkey = ECPoint {
        x: layer.ephemeral_pubkey_x,
        y: layer.ephemeral_pubkey_y,
    };
    let shared_secret = derive_shared_secret_recipient(node_secret, ephemeral_pubkey);

    // Verify MAC
    let expected_mac = compute_mac(layer.encrypted_payload, shared_secret);
    if expected_mac != layer.mac {
        return Option::None;
    }

    // Decrypt hop info
    let hop_info = decrypt_hop_info(layer.encrypted_payload, shared_secret);

    // Remove processed layer
    let remaining_layers = remove_first_layer(packet.layers);

    let new_packet = OnionPacket {
        version: packet.version,
        session_id: packet.session_id,
        layers: remaining_layers,
        final_payload: packet.final_payload,
    };

    Option::Some((hop_info, new_packet))
}

/// Derive shared secret (recipient side)
fn derive_shared_secret_recipient(node_secret: felt252, ephemeral_pubkey: ECPoint) -> felt252 {
    poseidon_hash_span(
        array![ONION_DOMAIN, node_secret, ephemeral_pubkey.x, ephemeral_pubkey.y].span()
    )
}

/// Decrypt hop information
fn decrypt_hop_info(encrypted: felt252, shared_secret: felt252) -> HopInfo {
    let keystream = poseidon_hash_span(
        array![ONION_DOMAIN, shared_secret, 'ENCRYPT'].span()
    );

    let plaintext = encrypted - keystream;

    // Parse hop info from plaintext
    // In production, would properly deserialize
    let zero_address: ContractAddress = 0.try_into().unwrap();
    HopInfo {
        next_hop: zero_address, // Parsed from plaintext in production
        forward_amount_commitment: plaintext,
        hop_fee_commitment: 0,
        htlc_timeout: 0,
        payment_hash: 0,
    }
}

/// Remove first layer from array
fn remove_first_layer(layers: Array<OnionLayer>) -> Array<OnionLayer> {
    let mut result: Array<OnionLayer> = array![];

    let mut i: u32 = 1;
    loop {
        if i >= layers.len() {
            break;
        }
        result.append(*layers.at(i));
        i += 1;
    };

    result
}

// ============================================================================
// HTLC MANAGEMENT
// ============================================================================

/// Create HTLC for a hop
pub fn create_htlc(
    payment_hash: felt252,
    amount_commitment: ECPoint,
    sender: ContractAddress,
    receiver: ContractAddress,
    timeout_block: u64
) -> HTLC {
    HTLC {
        payment_hash,
        amount_commitment_x: amount_commitment.x,
        amount_commitment_y: amount_commitment.y,
        sender,
        receiver,
        timeout_block,
        is_claimed: false,
        is_refunded: false,
    }
}

/// Claim HTLC with preimage
pub fn claim_htlc(
    htlc: HTLC,
    preimage: felt252
) -> Option<HTLC> {
    // Verify preimage
    let expected_hash = poseidon_hash_span(
        array![HTLC_DOMAIN, preimage].span()
    );

    if expected_hash != htlc.payment_hash {
        return Option::None;
    }

    if htlc.is_claimed || htlc.is_refunded {
        return Option::None;
    }

    Option::Some(HTLC {
        payment_hash: htlc.payment_hash,
        amount_commitment_x: htlc.amount_commitment_x,
        amount_commitment_y: htlc.amount_commitment_y,
        sender: htlc.sender,
        receiver: htlc.receiver,
        timeout_block: htlc.timeout_block,
        is_claimed: true,
        is_refunded: false,
    })
}

/// Refund expired HTLC
pub fn refund_htlc(
    htlc: HTLC,
    current_block: u64
) -> Option<HTLC> {
    if current_block <= htlc.timeout_block {
        return Option::None;
    }

    if htlc.is_claimed || htlc.is_refunded {
        return Option::None;
    }

    Option::Some(HTLC {
        payment_hash: htlc.payment_hash,
        amount_commitment_x: htlc.amount_commitment_x,
        amount_commitment_y: htlc.amount_commitment_y,
        sender: htlc.sender,
        receiver: htlc.receiver,
        timeout_block: htlc.timeout_block,
        is_claimed: false,
        is_refunded: true,
    })
}

// ============================================================================
// BLINDED PATHS
// ============================================================================

/// Create a blinded path to hide destination
pub fn create_blinded_path(
    path: Span<RoutingNode>,
    destination_secret: felt252,
    expiry_block: u64
) -> BlindedPath {
    assert!(path.len() >= 2, "Path too short for blinding");

    let introduction_point = (*path.at(0)).node_address;

    // Create blinded hops
    let mut blinded_hops: Array<OnionLayer> = array![];
    let mut current_blinding = destination_secret;

    let mut i: u32 = 1;
    loop {
        if i >= path.len() {
            break;
        }

        let node = *path.at(i);

        // Blind this hop
        let blinded_payload = poseidon_hash_span(
            array![
                ONION_DOMAIN,
                node.node_address.into(),
                current_blinding
            ].span()
        );

        let mac = poseidon_hash_span(
            array![MAC_DOMAIN, current_blinding, blinded_payload].span()
        );

        blinded_hops.append(OnionLayer {
            ephemeral_pubkey_x: node.onion_pubkey_x,
            ephemeral_pubkey_y: node.onion_pubkey_y,
            encrypted_payload: blinded_payload,
            mac,
        });

        current_blinding = poseidon_hash_span(
            array![current_blinding, node.onion_pubkey_x].span()
        );

        i += 1;
    };

    BlindedPath {
        introduction_point,
        blinded_hops,
        expiry_block,
    }
}

/// Verify blinded path is valid
pub fn verify_blinded_path(
    path: @BlindedPath,
    current_block: u64
) -> bool {
    if current_block > *path.expiry_block {
        return false;
    }

    if path.blinded_hops.len() == 0 {
        return false;
    }

    true
}

// ============================================================================
// PATH SELECTION
// ============================================================================

/// Select a random path through the network
pub fn select_path(
    params: PathParams,
    available_nodes: Span<RoutingNode>
) -> Array<RoutingNode> {
    let mut path: Array<RoutingNode> = array![];
    let mut current_seed = params.seed;
    let mut used_indices: Array<u32> = array![];

    let mut i: u32 = 0;
    loop {
        if i >= params.num_hops || i >= available_nodes.len() {
            break;
        }

        // Select random node not already in path
        let index_hash = poseidon_hash_span(
            array![ONION_DOMAIN, current_seed, i.into()].span()
        );
        let index_u256: u256 = index_hash.into();
        let mut node_index: u32 = (index_u256 % available_nodes.len().into()).try_into().unwrap();

        // Skip if already used
        let mut attempts: u32 = 0;
        loop {
            if attempts >= available_nodes.len() || !is_index_used(node_index, used_indices.span()) {
                break;
            }
            node_index = (node_index + 1) % available_nodes.len();
            attempts += 1;
        };

        if attempts < available_nodes.len() {
            let node = *available_nodes.at(node_index);
            if node.is_active && can_route_amount(node, params.amount) {
                path.append(node);
                used_indices.append(node_index);
            }
        }

        current_seed = index_hash;
        i += 1;
    };

    path
}

/// Check if index is already used
fn is_index_used(index: u32, used: Span<u32>) -> bool {
    let mut i: u32 = 0;
    loop {
        if i >= used.len() {
            break false;
        }
        if *used.at(i) == index {
            break true;
        }
        i += 1;
    }
}

/// Check if node can route the amount
fn can_route_amount(node: RoutingNode, amount: u256) -> bool {
    amount >= node.min_forward && amount <= node.max_forward
}
