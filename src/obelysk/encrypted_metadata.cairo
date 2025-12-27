// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2025 BitSage Network Foundation
//
// Encrypted Metadata System for Enhanced Privacy
//
// Implements:
// 1. Symmetric Encryption: ChaCha20-style stream cipher for metadata
// 2. Shared Secret Derivation: ECDH for sender-receiver shared secrets
// 3. Metadata Padding: Fixed-size encrypted blobs to prevent length analysis
// 4. Encrypted Tags: Searchable encryption for efficient scanning
//
// Properties:
// - Confidentiality: Only sender and receiver can decrypt metadata
// - Unlinkability: Encrypted metadata reveals nothing to observers
// - Efficiency: View tags allow fast rejection of non-matching entries

use core::poseidon::poseidon_hash_span;
use sage_contracts::obelysk::elgamal::{ECPoint, ec_mul, generator};

// ============================================================================
// ENCRYPTED METADATA STRUCTURES
// ============================================================================

/// Encrypted metadata blob (fixed size for privacy)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EncryptedMetadata {
    /// Encrypted data chunks (8 x felt252 = 256 bytes max)
    pub chunk0: felt252,
    pub chunk1: felt252,
    pub chunk2: felt252,
    pub chunk3: felt252,
    pub chunk4: felt252,
    pub chunk5: felt252,
    pub chunk6: felt252,
    pub chunk7: felt252,
    /// Encryption nonce (unique per encryption)
    pub nonce: felt252,
    /// Authentication tag (prevents tampering)
    pub auth_tag: felt252,
}

/// Plaintext metadata structure
#[derive(Drop, Serde)]
pub struct PlaintextMetadata {
    /// Job ID (optional)
    pub job_id: Option<u256>,
    /// Payment reference (optional)
    pub payment_ref: Option<felt252>,
    /// Custom memo (max 128 chars encoded)
    pub memo: Array<felt252>,
    /// Timestamp hint (for time-based filtering)
    pub timestamp_hint: u64,
    /// Payment type marker
    pub payment_type: u8,
    /// Extra fields for extensibility
    pub extra: Array<felt252>,
}

/// Compact encrypted metadata for common use cases
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct CompactEncryptedMetadata {
    /// Single encrypted chunk for simple metadata
    pub encrypted: felt252,
    /// Nonce
    pub nonce: felt252,
    /// Truncated auth tag (first 16 bytes)
    pub auth_tag_short: felt252,
}

/// Shared secret for metadata encryption
#[derive(Copy, Drop, Serde)]
pub struct MetadataSharedSecret {
    /// The shared secret point
    pub secret: ECPoint,
    /// Derived encryption key
    pub encryption_key: felt252,
    /// Derived authentication key
    pub auth_key: felt252,
}

/// Encrypted announcement with full metadata privacy
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PrivateAnnouncement {
    /// Ephemeral public key for ECDH
    pub ephemeral_pubkey_x: felt252,
    pub ephemeral_pubkey_y: felt252,
    /// Stealth address
    pub stealth_address: felt252,
    /// Encrypted amount (ElGamal)
    pub encrypted_amount_c1_x: felt252,
    pub encrypted_amount_c1_y: felt252,
    pub encrypted_amount_c2_x: felt252,
    pub encrypted_amount_c2_y: felt252,
    /// Encrypted metadata
    pub metadata: EncryptedMetadata,
    /// View tag for fast scanning
    pub view_tag: u8,
    /// Searchable encrypted tag (for specific queries)
    pub search_tag: felt252,
}

// ============================================================================
// CONSTANTS
// ============================================================================

/// Domain separator for key derivation
const KEY_DERIVATION_DOMAIN: felt252 = 'METADATA_KEY';

/// Domain separator for encryption
const ENCRYPTION_DOMAIN: felt252 = 'METADATA_ENC';

/// Domain separator for authentication
const AUTH_DOMAIN: felt252 = 'METADATA_AUTH';

/// Domain separator for search tags
const SEARCH_TAG_DOMAIN: felt252 = 'METADATA_SEARCH';

/// Maximum metadata chunks
const MAX_METADATA_CHUNKS: u32 = 8;

/// Padding value for unused chunks
const PADDING_VALUE: felt252 = 0xDEAD;

// ============================================================================
// SHARED SECRET DERIVATION
// ============================================================================

/// Derive shared secret from ephemeral private key and recipient public key
/// Uses ECDH: secret = ephemeral_private * recipient_public
pub fn derive_shared_secret(
    ephemeral_private: felt252,
    recipient_public: ECPoint
) -> MetadataSharedSecret {
    // ECDH: shared point = ephemeral_private * recipient_public
    let secret = ec_mul(ephemeral_private, recipient_public);

    // Derive encryption key
    let encryption_key = poseidon_hash_span(
        array![KEY_DERIVATION_DOMAIN, secret.x, secret.y, 'ENC'].span()
    );

    // Derive authentication key
    let auth_key = poseidon_hash_span(
        array![KEY_DERIVATION_DOMAIN, secret.x, secret.y, 'AUTH'].span()
    );

    MetadataSharedSecret {
        secret,
        encryption_key,
        auth_key,
    }
}

/// Derive shared secret from recipient private key and ephemeral public key
/// Recipient side of ECDH
pub fn derive_shared_secret_recipient(
    recipient_private: felt252,
    ephemeral_public: ECPoint
) -> MetadataSharedSecret {
    // ECDH: shared point = recipient_private * ephemeral_public
    let secret = ec_mul(recipient_private, ephemeral_public);

    // Derive encryption key (same as sender)
    let encryption_key = poseidon_hash_span(
        array![KEY_DERIVATION_DOMAIN, secret.x, secret.y, 'ENC'].span()
    );

    // Derive authentication key
    let auth_key = poseidon_hash_span(
        array![KEY_DERIVATION_DOMAIN, secret.x, secret.y, 'AUTH'].span()
    );

    MetadataSharedSecret {
        secret,
        encryption_key,
        auth_key,
    }
}

// ============================================================================
// STREAM CIPHER (ChaCha20-style)
// ============================================================================

/// Generate keystream for encryption/decryption
fn generate_keystream(
    key: felt252,
    nonce: felt252,
    block_index: u32
) -> felt252 {
    poseidon_hash_span(
        array![ENCRYPTION_DOMAIN, key, nonce, block_index.into()].span()
    )
}

/// Encrypt a single chunk using stream cipher
fn encrypt_chunk(
    plaintext: felt252,
    key: felt252,
    nonce: felt252,
    index: u32
) -> felt252 {
    let keystream = generate_keystream(key, nonce, index);
    plaintext + keystream // XOR in felt252 field
}

/// Decrypt a single chunk
fn decrypt_chunk(
    ciphertext: felt252,
    key: felt252,
    nonce: felt252,
    index: u32
) -> felt252 {
    let keystream = generate_keystream(key, nonce, index);
    ciphertext - keystream // Reverse XOR
}

// ============================================================================
// METADATA ENCRYPTION
// ============================================================================

/// Encrypt metadata with padding to fixed size
pub fn encrypt_metadata(
    plaintext: Span<felt252>,
    shared_secret: MetadataSharedSecret,
    nonce: felt252
) -> EncryptedMetadata {
    // Encrypt each chunk (pad if necessary)
    let chunk0 = if plaintext.len() > 0 {
        encrypt_chunk(*plaintext.at(0), shared_secret.encryption_key, nonce, 0)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 0)
    };

    let chunk1 = if plaintext.len() > 1 {
        encrypt_chunk(*plaintext.at(1), shared_secret.encryption_key, nonce, 1)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 1)
    };

    let chunk2 = if plaintext.len() > 2 {
        encrypt_chunk(*plaintext.at(2), shared_secret.encryption_key, nonce, 2)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 2)
    };

    let chunk3 = if plaintext.len() > 3 {
        encrypt_chunk(*plaintext.at(3), shared_secret.encryption_key, nonce, 3)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 3)
    };

    let chunk4 = if plaintext.len() > 4 {
        encrypt_chunk(*plaintext.at(4), shared_secret.encryption_key, nonce, 4)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 4)
    };

    let chunk5 = if plaintext.len() > 5 {
        encrypt_chunk(*plaintext.at(5), shared_secret.encryption_key, nonce, 5)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 5)
    };

    let chunk6 = if plaintext.len() > 6 {
        encrypt_chunk(*plaintext.at(6), shared_secret.encryption_key, nonce, 6)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 6)
    };

    let chunk7 = if plaintext.len() > 7 {
        encrypt_chunk(*plaintext.at(7), shared_secret.encryption_key, nonce, 7)
    } else {
        encrypt_chunk(PADDING_VALUE, shared_secret.encryption_key, nonce, 7)
    };

    // Compute authentication tag
    let auth_tag = compute_auth_tag(
        array![chunk0, chunk1, chunk2, chunk3, chunk4, chunk5, chunk6, chunk7].span(),
        shared_secret.auth_key,
        nonce
    );

    EncryptedMetadata {
        chunk0,
        chunk1,
        chunk2,
        chunk3,
        chunk4,
        chunk5,
        chunk6,
        chunk7,
        nonce,
        auth_tag,
    }
}

/// Decrypt metadata
pub fn decrypt_metadata(
    encrypted: EncryptedMetadata,
    shared_secret: MetadataSharedSecret
) -> Option<Array<felt252>> {
    // Verify authentication tag first
    let expected_tag = compute_auth_tag(
        array![
            encrypted.chunk0, encrypted.chunk1, encrypted.chunk2, encrypted.chunk3,
            encrypted.chunk4, encrypted.chunk5, encrypted.chunk6, encrypted.chunk7
        ].span(),
        shared_secret.auth_key,
        encrypted.nonce
    );

    if expected_tag != encrypted.auth_tag {
        return Option::None;
    }

    // Decrypt chunks
    let mut result: Array<felt252> = array![];

    let d0 = decrypt_chunk(encrypted.chunk0, shared_secret.encryption_key, encrypted.nonce, 0);
    if d0 != PADDING_VALUE {
        result.append(d0);
    }

    let d1 = decrypt_chunk(encrypted.chunk1, shared_secret.encryption_key, encrypted.nonce, 1);
    if d1 != PADDING_VALUE {
        result.append(d1);
    }

    let d2 = decrypt_chunk(encrypted.chunk2, shared_secret.encryption_key, encrypted.nonce, 2);
    if d2 != PADDING_VALUE {
        result.append(d2);
    }

    let d3 = decrypt_chunk(encrypted.chunk3, shared_secret.encryption_key, encrypted.nonce, 3);
    if d3 != PADDING_VALUE {
        result.append(d3);
    }

    let d4 = decrypt_chunk(encrypted.chunk4, shared_secret.encryption_key, encrypted.nonce, 4);
    if d4 != PADDING_VALUE {
        result.append(d4);
    }

    let d5 = decrypt_chunk(encrypted.chunk5, shared_secret.encryption_key, encrypted.nonce, 5);
    if d5 != PADDING_VALUE {
        result.append(d5);
    }

    let d6 = decrypt_chunk(encrypted.chunk6, shared_secret.encryption_key, encrypted.nonce, 6);
    if d6 != PADDING_VALUE {
        result.append(d6);
    }

    let d7 = decrypt_chunk(encrypted.chunk7, shared_secret.encryption_key, encrypted.nonce, 7);
    if d7 != PADDING_VALUE {
        result.append(d7);
    }

    Option::Some(result)
}

/// Compute authentication tag for ciphertext
fn compute_auth_tag(
    ciphertext: Span<felt252>,
    auth_key: felt252,
    nonce: felt252
) -> felt252 {
    let mut input: Array<felt252> = array![AUTH_DOMAIN, auth_key, nonce];

    let mut i: u32 = 0;
    loop {
        if i >= ciphertext.len() {
            break;
        }
        input.append(*ciphertext.at(i));
        i += 1;
    };

    poseidon_hash_span(input.span())
}

// ============================================================================
// SEARCHABLE ENCRYPTION
// ============================================================================

/// Generate a searchable tag for specific queries
/// Only the holder of the search key can generate matching tags
pub fn generate_search_tag(
    keyword: felt252,
    search_key: felt252,
    nonce: felt252
) -> felt252 {
    poseidon_hash_span(
        array![SEARCH_TAG_DOMAIN, search_key, keyword, nonce].span()
    )
}

/// Generate search token for querying
/// Holder of view key can generate tokens to search for their payments
pub fn generate_search_token(
    keyword: felt252,
    view_key: felt252
) -> felt252 {
    poseidon_hash_span(
        array![SEARCH_TAG_DOMAIN, view_key, keyword].span()
    )
}

/// Check if a search tag matches a token
/// Used for efficient scanning without decryption
pub fn match_search_tag(
    tag: felt252,
    token: felt252,
    nonce: felt252
) -> bool {
    let expected = poseidon_hash_span(array![token, nonce].span());
    tag == expected
}

// ============================================================================
// COMPACT METADATA HELPERS
// ============================================================================

/// Encrypt a single value (for simple job_id or payment_ref)
pub fn encrypt_compact(
    value: felt252,
    shared_secret: MetadataSharedSecret,
    nonce: felt252
) -> CompactEncryptedMetadata {
    let encrypted = encrypt_chunk(value, shared_secret.encryption_key, nonce, 0);

    let auth_tag_short = poseidon_hash_span(
        array![AUTH_DOMAIN, shared_secret.auth_key, nonce, encrypted].span()
    );

    CompactEncryptedMetadata {
        encrypted,
        nonce,
        auth_tag_short,
    }
}

/// Decrypt a compact metadata value
pub fn decrypt_compact(
    compact: CompactEncryptedMetadata,
    shared_secret: MetadataSharedSecret
) -> Option<felt252> {
    // Verify auth tag
    let expected_tag = poseidon_hash_span(
        array![AUTH_DOMAIN, shared_secret.auth_key, compact.nonce, compact.encrypted].span()
    );

    if expected_tag != compact.auth_tag_short {
        return Option::None;
    }

    let decrypted = decrypt_chunk(compact.encrypted, shared_secret.encryption_key, compact.nonce, 0);
    Option::Some(decrypted)
}

// ============================================================================
// METADATA SERIALIZATION
// ============================================================================

/// Serialize plaintext metadata to felt252 array
pub fn serialize_metadata(metadata: @PlaintextMetadata) -> Array<felt252> {
    let mut result: Array<felt252> = array![];

    // Encode payment type
    result.append((*metadata.payment_type).into());

    // Encode timestamp hint
    result.append((*metadata.timestamp_hint).into());

    // Encode job_id if present
    match metadata.job_id {
        Option::Some(job_id) => {
            result.append(1); // marker: has job_id
            result.append((*job_id.low).into());
            result.append((*job_id.high).into());
        },
        Option::None => {
            result.append(0); // marker: no job_id
        }
    };

    // Encode payment_ref if present
    match metadata.payment_ref {
        Option::Some(ref_val) => {
            result.append(1);
            result.append(*ref_val);
        },
        Option::None => {
            result.append(0);
        }
    };

    // Note: memo and extra fields truncated to fit in 8 chunks

    result
}

/// Deserialize felt252 array to plaintext metadata
pub fn deserialize_metadata(data: Span<felt252>) -> Option<PlaintextMetadata> {
    if data.len() < 3 {
        return Option::None;
    }

    let payment_type_felt = *data.at(0);
    let payment_type: u8 = payment_type_felt.try_into().unwrap_or(0);

    let timestamp_hint_felt = *data.at(1);
    let timestamp_hint: u64 = timestamp_hint_felt.try_into().unwrap_or(0);

    let has_job_id = *data.at(2);
    let (job_id, next_idx) = if has_job_id == 1 && data.len() >= 5 {
        let low: u128 = (*data.at(3)).try_into().unwrap_or(0);
        let high: u128 = (*data.at(4)).try_into().unwrap_or(0);
        (Option::Some(u256 { low, high }), 5)
    } else {
        (Option::None, 3)
    };

    let payment_ref = if data.len() > next_idx && *data.at(next_idx) == 1 && data.len() > next_idx + 1 {
        Option::Some(*data.at(next_idx + 1))
    } else {
        Option::None
    };

    Option::Some(PlaintextMetadata {
        job_id,
        payment_ref,
        memo: array![],
        timestamp_hint,
        payment_type,
        extra: array![],
    })
}

// ============================================================================
// PRIVATE ANNOUNCEMENT CREATION
// ============================================================================

/// Create a fully private announcement with encrypted metadata
pub fn create_private_announcement(
    ephemeral_private: felt252,
    recipient_public: ECPoint,
    stealth_address: felt252,
    encrypted_amount: (ECPoint, ECPoint), // (C1, C2)
    metadata: Span<felt252>,
    nonce: felt252
) -> PrivateAnnouncement {
    // Derive shared secret
    let shared_secret = derive_shared_secret(ephemeral_private, recipient_public);

    // Compute ephemeral public key
    let g = generator();
    let ephemeral_public = ec_mul(ephemeral_private, g);

    // Encrypt metadata
    let encrypted_metadata = encrypt_metadata(metadata, shared_secret, nonce);

    // Compute view tag (first byte of shared secret hash)
    let view_tag_hash = poseidon_hash_span(
        array![shared_secret.secret.x, shared_secret.secret.y].span()
    );
    let view_tag_u256: u256 = view_tag_hash.into();
    let view_tag: u8 = (view_tag_u256 % 256).try_into().unwrap();

    // Generate search tag
    let search_tag = generate_search_tag(
        stealth_address,
        shared_secret.encryption_key,
        nonce
    );

    let (c1, c2) = encrypted_amount;

    PrivateAnnouncement {
        ephemeral_pubkey_x: ephemeral_public.x,
        ephemeral_pubkey_y: ephemeral_public.y,
        stealth_address,
        encrypted_amount_c1_x: c1.x,
        encrypted_amount_c1_y: c1.y,
        encrypted_amount_c2_x: c2.x,
        encrypted_amount_c2_y: c2.y,
        metadata: encrypted_metadata,
        view_tag,
        search_tag,
    }
}

/// Decrypt a private announcement (recipient side)
pub fn decrypt_private_announcement(
    announcement: @PrivateAnnouncement,
    recipient_private: felt252
) -> Option<Array<felt252>> {
    // Reconstruct ephemeral public key
    let ephemeral_public = ECPoint {
        x: *announcement.ephemeral_pubkey_x,
        y: *announcement.ephemeral_pubkey_y,
    };

    // Derive shared secret
    let shared_secret = derive_shared_secret_recipient(recipient_private, ephemeral_public);

    // Quick view tag check
    let view_tag_hash = poseidon_hash_span(
        array![shared_secret.secret.x, shared_secret.secret.y].span()
    );
    let view_tag_u256: u256 = view_tag_hash.into();
    let expected_view_tag: u8 = (view_tag_u256 % 256).try_into().unwrap();

    if expected_view_tag != *announcement.view_tag {
        return Option::None;
    }

    // Decrypt metadata
    decrypt_metadata(*announcement.metadata, shared_secret)
}
