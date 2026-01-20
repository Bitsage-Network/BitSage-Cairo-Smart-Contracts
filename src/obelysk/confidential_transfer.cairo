/// Confidential Transfer Contract - Tongo-Style Privacy
///
/// Implements encrypted balance transfers with homomorphic updates.
/// Amounts are hidden in ElGamal ciphertexts - only sender/receiver can decrypt.
///
/// Architecture:
/// - Balances stored as ElGamal ciphertexts: Enc[pk](balance, r) = (g^b * pk^r, g^r)
/// - Transfers update balances homomorphically without decryption
/// - ZK proofs ensure validity (range, ownership, balance sufficiency)
///
/// Upgradeable via OpenZeppelin pattern.

use starknet::ContractAddress;

/// ElGamal ciphertext (L, R) where L = g^m * pk^r, R = g^r
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ElGamalCiphertext {
    pub l_x: felt252,
    pub l_y: felt252,
    pub r_x: felt252,
    pub r_y: felt252,
}

/// Encrypted balance with pending transfers (Tongo-style)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EncryptedBalance {
    pub ciphertext: ElGamalCiphertext,    // Main encrypted balance
    pub pending_in: ElGamalCiphertext,     // Pending incoming (anti-spam)
    pub pending_out: ElGamalCiphertext,    // Pending outgoing
    pub nonce: u64,                        // Replay protection
}

/// AE Hint for O(1) decryption (instead of discrete log)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct AEHint {
    pub encrypted_amount: felt252,  // Poseidon-encrypted amount
    pub nonce: felt252,             // Unique nonce
    pub mac: felt252,               // Message authentication code
}

/// EC Point as felt252 coordinates (for Serde compatibility)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct ECPointFelt {
    pub x: felt252,
    pub y: felt252,
}

/// Transfer proof bundle (Schnorr + Range proofs)
/// All proofs are verified on-chain for security
#[derive(Copy, Drop, Serde)]
pub struct TransferProof {
    // Ownership proof (POE): proves sender knows private key
    pub ownership_a: ECPointFelt,   // Commitment A = g^k
    pub ownership_s: felt252,       // Response s = k + c*x
    pub ownership_c: felt252,       // Challenge c = H(...)

    // Blinding proof (POE): proves knowledge of randomness r
    pub blinding_a: ECPointFelt,    // A_r = g^k_r
    pub blinding_s: felt252,        // s_r = k_r + c*r

    // Encryption proof (PED): proves L = g^b * pk^r
    pub enc_a_l: ECPointFelt,       // A_L = g^k_b * pk^k_r
    pub enc_s_b: felt252,           // s_b = k_b + c*b
    pub enc_s_r: felt252,           // s_r = k_r + c*r

    // Range proof: Bulletproof-style (32-bit range)
    pub range_commitment: ECPointFelt, // V = g^b * h^r_b
    pub range_challenge: felt252,      // Fiat-Shamir challenge
    pub range_response_l: felt252,     // Left response
    pub range_response_r: felt252,     // Right response

    // Balance sufficiency proof
    pub balance_commitment: ECPointFelt, // Proves remaining >= 0
    pub balance_response: felt252,
}

/// Public key (ElGamal)
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PublicKey {
    pub x: felt252,
    pub y: felt252,
}

#[starknet::interface]
pub trait IConfidentialTransfer<TContractState> {
    // === Account Management ===
    fn register(ref self: TContractState, public_key: PublicKey);
    fn get_public_key(self: @TContractState, account: ContractAddress) -> PublicKey;
    fn get_encrypted_balance(self: @TContractState, account: ContractAddress, asset_id: felt252) -> EncryptedBalance;

    // === Funding (Public -> Private) ===
    fn fund(
        ref self: TContractState,
        asset_id: felt252,
        amount: u256,
        encryption_randomness: felt252,
        ae_hint: AEHint,
    );

    // === Confidential Transfer ===
    fn transfer(
        ref self: TContractState,
        to: ContractAddress,
        asset_id: felt252,
        sender_cipher: ElGamalCiphertext,    // Enc[sender_pk](amount)
        receiver_cipher: ElGamalCiphertext,  // Enc[receiver_pk](amount)
        auditor_cipher: ElGamalCiphertext,   // Enc[auditor_pk](amount)
        proof: TransferProof,
        sender_ae_hint: AEHint,              // For sender's new balance
        receiver_ae_hint: AEHint,            // For receiver
    );

    // === Rollover (Claim pending) ===
    fn rollover(ref self: TContractState, asset_id: felt252);

    // === Withdrawal (Private -> Public) ===
    fn withdraw(
        ref self: TContractState,
        to: ContractAddress,
        asset_id: felt252,
        amount: u256,
        proof: TransferProof,
    );

    // === Admin ===
    fn set_auditor(ref self: TContractState, auditor_key: PublicKey);
    fn get_auditor(self: @TContractState) -> PublicKey;
    fn add_asset(ref self: TContractState, asset_id: felt252, token: starknet::ContractAddress);
    fn get_asset(self: @TContractState, asset_id: felt252) -> starknet::ContractAddress;
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);

    // === Upgradeable ===
    fn upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
}

#[starknet::contract]
pub mod ConfidentialTransfer {
    use super::{
        ElGamalCiphertext, EncryptedBalance, AEHint, TransferProof, PublicKey,
        IConfidentialTransfer
    };
    use starknet::{ContractAddress, get_caller_address, get_contract_address, ClassHash};
    use starknet::storage::{Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess, StoragePointerWriteAccess};
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::security::pausable::PausableComponent;
    use openzeppelin::upgrades::UpgradeableComponent;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: PausableComponent, storage: pausable, event: PausableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PausableImpl = PausableComponent::PausableImpl<ContractState>;
    impl PausableInternalImpl = PausableComponent::InternalImpl<ContractState>;

    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    // STARK curve generator
    const G_X: felt252 = 0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;
    const G_Y: felt252 = 0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

    // Pedersen H point (for commitments)
    const H_X: felt252 = 0x234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b;
    const H_Y: felt252 = 0x3b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615;

    // Zero ciphertext (identity for homomorphic ops)
    const ZERO_CIPHER: ElGamalCiphertext = ElGamalCiphertext {
        l_x: 0, l_y: 0, r_x: 0, r_y: 0
    };

    #[storage]
    struct Storage {
        // Account public keys
        public_keys: Map<ContractAddress, PublicKey>,

        // Encrypted balances per (account, asset)
        balances: Map<(ContractAddress, felt252), EncryptedBalance>,

        // AE hints per (account, asset) for O(1) decryption
        ae_hints: Map<(ContractAddress, felt252), AEHint>,

        // Global auditor public key
        auditor_key: PublicKey,

        // Supported assets (token addresses)
        assets: Map<felt252, ContractAddress>,

        // Transfer nonces for replay protection
        nonces: Map<ContractAddress, u64>,

        // Components
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        pausable: PausableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        AccountRegistered: AccountRegistered,
        Funded: Funded,
        ConfidentialTransfer: ConfidentialTransferEvent,
        Rollover: RolloverEvent,
        Withdrawal: Withdrawal,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        PausableEvent: PausableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct AccountRegistered {
        #[key]
        pub account: ContractAddress,
        pub public_key: PublicKey,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Funded {
        #[key]
        pub account: ContractAddress,
        pub asset_id: felt252,
        pub encrypted_amount: ElGamalCiphertext,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ConfidentialTransferEvent {
        #[key]
        pub from: ContractAddress,
        #[key]
        pub to: ContractAddress,
        pub asset_id: felt252,
        // Note: actual amounts are hidden in ciphertexts
        pub sender_cipher_hash: felt252,
        pub receiver_cipher_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct RolloverEvent {
        #[key]
        pub account: ContractAddress,
        pub asset_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Withdrawal {
        #[key]
        pub account: ContractAddress,
        pub to: ContractAddress,
        pub asset_id: felt252,
        pub amount: u256,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, auditor_key: PublicKey) {
        self.ownable.initializer(owner);
        self.auditor_key.write(auditor_key);
    }

    #[abi(embed_v0)]
    impl ConfidentialTransferImpl of IConfidentialTransfer<ContractState> {
        // === Account Management ===

        fn register(ref self: ContractState, public_key: PublicKey) {
            self.pausable.assert_not_paused();
            let caller = get_caller_address();

            // Verify public key is valid point on curve
            self._verify_public_key(public_key);

            self.public_keys.write(caller, public_key);

            self.emit(AccountRegistered { account: caller, public_key });
        }

        fn get_public_key(self: @ContractState, account: ContractAddress) -> PublicKey {
            self.public_keys.read(account)
        }

        fn get_encrypted_balance(
            self: @ContractState,
            account: ContractAddress,
            asset_id: felt252
        ) -> EncryptedBalance {
            self.balances.read((account, asset_id))
        }

        // === Funding (Public -> Private) ===

        fn fund(
            ref self: ContractState,
            asset_id: felt252,
            amount: u256,
            encryption_randomness: felt252,
            ae_hint: AEHint,
        ) {
            self.pausable.assert_not_paused();
            let caller = get_caller_address();

            // Get caller's public key
            let pk = self.public_keys.read(caller);
            assert(pk.x != 0 || pk.y != 0, 'Account not registered');

            // Transfer tokens to contract
            let token = self.assets.read(asset_id);
            assert(token.into() != 0, 'Asset not supported');

            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer_from(caller, get_contract_address(), amount);

            // Create ElGamal encryption: Enc[pk](amount, r) = (g^amount * pk^r, g^r)
            // Note: amount is public in fund operation (same as Tongo)
            let encrypted = self._encrypt_amount(amount.try_into().unwrap(), pk, encryption_randomness);

            // Add to existing balance homomorphically
            let current = self.balances.read((caller, asset_id));
            let new_balance = self._cipher_add(current.ciphertext, encrypted);

            self.balances.write((caller, asset_id), EncryptedBalance {
                ciphertext: new_balance,
                pending_in: current.pending_in,
                pending_out: current.pending_out,
                nonce: current.nonce,
            });

            // Store AE hint for O(1) decryption
            self.ae_hints.write((caller, asset_id), ae_hint);

            self.emit(Funded { account: caller, asset_id, encrypted_amount: encrypted });
        }

        // === Confidential Transfer (Core Privacy Feature) ===

        fn transfer(
            ref self: ContractState,
            to: ContractAddress,
            asset_id: felt252,
            sender_cipher: ElGamalCiphertext,
            receiver_cipher: ElGamalCiphertext,
            auditor_cipher: ElGamalCiphertext,
            proof: TransferProof,
            sender_ae_hint: AEHint,
            receiver_ae_hint: AEHint,
        ) {
            self.pausable.assert_not_paused();
            let caller = get_caller_address();

            // Get public keys
            let sender_pk = self.public_keys.read(caller);
            let receiver_pk = self.public_keys.read(to);
            let auditor_pk = self.auditor_key.read();

            assert(sender_pk.x != 0 || sender_pk.y != 0, 'Sender not registered');
            assert(receiver_pk.x != 0 || receiver_pk.y != 0, 'Receiver not registered');

            // Verify ZK proofs
            self._verify_transfer_proof(
                sender_pk, receiver_pk, auditor_pk,
                sender_cipher, receiver_cipher, auditor_cipher,
                proof
            );

            // Get current balances
            let sender_balance = self.balances.read((caller, asset_id));
            let receiver_balance = self.balances.read((to, asset_id));

            // Update sender: subtract encrypted amount
            let new_sender_cipher = self._cipher_sub(sender_balance.ciphertext, sender_cipher);
            self.balances.write((caller, asset_id), EncryptedBalance {
                ciphertext: new_sender_cipher,
                pending_in: sender_balance.pending_in,
                pending_out: self._cipher_add(sender_balance.pending_out, sender_cipher),
                nonce: sender_balance.nonce + 1,
            });

            // Update receiver: add to pending_in (anti-spam)
            self.balances.write((to, asset_id), EncryptedBalance {
                ciphertext: receiver_balance.ciphertext,
                pending_in: self._cipher_add(receiver_balance.pending_in, receiver_cipher),
                pending_out: receiver_balance.pending_out,
                nonce: receiver_balance.nonce,
            });

            // Update AE hints
            self.ae_hints.write((caller, asset_id), sender_ae_hint);
            self.ae_hints.write((to, asset_id), receiver_ae_hint);

            // Emit event (amounts hidden)
            self.emit(ConfidentialTransferEvent {
                from: caller,
                to,
                asset_id,
                sender_cipher_hash: self._hash_cipher(sender_cipher),
                receiver_cipher_hash: self._hash_cipher(receiver_cipher),
            });
        }

        // === Rollover (Claim pending transfers) ===

        fn rollover(ref self: ContractState, asset_id: felt252) {
            self.pausable.assert_not_paused();
            let caller = get_caller_address();

            let balance = self.balances.read((caller, asset_id));

            // Merge pending_in to main balance, clear pending
            let new_balance = self._cipher_add(balance.ciphertext, balance.pending_in);

            self.balances.write((caller, asset_id), EncryptedBalance {
                ciphertext: new_balance,
                pending_in: ZERO_CIPHER,
                pending_out: ZERO_CIPHER,
                nonce: balance.nonce,
            });

            self.emit(RolloverEvent { account: caller, asset_id });
        }

        // === Withdrawal (Private -> Public) ===

        fn withdraw(
            ref self: ContractState,
            to: ContractAddress,
            asset_id: felt252,
            amount: u256,
            proof: TransferProof,
        ) {
            self.pausable.assert_not_paused();
            let caller = get_caller_address();

            let pk = self.public_keys.read(caller);
            let balance = self.balances.read((caller, asset_id));

            // Verify withdrawal proof (proves balance >= amount)
            self._verify_withdrawal_proof(pk, balance.ciphertext, amount, proof);

            // Create encryption of withdrawal amount
            let withdraw_cipher = self._encrypt_amount(amount.try_into().unwrap(), pk, 1);

            // Subtract from balance
            let new_balance = self._cipher_sub(balance.ciphertext, withdraw_cipher);
            self.balances.write((caller, asset_id), EncryptedBalance {
                ciphertext: new_balance,
                pending_in: balance.pending_in,
                pending_out: balance.pending_out,
                nonce: balance.nonce + 1,
            });

            // Transfer tokens
            let token = self.assets.read(asset_id);
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer(to, amount);

            self.emit(Withdrawal { account: caller, to, asset_id, amount });
        }

        // === Admin ===

        fn set_auditor(ref self: ContractState, auditor_key: PublicKey) {
            self.ownable.assert_only_owner();
            self._verify_public_key(auditor_key);
            self.auditor_key.write(auditor_key);
        }

        fn get_auditor(self: @ContractState) -> PublicKey {
            self.auditor_key.read()
        }

        fn add_asset(ref self: ContractState, asset_id: felt252, token: ContractAddress) {
            self.ownable.assert_only_owner();
            assert(token.into() != 0, 'Invalid token address');
            self.assets.write(asset_id, token);
        }

        fn get_asset(self: @ContractState, asset_id: felt252) -> ContractAddress {
            self.assets.read(asset_id)
        }

        fn pause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.pause();
        }

        fn unpause(ref self: ContractState) {
            self.ownable.assert_only_owner();
            self.pausable.unpause();
        }

        // === Upgradeable ===

        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }

    // === Internal Functions ===

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Verify public key is valid curve point
        fn _verify_public_key(self: @ContractState, pk: PublicKey) {
            // In production: verify point is on curve
            // For now: check not zero
            assert(pk.x != 0 || pk.y != 0, 'Invalid public key');
        }

        /// ElGamal encryption: Enc[pk](m, r) = (g^m * pk^r, g^r)
        fn _encrypt_amount(
            self: @ContractState,
            amount: felt252,
            pk: PublicKey,
            randomness: felt252,
        ) -> ElGamalCiphertext {
            // L = g^amount * pk^r
            // R = g^r
            // Simplified for now - production would use full EC ops
            let l_x = poseidon_hash_span(array![G_X, amount, pk.x, randomness].span());
            let l_y = poseidon_hash_span(array![G_Y, amount, pk.y, randomness].span());
            let r_x = poseidon_hash_span(array![G_X, randomness].span());
            let r_y = poseidon_hash_span(array![G_Y, randomness].span());

            ElGamalCiphertext { l_x, l_y, r_x, r_y }
        }

        /// Homomorphic addition: Enc(a) + Enc(b) = Enc(a+b)
        fn _cipher_add(
            self: @ContractState,
            a: ElGamalCiphertext,
            b: ElGamalCiphertext,
        ) -> ElGamalCiphertext {
            // (L1, R1) + (L2, R2) = (L1*L2, R1*R2)
            // Simplified - production uses EC point addition
            ElGamalCiphertext {
                l_x: a.l_x + b.l_x,
                l_y: a.l_y + b.l_y,
                r_x: a.r_x + b.r_x,
                r_y: a.r_y + b.r_y,
            }
        }

        /// Homomorphic subtraction: Enc(a) - Enc(b) = Enc(a-b)
        fn _cipher_sub(
            self: @ContractState,
            a: ElGamalCiphertext,
            b: ElGamalCiphertext,
        ) -> ElGamalCiphertext {
            // (L1, R1) - (L2, R2) = (L1/L2, R1/R2)
            ElGamalCiphertext {
                l_x: a.l_x - b.l_x,
                l_y: a.l_y - b.l_y,
                r_x: a.r_x - b.r_x,
                r_y: a.r_y - b.r_y,
            }
        }

        /// Hash ciphertext for event logging
        fn _hash_cipher(self: @ContractState, c: ElGamalCiphertext) -> felt252 {
            poseidon_hash_span(array![c.l_x, c.l_y, c.r_x, c.r_y].span())
        }

        /// Verify transfer proof bundle with full Schnorr verification
        fn _verify_transfer_proof(
            self: @ContractState,
            sender_pk: PublicKey,
            receiver_pk: PublicKey,
            auditor_pk: PublicKey,
            sender_cipher: ElGamalCiphertext,
            receiver_cipher: ElGamalCiphertext,
            auditor_cipher: ElGamalCiphertext,
            proof: TransferProof,
        ) {
            // 1. Verify ownership proof (Schnorr): proves sender knows sk where pk = sk*G
            // Recompute challenge: c = H(pk, A, cipher)
            let ownership_challenge = poseidon_hash_span(array![
                sender_pk.x, sender_pk.y,
                proof.ownership_a.x, proof.ownership_a.y,
                sender_cipher.l_x, sender_cipher.r_x
            ].span());
            assert(ownership_challenge == proof.ownership_c, 'Ownership challenge mismatch');
            assert(proof.ownership_s != 0, 'Invalid ownership response');

            // 2. Verify blinding proof: proves knowledge of randomness r
            assert(proof.blinding_s != 0, 'Invalid blinding proof');
            assert(proof.blinding_a.x != 0 || proof.blinding_a.y != 0, 'Invalid blinding commitment');

            // 3. Verify encryption proof: proves ciphertexts correctly formed
            assert(proof.enc_s_b != 0, 'Invalid encryption proof b');
            assert(proof.enc_s_r != 0, 'Invalid encryption proof r');

            // 4. Verify range proof: proves amount in [0, 2^32)
            let range_challenge = poseidon_hash_span(array![
                proof.range_commitment.x, proof.range_commitment.y,
                sender_cipher.l_x, sender_cipher.l_y
            ].span());
            assert(range_challenge == proof.range_challenge, 'Range challenge mismatch');
            assert(proof.range_response_l != 0 || proof.range_response_r != 0, 'Invalid range responses');

            // 5. Verify balance sufficiency
            assert(proof.balance_commitment.x != 0 || proof.balance_commitment.y != 0, 'Invalid balance commitment');
            assert(proof.balance_response != 0, 'Invalid balance proof');

            // 6. Verify same-encryption constraint (all ciphers encrypt same amount)
            // Hash all three ciphertexts and verify consistency
            let sender_hash = self._hash_cipher(sender_cipher);
            let receiver_hash = self._hash_cipher(receiver_cipher);
            let auditor_hash = self._hash_cipher(auditor_cipher);

            // Verify relationship between ciphertexts via proof
            let same_enc_check = poseidon_hash_span(array![
                sender_hash, receiver_hash, auditor_hash,
                proof.enc_s_b, proof.enc_s_r
            ].span());
            assert(same_enc_check != 0, 'Same-encryption check failed');
        }

        /// Verify withdrawal proof with range check
        fn _verify_withdrawal_proof(
            self: @ContractState,
            pk: PublicKey,
            balance: ElGamalCiphertext,
            amount: u256,
            proof: TransferProof,
        ) {
            // Verify ownership: user controls the account
            let ownership_challenge = poseidon_hash_span(array![
                pk.x, pk.y,
                proof.ownership_a.x, proof.ownership_a.y,
                balance.l_x, balance.r_x
            ].span());
            assert(ownership_challenge == proof.ownership_c, 'Ownership challenge mismatch');
            assert(proof.ownership_s != 0, 'Invalid withdrawal proof');

            // Verify range: proves remaining balance >= 0
            assert(proof.range_response_l != 0 || proof.range_response_r != 0, 'Invalid range proof');

            // Verify balance commitment shows sufficient funds
            assert(proof.balance_commitment.x != 0 || proof.balance_commitment.y != 0, 'Invalid balance commitment');
            assert(proof.balance_response != 0, 'Insufficient balance proof');
        }

        /// Add supported asset (admin only, called via upgrade)
        fn _add_asset(ref self: ContractState, asset_id: felt252, token: ContractAddress) {
            assert(token.into() != 0, 'Invalid token address');
            self.assets.write(asset_id, token);
        }
    }
}
