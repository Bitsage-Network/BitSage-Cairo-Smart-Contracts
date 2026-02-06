// ============================================================================
// Shielded Swap Router — Privacy-preserving token swaps via Ekubo AMM
// ============================================================================
//
// Architecture: ILocker-based router that executes atomic private swaps.
// Uses Ekubo's lock/callback pattern to swap through existing AMM pools
// while hiding the user's identity — only the router appears on-chain.
//
// Flow:
//   1. User generates withdrawal proof + deposit commitment off-chain
//   2. Calls shielded_swap() → router locks Ekubo Core
//   3. In locked() callback:
//      a. Withdraw from source privacy pool (input token)
//      b. Swap via Ekubo AMM (input → output)
//      c. Deposit into destination privacy pool (output token)
//   4. User's identity never appears as swap participant
//
// Privacy model:
//   - Identity: HIDDEN (router is the on-chain actor)
//   - Amounts: VISIBLE (Ekubo AMM requires plaintext for constant-product math)
//
// Constraint: Each privacy pool instance holds a single token type.
//   The router maps token addresses → privacy pool addresses via pool_registry.

use starknet::ContractAddress;
use starknet::storage::Map;
use sage_contracts::obelysk::elgamal::ECPoint;
use sage_contracts::obelysk::lean_imt::LeanIMTProof;
use sage_contracts::obelysk::privacy_pools::{
    PPWithdrawalProof, ExclusionProofData,
};

// ============================================================================
// Ekubo Types (inline — avoids external dependency resolution issues)
// These match the Ekubo Protocol ABI exactly.
// ============================================================================

#[derive(Copy, Drop, Serde)]
pub struct PoolKey {
    pub token0: ContractAddress,
    pub token1: ContractAddress,
    pub fee: u128,
    pub tick_spacing: u128,
    pub extension: ContractAddress,
}

#[derive(Copy, Drop, Serde)]
pub struct SwapParameters {
    pub amount: i129,
    pub is_token1: bool,
    pub sqrt_ratio_limit: u256,
    pub skip_ahead: u32,
}

/// Signed 129-bit integer for Ekubo delta representation
#[derive(Copy, Drop, Serde)]
pub struct i129 {
    pub mag: u128,
    pub sign: bool, // true = negative
}

/// Ekubo swap delta — amounts owed/received for each token
#[derive(Copy, Drop, Serde)]
pub struct Delta {
    pub amount0: i129,
    pub amount1: i129,
}

// ============================================================================
// Shielded Swap Request
// ============================================================================

/// Complete parameters for an atomic private swap
#[derive(Drop, Serde)]
pub struct ShieldedSwapRequest {
    // --- Source (withdraw from privacy pool) ---
    pub source_pool: ContractAddress,
    pub withdrawal_proof: PPWithdrawalProof,

    // --- Ekubo swap parameters ---
    pub pool_key: PoolKey,
    pub swap_params: SwapParameters,
    pub min_amount_out: u256,

    // --- Destination (deposit into privacy pool) ---
    pub dest_pool: ContractAddress,
    pub deposit_commitment: felt252,
    pub deposit_amount_commitment: ECPoint,
    pub deposit_asset_id: felt252,
    pub deposit_range_proof: Span<felt252>,
}

// ============================================================================
// Interface
// ============================================================================

#[starknet::interface]
pub trait IShieldedSwapRouter<TContractState> {
    /// Execute a private swap: withdraw → Ekubo swap → deposit
    fn shielded_swap(ref self: TContractState, request: ShieldedSwapRequest);

    /// Ekubo ILocker callback — called by Ekubo Core during lock()
    fn locked(ref self: TContractState, id: u32, data: Span<felt252>) -> Span<felt252>;

    /// Admin: register a privacy pool address for a given token
    fn register_pool(ref self: TContractState, token: ContractAddress, pool: ContractAddress);

    /// Admin: update the Ekubo Core address
    fn set_ekubo_core(ref self: TContractState, core: ContractAddress);

    /// View: get registered pool for a token
    fn get_pool(self: @TContractState, token: ContractAddress) -> ContractAddress;

    /// View: get total swaps executed
    fn get_swap_count(self: @TContractState) -> u64;

    /// View: get the Ekubo Core address
    fn get_ekubo_core(self: @TContractState) -> ContractAddress;
}

// ============================================================================
// Ekubo Core Interface (lock + swap + settlement)
// ============================================================================

#[starknet::interface]
trait IEkuboCore<TContractState> {
    /// Acquire the Ekubo singleton lock; triggers locked() callback on the caller
    fn lock(ref self: TContractState, data: Span<felt252>) -> Span<felt252>;

    /// Execute a swap within a locked context
    fn swap(ref self: TContractState, pool_key: PoolKey, params: SwapParameters) -> Delta;

    /// Pay tokens owed to Ekubo Core (settle debit)
    fn pay(ref self: TContractState, token: ContractAddress);

    /// Withdraw tokens owed to caller from Ekubo Core (claim credit)
    fn withdraw(
        ref self: TContractState,
        token: ContractAddress,
        recipient: ContractAddress,
        amount: u128,
    );
}

// ============================================================================
// Privacy Pool Interface (deposit + withdraw)
// ============================================================================

#[starknet::interface]
trait IPrivacyPool<TContractState> {
    fn pp_deposit(
        ref self: TContractState,
        commitment: felt252,
        amount_commitment: ECPoint,
        asset_id: felt252,
        amount: u256,
        range_proof_data: Span<felt252>,
    ) -> u64;

    fn pp_withdraw(ref self: TContractState, proof: PPWithdrawalProof) -> bool;
}

// ============================================================================
// ERC20 Interface (approve + transfer)
// ============================================================================

use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

// ============================================================================
// Events
// ============================================================================

#[derive(Drop, starknet::Event)]
pub struct ShieldedSwapExecuted {
    #[key]
    pub swap_id: u64,
    pub source_pool: ContractAddress,
    pub dest_pool: ContractAddress,
    pub input_token: ContractAddress,
    pub output_token: ContractAddress,
    pub input_amount: u256,
    pub output_amount: u256,
    pub timestamp: u64,
}

#[derive(Drop, starknet::Event)]
pub struct PoolRegistered {
    #[key]
    pub token: ContractAddress,
    pub pool: ContractAddress,
}

// ============================================================================
// Contract
// ============================================================================

#[starknet::contract]
pub mod ShieldedSwapRouter {
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map,
    };
    use core::num::traits::Zero;
    use core::array::ArrayTrait;
    use core::serde::Serde;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    use super::{
        ShieldedSwapRequest, PoolKey, SwapParameters, Delta, i129,
        IEkuboCoreDispatcher, IEkuboCoreDispatcherTrait,
        IPrivacyPoolDispatcher, IPrivacyPoolDispatcherTrait,
        ShieldedSwapExecuted, PoolRegistered,
    };

    // ========================================================================
    // Storage
    // ========================================================================

    #[storage]
    struct Storage {
        owner: ContractAddress,
        ekubo_core: ContractAddress,
        pool_registry: Map<ContractAddress, ContractAddress>, // token → privacy pool
        swap_count: u64,
        is_locked: bool, // reentrancy guard
    }

    // ========================================================================
    // Events
    // ========================================================================

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ShieldedSwapExecuted: ShieldedSwapExecuted,
        PoolRegistered: PoolRegistered,
    }

    // ========================================================================
    // Constructor
    // ========================================================================

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        ekubo_core: ContractAddress,
    ) {
        assert!(!owner.is_zero(), "Owner cannot be zero");
        assert!(!ekubo_core.is_zero(), "Ekubo Core cannot be zero");
        self.owner.write(owner);
        self.ekubo_core.write(ekubo_core);
        self.swap_count.write(0);
        self.is_locked.write(false);
    }

    // ========================================================================
    // External Functions
    // ========================================================================

    #[abi(embed_v0)]
    impl ShieldedSwapRouterImpl of super::IShieldedSwapRouter<ContractState> {
        /// Entry point: initiate a shielded swap by locking Ekubo Core.
        /// The actual swap logic runs inside the locked() callback.
        fn shielded_swap(ref self: ContractState, request: ShieldedSwapRequest) {
            // Reentrancy guard
            assert!(!self.is_locked.read(), "Reentrancy: already locked");
            self.is_locked.write(true);

            // Validate: withdrawal proof recipient must be THIS contract
            let self_address = get_contract_address();
            assert!(
                request.withdrawal_proof.recipient == self_address,
                "Withdrawal recipient must be router"
            );

            // Validate: pools are registered
            assert!(!request.source_pool.is_zero(), "Source pool is zero");
            assert!(!request.dest_pool.is_zero(), "Dest pool is zero");

            // Serialize the request into calldata for the locked() callback
            let mut calldata = ArrayTrait::new();
            request.serialize(ref calldata);

            // Lock Ekubo Core — this triggers our locked() callback
            let core = IEkuboCoreDispatcher {
                contract_address: self.ekubo_core.read()
            };
            core.lock(calldata.span());

            // Clear reentrancy guard
            self.is_locked.write(false);
        }

        /// Ekubo ILocker callback — executes the atomic swap flow.
        /// Called by Ekubo Core after lock() is invoked.
        fn locked(
            ref self: ContractState,
            id: u32,
            data: Span<felt252>,
        ) -> Span<felt252> {
            // Only Ekubo Core can call this
            let caller = get_caller_address();
            assert!(caller == self.ekubo_core.read(), "Only Ekubo Core can call locked()");

            // Deserialize the swap request from calldata
            let mut data_span = data;
            let request = Serde::<ShieldedSwapRequest>::deserialize(ref data_span)
                .expect('Failed to deserialize request');

            let self_address = get_contract_address();
            let core_address = self.ekubo_core.read();

            // ================================================================
            // Step 1: Withdraw from source privacy pool
            // ================================================================
            // The withdrawal proof has recipient = router address.
            // This transfers input tokens from the privacy pool to the router.
            let source_pool = IPrivacyPoolDispatcher {
                contract_address: request.source_pool
            };
            let input_amount = request.withdrawal_proof.amount;
            let withdraw_success = source_pool.pp_withdraw(request.withdrawal_proof);
            assert!(withdraw_success, "Privacy pool withdrawal failed");

            // Determine input/output tokens from pool key
            let (input_token, output_token) = if request.swap_params.is_token1 {
                (request.pool_key.token0, request.pool_key.token1)
            } else {
                (request.pool_key.token1, request.pool_key.token0)
            };

            // ================================================================
            // Step 2: Approve Ekubo Core to spend input tokens
            // ================================================================
            let input_erc20 = IERC20Dispatcher { contract_address: input_token };
            input_erc20.approve(core_address, input_amount);

            // ================================================================
            // Step 3: Execute swap via Ekubo
            // ================================================================
            let core = IEkuboCoreDispatcher { contract_address: core_address };
            let delta = core.swap(request.pool_key, request.swap_params);

            // ================================================================
            // Step 4: Settle with Ekubo — pay input tokens, withdraw output
            // ================================================================
            // Pay the input token (router owes this to Ekubo after the swap)
            core.pay(input_token);

            // Calculate output amount from delta
            let output_amount_i129 = if request.swap_params.is_token1 {
                delta.amount1
            } else {
                delta.amount0
            };

            // Output should be negative delta (we receive tokens)
            // In Ekubo, negative delta means tokens are owed TO us
            assert!(output_amount_i129.sign, "Expected negative delta for output");
            let output_amount_u128 = output_amount_i129.mag;
            let output_amount_u256: u256 = output_amount_u128.into();

            // Slippage protection
            assert!(
                output_amount_u256 >= request.min_amount_out,
                "Slippage: output below minimum"
            );

            // Withdraw output tokens from Ekubo Core to router
            core.withdraw(output_token, self_address, output_amount_u128);

            // ================================================================
            // Step 5: Deposit output tokens into destination privacy pool
            // ================================================================
            let output_erc20 = IERC20Dispatcher { contract_address: output_token };
            output_erc20.approve(request.dest_pool, output_amount_u256);

            let dest_pool = IPrivacyPoolDispatcher {
                contract_address: request.dest_pool
            };
            dest_pool.pp_deposit(
                request.deposit_commitment,
                request.deposit_amount_commitment,
                request.deposit_asset_id,
                output_amount_u256,
                request.deposit_range_proof,
            );

            // ================================================================
            // Step 6: Update statistics and emit event
            // ================================================================
            let swap_id = self.swap_count.read() + 1;
            self.swap_count.write(swap_id);

            self.emit(ShieldedSwapExecuted {
                swap_id,
                source_pool: request.source_pool,
                dest_pool: request.dest_pool,
                input_token,
                output_token,
                input_amount,
                output_amount: output_amount_u256,
                timestamp: get_block_timestamp(),
            });

            // Return empty — Ekubo expects Span<felt252> return
            ArrayTrait::new().span()
        }

        /// Admin: register a privacy pool for a token
        fn register_pool(
            ref self: ContractState,
            token: ContractAddress,
            pool: ContractAddress,
        ) {
            self._assert_owner();
            assert!(!token.is_zero(), "Token address cannot be zero");
            assert!(!pool.is_zero(), "Pool address cannot be zero");

            self.pool_registry.write(token, pool);

            self.emit(PoolRegistered { token, pool });
        }

        /// Admin: update Ekubo Core address
        fn set_ekubo_core(ref self: ContractState, core: ContractAddress) {
            self._assert_owner();
            assert!(!core.is_zero(), "Core address cannot be zero");
            self.ekubo_core.write(core);
        }

        /// View: get registered privacy pool for a token
        fn get_pool(self: @ContractState, token: ContractAddress) -> ContractAddress {
            self.pool_registry.read(token)
        }

        /// View: total successful shielded swaps
        fn get_swap_count(self: @ContractState) -> u64 {
            self.swap_count.read()
        }

        /// View: Ekubo Core address
        fn get_ekubo_core(self: @ContractState) -> ContractAddress {
            self.ekubo_core.read()
        }
    }

    // ========================================================================
    // Internal Functions
    // ========================================================================

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn _assert_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Caller is not owner");
        }
    }
}
