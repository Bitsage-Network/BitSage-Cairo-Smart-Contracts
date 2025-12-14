// =============================================================================
// L1 BRIDGE CONTRACT - BitSage Network
// =============================================================================
//
// Starknet ↔ L1 (Ethereum) bridge for SAGE token:
// - Deposit SAGE on L1 → mint on Starknet
// - Burn on Starknet → withdraw on L1
// - Native USDC bridging support
// - Multi-token support
//
// Architecture:
// ┌─────────────────┐         ┌─────────────────┐
// │   Ethereum L1   │         │    Starknet     │
// │                 │         │                 │
// │  L1Bridge.sol   │◄───────►│  L1Bridge.cairo │
// │  - deposit()    │  L1↔L2  │  - withdraw()   │
// │  - withdraw()   │ message │  - deposit()    │
// │                 │         │                 │
// └─────────────────┘         └─────────────────┘
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Data Types
// =============================================================================

/// Bridge configuration for a token
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct BridgedToken {
    /// L1 token address (as felt252)
    pub l1_address: felt252,
    /// L2 (Starknet) token address
    pub l2_address: ContractAddress,
    /// Is this token supported
    pub is_supported: bool,
    /// Total deposited (L1 → L2)
    pub total_deposited: u256,
    /// Total withdrawn (L2 → L1)
    pub total_withdrawn: u256,
    /// Minimum bridge amount
    pub min_amount: u256,
    /// Maximum bridge amount per tx
    pub max_amount: u256,
    /// Bridge fee (basis points)
    pub fee_bps: u16,
}

/// Pending withdrawal
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct PendingWithdrawal {
    /// User requesting withdrawal
    pub user: ContractAddress,
    /// L1 recipient address
    pub l1_recipient: felt252,
    /// Token being withdrawn
    pub token: ContractAddress,
    /// Amount
    pub amount: u256,
    /// Timestamp requested
    pub requested_at: u64,
    /// Status: 0=pending, 1=processed, 2=cancelled
    pub status: u8,
}

/// Bridge statistics
#[derive(Copy, Drop, Serde)]
pub struct BridgeStats {
    pub total_deposits: u256,
    pub total_withdrawals: u256,
    pub pending_withdrawals: u64,
    pub total_fees_collected: u256,
    pub unique_users: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IL1Bridge<TContractState> {
    // === User Functions ===
    /// Handle L1 deposit message (called by Starknet messaging)
    fn handle_deposit(
        ref self: TContractState,
        from_address: felt252,  // L1 sender
        l1_token: felt252,
        recipient: ContractAddress,
        amount: u256,
    );
    
    /// Initiate withdrawal to L1
    fn initiate_withdrawal(
        ref self: TContractState,
        token: ContractAddress,
        l1_recipient: felt252,
        amount: u256,
    );
    
    /// Cancel pending withdrawal (before finalization)
    fn cancel_withdrawal(ref self: TContractState, withdrawal_id: u64);
    
    // === Admin Functions ===
    /// Add supported token
    fn add_token(
        ref self: TContractState,
        l1_address: felt252,
        l2_address: ContractAddress,
        min_amount: u256,
        max_amount: u256,
        fee_bps: u16,
    );
    
    /// Update token config
    fn update_token_config(
        ref self: TContractState,
        l2_address: ContractAddress,
        min_amount: u256,
        max_amount: u256,
        fee_bps: u16,
    );
    
    /// Set L1 bridge address
    fn set_l1_bridge(ref self: TContractState, l1_bridge: felt252);
    
    /// Pause bridge
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);
    
    /// Withdraw collected fees
    fn withdraw_fees(ref self: TContractState, token: ContractAddress, to: ContractAddress);
    
    // === View Functions ===
    fn get_token_config(self: @TContractState, l2_address: ContractAddress) -> BridgedToken;
    fn get_withdrawal(self: @TContractState, withdrawal_id: u64) -> PendingWithdrawal;
    fn get_bridge_stats(self: @TContractState) -> BridgeStats;
    fn get_l1_bridge(self: @TContractState) -> felt252;
    fn is_paused(self: @TContractState) -> bool;
    fn get_pending_withdrawal_count(self: @TContractState, user: ContractAddress) -> u64;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod L1Bridge {
    use super::{IL1Bridge, BridgedToken, PendingWithdrawal, BridgeStats};
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // =========================================================================
    // Constants
    // =========================================================================
    
    /// Starknet Core contract (for L1 messaging)
    const STARKNET_CORE: felt252 = 0x0; // Set during deployment
    
    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// L1 bridge contract address
        l1_bridge: felt252,
        /// Token configs: L2 address -> config
        tokens: Map<ContractAddress, BridgedToken>,
        /// L1 -> L2 address mapping
        l1_to_l2_token: Map<felt252, ContractAddress>,
        /// Pending withdrawals
        withdrawals: Map<u64, PendingWithdrawal>,
        /// Next withdrawal ID
        next_withdrawal_id: u64,
        /// User withdrawal count
        user_withdrawal_count: Map<ContractAddress, u64>,
        /// Total unique users
        total_users: u64,
        /// Collected fees per token
        collected_fees: Map<ContractAddress, u256>,
        /// Is bridge paused
        paused: bool,
        /// Total stats
        total_deposits: u256,
        total_withdrawals: u256,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        DepositHandled: DepositHandled,
        WithdrawalInitiated: WithdrawalInitiated,
        WithdrawalCancelled: WithdrawalCancelled,
        TokenAdded: TokenAdded,
        L1BridgeUpdated: L1BridgeUpdated,
        BridgePaused: BridgePaused,
        BridgeUnpaused: BridgeUnpaused,
    }

    #[derive(Drop, starknet::Event)]
    struct DepositHandled {
        #[key]
        from_l1: felt252,
        #[key]
        recipient: ContractAddress,
        token: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawalInitiated {
        #[key]
        withdrawal_id: u64,
        #[key]
        user: ContractAddress,
        l1_recipient: felt252,
        token: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawalCancelled {
        #[key]
        withdrawal_id: u64,
        user: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct TokenAdded {
        l1_address: felt252,
        l2_address: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct L1BridgeUpdated {
        old_bridge: felt252,
        new_bridge: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct BridgePaused {}

    #[derive(Drop, starknet::Event)]
    struct BridgeUnpaused {}

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress, l1_bridge: felt252) {
        self.owner.write(owner);
        self.l1_bridge.write(l1_bridge);
        self.next_withdrawal_id.write(0);
        self.total_users.write(0);
        self.paused.write(false);
        self.total_deposits.write(0);
        self.total_withdrawals.write(0);
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl L1BridgeImpl of IL1Bridge<ContractState> {
        fn handle_deposit(
            ref self: ContractState,
            from_address: felt252,
            l1_token: felt252,
            recipient: ContractAddress,
            amount: u256,
        ) {
            // Verify caller is Starknet messaging system or authorized
            // In production, this would verify the L1 message
            assert(!self.paused.read(), 'Bridge paused');
            
            // Get L2 token
            let l2_token = self.l1_to_l2_token.read(l1_token);
            let zero: ContractAddress = 0.try_into().unwrap();
            assert(l2_token != zero, 'Token not supported');
            
            let mut token_config = self.tokens.read(l2_token);
            assert(token_config.is_supported, 'Token not supported');
            assert(amount >= token_config.min_amount, 'Amount too small');
            assert(amount <= token_config.max_amount, 'Amount too large');
            
            // Calculate fee
            let fee = (amount * token_config.fee_bps.into()) / 10000;
            let net_amount = amount - fee;
            
            // Mint/transfer tokens to recipient
            let token = IERC20Dispatcher { contract_address: l2_token };
            // In production, would call mint() on bridged token
            // For now, transfer from bridge reserve
            token.transfer(recipient, net_amount);
            
            // Update stats
            token_config.total_deposited = token_config.total_deposited + amount;
            self.tokens.write(l2_token, token_config);
            
            let fees = self.collected_fees.read(l2_token);
            self.collected_fees.write(l2_token, fees + fee);
            
            let total = self.total_deposits.read();
            self.total_deposits.write(total + amount);
            
            self.emit(DepositHandled {
                from_l1: from_address,
                recipient,
                token: l2_token,
                amount: net_amount,
            });
        }

        fn initiate_withdrawal(
            ref self: ContractState,
            token: ContractAddress,
            l1_recipient: felt252,
            amount: u256,
        ) {
            assert(!self.paused.read(), 'Bridge paused');
            
            let caller = get_caller_address();
            let token_config = self.tokens.read(token);
            
            assert(token_config.is_supported, 'Token not supported');
            assert(amount >= token_config.min_amount, 'Amount too small');
            assert(amount <= token_config.max_amount, 'Amount too large');
            
            // Calculate fee
            let fee = (amount * token_config.fee_bps.into()) / 10000;
            let net_amount = amount - fee;
            
            // Transfer tokens from user to bridge
            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer_from(caller, starknet::get_contract_address(), amount);
            
            // Create withdrawal record
            let withdrawal_id = self.next_withdrawal_id.read();
            let withdrawal = PendingWithdrawal {
                user: caller,
                l1_recipient,
                token,
                amount: net_amount,
                requested_at: get_block_timestamp(),
                status: 0, // Pending
            };
            
            self.withdrawals.write(withdrawal_id, withdrawal);
            self.next_withdrawal_id.write(withdrawal_id + 1);
            
            // Update user count
            let user_count = self.user_withdrawal_count.read(caller);
            if user_count == 0 {
                let total = self.total_users.read();
                self.total_users.write(total + 1);
            }
            self.user_withdrawal_count.write(caller, user_count + 1);
            
            // Collect fee
            let fees = self.collected_fees.read(token);
            self.collected_fees.write(token, fees + fee);
            
            // Update stats
            let mut config = self.tokens.read(token);
            config.total_withdrawn = config.total_withdrawn + amount;
            self.tokens.write(token, config);
            
            let total = self.total_withdrawals.read();
            self.total_withdrawals.write(total + amount);
            
            // TODO: Send L1 message to complete withdrawal
            // starknet::send_message_to_l1_syscall(l1_bridge, payload)
            
            self.emit(WithdrawalInitiated {
                withdrawal_id,
                user: caller,
                l1_recipient,
                token,
                amount: net_amount,
            });
        }

        fn cancel_withdrawal(ref self: ContractState, withdrawal_id: u64) {
            let caller = get_caller_address();
            let mut withdrawal = self.withdrawals.read(withdrawal_id);
            
            assert(withdrawal.user == caller, 'Not your withdrawal');
            assert(withdrawal.status == 0, 'Cannot cancel');
            
            // Return tokens
            let token = IERC20Dispatcher { contract_address: withdrawal.token };
            token.transfer(caller, withdrawal.amount);
            
            // Update status
            withdrawal.status = 2; // Cancelled
            self.withdrawals.write(withdrawal_id, withdrawal);
            
            self.emit(WithdrawalCancelled { withdrawal_id, user: caller });
        }

        fn add_token(
            ref self: ContractState,
            l1_address: felt252,
            l2_address: ContractAddress,
            min_amount: u256,
            max_amount: u256,
            fee_bps: u16,
        ) {
            self._only_owner();
            
            assert(fee_bps <= 1000, 'Fee too high'); // Max 10%
            
            let token = BridgedToken {
                l1_address,
                l2_address,
                is_supported: true,
                total_deposited: 0,
                total_withdrawn: 0,
                min_amount,
                max_amount,
                fee_bps,
            };
            
            self.tokens.write(l2_address, token);
            self.l1_to_l2_token.write(l1_address, l2_address);
            
            self.emit(TokenAdded { l1_address, l2_address });
        }

        fn update_token_config(
            ref self: ContractState,
            l2_address: ContractAddress,
            min_amount: u256,
            max_amount: u256,
            fee_bps: u16,
        ) {
            self._only_owner();
            
            let mut token = self.tokens.read(l2_address);
            assert(token.is_supported, 'Token not found');
            assert(fee_bps <= 1000, 'Fee too high');
            
            token.min_amount = min_amount;
            token.max_amount = max_amount;
            token.fee_bps = fee_bps;
            
            self.tokens.write(l2_address, token);
        }

        fn set_l1_bridge(ref self: ContractState, l1_bridge: felt252) {
            self._only_owner();
            let old = self.l1_bridge.read();
            self.l1_bridge.write(l1_bridge);
            self.emit(L1BridgeUpdated { old_bridge: old, new_bridge: l1_bridge });
        }

        fn pause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(true);
            self.emit(BridgePaused {});
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            self.paused.write(false);
            self.emit(BridgeUnpaused {});
        }

        fn withdraw_fees(ref self: ContractState, token: ContractAddress, to: ContractAddress) {
            self._only_owner();
            let fees = self.collected_fees.read(token);
            if fees > 0 {
                self.collected_fees.write(token, 0);
                let token_dispatcher = IERC20Dispatcher { contract_address: token };
                token_dispatcher.transfer(to, fees);
            }
        }

        fn get_token_config(self: @ContractState, l2_address: ContractAddress) -> BridgedToken {
            self.tokens.read(l2_address)
        }

        fn get_withdrawal(self: @ContractState, withdrawal_id: u64) -> PendingWithdrawal {
            self.withdrawals.read(withdrawal_id)
        }

        fn get_bridge_stats(self: @ContractState) -> BridgeStats {
            BridgeStats {
                total_deposits: self.total_deposits.read(),
                total_withdrawals: self.total_withdrawals.read(),
                pending_withdrawals: self.next_withdrawal_id.read(),
                total_fees_collected: 0, // Would aggregate across tokens
                unique_users: self.total_users.read(),
            }
        }

        fn get_l1_bridge(self: @ContractState) -> felt252 {
            self.l1_bridge.read()
        }

        fn is_paused(self: @ContractState) -> bool {
            self.paused.read()
        }

        fn get_pending_withdrawal_count(self: @ContractState, user: ContractAddress) -> u64 {
            self.user_withdrawal_count.read(user)
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }
    }
}

