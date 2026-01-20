//! OTC Orderbook - Decentralized limit order book for SAGE trading
//!
//! Features:
//! - Limit orders (buy/sell at specific prices)
//! - Market orders (execute at best available price)
//! - Partial fills with remaining order tracking
//! - Order cancellation and expiration
//! - Multi-pair support (SAGE/USDC, SAGE/STRK, etc.)
//! - Maker/taker fee structure
//!
//! Design:
//! - Orders stored on-chain with efficient matching
//! - Price-time priority matching (best price first, then earliest)
//! - Events for off-chain indexing and UI updates

use starknet::{ContractAddress, ClassHash};

/// Order side (buy or sell)
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum OrderSide {
    #[default]
    Buy,   // Buying SAGE with quote token
    Sell,  // Selling SAGE for quote token
}

/// Order type
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum OrderType {
    #[default]
    Limit,   // Execute at specified price or better
    Market,  // Execute immediately at best available price
}

/// Order status
#[derive(Copy, Drop, Serde, starknet::Store, PartialEq, Default)]
pub enum OrderStatus {
    #[default]
    Open,        // Active and can be filled
    PartialFill, // Partially filled, remainder still active
    Filled,      // Completely filled
    Cancelled,   // Cancelled by user
    Expired,     // Past expiration time
}

/// Trading pair configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct TradingPair {
    /// Base token (always SAGE)
    pub base_token: ContractAddress,
    /// Quote token (USDC, STRK, etc.)
    pub quote_token: ContractAddress,
    /// Minimum order size in base token (SAGE)
    pub min_order_size: u256,
    /// Price tick size (minimum price increment)
    pub tick_size: u256,
    /// Whether pair is active for trading
    pub is_active: bool,
}

/// Order structure
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Order {
    /// Unique order ID
    pub order_id: u256,
    /// Order creator
    pub maker: ContractAddress,
    /// Trading pair ID
    pub pair_id: u8,
    /// Buy or sell
    pub side: OrderSide,
    /// Limit or market
    pub order_type: OrderType,
    /// Price per SAGE in quote token (18 decimals)
    pub price: u256,
    /// Original order amount in SAGE
    pub amount: u256,
    /// Remaining unfilled amount
    pub remaining: u256,
    /// Order status
    pub status: OrderStatus,
    /// Creation timestamp
    pub created_at: u64,
    /// Expiration timestamp (0 = no expiry)
    pub expires_at: u64,
}

/// Trade execution record
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Trade {
    /// Trade ID
    pub trade_id: u256,
    /// Maker order ID
    pub maker_order_id: u256,
    /// Taker order ID
    pub taker_order_id: u256,
    /// Maker address
    pub maker: ContractAddress,
    /// Taker address
    pub taker: ContractAddress,
    /// Execution price
    pub price: u256,
    /// SAGE amount traded
    pub amount: u256,
    /// Quote token amount
    pub quote_amount: u256,
    /// Timestamp
    pub executed_at: u64,
}

/// Orderbook configuration
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct OrderbookConfig {
    /// Maker fee in basis points (e.g., 10 = 0.1%)
    pub maker_fee_bps: u32,
    /// Taker fee in basis points (e.g., 30 = 0.3%)
    pub taker_fee_bps: u32,
    /// Default order expiration in seconds (0 = no default expiry)
    pub default_expiry_secs: u64,
    /// Maximum orders per user
    pub max_orders_per_user: u32,
    /// Whether orderbook is paused
    pub paused: bool,
}

#[starknet::interface]
pub trait IOTCOrderbook<TContractState> {
    // =========================================================================
    // Order Management
    // =========================================================================

    /// Place a limit order
    /// @param pair_id: Trading pair (0 = SAGE/USDC, 1 = SAGE/STRK, etc.)
    /// @param side: Buy or Sell
    /// @param price: Price per SAGE in quote token (18 decimals)
    /// @param amount: SAGE amount
    /// @param expires_in: Seconds until expiration (0 = use default)
    /// @return order_id: The created order ID
    fn place_limit_order(
        ref self: TContractState,
        pair_id: u8,
        side: OrderSide,
        price: u256,
        amount: u256,
        expires_in: u64
    ) -> u256;

    /// Place a market order (executes immediately at best price)
    /// @param pair_id: Trading pair
    /// @param side: Buy or Sell
    /// @param amount: SAGE amount (for sell) or max quote amount (for buy)
    /// @return filled_amount: Amount of SAGE filled
    fn place_market_order(
        ref self: TContractState,
        pair_id: u8,
        side: OrderSide,
        amount: u256
    ) -> u256;

    /// Cancel an open order
    fn cancel_order(ref self: TContractState, order_id: u256);

    /// Cancel all open orders for caller
    fn cancel_all_orders(ref self: TContractState);

    // =========================================================================
    // Batch Operations (gas efficient)
    // =========================================================================

    /// Place multiple limit orders in one transaction
    /// @param orders: Array of (pair_id, side, price, amount, expires_in)
    /// @return order_ids: Array of created order IDs
    fn batch_place_orders(
        ref self: TContractState,
        orders: Array<(u8, OrderSide, u256, u256, u64)>
    ) -> Array<u256>;

    /// Cancel multiple orders in one transaction
    fn batch_cancel_orders(ref self: TContractState, order_ids: Array<u256>);

    // =========================================================================
    // View Functions
    // =========================================================================

    /// Get order details
    fn get_order(self: @TContractState, order_id: u256) -> Order;

    /// Get user's open orders
    fn get_user_orders(self: @TContractState, user: ContractAddress) -> Array<u256>;

    /// Get best bid price for a pair
    fn get_best_bid(self: @TContractState, pair_id: u8) -> u256;

    /// Get best ask price for a pair
    fn get_best_ask(self: @TContractState, pair_id: u8) -> u256;

    /// Get spread (best_ask - best_bid)
    fn get_spread(self: @TContractState, pair_id: u8) -> u256;

    /// Get trading pair info
    fn get_pair(self: @TContractState, pair_id: u8) -> TradingPair;

    /// Get orderbook config
    fn get_config(self: @TContractState) -> OrderbookConfig;

    /// Get orderbook stats
    fn get_stats(self: @TContractState) -> (u256, u256, u256, u256);  // total_orders, total_trades, total_volume_sage, total_volume_usd

    // =========================================================================
    // Price Analytics Functions
    // =========================================================================

    /// Get Time-Weighted Average Price for a pair
    fn get_twap(self: @TContractState, pair_id: u8) -> u256;

    /// Get 24h stats: (volume, high, low, last_price)
    fn get_24h_stats(self: @TContractState, pair_id: u8) -> (u256, u256, u256, u256);

    /// Get last trade: (price, amount, timestamp)
    fn get_last_trade(self: @TContractState, pair_id: u8) -> (u256, u256, u64);

    /// Get price snapshot at index: (price, timestamp)
    fn get_price_snapshot(self: @TContractState, pair_id: u8, index: u32) -> (u256, u64);

    /// Get count of price snapshots
    fn get_snapshot_count(self: @TContractState, pair_id: u8) -> u32;

    // =========================================================================
    // Trustless Orderbook View Functions
    // =========================================================================

    /// Get total order count (for iteration)
    fn get_order_count(self: @TContractState) -> u256;

    /// Get total trade count
    fn get_trade_count(self: @TContractState) -> u256;

    /// Get orderbook depth - aggregated price levels with total amounts
    /// Returns (bids, asks) where each is Array<(price, total_amount, order_count)>
    fn get_orderbook_depth(
        self: @TContractState,
        pair_id: u8,
        max_levels: u32
    ) -> (Array<(u256, u256, u32)>, Array<(u256, u256, u32)>);

    /// Get active orders for a pair (paginated)
    /// Returns array of Order structs
    fn get_active_orders(
        self: @TContractState,
        pair_id: u8,
        offset: u32,
        limit: u32
    ) -> Array<Order>;

    /// Get trade history for a pair (paginated, newest first)
    fn get_trade_history(
        self: @TContractState,
        pair_id: u8,
        offset: u32,
        limit: u32
    ) -> Array<Trade>;

    /// Get orders at a specific price level
    fn get_orders_at_price(
        self: @TContractState,
        pair_id: u8,
        side: OrderSide,
        price: u256,
        limit: u32
    ) -> Array<Order>;

    // =========================================================================
    // Admin Functions
    // =========================================================================

    /// Add a new trading pair
    fn add_pair(ref self: TContractState, quote_token: ContractAddress, min_order_size: u256, tick_size: u256);

    /// Update pair status
    fn set_pair_active(ref self: TContractState, pair_id: u8, is_active: bool);

    /// Update orderbook config
    fn set_config(ref self: TContractState, config: OrderbookConfig);

    /// Pause/unpause
    fn pause(ref self: TContractState);
    fn unpause(ref self: TContractState);

    /// Set fee recipient
    fn set_fee_recipient(ref self: TContractState, recipient: ContractAddress);

    /// Withdraw collected fees
    fn withdraw_fees(ref self: TContractState, token: ContractAddress);

    /// Set referral system contract for reward distribution
    fn set_referral_system(ref self: TContractState, referral_system: ContractAddress);

    // =========================================================================
    // Upgradability Functions
    // =========================================================================

    /// Schedule a contract upgrade with timelock delay
    fn schedule_upgrade(ref self: TContractState, new_class_hash: ClassHash);

    /// Execute a scheduled upgrade after timelock has passed
    fn execute_upgrade(ref self: TContractState);

    /// Cancel a scheduled upgrade
    fn cancel_upgrade(ref self: TContractState);

    /// Get upgrade info: (pending_hash, scheduled_at, execute_after, delay)
    fn get_upgrade_info(self: @TContractState) -> (ClassHash, u64, u64, u64);

    /// Set upgrade timelock delay (owner only)
    fn set_upgrade_delay(ref self: TContractState, delay: u64);
}

#[starknet::contract]
mod OTCOrderbook {
    use super::{
        IOTCOrderbook, OrderSide, OrderType, OrderStatus,
        TradingPair, Order, Trade, OrderbookConfig
    };
    use starknet::{ContractAddress, ClassHash, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use starknet::SyscallResultTrait;
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use sage_contracts::growth::referral_system::{IReferralSystemDispatcher, IReferralSystemDispatcherTrait};

    const BPS_DENOMINATOR: u256 = 10000;
    const MAX_PAIRS: u8 = 10;
    const MAX_ORDER_SIZE: u256 = 10000000_000000000000000000; // 10M SAGE max per order
    const UPGRADE_DELAY: u64 = 172800; // 2 days timelock for upgrades

    #[storage]
    struct Storage {
        owner: ContractAddress,
        sage_token: ContractAddress,
        fee_recipient: ContractAddress,
        referral_system: ContractAddress,  // Optional referral integration
        config: OrderbookConfig,

        // Trading pairs
        pairs: Map<u8, TradingPair>,
        pair_count: u8,

        // Orders
        orders: Map<u256, Order>,
        order_count: u256,

        // User orders (user -> order_id array simulation via count + map)
        user_order_count: Map<ContractAddress, u32>,
        user_orders: Map<(ContractAddress, u32), u256>,  // (user, index) -> order_id

        // Order book structure (pair_id, side, price) -> order queue
        // Simplified: we track best bid/ask per pair
        best_bid: Map<u8, u256>,      // pair_id -> best bid price
        best_ask: Map<u8, u256>,      // pair_id -> best ask price

        // Price level order lists (pair_id, side, price, index) -> order_id
        price_level_count: Map<(u8, felt252, u256), u32>,
        price_level_orders: Map<(u8, felt252, u256, u32), u256>,

        // Trades
        trades: Map<u256, Trade>,
        trade_count: u256,

        // Stats
        total_volume_sage: u256,
        total_volume_quote: Map<u8, u256>,  // per pair

        // Collected fees
        collected_fees: Map<ContractAddress, u256>,  // token -> amount

        // === TWAP & PRICE ANALYTICS ===
        // Last trade data per pair
        last_trade_price: Map<u8, u256>,
        last_trade_amount: Map<u8, u256>,
        last_trade_time: Map<u8, u64>,

        // TWAP tracking (Time-Weighted Average Price)
        // Cumulative price*time for TWAP calculation
        twap_cumulative: Map<u8, u256>,
        twap_last_update: Map<u8, u64>,
        twap_last_price: Map<u8, u256>,

        // 24h rolling window tracking
        volume_24h: Map<u8, u256>,             // pair_id -> 24h volume
        volume_24h_reset_time: Map<u8, u64>,   // pair_id -> last reset timestamp
        high_24h: Map<u8, u256>,               // pair_id -> 24h high price
        low_24h: Map<u8, u256>,                // pair_id -> 24h low price

        // Price history snapshots (hourly)
        price_snapshot_count: Map<u8, u32>,                    // pair_id -> count
        price_snapshots: Map<(u8, u32), (u256, u64)>,          // (pair_id, index) -> (price, timestamp)

        // === UPGRADABILITY ===
        pending_upgrade: ClassHash,
        upgrade_scheduled_at: u64,
        upgrade_delay: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        OrderPlaced: OrderPlaced,
        OrderCancelled: OrderCancelled,
        OrderFilled: OrderFilled,
        TradeExecuted: TradeExecuted,
        PairAdded: PairAdded,
        ConfigUpdated: ConfigUpdated,
        UpgradeScheduled: UpgradeScheduled,
        UpgradeExecuted: UpgradeExecuted,
        UpgradeCancelled: UpgradeCancelled,
    }

    #[derive(Drop, starknet::Event)]
    struct OrderPlaced {
        #[key]
        order_id: u256,
        #[key]
        maker: ContractAddress,
        pair_id: u8,
        side: OrderSide,
        order_type: OrderType,
        price: u256,
        amount: u256,
        expires_at: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct OrderCancelled {
        #[key]
        order_id: u256,
        #[key]
        maker: ContractAddress,
        remaining_amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct OrderFilled {
        #[key]
        order_id: u256,
        filled_amount: u256,
        remaining_amount: u256,
        status: OrderStatus,
    }

    #[derive(Drop, starknet::Event)]
    struct TradeExecuted {
        #[key]
        trade_id: u256,
        #[key]
        maker_order_id: u256,
        #[key]
        taker_order_id: u256,
        maker: ContractAddress,
        taker: ContractAddress,
        price: u256,
        amount: u256,
        quote_amount: u256,
        maker_fee: u256,
        taker_fee: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct PairAdded {
        pair_id: u8,
        quote_token: ContractAddress,
        min_order_size: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct ConfigUpdated {
        maker_fee_bps: u32,
        taker_fee_bps: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeScheduled {
        #[key]
        new_class_hash: ClassHash,
        scheduled_by: ContractAddress,
        execute_after: u64,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeExecuted {
        old_class_hash: ClassHash,
        new_class_hash: ClassHash,
        executed_by: ContractAddress,
        timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct UpgradeCancelled {
        cancelled_class_hash: ClassHash,
        cancelled_by: ContractAddress,
        timestamp: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        fee_recipient: ContractAddress,
        usdc_token: ContractAddress,
    ) {
        assert!(!owner.is_zero(), "OTC: invalid owner");
        assert!(!sage_token.is_zero(), "OTC: invalid SAGE token");
        assert!(!fee_recipient.is_zero(), "OTC: invalid fee recipient");
        assert!(!usdc_token.is_zero(), "OTC: invalid USDC token");

        self.owner.write(owner);
        self.sage_token.write(sage_token);
        self.fee_recipient.write(fee_recipient);

        // Default config
        self.config.write(OrderbookConfig {
            maker_fee_bps: 10,           // 0.1% maker fee
            taker_fee_bps: 30,           // 0.3% taker fee
            default_expiry_secs: 604800, // 7 days
            max_orders_per_user: 100,
            paused: false,
        });

        // Add default SAGE/USDC pair
        let pair = TradingPair {
            base_token: sage_token,
            quote_token: usdc_token,
            min_order_size: 10_000000000000000000,  // 10 SAGE minimum
            tick_size: 1000000000000000,             // 0.001 USD tick
            is_active: true,
        };
        self.pairs.write(0, pair);
        self.pair_count.write(1);

        // Initialize best bid/ask to 0 (no orders)
        self.best_bid.write(0, 0);
        self.best_ask.write(0, 0);

        self.order_count.write(0);
        self.trade_count.write(0);

        // Initialize upgrade delay
        self.upgrade_delay.write(UPGRADE_DELAY);
    }

    #[abi(embed_v0)]
    impl OTCOrderbookImpl of IOTCOrderbook<ContractState> {
        fn place_limit_order(
            ref self: ContractState,
            pair_id: u8,
            side: OrderSide,
            price: u256,
            amount: u256,
            expires_in: u64
        ) -> u256 {
            self._require_not_paused();
            self._place_limit_order_internal(pair_id, side, price, amount, expires_in)
        }

        fn place_market_order(
            ref self: ContractState,
            pair_id: u8,
            side: OrderSide,
            amount: u256
        ) -> u256 {
            self._require_not_paused();

            let caller = get_caller_address();
            let now = get_block_timestamp();

            // Validate pair
            let pair = self.pairs.read(pair_id);
            assert!(pair.is_active, "Trading pair not active");

            // For market orders, we match against existing orders
            // Get best price on opposite side
            let best_price = match side {
                OrderSide::Buy => self.best_ask.read(pair_id),
                OrderSide::Sell => self.best_bid.read(pair_id),
            };

            assert!(best_price > 0, "No liquidity available");

            // Create order (will be immediately matched)
            let order_id = self.order_count.read() + 1;
            self.order_count.write(order_id);

            let order = Order {
                order_id,
                maker: caller,
                pair_id,
                side,
                order_type: OrderType::Market,
                price: best_price,  // Use best available price
                amount,
                remaining: amount,
                status: OrderStatus::Open,
                created_at: now,
                expires_at: now + 60,  // Market orders expire in 1 minute if not filled
            };

            // Lock funds
            self._lock_order_funds(caller, @pair, @order);

            // Store order
            self.orders.write(order_id, order);

            self.emit(OrderPlaced {
                order_id,
                maker: caller,
                pair_id,
                side,
                order_type: OrderType::Market,
                price: best_price,
                amount,
                expires_at: now + 60,
            });

            // Execute market order immediately
            let filled = self._execute_market_order(order_id);

            filled
        }

        fn cancel_order(ref self: ContractState, order_id: u256) {
            let caller = get_caller_address();
            let mut order = self.orders.read(order_id);

            assert!(order.maker == caller, "Not order owner");
            assert!(
                order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill,
                "Order not cancellable"
            );

            let remaining = order.remaining;

            // Refund remaining tokens
            self._refund_order(order_id);

            // Update order status
            order.status = OrderStatus::Cancelled;
            order.remaining = 0;
            self.orders.write(order_id, order);

            // Remove from price level
            self._remove_from_price_level(order.pair_id, order.side, order.price, order_id);

            self.emit(OrderCancelled {
                order_id,
                maker: caller,
                remaining_amount: remaining,
            });
        }

        fn cancel_all_orders(ref self: ContractState) {
            let caller = get_caller_address();
            let order_count = self.user_order_count.read(caller);

            let mut i: u32 = 0;
            loop {
                if i >= order_count {
                    break;
                }

                let order_id = self.user_orders.read((caller, i));
                let order = self.orders.read(order_id);

                if order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill {
                    // Cancel this order
                    self._refund_order(order_id);

                    let mut updated_order = order;
                    updated_order.status = OrderStatus::Cancelled;
                    updated_order.remaining = 0;
                    self.orders.write(order_id, updated_order);

                    self._remove_from_price_level(order.pair_id, order.side, order.price, order_id);

                    self.emit(OrderCancelled {
                        order_id,
                        maker: caller,
                        remaining_amount: order.remaining,
                    });
                }

                i += 1;
            };
        }

        // =========================================================================
        // Batch Operations
        // =========================================================================

        fn batch_place_orders(
            ref self: ContractState,
            orders: Array<(u8, OrderSide, u256, u256, u64)>
        ) -> Array<u256> {
            self._require_not_paused();

            let len = orders.len();
            assert!(len > 0, "Empty order array");
            assert!(len <= 20, "Max 20 orders per batch");

            let mut order_ids: Array<u256> = array![];
            let mut i: u32 = 0;

            loop {
                if i >= len {
                    break;
                }

                let (pair_id, side, price, amount, expires_in) = *orders.at(i);

                // Place each order (reusing existing logic)
                let order_id = self._place_limit_order_internal(pair_id, side, price, amount, expires_in);
                order_ids.append(order_id);

                i += 1;
            };

            order_ids
        }

        fn batch_cancel_orders(ref self: ContractState, order_ids: Array<u256>) {
            let len = order_ids.len();
            assert!(len > 0, "Empty order array");
            assert!(len <= 50, "Max 50 cancellations per batch");

            let caller = get_caller_address();
            let mut i: u32 = 0;

            loop {
                if i >= len {
                    break;
                }

                let order_id = *order_ids.at(i);
                let order = self.orders.read(order_id);

                // Only cancel if owned by caller and cancellable
                if order.maker == caller
                    && (order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill) {

                    let remaining = order.remaining;
                    self._refund_order(order_id);

                    let mut updated_order = order;
                    updated_order.status = OrderStatus::Cancelled;
                    updated_order.remaining = 0;
                    self.orders.write(order_id, updated_order);

                    self._remove_from_price_level(order.pair_id, order.side, order.price, order_id);

                    self.emit(OrderCancelled {
                        order_id,
                        maker: caller,
                        remaining_amount: remaining,
                    });
                }

                i += 1;
            };
        }

        fn get_order(self: @ContractState, order_id: u256) -> Order {
            self.orders.read(order_id)
        }

        fn get_user_orders(self: @ContractState, user: ContractAddress) -> Array<u256> {
            let count = self.user_order_count.read(user);
            let mut orders: Array<u256> = array![];

            let mut i: u32 = 0;
            loop {
                if i >= count {
                    break;
                }
                let order_id = self.user_orders.read((user, i));
                let order = self.orders.read(order_id);

                // Only include open or partial orders
                if order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill {
                    orders.append(order_id);
                }

                i += 1;
            };

            orders
        }

        fn get_best_bid(self: @ContractState, pair_id: u8) -> u256 {
            self.best_bid.read(pair_id)
        }

        fn get_best_ask(self: @ContractState, pair_id: u8) -> u256 {
            self.best_ask.read(pair_id)
        }

        fn get_spread(self: @ContractState, pair_id: u8) -> u256 {
            let bid = self.best_bid.read(pair_id);
            let ask = self.best_ask.read(pair_id);

            if bid == 0 || ask == 0 {
                return 0;
            }

            if ask > bid {
                ask - bid
            } else {
                0
            }
        }

        fn get_pair(self: @ContractState, pair_id: u8) -> TradingPair {
            self.pairs.read(pair_id)
        }

        fn get_config(self: @ContractState) -> OrderbookConfig {
            self.config.read()
        }

        fn get_stats(self: @ContractState) -> (u256, u256, u256, u256) {
            let total_volume_usd = self.total_volume_quote.read(0); // SAGE/USDC pair
            (
                self.order_count.read(),
                self.trade_count.read(),
                self.total_volume_sage.read(),
                total_volume_usd
            )
        }

        fn add_pair(
            ref self: ContractState,
            quote_token: ContractAddress,
            min_order_size: u256,
            tick_size: u256
        ) {
            self._only_owner();

            let pair_id = self.pair_count.read();
            assert!(pair_id < MAX_PAIRS, "Max pairs reached");

            let pair = TradingPair {
                base_token: self.sage_token.read(),
                quote_token,
                min_order_size,
                tick_size,
                is_active: true,
            };

            self.pairs.write(pair_id, pair);
            self.pair_count.write(pair_id + 1);
            self.best_bid.write(pair_id, 0);
            self.best_ask.write(pair_id, 0);

            self.emit(PairAdded {
                pair_id,
                quote_token,
                min_order_size,
            });
        }

        fn set_pair_active(ref self: ContractState, pair_id: u8, is_active: bool) {
            self._only_owner();

            let mut pair = self.pairs.read(pair_id);
            pair.is_active = is_active;
            self.pairs.write(pair_id, pair);
        }

        fn set_config(ref self: ContractState, config: OrderbookConfig) {
            self._only_owner();

            // Validate fees (max 5% each)
            assert!(config.maker_fee_bps <= 500, "Maker fee too high");
            assert!(config.taker_fee_bps <= 500, "Taker fee too high");

            self.config.write(config);

            self.emit(ConfigUpdated {
                maker_fee_bps: config.maker_fee_bps,
                taker_fee_bps: config.taker_fee_bps,
            });
        }

        fn pause(ref self: ContractState) {
            self._only_owner();
            let mut config = self.config.read();
            config.paused = true;
            self.config.write(config);
        }

        fn unpause(ref self: ContractState) {
            self._only_owner();
            let mut config = self.config.read();
            config.paused = false;
            self.config.write(config);
        }

        fn set_fee_recipient(ref self: ContractState, recipient: ContractAddress) {
            self._only_owner();
            assert!(!recipient.is_zero(), "Invalid recipient");
            self.fee_recipient.write(recipient);
        }

        fn withdraw_fees(ref self: ContractState, token: ContractAddress) {
            self._only_owner();

            let amount = self.collected_fees.read(token);
            assert!(amount > 0, "No fees to withdraw");

            self.collected_fees.write(token, 0);

            let token_dispatcher = IERC20Dispatcher { contract_address: token };
            token_dispatcher.transfer(self.fee_recipient.read(), amount);
        }

        fn set_referral_system(ref self: ContractState, referral_system: ContractAddress) {
            self._only_owner();
            self.referral_system.write(referral_system);
        }

        // =========================================================================
        // Price Analytics View Functions
        // =========================================================================

        /// Get TWAP for a pair over the observation period
        fn get_twap(self: @ContractState, pair_id: u8) -> u256 {
            let cumulative = self.twap_cumulative.read(pair_id);
            let last_update = self.twap_last_update.read(pair_id);
            let last_price = self.twap_last_price.read(pair_id);

            if last_update == 0 || last_price == 0 {
                return 0;
            }

            let current_time = get_block_timestamp();
            let time_elapsed: u256 = (current_time - last_update).into();

            // Add current period contribution
            let total_cumulative = cumulative + (last_price * time_elapsed);

            // Calculate average (use time since first observation)
            let first_update = self.volume_24h_reset_time.read(pair_id);
            if first_update == 0 {
                return last_price;
            }

            let total_time: u256 = (current_time - first_update).into();
            if total_time == 0 {
                return last_price;
            }

            total_cumulative / total_time
        }

        /// Get 24h stats for a pair: (volume, high, low, last_price)
        fn get_24h_stats(self: @ContractState, pair_id: u8) -> (u256, u256, u256, u256) {
            let volume = self.volume_24h.read(pair_id);
            let high = self.high_24h.read(pair_id);
            let low = self.low_24h.read(pair_id);
            let last_price = self.last_trade_price.read(pair_id);

            (volume, high, low, last_price)
        }

        /// Get last trade info: (price, amount, timestamp)
        fn get_last_trade(self: @ContractState, pair_id: u8) -> (u256, u256, u64) {
            let price = self.last_trade_price.read(pair_id);
            let amount = self.last_trade_amount.read(pair_id);
            let time = self.last_trade_time.read(pair_id);
            (price, amount, time)
        }

        /// Get price snapshot at index: (price, timestamp)
        fn get_price_snapshot(self: @ContractState, pair_id: u8, index: u32) -> (u256, u64) {
            self.price_snapshots.read((pair_id, index))
        }

        /// Get count of price snapshots
        fn get_snapshot_count(self: @ContractState, pair_id: u8) -> u32 {
            self.price_snapshot_count.read(pair_id)
        }

        // =========================================================================
        // Trustless Orderbook View Functions
        // =========================================================================

        /// Get total order count
        fn get_order_count(self: @ContractState) -> u256 {
            self.order_count.read()
        }

        /// Get total trade count
        fn get_trade_count(self: @ContractState) -> u256 {
            self.trade_count.read()
        }

        /// Get orderbook depth - aggregated price levels with total amounts
        /// Returns (bids, asks) where each is Array<(price, total_amount, order_count)>
        fn get_orderbook_depth(
            self: @ContractState,
            pair_id: u8,
            max_levels: u32
        ) -> (Array<(u256, u256, u32)>, Array<(u256, u256, u32)>) {
            let total_orders = self.order_count.read();

            // Collect all active bids and asks with their prices
            let mut bid_prices: Array<u256> = array![];
            let mut bid_amounts: Array<u256> = array![];
            let mut ask_prices: Array<u256> = array![];
            let mut ask_amounts: Array<u256> = array![];

            let mut i: u256 = 1;
            loop {
                if i > total_orders {
                    break;
                }

                let order = self.orders.read(i);

                // Only include active orders for this pair
                if order.pair_id == pair_id
                    && order.remaining > 0
                    && (order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill) {

                    match order.side {
                        OrderSide::Buy => {
                            bid_prices.append(order.price);
                            bid_amounts.append(order.remaining);
                        },
                        OrderSide::Sell => {
                            ask_prices.append(order.price);
                            ask_amounts.append(order.remaining);
                        },
                    }
                }

                i += 1;
            };

            // Aggregate by price level (simplified - in production would use sorted maps)
            let bids = self._aggregate_price_levels(@bid_prices, @bid_amounts, max_levels, true);
            let asks = self._aggregate_price_levels(@ask_prices, @ask_amounts, max_levels, false);

            (bids, asks)
        }

        /// Get active orders for a pair (paginated)
        fn get_active_orders(
            self: @ContractState,
            pair_id: u8,
            offset: u32,
            limit: u32
        ) -> Array<Order> {
            let total_orders = self.order_count.read();
            let mut result: Array<Order> = array![];
            let mut count: u32 = 0;
            let mut found: u32 = 0;
            let max_limit: u32 = if limit > 100 { 100 } else { limit }; // Cap at 100

            let mut i: u256 = 1;
            loop {
                if i > total_orders || found >= max_limit {
                    break;
                }

                let order = self.orders.read(i);

                // Check if active order for this pair
                if order.pair_id == pair_id
                    && order.remaining > 0
                    && (order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill) {

                    if count >= offset {
                        result.append(order);
                        found += 1;
                    }
                    count += 1;
                }

                i += 1;
            };

            result
        }

        /// Get trade history for a pair (paginated, newest first)
        fn get_trade_history(
            self: @ContractState,
            pair_id: u8,
            offset: u32,
            limit: u32
        ) -> Array<Trade> {
            let total_trades = self.trade_count.read();
            let mut result: Array<Trade> = array![];
            let mut count: u32 = 0;
            let mut found: u32 = 0;
            let max_limit: u32 = if limit > 100 { 100 } else { limit }; // Cap at 100

            // Iterate from newest to oldest
            let mut i: u256 = total_trades;
            loop {
                if i == 0 || found >= max_limit {
                    break;
                }

                let trade = self.trades.read(i);

                // Get the maker order to check pair_id
                let maker_order = self.orders.read(trade.maker_order_id);

                if maker_order.pair_id == pair_id {
                    if count >= offset {
                        result.append(trade);
                        found += 1;
                    }
                    count += 1;
                }

                i -= 1;
            };

            result
        }

        /// Get orders at a specific price level
        fn get_orders_at_price(
            self: @ContractState,
            pair_id: u8,
            side: OrderSide,
            price: u256,
            limit: u32
        ) -> Array<Order> {
            let total_orders = self.order_count.read();
            let mut result: Array<Order> = array![];
            let mut found: u32 = 0;
            let max_limit: u32 = if limit > 50 { 50 } else { limit }; // Cap at 50

            let mut i: u256 = 1;
            loop {
                if i > total_orders || found >= max_limit {
                    break;
                }

                let order = self.orders.read(i);

                // Check if matches criteria
                if order.pair_id == pair_id
                    && order.side == side
                    && order.price == price
                    && order.remaining > 0
                    && (order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill) {

                    result.append(order);
                    found += 1;
                }

                i += 1;
            };

            result
        }

        // =========================================================================
        // Upgradability Functions
        // =========================================================================

        /// Schedule a contract upgrade with timelock delay
        fn schedule_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._only_owner();

            let now = get_block_timestamp();
            let delay = self.upgrade_delay.read();
            let execute_after = now + delay;

            // Ensure no upgrade is already pending
            let pending = self.pending_upgrade.read();
            let zero_hash: ClassHash = 0.try_into().unwrap();
            assert!(pending == zero_hash, "Upgrade already pending");

            // Schedule the upgrade
            self.pending_upgrade.write(new_class_hash);
            self.upgrade_scheduled_at.write(now);

            self.emit(UpgradeScheduled {
                new_class_hash,
                scheduled_by: get_caller_address(),
                execute_after,
                timestamp: now,
            });
        }

        /// Execute a scheduled upgrade after timelock has passed
        fn execute_upgrade(ref self: ContractState) {
            self._only_owner();

            let now = get_block_timestamp();
            let pending = self.pending_upgrade.read();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();

            // Verify there's a pending upgrade
            let zero_hash: ClassHash = 0.try_into().unwrap();
            assert!(pending != zero_hash, "No pending upgrade");

            // Verify timelock has passed
            assert!(now >= scheduled_at + delay, "Timelock not expired");

            // Get current class hash for event
            let old_class_hash = starknet::syscalls::get_class_hash_at_syscall(
                get_contract_address()
            ).unwrap_syscall();

            // Clear pending upgrade state
            self.pending_upgrade.write(zero_hash);
            self.upgrade_scheduled_at.write(0);

            // Emit event before upgrade
            self.emit(UpgradeExecuted {
                old_class_hash,
                new_class_hash: pending,
                executed_by: get_caller_address(),
                timestamp: now,
            });

            // Execute the upgrade using replace_class syscall
            starknet::syscalls::replace_class_syscall(pending).unwrap_syscall();
        }

        /// Cancel a scheduled upgrade
        fn cancel_upgrade(ref self: ContractState) {
            self._only_owner();

            let pending = self.pending_upgrade.read();
            let zero_hash: ClassHash = 0.try_into().unwrap();

            // Verify there's a pending upgrade to cancel
            assert!(pending != zero_hash, "No pending upgrade");

            // Clear pending upgrade
            self.pending_upgrade.write(zero_hash);
            self.upgrade_scheduled_at.write(0);

            self.emit(UpgradeCancelled {
                cancelled_class_hash: pending,
                cancelled_by: get_caller_address(),
                timestamp: get_block_timestamp(),
            });
        }

        /// Get upgrade info: (pending_hash, scheduled_at, execute_after, delay)
        fn get_upgrade_info(self: @ContractState) -> (ClassHash, u64, u64, u64) {
            let pending = self.pending_upgrade.read();
            let scheduled_at = self.upgrade_scheduled_at.read();
            let delay = self.upgrade_delay.read();
            let execute_after = if scheduled_at > 0 { scheduled_at + delay } else { 0 };

            (pending, scheduled_at, execute_after, delay)
        }

        fn set_upgrade_delay(ref self: ContractState, delay: u64) {
            self._only_owner();
            self.upgrade_delay.write(delay);
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
        }

        fn _require_not_paused(self: @ContractState) {
            assert!(!self.config.read().paused, "Orderbook paused");
        }

        /// Aggregate price levels from arrays of prices and amounts
        /// Returns Array<(price, total_amount, order_count)> sorted by best price first
        fn _aggregate_price_levels(
            self: @ContractState,
            prices: @Array<u256>,
            amounts: @Array<u256>,
            max_levels: u32,
            is_bid: bool
        ) -> Array<(u256, u256, u32)> {
            let len = prices.len();
            if len == 0 {
                return array![];
            }

            // Simple aggregation: find unique prices and sum amounts
            // This is O(n^2) but acceptable for view functions with limited data
            let mut result: Array<(u256, u256, u32)> = array![];
            let mut processed: Array<u256> = array![]; // Track processed prices

            let mut i: u32 = 0;
            loop {
                if i >= len || result.len() >= max_levels {
                    break;
                }

                let price = *prices.at(i);

                // Check if already processed
                let mut already_processed = false;
                let mut j: u32 = 0;
                loop {
                    if j >= processed.len() {
                        break;
                    }
                    if *processed.at(j) == price {
                        already_processed = true;
                        break;
                    }
                    j += 1;
                };

                if !already_processed {
                    // Aggregate all orders at this price
                    let mut total_amount: u256 = 0;
                    let mut order_count: u32 = 0;

                    let mut k: u32 = 0;
                    loop {
                        if k >= len {
                            break;
                        }
                        if *prices.at(k) == price {
                            total_amount += *amounts.at(k);
                            order_count += 1;
                        }
                        k += 1;
                    };

                    // Insert sorted (bids: highest first, asks: lowest first)
                    let mut inserted = false;
                    let mut new_result: Array<(u256, u256, u32)> = array![];

                    let mut m: u32 = 0;
                    loop {
                        if m >= result.len() {
                            break;
                        }

                        let (existing_price, existing_amount, existing_count) = *result.at(m);

                        if !inserted {
                            let should_insert = if is_bid {
                                price > existing_price
                            } else {
                                price < existing_price
                            };

                            if should_insert {
                                new_result.append((price, total_amount, order_count));
                                inserted = true;
                            }
                        }

                        new_result.append((existing_price, existing_amount, existing_count));
                        m += 1;
                    };

                    if !inserted {
                        new_result.append((price, total_amount, order_count));
                    }

                    result = new_result;
                    processed.append(price);
                }

                i += 1;
            };

            // Trim to max_levels
            if result.len() > max_levels {
                let mut trimmed: Array<(u256, u256, u32)> = array![];
                let mut t: u32 = 0;
                loop {
                    if t >= max_levels {
                        break;
                    }
                    trimmed.append(*result.at(t));
                    t += 1;
                };
                return trimmed;
            }

            result
        }

        /// Internal function for placing limit orders (used by both single and batch)
        fn _place_limit_order_internal(
            ref self: ContractState,
            pair_id: u8,
            side: OrderSide,
            price: u256,
            amount: u256,
            expires_in: u64
        ) -> u256 {
            let caller = get_caller_address();
            let now = get_block_timestamp();
            let config = self.config.read();

            // Validate pair
            let pair = self.pairs.read(pair_id);
            assert!(pair.is_active, "Trading pair not active");

            // Validate order size
            assert!(amount >= pair.min_order_size, "Order below minimum size");
            assert!(amount <= MAX_ORDER_SIZE, "Order exceeds maximum size");

            // Validate price tick
            assert!(price > 0, "Price must be > 0");
            assert!(price % pair.tick_size == 0, "Price must be multiple of tick size");

            // Check user order limit
            let user_orders = self.user_order_count.read(caller);
            assert!(user_orders < config.max_orders_per_user, "Max orders reached");

            // Calculate expiration
            let expires_at = if expires_in > 0 {
                now + expires_in
            } else if config.default_expiry_secs > 0 {
                now + config.default_expiry_secs
            } else {
                0 // No expiry
            };

            // Create order
            let order_id = self.order_count.read() + 1;
            self.order_count.write(order_id);

            let order = Order {
                order_id,
                maker: caller,
                pair_id,
                side,
                order_type: OrderType::Limit,
                price,
                amount,
                remaining: amount,
                status: OrderStatus::Open,
                created_at: now,
                expires_at,
            };

            // Transfer tokens to orderbook
            self._lock_order_funds(caller, @pair, @order);

            // Store order
            self.orders.write(order_id, order);

            // Add to user's order list
            self.user_orders.write((caller, user_orders), order_id);
            self.user_order_count.write(caller, user_orders + 1);

            // Update price level
            self._add_to_price_level(pair_id, side, price, order_id);

            // Update best bid/ask
            self._update_best_prices(pair_id, side, price);

            self.emit(OrderPlaced {
                order_id,
                maker: caller,
                pair_id,
                side,
                order_type: OrderType::Limit,
                price,
                amount,
                expires_at,
            });

            // Try to match order
            self._try_match_order(order_id);

            order_id
        }

        fn _lock_order_funds(
            ref self: ContractState,
            user: ContractAddress,
            pair: @TradingPair,
            order: @Order
        ) {
            let this = get_contract_address();

            match order.side {
                OrderSide::Buy => {
                    // Lock quote tokens (e.g., USDC)
                    let quote_amount = (*order.price * *order.amount) / 1000000000000000000;
                    let quote_token = IERC20Dispatcher { contract_address: *pair.quote_token };
                    quote_token.transfer_from(user, this, quote_amount);
                },
                OrderSide::Sell => {
                    // Lock SAGE
                    let sage_token = IERC20Dispatcher { contract_address: *pair.base_token };
                    sage_token.transfer_from(user, this, *order.amount);
                },
            }
        }

        fn _refund_order(ref self: ContractState, order_id: u256) {
            let order = self.orders.read(order_id);
            let pair = self.pairs.read(order.pair_id);

            if order.remaining == 0 {
                return;
            }

            match order.side {
                OrderSide::Buy => {
                    // Refund quote tokens
                    let quote_amount = (order.price * order.remaining) / 1000000000000000000;
                    let quote_token = IERC20Dispatcher { contract_address: pair.quote_token };
                    quote_token.transfer(order.maker, quote_amount);
                },
                OrderSide::Sell => {
                    // Refund SAGE
                    let sage_token = IERC20Dispatcher { contract_address: pair.base_token };
                    sage_token.transfer(order.maker, order.remaining);
                },
            }
        }

        fn _add_to_price_level(
            ref self: ContractState,
            pair_id: u8,
            side: OrderSide,
            price: u256,
            order_id: u256
        ) {
            let side_felt: felt252 = match side {
                OrderSide::Buy => 'buy',
                OrderSide::Sell => 'sell',
            };

            let count = self.price_level_count.read((pair_id, side_felt, price));
            self.price_level_orders.write((pair_id, side_felt, price, count), order_id);
            self.price_level_count.write((pair_id, side_felt, price), count + 1);
        }

        fn _remove_from_price_level(
            ref self: ContractState,
            pair_id: u8,
            side: OrderSide,
            price: u256,
            _order_id: u256
        ) {
            // Simplified: just decrement count
            // In production, would maintain proper linked list
            let side_felt: felt252 = match side {
                OrderSide::Buy => 'buy',
                OrderSide::Sell => 'sell',
            };

            let count = self.price_level_count.read((pair_id, side_felt, price));
            if count > 0 {
                self.price_level_count.write((pair_id, side_felt, price), count - 1);
            }

            // Update best prices if needed
            if count <= 1 {
                self._recalculate_best_price(pair_id, side);
            }
        }

        fn _update_best_prices(ref self: ContractState, pair_id: u8, side: OrderSide, price: u256) {
            match side {
                OrderSide::Buy => {
                    let current_best = self.best_bid.read(pair_id);
                    if price > current_best {
                        self.best_bid.write(pair_id, price);
                    }
                },
                OrderSide::Sell => {
                    let current_best = self.best_ask.read(pair_id);
                    if current_best == 0 || price < current_best {
                        self.best_ask.write(pair_id, price);
                    }
                },
            }
        }

        fn _recalculate_best_price(ref self: ContractState, pair_id: u8, side: OrderSide) {
            // Scan through recent orders to find next best price
            // This is O(n) but acceptable for testnet; mainnet would use sorted structures
            let total_orders = self.order_count.read();
            let mut best_price: u256 = 0;
            let mut i: u256 = 1;

            loop {
                if i > total_orders {
                    break;
                }

                let order = self.orders.read(i);

                // Check if order matches criteria: same pair, same side, and active
                if order.pair_id == pair_id
                    && order.side == side
                    && order.remaining > 0
                    && (order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill) {

                    match side {
                        OrderSide::Buy => {
                            // For bids, find highest price
                            if order.price > best_price {
                                best_price = order.price;
                            }
                        },
                        OrderSide::Sell => {
                            // For asks, find lowest price
                            if best_price == 0 || order.price < best_price {
                                best_price = order.price;
                            }
                        },
                    }
                }

                i += 1;
            };

            match side {
                OrderSide::Buy => self.best_bid.write(pair_id, best_price),
                OrderSide::Sell => self.best_ask.write(pair_id, best_price),
            }
        }

        /// Find a valid maker order at given price level
        /// Returns order_id if found, 0 if no valid order exists
        fn _find_valid_maker_order(
            ref self: ContractState,
            pair_id: u8,
            side: OrderSide,
            price: u256,
            exclude_maker: ContractAddress
        ) -> u256 {
            let total_orders = self.order_count.read();
            let mut i: u256 = 1;

            loop {
                if i > total_orders {
                    break 0;
                }

                let order = self.orders.read(i);

                // Check if order matches: right pair, side, price, has remaining, is active, not self-trade
                if order.pair_id == pair_id
                    && order.side == side
                    && order.price == price
                    && order.remaining > 0
                    && (order.status == OrderStatus::Open || order.status == OrderStatus::PartialFill)
                    && order.maker != exclude_maker {
                    break i; // Found valid order
                }

                i += 1;
            }
        }

        fn _try_match_order(ref self: ContractState, order_id: u256) {
            let order = self.orders.read(order_id);

            // Get best price on opposite side
            let opposite_price = match order.side {
                OrderSide::Buy => self.best_ask.read(order.pair_id),
                OrderSide::Sell => self.best_bid.read(order.pair_id),
            };

            if opposite_price == 0 {
                return; // No orders on opposite side
            }

            // Check if prices cross
            let can_match = match order.side {
                OrderSide::Buy => order.price >= opposite_price,
                OrderSide::Sell => order.price <= opposite_price,
            };

            if !can_match {
                return;
            }

            // Execute match at maker's price (price-time priority)
            self._execute_match(order_id, opposite_price);
        }

        fn _execute_market_order(ref self: ContractState, order_id: u256) -> u256 {
            let mut order = self.orders.read(order_id);
            let mut filled: u256 = 0;

            // Keep matching until order is filled or no more liquidity
            loop {
                if order.remaining == 0 {
                    break;
                }

                let opposite_price = match order.side {
                    OrderSide::Buy => self.best_ask.read(order.pair_id),
                    OrderSide::Sell => self.best_bid.read(order.pair_id),
                };

                if opposite_price == 0 {
                    break; // No more liquidity
                }

                let matched = self._execute_match(order_id, opposite_price);
                filled += matched;

                // Refresh order state
                order = self.orders.read(order_id);
            };

            // If not fully filled, refund remaining
            if order.remaining > 0 {
                self._refund_order(order_id);
                let mut final_order = order;
                final_order.status = OrderStatus::Cancelled;
                final_order.remaining = 0;
                self.orders.write(order_id, final_order);
            }

            filled
        }

        fn _execute_match(ref self: ContractState, taker_order_id: u256, match_price: u256) -> u256 {
            let mut taker_order = self.orders.read(taker_order_id);
            let pair = self.pairs.read(taker_order.pair_id);
            let config = self.config.read();

            // Find a valid maker order at this price level
            let maker_order_side = match taker_order.side {
                OrderSide::Buy => OrderSide::Sell,
                OrderSide::Sell => OrderSide::Buy,
            };

            // Find valid maker order by scanning (price level tracking can be stale)
            let maker_order_id = self._find_valid_maker_order(
                taker_order.pair_id, maker_order_side, match_price, taker_order.maker
            );

            if maker_order_id == 0 {
                // No valid order found at this price, recalculate best price
                self._recalculate_best_price(taker_order.pair_id, maker_order_side);
                return 0;
            }

            let mut maker_order = self.orders.read(maker_order_id);

            // Double-check maker order is valid (belt and suspenders)
            if maker_order.remaining == 0
                || (maker_order.status != OrderStatus::Open && maker_order.status != OrderStatus::PartialFill) {
                self._recalculate_best_price(taker_order.pair_id, maker_order_side);
                return 0;
            }

            // Calculate fill amount
            let fill_amount = if taker_order.remaining < maker_order.remaining {
                taker_order.remaining
            } else {
                maker_order.remaining
            };

            if fill_amount == 0 {
                return 0;
            }

            // Calculate quote amount and fees
            let quote_amount = (match_price * fill_amount) / 1000000000000000000;
            let maker_fee = (quote_amount * config.maker_fee_bps.into()) / BPS_DENOMINATOR;
            let taker_fee = (quote_amount * config.taker_fee_bps.into()) / BPS_DENOMINATOR;

            // Execute transfers
            let sage = IERC20Dispatcher { contract_address: pair.base_token };
            let quote = IERC20Dispatcher { contract_address: pair.quote_token };

            match taker_order.side {
                OrderSide::Buy => {
                    // Taker buys SAGE: seller sends SAGE, buyer sends quote
                    // SAGE: maker -> taker (minus taker fee in SAGE)
                    let sage_after_fee = fill_amount - ((fill_amount * config.taker_fee_bps.into()) / BPS_DENOMINATOR);
                    sage.transfer(taker_order.maker, sage_after_fee);

                    // Quote: taker (already locked) -> maker (minus maker fee)
                    let quote_after_fee = quote_amount - maker_fee;
                    quote.transfer(maker_order.maker, quote_after_fee);

                    // Collect fees
                    let current_sage_fees = self.collected_fees.read(pair.base_token);
                    self.collected_fees.write(pair.base_token, current_sage_fees + (fill_amount - sage_after_fee));

                    let current_quote_fees = self.collected_fees.read(pair.quote_token);
                    self.collected_fees.write(pair.quote_token, current_quote_fees + maker_fee);
                },
                OrderSide::Sell => {
                    // Taker sells SAGE: taker sends SAGE, buyer sends quote
                    // SAGE: taker (already locked) -> maker (minus maker fee in SAGE)
                    let sage_after_fee = fill_amount - ((fill_amount * config.maker_fee_bps.into()) / BPS_DENOMINATOR);
                    sage.transfer(maker_order.maker, sage_after_fee);

                    // Quote: maker (already locked) -> taker (minus taker fee)
                    let quote_after_fee = quote_amount - taker_fee;
                    quote.transfer(taker_order.maker, quote_after_fee);

                    // Collect fees
                    let current_sage_fees = self.collected_fees.read(pair.base_token);
                    self.collected_fees.write(pair.base_token, current_sage_fees + (fill_amount - sage_after_fee));

                    let current_quote_fees = self.collected_fees.read(pair.quote_token);
                    self.collected_fees.write(pair.quote_token, current_quote_fees + taker_fee);
                },
            }

            // Update orders
            taker_order.remaining -= fill_amount;
            maker_order.remaining -= fill_amount;

            taker_order.status = if taker_order.remaining == 0 {
                OrderStatus::Filled
            } else {
                OrderStatus::PartialFill
            };

            maker_order.status = if maker_order.remaining == 0 {
                OrderStatus::Filled
            } else {
                OrderStatus::PartialFill
            };

            self.orders.write(taker_order_id, taker_order);
            self.orders.write(maker_order_id, maker_order);

            // Remove filled maker order from price level
            if maker_order.remaining == 0 {
                self._remove_from_price_level(maker_order.pair_id, maker_order.side, maker_order.price, maker_order_id);
            }

            // Record trade
            let trade_id = self.trade_count.read() + 1;
            self.trade_count.write(trade_id);

            let trade = Trade {
                trade_id,
                maker_order_id,
                taker_order_id,
                maker: maker_order.maker,
                taker: taker_order.maker,
                price: match_price,
                amount: fill_amount,
                quote_amount,
                executed_at: get_block_timestamp(),
            };
            self.trades.write(trade_id, trade);

            // Update stats
            let total_sage = self.total_volume_sage.read() + fill_amount;
            self.total_volume_sage.write(total_sage);

            let total_quote = self.total_volume_quote.read(taker_order.pair_id) + quote_amount;
            self.total_volume_quote.write(taker_order.pair_id, total_quote);

            // Update TWAP and price analytics
            self._update_price_analytics(taker_order.pair_id, match_price, fill_amount);

            // Emit events
            self.emit(TradeExecuted {
                trade_id,
                maker_order_id,
                taker_order_id,
                maker: maker_order.maker,
                taker: taker_order.maker,
                price: match_price,
                amount: fill_amount,
                quote_amount,
                maker_fee,
                taker_fee,
            });

            self.emit(OrderFilled {
                order_id: taker_order_id,
                filled_amount: fill_amount,
                remaining_amount: taker_order.remaining,
                status: taker_order.status,
            });

            self.emit(OrderFilled {
                order_id: maker_order_id,
                filled_amount: fill_amount,
                remaining_amount: maker_order.remaining,
                status: maker_order.status,
            });

            // Record trade with referral system for both parties
            self._record_referral_trade(taker_order.maker, quote_amount, taker_fee, pair.quote_token);
            self._record_referral_trade(maker_order.maker, quote_amount, maker_fee, pair.quote_token);

            fill_amount
        }

        /// Record trade with referral system if configured
        fn _record_referral_trade(
            ref self: ContractState,
            trader: ContractAddress,
            volume_usd: u256,
            fee_amount: u256,
            fee_token: ContractAddress
        ) {
            let referral_addr = self.referral_system.read();
            if referral_addr.is_zero() {
                return;  // Referral system not configured
            }

            // Call referral system to record trade and distribute rewards
            let referral = IReferralSystemDispatcher { contract_address: referral_addr };
            referral.record_trade(trader, volume_usd, fee_amount, fee_token);
        }

        /// Update TWAP and price analytics after each trade
        fn _update_price_analytics(ref self: ContractState, pair_id: u8, price: u256, volume: u256) {
            let current_time = get_block_timestamp();

            // Update last trade data (price, amount, timestamp)
            self.last_trade_price.write(pair_id, price);
            self.last_trade_amount.write(pair_id, volume);
            self.last_trade_time.write(pair_id, current_time);

            // Update TWAP cumulative
            let last_update = self.twap_last_update.read(pair_id);
            let last_price = self.twap_last_price.read(pair_id);

            if last_update > 0 && last_price > 0 {
                let time_elapsed: u256 = (current_time - last_update).into();
                let cumulative = self.twap_cumulative.read(pair_id);
                // Add weighted price contribution
                self.twap_cumulative.write(pair_id, cumulative + (last_price * time_elapsed));
            }

            self.twap_last_update.write(pair_id, current_time);
            self.twap_last_price.write(pair_id, price);

            // Update 24h volume (reset if window expired)
            let reset_time = self.volume_24h_reset_time.read(pair_id);
            let seconds_24h: u64 = 86400;

            if current_time >= reset_time + seconds_24h {
                // Reset 24h stats
                self.volume_24h.write(pair_id, volume);
                self.volume_24h_reset_time.write(pair_id, current_time);
                self.high_24h.write(pair_id, price);
                self.low_24h.write(pair_id, price);
            } else {
                // Update 24h stats
                let vol = self.volume_24h.read(pair_id) + volume;
                self.volume_24h.write(pair_id, vol);

                let high = self.high_24h.read(pair_id);
                if price > high || high == 0 {
                    self.high_24h.write(pair_id, price);
                }

                let low = self.low_24h.read(pair_id);
                if price < low || low == 0 {
                    self.low_24h.write(pair_id, price);
                }
            }

            // Record hourly price snapshot (every hour)
            let last_snapshot_count = self.price_snapshot_count.read(pair_id);
            let should_snapshot = if last_snapshot_count == 0 {
                true
            } else {
                let (_, last_snapshot_time) = self.price_snapshots.read((pair_id, last_snapshot_count - 1));
                current_time >= last_snapshot_time + 3600 // 1 hour
            };

            if should_snapshot {
                self.price_snapshots.write((pair_id, last_snapshot_count), (price, current_time));
                self.price_snapshot_count.write(pair_id, last_snapshot_count + 1);
            }
        }
    }
}
