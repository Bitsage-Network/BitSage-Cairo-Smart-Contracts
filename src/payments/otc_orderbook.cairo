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

use starknet::ContractAddress;

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
}

#[starknet::contract]
mod OTCOrderbook {
    use super::{
        IOTCOrderbook, OrderSide, OrderType, OrderStatus,
        TradingPair, Order, Trade, OrderbookConfig
    };
    use starknet::{ContractAddress, get_caller_address, get_block_timestamp, get_contract_address};
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess, Map
    };
    use core::num::traits::Zero;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use sage_contracts::growth::referral_system::{IReferralSystemDispatcher, IReferralSystemDispatcherTrait};

    const BPS_DENOMINATOR: u256 = 10000;
    const MAX_PAIRS: u8 = 10;
    const MAX_ORDER_SIZE: u256 = 10000000_000000000000000000; // 10M SAGE max per order

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

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        sage_token: ContractAddress,
        fee_recipient: ContractAddress,
        usdc_token: ContractAddress,
    ) {
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
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert!(get_caller_address() == self.owner.read(), "Only owner");
        }

        fn _require_not_paused(self: @ContractState) {
            assert!(!self.config.read().paused, "Orderbook paused");
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
            // Simplified: reset to 0, will be updated on next order
            // In production, would scan price levels
            match side {
                OrderSide::Buy => self.best_bid.write(pair_id, 0),
                OrderSide::Sell => self.best_ask.write(pair_id, 0),
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

            // Find maker order at this price level
            let maker_side: felt252 = match taker_order.side {
                OrderSide::Buy => 'sell',
                OrderSide::Sell => 'buy',
            };

            let level_count = self.price_level_count.read((taker_order.pair_id, maker_side, match_price));
            if level_count == 0 {
                return 0;
            }

            // Get first order at this level (FIFO)
            let maker_order_id = self.price_level_orders.read((taker_order.pair_id, maker_side, match_price, 0));
            let mut maker_order = self.orders.read(maker_order_id);

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
    }
}
