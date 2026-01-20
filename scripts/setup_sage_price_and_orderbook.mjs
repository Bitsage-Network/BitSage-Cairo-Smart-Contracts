/**
 * BitSage Price & Orderbook Setup
 *
 * This script:
 * 1. Sets the SAGE fallback price in the Oracle Wrapper contract ($0.10 USD)
 * 2. Seeds the OTC orderbook with initial sell orders
 *
 * Run with: node scripts/setup_sage_price_and_orderbook.mjs
 */

import { Account, RpcProvider, Contract, CallData, cairo } from 'starknet';

// ============================================================================
// CONFIGURATION
// ============================================================================

// Deployer credentials (owner of all contracts)
const DEPLOYER_ADDRESS = process.env.DEPLOYER_ADDRESS || '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',

    // Deployed contracts on Sepolia
    contracts: {
        oracleWrapper: '0x4d86bb472cb462a45d68a705a798b5e419359a5758d84b24af4bbe5441b6e5a',
        otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
        sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    },

    // Quote tokens on Sepolia
    tokens: {
        STRK: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
        ETH: '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
        USDC: '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8',
    },

    // Pair IDs on OTC Orderbook
    pairs: {
        SAGE_USDC: 0,  // Primary USD pair
        SAGE_STRK: 1,  // STRK pair
    },

    decimals: {
        SAGE: 18,
        STRK: 18,
        ETH: 18,
        USDC: 6,
        ORACLE: 8,  // Oracle prices use 8 decimals
    },

    // SAGE price: $0.10 USD
    sagePrice: {
        usd: 0.10,
        oracle8Decimals: 10_000_000n,  // 0.10 * 10^8
    },
};

// ============================================================================
// ABIs
// ============================================================================

const ORACLE_WRAPPER_ABI = [
    {
        name: 'set_fallback_price',
        type: 'function',
        inputs: [
            { name: 'pair', type: 'felt' },  // PricePair enum as felt
            { name: 'price', type: 'felt' }, // u128 price in 8 decimals
        ],
        outputs: [],
    },
    {
        name: 'get_sage_price',
        type: 'function',
        inputs: [],
        outputs: [{ name: 'price', type: 'Uint256' }],
        stateMutability: 'view',
    },
    {
        name: 'get_price',
        type: 'function',
        inputs: [{ name: 'pair', type: 'felt' }],
        outputs: [
            { name: 'price', type: 'felt' },
            { name: 'decimals', type: 'felt' },
            { name: 'last_updated', type: 'felt' },
            { name: 'num_sources', type: 'felt' },
        ],
        stateMutability: 'view',
    },
];

const OTC_ABI = [
    {
        name: 'place_limit_order',
        type: 'function',
        inputs: [
            { name: 'pair_id', type: 'felt' },
            { name: 'side', type: 'felt' }, // 0 = Buy, 1 = Sell
            { name: 'price', type: 'Uint256' },
            { name: 'amount', type: 'Uint256' },
            { name: 'expires_in', type: 'felt' },
        ],
        outputs: [{ name: 'order_id', type: 'Uint256' }],
    },
    {
        name: 'get_best_ask',
        type: 'function',
        inputs: [{ name: 'pair_id', type: 'felt' }],
        outputs: [{ name: 'price', type: 'Uint256' }],
        stateMutability: 'view',
    },
    {
        name: 'get_best_bid',
        type: 'function',
        inputs: [{ name: 'pair_id', type: 'felt' }],
        outputs: [{ name: 'price', type: 'Uint256' }],
        stateMutability: 'view',
    },
    {
        name: 'get_market_stats',
        type: 'function',
        inputs: [{ name: 'pair_id', type: 'felt' }],
        outputs: [
            { name: 'last_price', type: 'Uint256' },
            { name: 'volume_24h', type: 'Uint256' },
            { name: 'high_24h', type: 'Uint256' },
            { name: 'low_24h', type: 'Uint256' },
        ],
        stateMutability: 'view',
    },
    {
        name: 'get_pair',
        type: 'function',
        inputs: [{ name: 'pair_id', type: 'felt' }],
        outputs: [
            { name: 'base_token', type: 'felt' },
            { name: 'quote_token', type: 'felt' },
            { name: 'min_order_size', type: 'Uint256' },
            { name: 'tick_size', type: 'Uint256' },
            { name: 'is_active', type: 'felt' },
        ],
        stateMutability: 'view',
    },
];

const ERC20_ABI = [
    {
        name: 'balanceOf',
        type: 'function',
        inputs: [{ name: 'account', type: 'felt' }],
        outputs: [{ name: 'balance', type: 'Uint256' }],
        stateMutability: 'view',
    },
    {
        name: 'approve',
        type: 'function',
        inputs: [
            { name: 'spender', type: 'felt' },
            { name: 'amount', type: 'Uint256' },
        ],
        outputs: [{ name: 'success', type: 'felt' }],
    },
];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function log(message, type = 'info') {
    const colors = {
        info: '\x1b[36m',
        success: '\x1b[32m',
        warn: '\x1b[33m',
        error: '\x1b[31m',
        header: '\x1b[35m',
        price: '\x1b[34m',
    };
    const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
    console.log(`${colors[type] || ''}[${timestamp}] ${message}\x1b[0m`);
}

function toWei(amount, decimals) {
    return BigInt(Math.floor(amount * (10 ** decimals)));
}

function fromWei(amount, decimals) {
    return Number(amount) / (10 ** decimals);
}

// ============================================================================
// STEP 1: SET ORACLE FALLBACK PRICE
// ============================================================================

async function setOracleFallbackPrice(provider, account) {
    log('\n========================================', 'header');
    log('STEP 1: Setting SAGE Oracle Price', 'header');
    log('========================================\n', 'header');

    // PricePair enum: SAGE_USD = 0
    const SAGE_USD_PAIR = 0;
    const priceInOracle = CONFIG.sagePrice.oracle8Decimals;

    log(`Oracle Wrapper: ${CONFIG.contracts.oracleWrapper}`, 'info');
    log(`Setting SAGE/USD price to $${CONFIG.sagePrice.usd} (${priceInOracle} in 8 decimals)`, 'info');

    try {
        // Check current price first using provider.callContract
        try {
            const result = await provider.callContract({
                contractAddress: CONFIG.contracts.oracleWrapper,
                entrypoint: 'get_sage_price',
                calldata: [],
            });
            const currentPriceValue = BigInt(result[0] || 0);
            if (currentPriceValue > 0n) {
                const currentUsd = Number(currentPriceValue) / 1e18;
                log(`Current SAGE price: $${currentUsd.toFixed(4)}`, 'info');
            } else {
                log(`Current SAGE price: $0.00 (not set)`, 'warn');
            }
        } catch (e) {
            log(`Could not read current price: ${e.message}`, 'warn');
        }

        // Set the fallback price using account.execute
        log(`\nSending set_fallback_price transaction...`, 'info');

        const tx = await account.execute({
            contractAddress: CONFIG.contracts.oracleWrapper,
            entrypoint: 'set_fallback_price',
            calldata: [SAGE_USD_PAIR.toString(), priceInOracle.toString()],
        });

        log(`Transaction hash: ${tx.transaction_hash}`, 'info');
        log(`Waiting for confirmation...`, 'info');

        await provider.waitForTransaction(tx.transaction_hash);

        log(`Oracle price set successfully!`, 'success');

        // Verify the new price
        try {
            const result = await provider.callContract({
                contractAddress: CONFIG.contracts.oracleWrapper,
                entrypoint: 'get_sage_price',
                calldata: [],
            });
            const newPriceValue = BigInt(result[0] || 0);
            const newUsd = Number(newPriceValue) / 1e18;
            log(`Verified new SAGE price: $${newUsd.toFixed(4)}`, 'success');
        } catch (e) {
            log(`Could not verify new price: ${e.message}`, 'warn');
        }

        return true;
    } catch (error) {
        log(`Failed to set oracle price: ${error.message}`, 'error');
        if (error.message.includes('Only owner')) {
            log(`You must be the contract owner to set the fallback price`, 'error');
        }
        return false;
    }
}

// ============================================================================
// STEP 2: SEED ORDERBOOK
// ============================================================================

async function seedOrderbook(provider, account) {
    log('\n========================================', 'header');
    log('STEP 2: Seeding OTC Orderbook', 'header');
    log('========================================\n', 'header');

    // Check SAGE balance using provider.callContract
    try {
        const balanceResult = await provider.callContract({
            contractAddress: CONFIG.contracts.sageToken,
            entrypoint: 'balanceOf',
            calldata: [account.address],
        });
        const sageBalance = BigInt(balanceResult[0] || 0) + (BigInt(balanceResult[1] || 0) << 128n);
        log(`SAGE Balance: ${fromWei(sageBalance, 18).toFixed(4)} SAGE`, 'info');

        if (sageBalance < toWei(10000, 18)) {
            log(`Insufficient SAGE balance for seeding. Need at least 10,000 SAGE`, 'warn');
            log(`Skipping orderbook seeding...`, 'warn');
            return false;
        }
    } catch (e) {
        log(`Could not check SAGE balance: ${e.message}`, 'warn');
    }

    // Approve SAGE for OTC contract
    log(`\nApproving SAGE for OTC orderbook...`, 'info');
    try {
        const maxU256Low = (2n ** 128n - 1n).toString();
        const maxU256High = (2n ** 128n - 1n).toString();

        const approveTx = await account.execute({
            contractAddress: CONFIG.contracts.sageToken,
            entrypoint: 'approve',
            calldata: [CONFIG.contracts.otcOrderbook, maxU256Low, maxU256High],
        });
        await provider.waitForTransaction(approveTx.transaction_hash);
        log(`SAGE approved for OTC`, 'success');
    } catch (e) {
        log(`Approval may have failed: ${e.message}`, 'warn');
    }

    // Seed orders for SAGE/STRK pair (ID: 1)
    const pairId = CONFIG.pairs.SAGE_STRK;

    // Place sell orders at tiered prices
    // STRK ~$0.50, so $0.10 SAGE = 0.20 STRK per SAGE
    const sellOrders = [
        { price: 0.20, amount: 10000 },   // 10K SAGE @ 0.20 STRK ($0.10)
        { price: 0.22, amount: 20000 },   // 20K SAGE @ 0.22 STRK ($0.11)
        { price: 0.25, amount: 30000 },   // 30K SAGE @ 0.25 STRK ($0.125)
    ];

    log(`\nPlacing ${sellOrders.length} sell orders on SAGE/STRK pair...`, 'info');

    let ordersPlaced = 0;
    for (const order of sellOrders) {
        try {
            const priceWei = toWei(order.price, CONFIG.decimals.STRK);
            const amountWei = toWei(order.amount, CONFIG.decimals.SAGE);

            log(`  Placing sell: ${order.amount} SAGE @ ${order.price} STRK`, 'info');

            // u256 is passed as [low, high]
            const priceLow = (priceWei & ((1n << 128n) - 1n)).toString();
            const priceHigh = (priceWei >> 128n).toString();
            const amountLow = (amountWei & ((1n << 128n) - 1n)).toString();
            const amountHigh = (amountWei >> 128n).toString();

            const tx = await account.execute({
                contractAddress: CONFIG.contracts.otcOrderbook,
                entrypoint: 'place_limit_order',
                calldata: [
                    pairId.toString(),           // pair_id
                    '1',                          // side (1 = Sell)
                    priceLow, priceHigh,          // price as u256
                    amountLow, amountHigh,        // amount as u256
                    (86400 * 30).toString(),      // expires_in
                ],
            });

            await provider.waitForTransaction(tx.transaction_hash);
            log(`  Order placed! TX: ${tx.transaction_hash.slice(0, 20)}...`, 'success');
            ordersPlaced++;

        } catch (error) {
            log(`  Failed to place order: ${error.message}`, 'error');
        }
    }

    log(`\nOrderbook seeding complete: ${ordersPlaced}/${sellOrders.length} orders placed`, 'success');

    // Check best ask using provider.callContract
    try {
        const result = await provider.callContract({
            contractAddress: CONFIG.contracts.otcOrderbook,
            entrypoint: 'get_best_ask',
            calldata: [pairId.toString()],
        });
        const askPrice = BigInt(result[0] || 0) + (BigInt(result[1] || 0) << 128n);
        if (askPrice > 0n) {
            log(`Best ask price: ${fromWei(askPrice, 18).toFixed(4)} STRK`, 'price');
        }
    } catch (e) {
        log(`Could not get best ask: ${e.message}`, 'warn');
    }

    return ordersPlaced > 0;
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('\n==========================================', 'header');
    log('  BitSage Price & Orderbook Setup', 'header');
    log('==========================================', 'header');

    log(`\nConnecting to Starknet Sepolia...`, 'info');
    log(`RPC: ${CONFIG.rpcUrl}`, 'info');
    log(`Address: ${DEPLOYER_ADDRESS}`, 'info');
    log(`Key: ${DEPLOYER_PRIVATE_KEY.slice(0, 10)}...`, 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

    // Starknet.js v9 uses options object for Account constructor
    const account = new Account({
        provider,
        address: DEPLOYER_ADDRESS,
        signer: DEPLOYER_PRIVATE_KEY,
    });

    log(`Account: ${DEPLOYER_ADDRESS.slice(0, 10)}...${DEPLOYER_ADDRESS.slice(-8)}`, 'info');

    // Step 1: Set Oracle Price
    const oracleSuccess = await setOracleFallbackPrice(provider, account);

    // Step 2: Seed Orderbook
    const orderbookSuccess = await seedOrderbook(provider, account);

    // Summary
    log('\n==========================================', 'header');
    log('  SUMMARY', 'header');
    log('==========================================', 'header');
    log(`Oracle Price Set: ${oracleSuccess ? 'YES' : 'NO'}`, oracleSuccess ? 'success' : 'error');
    log(`Orderbook Seeded: ${orderbookSuccess ? 'YES' : 'NO'}`, orderbookSuccess ? 'success' : 'error');

    if (oracleSuccess) {
        log(`\nSAGE price is now $${CONFIG.sagePrice.usd} USD`, 'success');
        log(`Refresh the wallet page at localhost:3000/wallet to see the update!`, 'success');
    }

    log('\n', 'info');
}

main().catch((error) => {
    log(`\nFatal error: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
});
