/**
 * BitSage Production Orderbook Seeding
 *
 * Seeds the OTC orderbook with SAGE sell orders across all trading pairs.
 * Users can buy SAGE directly with STRK, ETH, or USDC.
 *
 * PRICING STRATEGY:
 * - Base price anchored to target market cap
 * - Tiered pricing with increasing prices for larger purchases (bonding curve effect)
 * - Spread across multiple price levels for natural orderbook depth
 */

import { Account, RpcProvider, Contract, CallData, cairo } from 'starknet';
import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',

    // Deployed contracts
    contracts: {
        otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
        sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    },

    // Quote tokens on Sepolia
    tokens: {
        STRK: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
        ETH: '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
        USDC: '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8',
    },

    // Pair IDs (must match on-chain configuration)
    pairs: {
        SAGE_STRK: 1,  // Real STRK pair
        SAGE_ETH: 2,   // ETH pair (if added)
        SAGE_USDC: 3,  // USDC pair (if added)
    },

    // Token decimals
    decimals: {
        SAGE: 18,
        STRK: 18,
        ETH: 18,
        USDC: 6,
    },
};

// ============================================================================
// PRICING STRATEGY
// ============================================================================

/**
 * SAGE Token Pricing Strategy
 *
 * Total Supply: 1,000,000,000 SAGE
 * Market Liquidity Pool: 100,000,000 SAGE (10%)
 *
 * STARTING PRICE: $0.10 USD per SAGE
 * FDV at launch: $100,000,000 (100M USD)
 *
 * Reference prices (using Pragma Oracle live rates):
 * - STRK: ~$0.084 USD → ~1.19 STRK per SAGE ($0.10 / $0.084)
 * - ETH: ~$3,300 USD → 0.0000303 ETH per SAGE
 * - USDC: 1:1 USD → 0.10 USDC per SAGE
 *
 * IMPORTANT: Prices are anchored to USD target via oracle conversion.
 * When STRK price changes, seed orders should be refreshed.
 *
 * Tiered pricing creates natural price discovery and rewards early buyers.
 */

const PRICING = {
    // Base price: $0.10 USD per SAGE
    // Tiered to create orderbook depth and bonding curve effect

    STRK: {
        // STRK ~$0.084 USD (Jan 2026), so $0.10 = ~1.19 STRK per SAGE
        // Formula: SAGE_price_in_STRK = target_USD / STRK_USD_rate
        tiers: [
            { price: 1.19, amount: 100000 },    // Tier 1: Best price - 100K SAGE @ 1.19 STRK ($0.10)
            { price: 1.31, amount: 200000 },    // Tier 2: 200K SAGE @ 1.31 STRK ($0.11)
            { price: 1.43, amount: 300000 },    // Tier 3: 300K SAGE @ 1.43 STRK ($0.12)
            { price: 1.55, amount: 400000 },    // Tier 4: 400K SAGE @ 1.55 STRK ($0.13)
            { price: 1.79, amount: 500000 },    // Tier 5: 500K SAGE @ 1.79 STRK ($0.15)
            { price: 2.38, amount: 500000 },    // Tier 6: 500K SAGE @ 2.38 STRK ($0.20) premium
        ],
        totalAmount: 2000000, // 2M SAGE available in STRK pair
    },

    ETH: {
        // ETH ~$3,300 USD (Jan 2026), so $0.10 = ~0.0000303 ETH per SAGE
        tiers: [
            { price: 0.0000303, amount: 100000 },   // $0.10 per SAGE
            { price: 0.0000333, amount: 200000 },   // $0.11 per SAGE
            { price: 0.0000364, amount: 300000 },   // $0.12 per SAGE
            { price: 0.0000394, amount: 400000 },   // $0.13 per SAGE
            { price: 0.0000606, amount: 500000 },   // $0.20 per SAGE (premium)
        ],
        totalAmount: 1500000, // 1.5M SAGE available in ETH pair
    },

    USDC: {
        // USDC = USD, direct pricing
        tiers: [
            { price: 0.10, amount: 200000 },   // $0.10 per SAGE (launch price)
            { price: 0.11, amount: 300000 },   // $0.11 per SAGE
            { price: 0.12, amount: 400000 },   // $0.12 per SAGE
            { price: 0.15, amount: 500000 },   // $0.15 per SAGE
            { price: 0.20, amount: 600000 },   // $0.20 per SAGE (premium)
        ],
        totalAmount: 2000000, // 2M SAGE available in USDC pair
    },
};

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
// OTC CONTRACT INTERFACE
// ============================================================================

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
        name: 'get_best_bid',
        type: 'function',
        inputs: [{ name: 'pair_id', type: 'felt' }],
        outputs: [{ name: 'price', type: 'Uint256' }],
        stateMutability: 'view',
    },
    {
        name: 'get_best_ask',
        type: 'function',
        inputs: [{ name: 'pair_id', type: 'felt' }],
        outputs: [{ name: 'price', type: 'Uint256' }],
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
    {
        name: 'allowance',
        type: 'function',
        inputs: [
            { name: 'owner', type: 'felt' },
            { name: 'spender', type: 'felt' },
        ],
        outputs: [{ name: 'remaining', type: 'Uint256' }],
        stateMutability: 'view',
    },
];

// ============================================================================
// MAIN FUNCTIONS
// ============================================================================

async function checkAndApprove(provider, account, tokenAddress, spender, amount) {
    const token = new Contract(ERC20_ABI, tokenAddress, account);

    // Check current allowance
    const allowance = await token.allowance(account.address, spender);
    const currentAllowance = BigInt(allowance.remaining.low) + (BigInt(allowance.remaining.high) << 128n);

    if (currentAllowance < amount) {
        log(`  Approving SAGE for OTC contract...`, 'info');
        // Approve max uint256
        const maxApproval = cairo.uint256(2n ** 128n - 1n);
        const tx = await token.approve(spender, maxApproval);
        await provider.waitForTransaction(tx.transaction_hash);
        log(`  Approval confirmed`, 'success');
    } else {
        log(`  SAGE already approved`, 'info');
    }
}

async function seedPair(provider, account, pairId, pairName, pricing, quoteDecimals) {
    log(`\n=== Seeding ${pairName} Pair (ID: ${pairId}) ===`, 'header');

    const otc = new Contract(OTC_ABI, CONFIG.contracts.otcOrderbook, account);
    const sage = new Contract(ERC20_ABI, CONFIG.contracts.sageToken, account);

    // Check pair is active
    try {
        const pair = await otc.get_pair(pairId);
        if (!pair.is_active) {
            log(`Pair ${pairId} is not active, skipping`, 'warn');
            return { success: false, reason: 'Pair not active' };
        }
    } catch (error) {
        log(`Pair ${pairId} does not exist, skipping`, 'warn');
        return { success: false, reason: 'Pair does not exist' };
    }

    // Check SAGE balance
    const balance = await sage.balanceOf(account.address);
    const sageBalance = BigInt(balance.balance.low) + (BigInt(balance.balance.high) << 128n);
    const sageBalanceFormatted = fromWei(sageBalance, CONFIG.decimals.SAGE);

    log(`  SAGE Balance: ${sageBalanceFormatted.toLocaleString()} SAGE`, 'info');

    // Calculate total SAGE needed for this pair
    const totalNeeded = toWei(pricing.totalAmount, CONFIG.decimals.SAGE);

    if (sageBalance < totalNeeded) {
        log(`  Insufficient SAGE! Need ${pricing.totalAmount.toLocaleString()}, have ${sageBalanceFormatted.toLocaleString()}`, 'error');
        return { success: false, reason: 'Insufficient SAGE' };
    }

    // Ensure approval
    await checkAndApprove(
        provider,
        account,
        CONFIG.contracts.sageToken,
        CONFIG.contracts.otcOrderbook,
        totalNeeded
    );

    // Place orders for each tier
    const placedOrders = [];
    const ORDER_SIDE_SELL = 1; // Sell side

    for (const tier of pricing.tiers) {
        try {
            // Price is in quote token per SAGE (quote token decimals)
            // For the contract: price is quote_amount per 1 SAGE (in 18 decimals always for price)
            const priceInWei = toWei(tier.price, 18); // Price always 18 decimals in contract
            const amountInWei = toWei(tier.amount, CONFIG.decimals.SAGE);

            log(`  Placing SELL order: ${tier.amount.toLocaleString()} SAGE @ ${tier.price} ${pairName.split('/')[1]}`, 'price');

            const tx = await otc.place_limit_order(
                pairId,
                ORDER_SIDE_SELL,
                cairo.uint256(priceInWei),
                cairo.uint256(amountInWei),
                0 // Use default expiry (7 days)
            );

            await provider.waitForTransaction(tx.transaction_hash);

            placedOrders.push({
                price: tier.price,
                amount: tier.amount,
                txHash: tx.transaction_hash,
            });

            log(`    ✓ Order placed successfully`, 'success');
        } catch (error) {
            log(`    ✗ Failed to place order: ${error.message}`, 'error');
        }
    }

    // Check best ask after seeding
    try {
        const bestAsk = await otc.get_best_ask(pairId);
        const askPrice = BigInt(bestAsk.price.low) + (BigInt(bestAsk.price.high) << 128n);
        const askFormatted = fromWei(askPrice, 18);
        log(`  Best Ask: ${askFormatted} ${pairName.split('/')[1]}`, 'success');
    } catch (error) {
        log(`  Could not fetch best ask: ${error.message}`, 'warn');
    }

    return { success: true, ordersPlaced: placedOrders.length, orders: placedOrders };
}

async function main() {
    log('\n╔══════════════════════════════════════════════════════════════╗', 'header');
    log('║     BitSage Production Orderbook Seeding                     ║', 'header');
    log('╚══════════════════════════════════════════════════════════════╝', 'header');

    // Load configuration
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

    // Get market maker account
    // First try to load from pool wallets, otherwise use deployer
    let account;
    let accountAddress;

    const poolWalletsPath = path.join(process.cwd(), 'deployment', 'pool_wallets', 'pool_addresses.json');

    if (fs.existsSync(poolWalletsPath)) {
        const poolWallets = JSON.parse(fs.readFileSync(poolWalletsPath, 'utf8'));
        accountAddress = poolWallets.marketLiquidity?.address;
        log(`Using Market Liquidity wallet: ${accountAddress}`, 'info');
    }

    // For now, use deployer as market maker (has the SAGE tokens)
    const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
    const deployerAddress = process.env.DEPLOYER_ADDRESS || '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';

    if (!deployerKey) {
        log('\nError: DEPLOYER_PRIVATE_KEY not set in environment', 'error');
        log('Export your private key: export DEPLOYER_PRIVATE_KEY=0x...', 'info');
        process.exit(1);
    }

    account = new Account(provider, deployerAddress, deployerKey);
    log(`\nMarket Maker Account: ${deployerAddress}`, 'info');

    // Display pricing summary
    log('\n┌─────────────────────────────────────────────────────────────────┐', 'header');
    log('│ PRICING SUMMARY                                                 │', 'header');
    log('├─────────────────────────────────────────────────────────────────┤', 'header');
    log('│ SAGE/STRK:                                                      │', 'price');
    for (const tier of PRICING.STRK.tiers) {
        log(`│   ${tier.amount.toLocaleString().padStart(10)} SAGE @ ${tier.price.toFixed(4)} STRK                        │`, 'info');
    }
    log('│                                                                 │', 'header');
    log('│ SAGE/ETH:                                                       │', 'price');
    for (const tier of PRICING.ETH.tiers) {
        log(`│   ${tier.amount.toLocaleString().padStart(10)} SAGE @ ${tier.price.toFixed(7)} ETH                      │`, 'info');
    }
    log('│                                                                 │', 'header');
    log('│ SAGE/USDC:                                                      │', 'price');
    for (const tier of PRICING.USDC.tiers) {
        log(`│   ${tier.amount.toLocaleString().padStart(10)} SAGE @ $${tier.price.toFixed(4)}                              │`, 'info');
    }
    log('└─────────────────────────────────────────────────────────────────┘', 'header');

    // Seed each pair
    const results = {
        STRK: await seedPair(provider, account, CONFIG.pairs.SAGE_STRK, 'SAGE/STRK', PRICING.STRK, CONFIG.decimals.STRK),
        ETH: await seedPair(provider, account, CONFIG.pairs.SAGE_ETH, 'SAGE/ETH', PRICING.ETH, CONFIG.decimals.ETH),
        USDC: await seedPair(provider, account, CONFIG.pairs.SAGE_USDC, 'SAGE/USDC', PRICING.USDC, CONFIG.decimals.USDC),
    };

    // Summary
    log('\n╔══════════════════════════════════════════════════════════════╗', 'header');
    log('║                    SEEDING COMPLETE                           ║', 'header');
    log('╚══════════════════════════════════════════════════════════════╝', 'header');

    for (const [pair, result] of Object.entries(results)) {
        if (result.success) {
            log(`✓ ${pair}: ${result.ordersPlaced} orders placed`, 'success');
        } else {
            log(`✗ ${pair}: ${result.reason}`, 'error');
        }
    }

    // Save results
    const resultsPath = path.join(process.cwd(), 'deployment', 'orderbook_seeding_results.json');
    fs.writeFileSync(resultsPath, JSON.stringify({
        timestamp: new Date().toISOString(),
        pricing: PRICING,
        results,
    }, null, 2));

    log(`\nResults saved to: ${resultsPath}`, 'success');
}

main().catch(error => {
    log(`\nFatal error: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
});
