#!/usr/bin/env node
/**
 * Seed OTC Orderbook with Buy Orders
 * First mints quote tokens (MockERC20), then places buy orders
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    quoteToken: '0x53b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080', // Mock STRK
};

// Buy orders - buying SAGE with quote token
// STRK ~$0.084, target SAGE price $0.10 USD = ~1.19 STRK per SAGE
// Bids are placed slightly below asks to create spread
const BUY_ORDERS = [
    { price: 1.13, amount: 500 },   // Best bid - ~$0.095 per SAGE
    { price: 1.07, amount: 750 },   // ~$0.09 per SAGE
    { price: 1.01, amount: 1000 },  // ~$0.085 per SAGE
    { price: 0.95, amount: 1500 },  // ~$0.08 per SAGE
    { price: 0.89, amount: 2000 },  // ~$0.075 per SAGE
];

const PAIR_ID = 0;
const EXPIRES_IN = 604800n;  // 7 days

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', error: '\x1b[31m',
        warn: '\x1b[33m', header: '\x1b[35m', reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]', header: '[====]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

function toWei(amount) {
    return BigInt(Math.floor(amount * 1e18));
}

async function getBalance(provider, tokenAddress, accountAddress) {
    try {
        const result = await provider.callContract({
            contractAddress: tokenAddress,
            entrypoint: 'balance_of',
            calldata: CallData.compile({ account: accountAddress }),
        });
        return BigInt(result[0]) + (BigInt(result[1] || 0) << 128n);
    } catch {
        return 0n;
    }
}

async function main() {
    log('=== Seeding OTC Orderbook with Buy Orders ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Calculate total quote tokens needed
    const totalQuoteNeeded = BUY_ORDERS.reduce((sum, o) => sum + (o.amount * o.price), 0);
    log(`Total quote tokens needed: ${totalQuoteNeeded.toFixed(2)} STRK`, 'info');

    // Check current quote balance
    let quoteBalance = await getBalance(provider, CONFIG.quoteToken, CONFIG.deployer.address);
    let quoteFormatted = Number(quoteBalance) / 1e18;
    log(`Current quote balance: ${quoteFormatted.toLocaleString()} STRK`, 'info');

    // Step 1: Mint quote tokens if needed
    if (quoteFormatted < totalQuoteNeeded * 1.1) {
        const mintAmount = toWei(totalQuoteNeeded * 1.2); // 20% extra
        log(`\nStep 1: Minting ${Number(mintAmount) / 1e18} quote tokens...`, 'info');

        try {
            const { transaction_hash: mintTx } = await account.execute({
                contractAddress: CONFIG.quoteToken,
                entrypoint: 'faucet',
                calldata: CallData.compile({
                    amount: cairo.uint256(mintAmount),
                }),
            });
            log(`  Faucet TX: ${mintTx}`, 'info');
            await provider.waitForTransaction(mintTx);
            log('  Tokens minted!', 'success');

            // Update balance
            quoteBalance = await getBalance(provider, CONFIG.quoteToken, CONFIG.deployer.address);
            quoteFormatted = Number(quoteBalance) / 1e18;
            log(`  New balance: ${quoteFormatted.toLocaleString()} STRK`, 'info');
        } catch (e) {
            log(`  Faucet failed: ${e.message}`, 'error');
            return;
        }
    } else {
        log('  Sufficient quote balance already available', 'success');
    }

    // Step 2: Approve quote tokens for orderbook
    log('\nStep 2: Approving quote tokens for orderbook...', 'info');
    const approveAmount = toWei(totalQuoteNeeded * 1.1);

    try {
        const { transaction_hash: approveTx } = await account.execute({
            contractAddress: CONFIG.quoteToken,
            entrypoint: 'approve',
            calldata: CallData.compile({
                spender: CONFIG.otcOrderbook,
                amount: cairo.uint256(approveAmount),
            }),
        });
        log(`  Approve TX: ${approveTx}`, 'info');
        await provider.waitForTransaction(approveTx);
        log('  Approval confirmed!', 'success');
    } catch (e) {
        log(`  Approval failed: ${e.message}`, 'error');
        return;
    }

    // Step 3: Place buy orders (bids)
    log('\nStep 3: Placing BUY orders (bids)...', 'info');

    for (const order of BUY_ORDERS) {
        const priceWei = toWei(order.price);
        const amountWei = toWei(order.amount);

        log(`  Placing: BUY ${order.amount} SAGE @ ${order.price} STRK`, 'info');

        try {
            const { transaction_hash: orderTx } = await account.execute({
                contractAddress: CONFIG.otcOrderbook,
                entrypoint: 'place_limit_order',
                calldata: CallData.compile({
                    pair_id: PAIR_ID,
                    side: 0,  // 0 = Buy
                    price: cairo.uint256(priceWei),
                    amount: cairo.uint256(amountWei),
                    expires_in: EXPIRES_IN,
                }),
            });
            await provider.waitForTransaction(orderTx);
            log(`    Order placed! TX: ${orderTx.slice(0, 20)}...`, 'success');
        } catch (e) {
            log(`    Failed: ${e.message}`, 'error');
        }

        // Small delay between orders
        await new Promise(r => setTimeout(r, 1000));
    }

    // Summary
    log('\n=== BUY ORDERS SEEDING COMPLETE ===', 'header');

    // Get stats
    try {
        const statsResult = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_stats',
            calldata: [],
        });
        const totalOrders = BigInt(statsResult[0]) + (BigInt(statsResult[1] || 0) << 128n);
        log(`Total orders on orderbook: ${totalOrders}`, 'success');

        // Get best bid/ask
        const bestBid = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_best_bid',
            calldata: CallData.compile({ pair_id: 0 }),
        });
        const bestAsk = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_best_ask',
            calldata: CallData.compile({ pair_id: 0 }),
        });

        const bidPrice = Number(BigInt(bestBid[0]) + (BigInt(bestBid[1] || 0) << 128n)) / 1e18;
        const askPrice = Number(BigInt(bestAsk[0]) + (BigInt(bestAsk[1] || 0) << 128n)) / 1e18;

        log(`Best Bid: ${bidPrice.toFixed(4)} STRK`, 'info');
        log(`Best Ask: ${askPrice.toFixed(4)} STRK`, 'info');
        if (bidPrice > 0 && askPrice > 0) {
            log(`Spread: ${((askPrice - bidPrice) / bidPrice * 100).toFixed(2)}%`, 'info');
        }
    } catch (e) {
        log(`Could not get orderbook stats: ${e.message}`, 'warn');
    }
}

main().catch(e => {
    console.error('Error:', e.message);
    console.error(e);
});
