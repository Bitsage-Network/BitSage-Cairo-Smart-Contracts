#!/usr/bin/env node
/**
 * Seed OTC Orderbook with Real Orders
 * Creates a realistic orderbook with buy and sell orders at various price levels
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
};

// Price levels in STRK (18 decimals)
// STRK ~$0.084 USD (Jan 2026), target SAGE price $0.10 USD = ~1.19 STRK per SAGE
// Formula: SAGE_price_in_STRK = target_USD / STRK_USD_rate
const ORDERS = {
    // Sell orders (asks) - selling SAGE for STRK
    sells: [
        { price: 1.19, amount: 500 },    // Best ask - ~$0.10 per SAGE
        { price: 1.25, amount: 750 },    // ~$0.105 per SAGE
        { price: 1.31, amount: 1000 },   // ~$0.11 per SAGE
        { price: 1.37, amount: 1500 },   // ~$0.115 per SAGE
        { price: 1.43, amount: 2000 },   // ~$0.12 per SAGE
    ],
    // Buy orders (bids) - buying SAGE with STRK
    buys: [
        { price: 1.13, amount: 500 },   // Best bid - ~$0.095 per SAGE
        { price: 1.07, amount: 750 },   // ~$0.09 per SAGE
        { price: 1.01, amount: 1000 },  // ~$0.085 per SAGE
        { price: 0.95, amount: 1500 },  // ~$0.08 per SAGE
        { price: 0.89, amount: 2000 },  // ~$0.075 per SAGE
    ],
};

const PAIR_ID = 0;  // SAGE/STRK pair
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
    log('=== Seeding OTC Orderbook with Real Orders ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Check SAGE balance
    log('\nChecking SAGE balance...', 'info');
    const sageBalance = await getBalance(provider, CONFIG.sageToken, CONFIG.deployer.address);
    const sageFormatted = Number(sageBalance) / 1e18;
    log(`  Deployer SAGE: ${sageFormatted.toLocaleString()} SAGE`, 'info');

    // Calculate total SAGE needed for sell orders
    const totalSellAmount = ORDERS.sells.reduce((sum, o) => sum + o.amount, 0);
    log(`  Total SAGE needed for sells: ${totalSellAmount} SAGE`, 'info');

    if (sageFormatted < totalSellAmount) {
        log(`Insufficient SAGE balance! Need ${totalSellAmount}, have ${sageFormatted}`, 'error');
        return;
    }

    // Step 1: Approve SAGE for orderbook (for sell orders)
    log('\nStep 1: Approving SAGE tokens for orderbook...', 'info');
    const approveAmount = toWei(totalSellAmount * 1.1); // 10% extra for safety

    try {
        const { transaction_hash: approveTx } = await account.execute({
            contractAddress: CONFIG.sageToken,
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

    // Step 2: Place sell orders (asks)
    log('\nStep 2: Placing SELL orders (asks)...', 'info');
    for (const order of ORDERS.sells) {
        const priceWei = toWei(order.price);
        const amountWei = toWei(order.amount);

        log(`  Placing: SELL ${order.amount} SAGE @ ${order.price} STRK`, 'info');

        try {
            const { transaction_hash: orderTx } = await account.execute({
                contractAddress: CONFIG.otcOrderbook,
                entrypoint: 'place_limit_order',
                calldata: CallData.compile({
                    pair_id: PAIR_ID,
                    side: 1,  // 1 = Sell
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

    // Step 3: Place buy orders (bids)
    // Note: Buy orders require quote token (STRK). For now, we'll just place sell orders
    // unless the deployer has STRK tokens as well
    log('\nStep 3: Placing BUY orders (bids)...', 'info');
    log('  Note: Buy orders require STRK tokens', 'warn');

    // Check if pair 0 is configured and what the quote token is
    try {
        const pairResult = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_pair',
            calldata: CallData.compile({ pair_id: 0 }),
        });
        const quoteToken = pairResult[1];
        log(`  Quote token: ${quoteToken}`, 'info');

        // Check quote token balance
        const quoteBalance = await getBalance(provider, quoteToken, CONFIG.deployer.address);
        const quoteFormatted = Number(quoteBalance) / 1e18;
        log(`  Quote balance: ${quoteFormatted.toLocaleString()}`, 'info');

        // Calculate total quote needed for buy orders
        const totalBuyQuote = ORDERS.buys.reduce((sum, o) => sum + (o.amount * o.price), 0);
        log(`  Total quote needed for buys: ${totalBuyQuote.toFixed(2)}`, 'info');

        if (quoteFormatted >= totalBuyQuote) {
            // Approve quote token for buy orders
            const approveQuote = toWei(totalBuyQuote * 1.1);
            const { transaction_hash: approveQuoteTx } = await account.execute({
                contractAddress: quoteToken,
                entrypoint: 'approve',
                calldata: CallData.compile({
                    spender: CONFIG.otcOrderbook,
                    amount: cairo.uint256(approveQuote),
                }),
            });
            await provider.waitForTransaction(approveQuoteTx);
            log('  Quote token approved!', 'success');

            // Place buy orders
            for (const order of ORDERS.buys) {
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

                await new Promise(r => setTimeout(r, 1000));
            }
        } else {
            log(`  Skipping buy orders - insufficient quote balance`, 'warn');
        }
    } catch (e) {
        log(`  Could not place buy orders: ${e.message}`, 'warn');
    }

    // Summary
    log('\n=== ORDERBOOK SEEDING COMPLETE ===', 'header');

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
        log(`Spread: ${((askPrice - bidPrice) / bidPrice * 100).toFixed(2)}%`, 'info');

    } catch (e) {
        log(`Could not get orderbook stats: ${e.message}`, 'warn');
    }
}

main().catch(e => {
    console.error('Error:', e.message);
    console.error(e);
});
