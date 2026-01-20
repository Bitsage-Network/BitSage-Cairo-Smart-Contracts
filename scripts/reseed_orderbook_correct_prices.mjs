#!/usr/bin/env node
/**
 * Cancel Old Orders and Re-Seed with Correct USD-Based Pricing
 *
 * This script:
 * 1. Fetches all orders placed by the deployer
 * 2. Cancels them to recover escrowed tokens
 * 3. Re-seeds with correct pricing (~$0.10/SAGE based on STRK ~$0.084)
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: process.env.DEPLOYER_ADDRESS || '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
};

// Correct pricing: STRK ~$0.084, target SAGE = $0.10 = ~1.19 STRK per SAGE
const SELL_ORDERS = [
    { price: 1.19, amount: 10000 },    // Best ask - ~$0.10 per SAGE
    { price: 1.31, amount: 15000 },    // ~$0.11 per SAGE
    { price: 1.43, amount: 20000 },    // ~$0.12 per SAGE
    { price: 1.55, amount: 25000 },    // ~$0.13 per SAGE
    { price: 1.79, amount: 30000 },    // ~$0.15 per SAGE
];

const PAIR_ID = 1;  // Real STRK pair
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

async function getDeployerOrders(provider, accountAddress) {
    try {
        const result = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_user_orders',
            calldata: CallData.compile({ user: accountAddress }),
        });

        // Parse order IDs from response
        const orderIds = [];
        // First element is array length, then pairs of (low, high) for each u256
        const len = Number(result[0]);
        for (let i = 0; i < len; i++) {
            const low = BigInt(result[1 + i * 2] || '0');
            const high = BigInt(result[2 + i * 2] || '0');
            const orderId = low + (high << 128n);
            if (orderId > 0n) {
                orderIds.push(orderId);
            }
        }
        return orderIds;
    } catch (e) {
        log(`Error fetching orders: ${e.message}`, 'error');
        return [];
    }
}

async function getOrderDetails(provider, orderId) {
    try {
        const result = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_order',
            calldata: [orderId.toString(), '0'], // u256 as (low, high)
        });

        // Parse order struct
        // [order_id_low, order_id_high, maker, pair_id, side, order_type,
        //  price_low, price_high, amount_low, amount_high, remaining_low,
        //  remaining_high, status, created_at, expires_at]
        const status = Number(result[12] || '0');
        const pairId = Number(result[3] || '0');
        const priceLow = BigInt(result[6] || '0');
        const priceHigh = BigInt(result[7] || '0');
        const price = priceLow + (priceHigh << 128n);

        return {
            orderId,
            pairId,
            price: Number(price) / 1e18,
            status, // 0=Open, 1=PartialFill, 2=Filled, 3=Cancelled
            isOpen: status === 0 || status === 1,
        };
    } catch (e) {
        return null;
    }
}

async function main() {
    log('=== Re-Seed Orderbook with Correct USD-Based Pricing ===', 'header');

    if (!CONFIG.deployer.privateKey) {
        log('Error: DEPLOYER_PRIVATE_KEY not set', 'error');
        log('Run: export DEPLOYER_PRIVATE_KEY=0x...', 'info');
        process.exit(1);
    }

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Step 1: Get all deployer's orders
    log('\nStep 1: Fetching deployer orders...', 'info');
    const orderIds = await getDeployerOrders(provider, CONFIG.deployer.address);
    log(`  Found ${orderIds.length} orders`, 'info');

    // Step 2: Check which orders are still open and on pair 1
    const ordersToCancel = [];
    for (const orderId of orderIds) {
        const details = await getOrderDetails(provider, orderId);
        if (details && details.isOpen && details.pairId === PAIR_ID) {
            ordersToCancel.push(details);
            log(`  Order #${orderId}: ${details.price.toFixed(4)} STRK (${details.isOpen ? 'OPEN' : 'CLOSED'})`, 'info');
        }
    }

    log(`\n  ${ordersToCancel.length} open orders to cancel on pair ${PAIR_ID}`, 'info');

    // Step 3: Cancel all open orders
    if (ordersToCancel.length > 0) {
        log('\nStep 2: Cancelling old orders...', 'info');

        for (const order of ordersToCancel) {
            try {
                log(`  Cancelling order #${order.orderId} @ ${order.price.toFixed(4)} STRK...`, 'info');
                const { transaction_hash: cancelTx } = await account.execute({
                    contractAddress: CONFIG.otcOrderbook,
                    entrypoint: 'cancel_order',
                    calldata: CallData.compile({
                        order_id: cairo.uint256(order.orderId),
                    }),
                });
                await provider.waitForTransaction(cancelTx);
                log(`    Cancelled!`, 'success');
            } catch (e) {
                log(`    Failed: ${e.message}`, 'error');
            }

            // Small delay between cancellations
            await new Promise(r => setTimeout(r, 1000));
        }
    }

    // Step 4: Check SAGE balance
    log('\nStep 3: Checking SAGE balance...', 'info');
    const sageResult = await provider.callContract({
        contractAddress: CONFIG.sageToken,
        entrypoint: 'balance_of',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    const sageBalance = BigInt(sageResult[0]) + (BigInt(sageResult[1] || 0) << 128n);
    const sageFormatted = Number(sageBalance) / 1e18;
    log(`  SAGE balance: ${sageFormatted.toLocaleString()} SAGE`, 'info');

    const totalNeeded = SELL_ORDERS.reduce((sum, o) => sum + o.amount, 0);
    log(`  SAGE needed: ${totalNeeded.toLocaleString()} SAGE`, 'info');

    if (sageFormatted < totalNeeded) {
        log(`  Insufficient SAGE! Adjusting order amounts...`, 'warn');
        // Scale down orders proportionally
        const scale = (sageFormatted * 0.9) / totalNeeded;
        for (const order of SELL_ORDERS) {
            order.amount = Math.floor(order.amount * scale);
        }
    }

    // Step 5: Approve SAGE
    log('\nStep 4: Approving SAGE for orderbook...', 'info');
    const approveAmount = toWei(totalNeeded * 1.1);
    try {
        const { transaction_hash: approveTx } = await account.execute({
            contractAddress: CONFIG.sageToken,
            entrypoint: 'approve',
            calldata: CallData.compile({
                spender: CONFIG.otcOrderbook,
                amount: cairo.uint256(approveAmount),
            }),
        });
        await provider.waitForTransaction(approveTx);
        log('  Approved!', 'success');
    } catch (e) {
        log(`  Approval failed: ${e.message}`, 'error');
        return;
    }

    // Step 6: Place new orders with correct pricing
    log('\nStep 5: Placing new SELL orders with correct USD pricing...', 'info');
    log('  (Target: $0.10-$0.15 per SAGE, STRK @ ~$0.084)', 'info');

    for (const order of SELL_ORDERS) {
        if (order.amount <= 0) continue;

        const priceWei = toWei(order.price);
        const amountWei = toWei(order.amount);
        const usdPrice = (order.price * 0.084).toFixed(3);

        log(`  Placing: SELL ${order.amount.toLocaleString()} SAGE @ ${order.price} STRK (~$${usdPrice}/SAGE)...`, 'info');

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
            log(`    Order placed!`, 'success');
        } catch (e) {
            log(`    Failed: ${e.message}`, 'error');
        }

        await new Promise(r => setTimeout(r, 1500));
    }

    // Summary
    log('\n=== RESEEDING COMPLETE ===', 'header');
    log('New orderbook prices (STRK per SAGE):', 'success');
    for (const order of SELL_ORDERS) {
        const usdPrice = (order.price * 0.084).toFixed(3);
        log(`  ${order.price.toFixed(2)} STRK = ~$${usdPrice} per SAGE`, 'info');
    }
    log('\nRefresh the trade page to see updated prices!', 'success');
}

main().catch(e => {
    console.error('Error:', e.message);
    console.error(e);
    process.exit(1);
});
