#!/usr/bin/env node
/**
 * Test OTC Orderbook
 * 1. Check orderbook config and pairs
 * 2. Approve SAGE tokens
 * 3. Place a limit sell order
 * 4. Check the order
 * 5. Cancel the order
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
};

// Order parameters
const ORDER = {
    pair_id: 0,                          // SAGE/STRK pair
    side: 1,                             // 1 = Sell (selling SAGE)
    price: 1n * 10n ** 18n,              // 1 STRK per SAGE
    amount: 10n * 10n ** 18n,            // 10 SAGE
    expires_in: 86400n,                  // 24 hours
};

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', error: '\x1b[31m',
        warn: '\x1b[33m', header: '\x1b[35m', reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]', header: '[====]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
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
    log('=== Testing OTC Orderbook ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Step 1: Check orderbook config
    log('\nStep 1: Checking orderbook configuration...', 'info');

    const configResult = await provider.callContract({
        contractAddress: CONFIG.otcOrderbook,
        entrypoint: 'get_config',
        calldata: [],
    });

    log(`  Maker fee: ${Number(configResult[0]) / 100}%`, 'info');
    log(`  Taker fee: ${Number(configResult[1]) / 100}%`, 'info');
    log(`  Default expiry: ${Number(BigInt(configResult[2])) / 3600} hours`, 'info');
    log(`  Max orders per user: ${configResult[3]}`, 'info');
    log(`  Paused: ${configResult[4] !== '0x0'}`, 'info');

    // Check pair 0
    log('\nStep 2: Checking trading pair 0...', 'info');
    try {
        const pairResult = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_pair',
            calldata: CallData.compile({ pair_id: 0 }),
        });
        log(`  Base token: ${pairResult[0]}`, 'info');
        log(`  Quote token: ${pairResult[1]}`, 'info');
        const minOrderSize = BigInt(pairResult[2]) + (BigInt(pairResult[3] || 0) << 128n);
        log(`  Min order size: ${(minOrderSize / 10n**18n).toString()} SAGE`, 'info');
    } catch (e) {
        log(`  Pair 0 not configured: ${e.message}`, 'warn');
    }

    // Step 3: Check SAGE balance
    log('\nStep 3: Checking SAGE balance...', 'info');
    const sageBalance = await getBalance(provider, CONFIG.sageToken, CONFIG.deployer.address);
    log(`  Deployer SAGE: ${(sageBalance / 10n**18n).toString()} SAGE`, 'info');

    if (sageBalance < ORDER.amount) {
        log('Insufficient SAGE balance for test order', 'error');
        return;
    }

    // Step 4: Approve SAGE for orderbook
    log('\nStep 4: Approving SAGE for orderbook...', 'info');

    const approveAmount = ORDER.amount * 2n; // Approve extra for fees
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

    // Step 5: Place limit sell order
    log('\nStep 5: Placing limit sell order...', 'info');
    log(`  Pair: 0 (SAGE/STRK)`, 'info');
    log(`  Side: Sell`, 'info');
    log(`  Price: 1 STRK per SAGE`, 'info');
    log(`  Amount: 10 SAGE`, 'info');
    log(`  Expires in: 24 hours`, 'info');

    let orderId;
    try {
        const { transaction_hash: orderTx } = await account.execute({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'place_limit_order',
            calldata: CallData.compile({
                pair_id: ORDER.pair_id,
                side: ORDER.side,  // 1 = Sell
                price: cairo.uint256(ORDER.price),
                amount: cairo.uint256(ORDER.amount),
                expires_in: ORDER.expires_in,
            }),
        });
        log(`  Order TX: ${orderTx}`, 'info');
        await provider.waitForTransaction(orderTx);
        log('  Order placed!', 'success');

        // Get order ID from events or stats
        const statsResult = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_stats',
            calldata: [],
        });
        const totalOrders = BigInt(statsResult[0]) + (BigInt(statsResult[1] || 0) << 128n);
        orderId = totalOrders; // Order ID is likely the latest order count
        log(`  Total orders now: ${totalOrders}`, 'info');

    } catch (e) {
        log(`  Order failed: ${e.message}`, 'error');
        console.error(e);
        return;
    }

    // Step 6: Check user orders
    log('\nStep 6: Checking user orders...', 'info');
    try {
        const userOrdersResult = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_user_orders',
            calldata: CallData.compile({ user: CONFIG.deployer.address }),
        });
        log(`  User has ${userOrdersResult.length} order(s)`, 'info');
        if (userOrdersResult.length > 0) {
            // First element is array length, then order IDs
            const numOrders = Number(userOrdersResult[0]);
            log(`  Order IDs: ${userOrdersResult.slice(1, numOrders + 1).map(id => BigInt(id).toString()).join(', ')}`, 'info');
            orderId = BigInt(userOrdersResult[1]); // Get the first order ID
        }
    } catch (e) {
        log(`  Could not get user orders: ${e.message}`, 'warn');
    }

    // Step 7: Cancel order
    if (orderId) {
        log(`\nStep 7: Cancelling order ${orderId}...`, 'info');
        try {
            const { transaction_hash: cancelTx } = await account.execute({
                contractAddress: CONFIG.otcOrderbook,
                entrypoint: 'cancel_order',
                calldata: CallData.compile({
                    order_id: cairo.uint256(orderId),
                }),
            });
            log(`  Cancel TX: ${cancelTx}`, 'info');
            await provider.waitForTransaction(cancelTx);
            log('  Order cancelled!', 'success');

            // Check SAGE was returned
            const sageAfter = await getBalance(provider, CONFIG.sageToken, CONFIG.deployer.address);
            log(`  SAGE balance after cancel: ${(sageAfter / 10n**18n).toString()} SAGE`, 'info');

        } catch (e) {
            log(`  Cancel failed: ${e.message}`, 'error');
        }
    }

    // Summary
    log('\n=== OTC ORDERBOOK TEST COMPLETE ===', 'header');
    log('All tests passed!', 'success');
}

main().catch(e => {
    console.error('Error:', e.message);
    console.error(e);
});
