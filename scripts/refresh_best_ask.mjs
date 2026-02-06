#!/usr/bin/env node
/**
 * Refresh best_ask on OTC Orderbook
 *
 * This script places a small sell order on pair_id 1 (SAGE/STRK) to refresh
 * the best_ask value which may have become stale after order fills.
 *
 * The issue: When an order is filled, the contract may not update best_ask
 * to the next price level, causing market orders to fail with "No liquidity".
 */

import { Account, RpcProvider, CallData, cairo, constants } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
};

// Order parameters to refresh best_ask on pair_id 1
const ORDER = {
    pair_id: 1,                                      // SAGE/STRK pair with real STRK
    side: 1,                                         // 1 = Sell
    price: 100000000000000000n,                      // 0.10 STRK (18 decimals)
    amount: 100000000000000000000n,                  // 100 SAGE (18 decimals)
    expires_in: 604800n,                             // 7 days in seconds
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

async function getBestAsk(provider, pairId) {
    try {
        const result = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_best_ask',
            calldata: CallData.compile({ pair_id: pairId }),
        });
        return BigInt(result[0]) + (BigInt(result[1] || 0) << 128n);
    } catch {
        return 0n;
    }
}

async function main() {
    log('=== Refreshing best_ask on OTC Orderbook ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

    // Create account properly (starknet.js v9 API)
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Step 1: Check current best_ask
    log('\nStep 1: Checking current best_ask for pair 1...', 'info');
    const currentBestAsk = await getBestAsk(provider, 1);
    log(`  Current best_ask: ${Number(currentBestAsk) / 1e18} STRK`, 'info');

    if (currentBestAsk > 0n) {
        log('  best_ask is already set! Market orders should work.', 'success');
        log('  Exiting without placing new order.', 'info');
        return;
    }

    log('  best_ask is 0 - need to refresh by placing a sell order', 'warn');

    // Step 2: Check SAGE balance
    log('\nStep 2: Checking SAGE balance...', 'info');
    const sageBalance = await getBalance(provider, CONFIG.sageToken, CONFIG.deployer.address);
    log(`  Deployer SAGE: ${Number(sageBalance) / 1e18} SAGE`, 'info');

    if (sageBalance < ORDER.amount) {
        log(`  Insufficient SAGE balance. Need ${Number(ORDER.amount) / 1e18} SAGE`, 'error');
        return;
    }

    // Step 3: Approve SAGE for orderbook
    log('\nStep 3: Approving SAGE for orderbook...', 'info');

    const approveAmount = ORDER.amount * 2n; // Extra for fees
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
        log('  Waiting for confirmation...', 'info');
        await provider.waitForTransaction(approveTx);
        log('  Approval confirmed!', 'success');
    } catch (e) {
        log(`  Approval failed: ${e.message}`, 'error');
        return;
    }

    // Step 4: Place limit sell order
    log('\nStep 4: Placing limit sell order to refresh best_ask...', 'info');
    log(`  Pair ID: ${ORDER.pair_id}`, 'info');
    log(`  Side: Sell`, 'info');
    log(`  Price: ${Number(ORDER.price) / 1e18} STRK per SAGE`, 'info');
    log(`  Amount: ${Number(ORDER.amount) / 1e18} SAGE`, 'info');
    log(`  Expires in: ${Number(ORDER.expires_in) / 86400} days`, 'info');

    try {
        const { transaction_hash: orderTx } = await account.execute({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'place_limit_order',
            calldata: CallData.compile({
                pair_id: ORDER.pair_id,
                side: ORDER.side,
                price: cairo.uint256(ORDER.price),
                amount: cairo.uint256(ORDER.amount),
                expires_in: ORDER.expires_in,
            }),
        });
        log(`  Order TX: ${orderTx}`, 'info');
        log('  Waiting for confirmation...', 'info');
        await provider.waitForTransaction(orderTx);
        log('  Order placed!', 'success');
    } catch (e) {
        log(`  Order failed: ${e.message}`, 'error');
        console.error(e);
        return;
    }

    // Step 5: Verify best_ask is now set
    log('\nStep 5: Verifying best_ask is now set...', 'info');
    const newBestAsk = await getBestAsk(provider, 1);
    log(`  New best_ask: ${Number(newBestAsk) / 1e18} STRK`, 'info');

    if (newBestAsk > 0n) {
        log('\n=== SUCCESS ===', 'header');
        log('best_ask is now set! Market buy orders should work.', 'success');
        log(`View on explorer: https://sepolia.starkscan.co/contract/${CONFIG.otcOrderbook}`, 'info');
    } else {
        log('\n=== WARNING ===', 'header');
        log('best_ask is still 0 after placing order. Contract may need investigation.', 'warn');
    }
}

main().catch(e => {
    console.error('Error:', e.message);
    console.error(e);
    process.exit(1);
});
