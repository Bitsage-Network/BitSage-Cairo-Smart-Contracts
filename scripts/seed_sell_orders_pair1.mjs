#!/usr/bin/env node
/**
 * Seed OTC Orderbook pair_id 1 with Sell Orders
 * This creates liquidity for users to buy SAGE with real STRK
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
};

// Sell orders - selling SAGE for STRK
// Prices in STRK per SAGE (anchored to USD target)
// STRK ~$0.084, target SAGE price $0.10 USD = ~1.19 STRK per SAGE
const SELL_ORDERS = [
    { price: 1.19, amount: 500 },    // Best ask - ~$0.10 per SAGE
    { price: 1.31, amount: 750 },    // ~$0.11 per SAGE
    { price: 1.43, amount: 1000 },   // ~$0.12 per SAGE
    { price: 1.55, amount: 1500 },   // ~$0.13 per SAGE
    { price: 1.79, amount: 2000 },   // ~$0.15 per SAGE
];

const PAIR_ID = 1;  // New pair with real STRK
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
    log('=== Seeding OTC Orderbook (Pair 1) with Sell Orders ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Calculate total SAGE needed
    const totalSageNeeded = SELL_ORDERS.reduce((sum, o) => sum + o.amount, 0);
    log(`Total SAGE needed: ${totalSageNeeded} SAGE`, 'info');

    // Check current SAGE balance
    let sageBalance = await getBalance(provider, CONFIG.sageToken, CONFIG.deployer.address);
    let sageFormatted = Number(sageBalance) / 1e18;
    log(`Current SAGE balance: ${sageFormatted.toLocaleString()} SAGE`, 'info');

    if (sageFormatted < totalSageNeeded) {
        log(`Insufficient SAGE balance! Need ${totalSageNeeded}, have ${sageFormatted}`, 'error');
        log('Please fund the deployer with SAGE tokens first.', 'warn');
        return;
    }

    // Step 1: Approve SAGE for OTC Orderbook
    log('\nStep 1: Approving SAGE for OTC Orderbook...', 'info');
    const approveAmount = toWei(totalSageNeeded * 1.1); // 10% buffer

    try {
        const { transaction_hash: approveTx } = await account.execute({
            contractAddress: CONFIG.sageToken,
            entrypoint: 'approve',
            calldata: CallData.compile({
                spender: CONFIG.otcOrderbook,
                amount: cairo.uint256(approveAmount),
            }),
        });
        log(`Approve tx: ${approveTx}`, 'info');
        await provider.waitForTransaction(approveTx);
        log('SAGE approved!', 'success');
    } catch (e) {
        log(`Approve failed: ${e.message}`, 'error');
        return;
    }

    // Step 2: Place sell orders
    log('\nStep 2: Placing sell orders...', 'info');

    for (const order of SELL_ORDERS) {
        const priceWei = toWei(order.price);
        const amountWei = toWei(order.amount);

        log(`Placing SELL order: ${order.amount} SAGE @ ${order.price} STRK...`, 'info');

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
            log(`Order tx: ${orderTx}`, 'info');
            await provider.waitForTransaction(orderTx);
            log(`Order placed!`, 'success');
        } catch (e) {
            log(`Order failed: ${e.message}`, 'error');
        }
    }

    // Final balance check
    sageBalance = await getBalance(provider, CONFIG.sageToken, CONFIG.deployer.address);
    sageFormatted = Number(sageBalance) / 1e18;
    log(`\nFinal SAGE balance: ${sageFormatted.toLocaleString()} SAGE`, 'info');

    log('\n=== Done! Liquidity seeded on pair_id 1 ===', 'header');
    log('Users can now buy SAGE with real STRK tokens.', 'success');
}

main().catch(console.error);
