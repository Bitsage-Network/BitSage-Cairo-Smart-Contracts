/**
 * Complete OTC Setup Script
 *
 * 1. Add ETH and USDC trading pairs
 * 2. Set Treasury as fee recipient
 * 3. Seed orderbook with SAGE sell orders at $0.10/SAGE
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',

    contracts: {
        otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
        sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    },

    tokens: {
        STRK: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
        ETH: '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
        USDC: '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8',
    },

    treasury: '0x6c2fc54050e474dc07637f42935ca6e18e8e17ab7bf9835504c85515beb860',

    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// $0.10 USD per SAGE pricing
// STRK ~$0.50 → 0.20 STRK/SAGE
// ETH ~$3500 → 0.0000286 ETH/SAGE
const PRICING = {
    STRK: [
        { price: 0.20, amount: 100000 },   // $0.10
        { price: 0.22, amount: 200000 },   // $0.11
        { price: 0.24, amount: 300000 },   // $0.12
        { price: 0.26, amount: 400000 },   // $0.13
        { price: 0.30, amount: 500000 },   // $0.15
        { price: 0.40, amount: 500000 },   // $0.20 premium
    ],
    ETH: [
        { price: 0.000028, amount: 100000 },
        { price: 0.000030, amount: 200000 },
        { price: 0.000032, amount: 300000 },
        { price: 0.000035, amount: 400000 },
        { price: 0.000040, amount: 500000 },
    ],
    USDC: [
        { price: 0.10, amount: 200000 },
        { price: 0.11, amount: 300000 },
        { price: 0.12, amount: 400000 },
        { price: 0.15, amount: 500000 },
        { price: 0.20, amount: 600000 },
    ],
};

function log(msg, type = 'info') {
    const colors = { info: '\x1b[36m', success: '\x1b[32m', warn: '\x1b[33m', error: '\x1b[31m', header: '\x1b[35m' };
    console.log(`${colors[type] || ''}${msg}\x1b[0m`);
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

async function getPair(provider, pairId) {
    try {
        const result = await provider.callContract({
            contractAddress: CONFIG.contracts.otcOrderbook,
            entrypoint: 'get_pair',
            calldata: CallData.compile({ pair_id: pairId }),
        });
        return {
            baseToken: result[0],
            quoteToken: result[1],
            minOrderSize: BigInt(result[2]) + (BigInt(result[3] || 0) << 128n),
            tickSize: BigInt(result[4]) + (BigInt(result[5] || 0) << 128n),
            isActive: result[6] !== '0x0' && result[6] !== 0n,
        };
    } catch {
        return null;
    }
}

async function main() {
    log('\n╔══════════════════════════════════════════════════════════════╗', 'header');
    log('║     BitSage OTC Complete Setup - $0.10/SAGE Launch          ║', 'header');
    log('╚══════════════════════════════════════════════════════════════╝', 'header');

    if (!CONFIG.deployer.privateKey) {
        log('\nError: DEPLOYER_PRIVATE_KEY not set', 'error');
        process.exit(1);
    }

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    log(`\nDeployer: ${CONFIG.deployer.address}`, 'info');

    // Step 1: Check SAGE balance
    log('\n=== Step 1: Checking SAGE Balance ===', 'header');
    const sageBalance = await getBalance(provider, CONFIG.contracts.sageToken, CONFIG.deployer.address);
    const sageFormatted = Number(sageBalance) / 1e18;
    log(`SAGE Balance: ${sageFormatted.toLocaleString()} SAGE`, 'info');

    // Calculate total needed
    const totalNeeded = PRICING.STRK.reduce((s, o) => s + o.amount, 0) +
        PRICING.ETH.reduce((s, o) => s + o.amount, 0) +
        PRICING.USDC.reduce((s, o) => s + o.amount, 0);
    log(`Total SAGE needed: ${totalNeeded.toLocaleString()} SAGE`, 'info');

    if (sageFormatted < totalNeeded) {
        log(`WARNING: Only seeding what's available`, 'warn');
    }

    // Step 2: Check existing pairs
    log('\n=== Step 2: Checking Trading Pairs ===', 'header');
    for (let i = 0; i <= 4; i++) {
        const pair = await getPair(provider, i);
        if (pair) {
            const quoteHex = pair.quoteToken.toString(16).padStart(64, '0');
            let tokenName = 'Unknown';
            if (quoteHex.includes(CONFIG.tokens.STRK.slice(2).toLowerCase())) tokenName = 'STRK';
            else if (quoteHex.includes(CONFIG.tokens.ETH.slice(2).toLowerCase())) tokenName = 'ETH';
            else if (quoteHex.includes(CONFIG.tokens.USDC.slice(2).toLowerCase())) tokenName = 'USDC';
            log(`  Pair ${i}: SAGE/${tokenName} - ${pair.isActive ? 'Active' : 'Inactive'}`, pair.isActive ? 'success' : 'warn');
        }
    }

    // Step 3: Add missing pairs
    log('\n=== Step 3: Adding Trading Pairs ===', 'header');

    const pairsToAdd = [
        { name: 'SAGE/ETH', token: CONFIG.tokens.ETH, minOrder: 10n * 10n ** 18n, tickSize: 10n ** 12n },
        { name: 'SAGE/USDC', token: CONFIG.tokens.USDC, minOrder: 10n * 10n ** 18n, tickSize: 10n ** 4n },
    ];

    for (const pairConfig of pairsToAdd) {
        try {
            log(`  Adding ${pairConfig.name}...`, 'info');
            const { transaction_hash } = await account.execute({
                contractAddress: CONFIG.contracts.otcOrderbook,
                entrypoint: 'add_pair',
                calldata: CallData.compile({
                    quote_token: pairConfig.token,
                    min_order_size: cairo.uint256(pairConfig.minOrder),
                    tick_size: cairo.uint256(pairConfig.tickSize),
                }),
            });
            await provider.waitForTransaction(transaction_hash);
            log(`  ✓ ${pairConfig.name} added!`, 'success');
        } catch (e) {
            if (e.message?.includes('already')) {
                log(`  ${pairConfig.name} already exists`, 'warn');
            } else {
                log(`  ✗ Failed: ${e.message?.slice(0, 100)}`, 'error');
            }
        }
    }

    // Step 4: Set fee recipient
    log('\n=== Step 4: Setting Fee Recipient to Treasury ===', 'header');
    try {
        log(`  Treasury: ${CONFIG.treasury}`, 'info');
        const { transaction_hash } = await account.execute({
            contractAddress: CONFIG.contracts.otcOrderbook,
            entrypoint: 'set_fee_recipient',
            calldata: CallData.compile({ recipient: CONFIG.treasury }),
        });
        await provider.waitForTransaction(transaction_hash);
        log(`  ✓ Fee recipient set to Treasury!`, 'success');
    } catch (e) {
        log(`  ✗ Failed: ${e.message?.slice(0, 100)}`, 'error');
    }

    // Step 5: Approve SAGE
    log('\n=== Step 5: Approving SAGE for OTC ===', 'header');
    try {
        const approveAmount = toWei(totalNeeded * 1.1);
        const { transaction_hash } = await account.execute({
            contractAddress: CONFIG.contracts.sageToken,
            entrypoint: 'approve',
            calldata: CallData.compile({
                spender: CONFIG.contracts.otcOrderbook,
                amount: cairo.uint256(approveAmount),
            }),
        });
        await provider.waitForTransaction(transaction_hash);
        log(`  ✓ SAGE approved!`, 'success');
    } catch (e) {
        log(`  ✗ Approval failed: ${e.message?.slice(0, 100)}`, 'error');
    }

    // Step 6: Seed orderbook
    log('\n=== Step 6: Seeding Orderbook with $0.10/SAGE Orders ===', 'header');

    const results = { placed: 0, failed: 0 };
    const SELL_SIDE = 1;
    const EXPIRES_IN = 604800n; // 7 days

    // Seed STRK pair (pair_id = 1)
    log('\n  --- SAGE/STRK Orders (Pair 1) ---', 'info');
    for (const order of PRICING.STRK) {
        try {
            const usdPrice = (order.price * 0.5).toFixed(2);
            log(`    ${order.amount.toLocaleString()} SAGE @ ${order.price} STRK ($${usdPrice})`, 'info');

            const { transaction_hash } = await account.execute({
                contractAddress: CONFIG.contracts.otcOrderbook,
                entrypoint: 'place_limit_order',
                calldata: CallData.compile({
                    pair_id: 1,
                    side: SELL_SIDE,
                    price: cairo.uint256(toWei(order.price)),
                    amount: cairo.uint256(toWei(order.amount)),
                    expires_in: EXPIRES_IN,
                }),
            });
            await provider.waitForTransaction(transaction_hash);
            log(`    ✓ Order placed`, 'success');
            results.placed++;
        } catch (e) {
            log(`    ✗ Failed: ${e.message?.slice(0, 80)}`, 'error');
            results.failed++;
        }
        await new Promise(r => setTimeout(r, 500));
    }

    // Seed ETH pair (pair_id = 2) if exists
    const ethPair = await getPair(provider, 2);
    if (ethPair?.isActive) {
        log('\n  --- SAGE/ETH Orders (Pair 2) ---', 'info');
        for (const order of PRICING.ETH) {
            try {
                const usdPrice = (order.price * 3500).toFixed(2);
                log(`    ${order.amount.toLocaleString()} SAGE @ ${order.price} ETH ($${usdPrice})`, 'info');

                const { transaction_hash } = await account.execute({
                    contractAddress: CONFIG.contracts.otcOrderbook,
                    entrypoint: 'place_limit_order',
                    calldata: CallData.compile({
                        pair_id: 2,
                        side: SELL_SIDE,
                        price: cairo.uint256(toWei(order.price)),
                        amount: cairo.uint256(toWei(order.amount)),
                        expires_in: EXPIRES_IN,
                    }),
                });
                await provider.waitForTransaction(transaction_hash);
                log(`    ✓ Order placed`, 'success');
                results.placed++;
            } catch (e) {
                log(`    ✗ Failed: ${e.message?.slice(0, 80)}`, 'error');
                results.failed++;
            }
            await new Promise(r => setTimeout(r, 500));
        }
    }

    // Seed USDC pair (pair_id = 3) if exists
    const usdcPair = await getPair(provider, 3);
    if (usdcPair?.isActive) {
        log('\n  --- SAGE/USDC Orders (Pair 3) ---', 'info');
        for (const order of PRICING.USDC) {
            try {
                log(`    ${order.amount.toLocaleString()} SAGE @ $${order.price}`, 'info');

                const { transaction_hash } = await account.execute({
                    contractAddress: CONFIG.contracts.otcOrderbook,
                    entrypoint: 'place_limit_order',
                    calldata: CallData.compile({
                        pair_id: 3,
                        side: SELL_SIDE,
                        price: cairo.uint256(toWei(order.price)),
                        amount: cairo.uint256(toWei(order.amount)),
                        expires_in: EXPIRES_IN,
                    }),
                });
                await provider.waitForTransaction(transaction_hash);
                log(`    ✓ Order placed`, 'success');
                results.placed++;
            } catch (e) {
                log(`    ✗ Failed: ${e.message?.slice(0, 80)}`, 'error');
                results.failed++;
            }
            await new Promise(r => setTimeout(r, 500));
        }
    }

    // Summary
    log('\n╔══════════════════════════════════════════════════════════════╗', 'header');
    log('║                    SETUP COMPLETE                            ║', 'header');
    log('╚══════════════════════════════════════════════════════════════╝', 'header');

    log(`\n  Orders placed: ${results.placed}`, 'success');
    if (results.failed > 0) log(`  Orders failed: ${results.failed}`, 'error');

    log('\n  Treasury (fee recipient):', 'info');
    log(`  ${CONFIG.treasury}`, 'success');

    log('\n  PRICING:', 'header');
    log('  ┌──────────────────────────────────────┐', 'info');
    log('  │ SAGE/STRK: 0.20 STRK = $0.10        │', 'info');
    log('  │ SAGE/ETH:  0.000028 ETH = $0.098    │', 'info');
    log('  │ SAGE/USDC: $0.10 directly           │', 'info');
    log('  └──────────────────────────────────────┘', 'info');

    log('\n✓ Users can now buy SAGE at $0.10 on your Trade page!', 'success');
}

main().catch(e => {
    log(`\nFatal error: ${e.message}`, 'error');
    console.error(e);
    process.exit(1);
});
