#!/usr/bin/env node
/**
 * Add SAGE/STRK trading pair with REAL STRK token
 * The existing pair_id 0 uses a mock STRK token, this adds pair_id 1 with real STRK
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    // Real STRK token on Sepolia
    realStrkToken: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
    // Mock STRK (currently in pair_id 0)
    mockStrkToken: '0x53b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080',
};

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', error: '\x1b[31m',
        warn: '\x1b[33m', header: '\x1b[35m', reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]', header: '[====]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

async function getPairInfo(provider, pairId) {
    try {
        const result = await provider.callContract({
            contractAddress: CONFIG.otcOrderbook,
            entrypoint: 'get_pair_info',
            calldata: CallData.compile({ pair_id: pairId }),
        });
        return {
            baseToken: result[0],
            quoteToken: result[1],
            minOrderSize: BigInt(result[2]) + (BigInt(result[3] || 0) << 128n),
            tickSize: BigInt(result[4]) + (BigInt(result[5] || 0) << 128n),
            isActive: result[6] === '0x1' || result[6] === true,
        };
    } catch (e) {
        return null;
    }
}

async function main() {
    log('=== Adding SAGE/STRK Pair with REAL STRK Token ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Check existing pairs
    log('Checking existing pairs...');
    for (let i = 0; i < 5; i++) {
        const pair = await getPairInfo(provider, i);
        if (pair) {
            const isRealStrk = pair.quoteToken.toLowerCase().includes('4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d');
            const isMockStrk = pair.quoteToken.toLowerCase().includes('53b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080');
            log(`  Pair ${i}: quote=${pair.quoteToken.slice(0, 20)}... active=${pair.isActive} ${isRealStrk ? '(REAL STRK)' : isMockStrk ? '(MOCK STRK)' : ''}`);
        } else {
            log(`  Pair ${i}: not configured`);
            break;
        }
    }

    // Parameters for the new pair
    // min_order_size: 1 SAGE (1 * 10^18)
    const minOrderSize = cairo.uint256(BigInt('1000000000000000000'));
    // tick_size: 0.0001 STRK (10^14) - allows 4 decimal places
    const tickSize = cairo.uint256(BigInt('100000000000000'));

    log('');
    log('Adding new pair with REAL STRK token...');
    log(`  Quote Token: ${CONFIG.realStrkToken}`);
    log(`  Min Order Size: 1 SAGE`);
    log(`  Tick Size: 0.0001 STRK`);

    try {
        const tx = await account.execute([
            {
                contractAddress: CONFIG.otcOrderbook,
                entrypoint: 'add_pair',
                calldata: CallData.compile({
                    quote_token: CONFIG.realStrkToken,
                    min_order_size: minOrderSize,
                    tick_size: tickSize,
                }),
            },
        ]);

        log(`Transaction hash: ${tx.transaction_hash}`, 'info');
        log('Waiting for confirmation...', 'info');

        await provider.waitForTransaction(tx.transaction_hash);
        log('Transaction confirmed!', 'success');

        // Verify the new pair
        log('');
        log('Verifying pairs after addition...');
        for (let i = 0; i < 5; i++) {
            const pair = await getPairInfo(provider, i);
            if (pair) {
                const isRealStrk = pair.quoteToken.toLowerCase().includes('4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d');
                log(`  Pair ${i}: quote=${pair.quoteToken.slice(0, 20)}... active=${pair.isActive} ${isRealStrk ? '(REAL STRK) <-- NEW' : ''}`, isRealStrk ? 'success' : 'info');
            } else {
                break;
            }
        }

        log('');
        log('=== IMPORTANT: Update Frontend ===', 'header');
        log('Update PAIR_ID_MAP to use the new pair_id for SAGE_STRK:', 'warn');
        log('  Old: "SAGE_STRK": 0  (uses Mock STRK)', 'info');
        log('  New: "SAGE_STRK": 1  (uses Real STRK)', 'success');

    } catch (error) {
        log(`Error: ${error.message || error}`, 'error');
        if (error.message) {
            log(`Full error: ${JSON.stringify(error, null, 2)}`, 'error');
        }
    }
}

main().catch(console.error);
