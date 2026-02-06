#!/usr/bin/env node
/**
 * BitSage Network - Fund Worker Wallet with STRK for Gas
 *
 * Transfers STRK tokens to the worker wallet for gas fees.
 */

import { Account, RpcProvider, CallData } from 'starknet';

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    rpcUrl: 'https://starknet-sepolia-rpc.publicnode.com',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// STRK Token on Sepolia
const STRK_TOKEN = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

// Worker wallet address (H100 GPU worker)
const WORKER_ADDRESS = '0x02654fb9ee4627d61db370f6e1849c9cbf16cd54a2a2e72a0be50a6ecceeee2a';

// Amount to transfer: 1 STRK (should be enough for many transactions)
const FUND_AMOUNT = 1n * 10n ** 18n;

// ============================================================================
// HELPERS
// ============================================================================

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m',
        success: '\x1b[32m',
        error: '\x1b[31m',
        warn: '\x1b[33m',
        reset: '\x1b[0m',
    };
    const prefix = {
        info: '[INFO]',
        success: '[OK]',
        error: '[ERR]',
        warn: '[WARN]',
    };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

function formatSTRK(amount) {
    return (BigInt(amount) / 10n ** 18n).toString();
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage Worker STRK Funding Script', 'info');
    log('='.repeat(60), 'info');

    // Initialize provider and account
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    log(`Using RPC: ${CONFIG.rpcUrl}`, 'info');
    log(`Deployer: ${CONFIG.deployer.address}`, 'info');
    log(`STRK Token: ${STRK_TOKEN}`, 'info');
    log(`Worker: ${WORKER_ADDRESS}`, 'info');
    log(`Amount to transfer: ${formatSTRK(FUND_AMOUNT)} STRK`, 'info');

    // Check deployer balance
    log('\nChecking balances...', 'info');

    const deployerBalanceResult = await provider.callContract({
        contractAddress: STRK_TOKEN,
        entrypoint: 'balanceOf',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    const deployerBalance = BigInt(deployerBalanceResult[0]) + (BigInt(deployerBalanceResult[1] || 0) << 128n);
    log(`Deployer STRK balance: ${formatSTRK(deployerBalance)} STRK`, 'info');

    const workerBalanceResult = await provider.callContract({
        contractAddress: STRK_TOKEN,
        entrypoint: 'balanceOf',
        calldata: CallData.compile({ account: WORKER_ADDRESS }),
    });
    const workerBalance = BigInt(workerBalanceResult[0]) + (BigInt(workerBalanceResult[1] || 0) << 128n);
    log(`Worker STRK balance: ${formatSTRK(workerBalance)} STRK`, 'info');

    if (deployerBalance < FUND_AMOUNT) {
        log(`Insufficient balance. Need ${formatSTRK(FUND_AMOUNT)} STRK, have ${formatSTRK(deployerBalance)} STRK`, 'error');
        process.exit(1);
    }

    // Execute transfer
    log('\nTransferring STRK to Worker...', 'info');

    // Split u256 into low/high for Starknet
    const amountLow = FUND_AMOUNT & ((1n << 128n) - 1n);
    const amountHigh = FUND_AMOUNT >> 128n;

    const transferCalldata = CallData.compile({
        recipient: WORKER_ADDRESS,
        amount: { low: amountLow, high: amountHigh }
    });

    try {
        const { transaction_hash } = await account.execute({
            contractAddress: STRK_TOKEN,
            entrypoint: 'transfer',
            calldata: transferCalldata,
        });
        log(`Transaction submitted: ${transaction_hash}`, 'info');

        log('Waiting for confirmation...', 'info');
        await provider.waitForTransaction(transaction_hash);
        log('Transfer confirmed!', 'success');

        // Verify new balances
        const newWorkerBalanceResult = await provider.callContract({
            contractAddress: STRK_TOKEN,
            entrypoint: 'balanceOf',
            calldata: CallData.compile({ account: WORKER_ADDRESS }),
        });
        const newWorkerBalance = BigInt(newWorkerBalanceResult[0]) + (BigInt(newWorkerBalanceResult[1] || 0) << 128n);

        log('\nFinal balances:', 'info');
        log(`Worker: ${formatSTRK(newWorkerBalance)} STRK`, 'success');

        log('\nWorker funded successfully!', 'success');
        log(`Explorer: https://sepolia.starkscan.co/tx/${transaction_hash}`, 'info');

    } catch (error) {
        log(`Transfer failed: ${error.message}`, 'error');
        console.error(error);
        process.exit(1);
    }
}

main().catch(console.error);
