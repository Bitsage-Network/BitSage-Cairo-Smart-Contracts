#!/usr/bin/env node
/**
 * BitSage Network - Fund Faucet with SAGE Tokens
 *
 * Transfers SAGE tokens to the Faucet contract for distribution.
 */

import { Account, RpcProvider, CallData, hash } from 'starknet';

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
};

// Contract addresses (from latest deployment)
const SAGE_TOKEN = '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850';
const FAUCET = '0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3';

// Amount to fund (9999 SAGE - just under the 10k large transfer threshold)
const FUND_AMOUNT = 9999n * 10n ** 18n;

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

function formatSAGE(amount) {
    return (BigInt(amount) / 10n ** 18n).toString();
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage Faucet Funding Script', 'info');
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
    log(`SAGEToken: ${SAGE_TOKEN}`, 'info');
    log(`Faucet: ${FAUCET}`, 'info');
    log(`Amount to transfer: ${formatSAGE(FUND_AMOUNT)} SAGE`, 'info');

    // Check deployer balance using direct call
    log('\nChecking balances...', 'info');

    const balanceOfSelector = hash.getSelectorFromName('balance_of');

    const deployerBalanceResult = await provider.callContract({
        contractAddress: SAGE_TOKEN,
        entrypoint: 'balance_of',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    // u256 returns as [low, high]
    const deployerBalance = BigInt(deployerBalanceResult[0]) + (BigInt(deployerBalanceResult[1] || 0) << 128n);
    log(`Deployer SAGE balance: ${formatSAGE(deployerBalance)} SAGE`, 'info');

    const faucetBalanceResult = await provider.callContract({
        contractAddress: SAGE_TOKEN,
        entrypoint: 'balance_of',
        calldata: CallData.compile({ account: FAUCET }),
    });
    const faucetBalance = BigInt(faucetBalanceResult[0]) + (BigInt(faucetBalanceResult[1] || 0) << 128n);
    log(`Faucet SAGE balance: ${formatSAGE(faucetBalance)} SAGE`, 'info');

    if (deployerBalance < FUND_AMOUNT) {
        log(`Insufficient balance. Need ${formatSAGE(FUND_AMOUNT)} SAGE, have ${formatSAGE(deployerBalance)} SAGE`, 'error');
        process.exit(1);
    }

    // Execute transfer using multicall
    log('\nTransferring SAGE to Faucet...', 'info');

    // Split u256 into low/high for Starknet
    const amountLow = FUND_AMOUNT & ((1n << 128n) - 1n);
    const amountHigh = FUND_AMOUNT >> 128n;

    const transferCalldata = CallData.compile({
        recipient: FAUCET,
        amount: { low: amountLow, high: amountHigh }
    });

    try {
        const { transaction_hash } = await account.execute({
            contractAddress: SAGE_TOKEN,
            entrypoint: 'transfer',
            calldata: transferCalldata,
        });
        log(`Transaction submitted: ${transaction_hash}`, 'info');

        log('Waiting for confirmation...', 'info');
        await provider.waitForTransaction(transaction_hash);
        log('Transfer confirmed!', 'success');

        // Verify new balances
        const newDeployerBalanceResult = await provider.callContract({
            contractAddress: SAGE_TOKEN,
            entrypoint: 'balance_of',
            calldata: CallData.compile({ account: CONFIG.deployer.address }),
        });
        const newDeployerBalance = BigInt(newDeployerBalanceResult[0]) + (BigInt(newDeployerBalanceResult[1] || 0) << 128n);

        const newFaucetBalanceResult = await provider.callContract({
            contractAddress: SAGE_TOKEN,
            entrypoint: 'balance_of',
            calldata: CallData.compile({ account: FAUCET }),
        });
        const newFaucetBalance = BigInt(newFaucetBalanceResult[0]) + (BigInt(newFaucetBalanceResult[1] || 0) << 128n);

        log('\nFinal balances:', 'info');
        log(`Deployer: ${formatSAGE(newDeployerBalance)} SAGE`, 'info');
        log(`Faucet: ${formatSAGE(newFaucetBalance)} SAGE`, 'success');

        log('\nFaucet funded successfully!', 'success');
        log(`Explorer: https://sepolia.starkscan.co/tx/${transaction_hash}`, 'info');

    } catch (error) {
        log(`Transfer failed: ${error.message}`, 'error');
        console.error(error);
        process.exit(1);
    }
}

main().catch(console.error);
