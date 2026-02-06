#!/usr/bin/env node
/**
 * BitSage Network - Fund Paymaster with SAGE Tokens
 *
 * Deposits SAGE tokens into the Paymaster contract for gas sponsorship.
 */

import { Account, RpcProvider, CallData, Contract } from 'starknet';

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

// Contract addresses
const SAGE_TOKEN = '0x04321b7282ae6aa354988eed57f2ff851314af8524de8b1f681a128003cc4ea5';
const PAYMASTER = '0x6c838b18b68070d18368c815d70b1736d952878f5f37fa1769a837200616a72';

// Amount to deposit: 10,000 SAGE tokens
const DEPOSIT_AMOUNT = 10000n * 10n ** 18n;

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

function formatToken(amount, decimals = 18) {
    return (Number(amount) / 10 ** decimals).toLocaleString();
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage Paymaster Funding', 'info');
    log('='.repeat(60), 'info');

    // Initialize provider and account
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
    });

    log(`Deployer: ${CONFIG.deployer.address}`, 'info');
    log(`Paymaster: ${PAYMASTER}`, 'info');
    log(`SAGE Token: ${SAGE_TOKEN}`, 'info');
    log(`Amount to deposit: ${formatToken(DEPOSIT_AMOUNT)} SAGE`, 'info');

    // Check deployer SAGE balance
    log('\n[1/4] Checking balances...', 'info');

    const deployerBalanceResult = await provider.callContract({
        contractAddress: SAGE_TOKEN,
        entrypoint: 'balance_of',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    const deployerBalance = BigInt(deployerBalanceResult[0]) + (BigInt(deployerBalanceResult[1] || 0) << 128n);
    log(`Deployer SAGE balance: ${formatToken(deployerBalance)} SAGE`, 'info');

    if (deployerBalance < DEPOSIT_AMOUNT) {
        log(`Insufficient SAGE balance. Need ${formatToken(DEPOSIT_AMOUNT)}, have ${formatToken(deployerBalance)}`, 'error');
        process.exit(1);
    }

    // Step 2: Approve Paymaster to spend SAGE tokens
    log('\n[2/4] Approving Paymaster to spend SAGE...', 'info');

    const amountLow = DEPOSIT_AMOUNT & ((1n << 128n) - 1n);
    const amountHigh = DEPOSIT_AMOUNT >> 128n;

    const approveCalldata = CallData.compile({
        spender: PAYMASTER,
        amount: { low: amountLow, high: amountHigh },
    });

    const { transaction_hash: approveTxHash } = await account.execute({
        contractAddress: SAGE_TOKEN,
        entrypoint: 'approve',
        calldata: approveCalldata,
    });

    log(`Approve tx: ${approveTxHash}`, 'info');
    log('Waiting for approval confirmation...', 'info');
    await provider.waitForTransaction(approveTxHash);
    log('Approval confirmed!', 'success');

    // Step 3: Deposit funds into Paymaster
    log('\n[3/4] Depositing SAGE into Paymaster...', 'info');

    const depositCalldata = CallData.compile({
        amount: { low: amountLow, high: amountHigh },
    });

    const { transaction_hash: depositTxHash } = await account.execute({
        contractAddress: PAYMASTER,
        entrypoint: 'deposit_funds',
        calldata: depositCalldata,
    });

    log(`Deposit tx: ${depositTxHash}`, 'info');
    log('Waiting for deposit confirmation...', 'info');
    await provider.waitForTransaction(depositTxHash);
    log('Deposit confirmed!', 'success');

    // Step 4: Verify Paymaster balance
    log('\n[4/4] Verifying Paymaster balance...', 'info');

    const paymasterBalanceResult = await provider.callContract({
        contractAddress: PAYMASTER,
        entrypoint: 'get_balance',
        calldata: [],
    });
    const paymasterBalance = BigInt(paymasterBalanceResult[0]) + (BigInt(paymasterBalanceResult[1] || 0) << 128n);
    log(`Paymaster SAGE balance: ${formatToken(paymasterBalance)} SAGE`, 'success');

    // Summary
    log('\n' + '='.repeat(60), 'info');
    log('FUNDING COMPLETE', 'success');
    log('='.repeat(60), 'info');

    console.log(`
Paymaster: ${PAYMASTER}
Balance: ${formatToken(paymasterBalance)} SAGE

Workers can now use gas sponsorship!

Explorer:
  Approve: https://sepolia.starkscan.co/tx/${approveTxHash}
  Deposit: https://sepolia.starkscan.co/tx/${depositTxHash}
`);
}

main().catch((error) => {
    log(`Funding failed: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
});
