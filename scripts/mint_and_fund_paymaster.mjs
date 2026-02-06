#!/usr/bin/env node
/**
 * BitSage Network - Mint SAGE and Fund Paymaster
 *
 * Mints SAGE tokens to the deployer, then deposits into the Paymaster for gas sponsorship.
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

// Contract addresses (using OLD SAGE token where deployer has balance)
const SAGE_TOKEN = '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850';
const PAYMASTER = '0x3370e353a2f3f6880f1a90708792279b8dc9d03b8560d7a95dfa08b9f9ed8bb';

// Amounts - depositing from existing balance, no minting needed
const DEPOSIT_AMOUNT = 100000n * 10n ** 18n;  // 100,000 SAGE to deposit to paymaster

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

function toU256Calldata(amount) {
    const low = amount & ((1n << 128n) - 1n);
    const high = amount >> 128n;
    return { low, high };
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage - Mint SAGE and Fund Paymaster', 'info');
    log('='.repeat(60), 'info');

    // Initialize provider and account
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
    });

    log(`Deployer (Owner): ${CONFIG.deployer.address}`, 'info');
    log(`SAGE Token: ${SAGE_TOKEN}`, 'info');
    log(`Paymaster: ${PAYMASTER}`, 'info');

    // Step 1: Check balance (deployer already has SAGE tokens)
    log('\n[1/3] Checking SAGE balance...', 'info');

    const balanceResult = await provider.callContract({
        contractAddress: SAGE_TOKEN,
        entrypoint: 'balance_of',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    const balance = BigInt(balanceResult[0]) + (BigInt(balanceResult[1] || 0) << 128n);
    log(`Deployer SAGE balance: ${formatToken(balance)} SAGE`, 'success');

    if (balance < DEPOSIT_AMOUNT) {
        log(`Insufficient balance. Need ${formatToken(DEPOSIT_AMOUNT)}, have ${formatToken(balance)}`, 'error');
        process.exit(1);
    }

    // Step 2: Approve Paymaster
    log('\n[2/3] Approving Paymaster...', 'info');

    const approveCalldata = CallData.compile({
        spender: PAYMASTER,
        amount: toU256Calldata(DEPOSIT_AMOUNT),
    });

    const { transaction_hash: approveTxHash } = await account.execute({
        contractAddress: SAGE_TOKEN,
        entrypoint: 'approve',
        calldata: approveCalldata,
    });

    log(`Approve tx: ${approveTxHash}`, 'info');
    await provider.waitForTransaction(approveTxHash);
    log('Approval confirmed!', 'success');

    // Step 3: Deposit to Paymaster
    log('\n[3/3] Depositing to Paymaster...', 'info');

    const depositCalldata = CallData.compile({
        amount: toU256Calldata(DEPOSIT_AMOUNT),
    });

    const { transaction_hash: depositTxHash } = await account.execute({
        contractAddress: PAYMASTER,
        entrypoint: 'deposit_funds',
        calldata: depositCalldata,
    });

    log(`Deposit tx: ${depositTxHash}`, 'info');
    await provider.waitForTransaction(depositTxHash);
    log('Deposit confirmed!', 'success');

    // Verify Paymaster balance
    const paymasterBalanceResult = await provider.callContract({
        contractAddress: PAYMASTER,
        entrypoint: 'get_balance',
        calldata: [],
    });
    const paymasterBalance = BigInt(paymasterBalanceResult[0]) + (BigInt(paymasterBalanceResult[1] || 0) << 128n);

    // Summary
    log('\n' + '='.repeat(60), 'info');
    log('COMPLETE', 'success');
    log('='.repeat(60), 'info');

    console.log(`
Paymaster Funded: ${formatToken(DEPOSIT_AMOUNT)} SAGE
Paymaster Balance: ${formatToken(paymasterBalance)} SAGE

Explorer:
  https://sepolia.starkscan.co/contract/${PAYMASTER}

Workers can now use the Paymaster for gas sponsorship!
`);
}

main().catch((error) => {
    log(`Failed: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
});
