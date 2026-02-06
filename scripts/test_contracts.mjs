#!/usr/bin/env node
/**
 * BitSage Contract Testing Script
 * Tests: Faucet, OTC Orderbook, Account Funding
 */

import { Account, RpcProvider, Contract, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// Redeployed contract addresses (Dec 31, 2025)
const CONTRACTS = {
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    faucet: '0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3',
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    jobManager: '0x355b8c5e9dd3310a3c361559b53cfcfdc20b2bf7d5bd87a84a83389b8cbb8d3',
    cdcPool: '0x1f978cad424f87a6cea8aa27cbcbba10b9a50d41e296ae07e1c635392a2339',
};

// Test accounts to fund
const TEST_ACCOUNTS = [
    '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7', // Example test account 1
    '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d', // Example test account 2
];

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', error: '\x1b[31m',
        warn: '\x1b[33m', header: '\x1b[35m', reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]', header: '[====]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

function formatSAGE(amount) {
    return (BigInt(amount) / 10n ** 18n).toLocaleString();
}

async function getBalance(provider, tokenAddress, accountAddress) {
    const result = await provider.callContract({
        contractAddress: tokenAddress,
        entrypoint: 'balance_of',
        calldata: CallData.compile({ account: accountAddress }),
    });
    return BigInt(result[0]) + (BigInt(result[1] || 0) << 128n);
}

// ============================================================================
// TEST: Faucet
// ============================================================================

async function testFaucet(provider, account) {
    log('\n=== TESTING FAUCET ===', 'header');

    // Check faucet balance
    const faucetBalance = await getBalance(provider, CONTRACTS.sageToken, CONTRACTS.faucet);
    log(`Faucet SAGE balance: ${formatSAGE(faucetBalance)} SAGE`, 'info');

    // Check if caller can claim
    try {
        const canClaimResult = await provider.callContract({
            contractAddress: CONTRACTS.faucet,
            entrypoint: 'can_claim',
            calldata: CallData.compile({ user: CONFIG.deployer.address }),
        });
        const canClaim = canClaimResult[0] !== '0x0';
        log(`Deployer can claim: ${canClaim}`, canClaim ? 'success' : 'warn');

        if (!canClaim) {
            // Check cooldown
            const cooldownResult = await provider.callContract({
                contractAddress: CONTRACTS.faucet,
                entrypoint: 'get_time_until_next_claim',
                calldata: CallData.compile({ user: CONFIG.deployer.address }),
            });
            const cooldownSeconds = Number(BigInt(cooldownResult[0]));
            log(`Cooldown remaining: ${cooldownSeconds} seconds (${Math.round(cooldownSeconds/3600)} hours)`, 'info');
        }
    } catch (e) {
        log(`Error checking claim status: ${e.message}`, 'error');
    }

    // Get faucet config
    try {
        const configResult = await provider.callContract({
            contractAddress: CONTRACTS.faucet,
            entrypoint: 'get_config',
            calldata: [],
        });
        log(`Faucet config response: ${JSON.stringify(configResult)}`, 'info');
    } catch (e) {
        log(`Could not read faucet config: ${e.message}`, 'warn');
    }

    return true;
}

// ============================================================================
// TEST: OTC Orderbook
// ============================================================================

async function testOTCOrderbook(provider, account) {
    log('\n=== TESTING OTC ORDERBOOK ===', 'header');

    // Check if contract exists
    try {
        const classHash = await provider.getClassHashAt(CONTRACTS.otcOrderbook);
        log(`OTC Orderbook class hash: ${classHash}`, 'success');
    } catch (e) {
        log(`OTC Orderbook not found at address: ${e.message}`, 'error');
        return false;
    }

    // Try to read orderbook state
    try {
        const orderCountResult = await provider.callContract({
            contractAddress: CONTRACTS.otcOrderbook,
            entrypoint: 'get_order_count',
            calldata: [],
        });
        log(`Total orders: ${BigInt(orderCountResult[0])}`, 'info');
    } catch (e) {
        log(`Could not read order count: ${e.message}`, 'warn');
    }

    // Try to get supported pairs
    try {
        const pairCountResult = await provider.callContract({
            contractAddress: CONTRACTS.otcOrderbook,
            entrypoint: 'get_pair_count',
            calldata: [],
        });
        log(`Supported pairs: ${BigInt(pairCountResult[0])}`, 'info');
    } catch (e) {
        log(`Could not read pair count: ${e.message}`, 'warn');
    }

    return true;
}

// ============================================================================
// TEST: Account Balances
// ============================================================================

async function testAccountBalances(provider) {
    log('\n=== CHECKING ACCOUNT BALANCES ===', 'header');

    // Deployer balance
    const deployerBalance = await getBalance(provider, CONTRACTS.sageToken, CONFIG.deployer.address);
    log(`Deployer: ${formatSAGE(deployerBalance)} SAGE`, 'info');

    // Faucet balance
    const faucetBalance = await getBalance(provider, CONTRACTS.sageToken, CONTRACTS.faucet);
    log(`Faucet: ${formatSAGE(faucetBalance)} SAGE`, 'info');

    // CDCPool balance
    const cdcPoolBalance = await getBalance(provider, CONTRACTS.sageToken, CONTRACTS.cdcPool);
    log(`CDCPool: ${formatSAGE(cdcPoolBalance)} SAGE`, 'info');

    // OTC Orderbook balance
    const otcBalance = await getBalance(provider, CONTRACTS.sageToken, CONTRACTS.otcOrderbook);
    log(`OTC Orderbook: ${formatSAGE(otcBalance)} SAGE`, 'info');

    return true;
}

// ============================================================================
// TEST: Fund Test Account
// ============================================================================

async function fundTestAccount(provider, account, recipientAddress, amount) {
    log(`\n=== FUNDING TEST ACCOUNT ===`, 'header');
    log(`Recipient: ${recipientAddress}`, 'info');
    log(`Amount: ${formatSAGE(amount)} SAGE`, 'info');

    // Check current balance
    let recipientBalance;
    try {
        recipientBalance = await getBalance(provider, CONTRACTS.sageToken, recipientAddress);
        log(`Current balance: ${formatSAGE(recipientBalance)} SAGE`, 'info');
    } catch (e) {
        log(`Could not check balance (account may not exist): ${e.message}`, 'warn');
        recipientBalance = 0n;
    }

    // Transfer tokens
    const amountLow = amount & ((1n << 128n) - 1n);
    const amountHigh = amount >> 128n;

    try {
        const { transaction_hash } = await account.execute({
            contractAddress: CONTRACTS.sageToken,
            entrypoint: 'transfer',
            calldata: CallData.compile({
                recipient: recipientAddress,
                amount: { low: amountLow, high: amountHigh }
            }),
        });
        log(`Transfer tx: ${transaction_hash}`, 'info');
        await provider.waitForTransaction(transaction_hash);
        log('Transfer confirmed!', 'success');

        // Check new balance
        const newBalance = await getBalance(provider, CONTRACTS.sageToken, recipientAddress);
        log(`New balance: ${formatSAGE(newBalance)} SAGE`, 'success');

        return true;
    } catch (e) {
        log(`Transfer failed: ${e.message}`, 'error');
        return false;
    }
}

// ============================================================================
// TEST: Claim from Faucet (with a different account simulation)
// ============================================================================

async function testFaucetClaim(provider, account) {
    log('\n=== TESTING FAUCET CLAIM ===', 'header');

    // Check if deployer can claim
    try {
        const canClaimResult = await provider.callContract({
            contractAddress: CONTRACTS.faucet,
            entrypoint: 'can_claim',
            calldata: CallData.compile({ user: CONFIG.deployer.address }),
        });
        const canClaim = canClaimResult[0] !== '0x0';

        if (!canClaim) {
            log('Deployer cannot claim yet (cooldown active)', 'warn');
            return false;
        }

        log('Attempting to claim from faucet...', 'info');
        const beforeBalance = await getBalance(provider, CONTRACTS.sageToken, CONFIG.deployer.address);

        const { transaction_hash } = await account.execute({
            contractAddress: CONTRACTS.faucet,
            entrypoint: 'claim',
            calldata: [],
        });
        log(`Claim tx: ${transaction_hash}`, 'info');
        await provider.waitForTransaction(transaction_hash);

        const afterBalance = await getBalance(provider, CONTRACTS.sageToken, CONFIG.deployer.address);
        const received = afterBalance - beforeBalance;
        log(`Claimed ${formatSAGE(received)} SAGE from faucet!`, 'success');

        return true;
    } catch (e) {
        log(`Faucet claim failed: ${e.message}`, 'error');
        return false;
    }
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage Contract Testing Suite', 'header');
    log('='.repeat(60), 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    const results = {
        faucet: false,
        otcOrderbook: false,
        balances: false,
        faucetClaim: false,
    };

    // Run tests
    try {
        results.balances = await testAccountBalances(provider);
        results.faucet = await testFaucet(provider, account);
        results.otcOrderbook = await testOTCOrderbook(provider, account);
        results.faucetClaim = await testFaucetClaim(provider, account);
    } catch (e) {
        log(`Test error: ${e.message}`, 'error');
    }

    // Summary
    log('\n=== TEST SUMMARY ===', 'header');
    for (const [test, passed] of Object.entries(results)) {
        log(`${test}: ${passed ? 'PASSED' : 'FAILED/SKIPPED'}`, passed ? 'success' : 'warn');
    }
}

main().catch(console.error);
