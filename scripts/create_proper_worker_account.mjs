#!/usr/bin/env node
/**
 * BitSage Network - Create Proper Worker Account
 *
 * Creates a proper Starknet account with correct address computation,
 * funds it, deploys it, and outputs the config for the worker.
 */

import { Account, RpcProvider, CallData, ec, hash } from 'starknet';

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

// OpenZeppelin Account class hash v0.8.1 on Sepolia (simple constructor: just public_key)
const OZ_ACCOUNT_CLASS_HASH = '0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f';

// Amount to fund: 0.5 STRK
const FUND_AMOUNT = 5n * 10n ** 17n;

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
    return (Number(amount) / 1e18).toFixed(4);
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage Worker Account Creation', 'info');
    log('='.repeat(60), 'info');

    // Initialize provider
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

    // Initialize deployer account for funding
    const deployer = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Step 1: Generate new private key
    log('\n[1/5] Generating new keypair...', 'info');
    const privateKey = ec.starkCurve.utils.randomPrivateKey();
    const privateKeyHex = '0x' + Buffer.from(privateKey).toString('hex');
    const publicKey = ec.starkCurve.getStarkKey(privateKeyHex);

    log(`  Private key: ${privateKeyHex.slice(0, 14)}...`, 'info');
    log(`  Public key: ${publicKey}`, 'info');

    // Step 2: Compute address
    log('\n[2/5] Computing account address...', 'info');
    const constructorCalldata = CallData.compile({ public_key: publicKey });
    const accountAddress = hash.calculateContractAddressFromHash(
        publicKey, // salt
        OZ_ACCOUNT_CLASS_HASH,
        constructorCalldata,
        0 // deployer
    );

    log(`  Account address: ${accountAddress}`, 'success');
    log(`  Class hash: ${OZ_ACCOUNT_CLASS_HASH}`, 'info');

    // Step 3: Fund the new account
    log('\n[3/5] Funding new account...', 'info');

    // Check deployer balance first
    const deployerBalanceResult = await provider.callContract({
        contractAddress: STRK_TOKEN,
        entrypoint: 'balanceOf',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    const deployerBalance = BigInt(deployerBalanceResult[0]) + (BigInt(deployerBalanceResult[1] || 0) << 128n);
    log(`  Deployer STRK balance: ${formatSTRK(deployerBalance)} STRK`, 'info');

    if (deployerBalance < FUND_AMOUNT) {
        log(`  Insufficient balance for funding!`, 'error');
        process.exit(1);
    }

    // Transfer STRK
    const amountLow = FUND_AMOUNT & ((1n << 128n) - 1n);
    const amountHigh = FUND_AMOUNT >> 128n;

    const transferCalldata = CallData.compile({
        recipient: accountAddress,
        amount: { low: amountLow, high: amountHigh }
    });

    const { transaction_hash: fundTxHash } = await deployer.execute({
        contractAddress: STRK_TOKEN,
        entrypoint: 'transfer',
        calldata: transferCalldata,
    });
    log(`  Transfer tx: ${fundTxHash}`, 'info');

    log('  Waiting for confirmation...', 'info');
    await provider.waitForTransaction(fundTxHash);
    log(`  Funded ${formatSTRK(FUND_AMOUNT)} STRK`, 'success');

    // Step 4: Deploy account
    log('\n[4/5] Deploying account...', 'info');

    const newAccount = new Account({
        provider,
        address: accountAddress,
        signer: privateKeyHex,
        cairoVersion: '1',
    });

    const deployPayload = {
        classHash: OZ_ACCOUNT_CLASS_HASH,
        constructorCalldata,
        addressSalt: publicKey,
    };

    try {
        const { transaction_hash: deployTxHash, contract_address } = await newAccount.deployAccount(deployPayload);
        log(`  Deploy tx: ${deployTxHash}`, 'info');

        log('  Waiting for confirmation...', 'info');
        await provider.waitForTransaction(deployTxHash);
        log(`  Account deployed at: ${contract_address}`, 'success');
    } catch (error) {
        log(`  Deployment failed: ${error.message}`, 'error');
        console.error(error);
        process.exit(1);
    }

    // Step 5: Output worker config
    log('\n[5/5] Worker Configuration', 'info');
    log('='.repeat(60), 'info');

    console.log('\nUpdate your worker config (~/.bitsage/worker.toml) with:\n');
    console.log('[wallet]');
    console.log(`address = "${accountAddress}"`);
    console.log(`private_key = "${privateKeyHex}"`);
    console.log('');

    console.log('Or run this on your H100 worker:');
    console.log('');
    console.log(`ssh shadeform@62.169.159.217 "cat > ~/.bitsage/keys/starknet.key << 'EOF'
${privateKeyHex}
EOF"`);
    console.log('');
    console.log(`ssh shadeform@62.169.159.217 "sed -i 's/address = .*/address = \\"${accountAddress}\\"/' ~/.bitsage/worker.toml"`);
    console.log('');

    log('\nAccount created successfully!', 'success');
    log(`Explorer: https://sepolia.starkscan.co/contract/${accountAddress}`, 'info');

    // Save to file for easy copy
    const outputData = {
        address: accountAddress,
        privateKey: privateKeyHex,
        publicKey: publicKey,
        classHash: OZ_ACCOUNT_CLASS_HASH,
        network: 'sepolia',
        funded: formatSTRK(FUND_AMOUNT) + ' STRK',
    };
    console.log('\nJSON output:');
    console.log(JSON.stringify(outputData, null, 2));
}

main().catch(console.error);
