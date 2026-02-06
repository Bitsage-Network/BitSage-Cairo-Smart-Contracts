#!/usr/bin/env node
/**
 * Create a new test account and claim from faucet
 * 1. Generate new keypair
 * 2. Compute account address
 * 3. Fund with STRK for gas (from deployer)
 * 4. Deploy account
 * 5. Claim 20 SAGE from faucet
 */

import {
    Account, RpcProvider, CallData, cairo, stark, ec, hash,
    constants
} from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    faucet: '0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3',
    // STRK token on Sepolia
    strkToken: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
    // OpenZeppelin Account class hash (deployed on Sepolia)
    ozAccountClassHash: '0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f',
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

async function main() {
    log('=== Create Test Account & Claim from Faucet ===', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const deployerAccount = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Step 1: Generate new keypair
    log('\nStep 1: Generating new keypair...', 'info');
    const privateKey = stark.randomAddress();
    const publicKey = ec.starkCurve.getStarkKey(privateKey);
    log(`Private Key: ${privateKey}`, 'info');
    log(`Public Key: ${publicKey}`, 'info');

    // Step 2: Compute account address
    log('\nStep 2: Computing account address...', 'info');

    // For OZ Account, constructor takes (public_key)
    const constructorCalldata = CallData.compile({ public_key: publicKey });

    const accountAddress = hash.calculateContractAddressFromHash(
        publicKey, // salt
        CONFIG.ozAccountClassHash,
        constructorCalldata,
        0 // deployer address (0 for universal deployer)
    );
    log(`Account Address: ${accountAddress}`, 'success');

    // Step 3: Check deployer STRK balance and fund new account
    log('\nStep 3: Funding new account with STRK for gas...', 'info');

    const deployerStrkBalance = await getBalance(provider, CONFIG.strkToken, CONFIG.deployer.address);
    log(`Deployer STRK balance: ${(deployerStrkBalance / 10n**18n).toString()} STRK`, 'info');

    if (deployerStrkBalance < 1n * 10n**18n) {
        log('Deployer has insufficient STRK for funding. Need at least 1 STRK.', 'error');
        log('Please fund deployer with STRK from Starknet faucet: https://faucet.goerli.starknet.io/', 'info');
        return;
    }

    // Send 0.1 STRK to new account for deployment and gas
    const fundAmount = 100000000000000000n; // 0.1 STRK
    const fundAmountLow = fundAmount & ((1n << 128n) - 1n);
    const fundAmountHigh = fundAmount >> 128n;

    try {
        const { transaction_hash: fundTx } = await deployerAccount.execute({
            contractAddress: CONFIG.strkToken,
            entrypoint: 'transfer',
            calldata: CallData.compile({
                recipient: accountAddress,
                amount: { low: fundAmountLow, high: fundAmountHigh }
            }),
        });
        log(`Funding TX: ${fundTx}`, 'info');
        await provider.waitForTransaction(fundTx);
        log('Account funded with 0.1 STRK!', 'success');
    } catch (e) {
        log(`Failed to fund account: ${e.message}`, 'error');
        return;
    }

    // Step 4: Deploy the account
    log('\nStep 4: Deploying account...', 'info');

    const newAccount = new Account({
        provider,
        address: accountAddress,
        signer: privateKey,
        cairoVersion: '1',
    });

    try {
        const { transaction_hash: deployTx, contract_address } = await newAccount.deployAccount({
            classHash: CONFIG.ozAccountClassHash,
            constructorCalldata,
            addressSalt: publicKey,
        });
        log(`Deploy TX: ${deployTx}`, 'info');
        await provider.waitForTransaction(deployTx);
        log(`Account deployed at: ${contract_address}`, 'success');
    } catch (e) {
        log(`Deploy failed: ${e.message}`, 'error');
        // Account might already be deployed, continue
        if (!e.message.includes('already deployed')) {
            return;
        }
        log('Account may already be deployed, continuing...', 'warn');
    }

    // Step 5: Claim from faucet
    log('\nStep 5: Claiming from faucet...', 'info');

    const sageBefore = await getBalance(provider, CONFIG.sageToken, accountAddress);
    log(`SAGE balance before: ${(sageBefore / 10n**18n).toString()} SAGE`, 'info');

    try {
        const { transaction_hash: claimTx } = await newAccount.execute({
            contractAddress: CONFIG.faucet,
            entrypoint: 'claim',
            calldata: [],
        });
        log(`Claim TX: ${claimTx}`, 'info');
        await provider.waitForTransaction(claimTx);
        log('Claim successful!', 'success');

        const sageAfter = await getBalance(provider, CONFIG.sageToken, accountAddress);
        const received = sageAfter - sageBefore;

        log(`\n=== RESULT ===`, 'header');
        log(`SAGE balance after: ${(sageAfter / 10n**18n).toString()} SAGE`, 'success');
        log(`Received from faucet: ${(received / 10n**18n).toString()} SAGE`, 'success');

        log(`\n=== TEST ACCOUNT CREDENTIALS ===`, 'header');
        log(`Address: ${accountAddress}`, 'success');
        log(`Private Key: ${privateKey}`, 'success');
        log(`SAGE Balance: ${(sageAfter / 10n**18n).toString()} SAGE`, 'success');

        log(`\nExplorer: https://sepolia.starkscan.co/contract/${accountAddress}`, 'info');

    } catch (e) {
        log(`Claim failed: ${e.message}`, 'error');
    }
}

main().catch(console.error);
