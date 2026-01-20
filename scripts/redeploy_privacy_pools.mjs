#!/usr/bin/env node
/**
 * BitSage - Redeploy PrivacyPools with 5min upgrade delay
 * This deploys the updated version with the `amount` parameter in pp_deposit
 */

import { Account, RpcProvider, CallData, json, hash } from 'starknet';
import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

// Configuration
const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY || '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
    // Existing deployed contracts
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    privacyRouter: '0x0051e114ec3d524f203900c78e5217f23de51e29d6a6ecabb6dc92fb8ccca6e0',
    // 5 minute upgrade delay (300 seconds)
    upgradeDelay: 300,
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m',
        success: '\x1b[32m',
        error: '\x1b[31m',
        warn: '\x1b[33m',
        reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

async function main() {
    log('='.repeat(60), 'info');
    log('BitSage - Redeploy PrivacyPools Contract', 'info');
    log('='.repeat(60), 'info');
    log(`Network: Sepolia`, 'info');
    log(`RPC: ${CONFIG.rpcUrl}`, 'info');
    log(`Deployer: ${CONFIG.deployer.address}`, 'info');
    log(`Upgrade Delay: ${CONFIG.upgradeDelay} seconds (5 minutes)`, 'info');
    log('='.repeat(60), 'info');

    // Setup provider and account
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Load compiled contract
    const contractPath = join(ROOT_DIR, 'target/dev/sage_contracts_PrivacyPools.contract_class.json');
    const compiledContract = json.parse(readFileSync(contractPath, 'utf-8'));

    log('\n=== Step 1: Declare new contract class ===', 'info');

    let classHash;
    try {
        // Check if already declared
        const compiledCasmPath = join(ROOT_DIR, 'target/dev/sage_contracts_PrivacyPools.compiled_contract_class.json');
        const compiledCasm = json.parse(readFileSync(compiledCasmPath, 'utf-8'));

        const declareResponse = await account.declare({
            contract: compiledContract,
            casm: compiledCasm,
        });

        log(`Declaration tx: ${declareResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(declareResponse.transaction_hash);
        classHash = declareResponse.class_hash;
        log(`New class hash: ${classHash}`, 'success');
    } catch (e) {
        if (e.message?.includes('already declared') || e.message?.includes('StarknetErrorCode.CLASS_ALREADY_DECLARED')) {
            // Class already declared, compute the hash
            classHash = hash.computeContractClassHash(compiledContract);
            log(`Class already declared: ${classHash}`, 'warn');
        } else {
            log(`Declaration failed: ${e.message}`, 'error');
            throw e;
        }
    }

    await sleep(5000);

    log('\n=== Step 2: Deploy new contract instance ===', 'info');

    let contractAddress;
    try {
        // PrivacyPools has no constructor, just deploy
        const salt = BigInt(Date.now());

        const deployResponse = await account.deployContract({
            classHash: classHash,
            constructorCalldata: [], // No constructor
            salt: salt,
        });

        log(`Deploy tx: ${deployResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(deployResponse.transaction_hash);
        contractAddress = deployResponse.contract_address;
        log(`Contract deployed at: ${contractAddress}`, 'success');
    } catch (e) {
        log(`Deployment failed: ${e.message}`, 'error');
        throw e;
    }

    await sleep(5000);

    log('\n=== Step 3: Initialize contract ===', 'info');

    try {
        const initCalldata = CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: CONFIG.sageToken,
            privacy_router: CONFIG.privacyRouter,
        });

        const initResponse = await account.execute([{
            contractAddress: contractAddress,
            entrypoint: 'initialize',
            calldata: initCalldata,
        }]);

        log(`Initialize tx: ${initResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(initResponse.transaction_hash);
        log('Contract initialized successfully', 'success');
    } catch (e) {
        log(`Initialization failed: ${e.message}`, 'error');
        throw e;
    }

    // Save deployment info
    const deploymentInfo = {
        network: 'sepolia',
        deployed_at: new Date().toISOString(),
        class_hash: classHash,
        contract_address: contractAddress,
        sage_token: CONFIG.sageToken,
        privacy_router: CONFIG.privacyRouter,
        upgrade_delay_seconds: CONFIG.upgradeDelay,
        deployer: CONFIG.deployer.address,
    };

    const outputPath = join(ROOT_DIR, 'deployment/privacy_pools_v2_deployment.json');
    writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
    log(`\nDeployment info saved to: ${outputPath}`, 'success');

    log('\n='.repeat(60), 'info');
    log('DEPLOYMENT COMPLETE', 'success');
    log('='.repeat(60), 'info');
    log(`\nNew PrivacyPools Address: ${contractAddress}`, 'success');
    log(`Class Hash: ${classHash}`, 'info');
    log('\nUpdate your .env file:', 'warn');
    log(`NEXT_PUBLIC_PRIVACY_POOLS_ADDRESS=${contractAddress}`, 'info');
    log('='.repeat(60), 'info');

    return { classHash, contractAddress };
}

main()
    .then(result => {
        console.log('\nResult:', result);
        process.exit(0);
    })
    .catch(e => {
        console.error('\nFatal error:', e);
        process.exit(1);
    });
