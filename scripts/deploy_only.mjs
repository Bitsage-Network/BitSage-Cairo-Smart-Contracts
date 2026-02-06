#!/usr/bin/env node
/**
 * BitSage - Deploy Only (classes already declared)
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';
import { writeFileSync } from 'fs';
import { fileURLToPath } from 'url'
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// Already declared class hashes
const CLASS_HASHES = {
    CDCPool: '0x2155bc9d716f319471b7fc702e219663442a1d1c189ec76f8b5a81baf607531',
    JobManager: '0x7324358bc0e496c9a48a523f779aac43869a0ae2ddc1fd654001b4d1f3431e2',
    PrivacyRouter: '0x3e52652eaf09649d9f5a2264a280efe1912dca67752921ad44df479731c1899',
};

const DEPLOYED = {
    SAGEToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    PaymentRouter: '0x6a0639e673febf90b6a6e7d3743c81f96b39a3037b60429d479c62c5d20d41',
};

const newDeployed = { ...DEPLOYED };
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', error: '\x1b[31m', warn: '\x1b[33m', reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

async function main() {
    log('BitSage - Deploy Only (Classes Already Declared)', 'info');
    log('='.repeat(60), 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    const results = { deployed: [], failed: [] };

    // 1. CDCPool
    log('\n=== Deploying CDCPool ===', 'info');
    try {
        const minStake = 100n * 10n ** 18n;
        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            min_stake: cairo.uint256(minStake),
        });

        log(`Using class hash: ${CLASS_HASHES.CDCPool}`, 'info');
        const salt = BigInt(Date.now());
        const deployResponse = await account.deployContract({
            classHash: CLASS_HASHES.CDCPool,
            constructorCalldata: calldata,
            salt,
        });

        log(`Tx submitted: ${deployResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(deployResponse.transaction_hash);
        log(`CDCPool deployed: ${deployResponse.contract_address}`, 'success');
        newDeployed.CDCPool = deployResponse.contract_address;
        results.deployed.push({ name: 'CDCPool', address: deployResponse.contract_address });
    } catch (e) {
        log(`CDCPool failed: ${e.message}`, 'error');
        results.failed.push({ name: 'CDCPool', error: e.message });
    }

    await sleep(10000);

    // 2. JobManager
    log('\n=== Deploying JobManager ===', 'info');
    try {
        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            payment_token: DEPLOYED.SAGEToken,
            treasury: CONFIG.deployer.address,
            cdc_pool_contract: newDeployed.CDCPool || '0x0',
        });

        log(`Using class hash: ${CLASS_HASHES.JobManager}`, 'info');
        const salt = BigInt(Date.now());
        const deployResponse = await account.deployContract({
            classHash: CLASS_HASHES.JobManager,
            constructorCalldata: calldata,
            salt,
        });

        log(`Tx submitted: ${deployResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(deployResponse.transaction_hash);
        log(`JobManager deployed: ${deployResponse.contract_address}`, 'success');
        newDeployed.JobManager = deployResponse.contract_address;
        results.deployed.push({ name: 'JobManager', address: deployResponse.contract_address });
    } catch (e) {
        log(`JobManager failed: ${e.message}`, 'error');
        results.failed.push({ name: 'JobManager', error: e.message });
    }

    await sleep(10000);

    // 3. PrivacyRouter
    log('\n=== Deploying PrivacyRouter ===', 'info');
    try {
        const calldata = CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            payment_router: DEPLOYED.PaymentRouter,
        });

        log(`Using class hash: ${CLASS_HASHES.PrivacyRouter}`, 'info');
        const salt = BigInt(Date.now());
        const deployResponse = await account.deployContract({
            classHash: CLASS_HASHES.PrivacyRouter,
            constructorCalldata: calldata,
            salt,
        });

        log(`Tx submitted: ${deployResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(deployResponse.transaction_hash);
        log(`PrivacyRouter deployed: ${deployResponse.contract_address}`, 'success');
        newDeployed.PrivacyRouter = deployResponse.contract_address;
        results.deployed.push({ name: 'PrivacyRouter', address: deployResponse.contract_address });
    } catch (e) {
        log(`PrivacyRouter failed: ${e.message}`, 'error');
        results.failed.push({ name: 'PrivacyRouter', error: e.message });
    }

    // Summary
    log('\n' + '='.repeat(60), 'info');
    log('DEPLOYMENT SUMMARY', 'info');
    log(`Deployed: ${results.deployed.length}/3`, results.deployed.length === 3 ? 'success' : 'warn');
    log(`Failed: ${results.failed.length}`, results.failed.length > 0 ? 'error' : 'info');

    if (results.deployed.length > 0) {
        log('\nSuccessfully Deployed:', 'success');
        for (const c of results.deployed) {
            log(`  ${c.name}: ${c.address}`, 'success');
        }
    }

    if (results.failed.length > 0) {
        log('\nFailed:', 'error');
        for (const c of results.failed) {
            log(`  ${c.name}: ${c.error.substring(0, 100)}`, 'error');
        }
    }

    // Save results
    const outputPath = join(ROOT_DIR, 'deployment', 'final_3_contracts.json');
    writeFileSync(outputPath, JSON.stringify({
        network: 'sepolia',
        deployer: CONFIG.deployer.address,
        deployed_at: new Date().toISOString(),
        contracts: newDeployed,
        results,
    }, null, 2));
    log(`\nResults saved to: ${outputPath}`, 'info');
}

main().catch(console.error);
