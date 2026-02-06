#!/usr/bin/env node
/**
 * BitSage - Deploy with manual fee to avoid estimateFee rate limiting
 */

import { Account, RpcProvider, CallData, json, hash, cairo } from 'starknet';
import { readFileSync, writeFileSync } from 'fs';
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

async function declareWithManualFee(account, provider, name, artifact) {
    const sierraPath = join(ROOT_DIR, 'target/dev', `${artifact}.contract_class.json`);
    const casmPath = join(ROOT_DIR, 'target/dev', `${artifact}.compiled_contract_class.json`);

    const sierra = json.parse(readFileSync(sierraPath).toString());
    const casm = json.parse(readFileSync(casmPath).toString());
    const classHash = hash.computeContractClassHash(sierra);

    log(`${name} class hash: ${classHash}`, 'info');
    log(`Declaring ${name} with manual fee...`, 'info');

    try {
        // Try with skipValidate to avoid estimateFee
        const declareResponse = await account.declare(
            { contract: sierra, casm },
            { skipValidate: true }
        );
        log(`Declared, tx: ${declareResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(declareResponse.transaction_hash);
        log(`${name} declared`, 'success');
        return classHash;
    } catch (e) {
        if (e.message?.includes('already declared') || e.message?.includes('CLASS_ALREADY_DECLARED')) {
            log(`${name} already declared`, 'warn');
            return classHash;
        }
        throw e;
    }
}

async function deployWithManualFee(account, provider, name, classHash, calldata) {
    log(`Deploying ${name}...`, 'info');
    const salt = BigInt(Date.now());

    const deployResponse = await account.deployContract(
        { classHash, constructorCalldata: calldata, salt },
        { skipValidate: true }
    );

    await provider.waitForTransaction(deployResponse.transaction_hash);
    log(`${name} deployed: ${deployResponse.contract_address}`, 'success');
    return deployResponse.contract_address;
}

async function main() {
    log('BitSage - Deploy with Manual Fee', 'info');
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
    log('\n=== CDCPool ===', 'info');
    try {
        const classHash = await declareWithManualFee(account, provider, 'CDCPool', 'sage_contracts_CDCPool');
        await sleep(5000);

        const minStake = 100n * 10n ** 18n;
        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            min_stake: cairo.uint256(minStake),
        });
        const addr = await deployWithManualFee(account, provider, 'CDCPool', classHash, calldata);
        newDeployed.CDCPool = addr;
        results.deployed.push({ name: 'CDCPool', address: addr });
    } catch (e) {
        log(`CDCPool failed: ${e.message}`, 'error');
        results.failed.push({ name: 'CDCPool', error: e.message });
    }

    await sleep(15000);

    // 2. JobManager
    log('\n=== JobManager ===', 'info');
    try {
        const classHash = await declareWithManualFee(account, provider, 'JobManager', 'sage_contracts_JobManager');
        await sleep(5000);

        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            payment_token: DEPLOYED.SAGEToken,
            treasury: CONFIG.deployer.address,
            cdc_pool_contract: newDeployed.CDCPool || '0x0',
        });
        const addr = await deployWithManualFee(account, provider, 'JobManager', classHash, calldata);
        newDeployed.JobManager = addr;
        results.deployed.push({ name: 'JobManager', address: addr });
    } catch (e) {
        log(`JobManager failed: ${e.message}`, 'error');
        results.failed.push({ name: 'JobManager', error: e.message });
    }

    await sleep(15000);

    // 3. PrivacyRouter
    log('\n=== PrivacyRouter ===', 'info');
    try {
        const classHash = await declareWithManualFee(account, provider, 'PrivacyRouter', 'sage_contracts_PrivacyRouter');
        await sleep(5000);

        const calldata = CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            payment_router: DEPLOYED.PaymentRouter,
        });
        const addr = await deployWithManualFee(account, provider, 'PrivacyRouter', classHash, calldata);
        newDeployed.PrivacyRouter = addr;
        results.deployed.push({ name: 'PrivacyRouter', address: addr });
    } catch (e) {
        log(`PrivacyRouter failed: ${e.message}`, 'error');
        results.failed.push({ name: 'PrivacyRouter', error: e.message });
    }

    // Summary
    log('\n' + '='.repeat(60), 'info');
    log(`Deployed: ${results.deployed.length}`, results.deployed.length > 0 ? 'success' : 'info');
    log(`Failed: ${results.failed.length}`, results.failed.length > 0 ? 'error' : 'info');

    if (results.deployed.length > 0) {
        log('\nDeployed:', 'success');
        for (const c of results.deployed) log(`  ${c.name}: ${c.address}`, 'success');
    }

    const outputPath = join(ROOT_DIR, 'deployment', 'final_3_contracts.json');
    writeFileSync(outputPath, JSON.stringify({
        network: 'sepolia',
        deployer: CONFIG.deployer.address,
        deployed_at: new Date().toISOString(),
        contracts: newDeployed,
        results,
    }, null, 2));
    log(`\nSaved to ${outputPath}`, 'info');
}

main().catch(console.error);
