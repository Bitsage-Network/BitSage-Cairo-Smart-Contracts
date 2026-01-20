#!/usr/bin/env node
/**
 * BitSage - Deploy with alternative RPC
 * Try multiple RPC endpoints until one works
 */

import { Account, RpcProvider, CallData, json, hash, cairo } from 'starknet';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url'
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

const CONFIG = {
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
};

// Alternative RPC endpoints to try
const RPC_ENDPOINTS = [
    'https://free-rpc.nethermind.io/sepolia-juno',
    'https://starknet-sepolia.public.blastapi.io',
    'https://rpc.starknet-testnet.lava.build',
];

const DEPLOYED = {
    SAGEToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    PaymentRouter: '0x6a0639e673febf90b6a6e7d3743c81f96b39a3037b60429d479c62c5d20d41',
};

const newDeployed = { ...DEPLOYED };
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

async function findWorkingRPC() {
    for (const rpc of RPC_ENDPOINTS) {
        log(`Testing RPC: ${rpc}`, 'info');
        try {
            const provider = new RpcProvider({ nodeUrl: rpc });
            const chainId = await provider.getChainId();
            log(`RPC working! Chain ID: ${chainId}`, 'success');
            return { provider, rpc };
        } catch (e) {
            log(`RPC failed: ${e.message.substring(0, 50)}`, 'warn');
        }
    }
    throw new Error('No working RPC found');
}

async function deployOneContract(account, provider, name, artifact, calldata) {
    const sierraPath = join(ROOT_DIR, 'target/dev', `${artifact}.contract_class.json`);
    const casmPath = join(ROOT_DIR, 'target/dev', `${artifact}.compiled_contract_class.json`);

    const sierra = json.parse(readFileSync(sierraPath).toString());
    const casm = json.parse(readFileSync(casmPath).toString());

    const classHash = hash.computeContractClassHash(sierra);
    log(`${name} class hash: ${classHash}`, 'info');

    // Declare
    log(`Declaring ${name}...`, 'info');
    try {
        const declareResponse = await account.declare({ contract: sierra, casm });
        log(`Declared, tx: ${declareResponse.transaction_hash}`, 'info');
        await provider.waitForTransaction(declareResponse.transaction_hash);
        log(`${name} declared successfully`, 'success');
    } catch (e) {
        if (e.message?.includes('already declared') || e.message?.includes('CLASS_ALREADY_DECLARED')) {
            log(`${name} already declared`, 'warn');
        } else {
            throw e;
        }
    }

    await sleep(5000);

    // Deploy
    log(`Deploying ${name}...`, 'info');
    const salt = BigInt(Date.now());
    const deployResponse = await account.deployContract({
        classHash,
        constructorCalldata: calldata,
        salt,
    });

    await provider.waitForTransaction(deployResponse.transaction_hash);
    log(`${name} deployed: ${deployResponse.contract_address}`, 'success');
    return deployResponse.contract_address;
}

async function main() {
    log('BitSage - Deploy with Alternative RPC', 'info');
    log('='.repeat(60), 'info');

    // Find working RPC
    const { provider, rpc } = await findWorkingRPC();
    log(`Using RPC: ${rpc}`, 'success');

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
        const minStake = 100n * 10n ** 18n;
        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            min_stake: cairo.uint256(minStake),
        });
        const addr = await deployOneContract(account, provider, 'CDCPool', 'sage_contracts_CDCPool', calldata);
        newDeployed.CDCPool = addr;
        results.deployed.push({ name: 'CDCPool', address: addr });
    } catch (e) {
        log(`CDCPool failed: ${e.message}`, 'error');
        results.failed.push({ name: 'CDCPool', error: e.message });
    }

    await sleep(10000);

    // 2. JobManager
    log('\n=== JobManager ===', 'info');
    try {
        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            payment_token: DEPLOYED.SAGEToken,
            treasury: CONFIG.deployer.address,
            cdc_pool_contract: newDeployed.CDCPool || '0x0',
        });
        const addr = await deployOneContract(account, provider, 'JobManager', 'sage_contracts_JobManager', calldata);
        newDeployed.JobManager = addr;
        results.deployed.push({ name: 'JobManager', address: addr });
    } catch (e) {
        log(`JobManager failed: ${e.message}`, 'error');
        results.failed.push({ name: 'JobManager', error: e.message });
    }

    await sleep(10000);

    // 3. PrivacyRouter
    log('\n=== PrivacyRouter ===', 'info');
    try {
        const calldata = CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            payment_router: DEPLOYED.PaymentRouter,
        });
        const addr = await deployOneContract(account, provider, 'PrivacyRouter', 'sage_contracts_PrivacyRouter', calldata);
        newDeployed.PrivacyRouter = addr;
        results.deployed.push({ name: 'PrivacyRouter', address: addr });
    } catch (e) {
        log(`PrivacyRouter failed: ${e.message}`, 'error');
        results.failed.push({ name: 'PrivacyRouter', error: e.message });
    }

    // Summary
    log('\n' + '='.repeat(60), 'info');
    log('SUMMARY', 'info');
    log(`Deployed: ${results.deployed.length}`, results.deployed.length > 0 ? 'success' : 'info');
    log(`Failed: ${results.failed.length}`, results.failed.length > 0 ? 'error' : 'info');

    if (results.deployed.length > 0) {
        log('\nDeployed:', 'success');
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

    // Save
    const outputPath = join(ROOT_DIR, 'deployment', 'final_3_contracts.json');
    writeFileSync(outputPath, JSON.stringify({
        network: 'sepolia',
        rpc_used: rpc,
        deployer: CONFIG.deployer.address,
        deployed_at: new Date().toISOString(),
        contracts: newDeployed,
        results,
    }, null, 2));
    log(`\nSaved to ${outputPath}`, 'info');
}

main().catch(console.error);
