#!/usr/bin/env node
/**
 * BitSage Network - Deploy Final 4 Contracts
 *
 * Deploys: CDCPool, JobManager, PrivacyRouter
 * Initializes: PrivacyPools
 *
 * Uses longer delays to avoid RPC rate limiting
 */

import { Account, RpcProvider, CallData, json, hash, cairo } from 'starknet';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url'
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// Already deployed contracts
const DEPLOYED = {
    SAGEToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    OracleWrapper: '0x4d86bb472cb462a45d68a705a798b5e419359a5758d84b24af4bbe5441b6e5a',
    ProverStaking: '0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b',
    PaymentRouter: '0x6a0639e673febf90b6a6e7d3743c81f96b39a3037b60429d479c62c5d20d41',
    PrivacyPools: '0xd85ad03dcd91a075bef0f4226149cb7e43da795d2c1d33e3227c68bfbb78a7',
};

const newDeployed = { ...DEPLOYED };

// ============================================================================
// HELPERS
// ============================================================================

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

async function declareContract(account, provider, contractName, artifactPath, retries = 5) {
    const sierraPath = join(ROOT_DIR, 'target/dev', `${artifactPath}.contract_class.json`);
    const casmPath = join(ROOT_DIR, 'target/dev', `${artifactPath}.compiled_contract_class.json`);

    if (!existsSync(sierraPath)) throw new Error(`Sierra not found: ${sierraPath}`);
    if (!existsSync(casmPath)) throw new Error(`CASM not found: ${casmPath}`);

    const sierra = json.parse(readFileSync(sierraPath).toString());
    const casm = json.parse(readFileSync(casmPath).toString());

    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const declareResponse = await account.declare({ contract: sierra, casm });
            log(`Declared ${contractName}: ${declareResponse.class_hash}`, 'info');
            await provider.waitForTransaction(declareResponse.transaction_hash);
            return declareResponse.class_hash;
        } catch (e) {
            if (e.message?.includes('already declared') || e.message?.includes('CLASS_ALREADY_DECLARED')) {
                const classHash = hash.computeContractClassHash(sierra);
                log(`${contractName} already declared: ${classHash}`, 'warn');
                return classHash;
            }
            if (e.message?.includes('html') || e.message?.includes('HTML')) {
                log(`RPC rate limit hit (attempt ${attempt}/${retries}), waiting...`, 'warn');
                await sleep(10000 * attempt); // Exponential backoff
                continue;
            }
            throw e;
        }
    }
    throw new Error(`Failed to declare ${contractName} after ${retries} attempts`);
}

async function deployContract(account, provider, contractName, classHash, constructorCalldata, retries = 5) {
    const salt = BigInt(Date.now());

    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            log(`Deploying ${contractName} (attempt ${attempt}/${retries})...`, 'info');
            const deployResponse = await account.deployContract({
                classHash,
                constructorCalldata,
                salt,
            });

            await provider.waitForTransaction(deployResponse.transaction_hash);
            log(`${contractName} deployed: ${deployResponse.contract_address}`, 'success');
            return deployResponse.contract_address;
        } catch (e) {
            if (e.message?.includes('html') || e.message?.includes('HTML')) {
                log(`RPC rate limit hit (attempt ${attempt}/${retries}), waiting...`, 'warn');
                await sleep(10000 * attempt);
                continue;
            }
            if (attempt === retries) {
                log(`Failed to deploy ${contractName}: ${e.message}`, 'error');
                throw e;
            }
            log(`Attempt ${attempt} failed: ${e.message}, retrying...`, 'warn');
            await sleep(5000);
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage - Deploy Final 4 Contracts', 'info');
    log('='.repeat(60), 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    log(`Deployer: ${CONFIG.deployer.address}`, 'info');

    const results = { deployed: [], failed: [], initialized: [] };

    // ==== 1. Deploy CDCPool ====
    log('\n--- Deploying CDCPool ---', 'info');
    try {
        const classHash = await declareContract(account, provider, 'CDCPool', 'sage_contracts_CDCPool');
        await sleep(5000);

        const minStake = 100n * 10n ** 18n;
        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            min_stake: cairo.uint256(minStake),
        });

        const address = await deployContract(account, provider, 'CDCPool', classHash, calldata);
        newDeployed.CDCPool = address;
        results.deployed.push({ name: 'CDCPool', address, classHash });
        await sleep(10000);
    } catch (e) {
        results.failed.push({ name: 'CDCPool', error: e.message });
    }

    // ==== 2. Deploy JobManager ====
    log('\n--- Deploying JobManager ---', 'info');
    try {
        const classHash = await declareContract(account, provider, 'JobManager', 'sage_contracts_JobManager');
        await sleep(5000);

        const calldata = CallData.compile({
            admin: CONFIG.deployer.address,
            payment_token: DEPLOYED.SAGEToken,
            treasury: CONFIG.deployer.address,
            cdc_pool_contract: newDeployed.CDCPool || '0x0',
        });

        const address = await deployContract(account, provider, 'JobManager', classHash, calldata);
        newDeployed.JobManager = address;
        results.deployed.push({ name: 'JobManager', address, classHash });
        await sleep(10000);
    } catch (e) {
        results.failed.push({ name: 'JobManager', error: e.message });
    }

    // ==== 3. Deploy PrivacyRouter ====
    log('\n--- Deploying PrivacyRouter ---', 'info');
    try {
        const classHash = await declareContract(account, provider, 'PrivacyRouter', 'sage_contracts_PrivacyRouter');
        await sleep(5000);

        const calldata = CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            payment_router: DEPLOYED.PaymentRouter,
        });

        const address = await deployContract(account, provider, 'PrivacyRouter', classHash, calldata);
        newDeployed.PrivacyRouter = address;
        results.deployed.push({ name: 'PrivacyRouter', address, classHash });
        await sleep(10000);
    } catch (e) {
        results.failed.push({ name: 'PrivacyRouter', error: e.message });
    }

    // ==== 4. Initialize PrivacyPools ====
    log('\n--- Initializing PrivacyPools ---', 'info');
    try {
        const initCalldata = CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: DEPLOYED.SAGEToken,
            privacy_router: newDeployed.PrivacyRouter || DEPLOYED.PaymentRouter,
        });

        log(`Calling initialize() on ${DEPLOYED.PrivacyPools}`, 'info');
        const { transaction_hash } = await account.execute({
            contractAddress: DEPLOYED.PrivacyPools,
            entrypoint: 'initialize',
            calldata: initCalldata,
        });
        await provider.waitForTransaction(transaction_hash);
        log('PrivacyPools initialized!', 'success');
        results.initialized.push({ name: 'PrivacyPools', address: DEPLOYED.PrivacyPools, tx: transaction_hash });
    } catch (e) {
        log(`Failed to initialize PrivacyPools: ${e.message}`, 'error');
        results.failed.push({ name: 'PrivacyPools (initialize)', error: e.message });
    }

    // Save results
    const outputPath = join(ROOT_DIR, 'deployment', 'all_deployed_contracts.json');
    writeFileSync(outputPath, JSON.stringify({
        network: 'sepolia',
        deployer: CONFIG.deployer.address,
        deployed_at: new Date().toISOString(),
        all_contracts: newDeployed,
        new_deployments: results.deployed,
        initialized: results.initialized,
        failed: results.failed,
    }, null, 2));

    log('\n' + '='.repeat(60), 'info');
    log('DEPLOYMENT SUMMARY', 'info');
    log(`Deployed: ${results.deployed.length}`, results.deployed.length > 0 ? 'success' : 'info');
    log(`Initialized: ${results.initialized.length}`, results.initialized.length > 0 ? 'success' : 'info');
    log(`Failed: ${results.failed.length}`, results.failed.length > 0 ? 'error' : 'info');

    if (results.deployed.length > 0) {
        log('\nNewly Deployed:', 'success');
        for (const c of results.deployed) {
            log(`  ${c.name}: ${c.address}`, 'success');
        }
    }

    if (results.initialized.length > 0) {
        log('\nInitialized:', 'success');
        for (const c of results.initialized) {
            log(`  ${c.name}: ${c.address}`, 'success');
        }
    }

    if (results.failed.length > 0) {
        log('\nFailed:', 'error');
        for (const c of results.failed) {
            log(`  ${c.name}: ${c.error}`, 'error');
        }
    }

    log(`\nResults saved to: ${outputPath}`, 'info');
}

main().catch(console.error);
