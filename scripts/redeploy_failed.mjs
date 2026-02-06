#!/usr/bin/env node
/**
 * BitSage Network - Redeploy Failed Contracts
 *
 * Fixes constructor parameter serialization and deploys the 17 failed contracts
 * in the correct dependency order.
 */

import { Account, RpcProvider, CallData, json, hash, cairo } from 'starknet';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
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

// Already deployed contracts with correct owner
const DEPLOYED = {
    SAGEToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    AddressRegistry: '0x78f99c76731eb0d8d7a6102855772d8560bff91a1f71b59ff0571dfa7ee54c6',
    ProverStaking: '0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b',
    WorkerStaking: '0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613',
    Collateral: '0x4f5405d65d93afb71743e5ac20e4d9ef2667f256f08e61de734992ebd58603',
    ValidatorRegistry: '0x431a8b6afb9b6f3ffa2fa9e58519b64dbe9eb53c6ac8fb69d3dcb8b9b92f5d9',
    ProofVerifier: '0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b',
    FraudProof: '0x5d5bc1565e4df7c61c811b0c494f1345fc0f964e154e57e829c727990116b50',
    OptimisticTEE: '0x4238502196d7dab552e2af5d15219c8227c9f4dc69f0df1fa2ca9f8cb29eb33',
    Escrow: '0x7d7b5aa04b8eec7676568c8b55acd5682b8f7cb051f69c1876f0e5a6d8edfd4',
    FeeManager: '0x74344374490948307360e6a8376d656190773115a4fca4d049366cea7edde39',
    DynamicPricing: '0x28881df510544345d29e12701b6b6366441219364849a43d3443f37583bc0df',
    MixingRouter: '0x4a4e05233271f5203791321f2ba92b2de73ad051f788e7b605f204b5a43b8d1',
    SteganographicRouter: '0x47ab97833df3f77d807a4699ca0f0245d533a4d9e0664f809a04cee3ec720dc',
    OTCOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    ReferralSystem: '0x1d400338a38fca24e67c113bcecac4875ec1b85a00b14e4e541ed224fee59e4',
    Gamification: '0x3beb685db6a20804ee0939948cee05c42de655b6b78a93e1e773447ce981cde',
    RewardVesting: '0x52e086edb779dbe2a9bb2989be63e8847a791cb1628ad5b81e73d6c6f448016',
    Faucet: '0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3',
    ObelyskProverRegistry: '0x34a02ecafacfa81be6d23ad5b5e061e92c2b8884cfb388f95b57122a492b3e9',
};

// New deployments will be stored here
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

async function declareContract(account, provider, contractName, artifactPath) {
    const sierraPath = join(ROOT_DIR, 'target/dev', `${artifactPath}.contract_class.json`);
    const casmPath = join(ROOT_DIR, 'target/dev', `${artifactPath}.compiled_contract_class.json`);

    if (!existsSync(sierraPath)) throw new Error(`Sierra not found: ${sierraPath}`);
    if (!existsSync(casmPath)) throw new Error(`CASM not found: ${casmPath}`);

    const sierra = json.parse(readFileSync(sierraPath).toString());
    const casm = json.parse(readFileSync(casmPath).toString());

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
        throw e;
    }
}

async function deployContract(account, provider, contractName, classHash, constructorCalldata) {
    const salt = BigInt(Date.now());

    try {
        const deployResponse = await account.deployContract({
            classHash,
            constructorCalldata,
            salt,
        });

        log(`Deploying ${contractName}...`, 'info');
        await provider.waitForTransaction(deployResponse.transaction_hash);
        log(`${contractName} deployed: ${deployResponse.contract_address}`, 'success');
        return deployResponse.contract_address;
    } catch (e) {
        log(`Failed to deploy ${contractName}: ${e.message}`, 'error');
        throw e;
    }
}

// ============================================================================
// CONTRACT DEPLOYMENTS
// ============================================================================

const CONTRACTS_TO_DEPLOY = [
    // Tier 1: Simple contracts with no complex dependencies
    {
        name: 'StwoVerifier',
        artifact: 'sage_contracts_StwoVerifier',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            min_security_bits: 80,
            max_proof_size: 1000000,
            gpu_tee_enabled: cairo.felt(1), // true as felt
        }),
    },
    {
        name: 'MeteredBilling',
        artifact: 'sage_contracts_MeteredBilling',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            proof_verifier: newDeployed.ProofVerifier,
        }),
    },
    {
        name: 'ProofGatedPayment',
        artifact: 'sage_contracts_ProofGatedPayment',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            proof_verifier: newDeployed.ProofVerifier,
        }),
    },
    {
        name: 'OracleWrapper',
        artifact: 'sage_contracts_OracleWrapper',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            oracle_address: CONFIG.deployer.address, // Placeholder - set real oracle later
        }),
    },
    {
        name: 'LinearVestingWithCliff',
        artifact: 'sage_contracts_LinearVestingWithCliff',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            token: newDeployed.SAGEToken,
        }),
    },
    {
        name: 'MilestoneVesting',
        artifact: 'sage_contracts_MilestoneVesting',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            token: newDeployed.SAGEToken,
        }),
    },

    // Tier 2: Contracts that depend on Tier 1
    {
        name: 'CDCPool',
        artifact: 'sage_contracts_CDCPool',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            sage_token: newDeployed.SAGEToken,
            staking_contract: newDeployed.ProverStaking,
        }),
    },
    {
        name: 'TreasuryTimelock',
        artifact: 'sage_contracts_TreasuryTimelock',
        getCalldata: () => {
            // Array of multisig members (just deployer for now)
            const members = [CONFIG.deployer.address];
            const emergencyMembers = [CONFIG.deployer.address];
            return CallData.compile({
                multisig_members: members,
                threshold: 1,
                timelock_delay: 86400, // 1 day
                admin: CONFIG.deployer.address,
                emergency_members: emergencyMembers,
            });
        },
    },

    // Tier 3: Contracts that depend on Tier 2
    {
        name: 'GovernanceTreasury',
        artifact: 'sage_contracts_GovernanceTreasury',
        getCalldata: () => CallData.compile({
            admin: CONFIG.deployer.address,
            token: newDeployed.SAGEToken,
            timelock: () => newDeployed.TreasuryTimelock,
        }),
        getDynamicCalldata: () => CallData.compile({
            admin: CONFIG.deployer.address,
            token: newDeployed.SAGEToken,
            timelock: newDeployed.TreasuryTimelock,
        }),
    },
    {
        name: 'JobManager',
        artifact: 'sage_contracts_JobManager',
        getCalldata: () => CallData.compile({
            admin: CONFIG.deployer.address,
            payment_token: newDeployed.SAGEToken,
            treasury: CONFIG.deployer.address, // Will be updated later
            cdc_pool_contract: '0x0', // Optional, can be zero
        }),
    },
    {
        name: 'BurnManager',
        artifact: 'sage_contracts_BurnManager',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            token_contract: newDeployed.SAGEToken,
            treasury_contract: CONFIG.deployer.address, // Placeholder
            revenue_config: {
                burn_percentage: 1000, // 10%
                min_burn_amount: cairo.uint256(1000000000000000000n), // 1 token
                burn_interval: 86400, // Daily
            },
            buyback_config: {
                buyback_percentage: 500, // 5%
                min_buyback_amount: cairo.uint256(1000000000000000000n),
                buyback_interval: 604800, // Weekly
            },
        }),
    },

    // Tier 4: Final contracts
    {
        name: 'ReputationManager',
        artifact: 'sage_contracts_ReputationManager',
        getCalldata: () => CallData.compile({
            admin: CONFIG.deployer.address,
            cdc_pool: '0x0', // Will be set after CDCPool is deployed
            job_manager: '0x0', // Will be set after JobManager is deployed
            update_rate_limit: 3600, // 1 hour
        }),
        getDynamicCalldata: () => CallData.compile({
            admin: CONFIG.deployer.address,
            cdc_pool: newDeployed.CDCPool || '0x0',
            job_manager: newDeployed.JobManager || '0x0',
            update_rate_limit: 3600,
        }),
    },
    {
        name: 'PaymentRouter',
        artifact: 'sage_contracts_PaymentRouter',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            payment_token: newDeployed.SAGEToken,
            fee_manager: newDeployed.FeeManager,
            escrow: newDeployed.Escrow,
        }),
    },
    {
        name: 'PrivacyRouter',
        artifact: 'sage_contracts_PrivacyRouter',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            prover_registry: newDeployed.ObelyskProverRegistry,
        }),
    },
    {
        name: 'WorkerPrivacyHelper',
        artifact: 'sage_contracts_WorkerPrivacyHelper',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
        }),
    },
    {
        name: 'PrivacyPools',
        artifact: 'sage_contracts_PrivacyPools',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
            token: newDeployed.SAGEToken,
        }),
    },
    {
        name: 'ConfidentialSwap',
        artifact: 'sage_contracts_ConfidentialSwapContract',
        getCalldata: () => CallData.compile({
            owner: CONFIG.deployer.address,
        }),
    },
];

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage - Redeploy Failed Contracts', 'info');
    log('='.repeat(60), 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    log(`Deployer: ${CONFIG.deployer.address}`, 'info');
    log(`RPC: ${CONFIG.rpcUrl}`, 'info');

    const results = { deployed: [], failed: [] };

    for (const contract of CONTRACTS_TO_DEPLOY) {
        log(`\n--- Deploying ${contract.name} ---`, 'info');

        try {
            // Declare
            const classHash = await declareContract(
                account,
                provider,
                contract.name,
                contract.artifact
            );

            await sleep(2000);

            // Get calldata (use dynamic if available and dependencies are met)
            let calldata;
            if (contract.getDynamicCalldata) {
                calldata = contract.getDynamicCalldata();
            } else {
                calldata = contract.getCalldata();
            }

            // Deploy
            const address = await deployContract(
                account,
                provider,
                contract.name,
                classHash,
                calldata
            );

            newDeployed[contract.name] = address;
            results.deployed.push({ name: contract.name, address, classHash });

            await sleep(3000);

        } catch (error) {
            log(`Failed: ${contract.name} - ${error.message}`, 'error');
            results.failed.push({ name: contract.name, error: error.message });
        }
    }

    // Save results
    const outputPath = join(ROOT_DIR, 'deployment', 'redeployed_contracts.json');
    writeFileSync(outputPath, JSON.stringify({
        network: 'sepolia',
        deployer: CONFIG.deployer.address,
        deployed_at: new Date().toISOString(),
        all_contracts: newDeployed,
        new_deployments: results.deployed,
        failed: results.failed,
    }, null, 2));

    log('\n' + '='.repeat(60), 'info');
    log('DEPLOYMENT SUMMARY', 'info');
    log(`Deployed: ${results.deployed.length}`, 'success');
    log(`Failed: ${results.failed.length}`, results.failed.length > 0 ? 'error' : 'info');
    log(`Results saved to: ${outputPath}`, 'info');

    if (results.deployed.length > 0) {
        log('\nNewly Deployed:', 'success');
        for (const c of results.deployed) {
            log(`  ${c.name}: ${c.address}`, 'success');
        }
    }

    if (results.failed.length > 0) {
        log('\nFailed:', 'error');
        for (const c of results.failed) {
            log(`  ${c.name}: ${c.error.substring(0, 100)}...`, 'error');
        }
    }
}

main().catch(console.error);
