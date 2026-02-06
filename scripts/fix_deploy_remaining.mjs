#!/usr/bin/env node
/**
 * BitSage Network - Fix and Deploy Remaining Contracts
 *
 * Deploys the 10 failed contracts with corrected constructor parameter serialization.
 * Key fixes:
 * - Structs are serialized as flat arrays of their fields
 * - Arrays are prefixed with their length
 * - Booleans are 0/1 felts
 * - PrivacyPools uses initialize() pattern - no constructor args
 */

import { Account, RpcProvider, CallData, json, hash, cairo, Contract } from 'starknet';
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

// Already deployed contracts (with correct owner)
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
    // From previous batch
    StwoVerifier: '0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d',
    MeteredBilling: '0x1adb19d21f28f56ae9a8852d19f2e2af728764846d30002da8782d571ae01b2',
    ProofGatedPayment: '0x7e74d191b1cca7cac00adc03bc64eaa6236b81001f50c61d1d70ec4bfde8af0',
    OracleWrapper: '0x4d86bb472cb462a45d68a705a798b5e419359a5758d84b24af4bbe5441b6e5a',
    TreasuryTimelock: '0x4cc9603d7e72469de22aa84d9ac20ddcbaa7309d7eb091f75cd7f7a9e087947',
    ReputationManager: '0x4ef80990256fb016381f57c340a306e37376c1de70fa11147a4f1fc57a834de',
    ConfidentialSwap: '0x29516b3abfbc56fdf0c1f136c971602325cbabf07ad8f984da582e2106ad2af',
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

async function deployContract(account, provider, contractName, classHash, constructorCalldata, retries = 3) {
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
// CONTRACT DEPLOYMENTS - With Correct Calldata Serialization
// ============================================================================

const CONTRACTS_TO_DEPLOY = [
    // 1. LinearVestingWithCliff - VestingConfig struct needs flat serialization
    {
        name: 'LinearVestingWithCliff',
        artifact: 'sage_contracts_LinearVestingWithCliff',
        getCalldata: () => {
            // VestingConfig struct: min_cliff_duration, max_cliff_duration,
            // min_vesting_duration, max_vesting_duration, allow_revocation
            return [
                CONFIG.deployer.address,              // owner
                newDeployed.SAGEToken,                // token_contract
                // VestingConfig fields (flattened):
                '0',                                  // min_cliff_duration (0 = no minimum)
                String(365 * 24 * 3600),              // max_cliff_duration (1 year)
                String(30 * 24 * 3600),               // min_vesting_duration (30 days)
                String(4 * 365 * 24 * 3600),          // max_vesting_duration (4 years)
                '1',                                  // allow_revocation (true)
            ];
        },
    },

    // 2. MilestoneVesting - VerificationConfig struct
    {
        name: 'MilestoneVesting',
        artifact: 'sage_contracts_MilestoneVesting',
        getCalldata: () => {
            // VerificationConfig: require_verification, verification_timeout,
            // auto_verify_after_timeout, min_verifiers
            return [
                CONFIG.deployer.address,              // owner
                newDeployed.SAGEToken,                // token_contract
                // VerificationConfig fields (flattened):
                '1',                                  // require_verification (true)
                String(7 * 24 * 3600),                // verification_timeout (7 days)
                '0',                                  // auto_verify_after_timeout (false)
                '2',                                  // min_verifiers (2)
            ];
        },
    },

    // 3. CDCPool - Simple params, had RPC issues before
    {
        name: 'CDCPool',
        artifact: 'sage_contracts_CDCPool',
        getCalldata: () => {
            // min_stake is u256, need low/high
            const minStake = 100n * 10n ** 18n; // 100 SAGE minimum stake
            return CallData.compile({
                admin: CONFIG.deployer.address,
                sage_token: newDeployed.SAGEToken,
                min_stake: cairo.uint256(minStake),
            });
        },
    },

    // 4. JobManager - Simple 4 addresses
    {
        name: 'JobManager',
        artifact: 'sage_contracts_JobManager',
        getCalldata: () => {
            return CallData.compile({
                admin: CONFIG.deployer.address,
                payment_token: newDeployed.SAGEToken,
                treasury: CONFIG.deployer.address, // Will update later
                cdc_pool_contract: '0x0', // Optional, can be zero initially
            });
        },
    },

    // 5. PaymentRouter - 5 addresses
    {
        name: 'PaymentRouter',
        artifact: 'sage_contracts_PaymentRouter',
        getCalldata: () => {
            return CallData.compile({
                owner: CONFIG.deployer.address,
                sage_address: newDeployed.SAGEToken,
                oracle_address: newDeployed.OracleWrapper,
                staker_rewards_pool: newDeployed.ProverStaking,
                treasury_address: CONFIG.deployer.address,
            });
        },
    },

    // 6. PrivacyRouter - 3 addresses
    {
        name: 'PrivacyRouter',
        artifact: 'sage_contracts_PrivacyRouter',
        getCalldata: () => {
            return CallData.compile({
                owner: CONFIG.deployer.address,
                sage_token: newDeployed.SAGEToken,
                payment_router: newDeployed.PaymentRouter || CONFIG.deployer.address,
            });
        },
    },

    // 7. WorkerPrivacyHelper - 3 addresses
    {
        name: 'WorkerPrivacyHelper',
        artifact: 'sage_contracts_WorkerPrivacyHelper',
        getCalldata: () => {
            return CallData.compile({
                owner: CONFIG.deployer.address,
                payment_router: newDeployed.PaymentRouter || CONFIG.deployer.address,
                privacy_router: newDeployed.PrivacyRouter || CONFIG.deployer.address,
            });
        },
    },

    // 8. GovernanceTreasury - Array + struct (complex)
    {
        name: 'GovernanceTreasury',
        artifact: 'sage_contracts_GovernanceTreasury',
        getCalldata: () => {
            // GovernanceConfig: voting_delay, voting_period, execution_delay,
            // quorum_threshold (u256), proposal_threshold (u256)
            const quorum = 1000n * 10n ** 18n; // 1000 SAGE
            const proposalThreshold = 100n * 10n ** 18n; // 100 SAGE

            return [
                CONFIG.deployer.address,              // owner
                newDeployed.SAGEToken,                // sage_token
                // Array<ContractAddress> - length first, then elements
                '1',                                  // array length
                CONFIG.deployer.address,              // council member
                // council_threshold
                '1',
                // GovernanceConfig flattened:
                String(1 * 24 * 3600),                // voting_delay (1 day)
                String(3 * 24 * 3600),                // voting_period (3 days)
                String(1 * 24 * 3600),                // execution_delay (1 day)
                // quorum_threshold (u256 low, high)
                String(quorum & ((1n << 128n) - 1n)),
                String(quorum >> 128n),
                // proposal_threshold (u256 low, high)
                String(proposalThreshold & ((1n << 128n) - 1n)),
                String(proposalThreshold >> 128n),
            ];
        },
    },

    // 9. BurnManager - Complex with 2 structs
    {
        name: 'BurnManager',
        artifact: 'sage_contracts_BurnManager',
        getCalldata: () => {
            // RevenueBurnConfig: revenue_percentage (u256), min_burn_amount (u256),
            // max_burn_amount (u256), accumulation_period (u64)
            // BuybackConfig: treasury_allocation (u256), price_threshold (u256),
            // max_slippage (u256), cooldown_period (u64)

            const minBurn = 10n * 10n ** 18n;
            const maxBurn = 10000n * 10n ** 18n;
            const treasuryAlloc = 500n; // 5% in basis points * 100
            const priceThreshold = 1n * 10n ** 18n; // $1
            const maxSlippage = 100n; // 1%

            return [
                CONFIG.deployer.address,              // owner
                newDeployed.SAGEToken,                // token_contract
                CONFIG.deployer.address,              // treasury_contract
                // RevenueBurnConfig flattened:
                '1000', '0',                          // revenue_percentage (u256: 10%)
                String(minBurn & ((1n << 128n) - 1n)), String(minBurn >> 128n), // min_burn (u256)
                String(maxBurn & ((1n << 128n) - 1n)), String(maxBurn >> 128n), // max_burn (u256)
                String(24 * 3600),                    // accumulation_period (1 day)
                // BuybackConfig flattened:
                String(treasuryAlloc), '0',           // treasury_allocation (u256)
                String(priceThreshold), '0',          // price_threshold (u256)
                String(maxSlippage), '0',             // max_slippage (u256)
                String(7 * 24 * 3600),                // cooldown_period (7 days)
            ];
        },
    },

    // 10. PrivacyPools - NO constructor, uses initialize()
    {
        name: 'PrivacyPools',
        artifact: 'sage_contracts_PrivacyPools',
        getCalldata: () => [],  // Empty calldata - no constructor
        postDeploy: async (account, provider, address) => {
            log('Calling initialize() on PrivacyPools...', 'info');
            const sierraPath = join(ROOT_DIR, 'target/dev', 'sage_contracts_PrivacyPools.contract_class.json');
            const sierra = json.parse(readFileSync(sierraPath).toString());

            const contract = new Contract(sierra.abi, address, account);
            const initCalldata = CallData.compile({
                owner: CONFIG.deployer.address,
                sage_token: newDeployed.SAGEToken,
                privacy_router: newDeployed.PrivacyRouter || CONFIG.deployer.address,
            });

            const { transaction_hash } = await account.execute({
                contractAddress: address,
                entrypoint: 'initialize',
                calldata: initCalldata,
            });
            await provider.waitForTransaction(transaction_hash);
            log('PrivacyPools initialized!', 'success');
        },
    },
];

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage - Deploy Remaining 10 Contracts', 'info');
    log('='.repeat(60), 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    // starknet.js v9 Account constructor format
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

            // Get calldata
            const calldata = contract.getCalldata();
            log(`Calldata: ${JSON.stringify(calldata).substring(0, 200)}...`, 'info');

            // Deploy
            const address = await deployContract(
                account,
                provider,
                contract.name,
                classHash,
                calldata
            );

            newDeployed[contract.name] = address;

            // Post-deploy hook (for PrivacyPools initialize)
            if (contract.postDeploy) {
                await contract.postDeploy(account, provider, address);
            }

            results.deployed.push({ name: contract.name, address, classHash });
            await sleep(3000);

        } catch (error) {
            log(`Failed: ${contract.name} - ${error.message}`, 'error');
            console.error(error);
            results.failed.push({ name: contract.name, error: error.message });
        }
    }

    // Save results
    const outputPath = join(ROOT_DIR, 'deployment', 'final_deployed_contracts.json');
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

    log('\n' + '='.repeat(60), 'info');
    log('TOTAL CONTRACTS WITH CORRECT OWNER:', 'info');
    log(`  ${Object.keys(newDeployed).length} contracts`, 'success');
}

main().catch(console.error);
