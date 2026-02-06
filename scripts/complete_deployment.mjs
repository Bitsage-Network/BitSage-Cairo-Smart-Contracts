#!/usr/bin/env node
/**
 * BitSage Network - Complete Remaining Deployments
 *
 * Uses the NEW SAGEToken that was already deployed with correct owner.
 * Only deploys contracts that are missing or need the correct SAGEToken reference.
 */

import { Account, RpcProvider, CallData, json, hash } from 'starknet';
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
    rpcUrl: 'https://api.cartridge.gg/x/starknet/sepolia',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
    strkToken: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
    usdcToken: '0x053b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080',
};

// ============================================================================
// ALREADY DEPLOYED CONTRACTS (with correct owner)
// ============================================================================

// The NEW SAGEToken deployed with correct owner
const SAGE_TOKEN = '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850';

// Pre-populated deployed addresses - will be updated as we deploy
const deployed = {
    SAGEToken: SAGE_TOKEN,
};

// ============================================================================
// HELPER FUNCTIONS
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
    const prefix = {
        info: '[INFO]',
        success: '[OK]',
        error: '[ERR]',
        warn: '[WARN]',
    };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

async function declareContract(account, provider, contractName, artifactPath) {
    const sierraPath = join(ROOT_DIR, 'target/dev', `${artifactPath}.contract_class.json`);
    const casmPath = join(ROOT_DIR, 'target/dev', `${artifactPath}.compiled_contract_class.json`);

    if (!existsSync(sierraPath)) {
        throw new Error(`Sierra file not found: ${sierraPath}`);
    }
    if (!existsSync(casmPath)) {
        throw new Error(`CASM file not found: ${casmPath}`);
    }

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
    const calldata = Object.keys(constructorCalldata).length > 0
        ? CallData.compile(constructorCalldata)
        : [];

    const deployResponse = await account.deployContract({
        classHash,
        constructorCalldata: calldata,
    });

    log(`Deploying ${contractName}... TX: ${deployResponse.transaction_hash.slice(0, 20)}...`, 'info');
    await provider.waitForTransaction(deployResponse.transaction_hash);
    log(`${contractName} deployed at: ${deployResponse.contract_address}`, 'success');

    return deployResponse.contract_address;
}

async function initializeContract(account, provider, contractAddress, initArgs) {
    const initCalldata = CallData.compile(initArgs);
    const initTx = await account.execute({
        contractAddress,
        entrypoint: 'initialize',
        calldata: initCalldata,
    });
    log(`Initializing... TX: ${initTx.transaction_hash.slice(0, 20)}...`, 'info');
    await provider.waitForTransaction(initTx.transaction_hash);
    log(`Initialized!`, 'success');
}

// ============================================================================
// CONTRACT DEFINITIONS
// ============================================================================

const CONTRACTS_TO_DEPLOY = [
    // Basic Infrastructure
    {
        name: 'ReputationManager',
        file: 'sage_contracts_ReputationManager',
        getCalldata: () => ({ owner: CONFIG.deployer.address }),
    },
    {
        name: 'AddressRegistry',
        file: 'sage_contracts_AddressRegistry',
        getCalldata: () => ({ owner: CONFIG.deployer.address }),
    },
    // Staking & Collateral
    {
        name: 'ProverStaking',
        file: 'sage_contracts_ProverStaking',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            treasury: CONFIG.deployer.address,
        }),
    },
    {
        name: 'WorkerStaking',
        file: 'sage_contracts_WorkerStaking',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            treasury: CONFIG.deployer.address,
            burn_address: CONFIG.deployer.address,
        }),
    },
    {
        name: 'Collateral',
        file: 'sage_contracts_Collateral',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'ValidatorRegistry',
        file: 'sage_contracts_ValidatorRegistry',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    // Verification & Proofs
    {
        name: 'ProofVerifier',
        file: 'sage_contracts_ProofVerifier',
        getCalldata: () => ({ owner: CONFIG.deployer.address }),
    },
    {
        name: 'StwoVerifier',
        file: 'sage_contracts_StwoVerifier',
        getCalldata: () => ({ owner: CONFIG.deployer.address }),
    },
    {
        name: 'FraudProof',
        file: 'sage_contracts_FraudProof',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            staking_contract: deployed.ProverStaking,
        }),
    },
    {
        name: 'OptimisticTEE',
        file: 'sage_contracts_OptimisticTEE',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            proof_verifier: deployed.ProofVerifier,
            sage_token: deployed.SAGEToken,
        }),
    },
    // Payments & Economics
    {
        name: 'Escrow',
        file: 'sage_contracts_Escrow',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'FeeManager',
        file: 'sage_contracts_FeeManager',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            treasury: CONFIG.deployer.address,
            job_manager: CONFIG.deployer.address,
        }),
    },
    {
        name: 'MeteredBilling',
        file: 'sage_contracts_MeteredBilling',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            fee_manager: deployed.FeeManager || CONFIG.deployer.address,
        }),
    },
    {
        name: 'ProofGatedPayment',
        file: 'sage_contracts_ProofGatedPayment',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            proof_verifier: deployed.ProofVerifier,
        }),
    },
    {
        name: 'DynamicPricing',
        file: 'sage_contracts_DynamicPricing',
        getCalldata: () => ({ owner: CONFIG.deployer.address }),
    },
    // Core Business Logic
    {
        name: 'CDCPool',
        file: 'sage_contracts_CDCPool',
        getCalldata: () => ({
            admin: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            min_stake: { low: '0x3635c9adc5dea00000', high: '0x0' }, // 1000 SAGE
            reputation_manager: deployed.ReputationManager,
        }),
    },
    {
        name: 'OracleWrapper',
        file: 'sage_contracts_OracleWrapper',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            pragma_oracle: CONFIG.deployer.address,
        }),
    },
    {
        name: 'PaymentRouter',
        file: 'sage_contracts_PaymentRouter',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            oracle: deployed.OracleWrapper || CONFIG.deployer.address,
            cdc_pool: deployed.CDCPool,
            privacy_router: CONFIG.deployer.address,
        }),
    },
    {
        name: 'JobManager',
        file: 'sage_contracts_JobManager',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            payment_router: deployed.PaymentRouter,
            cdc_pool: deployed.CDCPool,
        }),
    },
    // Privacy Layer
    {
        name: 'PrivacyRouter',
        file: 'sage_contracts_PrivacyRouter',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            payment_router: deployed.PaymentRouter,
        }),
    },
    {
        name: 'WorkerPrivacyHelper',
        file: 'sage_contracts_WorkerPrivacyHelper',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            privacy_router: deployed.PrivacyRouter,
        }),
    },
    {
        name: 'PrivacyPools',
        file: 'sage_contracts_PrivacyPools',
        getCalldata: () => ({}),
        initialize: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            privacy_router: deployed.PrivacyRouter,
        }),
    },
    {
        name: 'MixingRouter',
        file: 'sage_contracts_MixingRouter',
        getCalldata: () => ({}),
        initialize: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'SteganographicRouter',
        file: 'sage_contracts_SteganographicRouter',
        getCalldata: () => ({}),
        initialize: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'ConfidentialSwapContract',
        file: 'sage_contracts_ConfidentialSwapContract',
        getCalldata: () => ({ owner: CONFIG.deployer.address }),
    },
    // Trading & Growth
    {
        name: 'OTCOrderbook',
        file: 'sage_contracts_OTCOrderbook',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            fee_recipient: CONFIG.deployer.address,
            usdc_token: CONFIG.usdcToken,
        }),
    },
    {
        name: 'ReferralSystem',
        file: 'sage_contracts_ReferralSystem',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            reward_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'Gamification',
        file: 'sage_contracts_Gamification',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    // Governance & Vesting
    {
        name: 'TreasuryTimelock',
        file: 'sage_contracts_TreasuryTimelock',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            min_delay: 86400, // 24 hours
        }),
    },
    {
        name: 'GovernanceTreasury',
        file: 'sage_contracts_GovernanceTreasury',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
            timelock: deployed.TreasuryTimelock,
        }),
    },
    {
        name: 'BurnManager',
        file: 'sage_contracts_BurnManager',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'LinearVestingWithCliff',
        file: 'sage_contracts_LinearVestingWithCliff',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'MilestoneVesting',
        file: 'sage_contracts_MilestoneVesting',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'RewardVesting',
        file: 'sage_contracts_RewardVesting',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    // Final Infrastructure
    {
        name: 'Faucet',
        file: 'sage_contracts_Faucet',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            sage_token: deployed.SAGEToken,
        }),
    },
    {
        name: 'ObelyskProverRegistry',
        file: 'sage_contracts_ObelyskProverRegistry',
        getCalldata: () => ({
            owner: CONFIG.deployer.address,
            verifier: deployed.ProofVerifier,
            sage_token: deployed.SAGEToken,
            treasury: CONFIG.deployer.address,
        }),
    },
];

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    console.log('\n' + '='.repeat(70));
    console.log('   BitSage Network - Complete Sepolia Deployment');
    console.log('='.repeat(70));
    console.log(`Deployer: ${CONFIG.deployer.address}`);
    console.log(`SAGEToken: ${SAGE_TOKEN}`);
    console.log(`RPC: ${CONFIG.rpcUrl}`);
    console.log('='.repeat(70) + '\n');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const chainId = await provider.getChainId();
    log(`Connected to chain: ${chainId}`, 'success');

    // Check STRK balance
    const balanceResult = await provider.callContract({
        contractAddress: CONFIG.strkToken,
        entrypoint: 'balanceOf',
        calldata: [CONFIG.deployer.address],
    });
    const strkBalance = Number(BigInt(balanceResult[0])) / 1e18;
    log(`STRK Balance: ${strkBalance.toFixed(2)} STRK`, 'info');

    if (strkBalance < 5) {
        log('WARNING: Low STRK balance! Deployment may fail.', 'warn');
    }

    // Create account
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Results tracking
    const results = {
        network: 'sepolia',
        rpc_url: CONFIG.rpcUrl,
        deployer: CONFIG.deployer.address,
        deployed_at: new Date().toISOString(),
        contracts: {
            SAGEToken: {
                address: SAGE_TOKEN,
                note: 'Previously deployed with correct owner',
            },
        },
    };

    let totalDeployed = 1; // SAGEToken already deployed
    let totalFailed = 0;

    // Deploy each contract
    for (const contract of CONTRACTS_TO_DEPLOY) {
        try {
            log(`\nDeploying ${contract.name}...`, 'info');

            // Declare
            const classHash = await declareContract(account, provider, contract.name, contract.file);

            // Get constructor calldata
            const calldata = contract.getCalldata();

            // Deploy
            const address = await deployContract(account, provider, contract.name, classHash, calldata);

            // Store deployed address
            deployed[contract.name] = address;
            results.contracts[contract.name] = {
                class_hash: classHash,
                address: address,
            };

            // Initialize if needed
            if (contract.initialize) {
                const initArgs = contract.initialize();
                await initializeContract(account, provider, address, initArgs);
            }

            totalDeployed++;
            await sleep(500);

        } catch (error) {
            log(`Failed to deploy ${contract.name}: ${error.message}`, 'error');
            results.contracts[contract.name] = { error: error.message };
            totalFailed++;
        }
    }

    // Save results
    const outputPath = join(ROOT_DIR, 'deployment/deployed_addresses_sepolia_new.json');
    results.notes = [
        `Deployment completed on ${new Date().toISOString()}`,
        `Deployed ${totalDeployed} contracts successfully`,
        `Failed: ${totalFailed} contracts`,
        'All contracts owned by deployer: 0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        'SAGEToken at: ' + SAGE_TOKEN,
    ];
    results.explorer = {
        base_url: 'https://sepolia.starkscan.co',
        contract_url_template: 'https://sepolia.starkscan.co/contract/{address}',
    };

    writeFileSync(outputPath, JSON.stringify(results, null, 2));
    log(`\nResults saved to: ${outputPath}`, 'success');

    // Print summary
    console.log('\n' + '='.repeat(70));
    console.log('   DEPLOYMENT SUMMARY');
    console.log('='.repeat(70));
    console.log(`Deployed: ${totalDeployed}`);
    console.log(`Failed: ${totalFailed}`);
    console.log('='.repeat(70));

    console.log('\nKey Addresses:');
    console.log(`  SAGEToken:      ${deployed.SAGEToken}`);
    console.log(`  Faucet:         ${deployed.Faucet || 'Not deployed'}`);
    console.log(`  JobManager:     ${deployed.JobManager || 'Not deployed'}`);
    console.log(`  OTCOrderbook:   ${deployed.OTCOrderbook || 'Not deployed'}`);
    console.log(`  PrivacyPools:   ${deployed.PrivacyPools || 'Not deployed'}`);

    console.log('\nDeployment complete!\n');
}

main().catch((error) => {
    console.error('\nDeployment failed:', error.message);
    if (error.data) {
        console.error('Error data:', JSON.stringify(error.data, null, 2));
    }
    process.exit(1);
});
