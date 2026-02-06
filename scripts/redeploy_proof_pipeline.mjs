#!/usr/bin/env node
// Redeploy Proof Pipeline Contracts
//
// Deploys 5 pipeline contracts with deployer as owner, then configures
// cross-references between them. Uses Starknet Sepolia testnet.
//
// Usage: DEPLOYER_PRIVATE_KEY=0x... node scripts/redeploy_proof_pipeline.mjs

import { Account, RpcProvider, json, CallData, hash, Contract, uint256 } from 'starknet';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =============================================================================
// Configuration
// =============================================================================

const CONFIG = {
    rpcUrl: process.env.STARKNET_RPC_URL || 'https://starknet-sepolia-rpc.publicnode.com',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// Existing deployed contract addresses (Sepolia)
const EXISTING = {
    sage_token: '0x04321b7282ae6aa354988eed57f2ff851314af8524de8b1f681a128003cc4ea5',
    payment_router: '0x3a3d409738734ae42365a20ae217687991cbba9db743c30d87f6a6dbaf523c6',
};

// Contracts to deploy (in order)
const PIPELINE_CONTRACTS = [
    'StwoVerifier',
    'ProofGatedPayment',
    'OptimisticTEE',
    'ProverStaking',
    'FeeManager',
];

// =============================================================================
// Logging
// =============================================================================

const COLORS = { reset: '\x1b[0m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m', bold: '\x1b[1m' };

function log(level, msg) {
    const colors = { info: COLORS.cyan, success: COLORS.green, warn: COLORS.yellow, error: COLORS.red };
    const prefix = { info: '[INFO]', success: '[OK]', warn: '[WARN]', error: '[ERR]' };
    console.log(`${colors[level] || ''}${prefix[level] || ''} ${msg}${COLORS.reset}`);
}

// =============================================================================
// Main Deployment
// =============================================================================

async function main() {
    log('info', '=== BitSage Proof Pipeline Redeployment ===');

    if (!CONFIG.deployer.privateKey) {
        log('error', 'DEPLOYER_PRIVATE_KEY environment variable is required');
        process.exit(1);
    }

    // Initialize provider and account
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    log('info', `Deployer: ${CONFIG.deployer.address}`);
    log('info', `RPC: ${CONFIG.rpcUrl}`);

    const deployed = {};

    // =========================================================================
    // Step 1: Deploy all 5 contracts
    // =========================================================================

    for (const contractName of PIPELINE_CONTRACTS) {
        log('info', `\n--- Deploying ${contractName} ---`);

        const cairoName = `sage_contracts_${contractName}`;
        const contractPath = path.join(__dirname, `../target/dev/${cairoName}.contract_class.json`);
        const compiledPath = path.join(__dirname, `../target/dev/${cairoName}.compiled_contract_class.json`);

        if (!fs.existsSync(contractPath)) {
            log('warn', `Contract artifact not found: ${contractPath}`);
            log('warn', `Skipping ${contractName} — run 'scarb build' first`);
            continue;
        }

        const contractClass = json.parse(fs.readFileSync(contractPath, 'utf8'));
        const compiledContract = fs.existsSync(compiledPath)
            ? json.parse(fs.readFileSync(compiledPath, 'utf8'))
            : null;

        // Declare
        let classHash;
        try {
            log('info', `Declaring ${contractName}...`);
            const declareResponse = await account.declare({
                contract: contractClass,
                casm: compiledContract,
            });
            classHash = declareResponse.class_hash;
            log('success', `Declared: ${classHash}`);
            await provider.waitForTransaction(declareResponse.transaction_hash);
        } catch (error) {
            if (error.message?.includes('already declared') || error.message?.includes('CLASS_ALREADY_DECLARED')) {
                classHash = hash.computeContractClassHash(contractClass);
                log('warn', `Already declared: ${classHash}`);
            } else {
                log('error', `Declaration failed: ${error.message}`);
                throw error;
            }
        }

        // Build constructor calldata based on contract type
        const owner = CONFIG.deployer.address;
        const deployer_placeholder = CONFIG.deployer.address;
        let constructorCalldata;

        switch (contractName) {
            case 'StwoVerifier':
                constructorCalldata = CallData.compile({
                    owner,
                    min_security_bits: 128,
                    max_proof_size: 262144,
                    gpu_tee_enabled: 1, // true
                });
                break;
            case 'ProofGatedPayment':
                constructorCalldata = CallData.compile({
                    owner,
                    proof_verifier: deployer_placeholder,
                });
                break;
            case 'OptimisticTEE':
                constructorCalldata = CallData.compile({
                    owner,
                    proof_verifier: deployer_placeholder,
                    sage_token: EXISTING.sage_token,
                });
                break;
            case 'ProverStaking':
                constructorCalldata = CallData.compile({
                    owner,
                    sage_token: EXISTING.sage_token,
                    treasury: owner,
                });
                break;
            case 'FeeManager':
                constructorCalldata = CallData.compile({
                    owner,
                    sage_token: EXISTING.sage_token,
                    treasury: owner,
                    job_manager: owner,
                });
                break;
            default:
                constructorCalldata = CallData.compile({ owner });
        }

        // Deploy
        try {
            const salt = '0x' + Date.now().toString(16);
            log('info', `Deploying ${contractName} with salt ${salt}...`);

            const deployResponse = await account.deployContract({
                classHash,
                constructorCalldata,
                salt,
            });

            await provider.waitForTransaction(deployResponse.transaction_hash);

            const address = deployResponse.contract_address
                || deployResponse.address
                || deployResponse.contract_address?.[0];

            deployed[contractName] = {
                class_hash: classHash,
                address: address,
            };

            log('success', `${contractName} deployed at: ${address}`);
        } catch (error) {
            log('error', `Deployment of ${contractName} failed: ${error.message}`);
            // Continue with remaining contracts
        }
    }

    // =========================================================================
    // Step 2: Configure cross-references
    // =========================================================================

    log('info', '\n--- Configuring cross-references ---');

    const configCalls = [];

    // Set upgrade delay on all pipeline contracts (testnet)
    // Some contracts enforce a minimum (e.g. FeeManager requires >= 1 day)
    const UPGRADE_DELAYS = {
        StwoVerifier: 300,         // 5 minutes (testnet default)
        ProofGatedPayment: 300,    // 5 minutes
        OptimisticTEE: 300,        // 5 minutes
        ProverStaking: 300,        // 5 minutes
        FeeManager: 86400,         // 1 day (contract-enforced minimum)
    };
    for (const [name, info] of Object.entries(deployed)) {
        const delay = UPGRADE_DELAYS[name] || 86400;
        configCalls.push({
            contractAddress: info.address,
            entrypoint: 'set_upgrade_delay',
            calldata: CallData.compile({ new_delay: delay }),
        });
        log('info', `${name}.set_upgrade_delay(${delay}s)`);
    }

    // StwoVerifier.set_verification_callback(ProofGatedPayment)
    if (deployed.StwoVerifier && deployed.ProofGatedPayment) {
        configCalls.push({
            contractAddress: deployed.StwoVerifier.address,
            entrypoint: 'set_verification_callback',
            calldata: CallData.compile({
                callback_contract: deployed.ProofGatedPayment.address,
            }),
        });
        log('info', 'StwoVerifier.set_verification_callback -> ProofGatedPayment');
    }

    // ProofGatedPayment.configure(PaymentRouter, OptimisticTEE, deployer, StwoVerifier)
    if (deployed.ProofGatedPayment && deployed.OptimisticTEE && deployed.StwoVerifier) {
        configCalls.push({
            contractAddress: deployed.ProofGatedPayment.address,
            entrypoint: 'configure',
            calldata: CallData.compile({
                payment_router: EXISTING.payment_router,
                optimistic_tee: deployed.OptimisticTEE.address,
                fee_manager: CONFIG.deployer.address,
                proof_verifier: deployed.StwoVerifier.address,
            }),
        });
        log('info', 'ProofGatedPayment.configure -> PaymentRouter, OptimisticTEE, StwoVerifier');
    }

    // OptimisticTEE.configure(ProofGatedPayment, ProverStaking)
    if (deployed.OptimisticTEE && deployed.ProofGatedPayment && deployed.ProverStaking) {
        configCalls.push({
            contractAddress: deployed.OptimisticTEE.address,
            entrypoint: 'configure',
            calldata: CallData.compile({
                proof_gated_payment: deployed.ProofGatedPayment.address,
                prover_staking: deployed.ProverStaking.address,
            }),
        });
        log('info', 'OptimisticTEE.configure -> ProofGatedPayment, ProverStaking');
    }

    if (configCalls.length > 0) {
        try {
            log('info', `Executing ${configCalls.length} configuration calls...`);
            const { transaction_hash } = await account.execute(configCalls);
            await provider.waitForTransaction(transaction_hash);
            log('success', `Configuration tx: ${transaction_hash}`);
        } catch (error) {
            log('error', `Configuration failed: ${error.message}`);
            log('warn', 'Some contracts may need manual configuration');
        }
    }

    // =========================================================================
    // Step 3: Save deployment results
    // =========================================================================

    const deploymentResult = {
        network: 'sepolia',
        deployer: CONFIG.deployer.address,
        timestamp: new Date().toISOString(),
        contracts: deployed,
        existing: EXISTING,
    };

    const outputPath = path.join(__dirname, '../deployment/proof_pipeline_addresses.json');
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    fs.writeFileSync(outputPath, JSON.stringify(deploymentResult, null, 2));
    log('success', `Deployment saved to: ${outputPath}`);

    // =========================================================================
    // Step 4: Print summary for network.rs update
    // =========================================================================

    log('info', '\n=== Deployment Summary ===');
    log('info', 'Update rust-node/src/obelysk/starknet/network.rs with:');
    console.log('');

    for (const [name, info] of Object.entries(deployed)) {
        const field_name = name.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '');
        console.log(`    ${field_name}: "${info.address}".to_string(),`);
    }

    console.log('');
    log('success', 'Pipeline redeployment complete!');
    log('info', 'Next: Update network.rs addresses, rebuild, and run benchmarks');
}

main().catch((error) => {
    log('error', `Fatal: ${error.message}`);
    console.error(error);
    process.exit(1);
});
