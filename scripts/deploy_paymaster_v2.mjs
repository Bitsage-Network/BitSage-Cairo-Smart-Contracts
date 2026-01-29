#!/usr/bin/env node
/**
 * BitSage Network - Deploy PaymasterV2 Contract
 *
 * Fresh deployment of the production-hardened PaymasterV2 with:
 *   - Timelock upgrade mechanism (5-min delay)
 *   - ProverStaking eligibility checks
 *   - Per-epoch spending caps
 *   - Restricted target contracts (ProofVerifier + StwoVerifier)
 *
 * Usage:
 *   DEPLOYER_PRIVATE_KEY=0x... node scripts/deploy_paymaster_v2.mjs
 */

import { Account, RpcProvider, CallData, Contract, hash, json, uint256 } from 'starknet';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
    rpcUrl: 'https://starknet-sepolia-rpc.publicnode.com',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// Sepolia contract addresses
const ADDRESSES = {
    sage_token: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    privacy_router: '0x0051e114ec3d524f203900c78e5217f23de51e29d6a6ecabb6dc92fb8ccca6e0',
    privacy_pools: '0x3e6b8684b1b1d55b88bd917b08df820fa3f23c92e19bab168e569bda430ef73',
    prover_staking: '0x3287a0af5ab2d74fbf968204ce2291adde008d645d42bc363cb741ebfa941b',
    proof_verifier: '0x17ada59ab642b53e6620ef2026f21eb3f2d1a338d6e85cb61d5bcd8dfbebc8b',
    stwo_verifier: '0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d',
    old_paymaster: '0x3370e353a2f3f6880f1a90708792279b8dc9d03b8560d7a95dfa08b9f9ed8bb',
};

const STRK_TOKEN = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

// 100 STRK per epoch (1 hour), denominated in wei (10^18)
const MAX_EPOCH_SPEND = uint256.bnToUint256(BigInt('100000000000000000000'));
const EPOCH_DURATION = 3600; // 1 hour in seconds

// Initial funding: 10 STRK (conservative)
const INITIAL_FUNDING = uint256.bnToUint256(BigInt('10000000000000000000'));

// ============================================================================
// HELPERS
// ============================================================================

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

function formatSTRK(amount) {
    return (Number(amount) / 1e18).toFixed(4);
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    log('BitSage PaymasterV2 Deployment', 'info');
    log('='.repeat(60), 'info');

    if (!CONFIG.deployer.privateKey) {
        log('DEPLOYER_PRIVATE_KEY environment variable not set', 'error');
        process.exit(1);
    }

    // Initialize provider and account (starknet.js v9 API)
    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
    });

    log(`Deployer: ${CONFIG.deployer.address}`, 'info');

    // Check deployer STRK balance
    const balanceResult = await provider.callContract({
        contractAddress: STRK_TOKEN,
        entrypoint: 'balanceOf',
        calldata: CallData.compile({ account: CONFIG.deployer.address }),
    });
    const balance = BigInt(balanceResult[0]) + (BigInt(balanceResult[1] || 0) << 128n);
    log(`Deployer STRK balance: ${formatSTRK(balance)} STRK`, 'info');

    // ========================================================================
    // Step 1: Load contract artifacts
    // ========================================================================
    log('\n[1/8] Loading PaymasterV2 contract artifacts...', 'info');
    const contractPath = path.join(__dirname, '../target/dev/sage_contracts_Paymaster.contract_class.json');
    const compiledPath = path.join(__dirname, '../target/dev/sage_contracts_Paymaster.compiled_contract_class.json');

    if (!fs.existsSync(contractPath)) {
        log(`Contract not found at ${contractPath}`, 'error');
        log('Run "scarb build" first!', 'error');
        process.exit(1);
    }

    const contractClass = json.parse(fs.readFileSync(contractPath, 'utf8'));
    const compiledContract = json.parse(fs.readFileSync(compiledPath, 'utf8'));
    log('Artifacts loaded', 'success');

    // ========================================================================
    // Step 2: Declare contract class
    // ========================================================================
    log('\n[2/8] Declaring PaymasterV2 contract class...', 'info');

    let classHash;
    try {
        const declareResponse = await account.declare({
            contract: contractClass,
            casm: compiledContract,
        });

        log(`Declaration tx: ${declareResponse.transaction_hash}`, 'info');
        log('Waiting for declaration...', 'info');
        await provider.waitForTransaction(declareResponse.transaction_hash);

        classHash = declareResponse.class_hash;
        log(`Class hash: ${classHash}`, 'success');
    } catch (error) {
        if (error.message?.includes('already declared') || error.message?.includes('CLASS_ALREADY_DECLARED')) {
            classHash = hash.computeContractClassHash(contractClass);
            log(`Contract already declared: ${classHash}`, 'warn');
        } else {
            throw error;
        }
    }

    // ========================================================================
    // Step 3: Deploy new PaymasterV2 contract
    // ========================================================================
    log('\n[3/8] Deploying PaymasterV2...', 'info');

    const salt = '0x' + Date.now().toString(16);

    const deployResponse = await account.deployContract({
        classHash,
        constructorCalldata: [],
        salt,
    });

    log(`Deploy tx: ${deployResponse.transaction_hash}`, 'info');
    log('Waiting for deployment...', 'info');
    await provider.waitForTransaction(deployResponse.transaction_hash);

    const paymasterAddress = deployResponse.contract_address;
    log(`PaymasterV2 deployed at: ${paymasterAddress}`, 'success');

    // ========================================================================
    // Step 4: Initialize V1 base
    // ========================================================================
    log('\n[4/8] Initializing PaymasterV2 (base)...', 'info');

    const initCalldata = CallData.compile({
        owner: CONFIG.deployer.address,
        fee_token: ADDRESSES.sage_token,
        privacy_router: ADDRESSES.privacy_router,
        privacy_pools: ADDRESSES.privacy_pools,
    });

    const { transaction_hash: initTxHash } = await account.execute({
        contractAddress: paymasterAddress,
        entrypoint: 'initialize',
        calldata: initCalldata,
    });

    log(`Initialize tx: ${initTxHash}`, 'info');
    await provider.waitForTransaction(initTxHash);
    log('Base initialization complete', 'success');

    // ========================================================================
    // Step 5: Initialize V2 (staking + verifiers)
    // ========================================================================
    log('\n[5/8] Initializing V2 (staking, verifiers)...', 'info');

    const initV2Calldata = CallData.compile({
        prover_staking: ADDRESSES.prover_staking,
        proof_verifier: ADDRESSES.proof_verifier,
        stwo_verifier: ADDRESSES.stwo_verifier,
    });

    const { transaction_hash: initV2TxHash } = await account.execute({
        contractAddress: paymasterAddress,
        entrypoint: 'initialize_v2',
        calldata: initV2Calldata,
    });

    log(`Initialize V2 tx: ${initV2TxHash}`, 'info');
    await provider.waitForTransaction(initV2TxHash);
    log('V2 initialization complete', 'success');

    // ========================================================================
    // Step 6: Set spending cap (100 STRK / hour)
    // ========================================================================
    log('\n[6/8] Setting spending cap (100 STRK/hour)...', 'info');

    const spendingCapCalldata = CallData.compile({
        max_per_epoch: MAX_EPOCH_SPEND,
        epoch_duration: EPOCH_DURATION,
    });

    const { transaction_hash: capTxHash } = await account.execute({
        contractAddress: paymasterAddress,
        entrypoint: 'set_spending_cap',
        calldata: spendingCapCalldata,
    });

    log(`Spending cap tx: ${capTxHash}`, 'info');
    await provider.waitForTransaction(capTxHash);
    log('Spending cap set: 100 STRK per hour', 'success');

    // ========================================================================
    // Step 7: Register proof verifier selectors as sponsorable
    // ========================================================================
    log('\n[7/8] Registering sponsorable functions...', 'info');

    // Selectors computed via sn_keccak (starknet.js getSelectorFromName)
    const VERIFY_PROOF_SELECTOR = '0x821b8b00fd9e4b2b57538b4571c0227e80f5dbdbfef0628722b3f06f3188';
    const SUBMIT_PROOF_SELECTOR = '0x93bfb85321bf1240b79f8a2cf9178de6ea382435fd15247758552f87f2d952';

    const registerCalls = [
        {
            contractAddress: paymasterAddress,
            entrypoint: 'register_sponsorable_function',
            calldata: CallData.compile({
                contract: ADDRESSES.proof_verifier,
                selector: VERIFY_PROOF_SELECTOR,
            }),
        },
        {
            contractAddress: paymasterAddress,
            entrypoint: 'register_sponsorable_function',
            calldata: CallData.compile({
                contract: ADDRESSES.proof_verifier,
                selector: SUBMIT_PROOF_SELECTOR,
            }),
        },
        {
            contractAddress: paymasterAddress,
            entrypoint: 'register_sponsorable_function',
            calldata: CallData.compile({
                contract: ADDRESSES.stwo_verifier,
                selector: VERIFY_PROOF_SELECTOR,
            }),
        },
        {
            contractAddress: paymasterAddress,
            entrypoint: 'register_sponsorable_function',
            calldata: CallData.compile({
                contract: ADDRESSES.stwo_verifier,
                selector: SUBMIT_PROOF_SELECTOR,
            }),
        },
    ];

    const { transaction_hash: registerTxHash } = await account.execute(registerCalls);
    log(`Register selectors tx: ${registerTxHash}`, 'info');
    await provider.waitForTransaction(registerTxHash);
    log('Sponsorable functions registered', 'success');

    // ========================================================================
    // Step 8: Fund with 10 STRK (conservative initial amount)
    // ========================================================================
    log('\n[8/8] Funding PaymasterV2 with 10 STRK...', 'info');

    // Transfer STRK directly to the paymaster contract address.
    // Note: deposit_funds() uses config.fee_token (SAGE), but V3 gas sponsorship
    // requires STRK balance on the contract. We transfer STRK directly.
    const { transaction_hash: fundTxHash } = await account.execute({
        contractAddress: STRK_TOKEN,
        entrypoint: 'transfer',
        calldata: CallData.compile({
            recipient: paymasterAddress,
            amount: INITIAL_FUNDING,
        }),
    });

    log(`Fund tx: ${fundTxHash}`, 'info');
    await provider.waitForTransaction(fundTxHash);
    log('PaymasterV2 funded with 10 STRK', 'success');

    // ========================================================================
    // Output results
    // ========================================================================
    log('\n' + '='.repeat(60), 'info');
    log('PAYMASTERV2 DEPLOYMENT COMPLETE', 'success');
    log('='.repeat(60), 'info');

    console.log(`
PaymasterV2 Contract:
  Address: ${paymasterAddress}
  Class Hash: ${classHash}

Configuration:
  Owner: ${CONFIG.deployer.address}
  Fee Token (SAGE): ${ADDRESSES.sage_token}
  Prover Staking: ${ADDRESSES.prover_staking}
  Proof Verifier: ${ADDRESSES.proof_verifier}
  Stwo Verifier: ${ADDRESSES.stwo_verifier}
  Spending Cap: 100 STRK/hour
  Initial Funding: 10 STRK

Old Paymaster (to drain):
  Address: ${ADDRESSES.old_paymaster}

Explorer:
  https://sepolia.starkscan.co/contract/${paymasterAddress}

Next Steps:
  1. Test: Submit proof from staked worker via V3 -> should succeed
  2. Test: Submit from non-staked address -> should be rejected
  3. Withdraw STRK from old paymaster:
     cast send ${ADDRESSES.old_paymaster} withdraw_funds(800000000000000000000, ${CONFIG.deployer.address})
  4. Update PAYMASTER_ADDRESS in rust-node/.env to: ${paymasterAddress}
  5. Monitor for 24 hours, then increase funding
`);

    // Update deployed addresses file
    const deployedPath = path.join(__dirname, '../deployment/deployed_addresses_sepolia.json');
    if (fs.existsSync(deployedPath)) {
        const deployed = JSON.parse(fs.readFileSync(deployedPath, 'utf8'));
        deployed.contracts.PaymasterV2 = {
            class_hash: classHash,
            address: paymasterAddress,
        };
        // Keep old paymaster reference
        if (deployed.contracts.Paymaster) {
            deployed.contracts.PaymasterV1_deprecated = deployed.contracts.Paymaster;
        }
        fs.writeFileSync(deployedPath, JSON.stringify(deployed, null, 2));
        log('Updated deployed_addresses_sepolia.json', 'success');
    }
}

main().catch((error) => {
    log(`Deployment failed: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
});
