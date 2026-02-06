#!/usr/bin/env node
/**
 * Redeploy PaymentRouter with updated code (authorized_submitter support)
 *
 * Usage: DEPLOYER_PRIVATE_KEY=0x... node scripts/redeploy_payment_router.mjs
 */

import { Account, RpcProvider, CallData, json, hash } from 'starknet';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = join(__dirname, '..');

const CONFIG = {
    rpcUrl: 'https://api.cartridge.gg/x/starknet/sepolia',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },
};

// Existing deployed addresses needed for constructor
const EXISTING = {
    SAGEToken: '0x04321b7282ae6aa354988eed57f2ff851314af8524de8b1f681a128003cc4ea5',
    OracleWrapper: '0x0020ba92a5df4c7719decbc8e43d5475059311b0b8bb2cdd623f5f29d61f0f2d',
    CDCPool: '0x012c8ab3fad97954eafbf99ab9d76a9c8e85dd0f6b38139d12d3c5e3f14f950b',
};

async function main() {
    if (!CONFIG.deployer.privateKey) {
        console.error('ERROR: Set DEPLOYER_PRIVATE_KEY env var');
        process.exit(1);
    }

    console.log('=== Redeploying PaymentRouter ===');
    console.log(`Deployer: ${CONFIG.deployer.address}`);

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const chainId = await provider.getChainId();
    console.log(`Chain: ${chainId}`);

    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Declare new class
    const sierraPath = join(ROOT_DIR, 'target/dev/sage_contracts_PaymentRouter.contract_class.json');
    const casmPath = join(ROOT_DIR, 'target/dev/sage_contracts_PaymentRouter.compiled_contract_class.json');

    if (!existsSync(sierraPath) || !existsSync(casmPath)) {
        console.error('ERROR: Build artifacts not found. Run `scarb build` first.');
        process.exit(1);
    }

    const sierra = json.parse(readFileSync(sierraPath).toString());
    const casm = json.parse(readFileSync(casmPath).toString());

    let classHash;
    try {
        const declareResponse = await account.declare({ contract: sierra, casm });
        classHash = declareResponse.class_hash;
        console.log(`Declared: ${classHash}`);
        await provider.waitForTransaction(declareResponse.transaction_hash);
    } catch (e) {
        if (e.message?.includes('already declared') || e.message?.includes('CLASS_ALREADY_DECLARED')) {
            classHash = hash.computeContractClassHash(sierra);
            console.log(`Already declared: ${classHash}`);
        } else {
            throw e;
        }
    }

    // Deploy with deployer as owner
    const constructorCalldata = CallData.compile({
        owner: CONFIG.deployer.address,
        sage_address: EXISTING.SAGEToken,
        oracle_address: EXISTING.OracleWrapper,
        staker_rewards_pool: EXISTING.CDCPool,
        treasury_address: CONFIG.deployer.address,
    });

    const deployResponse = await account.deployContract({
        classHash,
        constructorCalldata,
    });

    console.log(`Deploy TX: ${deployResponse.transaction_hash}`);
    await provider.waitForTransaction(deployResponse.transaction_hash);
    console.log(`\nPaymentRouter deployed at: ${deployResponse.contract_address}`);
    console.log(`Class hash: ${classHash}`);
    console.log(`Owner: ${CONFIG.deployer.address}`);

    // Now call set_authorized_submitter to allow deployer to submit jobs
    console.log('\nSetting authorized submitter to deployer...');
    const setSubmitterTx = await account.execute({
        contractAddress: deployResponse.contract_address,
        entrypoint: 'set_authorized_submitter',
        calldata: CallData.compile({ submitter: CONFIG.deployer.address }),
    });
    console.log(`set_authorized_submitter TX: ${setSubmitterTx.transaction_hash}`);
    await provider.waitForTransaction(setSubmitterTx.transaction_hash);
    console.log('Authorized submitter set!');

    // Update deployed_addresses_sepolia.json
    const addrFile = join(ROOT_DIR, 'deployment/deployed_addresses_sepolia.json');
    const addresses = JSON.parse(readFileSync(addrFile, 'utf8'));
    addresses.contracts.PaymentRouter = {
        class_hash: classHash,
        address: deployResponse.contract_address,
    };
    writeFileSync(addrFile, JSON.stringify(addresses, null, 2) + '\n');
    console.log('\nUpdated deployed_addresses_sepolia.json');

    console.log('\n=== DONE ===');
    console.log(`Update network.rs PAYMENT_ROUTER address to: ${deployResponse.contract_address}`);
    console.log('Then rebuild and redeploy the coordinator/worker.');
}

main().catch(e => {
    console.error('FAILED:', e);
    process.exit(1);
});
