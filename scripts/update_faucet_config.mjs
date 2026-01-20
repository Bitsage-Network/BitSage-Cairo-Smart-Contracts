#!/usr/bin/env node
/**
 * Update Faucet Configuration
 * Increases drip amount from 0.02 SAGE to 20 SAGE for testnet
 */

import { Account, RpcProvider, CallData, cairo } from 'starknet';

const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
    },
    faucet: '0x62d3231450645503345e2e022b60a96aceff73898d26668f3389547a61471d3',
};

// New faucet configuration
const NEW_CONFIG = {
    drip_amount: 20n * 10n ** 18n,  // 20 SAGE (was 0.02 SAGE)
    cooldown_secs: 3600n,            // 1 hour (was 24 hours) - for easier testing
    max_claims_per_address: 0n,      // Unlimited
    is_active: true,
};

function log(msg, type = 'info') {
    const colors = {
        info: '\x1b[36m', success: '\x1b[32m', error: '\x1b[31m', warn: '\x1b[33m', reset: '\x1b[0m',
    };
    const prefix = { info: '[INFO]', success: '[OK]', error: '[ERR]', warn: '[WARN]' };
    console.log(`${colors[type]}${prefix[type]} ${msg}${colors.reset}`);
}

async function main() {
    log('=== Updating Faucet Configuration ===', 'info');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
    const account = new Account({
        provider,
        address: CONFIG.deployer.address,
        signer: CONFIG.deployer.privateKey,
        cairoVersion: '1',
    });

    // Get current config
    log('\nCurrent configuration:', 'info');
    const currentConfig = await provider.callContract({
        contractAddress: CONFIG.faucet,
        entrypoint: 'get_config',
        calldata: [],
    });

    const currentDrip = BigInt(currentConfig[0]) + (BigInt(currentConfig[1] || 0) << 128n);
    const currentCooldown = BigInt(currentConfig[2]);
    log(`  Drip amount: ${(currentDrip / 10n**18n).toString()} SAGE`, 'info');
    log(`  Cooldown: ${currentCooldown} seconds (${Number(currentCooldown) / 3600} hours)`, 'info');

    // New config
    log('\nNew configuration:', 'info');
    log(`  Drip amount: ${(NEW_CONFIG.drip_amount / 10n**18n).toString()} SAGE`, 'info');
    log(`  Cooldown: ${NEW_CONFIG.cooldown_secs} seconds (${Number(NEW_CONFIG.cooldown_secs) / 3600} hours)`, 'info');

    // Build calldata for FaucetConfig struct
    // FaucetConfig { drip_amount: u256, cooldown_secs: u64, max_claims_per_address: u64, is_active: bool }
    const dripLow = NEW_CONFIG.drip_amount & ((1n << 128n) - 1n);
    const dripHigh = NEW_CONFIG.drip_amount >> 128n;

    const calldata = CallData.compile({
        config: {
            drip_amount: cairo.uint256(NEW_CONFIG.drip_amount),
            cooldown_secs: NEW_CONFIG.cooldown_secs,
            max_claims_per_address: NEW_CONFIG.max_claims_per_address,
            is_active: NEW_CONFIG.is_active,
        }
    });

    log('\nUpdating configuration...', 'info');

    try {
        const { transaction_hash } = await account.execute({
            contractAddress: CONFIG.faucet,
            entrypoint: 'update_config',
            calldata,
        });
        log(`Transaction: ${transaction_hash}`, 'info');
        await provider.waitForTransaction(transaction_hash);
        log('Configuration updated!', 'success');

        // Verify new config
        const newConfig = await provider.callContract({
            contractAddress: CONFIG.faucet,
            entrypoint: 'get_config',
            calldata: [],
        });

        const newDrip = BigInt(newConfig[0]) + (BigInt(newConfig[1] || 0) << 128n);
        const newCooldown = BigInt(newConfig[2]);

        log('\nVerified new configuration:', 'success');
        log(`  Drip amount: ${(newDrip / 10n**18n).toString()} SAGE`, 'success');
        log(`  Cooldown: ${newCooldown} seconds (${Number(newCooldown) / 3600} hours)`, 'success');

        log(`\nExplorer: https://sepolia.starkscan.co/tx/${transaction_hash}`, 'info');

    } catch (e) {
        log(`Failed to update config: ${e.message}`, 'error');
        console.error(e);
    }
}

main().catch(console.error);
