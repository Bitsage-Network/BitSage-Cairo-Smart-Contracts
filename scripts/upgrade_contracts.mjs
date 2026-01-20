#!/usr/bin/env node
/**
 * BitSage Network - Contract Upgrade Script
 *
 * Upgrades deployed contracts with Cairo 2.12.0 fixes:
 * - SAGEToken: match statement → if-else chain
 * - StwoVerifier: match statement → if-else chain
 * - WorkerStaking: StakeInfo field visibility
 *
 * Usage:
 *   node scripts/upgrade_contracts.mjs [--schedule|--execute|--status]
 *
 * The upgrade process has 2 phases:
 *   1. schedule: Declare new class and schedule upgrade (starts 48h timelock)
 *   2. execute: Execute the upgrade after timelock expires
 */

import { Account, RpcProvider, Contract, json, CallData, hash } from 'starknet';
import fs from 'fs';
import path from 'path';

// Configuration
// Using Alchemy RPC (note: SAGEToken requires higher limits due to ~5MB contract size)
const CONFIG = {
  rpcUrl: process.env.STARKNET_RPC_URL || 'https://starknet-sepolia.g.alchemy.com/v2/GUBwFqKhSgn4mwVbN6Sbn',
  deployerAddress: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
  deployerPrivateKey: '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a',
};

// Contracts to upgrade with their deployed addresses
const CONTRACTS_TO_UPGRADE = {
  SAGEToken: {
    address: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
    sierraPath: 'target/dev/sage_contracts_SAGEToken.contract_class.json',
    casmPath: 'target/dev/sage_contracts_SAGEToken.compiled_contract_class.json',
    reason: 'Fixed match statement for Cairo 2.12.0 compatibility (year emission rates)',
  },
  StwoVerifier: {
    address: '0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d',
    sierraPath: 'target/dev/sage_contracts_StwoVerifier.contract_class.json',
    casmPath: 'target/dev/sage_contracts_StwoVerifier.compiled_contract_class.json',
    reason: 'Fixed match statement for Cairo 2.12.0 compatibility (fraud type handling)',
  },
  WorkerStaking: {
    address: '0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613',
    sierraPath: 'target/dev/sage_contracts_WorkerStaking.contract_class.json',
    casmPath: 'target/dev/sage_contracts_WorkerStaking.compiled_contract_class.json',
    reason: 'Made StakeInfo struct fields public for cross-contract access (FraudProof integration)',
  },
};

// Upgrade status tracking
const STATUS_FILE = 'deployment/upgrade_status.json';

async function loadStatus() {
  try {
    if (fs.existsSync(STATUS_FILE)) {
      return JSON.parse(fs.readFileSync(STATUS_FILE, 'utf8'));
    }
  } catch (e) {
    console.log('No existing upgrade status found, starting fresh');
  }
  return { scheduled: {}, executed: {} };
}

async function saveStatus(status) {
  fs.writeFileSync(STATUS_FILE, JSON.stringify(status, null, 2));
}

async function declareContract(account, sierraPath, casmPath) {
  console.log(`  Declaring contract from ${sierraPath}...`);

  const sierra = JSON.parse(fs.readFileSync(sierraPath, 'utf8'));
  const casm = JSON.parse(fs.readFileSync(casmPath, 'utf8'));

  // Check if already declared
  const classHash = hash.computeContractClassHash(sierra);
  console.log(`  Computed class hash: ${classHash}`);

  try {
    const existingClass = await account.getClassByHash(classHash);
    if (existingClass) {
      console.log(`  Class already declared, skipping declaration`);
      return classHash;
    }
  } catch (e) {
    // Class not found, need to declare
  }

  const declareResponse = await account.declare({
    contract: sierra,
    casm: casm,
  });

  console.log(`  Declaration tx: ${declareResponse.transaction_hash}`);
  await account.waitForTransaction(declareResponse.transaction_hash);
  console.log(`  Declared class hash: ${declareResponse.class_hash}`);

  return declareResponse.class_hash;
}

async function scheduleUpgrade(account, contractAddress, newClassHash, contractName) {
  console.log(`  Scheduling upgrade for ${contractName}...`);
  console.log(`    Contract: ${contractAddress}`);
  console.log(`    New class: ${newClassHash}`);

  // Call schedule_upgrade on the contract
  const { transaction_hash } = await account.execute({
    contractAddress: contractAddress,
    entrypoint: 'schedule_upgrade',
    calldata: CallData.compile({ new_class_hash: newClassHash }),
  });

  console.log(`  Schedule tx: ${transaction_hash}`);
  await account.waitForTransaction(transaction_hash);
  console.log(`  Upgrade scheduled! Timelock started (48 hours)`);

  return transaction_hash;
}

async function executeUpgrade(account, contractAddress, contractName) {
  console.log(`  Executing upgrade for ${contractName}...`);
  console.log(`    Contract: ${contractAddress}`);

  // Call execute_upgrade on the contract
  const { transaction_hash } = await account.execute({
    contractAddress: contractAddress,
    entrypoint: 'execute_upgrade',
    calldata: [],
  });

  console.log(`  Execute tx: ${transaction_hash}`);
  await account.waitForTransaction(transaction_hash);
  console.log(`  Upgrade executed successfully!`);

  return transaction_hash;
}

async function getUpgradeStatus(provider, contractAddress) {
  try {
    // Read pending_upgrade and upgrade_delay from contract storage
    const pendingUpgrade = await provider.callContract({
      contractAddress: contractAddress,
      entrypoint: 'get_pending_upgrade',
      calldata: [],
    });

    return {
      pending: pendingUpgrade.result[0] !== '0x0',
      classHash: pendingUpgrade.result[0],
    };
  } catch (e) {
    // Fallback: try reading storage directly
    return { pending: false, classHash: null };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const action = args[0] || '--status';

  console.log('='.repeat(60));
  console.log('BitSage Network - Contract Upgrade Tool');
  console.log('='.repeat(60));
  console.log(`Action: ${action}`);
  console.log(`Network: Starknet Sepolia`);
  console.log(`Deployer: ${CONFIG.deployerAddress}`);
  console.log('');

  // Initialize provider and account (starknet.js v9 uses options object)
  const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });
  const account = new Account({
    provider,
    address: CONFIG.deployerAddress,
    signer: CONFIG.deployerPrivateKey,
    cairoVersion: '1',
  });

  // Load status
  const status = await loadStatus();

  if (action === '--status') {
    console.log('Upgrade Status:');
    console.log('-'.repeat(40));

    for (const [name, config] of Object.entries(CONTRACTS_TO_UPGRADE)) {
      console.log(`\n${name}:`);
      console.log(`  Address: ${config.address}`);
      console.log(`  Reason: ${config.reason}`);

      if (status.scheduled[name]) {
        const scheduled = status.scheduled[name];
        console.log(`  Scheduled: ${new Date(scheduled.timestamp).toISOString()}`);
        console.log(`  New Class: ${scheduled.classHash}`);
        console.log(`  Schedule Tx: ${scheduled.txHash}`);

        const timelock = 48 * 60 * 60 * 1000; // 48 hours in ms
        const unlockTime = new Date(scheduled.timestamp + timelock);
        const now = new Date();

        if (now >= unlockTime) {
          console.log(`  Status: READY TO EXECUTE`);
        } else {
          const remaining = Math.ceil((unlockTime - now) / (1000 * 60 * 60));
          console.log(`  Status: Timelock active (${remaining}h remaining)`);
        }
      } else if (status.executed[name]) {
        console.log(`  Status: UPGRADED`);
        console.log(`  Execute Tx: ${status.executed[name].txHash}`);
      } else {
        console.log(`  Status: Not scheduled`);
      }
    }

  } else if (action === '--schedule') {
    console.log('Scheduling upgrades...\n');

    for (const [name, config] of Object.entries(CONTRACTS_TO_UPGRADE)) {
      if (status.scheduled[name] || status.executed[name]) {
        console.log(`\n${name}: Already scheduled or executed, skipping`);
        continue;
      }

      console.log(`\n${name}:`);
      console.log(`  ${config.reason}`);

      try {
        // Check if compiled files exist
        if (!fs.existsSync(config.sierraPath)) {
          console.log(`  ERROR: Sierra file not found: ${config.sierraPath}`);
          console.log(`  Run 'scarb build' first`);
          continue;
        }

        // Declare new class
        const classHash = await declareContract(account, config.sierraPath, config.casmPath);

        // Schedule upgrade
        const txHash = await scheduleUpgrade(account, config.address, classHash, name);

        // Save status
        status.scheduled[name] = {
          classHash,
          txHash,
          timestamp: Date.now(),
        };
        await saveStatus(status);

      } catch (e) {
        console.log(`  ERROR: ${e.message}`);
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log('Upgrades scheduled. Run --status to check timelock progress.');
    console.log('After 48 hours, run --execute to complete the upgrades.');

  } else if (action === '--execute') {
    console.log('Executing upgrades...\n');

    for (const [name, config] of Object.entries(CONTRACTS_TO_UPGRADE)) {
      if (status.executed[name]) {
        console.log(`\n${name}: Already executed, skipping`);
        continue;
      }

      if (!status.scheduled[name]) {
        console.log(`\n${name}: Not scheduled, run --schedule first`);
        continue;
      }

      const scheduled = status.scheduled[name];
      const timelock = 48 * 60 * 60 * 1000; // 48 hours in ms
      const unlockTime = new Date(scheduled.timestamp + timelock);
      const now = new Date();

      if (now < unlockTime) {
        const remaining = Math.ceil((unlockTime - now) / (1000 * 60 * 60));
        console.log(`\n${name}: Timelock not expired (${remaining}h remaining)`);
        continue;
      }

      console.log(`\n${name}:`);

      try {
        const txHash = await executeUpgrade(account, config.address, name);

        status.executed[name] = {
          txHash,
          timestamp: Date.now(),
          classHash: scheduled.classHash,
        };
        delete status.scheduled[name];
        await saveStatus(status);

      } catch (e) {
        console.log(`  ERROR: ${e.message}`);
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log('Upgrades executed. Run --status to verify.');

  } else {
    console.log('Usage:');
    console.log('  node scripts/upgrade_contracts.mjs --status   # Check upgrade status');
    console.log('  node scripts/upgrade_contracts.mjs --schedule # Schedule upgrades (starts 48h timelock)');
    console.log('  node scripts/upgrade_contracts.mjs --execute  # Execute upgrades after timelock');
  }
}

main().catch(console.error);
