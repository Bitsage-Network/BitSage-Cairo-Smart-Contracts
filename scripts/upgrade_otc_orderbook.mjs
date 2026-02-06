#!/usr/bin/env node
/**
 * BitSage Network - OTC Orderbook Upgrade Script
 *
 * Upgrades OTC Orderbook contract with new trustless view functions:
 * - get_orderbook_depth: Aggregated price levels with amounts
 * - get_trade_history: Paginated trade history
 * - get_active_orders: Paginated active orders
 * - get_order_count / get_trade_count: Total counts
 *
 * Usage:
 *   node scripts/upgrade_otc_orderbook.mjs --set-delay    # Set 5 min delay first
 *   node scripts/upgrade_otc_orderbook.mjs --schedule     # Declare & schedule upgrade
 *   node scripts/upgrade_otc_orderbook.mjs --execute      # Execute after delay
 *   node scripts/upgrade_otc_orderbook.mjs --status       # Check status
 */

import { Account, RpcProvider, CallData, hash, ETransactionVersion } from 'starknet';
import fs from 'fs';

// Configuration
const CONFIG = {
  rpcUrl: 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/${process.env.ALCHEMY_API_KEY}',
  deployerAddress: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
  deployerPrivateKey: process.env.DEPLOYER_PRIVATE_KEY,
};

// OTC Orderbook contract
const OTC_ORDERBOOK = {
  address: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
  sierraPath: 'target/dev/sage_contracts_OTCOrderbook.contract_class.json',
  casmPath: 'target/dev/sage_contracts_OTCOrderbook.compiled_contract_class.json',
};

// 5 minutes in seconds
const UPGRADE_DELAY_5_MIN = 300;

const STATUS_FILE = 'deployment/otc_upgrade_status.json';

async function loadStatus() {
  try {
    if (fs.existsSync(STATUS_FILE)) {
      return JSON.parse(fs.readFileSync(STATUS_FILE, 'utf8'));
    }
  } catch (e) {
    console.log('No existing status found');
  }
  return { delaySet: false, scheduled: null, executed: null };
}

async function saveStatus(status) {
  const dir = 'deployment';
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(STATUS_FILE, JSON.stringify(status, null, 2));
}

async function setUpgradeDelay(account, provider) {
  console.log('\n=== Setting Upgrade Delay to 5 minutes ===');
  console.log('Contract:', OTC_ORDERBOOK.address);
  console.log('New delay:', UPGRADE_DELAY_5_MIN, 'seconds (5 minutes)');

  // First check current delay
  try {
    const result = await provider.callContract({
      contractAddress: OTC_ORDERBOOK.address,
      entrypoint: 'get_upgrade_info',
      calldata: [],
    });
    console.log('Current delay:', BigInt(result[3]).toString(), 'seconds');
  } catch (e) {
    console.log('Could not read current delay:', e.message);
  }

  // Set new delay
  const { transaction_hash } = await account.execute({
    contractAddress: OTC_ORDERBOOK.address,
    entrypoint: 'set_upgrade_delay',
    calldata: CallData.compile({ delay: UPGRADE_DELAY_5_MIN }),
  });

  console.log('TX:', transaction_hash);
  console.log('Waiting for confirmation...');
  await provider.waitForTransaction(transaction_hash);
  console.log('Upgrade delay set to 5 minutes!');

  return transaction_hash;
}

async function declareContract(account, provider) {
  console.log('\n=== Declaring New Contract Class ===');

  if (!fs.existsSync(OTC_ORDERBOOK.sierraPath)) {
    throw new Error('Sierra file not found: ' + OTC_ORDERBOOK.sierraPath + '\nRun "scarb build" first');
  }
  if (!fs.existsSync(OTC_ORDERBOOK.casmPath)) {
    throw new Error('CASM file not found: ' + OTC_ORDERBOOK.casmPath + '\nRun "scarb build" first');
  }

  const sierra = JSON.parse(fs.readFileSync(OTC_ORDERBOOK.sierraPath, 'utf8'));
  const casm = JSON.parse(fs.readFileSync(OTC_ORDERBOOK.casmPath, 'utf8'));

  // Compute class hash
  const classHash = hash.computeContractClassHash(sierra);
  console.log('Computed class hash:', classHash);

  // Check if already declared
  try {
    await provider.getClassByHash(classHash);
    console.log('Class already declared, skipping declaration');
    return classHash;
  } catch (e) {
    // Not declared yet
  }

  console.log('Declaring contract...');
  const declareResponse = await account.declare({
    contract: sierra,
    casm: casm,
  });

  console.log('Declaration TX:', declareResponse.transaction_hash);
  console.log('Waiting for confirmation...');
  await provider.waitForTransaction(declareResponse.transaction_hash);
  console.log('Declared class hash:', declareResponse.class_hash);

  return declareResponse.class_hash;
}

async function scheduleUpgrade(account, provider, classHash) {
  console.log('\n=== Scheduling Upgrade ===');
  console.log('Contract:', OTC_ORDERBOOK.address);
  console.log('New class:', classHash);

  const { transaction_hash } = await account.execute({
    contractAddress: OTC_ORDERBOOK.address,
    entrypoint: 'schedule_upgrade',
    calldata: CallData.compile({ new_class_hash: classHash }),
  });

  console.log('TX:', transaction_hash);
  console.log('Waiting for confirmation...');
  await provider.waitForTransaction(transaction_hash);
  console.log('Upgrade scheduled! 5-minute timelock started.');

  return transaction_hash;
}

async function executeUpgrade(account, provider) {
  console.log('\n=== Executing Upgrade ===');
  console.log('Contract:', OTC_ORDERBOOK.address);

  // Check if timelock expired
  const result = await provider.callContract({
    contractAddress: OTC_ORDERBOOK.address,
    entrypoint: 'get_upgrade_info',
    calldata: [],
  });

  const pendingHash = result[0];
  const scheduledAt = Number(BigInt(result[1]));
  const executeAfter = Number(BigInt(result[2]));
  const delay = Number(BigInt(result[3]));
  const now = Math.floor(Date.now() / 1000);

  console.log('Pending class:', pendingHash);
  console.log('Scheduled at:', new Date(scheduledAt * 1000).toISOString());
  console.log('Execute after:', new Date(executeAfter * 1000).toISOString());
  console.log('Current time:', new Date(now * 1000).toISOString());

  if (pendingHash === '0x0') {
    throw new Error('No pending upgrade');
  }

  if (now < executeAfter) {
    const remaining = executeAfter - now;
    throw new Error('Timelock not expired. ' + remaining + ' seconds remaining (' + Math.ceil(remaining/60) + ' minutes)');
  }

  const { transaction_hash } = await account.execute({
    contractAddress: OTC_ORDERBOOK.address,
    entrypoint: 'execute_upgrade',
    calldata: [],
  });

  console.log('TX:', transaction_hash);
  console.log('Waiting for confirmation...');
  await provider.waitForTransaction(transaction_hash);
  console.log('Upgrade executed successfully!');

  return transaction_hash;
}

async function checkStatus(provider) {
  console.log('\n=== OTC Orderbook Upgrade Status ===');
  console.log('Contract:', OTC_ORDERBOOK.address);

  try {
    const result = await provider.callContract({
      contractAddress: OTC_ORDERBOOK.address,
      entrypoint: 'get_upgrade_info',
      calldata: [],
    });

    const pendingHash = result[0];
    const scheduledAt = Number(BigInt(result[1]));
    const executeAfter = Number(BigInt(result[2]));
    const delay = Number(BigInt(result[3]));
    const now = Math.floor(Date.now() / 1000);

    console.log('\nUpgrade delay:', delay, 'seconds (' + Math.round(delay/60) + ' minutes)');
    console.log('Pending class hash:', pendingHash === '0x0' ? 'None' : pendingHash);

    if (pendingHash !== '0x0') {
      console.log('Scheduled at:', new Date(scheduledAt * 1000).toISOString());
      console.log('Execute after:', new Date(executeAfter * 1000).toISOString());

      if (now >= executeAfter) {
        console.log('\nStatus: READY TO EXECUTE');
      } else {
        const remaining = executeAfter - now;
        console.log('\nStatus: Timelock active');
        console.log('Time remaining:', remaining, 'seconds (' + Math.ceil(remaining/60) + ' minutes)');
      }
    } else {
      console.log('\nStatus: No pending upgrade');
    }
  } catch (e) {
    console.log('Error reading status:', e.message);
  }

  // Check local status file
  const status = await loadStatus();
  if (status.scheduled) {
    console.log('\nLocal status:');
    console.log('  Scheduled at:', new Date(status.scheduled.timestamp).toISOString());
    console.log('  Class hash:', status.scheduled.classHash);
  }
  if (status.executed) {
    console.log('\nUpgrade executed at:', new Date(status.executed.timestamp).toISOString());
  }
}

async function main() {
  const args = process.argv.slice(2);
  const action = args[0] || '--status';

  console.log('='.repeat(60));
  console.log('BitSage Network - OTC Orderbook Upgrade');
  console.log('='.repeat(60));
  console.log('Action:', action);
  console.log('Network: Starknet Sepolia');
  console.log('Deployer:', CONFIG.deployerAddress);

  const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

  // For status, no account needed
  if (action === '--status') {
    await checkStatus(provider);
    return;
  }

  // Create account for write operations
  const account = new Account({
    provider,
    address: CONFIG.deployerAddress,
    signer: CONFIG.deployerPrivateKey,
    cairoVersion: '1',
    transactionVersion: ETransactionVersion.V3,
  });

  const status = await loadStatus();

  try {
    if (action === '--set-delay') {
      const txHash = await setUpgradeDelay(account, provider);
      status.delaySet = true;
      status.delayTxHash = txHash;
      await saveStatus(status);
      console.log('\nDelay set! Now run --schedule to declare and schedule the upgrade.');

    } else if (action === '--schedule') {
      // Declare and schedule
      const classHash = await declareContract(account, provider);
      const txHash = await scheduleUpgrade(account, provider, classHash);

      status.scheduled = {
        classHash,
        txHash,
        timestamp: Date.now(),
      };
      await saveStatus(status);

      console.log('\n' + '='.repeat(60));
      console.log('Upgrade scheduled successfully!');
      console.log('Wait 5 minutes, then run --execute to complete the upgrade.');

    } else if (action === '--execute') {
      const txHash = await executeUpgrade(account, provider);

      status.executed = {
        txHash,
        timestamp: Date.now(),
        classHash: status.scheduled?.classHash,
      };
      status.scheduled = null;
      await saveStatus(status);

      console.log('\n' + '='.repeat(60));
      console.log('OTC Orderbook upgraded successfully!');
      console.log('The new trustless view functions are now available.');

    } else {
      console.log('\nUsage:');
      console.log('  node scripts/upgrade_otc_orderbook.mjs --set-delay  # Set 5 min timelock');
      console.log('  node scripts/upgrade_otc_orderbook.mjs --schedule   # Declare & schedule');
      console.log('  node scripts/upgrade_otc_orderbook.mjs --execute    # Execute upgrade');
      console.log('  node scripts/upgrade_otc_orderbook.mjs --status     # Check status');
    }
  } catch (e) {
    console.error('\nError:', e.message);
    if (e.data) {
      console.error('Details:', JSON.stringify(e.data, null, 2));
    }
    process.exit(1);
  }
}

main().catch(console.error);
