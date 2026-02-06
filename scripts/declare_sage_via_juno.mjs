#!/usr/bin/env node
/**
 * Declare SAGEToken via local Juno node on EC2
 *
 * This script uses starknet.js 9.2.1 which computes the correct CASM hash:
 * 0x49ff6921e531423aa7c19eba1c1f1b5f6ea8c7637c369ffc1ff803862894bd0
 *
 * Juno endpoint: http://54.242.201.251:8545 (nginx proxy with 50MB limit)
 */

import { RpcProvider, Account, hash, ETransactionVersion } from 'starknet';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const JUNO_RPC = 'http://54.242.201.251:8545';
const DEPLOYER_ADDRESS = '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PK = process.env.DEPLOYER_PRIVATE_KEY;

// Expected hashes
const EXPECTED_CLASS_HASH = '0x16215c09e2b8f7df7d4977b26685b3c158e037c75bed77d549275eb8898ec7c';
const EXPECTED_CASM_HASH = '0x49ff6921e531423aa7c19eba1c1f1b5f6ea8c7637c369ffc1ff803862894bd0';

async function main() {
  console.log('=== SAGEToken Declaration via Local Juno ===\n');
  console.log('Juno RPC:', JUNO_RPC);
  console.log('Deployer:', DEPLOYER_ADDRESS);
  console.log('');

  // Load contract files
  const sierraPath = path.join(__dirname, '../target/dev/sage_contracts_SAGEToken.contract_class.json');
  const casmPath = path.join(__dirname, '../target/dev/sage_contracts_SAGEToken.compiled_contract_class.json');

  console.log('Loading contract files...');
  const sierra = JSON.parse(fs.readFileSync(sierraPath, 'utf8'));
  const casm = JSON.parse(fs.readFileSync(casmPath, 'utf8'));

  console.log('Sierra size:', (JSON.stringify(sierra).length / 1024 / 1024).toFixed(2), 'MB');
  console.log('CASM size:', (JSON.stringify(casm).length / 1024 / 1024).toFixed(2), 'MB');
  console.log('');

  // Compute and verify hashes
  console.log('Computing hashes with starknet.js...');
  const computedClassHash = hash.computeContractClassHash(sierra);
  const computedCasmHash = hash.computeCompiledClassHash(casm);

  console.log('Computed Sierra hash:', computedClassHash);
  console.log('Expected Sierra hash:', EXPECTED_CLASS_HASH);
  console.log('Match:', computedClassHash.toLowerCase() === EXPECTED_CLASS_HASH.toLowerCase() ? '✓' : '✗');
  console.log('');
  console.log('Computed CASM hash:', computedCasmHash);
  console.log('Expected CASM hash:', EXPECTED_CASM_HASH);
  console.log('Match:', computedCasmHash.toLowerCase() === EXPECTED_CASM_HASH.toLowerCase() ? '✓' : '✗');
  console.log('');

  // Create provider and account
  console.log('Connecting to Juno...');
  const provider = new RpcProvider({
    nodeUrl: JUNO_RPC,
    headers: {
      'Content-Type': 'application/json',
    }
  });

  // Check Juno sync status
  console.log('Checking Juno sync status...');
  try {
    const blockNumber = await provider.getBlockNumber();
    console.log('Juno block:', blockNumber);
  } catch (e) {
    console.log('Warning: Could not get block number:', e.message);
  }

  // Check if already declared
  console.log('\nChecking if class already declared...');
  try {
    await provider.getClassByHash(computedClassHash);
    console.log('SUCCESS: Class is already declared!');
    console.log('Class hash:', computedClassHash);
    return;
  } catch (e) {
    if (e.message.includes('not found') || e.message.includes('CLASS_HASH_NOT_FOUND')) {
      console.log('Class not yet declared - proceeding with declaration...');
    } else {
      console.log('Error checking class:', e.message.substring(0, 100));
    }
  }

  // Create account
  const account = new Account(
    provider,
    DEPLOYER_ADDRESS,
    DEPLOYER_PK,
    '1',  // Cairo version
    ETransactionVersion.V3
  );

  // Check account balance
  console.log('\nChecking account nonce...');
  try {
    const nonce = await account.getNonce();
    console.log('Account nonce:', nonce);
  } catch (e) {
    console.log('Warning: Could not get nonce:', e.message.substring(0, 100));
  }

  // Declare contract
  console.log('\n=== Declaring SAGEToken ===');
  console.log('This may take a while due to the large contract size...');

  try {
    const declareResponse = await account.declare({
      contract: sierra,
      casm: casm,
    });

    console.log('\nDeclare transaction submitted!');
    console.log('Class hash:', declareResponse.class_hash);
    console.log('TX hash:', declareResponse.transaction_hash);

    // Wait for transaction
    console.log('\nWaiting for transaction confirmation...');
    const receipt = await provider.waitForTransaction(declareResponse.transaction_hash, {
      retryInterval: 5000,
    });

    console.log('Status:', receipt.execution_status);

    if (receipt.execution_status === 'SUCCEEDED') {
      console.log('\n=== SUCCESS ===');
      console.log('SAGEToken class declared!');
      console.log('Class hash:', declareResponse.class_hash);
      console.log('');
      console.log('Next step: Run scripts/schedule_sage_upgrade.mjs');
    } else {
      console.log('\n=== FAILED ===');
      console.log('Execution status:', receipt.execution_status);
      if (receipt.revert_reason) {
        console.log('Revert reason:', receipt.revert_reason);
      }
    }

  } catch (e) {
    console.log('\nError during declaration:', e.message);

    // Check for specific errors
    if (e.message.includes('CLASS_ALREADY_DECLARED')) {
      console.log('\nThe class is already declared - this is fine!');
      console.log('Class hash:', computedClassHash);
    } else if (e.message.includes('StarknetErrorCode.UNDECLARED_CLASS')) {
      console.log('\nThe Juno node may not be fully synced yet.');
      console.log('Check sync status: docker logs juno-setup-juno-1 --tail 20');
    } else if (e.message.includes('Invalid transaction nonce')) {
      console.log('\nNonce mismatch - the node may be behind the chain.');
    } else {
      console.log('\nFull error:', e.message.substring(0, 500));
    }
  }
}

main().catch(console.error);
