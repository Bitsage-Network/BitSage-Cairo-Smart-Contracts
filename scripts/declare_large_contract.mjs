#!/usr/bin/env node
/**
 * Declare Large Contract Script
 *
 * Handles declaration of large contracts (>2MB) that may timeout on public RPCs.
 * Uses multiple RPC providers with fallback and increased timeouts.
 */

import { Account, RpcProvider, json, CallData, hash } from 'starknet';
import fs from 'fs';

const DEPLOYER_ADDRESS = '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY;

// RPC providers to try (in order)
const RPC_PROVIDERS = [
  // Alchemy Core RPC v0.10 - higher limits
  'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/${process.env.ALCHEMY_API_KEY}',
];

async function declareWithProvider(rpcUrl, sierra, casm) {
  console.log(`\nTrying RPC: ${rpcUrl}`);

  const provider = new RpcProvider({
    nodeUrl: rpcUrl,
    default_timeout: 300000, // 5 minutes
  });

  const account = new Account({
    provider,
    address: DEPLOYER_ADDRESS,
    signer: DEPLOYER_PRIVATE_KEY,
    cairoVersion: '1',
  });

  // Compute class hash
  const classHash = hash.computeContractClassHash(sierra);
  console.log(`Class hash: ${classHash}`);

  // Check if already declared
  try {
    const existingClass = await account.getClassByHash(classHash);
    if (existingClass) {
      console.log('Class already declared!');
      return { classHash, alreadyDeclared: true };
    }
  } catch (e) {
    // Class not found, proceed with declaration
  }

  console.log('Declaring contract (this may take a few minutes)...');

  const declareResponse = await account.declare({
    contract: sierra,
    casm: casm,
  });

  console.log(`Declaration tx: ${declareResponse.transaction_hash}`);

  // Wait for transaction with extended timeout
  console.log('Waiting for transaction confirmation...');
  await account.waitForTransaction(declareResponse.transaction_hash, {
    retryInterval: 10000,
    successStates: ['ACCEPTED_ON_L2', 'ACCEPTED_ON_L1'],
  });

  console.log(`Declared class hash: ${declareResponse.class_hash}`);
  return { classHash: declareResponse.class_hash, txHash: declareResponse.transaction_hash };
}

async function main() {
  const contractName = process.argv[2] || 'SAGEToken';

  console.log('='.repeat(60));
  console.log(`Declaring Large Contract: ${contractName}`);
  console.log('='.repeat(60));

  const sierraPath = `target/dev/sage_contracts_${contractName}.contract_class.json`;
  const casmPath = `target/dev/sage_contracts_${contractName}.compiled_contract_class.json`;

  if (!fs.existsSync(sierraPath)) {
    console.error(`Sierra file not found: ${sierraPath}`);
    console.error('Run "scarb build" first');
    process.exit(1);
  }

  console.log(`Sierra: ${sierraPath} (${(fs.statSync(sierraPath).size / 1024 / 1024).toFixed(2)} MB)`);
  console.log(`CASM: ${casmPath} (${(fs.statSync(casmPath).size / 1024 / 1024).toFixed(2)} MB)`);

  const sierra = JSON.parse(fs.readFileSync(sierraPath, 'utf8'));
  const casm = JSON.parse(fs.readFileSync(casmPath, 'utf8'));

  let lastError = null;

  for (const rpcUrl of RPC_PROVIDERS) {
    try {
      const result = await declareWithProvider(rpcUrl, sierra, casm);
      console.log('\n' + '='.repeat(60));
      console.log('SUCCESS!');
      console.log(`Class Hash: ${result.classHash}`);
      if (result.txHash) {
        console.log(`Transaction: ${result.txHash}`);
      }
      return;
    } catch (e) {
      lastError = e;
      console.error(`Failed with ${rpcUrl}: ${e.message}`);
    }
  }

  console.error('\n' + '='.repeat(60));
  console.error('All RPC providers failed');
  console.error(`Last error: ${lastError?.message}`);
  process.exit(1);
}

main().catch(console.error);
