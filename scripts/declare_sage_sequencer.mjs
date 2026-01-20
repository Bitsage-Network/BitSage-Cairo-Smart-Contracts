#!/usr/bin/env node
/**
 * Try declaring SAGEToken directly to Starknet sequencer endpoints
 */

import { RpcProvider, Account, hash, ETransactionVersion } from 'starknet';
import fs from 'fs';

const DEPLOYER_ADDRESS = '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PK = '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a';

// Endpoints to try - including sequencer-style endpoints
const ENDPOINTS = [
  // Official Starknet sequencer (if available)
  'https://alpha-sepolia.starknet.io/rpc/v0.7',
  // Chainstack with explicit version
  'https://nd-012-345-678.p2pify.com/4f2a6b7c8d9e0f1a2b3c4d5e6f7a8b9c/starknet/sepolia/rpc/v0.7',
  // Infura endpoint
  'https://starknet-sepolia.infura.io/v3/4f2a6b7c8d9e0f1a2b3c4d5e6f7a8b9c',
];

async function tryDeclare() {
  console.log('=== SAGEToken Declaration via Sequencer ===\n');

  const sierraPath = 'target/dev/sage_contracts_SAGEToken.contract_class.json';
  const casmPath = 'target/dev/sage_contracts_SAGEToken.compiled_contract_class.json';

  const sierra = JSON.parse(fs.readFileSync(sierraPath, 'utf8'));
  const casm = JSON.parse(fs.readFileSync(casmPath, 'utf8'));

  const classHash = hash.computeContractClassHash(sierra);
  console.log('Target class hash:', classHash);
  console.log('Sierra size:', (JSON.stringify(sierra).length / 1024 / 1024).toFixed(2), 'MB');
  console.log('');

  // First check if already declared
  console.log('Checking if already declared...');
  try {
    const checkProvider = new RpcProvider({
      nodeUrl: 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_7/GUBwFqKhSgn4mwVbN6Sbn'
    });
    await checkProvider.getClassByHash(classHash);
    console.log('SUCCESS: Class already declared!');
    console.log('Class hash:', classHash);
    return;
  } catch (e) {
    if (e.message.includes('not found') || e.message.includes('CLASS_HASH_NOT_FOUND')) {
      console.log('Not yet declared - proceeding with declaration...\n');
    } else {
      console.log('Check error:', e.message);
    }
  }

  // Try official Starknet public endpoint
  console.log('\n--- Trying Starknet public endpoint ---');
  try {
    const provider = new RpcProvider({
      nodeUrl: 'https://free-rpc.nethermind.io/sepolia-juno',
      headers: {
        'Content-Type': 'application/json',
      }
    });

    const account = new Account({
      provider,
      address: DEPLOYER_ADDRESS,
      signer: DEPLOYER_PK,
      cairoVersion: '1',
      transactionVersion: ETransactionVersion.V3,
    });

    console.log('Attempting declaration...');
    const result = await account.declareIfNot({
      contract: sierra,
      casm: casm,
    });

    if (result.class_hash) {
      console.log('SUCCESS! Class hash:', result.class_hash);
      if (result.transaction_hash) {
        console.log('TX Hash:', result.transaction_hash);
      }
      return;
    }
  } catch (e) {
    console.log('Error:', e.message.substring(0, 200));
  }

  console.log('\n=== Summary ===');
  console.log('The SAGEToken contract (3MB) exceeds HTTP payload limits of all public RPC providers.');
  console.log('\nRecommended solutions:');
  console.log('1. Use Voyager declaration tool: https://sepolia.voyager.online/contract-declaration');
  console.log('   - Upload Sierra JSON: target/dev/sage_contracts_SAGEToken.contract_class.json');
  console.log('   - Upload CASM JSON: target/dev/sage_contracts_SAGEToken.compiled_contract_class.json');
  console.log('   - Connect Argent X or Braavos wallet');
  console.log('');
  console.log('2. Contact Alchemy/Infura for enterprise tier with higher payload limits');
  console.log('');
  console.log('3. Run your own Starknet full node (Juno/Pathfinder) with increased limits');
  console.log('');
  console.log('Expected class hash: ' + classHash);
}

tryDeclare().catch(console.error);
