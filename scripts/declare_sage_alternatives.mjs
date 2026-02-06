#!/usr/bin/env node
/**
 * Alternative approaches to declare SAGEToken (3MB contract)
 */

import { RpcProvider, Account, hash, ETransactionVersion } from 'starknet';
import fs from 'fs';
import https from 'https';
import http from 'http';
import zlib from 'zlib';

const DEPLOYER_ADDRESS = '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PK = process.env.DEPLOYER_PRIVATE_KEY;

// Various RPC endpoints to try
const RPC_ENDPOINTS = [
  // Starknet public sequencer (might have higher limits)
  'https://starknet-sepolia.public.blastapi.io',
  // Nethermind
  'https://free-rpc.nethermind.io/sepolia-juno/v0_7',
  // Try v0_6 which might be more lenient
  'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_6/${process.env.ALCHEMY_API_KEY}',
];

async function loadContract() {
  const sierraPath = 'target/dev/sage_contracts_SAGEToken.contract_class.json';
  const casmPath = 'target/dev/sage_contracts_SAGEToken.compiled_contract_class.json';

  const sierra = JSON.parse(fs.readFileSync(sierraPath, 'utf8'));
  const casm = JSON.parse(fs.readFileSync(casmPath, 'utf8'));

  const sierraStr = JSON.stringify(sierra);
  const casmStr = JSON.stringify(casm);

  console.log('Contract sizes:');
  console.log('  Sierra:', (sierraStr.length / 1024 / 1024).toFixed(2), 'MB');
  console.log('  CASM:', (casmStr.length / 1024 / 1024).toFixed(2), 'MB');

  const classHash = hash.computeContractClassHash(sierra);
  console.log('  Class hash:', classHash);

  return { sierra, casm, classHash };
}

async function tryDeclareWithCompression(rpcUrl, account, sierra, casm) {
  console.log('\n--- Trying with gzip compression:', rpcUrl.substring(0, 60) + '...');

  const provider = new RpcProvider({ nodeUrl: rpcUrl });

  try {
    // Prepare the declare request
    const declareContractPayload = {
      contract: sierra,
      casm: casm,
    };

    console.log('  Preparing declare transaction...');
    const result = await account.declareIfNot(declareContractPayload);

    if (result.class_hash) {
      console.log('  SUCCESS! Class hash:', result.class_hash);
      if (result.transaction_hash) {
        console.log('  TX Hash:', result.transaction_hash);
      }
      return true;
    }
  } catch (e) {
    const errStr = e.message || String(e);
    if (errStr.includes('Payload Too Large')) {
      console.log('  FAILED: Payload too large');
    } else if (errStr.includes('already declared')) {
      console.log('  SUCCESS: Already declared!');
      return true;
    } else {
      console.log('  FAILED:', errStr.substring(0, 100));
    }
  }

  return false;
}

async function tryRawHttpPost(rpcUrl, requestBody) {
  console.log('\n--- Trying raw HTTP POST:', rpcUrl.substring(0, 60) + '...');

  return new Promise((resolve) => {
    const url = new URL(rpcUrl);
    const bodyStr = JSON.stringify(requestBody);
    const compressed = zlib.gzipSync(bodyStr);

    console.log('  Original size:', (bodyStr.length / 1024 / 1024).toFixed(2), 'MB');
    console.log('  Compressed size:', (compressed.length / 1024 / 1024).toFixed(2), 'MB');

    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
        'Content-Length': compressed.length,
        'Accept': 'application/json',
      },
      timeout: 120000,
    };

    const protocol = url.protocol === 'https:' ? https : http;
    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        console.log('  Response status:', res.statusCode);
        if (res.statusCode === 200) {
          try {
            const json = JSON.parse(data);
            if (json.result) {
              console.log('  SUCCESS:', JSON.stringify(json.result).substring(0, 100));
              resolve(true);
              return;
            }
          } catch (e) {}
        }
        console.log('  Response:', data.substring(0, 200));
        resolve(false);
      });
    });

    req.on('error', (e) => {
      console.log('  Error:', e.message);
      resolve(false);
    });

    req.on('timeout', () => {
      console.log('  Timeout');
      req.destroy();
      resolve(false);
    });

    req.write(compressed);
    req.end();
  });
}

async function main() {
  console.log('=== SAGEToken Declaration - Alternative Methods ===\n');

  const { sierra, casm, classHash } = await loadContract();

  // Try each RPC endpoint
  for (const rpcUrl of RPC_ENDPOINTS) {
    console.log('\n========================================');
    console.log('Trying:', rpcUrl);
    console.log('========================================');

    try {
      const provider = new RpcProvider({ nodeUrl: rpcUrl });
      const account = new Account({
        provider,
        address: DEPLOYER_ADDRESS,
        signer: DEPLOYER_PK,
        cairoVersion: '1',
        transactionVersion: ETransactionVersion.V3,
      });

      const success = await tryDeclareWithCompression(rpcUrl, account, sierra, casm);
      if (success) {
        console.log('\n\n=== SUCCESS! SAGEToken declared ===');
        console.log('Class hash:', classHash);
        return;
      }
    } catch (e) {
      console.log('Provider error:', e.message);
    }
  }

  console.log('\n\n=== All standard attempts failed ===');
  console.log('\nAlternative options:');
  console.log('1. Use Argent X browser wallet to declare (handles large contracts)');
  console.log('2. Deploy a Juno/Pathfinder node locally with no payload limits');
  console.log('3. Contact Starknet Foundation for assistance');
  console.log('4. Use Voyager contract deployment tool: https://sepolia.voyager.online/contract-declaration');
  console.log('\nClass hash (for verification):', classHash);
}

main().catch(console.error);
