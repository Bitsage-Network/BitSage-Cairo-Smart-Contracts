#!/usr/bin/env node
/**
 * Set 5-minute upgrade delays on all contracts
 *
 * Prerequisites:
 * - All contracts must be upgraded to new versions that allow 5-min delays
 * - No pending upgrades on any contract
 */

import { RpcProvider, Account, CallData, ETransactionVersion } from 'starknet';

const RPC_URL = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/${process.env.ALCHEMY_API_KEY}';
const DEPLOYER_ADDRESS = '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PK = process.env.DEPLOYER_PRIVATE_KEY;

const FIVE_MINUTES = 300;

const CONTRACTS = [
  {
    name: 'SAGEToken',
    address: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
  },
  {
    name: 'StwoVerifier',
    address: '0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d',
  },
  {
    name: 'WorkerStaking',
    address: '0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613',
  },
  // OTCOrderbook already has 5-min delay
];

async function main() {
  console.log('=== Set 5-Minute Upgrade Delays ===\n');

  const provider = new RpcProvider({ nodeUrl: RPC_URL });
  const account = new Account({
    provider,
    address: DEPLOYER_ADDRESS,
    signer: DEPLOYER_PK,
    cairoVersion: '1',
    transactionVersion: ETransactionVersion.V3,
  });

  for (const contract of CONTRACTS) {
    console.log('\n--- ' + contract.name + ' ---');
    console.log('Address:', contract.address);

    try {
      // Check current status
      const info = await provider.callContract({
        contractAddress: contract.address,
        entrypoint: 'get_upgrade_info',
        calldata: [],
      });

      const pendingClass = info[0];
      let currentDelay;

      // Handle different return formats (3 or 4 elements)
      if (info.length >= 4) {
        currentDelay = Number(BigInt(info[3]));
      } else {
        currentDelay = Number(BigInt(info[2]));
      }

      console.log('Current delay:', currentDelay + 's (' + (currentDelay/60) + ' min)');

      // Check for pending upgrade
      if (pendingClass !== '0x0' && pendingClass !== '0') {
        console.log('WARNING: Pending upgrade exists - cannot change delay');
        console.log('Pending class:', pendingClass);
        continue;
      }

      // Skip if already 5 minutes
      if (currentDelay === FIVE_MINUTES) {
        console.log('Already set to 5 minutes - skipping');
        continue;
      }

      // Set new delay
      console.log('Setting delay to 5 minutes...');
      const { transaction_hash } = await account.execute({
        contractAddress: contract.address,
        entrypoint: 'set_upgrade_delay',
        calldata: CallData.compile({ delay: FIVE_MINUTES }),
      });

      console.log('TX Hash:', transaction_hash);
      console.log('Waiting for confirmation...');

      const receipt = await provider.waitForTransaction(transaction_hash, {
        retryInterval: 5000,
      });

      if (receipt.execution_status === 'SUCCEEDED') {
        console.log('SUCCESS: Delay set to 5 minutes');
      } else {
        console.log('FAILED:', receipt.execution_status);
      }

    } catch (e) {
      console.log('Error:', e.message.substring(0, 150));
    }
  }

  console.log('\n\n=== Final Status ===');
  for (const contract of CONTRACTS) {
    try {
      const info = await provider.callContract({
        contractAddress: contract.address,
        entrypoint: 'get_upgrade_info',
        calldata: [],
      });
      const delay = info.length >= 4 ? Number(BigInt(info[3])) : Number(BigInt(info[2]));
      console.log(contract.name + ': ' + delay + 's (' + (delay/60) + ' min)');
    } catch (e) {
      console.log(contract.name + ': Error reading');
    }
  }
}

main().catch(console.error);
