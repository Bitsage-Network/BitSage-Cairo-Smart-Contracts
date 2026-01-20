#!/usr/bin/env node
/**
 * Schedule SAGEToken upgrade after class declaration
 *
 * Prerequisites:
 * 1. SAGEToken class must be declared via Voyager
 * 2. Expected class hash: 0x16215c09e2b8f7df7d4977b26685b3c158e037c75bed77d549275eb8898ec7c
 */

import { RpcProvider, Account, CallData, ETransactionVersion } from 'starknet';

const RPC_URL = 'https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/GUBwFqKhSgn4mwVbN6Sbn';
const DEPLOYER_ADDRESS = '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344';
const DEPLOYER_PK = '0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a';

const SAGE_TOKEN = {
  address: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',
  newClassHash: '0x16215c09e2b8f7df7d4977b26685b3c158e037c75bed77d549275eb8898ec7c',
};

async function main() {
  console.log('=== SAGEToken Upgrade Scheduler ===\n');

  const provider = new RpcProvider({ nodeUrl: RPC_URL });
  const account = new Account({
    provider,
    address: DEPLOYER_ADDRESS,
    signer: DEPLOYER_PK,
    cairoVersion: '1',
    transactionVersion: ETransactionVersion.V3,
  });

  // First verify the class is declared
  console.log('1. Verifying class is declared...');
  try {
    await provider.getClassByHash(SAGE_TOKEN.newClassHash);
    console.log('   Class hash verified!');
  } catch (e) {
    console.log('   ERROR: Class not declared yet!');
    console.log('   Please declare via Voyager first:');
    console.log('   https://sepolia.voyager.online/contract-declaration');
    console.log('   Expected class hash:', SAGE_TOKEN.newClassHash);
    process.exit(1);
  }

  // Check current upgrade info
  console.log('\n2. Checking current upgrade status...');
  const info = await provider.callContract({
    contractAddress: SAGE_TOKEN.address,
    entrypoint: 'get_upgrade_info',
    calldata: [],
  });

  const pendingClass = info[0];
  const delay = Number(BigInt(info[3]));
  console.log('   Current pending:', pendingClass);
  console.log('   Current delay:', delay, 'seconds (' + (delay/3600).toFixed(1) + 'h)');

  if (pendingClass !== '0x0' && pendingClass !== '0') {
    console.log('\n   WARNING: There is already a pending upgrade!');
    console.log('   Cancel it first or wait for execution.');
    process.exit(1);
  }

  // Schedule upgrade
  console.log('\n3. Scheduling upgrade...');
  console.log('   New class hash:', SAGE_TOKEN.newClassHash);

  const { transaction_hash } = await account.execute({
    contractAddress: SAGE_TOKEN.address,
    entrypoint: 'schedule_upgrade',
    calldata: CallData.compile({ new_class_hash: SAGE_TOKEN.newClassHash }),
  });

  console.log('   TX Hash:', transaction_hash);
  console.log('   Waiting for confirmation...');

  const receipt = await provider.waitForTransaction(transaction_hash, {
    retryInterval: 5000,
  });

  console.log('   Status:', receipt.execution_status);

  if (receipt.execution_status === 'SUCCEEDED') {
    console.log('\n=== SUCCESS ===');
    console.log('SAGEToken upgrade scheduled!');
    console.log('Execute after:', delay, 'seconds (' + (delay/3600).toFixed(1) + ' hours)');

    const executeTime = new Date(Date.now() + delay * 1000);
    console.log('Ready at:', executeTime.toISOString());
  }
}

main().catch(console.error);
