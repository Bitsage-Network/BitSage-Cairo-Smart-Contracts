/**
 * ConfidentialTransfer Contract Verification & Testing
 *
 * Tests the deployed ConfidentialTransfer contract on Sepolia:
 * 1. Contract accessibility check
 * 2. Asset configuration verification
 * 3. Registration flow test
 * 4. Balance queries
 */

import { RpcProvider, Contract, Account, CallData, shortString, stark } from "starknet";
import * as fs from "fs";

// Configuration
const CONFIG = {
  rpcUrl: "https://rpc.starknet-testnet.lava.build",
  deployerAddress: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344",
  deployerPrivateKey: "0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a",
  confidentialTransferAddress: "0x626df6abac7e4c2140d8a2e2024503431a5492526adda96f78c1b623a855b",
  assets: {
    SAGE: {
      id: "0x53414745", // 'SAGE' in felt
      address: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850",
    },
    STRK: {
      id: "0x5354524b", // 'STRK' in felt
      address: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
    },
    USDC: {
      id: "0x55534443", // 'USDC' in felt
      address: "0x053b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080",
    },
  },
};

// ConfidentialTransfer ABI (minimal for testing)
const CONFIDENTIAL_TRANSFER_ABI = [
  {
    type: "function",
    name: "get_supported_asset",
    inputs: [{ name: "asset_id", type: "felt252" }],
    outputs: [{ name: "address", type: "core::starknet::contract_address::ContractAddress" }],
    state_mutability: "view",
  },
  {
    type: "function",
    name: "get_public_key",
    inputs: [{ name: "user", type: "core::starknet::contract_address::ContractAddress" }],
    outputs: [{ name: "pk", type: "(felt252, felt252)" }],
    state_mutability: "view",
  },
  {
    type: "function",
    name: "get_encrypted_balance",
    inputs: [
      { name: "user", type: "core::starknet::contract_address::ContractAddress" },
      { name: "asset_id", type: "felt252" },
    ],
    outputs: [
      { name: "c1_x", type: "felt252" },
      { name: "c1_y", type: "felt252" },
      { name: "c2_x", type: "felt252" },
      { name: "c2_y", type: "felt252" },
    ],
    state_mutability: "view",
  },
  {
    type: "function",
    name: "get_auditor",
    inputs: [],
    outputs: [{ name: "auditor", type: "(felt252, felt252)" }],
    state_mutability: "view",
  },
  {
    type: "function",
    name: "owner",
    inputs: [],
    outputs: [{ name: "owner", type: "core::starknet::contract_address::ContractAddress" }],
    state_mutability: "view",
  },
  {
    type: "function",
    name: "register",
    inputs: [{ name: "public_key", type: "(felt252, felt252)" }],
    outputs: [],
    state_mutability: "external",
  },
];

async function main() {
  console.log("=".repeat(60));
  console.log("ConfidentialTransfer Contract Verification");
  console.log("=".repeat(60));

  // Initialize provider
  const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

  console.log("\n[1] Checking RPC connection...");
  try {
    const block = await provider.getBlock("latest");
    console.log(`   ✓ Connected to Sepolia (block: ${block.block_number})`);
  } catch (error) {
    console.error(`   ✗ Failed to connect: ${error.message}`);
    process.exit(1);
  }

  // Initialize account
  console.log("\n[2] Initializing account...");
  const account = new Account({
    provider,
    address: CONFIG.deployerAddress,
    signer: CONFIG.deployerPrivateKey,
    cairoVersion: "1",
  });
  console.log(`   ✓ Account: ${CONFIG.deployerAddress.slice(0, 10)}...`);

  // Test contract accessibility
  console.log("\n[3] Checking contract accessibility...");
  try {
    const classHash = await provider.getClassHashAt(CONFIG.confidentialTransferAddress);
    console.log(`   ✓ Contract deployed at: ${CONFIG.confidentialTransferAddress.slice(0, 10)}...`);
    console.log(`   ✓ Class hash: ${classHash.slice(0, 20)}...`);
  } catch (error) {
    console.error(`   ✗ Contract not found: ${error.message}`);
    process.exit(1);
  }

  // Check owner
  console.log("\n[4] Checking contract owner...");
  try {
    const result = await provider.callContract({
      contractAddress: CONFIG.confidentialTransferAddress,
      entrypoint: "owner",
      calldata: [],
    });
    const owner = result[0];
    console.log(`   ✓ Owner: ${owner.slice(0, 20)}...`);
    const isOwner = BigInt(owner) === BigInt(CONFIG.deployerAddress);
    console.log(`   ${isOwner ? "✓" : "⚠"} Deployer ${isOwner ? "is" : "is NOT"} owner`);
  } catch (error) {
    console.log(`   ⚠ Could not get owner: ${error.message}`);
  }

  // Verify supported assets
  console.log("\n[5] Verifying supported assets...");
  for (const [symbol, config] of Object.entries(CONFIG.assets)) {
    try {
      const result = await provider.callContract({
        contractAddress: CONFIG.confidentialTransferAddress,
        entrypoint: "get_asset",
        calldata: [config.id],
      });
      const storedAddress = result[0];

      if (BigInt(storedAddress) === BigInt(config.address)) {
        console.log(`   ✓ ${symbol}: ${config.address.slice(0, 15)}... (verified)`);
      } else if (BigInt(storedAddress) === 0n) {
        console.log(`   ⚠ ${symbol}: Not configured yet`);
      } else {
        console.log(`   ✗ ${symbol}: Mismatch - expected ${config.address.slice(0, 15)}..., got ${storedAddress.slice(0, 15)}...`);
      }
    } catch (error) {
      console.log(`   ✗ ${symbol}: Error - ${error.message}`);
    }
  }

  // Check auditor configuration
  console.log("\n[6] Checking auditor configuration...");
  try {
    const result = await provider.callContract({
      contractAddress: CONFIG.confidentialTransferAddress,
      entrypoint: "get_auditor",
      calldata: [],
    });
    const auditorX = BigInt(result[0] || "0");
    const auditorY = BigInt(result[1] || "0");
    if (auditorX !== 0n || auditorY !== 0n) {
      console.log(`   ✓ Auditor configured: (${auditorX.toString(16).slice(0, 10)}..., ${auditorY.toString(16).slice(0, 10)}...)`);
    } else {
      console.log(`   ⚠ Auditor not configured (optional)`);
    }
  } catch (error) {
    console.log(`   ⚠ Could not check auditor: ${error.message}`);
  }

  // Check deployer registration status
  console.log("\n[7] Checking deployer registration status...");
  try {
    const result = await provider.callContract({
      contractAddress: CONFIG.confidentialTransferAddress,
      entrypoint: "get_public_key",
      calldata: [CONFIG.deployerAddress],
    });
    const pkX = BigInt(result[0] || "0");
    const pkY = BigInt(result[1] || "0");

    if (pkX !== 0n || pkY !== 0n) {
      console.log(`   ✓ Deployer already registered`);
      console.log(`     Public key: (${pkX.toString(16).slice(0, 15)}..., ${pkY.toString(16).slice(0, 15)}...)`);
    } else {
      console.log(`   ○ Deployer not registered (can register with frontend)`);
    }
  } catch (error) {
    console.log(`   ⚠ Could not check registration: ${error.message}`);
  }

  // Check encrypted balances for deployer
  console.log("\n[8] Checking encrypted balances (if registered)...");
  for (const [symbol, config] of Object.entries(CONFIG.assets)) {
    try {
      const result = await provider.callContract({
        contractAddress: CONFIG.confidentialTransferAddress,
        entrypoint: "get_encrypted_balance",
        calldata: [CONFIG.deployerAddress, config.id],
      });
      const c1x = BigInt(result[0] || "0");
      const c1y = BigInt(result[1] || "0");
      const c2x = BigInt(result[2] || "0");
      const c2y = BigInt(result[3] || "0");

      if (c1x !== 0n || c1y !== 0n || c2x !== 0n || c2y !== 0n) {
        console.log(`   ○ ${symbol}: Has encrypted balance (ciphertext present)`);
      } else {
        console.log(`   ○ ${symbol}: Zero balance or not registered`);
      }
    } catch (error) {
      console.log(`   ✗ ${symbol}: Error - ${error.message}`);
    }
  }

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("Verification Complete!");
  console.log("=".repeat(60));

  console.log(`
Next steps for testing:
1. Connect wallet on frontend: https://your-app.com/privacy
2. Register privacy keys via ConfidentialWallet component
3. Fund private balance (deposit public tokens)
4. Test private transfer to another registered user
5. Withdraw back to public balance

Contract Address: ${CONFIG.confidentialTransferAddress}
Explorer: https://sepolia.starkscan.co/contract/${CONFIG.confidentialTransferAddress}
  `);
}

main().catch(console.error);
