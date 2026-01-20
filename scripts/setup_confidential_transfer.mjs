#!/usr/bin/env node
/**
 * Setup ConfidentialTransfer Contract
 *
 * Adds supported assets (SAGE, STRK, USDC) to the ConfidentialTransfer contract.
 */

import { Account, RpcProvider, Contract, CallData, ETransactionVersion } from "starknet";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const CONFIG = {
  rpcUrl: "https://rpc.starknet-testnet.lava.build",
  deployerAddress: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344",
  deployerPrivateKey: "0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a",
  confidentialTransferAddress: "0x626df6abac7e4c2140d8a2e2024503431a5492526adda96f78c1b623a855b",
};

// Token addresses on Sepolia
const TOKENS = {
  SAGE: {
    address: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850",
    assetId: "0x53414745", // "SAGE" as felt
  },
  STRK: {
    address: "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
    assetId: "0x5354524b", // "STRK" as felt
  },
  USDC: {
    address: "0x053b40a647cedfca6ca84f542a0fe36736031905a9639a7f19a3c1e66bfd5080",
    assetId: "0x55534443", // "USDC" as felt
  },
};

// ConfidentialTransfer ABI (minimal for add_asset)
const CONFIDENTIAL_TRANSFER_ABI = [
  {
    name: "add_asset",
    type: "function",
    inputs: [
      { name: "asset_id", type: "felt252" },
      { name: "token", type: "core::starknet::contract_address::ContractAddress" }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    name: "get_asset",
    type: "function",
    inputs: [
      { name: "asset_id", type: "felt252" }
    ],
    outputs: [{ type: "core::starknet::contract_address::ContractAddress" }],
    state_mutability: "view"
  }
];

async function main() {
  console.log("=".repeat(60));
  console.log("Setup ConfidentialTransfer - Adding Supported Assets");
  console.log("=".repeat(60));
  console.log(`Contract: ${CONFIG.confidentialTransferAddress}`);
  console.log("");

  // Initialize provider and account
  const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

  const chainId = await provider.getChainId();
  console.log(`Connected to chain: ${chainId}`);

  const account = new Account({
    provider,
    address: CONFIG.deployerAddress,
    signer: CONFIG.deployerPrivateKey,
    cairoVersion: "1",
  });

  // Add each asset
  for (const [name, token] of Object.entries(TOKENS)) {
    console.log("");
    console.log(`Adding ${name}...`);
    console.log(`  Asset ID: ${token.assetId}`);
    console.log(`  Token Address: ${token.address}`);

    try {
      // Add the asset using direct execute
      const tx = await account.execute(
        {
          contractAddress: CONFIG.confidentialTransferAddress,
          entrypoint: "add_asset",
          calldata: [token.assetId, token.address],
        },
        { version: ETransactionVersion.V3 }
      );

      console.log(`  TX: ${tx.transaction_hash}`);
      await provider.waitForTransaction(tx.transaction_hash);
      console.log(`  ✓ ${name} added successfully!`);

    } catch (error) {
      console.error(`  ✗ Failed to add ${name}:`, error.message);
    }
  }

  console.log("");
  console.log("=".repeat(60));
  console.log("Asset Setup Complete!");
  console.log("=".repeat(60));

  console.log("\nAll assets configured!");
}

main()
  .then(() => {
    console.log("\nSetup complete!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Setup failed:", error);
    process.exit(1);
  });
