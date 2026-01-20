#!/usr/bin/env node
/**
 * Deploy New Production Contracts to Sepolia
 *
 * Deploys:
 * - ConfidentialTransfer (Tongo-style privacy)
 * - ConfidentialSwap (upgrades if already deployed)
 *
 * All contracts are upgradeable with proper security.
 */

import { Account, RpcProvider, Contract, CallData, hash, ETransactionVersion } from "starknet";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const CONFIG = {
  rpcUrl: "https://rpc.starknet-testnet.lava.build",
  deployerAddress: "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344",
  deployerPrivateKey: "0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a",
  // Auditor public key for ConfidentialTransfer
  auditorPublicKey: {
    x: "0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
    y: "0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f"
  }
};

// Contracts to deploy
const CONTRACTS = [
  {
    name: "ConfidentialTransfer",
    classFile: "sage_contracts_ConfidentialTransfer.contract_class.json",
    casmFile: "sage_contracts_ConfidentialTransfer.compiled_contract_class.json",
    constructorArgs: () => [
      CONFIG.deployerAddress,
      CONFIG.auditorPublicKey
    ]
  }
];

async function main() {
  console.log("=".repeat(60));
  console.log("BitSage Network - Production Contract Deployment");
  console.log("=".repeat(60));
  console.log(`Network: Sepolia`);
  console.log(`Deployer: ${CONFIG.deployerAddress}`);
  console.log("");

  // Initialize provider
  const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

  // Check network connectivity
  try {
    const chainId = await provider.getChainId();
    console.log(`Connected to chain: ${chainId}`);
  } catch (error) {
    console.error("Failed to connect to RPC:", error.message);
    process.exit(1);
  }

  // Initialize account (starknet.js v9 format)
  const account = new Account({
    provider,
    address: CONFIG.deployerAddress,
    signer: CONFIG.deployerPrivateKey,
    cairoVersion: "1",
  });
  console.log("Account initialized");

  const deployedContracts = {};
  const targetDir = path.join(__dirname, "..", "target", "dev");

  for (const contract of CONTRACTS) {
    console.log("");
    console.log("-".repeat(40));
    console.log(`Deploying ${contract.name}...`);
    console.log("-".repeat(40));

    try {
      // Read compiled contract
      const contractPath = path.join(targetDir, contract.classFile);

      if (!fs.existsSync(contractPath)) {
        console.log(`Skipping ${contract.name} - contract file not found at ${contractPath}`);
        continue;
      }

      const sierraContract = JSON.parse(fs.readFileSync(contractPath, "utf-8"));

      // Read CASM
      const casmPath = path.join(targetDir, contract.casmFile);
      if (!fs.existsSync(casmPath)) {
        console.log(`Skipping ${contract.name} - CASM file not found at ${casmPath}`);
        continue;
      }
      const casmContract = JSON.parse(fs.readFileSync(casmPath, "utf-8"));

      // Declare the contract class
      console.log("Declaring contract class...");

      let classHash;
      try {
        const declareResponse = await account.declare(
          { contract: sierraContract, casm: casmContract },
          { version: ETransactionVersion.V3 }
        );

        console.log(`Declare tx: ${declareResponse.transaction_hash}`);
        await provider.waitForTransaction(declareResponse.transaction_hash);
        classHash = declareResponse.class_hash;
        console.log(`Class hash: ${classHash}`);
      } catch (error) {
        // Check if already declared
        if (error.message?.includes("already declared") || error.message?.includes("CLASS_ALREADY_DECLARED")) {
          console.log("Contract already declared, computing class hash...");
          classHash = hash.computeSierraContractClassHash(sierraContract);
          console.log(`Class hash: ${classHash}`);
        } else {
          console.error("Declare error:", error.message);
          throw error;
        }
      }

      // Prepare constructor calldata
      const constructorArgs = contract.constructorArgs();
      console.log("Constructor args:", constructorArgs);
      const calldata = CallData.compile(constructorArgs);
      console.log("Compiled calldata:", calldata);

      // Deploy the contract
      console.log("Deploying contract instance...");

      const deployResponse = await account.deployContract(
        { classHash, constructorCalldata: calldata },
        { version: ETransactionVersion.V3 }
      );

      console.log(`Deploy tx: ${deployResponse.transaction_hash}`);
      await provider.waitForTransaction(deployResponse.transaction_hash);

      const contractAddress = deployResponse.contract_address;
      console.log(`Contract address: ${contractAddress}`);

      deployedContracts[contract.name] = {
        classHash,
        address: contractAddress,
        deployTx: deployResponse.transaction_hash,
        timestamp: new Date().toISOString()
      };

      console.log(`✓ ${contract.name} deployed successfully!`);

    } catch (error) {
      console.error(`✗ Failed to deploy ${contract.name}:`, error.message || error);
      if (error.message) {
        console.error("Full error:", error);
      }
    }
  }

  // Save deployment results
  console.log("");
  console.log("=".repeat(60));
  console.log("Deployment Summary");
  console.log("=".repeat(60));

  for (const [name, info] of Object.entries(deployedContracts)) {
    console.log(`${name}:`);
    console.log(`  Address: ${info.address}`);
    console.log(`  Class Hash: ${info.classHash}`);
  }

  // Save to file
  const outputPath = path.join(__dirname, "..", "deployment", "new_contracts_deployment.json");
  fs.writeFileSync(outputPath, JSON.stringify(deployedContracts, null, 2));
  console.log("");
  console.log(`Deployment info saved to: ${outputPath}`);

  return deployedContracts;
}

main()
  .then((result) => {
    console.log("");
    console.log("Deployment complete!");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
