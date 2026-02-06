#!/usr/bin/env node
/**
 * Fund PaymentRouter with SAGE tokens
 *
 * Transfers SAGE tokens from deployer to PaymentRouter contract so that
 * _distribute_fees fires during proof verification cascade.
 *
 * Without SAGE balance on PaymentRouter:
 *   - register_job_payment works
 *   - submit_and_verify works
 *   - mark_proof_verified works
 *   - _execute_payment works
 *   - _distribute_fees SILENTLY SKIPS (no SAGE balance)
 *
 * With SAGE balance on PaymentRouter (after running this script):
 *   - _distribute_fees fires: FeesDistributed, WorkerPaid, TokenBurned
 *   - 3-4 additional ERC20 Transfer events
 *   - Total: 15+ events per transaction
 *
 * Usage:
 *   DEPLOYER_PRIVATE_KEY=0x... node fund_payment_router.mjs [amount_sage]
 *
 * Default: 1000 SAGE (18 decimals)
 */

import { Account, RpcProvider, Contract, cairo, uint256 } from "starknet";

// Contract addresses (Sepolia - deployed 2025-12-27)
const SAGE_TOKEN = "0x04321b7282ae6aa354988eed57f2ff851314af8524de8b1f681a128003cc4ea5";
const PAYMENT_ROUTER = "0x3a3d409738734ae42365a20ae217687991cbba9db743c30d87f6a6dbaf523c6";
const DEPLOYER_ADDRESS = "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344";

// ERC20 ABI (minimal for transfer)
const ERC20_ABI = [
  {
    name: "transfer",
    type: "function",
    inputs: [
      { name: "recipient", type: "core::starknet::contract_address::ContractAddress" },
      { name: "amount", type: "core::integer::u256" },
    ],
    outputs: [{ type: "core::bool" }],
    state_mutability: "external",
  },
  {
    name: "balanceOf",
    type: "function",
    inputs: [
      { name: "account", type: "core::starknet::contract_address::ContractAddress" },
    ],
    outputs: [{ type: "core::integer::u256" }],
    state_mutability: "view",
  },
];

async function main() {
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
  if (!privateKey) {
    console.error("ERROR: DEPLOYER_PRIVATE_KEY env var required");
    console.error("Usage: DEPLOYER_PRIVATE_KEY=0x... node fund_payment_router.mjs [amount_sage]");
    process.exit(1);
  }

  const rpcUrl = process.env.STARKNET_RPC_URL || "https://starknet-sepolia-rpc.publicnode.com";
  const amountSage = parseInt(process.argv[2] || "1000", 10);
  const amountWei = BigInt(amountSage) * BigInt("1000000000000000000"); // 18 decimals

  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║     Fund PaymentRouter with SAGE Tokens                 ║");
  console.log("╠══════════════════════════════════════════════════════════╣");
  console.log(`║  Amount:    ${amountSage} SAGE                                    ║`);
  console.log(`║  Network:   Sepolia                                     ║`);
  console.log("╚══════════════════════════════════════════════════════════╝");
  console.log();

  // Connect
  const provider = new RpcProvider({ nodeUrl: rpcUrl });
  const account = new Account(provider, DEPLOYER_ADDRESS, privateKey);
  const sageToken = new Contract(ERC20_ABI, SAGE_TOKEN, provider);

  // Check deployer balance
  console.log("Checking deployer SAGE balance...");
  const deployerBalance = await sageToken.balanceOf(DEPLOYER_ADDRESS);
  const deployerSage = Number(BigInt(deployerBalance.toString()) / BigInt("1000000000000000000"));
  console.log(`  Deployer balance: ${deployerSage} SAGE`);

  if (BigInt(deployerBalance.toString()) < amountWei) {
    console.error(`  ERROR: Insufficient SAGE balance. Need ${amountSage}, have ${deployerSage}`);
    process.exit(1);
  }

  // Check current PaymentRouter balance
  const routerBalance = await sageToken.balanceOf(PAYMENT_ROUTER);
  const routerSage = Number(BigInt(routerBalance.toString()) / BigInt("1000000000000000000"));
  console.log(`  PaymentRouter balance: ${routerSage} SAGE`);
  console.log();

  // Transfer SAGE to PaymentRouter
  console.log(`Transferring ${amountSage} SAGE to PaymentRouter...`);
  const transferCall = sageToken.populate("transfer", [
    PAYMENT_ROUTER,
    uint256.bnToUint256(amountWei),
  ]);

  const tx = await account.execute([transferCall]);
  console.log(`  TX hash: ${tx.transaction_hash}`);
  console.log("  Waiting for confirmation...");

  await provider.waitForTransaction(tx.transaction_hash);
  console.log("  Confirmed!");
  console.log();

  // Verify new balance
  const newBalance = await sageToken.balanceOf(PAYMENT_ROUTER);
  const newSage = Number(BigInt(newBalance.toString()) / BigInt("1000000000000000000"));
  console.log(`  PaymentRouter new balance: ${newSage} SAGE`);
  console.log();
  console.log("PaymentRouter is now funded. _distribute_fees will fire during proof verification.");
  console.log("Expected additional events: FeesDistributed, WorkerPaid, TokenBurned, ERC20 Transfers");
  console.log();
  console.log(`Starkscan: https://sepolia.starkscan.co/tx/${tx.transaction_hash}`);
}

main().catch((e) => {
  console.error("Error:", e.message || e);
  process.exit(1);
});
