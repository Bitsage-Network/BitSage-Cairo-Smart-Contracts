/**
 * Check OTC Orderbook Contract State
 * Diagnoses why orderbook might be empty
 */

import { RpcProvider } from "starknet";

const CONFIG = {
  rpcUrl: "https://rpc.starknet-testnet.lava.build",
  otcOrderbookAddress: "0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0",
};

// Pair IDs matching the frontend config
const PAIRS = [
  { id: 0, name: "SAGE_USDC" },
  { id: 1, name: "SAGE_STRK" },
  { id: 2, name: "SAGE_ETH" },
  { id: 3, name: "STRK_USDC" },
];

async function main() {
  console.log("=".repeat(60));
  console.log("OTC Orderbook Contract Diagnostic");
  console.log("=".repeat(60));

  const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

  // Check connection
  console.log("\n[1] Checking RPC connection...");
  try {
    const block = await provider.getBlock("latest");
    console.log(`   ✓ Connected to Sepolia (block: ${block.block_number})`);
  } catch (error) {
    console.error(`   ✗ Failed to connect: ${error.message}`);
    process.exit(1);
  }

  // Check contract exists
  console.log("\n[2] Checking OTC Orderbook contract...");
  try {
    const classHash = await provider.getClassHashAt(CONFIG.otcOrderbookAddress);
    console.log(`   ✓ Contract deployed at: ${CONFIG.otcOrderbookAddress.slice(0, 20)}...`);
    console.log(`   ✓ Class hash: ${classHash.slice(0, 20)}...`);
  } catch (error) {
    console.error(`   ✗ Contract not found: ${error.message}`);
    process.exit(1);
  }

  // Try to get total order count
  console.log("\n[3] Checking total orders...");
  try {
    const result = await provider.callContract({
      contractAddress: CONFIG.otcOrderbookAddress,
      entrypoint: "get_order_count",
      calldata: [],
    });
    const orderCount = BigInt(result[0] || "0");
    console.log(`   Total orders: ${orderCount}`);
  } catch (error) {
    console.log(`   ⚠ get_order_count not available: ${error.message.slice(0, 50)}...`);
  }

  // Check each trading pair
  console.log("\n[4] Checking orderbook depth for each pair...");
  for (const pair of PAIRS) {
    console.log(`\n   Pair ${pair.id}: ${pair.name}`);

    try {
      // Get orderbook depth
      const depthResult = await provider.callContract({
        contractAddress: CONFIG.otcOrderbookAddress,
        entrypoint: "get_orderbook_depth",
        calldata: [pair.id.toString(), "15"], // max 15 levels
      });

      // Parse response - should be (bids_array, asks_array)
      console.log(`   Raw response length: ${depthResult.length} elements`);

      if (depthResult.length === 0) {
        console.log(`   ⚠ Empty response - no orderbook data`);
      } else {
        // Try to interpret the response
        // First element might be length of bids array
        const bidCount = parseInt(depthResult[0] || "0");
        console.log(`   Bid levels (raw[0]): ${bidCount}`);

        // Find asks start - depends on structure
        // If format is [bid_count, bid1_price, bid1_amount, bid1_count, ..., ask_count, ...]
        if (bidCount === 0) {
          // Check for asks
          const askCountIdx = 1;
          const askCount = parseInt(depthResult[askCountIdx] || "0");
          console.log(`   Ask levels (raw[1]): ${askCount}`);
        }

        // Print first few raw values for debugging
        console.log(`   First 10 raw values: ${depthResult.slice(0, 10).map(v => v.toString().slice(0, 10)).join(', ')}`);
      }
    } catch (error) {
      console.log(`   ✗ Error getting depth: ${error.message.slice(0, 80)}`);
    }

    // Also check active orders count for this pair
    try {
      const activeResult = await provider.callContract({
        contractAddress: CONFIG.otcOrderbookAddress,
        entrypoint: "get_active_orders",
        calldata: [pair.id.toString(), "0", "10"], // pair_id, offset, limit
      });
      console.log(`   Active orders response length: ${activeResult.length}`);
      if (activeResult.length > 0) {
        const orderCount = parseInt(activeResult[0] || "0");
        console.log(`   Active order count: ${orderCount}`);
      }
    } catch (error) {
      console.log(`   ⚠ get_active_orders error: ${error.message.slice(0, 50)}...`);
    }
  }

  // Check if pair is registered
  console.log("\n[5] Checking if trading pairs are registered...");
  for (const pair of PAIRS) {
    try {
      const pairResult = await provider.callContract({
        contractAddress: CONFIG.otcOrderbookAddress,
        entrypoint: "get_pair_info",
        calldata: [pair.id.toString()],
      });
      console.log(`   ${pair.name} (${pair.id}): Response length ${pairResult.length}`);
      if (pairResult.length > 0 && BigInt(pairResult[0]) !== 0n) {
        console.log(`     ✓ Pair registered`);
      } else {
        console.log(`     ⚠ Pair may not be registered`);
      }
    } catch (error) {
      console.log(`   ${pair.name}: Error - ${error.message.slice(0, 50)}...`);
    }
  }

  // Check best bid/ask
  console.log("\n[6] Checking best bid/ask for each pair...");
  for (const pair of PAIRS) {
    try {
      const bestAskResult = await provider.callContract({
        contractAddress: CONFIG.otcOrderbookAddress,
        entrypoint: "get_best_ask",
        calldata: [pair.id.toString()],
      });
      const bestAsk = BigInt(bestAskResult[0] || "0");

      const bestBidResult = await provider.callContract({
        contractAddress: CONFIG.otcOrderbookAddress,
        entrypoint: "get_best_bid",
        calldata: [pair.id.toString()],
      });
      const bestBid = BigInt(bestBidResult[0] || "0");

      console.log(`   ${pair.name}: Best Bid ${bestBid}, Best Ask ${bestAsk}`);
      if (bestBid === 0n && bestAsk === 0n) {
        console.log(`     ⚠ No active orders (both bid and ask are 0)`);
      }
    } catch (error) {
      console.log(`   ${pair.name}: Error - ${error.message.slice(0, 50)}...`);
    }
  }

  console.log("\n" + "=".repeat(60));
  console.log("Diagnostic Complete");
  console.log("=".repeat(60));
}

main().catch(console.error);
