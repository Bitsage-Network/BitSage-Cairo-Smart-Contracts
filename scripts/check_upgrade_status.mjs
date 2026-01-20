import { RpcProvider } from 'starknet';

const RPC_URL = "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_7/GUBwFqKhSgn4mwVbN6Sbn";
const provider = new RpcProvider({ nodeUrl: RPC_URL });

const CONTRACTS = {
  StwoVerifier: "0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d",
  WorkerStaking: "0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613",
  SAGEToken: "0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850",
  OTCOrderbook: "0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0"
};

async function checkStatus() {
  console.log("=== Upgrade Status Check ===\n");

  for (const [name, address] of Object.entries(CONTRACTS)) {
    console.log("\n--- " + name + " ---");
    try {
      // Try to read upgrade info (pending_class_hash, ready_time, delay, [sometimes current_time])
      const infoCall = await provider.callContract({
        contractAddress: address,
        entrypoint: "get_upgrade_info",
        calldata: []
      });

      const classHash = infoCall[0];
      const readyTime = BigInt(infoCall[1] || "0");
      const delay = Number(infoCall[2] || "0");

      console.log("  Current delay: " + delay + "s (" + (delay/3600).toFixed(1) + "h)");

      if (classHash !== "0x0" && classHash !== "0") {
        const now = BigInt(Math.floor(Date.now() / 1000));
        const isReady = readyTime <= now;
        console.log("  Pending Class: " + classHash);
        console.log("  Ready Time: " + new Date(Number(readyTime) * 1000).toISOString());
        if (isReady) {
          console.log("  Status: READY TO EXECUTE NOW!");
        } else {
          const waitSecs = Number(readyTime - now);
          const waitHrs = (waitSecs / 3600).toFixed(1);
          console.log("  Status: Wait " + waitSecs + "s (" + waitHrs + "h) - ready at " + new Date(Number(readyTime) * 1000).toLocaleString());
        }
      } else {
        console.log("  No pending upgrade");
      }

    } catch (e) {
      console.log("  Error: " + e.message);
    }
  }
}

checkStatus().catch(console.error);
