import { RpcProvider, Account, ETransactionVersion } from 'starknet';

const RPC_URL = "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_10/GUBwFqKhSgn4mwVbN6Sbn";

const DEPLOYER_ADDRESS = "0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344";
const DEPLOYER_PK = "0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a";

const CONTRACTS_TO_EXECUTE = [
  { name: "StwoVerifier", address: "0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d" },
  { name: "WorkerStaking", address: "0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613" }
];

async function executeUpgrades() {
  const provider = new RpcProvider({ nodeUrl: RPC_URL });
  const account = new Account({
    provider,
    address: DEPLOYER_ADDRESS,
    signer: DEPLOYER_PK,
    cairoVersion: '1',
    transactionVersion: ETransactionVersion.V3,
  });

  console.log("=== Executing Pending Upgrades ===\n");
  console.log("Deployer:", DEPLOYER_ADDRESS);

  for (const contract of CONTRACTS_TO_EXECUTE) {
    console.log("\n--- Executing " + contract.name + " upgrade ---");
    console.log("Address:", contract.address);

    try {
      const result = await account.execute({
        contractAddress: contract.address,
        entrypoint: "execute_upgrade",
        calldata: []
      });

      console.log("TX Hash: " + result.transaction_hash);
      console.log("Waiting for confirmation...");

      const receipt = await provider.waitForTransaction(result.transaction_hash, {
        retryInterval: 5000
      });

      console.log("Status: " + receipt.execution_status);
      if (receipt.execution_status === "SUCCEEDED") {
        console.log("SUCCESS: " + contract.name + " upgraded!");
      }
    } catch (e) {
      console.log("Error: " + e.message);
    }
  }
}

executeUpgrades().catch(console.error);
