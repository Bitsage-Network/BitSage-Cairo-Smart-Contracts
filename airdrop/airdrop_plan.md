# CIRO Token Airdrop Plan (Testnet)

This plan documents the addresses, tooling and steps to safely distribute CIRO from the main holder to 10 recipient accounts using a separate keystore.

- Network: Starknet Sepolia
- Token (CIRO): `0x03c0f7574905d7cbc2cca18d6c090265fa35b572d8e9dc62efeb5339908720d8`
- Decimals: 18
- Total Supply (on-chain): 50,000,000 CIRO
- Main Holder (deployer): `0x0737c361e784a8f58508c211d50e397059590a416c373ed527b9a45287eacfc2` (balance confirmed)
- Main Holder account file: keep under `CIRO_Network_Backup/.../testnet_account.json` or equivalent
- Main Holder keystore: `CIRO_Network_Backup/20250711_061352/testnet_keystore.json`
- Recipients registry: `cairo-contracts/airdrop/recipients.json` (this file)
- Airdrop script: `cairo-contracts/airdrop/airdrop.sh`

## Safety

1) Use the backup keystore only for transfers from the main holder.
2) Generate a separate keystore for all new recipient accounts and store it under `cairo-contracts/airdrop/keystores/`.
3) Keep both keystores with distinct passwords (do not reuse).

## Workflow

1. Generate 10 recipient accounts (OpenZeppelin account type)
   - Create keystores for each recipient under `cairo-contracts/airdrop/keystores/` (separate password from main holder)
   - Compute their addresses (no need to deploy immediately to receive ERC20 balances)
   - Write the resulting addresses into `recipients.json`

2. Review `recipients.json` and decide per-recipient amount (default: 100,000 CIRO each)

3. Run the airdrop:
   - Execute `./airdrop.sh` (it loops over `recipients.json` and submits `transfer` calls)
   - You will be prompted for the main holder keystore password at runtime

4. Verification:
   - Indexer and dashboard will show ERC20 `Transfer` events
   - Re-run `starkli call ... balance_of` for each recipient to confirm

## Notes

- ERC20 balances can be assigned to any address (account deployment not required to receive). To move funds later, recipients should deploy/control their accounts using their keystores.
- All script parameters are defined at the top of `airdrop.sh`.


