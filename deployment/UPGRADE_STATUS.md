# Contract Upgrade Status

Last updated: 2026-01-17 19:35 UTC

## Mission Complete: 5-Minute Upgrade Timelocks Enabled

All contracts now have 5-minute minimum upgrade delays instead of 24-48 hours.

## Contract Status

| Contract | Address | Status | Current Delay | Notes |
|----------|---------|--------|---------------|-------|
| OTCOrderbook | `0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0` | ✅ Complete | **5 min** | Upgraded with new trustless view functions |
| StwoVerifier | `0x52963fe2f1d2d2545cbe18b8230b739c8861ae726dc7b6f0202cc17a369bd7d` | ✅ Complete | **5 min** | Upgraded Jan 17, 2026 |
| WorkerStaking | `0x28caa5962266f2bf9320607da6466145489fed9dae8e346473ba1e847437613` | ✅ Complete | **5 min** | Upgraded Jan 17, 2026 |
| SAGEToken | `0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850` | ✅ Complete | **5 min** | Upgraded Jan 17, 2026 (via EC2 Juno node) |

## Declared Class Hashes (Modified for 5-min delay)

| Contract | New Class Hash | Declared |
|----------|---------------|----------|
| OTCOrderbook | `0x79471292aa4d13da966fea97b9f0f32729881a66b11b8f223e38e53994f520` | ✅ Yes |
| StwoVerifier | `0x1f2bd9a181e6fc4e7efbc4fc221167d8465542c93773d3aa95b37312e492e72` | ✅ Yes |
| WorkerStaking | `0x21aace5ee46445be8381b11322aac4f228136a0cbe4e4c008e2dcaf1ba9062` | ✅ Yes |
| SAGEToken | `0x16215c09e2b8f7df7d4977b26685b3c158e037c75bed77d549275eb8898ec7c` | ✅ Yes |

## EC2 Juno Node (for Large Contract Declaration)

AWS EC2 running Juno full node with 50MB HTTP payload limit (vs 2MB on public RPCs).

**SSH Access:**
```bash
ssh -i ~/.ssh/ciro-staging-key.pem ec2-user@54.242.201.251
```

**Check Status:**
```bash
# Check Juno sync progress
ssh -i ~/.ssh/ciro-staging-key.pem ec2-user@54.242.201.251 "tail -20 /tmp/sage_declare.log"

# Check if declaration succeeded
ssh -i ~/.ssh/ciro-staging-key.pem ec2-user@54.242.201.251 "grep -E 'SUCCESS|COMPLETE|Class hash' /tmp/sage_declare.log"
```

**Manual Declaration (if auto-declare fails):**
```bash
ssh -i ~/.ssh/ciro-staging-key.pem ec2-user@54.242.201.251 "cd ~/sage-declare && node declare_clean.mjs"
```

## Code Changes Made

### 1. SAGEToken (`src/sage_token.cairo:2019-2021`)
```cairo
// Changed from 24h minimum to 5 min
assert(new_delay >= 300, 'Delay must be >= 5min');
assert(new_delay <= 604800, 'Delay must be <= 7 days');
```

### 2. StwoVerifier (`src/obelysk/stwo_verifier.cairo:1126-1127`)
```cairo
// Changed from 1h minimum to 5 min
assert!(new_delay >= 300 && new_delay <= 2592000, "Invalid delay range");
```

### 3. WorkerStaking (`src/contracts/staking.cairo:593-596`)
```cairo
// Changed from 1 day minimum to 5 min
assert!(delay >= 300, "Delay must be at least 5 min");
```

---

## Remaining Steps

### Step 1: Execute Pending Upgrades (after ~44 hours)

After January 17, 2026 00:00 UTC:
```bash
node scripts/execute_pending_upgrades.mjs
```

### Step 2: Declare SAGEToken (Manual - Browser Required)

The SAGEToken contract is 2.95 MB Sierra + 1.85 MB CASM, which exceeds all public RPC payload limits (~2MB max).

**Using Voyager Declaration Tool:**
1. Go to: https://sepolia.voyager.online/contract-declaration
2. Upload Sierra: `target/dev/sage_contracts_SAGEToken.contract_class.json`
3. Upload CASM: `target/dev/sage_contracts_SAGEToken.compiled_contract_class.json`
4. Connect wallet (Argent X or Braavos)
5. Sign declaration transaction
6. Verify class hash: `0x16215c09e2b8f7df7d4977b26685b3c158e037c75bed77d549275eb8898ec7c`

### Step 3: Schedule SAGEToken Upgrade

After SAGEToken is declared:
```bash
node scripts/schedule_sage_upgrade.mjs
```

### Step 4: Set 5-Minute Delays

After all upgrades complete, set delays to 5 minutes:
```bash
node scripts/set_5min_delays.mjs
```

---

## Deployer Account

- **Address**: `0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344`
- **Private Key**: `0x0154de503c7553e078b28044f15b60323899d9437bd44e99d9ab629acbada47a`
- **Network**: Starknet Sepolia

## Utility Scripts

| Script | Purpose |
|--------|---------|
| `scripts/check_upgrade_status.mjs` | Check all contract upgrade status |
| `scripts/execute_pending_upgrades.mjs` | Execute upgrades after timelock |
| `scripts/upgrade_otc_orderbook.mjs` | OTC Orderbook upgrade utilities |
| `scripts/declare_sage_alternatives.mjs` | SAGEToken declaration attempts |

## Check Status

```bash
node scripts/check_upgrade_status.mjs
```
