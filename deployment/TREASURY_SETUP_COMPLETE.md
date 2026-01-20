# BitSage Treasury & Pool Infrastructure

**Generated:** 2026-01-13
**Network:** Starknet Sepolia

---

## Pool Wallet Addresses

| Pool | Address | Allocation | SAGE Tokens |
|------|---------|------------|-------------|
| **Treasury** | `0x6c2fc54050e474dc07637f42935ca6e18e8e17ab7bf9835504c85515beb860` | 15% | 150,000,000 |
| **Market Liquidity** | `0x2a4b7dbd8723e57fd03250207dd0633561a3b222ac84f28d5b6228b33e4aef1` | 10% | 100,000,000 |
| **Ecosystem Rewards** | `0x402fb3031f8d1004538b0ab48054431e69a265fb53b645180de6044c333fc53` | 30% | 300,000,000 |
| **Public Sale** | `0x5c3970100383ae00e135b92794fc0fc5f4537eb553e92e7d23efa352c253376` | 5% | 50,000,000 |

---

## Deployed Contracts

| Contract | Address |
|----------|---------|
| OTC Orderbook | `0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0` |
| SAGE Token | `0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850` |
| Deployer/Owner | `0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344` |

---

## Quote Tokens (Sepolia)

| Token | Address |
|-------|---------|
| STRK | `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d` |
| ETH | `0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7` |
| USDC | `0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8` |

---

## Trading Pair Configuration

| Pair ID | Pair | Quote Token | Status |
|---------|------|-------------|--------|
| 0 | SAGE/Mock STRK | (legacy) | Deprecated |
| 1 | SAGE/STRK | Real STRK | Active |
| 2 | SAGE/ETH | ETH | To be added |
| 3 | SAGE/USDC | USDC | To be added |

---

## SAGE Token Pricing

### Target Valuation
- **Total Supply:** 1,000,000,000 SAGE
- **Target FDV:** $1M - $5M (at launch)
- **Target Price:** $0.001 - $0.005 per SAGE

### Price Tiers (SAGE/STRK - Pair 1)

| Tier | Price (STRK/SAGE) | Amount (SAGE) | Est. USD Value |
|------|-------------------|---------------|----------------|
| 1 (Best) | 0.005 | 50,000 | $0.0025/SAGE |
| 2 | 0.006 | 100,000 | $0.003/SAGE |
| 3 | 0.007 | 200,000 | $0.0035/SAGE |
| 4 | 0.008 | 300,000 | $0.004/SAGE |
| 5 | 0.010 | 500,000 | $0.005/SAGE |
| 6 (Premium) | 0.015 | 1,000,000 | $0.0075/SAGE |

### Price Tiers (SAGE/USDC - Pair 3)

| Tier | Price (USDC/SAGE) | Amount (SAGE) |
|------|-------------------|---------------|
| 1 (Best) | $0.0025 | 100,000 |
| 2 | $0.003 | 200,000 |
| 3 | $0.004 | 300,000 |
| 4 (Premium) | $0.005 | 500,000 |

---

## Keystore Files

Encrypted keystores are stored in:
```
deployment/pool_wallets/keystores/
├── treasury_keystore.json
├── marketLiquidity_keystore.json
├── ecosystemRewards_keystore.json
├── publicSale_keystore.json
└── PASSWORDS_SECURE.json  # MOVE TO SECURE STORAGE!
```

### Keystore Passwords (SECURE IMMEDIATELY)

| Pool | Password |
|------|----------|
| Treasury | `4795a788171a3a7490ceb5e4a88915477d8670d8fc1bb9f549e49abac18f313a` |
| Market Liquidity | `b14438b3c76eb144ec626aa12d58eb9408b333ac4f7d80ee8dd9e4868586978f` |
| Ecosystem Rewards | `de228f2d6765b0d7042b540565033397ed8427b7cbc31c5c87d69587c698faa4` |
| Public Sale | `aee247502639c2d8429880e5c0480e8f2a3d5048b43918f955c7dc07b0b6b3e0` |

---

## Money Flow Architecture

```
                    ┌──────────────────────────────┐
                    │     SAGE Token Contract      │
                    │  Total: 1B SAGE              │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────┴───────────────┐
                    │                              │
        ┌───────────▼──────────┐     ┌────────────▼──────────┐
        │  Market Liquidity    │     │  Ecosystem Rewards    │
        │  100M SAGE (10%)     │     │  300M SAGE (30%)      │
        │                      │     │                       │
        │  → OTC Orderbook     │     │  → Mining rewards     │
        │  → DEX liquidity     │     │  → Staking rewards    │
        └──────────┬───────────┘     └───────────────────────┘
                   │
                   ▼
        ┌──────────────────────────────────────────────────┐
        │              OTC ORDERBOOK CONTRACT              │
        │                                                  │
        │  SELL Orders (Protocol → Users):                 │
        │  ├── SAGE/STRK @ tiered prices                   │
        │  ├── SAGE/ETH @ tiered prices                    │
        │  └── SAGE/USDC @ tiered prices                   │
        │                                                  │
        │  Payment Flow:                                   │
        │  User pays STRK/ETH/USDC → Market Liquidity      │
        │  User receives SAGE (minus 0.3% taker fee)       │
        │                                                  │
        │  Fee Collection:                                 │
        │  0.1% maker + 0.3% taker → Treasury              │
        └──────────────────────────────────────────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │      TREASURY        │
        │  150M SAGE (15%)     │
        │                      │
        │  Receives:           │
        │  • Trading fees      │
        │  • Protocol revenue  │
        │                      │
        │  Uses:               │
        │  • Operations        │
        │  • Development       │
        │  • Buybacks          │
        └──────────────────────┘
```

---

## Setup Checklist

### Completed
- [x] Generated pool wallet addresses
- [x] Created encrypted keystores
- [x] Defined pricing strategy
- [x] Created seeding scripts

### Remaining Steps

1. **Fund Pool Wallets**
   ```bash
   # Fund each wallet with ~0.1 ETH for gas
   # Use faucet: https://faucet.starknet.io
   ```

2. **Deploy Pool Accounts**
   ```bash
   # After funding, deploy each account on-chain
   export DEPLOYER_PRIVATE_KEY=0x...
   node scripts/deploy_pool_accounts.mjs
   ```

3. **Transfer SAGE to Market Liquidity**
   ```bash
   # Transfer 100M SAGE to Market Liquidity wallet
   node scripts/transfer_sage_to_pools.mjs
   ```

4. **Add Trading Pairs**
   ```bash
   # Add ETH and USDC pairs to OTC
   node scripts/add_trading_pairs.mjs
   ```

5. **Set Fee Recipient**
   ```bash
   # Set Treasury as fee recipient
   node scripts/set_fee_recipient.mjs
   ```

6. **Seed Orderbook**
   ```bash
   # Populate orderbook with SAGE sell orders
   export DEPLOYER_PRIVATE_KEY=0x...
   node scripts/seed_orderbook_production.mjs
   ```

7. **Verify Confidential Swap**
   ```bash
   # Check Confidential Swap contract is properly configured
   node scripts/verify_confidential_swap.mjs
   ```

---

## Security Recommendations

1. **Move PASSWORDS_SECURE.json to cold storage immediately**
2. **Use hardware wallet for mainnet deployment**
3. **Set up multi-sig for Treasury wallet**
4. **Enable timelock on critical contract functions**
5. **Regular audit of fee collection and withdrawals**

---

## Explorer Links (Sepolia)

- [OTC Orderbook](https://sepolia.starkscan.co/contract/0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0)
- [SAGE Token](https://sepolia.starkscan.co/contract/0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850)
- [Treasury Wallet](https://sepolia.starkscan.co/contract/0x6c2fc54050e474dc07637f42935ca6e18e8e17ab7bf9835504c85515beb860)
- [Market Liquidity](https://sepolia.starkscan.co/contract/0x2a4b7dbd8723e57fd03250207dd0633561a3b222ac84f28d5b6228b33e4aef1)
