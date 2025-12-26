# BitSage Network - Starknet Mainnet Deployment Guide

## External Addresses (Starknet Mainnet)

```cairo
// USDC Token
const USDC_ADDRESS: felt252 = 0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8;

// Pragma Oracle (optional - can use fallback initially)
const PRAGMA_ORACLE: felt252 = 0x2a85bd616f912537c50a49a4076db02c00b29b2cdc8a197ce92ed1837fa875b;

// ETH Token (for gas estimation)
const ETH_ADDRESS: felt252 = 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7;
```

## Deployment Order

Deploy contracts in this order (each depends on previous):

1. **SAGE Token** → Returns `SAGE_ADDRESS`
2. **Oracle Wrapper** → Returns `ORACLE_ADDRESS`
3. **Prover Staking** (needs SAGE) → Returns `STAKING_ADDRESS`
4. **OTC Orderbook** (needs SAGE, USDC) → Returns `OTC_ADDRESS`
5. **Payment Router** (needs SAGE, Staking, OTC) → Returns `ROUTER_ADDRESS`
6. **Buyback Engine** (needs SAGE, USDC, Oracle, OTC) → Returns `BUYBACK_ADDRESS`
7. **Burn Manager** (needs SAGE, Oracle, OTC) → Returns `BURN_ADDRESS`
8. **CDC Pool** (needs SAGE, Staking) → Returns `CDC_ADDRESS`
9. **Job Manager** (needs Router, CDC) → Returns `JOB_ADDRESS`
10. **Optimistic TEE** (needs Staking, Payment) → Returns `TEE_ADDRESS`
11. **Privacy Router** (needs SAGE) → Returns `PRIVACY_ADDRESS`

---

## Post-Deployment Configuration

### 1. Oracle Setup (Initial - Before Pragma Lists SAGE)

```cairo
// Set your own SAGE price initially
// Price is in 8 decimals: 10000000 = $0.10
oracle.set_fallback_price(PricePair::SAGE_USD, 10000000);

// USDC is always $1.00
oracle.set_fallback_price(PricePair::USDC_USD, 100000000);
```

### 2. TEE Root Certificates

Get root certificate hashes from official vendor PKIs:

**Intel TDX:**
```bash
# Download Intel's root CA
curl -o intel_root.pem https://certificates.trustedservices.intel.com/IntelSGXRootCA.der

# Get keccak256 hash (use any keccak256 tool)
# Result example: 0x1a2b3c4d...
```

**AMD SEV-SNP:**
```bash
# Download from https://developer.amd.com/sev/
# ARK (AMD Root Key) certificate
```

**NVIDIA Confidential Computing:**
```bash
# Download from https://docs.nvidia.com/confidential-computing/
```

**Add to contract:**
```cairo
// TEE Types: 1 = Intel TDX, 2 = AMD SEV-SNP, 3 = NVIDIA CC

// Intel TDX root
optimistic_tee.add_trusted_root(1, 0x<intel_root_hash>);

// AMD SEV-SNP root
optimistic_tee.add_trusted_root(2, 0x<amd_root_hash>);

// NVIDIA CC root
optimistic_tee.add_trusted_root(3, 0x<nvidia_root_hash>);
```

### 3. OTC Orderbook - Initial Liquidity ($300)

**Step 1: Approve SAGE tokens**
```cairo
// Approve OTC orderbook to spend your SAGE
sage_token.approve(OTC_ADDRESS, 3000000000000000000000); // 3000 SAGE
```

**Step 2: Place sell orders at different price levels**
```cairo
// Create tiered liquidity for price discovery
// Pair ID 0 = SAGE/USDC

// Order 1: 1000 SAGE at $0.10
otc_orderbook.place_limit_order(
    pair_id: 0,
    side: OrderSide::Sell,
    price: 100000,      // $0.10 with 6 decimals
    amount: 1000000000000000000000  // 1000 SAGE (18 decimals)
);

// Order 2: 1000 SAGE at $0.11
otc_orderbook.place_limit_order(
    pair_id: 0,
    side: OrderSide::Sell,
    price: 110000,      // $0.11
    amount: 1000000000000000000000
);

// Order 3: 1000 SAGE at $0.12
otc_orderbook.place_limit_order(
    pair_id: 0,
    side: OrderSide::Sell,
    price: 120000,      // $0.12
    amount: 1000000000000000000000
);
```

**How users buy SAGE:**
```cairo
// User approves USDC
usdc.approve(OTC_ADDRESS, 100000000); // $100 USDC

// User places market buy
otc_orderbook.place_market_order(
    pair_id: 0,
    side: OrderSide::Buy,
    amount: 100000000  // $100 worth
);
// → User receives ~1000 SAGE at $0.10 (best ask)
// → You receive $100 USDC
```

### 4. Buyback Engine Configuration

```cairo
// Set minimum buyback amount ($10)
buyback_engine.set_config(BuybackConfig {
    min_buyback_amount: 10000000,     // $10 minimum
    max_buyback_amount: 1000000000,   // $1000 max per tx
    cooldown_period: 3600,            // 1 hour between buybacks
    auto_enabled: true,
    execution_venue: OTC_ADDRESS,     // Use your OTC orderbook
    max_slippage_bps: 500,            // 5% max slippage
});
```

### 5. Emergency Council Setup

```cairo
// Add trusted addresses to emergency council
sage_token.add_emergency_council(YOUR_MULTISIG_ADDRESS);
sage_token.add_emergency_council(BACKUP_ADDRESS);
```

---

## Gas Estimates

| Contract | Estimated Deployment Gas |
|----------|-------------------------|
| SAGE Token | ~0.02 ETH |
| Oracle Wrapper | ~0.005 ETH |
| Prover Staking | ~0.015 ETH |
| OTC Orderbook | ~0.02 ETH |
| Payment Router | ~0.015 ETH |
| Buyback Engine | ~0.01 ETH |
| Burn Manager | ~0.01 ETH |
| CDC Pool | ~0.025 ETH |
| Job Manager | ~0.015 ETH |
| Optimistic TEE | ~0.02 ETH |
| Privacy Router | ~0.015 ETH |
| **TOTAL** | **~0.17 ETH** |

Recommend having **0.25+ ETH** for deployments + post-config transactions.

---

## Verification Checklist

After deployment, verify:

- [ ] SAGE token total supply correct (1B tokens)
- [ ] Oracle returning correct SAGE price
- [ ] OTC orderbook has your sell orders
- [ ] Buyback engine configured with OTC venue
- [ ] TEE root certificates added
- [ ] Emergency council addresses set
- [ ] All contract addresses linked correctly

---

## Adding More Liquidity Later

When you get more funding:

```cairo
// Approve more SAGE
sage_token.approve(OTC_ADDRESS, NEW_AMOUNT);

// Place additional orders
otc_orderbook.place_limit_order(...);

// Or add to existing price levels
```

## Governance Parameter Changes

After launch, use governance proposals:

```cairo
// Create proposal to adjust inflation
sage_token.create_typed_proposal(
    description: 'Reduce inflation by 1%',
    proposal_type: 1,  // Major change
    inflation_change: -100,  // -1% in basis points
    burn_rate_change: 0
);

// Community votes
// If passed, execute after voting period
sage_token.execute_proposal(proposal_id);
```
