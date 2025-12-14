# BitSage DeFi Integration Plan
## December 2025 - Starknet Ecosystem Integration

---

## ✅ Current Frontend Status (Already Correct!)

The **BitSage-Validator** frontend is already properly designed:

```
/src/app/(app)/bridge/page.tsx
  ✅ Uses StarkGate (external link)
  ✅ Uses AVNU for swaps (external link)
  ✅ Supports ETH, USDC, STRK bridging
  ✅ Privacy mode integration planned
```

**Key External Links (from `/lib/contracts/addresses.ts`):**
- StarkGate: https://starkgate.starknet.io
- AVNU: https://app.avnu.fi
- Starkscan: https://sepolia.starkscan.co

---

## ✅ Proper Starknet DeFi Integration (Dec 2025)

### 1. 🌉 BRIDGING - StarkGate Integration

**Reality**: Starknet uses **StarkGate** (official bridge) for L1↔L2 transfers.

**Options for SAGE Token:**

#### Option A: Use Existing Infrastructure (Recommended)
```
User wants SAGE on Starknet:
1. Buy ETH/USDC on Ethereum
2. Bridge via StarkGate to Starknet  
3. Swap for SAGE on Ekubo/JediSwap
```

#### Option B: Native Starknet Token (Current)
```
SAGE is deployed natively on Starknet
- No bridging needed for SAGE itself
- Users bridge other assets (ETH, USDC) to buy SAGE
```

#### Option C: Custom Bridge (Complex - Not Recommended)
```
Would require:
- L1 Solidity contract (deposit/withdraw)
- L2 Cairo contract (mint/burn)
- Starknet messaging integration
- Security audits ($50k+)
- Maintenance overhead
```

**Recommendation**: **Option B** - SAGE is native to Starknet. Users bridge USDC/ETH to buy SAGE.

**StarkGate Addresses (Mainnet - Dec 2025):**
```
ETH Bridge: 0x073314940630fd6dcda0d772d4c972c4e0a9946bef9dabf4ef84eda8ef542b82
USDC Bridge: 0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8
STRK Bridge: 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
```

---

### 2. 📊 ORACLE - Pragma Integration

**Reality**: Pragma is THE oracle on Starknet. We need to:

1. **Use their deployed contracts** (not create our own)
2. **Check if SAGE/USD exists** or use a proxy calculation

**Pragma Mainnet Addresses (Dec 2025):**
```cairo
// Pragma Oracle Contract
const PRAGMA_ORACLE: felt252 = 0x2a85bd616f912537c50a49a4076db02c00b29b2cdc8a197ce92ed1837fa875b;

// Summary Stats Contract (for aggregated data)
const PRAGMA_SUMMARY: felt252 = 0x49eefafae944d07744d07cc72a5bf14728a6fb463c3eae5bca13552f5d455fd;
```

**Available Pairs on Pragma:**
- ETH/USD ✅
- STRK/USD ✅
- USDC/USD ✅
- BTC/USD ✅
- SAGE/USD ❌ (would need to be added)

**Strategy for SAGE/USD Pricing:**

```
Option 1: Register SAGE with Pragma (requires partnership)
- Contact Pragma team
- Provide liquidity sources for price feeds
- Takes 2-4 weeks

Option 2: Calculate from DEX (immediate)
- Get SAGE/USDC price from Ekubo/JediSwap
- Get USDC/USD from Pragma (always ~$1.00)
- SAGE/USD = SAGE/USDC * USDC/USD
```

**Proper Pragma Integration Code:**
```cairo
use pragma_lib::abi::{IPragmaABIDispatcher, IPragmaABIDispatcherTrait};
use pragma_lib::types::{DataType, PragmaPricesResponse};

fn get_eth_usd_price() -> u128 {
    let oracle = IPragmaABIDispatcher { 
        contract_address: PRAGMA_ORACLE.try_into().unwrap() 
    };
    
    let response = oracle.get_data_median(DataType::SpotEntry('ETH/USD'));
    response.price
}
```

---

### 3. 💱 DEX - Liquidity Strategy

**Reality**: Building our own AMM is unnecessary. Starknet has mature DEXs.

**Starknet DEX Landscape (Dec 2025):**

| DEX | Type | TVL | Best For |
|-----|------|-----|----------|
| **Ekubo** | Concentrated Liquidity | ~$50M+ | Main liquidity, best rates |
| **JediSwap** | Uniswap V2 style | ~$20M+ | Simple swaps |
| **10kSwap** | Uniswap V2 | ~$10M+ | Alternative |
| **Avnu** | Aggregator | N/A | Best execution routing |

**Recommended Strategy:**

#### Phase 1: List on Ekubo (Primary)
```
Ekubo Factory: 0x00000005dd3d2f4429af886cd1a3b08289dbcea99a294197e9eb43b0e0325b4b

Steps:
1. Create SAGE/USDC pool on Ekubo
2. Provide initial liquidity ($50k-$100k recommended)
3. Set tick spacing and fee tier
```

#### Phase 2: Add JediSwap (Secondary)
```
JediSwap Router: 0x041fd22b238fa21cfcf5dd45a8548974d8263b3a531a60388411c5e230f97023

Steps:
1. Create SAGE/USDC pair
2. Add liquidity
3. Enable on Avnu aggregator
```

#### Phase 3: Avnu Integration (Aggregation)
```
Avnu automatically routes through all DEXs
Once listed on Ekubo + JediSwap, Avnu will include SAGE
```

**Liquidity Requirements:**
```
Minimum viable: $50,000 in SAGE/USDC
- $25,000 worth of SAGE
- $25,000 USDC

Recommended: $200,000+
- Better price stability
- Lower slippage
- Attracts more traders
```

---

### 4. 📋 Realistic Action Plan

#### Week 1: Foundation
- [ ] Verify SAGE token is properly deployed
- [ ] Confirm tokenomics and initial supply
- [ ] Prepare initial liquidity allocation

#### Week 2: DEX Listing
- [ ] Create Ekubo SAGE/USDC pool
- [ ] Provide initial liquidity
- [ ] Test swaps work correctly
- [ ] Create JediSwap pair as backup

#### Week 3: Oracle Setup
- [ ] Contact Pragma for SAGE listing (optional)
- [ ] Implement DEX-based price oracle as fallback
- [ ] Integrate pricing into protocol contracts

#### Week 4: Ecosystem Integration
- [ ] Register on DeFiLlama
- [ ] Add to Starknet token lists
- [ ] Integrate with Argent/Braavos wallets
- [ ] Submit to CoinGecko/CMC

---

### 5. 🔧 What Contracts We Actually Need

**DELETE these placeholder contracts:**
- ❌ `bridge/l1_bridge.cairo` - Not needed, use StarkGate
- ❌ `dex/amm_pool.cairo` - Not needed, use Ekubo/JediSwap

**KEEP but MODIFY:**
- ✅ `oracle/pragma_oracle.cairo` → Rename to `price_oracle.cairo`
  - Integrate with real Pragma addresses
  - Add DEX price fallback

**NEW contracts needed:**
```
src/integrations/
├── ekubo_integration.cairo    # Interface to Ekubo for liquidity ops
├── price_oracle.cairo         # Pragma + DEX price fetching  
└── starkgate_helper.cairo     # Helper for users to bridge (optional)
```

---

### 6. 💰 Budget Considerations

| Item | Cost | Notes |
|------|------|-------|
| Initial Liquidity | $50k-200k | Required for DEX listing |
| Security Audit | $20k-50k | For token + staking contracts |
| Pragma Listing | Free-$5k | May need partnership |
| Marketing/Launch | $10k-30k | Community building |
| Gas/Deployment | ~$500 | Minimal on Starknet |

---

### 7. 📞 Key Contacts

**Ekubo**: https://ekubo.org - Discord for listing
**JediSwap**: https://jediswap.xyz - Submit token
**Pragma**: https://pragma.build - Oracle registration
**Avnu**: https://avnu.fi - Auto-includes listed tokens
**Argent**: https://argent.xyz - Wallet integration
**Braavos**: https://braavos.app - Wallet integration

---

## Summary

**We should:**
1. ✅ Use existing DEXs (Ekubo, JediSwap) - NOT build our own AMM
2. ✅ Use StarkGate for bridging - NOT build custom bridge
3. ✅ Integrate with Pragma properly - NOT create placeholder
4. ✅ Focus on what makes BitSage unique - GPU proving, Obelysk protocol

**Our actual smart contract focus should be:**
- SAGE Token (done ✅)
- Staking/Economics (done ✅)
- Obelysk Protocol (done ✅)
- Prover Registry (done ✅)
- DEX/Oracle **integrations** (not implementations)

