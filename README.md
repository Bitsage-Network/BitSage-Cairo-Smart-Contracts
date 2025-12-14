# BitSage Network - Cairo Smart Contracts

A comprehensive DePIN (Decentralized Physical Infrastructure) platform for GPU compute and ZK proof generation on Starknet.

## 🚀 Quick Start

### Prerequisites
- [Scarb](https://docs.swmansion.com/scarb/) v2.8.0+ (Cairo package manager)
- [Starknet Foundry](https://foundry-rs.github.io/starknet-foundry/) (for testing)

### Build
```bash
scarb build
```

### Test
```bash
snforge test
```

## 📋 Contract Architecture

```
src/
├── economics/                 # Token Economics (Financial Model v2)
│   ├── fee_manager.cairo      # 20% protocol fee, 70/20/10 split
│   ├── collateral.cairo       # Weight-backed collateral system
│   ├── escrow.cairo           # Job payment escrow
│   ├── vesting.cairo          # Reward vesting (0-180 epochs)
│   └── pricing.cairo          # Dynamic pricing (Units of Compute)
│
├── obelysk/                   # Obelysk Protocol (GPU Proving)
│   ├── prover_registry.cairo  # GPU prover marketplace
│   ├── validator_registry.cairo # Validator management
│   ├── optimistic_tee.cairo   # TEE verification
│   └── stwo_verifier.cairo    # STWO proof verification
│
├── staking/                   # Staking System
│   └── prover_staking.cairo   # GPU worker staking
│
├── vesting/                   # Token Vesting
│   ├── linear_vesting.cairo   # Time-based release
│   ├── milestone_vesting.cairo # Achievement-based release
│   ├── burn_manager.cairo     # Token burn mechanism
│   └── treasury_timelock.cairo # Multi-sig treasury
│
├── governance/                # DAO Governance
│   └── governance_treasury.cairo
│
├── interfaces/                # Contract Interfaces
└── utils/                     # Shared Utilities
```

## 💰 Economics Overview

### Fee Distribution (Financial Model v2)
```
Client Payment (GMV)
       │
       ▼
┌──────────────────┐
│  Protocol Fee    │ 20% of GMV
└──────────────────┘
       │
  ┌────┼────┬───────────┐
  ▼    ▼    ▼           ▼
🔥70% 💰20% 📈10%      💵80%
BURN  TREAS STAKERS    WORKER
```

**Break-even GMV**: ~$1.875M/month at $75K OpEx

### Collateral System
| Component | Value |
|-----------|-------|
| Base Weight | 20% (unconditional) |
| Collateral Weight | 80% (requires backing) |
| Grace Period | 180 epochs (~6 months) |
| Unbonding | 7 days |

### Dynamic Pricing
| Utilization | Price Action |
|-------------|--------------|
| < 40% | ↓ Decrease (encourage usage) |
| 40-60% | → Stable (no change) |
| > 60% | ↑ Increase (moderate demand) |

- **Max Elasticity**: 5% per epoch
- **Grace Period**: 90 epochs free

### Reward Vesting
| Reward Type | Vesting Period |
|-------------|----------------|
| Work Rewards | Immediate |
| Subsidy Rewards | 180 epochs |
| Top Miner | 90 epochs |

## 🔐 Core Contracts

### Economics Module
| Contract | Description |
|----------|-------------|
| `FeeManager` | Processes transactions, burns 70%, distributes 20% treasury, 10% stakers |
| `Collateral` | Manages collateral deposits, weight calculation, slashing |
| `Escrow` | Locks job payments, handles refunds, completion payouts |
| `Vesting` | Linear vesting for work/subsidy/top miner rewards |
| `DynamicPricing` | Per-model pricing based on utilization |

### Obelysk Protocol
| Contract | Description |
|----------|-------------|
| `ProverRegistry` | GPU prover registration, TEE attestation, proof marketplace |
| `ValidatorRegistry` | Validator lifecycle: register, stake, jail, unjail |
| `OptimisticTEE` | TEE verification with optimistic challenges |
| `StwoVerifier` | STWO proof verification interface |

### Staking
| Contract | Description |
|----------|-------------|
| `ProverStaking` | GPU tier-based staking (Consumer → Frontier) |

## 🌐 Network Information

### Starknet Sepolia (Testnet)
Core contracts deployed and functional.

### Mainnet
Pending security audits.

## 🔧 Development

### Environment Setup
```bash
# Install Scarb
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Install Starknet Foundry
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh
```

### Local Testing
```bash
# Run all tests
snforge test

# Run specific test
snforge test test_fee_manager
```

### Deployment
```bash
# Deploy to Sepolia
./scripts/deploy_to_sepolia.sh
```

## 📊 Token Economics

| Parameter | Value |
|-----------|-------|
| Total Supply | 1B CIRO |
| Protocol Fee | 20% of GMV |
| Burn Rate | 70% of fees |
| Treasury Rate | 20% of fees |
| Staker Rate | 10% of fees |
| Min Validator Stake | 10,000 CIRO |
| Min Prover Stake | 1,000-25,000 CIRO (tier-based) |

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**⚠️ Important**: This protocol handles real compute resources and value. Review all code thoroughly before use.
