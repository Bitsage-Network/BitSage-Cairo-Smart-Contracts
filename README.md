<p align="center">
  <img src="https://raw.githubusercontent.com/Bitsage-Network/brand/main/logo.svg" alt="BitSage Network" width="200"/>
</p>

<h1 align="center">BitSage Smart Contracts</h1>

<p align="center">
  <strong>The Economic Heart of Decentralized GPU Compute</strong>
</p>

<p align="center">
  <a href="#architecture">Architecture</a> •
  <a href="#economics">Economics</a> •
  <a href="#contracts">Contracts</a> •
  <a href="#quickstart">Quick Start</a> •
  <a href="#deployment">Deployment</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Cairo-2.8+-blue?style=flat-square" alt="Cairo"/>
  <img src="https://img.shields.io/badge/Starknet-Sepolia-purple?style=flat-square" alt="Network"/>
  <img src="https://img.shields.io/badge/License-BUSL--1.1-green?style=flat-square" alt="License"/>
</p>

---

## 🌟 Vision

BitSage Network is building the **decentralized infrastructure for verifiable GPU compute**. Our smart contracts form the economic backbone—enabling trustless payments, fair pricing, and cryptographic proof verification for GPU workers worldwide.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│     ██████╗ ██╗████████╗███████╗ █████╗  ██████╗ ███████╗                   │
│     ██╔══██╗██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝ ██╔════╝                   │
│     ██████╔╝██║   ██║   ███████╗███████║██║  ███╗█████╗                     │
│     ██╔══██╗██║   ██║   ╚════██║██╔══██║██║   ██║██╔══╝                     │
│     ██████╔╝██║   ██║   ███████║██║  ██║╚██████╔╝███████╗                   │
│     ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                   │
│                                                                             │
│              Powering the Future of Decentralized Compute                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

<h2 id="architecture">🏗️ Architecture</h2>

### System Overview

```
                              ┌─────────────────────┐
                              │      CLIENTS        │
                              │   (Job Requests)    │
                              └──────────┬──────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                           JOB ORCHESTRATION LAYER                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ JobManager   │  │   Escrow     │  │   Pricing    │  │  FeeManager  │   │
│  │              │◄─┤  (Payment    │◄─┤  (Dynamic)   │◄─┤  (70/20/10)  │   │
│  │ Dispatch     │  │   Lock)      │  │              │  │              │   │
│  └──────┬───────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────┼──────────────────────────────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                            COMPUTE LAYER                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   CDC Pool   │  │   Prover     │  │  Validator   │  │   Prover     │   │
│  │  (Worker     │  │  Registry    │  │  Registry    │  │   Staking    │   │
│  │   Matching)  │  │  (GPU TEE)   │  │              │  │              │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                          VERIFICATION LAYER                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │    STWO      │  │  Optimistic  │  │    Fraud     │  │   Proof      │   │
│  │   Verifier   │  │     TEE      │  │    Proof     │  │   Verifier   │   │
│  │  (ZK Proofs) │  │ (Challenge)  │  │              │  │              │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                          ECONOMIC LAYER                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Collateral  │  │   Vesting    │  │  Governance  │  │    CIRO      │   │
│  │  (20%/80%)   │  │  (180 epoch) │  │  Treasury    │  │    Token     │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└────────────────────────────────────────────────────────────────────────────┘
```

### Contract Directory

```
src/
│
├── 🪙 CORE TOKEN
│   └── ciro_token.cairo              # ERC20 with governance features
│
├── 💼 JOB ORCHESTRATION
│   ├── job_manager.cairo             # Job submission & assignment
│   ├── cdc_pool.cairo                # Worker pool management
│   └── reputation_manager.cairo      # Trust scoring system
│
├── 💰 ECONOMICS
│   ├── economics/
│   │   ├── fee_manager.cairo         # 20% fee → 70% burn / 20% treasury / 10% stakers
│   │   ├── collateral.cairo          # Weight-backed stake system
│   │   ├── escrow.cairo              # Payment locking
│   │   ├── vesting.cairo             # Reward distribution
│   │   └── pricing.cairo             # Dynamic Units of Compute
│   │
│   └── vesting/
│       ├── linear_vesting.cairo      # Time-based release
│       ├── milestone_vesting.cairo   # Achievement unlocks
│       ├── burn_manager.cairo        # Deflationary mechanics
│       └── treasury_timelock.cairo   # Multi-sig treasury
│
├── 🔐 OBELYSK PROTOCOL (GPU Proving)
│   └── obelysk/
│       ├── prover_registry.cairo     # GPU prover marketplace
│       ├── validator_registry.cairo  # Validator management
│       ├── optimistic_tee.cairo      # TEE with challenge period
│       └── stwo_verifier.cairo       # ZK proof verification
│
├── 📊 STAKING
│   └── staking/
│       └── prover_staking.cairo      # GPU tier-based staking
│
├── 🏛️ GOVERNANCE
│   └── governance/
│       └── governance_treasury.cairo # DAO treasury control
│
├── ⚔️ SECURITY
│   └── contracts/
│       ├── fraud_proof.cairo         # Dispute resolution
│       ├── proof_verifier.cairo      # Generic verification
│       ├── staking.cairo             # Worker staking
│       └── gamification.cairo        # Engagement incentives
│
└── 🔧 UTILITIES
    ├── interfaces/                   # Contract ABIs
    └── utils/                        # Shared libraries
```

---

<h2 id="economics">💎 Token Economics</h2>

### The CIRO Token

<table>
<tr>
<td width="50%">

#### Supply & Distribution

| Parameter | Value |
|-----------|-------|
| **Total Supply** | 1,000,000,000 CIRO |
| **Initial Circulating** | 50,000,000 CIRO |
| **Decimals** | 18 |
| **Token Standard** | ERC20 + Governance |

</td>
<td width="50%">

#### Staking Requirements

| Tier | Min Stake |
|------|-----------|
| 🎮 Consumer (RTX 4090) | 1,000 CIRO |
| 🖥️ Workstation (A6000) | 2,500 CIRO |
| 🏢 DataCenter (A100) | 5,000 CIRO |
| 🚀 Enterprise (H100) | 10,000 CIRO |
| ⚡ Frontier (B200) | 25,000 CIRO |

</td>
</tr>
</table>

### Fee Distribution Model

```
                         CLIENT PAYMENT (100% GMV)
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │      PROTOCOL FEE: 20%       │
                    │         ($20 of $100)        │
                    └──────────────┬───────────────┘
                                   │
           ┌───────────────────────┼───────────────────────┐
           │                       │                       │
           ▼                       ▼                       ▼
    ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
    │             │         │             │         │             │
    │  🔥 BURN    │         │  💰 TREASURY│         │  📈 STAKERS │
    │    70%      │         │     20%     │         │     10%     │
    │   ($14)     │         │    ($4)     │         │    ($2)     │
    │             │         │             │         │             │
    │ Deflationary│         │  Operations │         │ Real Yield  │
    │  Pressure   │         │  & Growth   │         │  Rewards    │
    │             │         │             │         │             │
    └─────────────┘         └─────────────┘         └─────────────┘

                    ┌──────────────────────────────┐
                    │      WORKER PAYMENT: 80%     │
                    │         ($80 of $100)        │
                    └──────────────────────────────┘
```

**Break-even GMV**: ~$1.875M/month at $75K monthly OpEx

### Collateral System

```
┌────────────────────────────────────────────────────────────────────────┐
│                         WEIGHT CALCULATION                             │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   Proof of Compute (PoC)  ──────►  POTENTIAL WEIGHT                    │
│                                          │                             │
│                          ┌───────────────┴───────────────┐             │
│                          │                               │             │
│                          ▼                               ▼             │
│                    ┌──────────┐                   ┌──────────────┐     │
│                    │   20%    │                   │     80%      │     │
│                    │   BASE   │                   │  COLLATERAL  │     │
│                    │  WEIGHT  │                   │   ELIGIBLE   │     │
│                    │  (FREE)  │                   │   (BACKED)   │     │
│                    └──────────┘                   └──────────────┘     │
│                                                                        │
│   Grace Period: 180 epochs (~6 months) - No collateral required        │
│   Unbonding Period: 7 days                                             │
│   Slashing: 10-50% based on violation severity                         │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Dynamic Pricing

Prices adjust automatically based on network utilization:

```
UTILIZATION          PRICE ACTION              RATIONALE
────────────────────────────────────────────────────────────────────
     0%  ┐
         │           ↓ DECREASE               Encourage usage
    40%  ┘           ───────────              when idle

    40%  ┐
         │           → STABLE                 Optimal zone
    60%  ┘           ───────────              no change needed

    60%  ┐
         │           ↑ INCREASE               Moderate demand
   100%  ┘           ───────────              prevent congestion

Max Elasticity: 5% per epoch
Grace Period: 90 epochs (FREE)
```

### Reward Vesting Schedule

| Reward Type | Vesting | Rationale |
|-------------|---------|-----------|
| 💼 **Work Rewards** | Immediate | Incentivize active participation |
| 🌱 **Subsidy Rewards** | 180 epochs | Long-term alignment |
| 🏆 **Top Miner** | 90 epochs | Retain top performers |

---

<h2 id="contracts">📜 Contract Reference</h2>

### Core Contracts

<details>
<summary><strong>🪙 CIRO Token</strong> - Governance-enabled ERC20</summary>

```cairo
// Key Features:
- Standard ERC20 transfers
- Governance voting power (time-weighted)
- Pausable for emergencies
- Multi-sig admin controls

// Governance Tiers:
- Veteran Holder: 365+ days → 2x voting power
- Long-term Holder: 90+ days → 1.5x voting power
```
</details>

<details>
<summary><strong>💼 Job Manager</strong> - Compute job orchestration</summary>

```cairo
// Workflow:
1. Client submits job → Escrow locks payment
2. CDC Pool matches worker → Job assigned
3. Worker executes → Proof generated
4. Verification passes → Payment released
5. Fees distributed → 70% burn / 20% treasury / 10% stakers
```
</details>

<details>
<summary><strong>🏊 CDC Pool</strong> - Worker pool management</summary>

```cairo
// Features:
- Worker registration with GPU specs
- Stake-weighted matching
- Reputation tracking
- Tier-based benefits
- Slashing for violations
```
</details>

<details>
<summary><strong>💰 Fee Manager</strong> - Economic distribution</summary>

```cairo
// Distribution:
process_transaction(gmv, worker) → {
    protocol_fee: gmv * 20%
    burn:     protocol_fee * 70%  → 🔥 Dead address
    treasury: protocol_fee * 20%  → 💰 Operations
    stakers:  protocol_fee * 10%  → 📈 Real yield
    worker:   gmv * 80%           → 💵 Direct payment
}
```
</details>

<details>
<summary><strong>🔐 Prover Registry</strong> - GPU prover marketplace</summary>

```cairo
// TEE Attestation:
- Intel TDX support
- NVIDIA H100 Confidential Compute
- AMD SEV-SNP
- Image hash verification
- Measurement whitelisting
```
</details>

<details>
<summary><strong>⚖️ Validator Registry</strong> - Consensus participation</summary>

```cairo
// Lifecycle:
Pending → Active → Jailed → Unjailed → Active
                      ↓
                Tombstoned (permanent)

// Requirements:
- Min stake: 10,000 CIRO
- TEE attestation
- Proof-of-Compute participation
```
</details>

---

<h2 id="quickstart">🚀 Quick Start</h2>

### Prerequisites

```bash
# Install Scarb (Cairo package manager)
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh

# Install Starknet Foundry (testing framework)
curl -L https://raw.githubusercontent.com/foundry-rs/starknet-foundry/master/scripts/install.sh | sh
```

### Build & Test

```bash
# Clone the repository
git clone https://github.com/Bitsage-Network/BitSage-Cairo-Smart-Contracts.git
cd BitSage-Cairo-Smart-Contracts

# Build all contracts
scarb build

# Run tests
snforge test

# Run specific test
snforge test test_fee_distribution
```

### Project Structure

```
BitSage-Cairo-Smart-Contracts/
├── src/                    # Contract source code
├── tests/                  # Test files
├── scripts/                # Deployment scripts
├── airdrop/                # Token distribution tools
├── Scarb.toml              # Project configuration
└── README.md               # You are here
```

---

<h2 id="deployment">🌐 Deployment</h2>

### Network Status

| Network | Status | Explorer |
|---------|--------|----------|
| **Sepolia** | ✅ Active | [Voyager](https://sepolia.voyager.online) |
| **Mainnet** | 🔜 Pending Audit | - |

### Deploy to Sepolia

```bash
# Set environment
export STARKNET_RPC="https://starknet-sepolia.public.blastapi.io"
export STARKNET_ACCOUNT="path/to/account.json"
export STARKNET_KEYSTORE="path/to/keystore.json"

# Deploy core contracts
./scripts/deploy_to_sepolia.sh

# Verify deployment
./scripts/verify_contracts.sh
```

### Contract Addresses (Sepolia)

```
CIRO Token:        0x0662c81...279a
Treasury Timelock: 0x04736828...089c7
CDC Pool:          [pending]
Job Manager:       [pending]
Fee Manager:       [pending]
```

---

## 📁 Additional Resources

### Airdrop Tools

Located in `airdrop/`:
- `airdrop.sh` - Batch token distribution script
- `recipients.json` - Recipient registry
- `airdrop_plan.md` - Distribution documentation

### Scripts

| Script | Purpose |
|--------|---------|
| `deploy_core.sh` | Deploy essential contracts |
| `deploy_full_system.sh` | Full deployment |
| `verify_contracts.sh` | Verify on explorer |
| `create_admin_accounts.sh` | Generate admin wallets |

---

## 🔒 Security

### Audit Status

- [ ] Internal review complete
- [ ] External audit scheduled
- [ ] Bug bounty program active

### Security Features

- **Pausable**: Emergency stop capability
- **Multi-sig**: Admin operations require approval
- **Timelock**: Treasury operations delayed
- **Rate limits**: Anti-abuse mechanisms
- **Slashing**: Economic penalties for violations

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing`
3. Write tests first (TDD)
4. Implement your changes
5. Run `scarb build && snforge test`
6. Submit PR

---

## 📄 License

This project is licensed under the **Business Source License 1.1** (BUSL-1.1).

- **Change Date**: January 1, 2029
- **Change License**: Apache License 2.0

See [LICENSE](LICENSE) for full details.

---

<p align="center">
  <strong>Built with ❤️ by the BitSage Team</strong>
</p>

<p align="center">
  <a href="https://bitsage.network">Website</a> •
  <a href="https://twitter.com/BitsageNetwork">Twitter</a> •
  <a href="https://discord.gg/bitsage">Discord</a> •
  <a href="https://docs.bitsage.network">Docs</a>
</p>
