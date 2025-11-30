# CIRO Network - Cairo Smart Contracts

A comprehensive DePIN (Decentralized Physical Infrastructure) platform enabling global compute resource sharing through blockchain technology.

## 🚀 Quick Start

### Prerequisites
- [Scarb](https://docs.swmansion.com/scarb/) (Cairo package manager)
- [Starknet Foundry](https://foundry-rs.github.io/starknet-foundry/) (for testing and deployment)

### Build
```bash
cd cairo-contracts
scarb build
```

### Test
```bash
scarb test
```

## 📋 Contract Overview

### Core Contracts

| Contract | Purpose | Status |
|----------|---------|--------|
| **CIRO Token** | ERC20 governance token with advanced features | ✅ Deployed |
| **CDC Pool** | Compute Data Contribution rewards pool | ✅ Deployed |
| **Job Manager** | Decentralized job distribution and execution | ✅ Deployed |
| **Governance Treasury** | DAO governance with multi-sig controls | ✅ Deployed |

### Vesting Contracts

| Contract | Purpose | Status |
|----------|---------|--------|
| **Linear Vesting** | Time-based token release with cliff | ✅ Deployed |
| **Milestone Vesting** | Achievement-based token release | ✅ Deployed |
| **Burn Manager** | Revenue sharing and token burn mechanism | ✅ Deployed |

## 🌐 Network Information

### Testnet (Starknet Sepolia)
All contracts are deployed and fully functional on Starknet Sepolia testnet.

### Mainnet
Coming soon - pending community validation and security audits.

## 🔧 Development

### Contract Structure
```
src/
├── ciro_token.cairo          # Main governance token
├── cdc_pool.cairo           # Compute contribution rewards
├── job_manager.cairo        # Job distribution system
├── governance/              # DAO governance contracts
├── vesting/                 # Token vesting mechanisms
├── interfaces/             # Contract interfaces
└── utils/                  # Shared utilities and libraries
```

### Key Features
- **Token Economics**: 1B total supply with governance-controlled minting
- **Reward Mechanisms**: CDC Pool for compute contribution incentives
- **DAO Governance**: Community-driven decision making with multi-sig controls
- **Vesting System**: Flexible token distribution for teams, investors, and community
- **Security**: Comprehensive access controls and emergency mechanisms

## 📚 Documentation

For comprehensive documentation, please visit our [documentation site](../docs/book/html/index.html).

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](../docs/src/contributing/guide.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](../docs/src/legal/license.md) file for details.

## 🔗 Links

- [Website](https://ciro.network)
- [Documentation](../docs/book/html/index.html)
- [Community](../docs/src/resources/community/discord.md)

---

**⚠️ Important**: This is a DePIN protocol handling real compute resources and value. Please review all code thoroughly before use.
