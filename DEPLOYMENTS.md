### CIRO Network – Sepolia Deployments (Canonical Record)

This file tracks the latest known contract addresses per network. Values marked as pending mean no successful deployment address is recorded in this repository for the current session.

Network: Sepolia

- CIRO Token: `0x0662c81332894247404fff35313f84d0d832b5eeaaaa6f58e6d32c4dd66d279a`
- Treasury Timelock: `0x04736828c69fda6977bdb97c982db6bf1bbcae0396a2faac450b2ec7338089c7`
- Reputation Manager: pending (no successful deployment recorded in this session)
- CDC Pool: pending (no successful deployment recorded in this session)
- Job Manager: pending (no successful deployment recorded in this session)

Sources of truth used by services:
- Root `contracts.json` – consumed by the indexer/dashboard for CIRO token and other core addresses
- `cairo-contracts/reputation_manager_deployment.json` – used to auto-load RM address when present

To update after deployment:
1) Write addresses to `contracts.json` at repo root.
2) If Reputation Manager was deployed, update `cairo-contracts/reputation_manager_deployment.json` with `contract_address` and `class_hash`.
3) Restart the indexer and dashboard.


