#!/usr/bin/env bash
set -euo pipefail

# Create dedicated admin accounts for core contracts on Starknet Sepolia
# Requires: starkli, jq
# Usage:
#   ADMIN_PW='your_password' ./scripts/create_admin_accounts.sh
#
# Outputs account JSONs under cairo-contracts/admin_accounts/generated/
# and keystores under cairo-contracts/admin_accounts/keystores/

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
OUT_DIR="$ROOT_DIR/admin_accounts"
KS_DIR="$OUT_DIR/keystores"
GEN_DIR="$OUT_DIR/generated"
mkdir -p "$KS_DIR" "$GEN_DIR"

# RPC: prefer contracts.json if present
RPC_URL=${RPC_URL:-}
if [ -z "${RPC_URL}" ]; then
  if [ -f "$ROOT_DIR/../contracts.json" ]; then
    RPC_URL=$(jq -r '.rpc_url // empty' "$ROOT_DIR/../contracts.json")
  fi
fi
RPC_URL=${RPC_URL:-"https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_8/GUBwFqKhSgn4mwVbN6Sbn"}

# OpenZeppelin account class hash commonly used on Sepolia (OZ v0.7.x)
OZ_CLASS_HASH=${OZ_CLASS_HASH:-0x5b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564}

admins=(
  "cdc_pool"
  "job_manager"
  "reputation_manager"
  "governance_treasury"
)

PW="${ADMIN_PW:-}"
if [ -z "$PW" ]; then
  echo "Please provide ADMIN_PW env var for non-interactive keystore creation." >&2
  echo "Example: ADMIN_PW='c1r0$' ./scripts/create_admin_accounts.sh" >&2
  exit 1
fi

create_one() {
  name="$1"
  ks="$KS_DIR/${name}.keystore.json"
  acct="$GEN_DIR/${name}.account.json"

  if [ -f "$ks" ]; then
    echo "Keystore exists for $name — skipping creation"
  else
    echo "Creating keystore $ks ..."
    printf '%s\n' "$PW" | starkli signer keystore new "$ks" >/dev/null
  fi

  if [ -f "$acct" ]; then
    echo "Account file exists for $name — skipping init"
  else
    echo "Deriving address for $name ..."
    printf '%s\n' "$PW" | starkli account oz init \
      --keystore "$ks" \
      --class-hash "$OZ_CLASS_HASH" \
      "$acct" >/dev/null
  fi

  # Extract address
  addr=$(jq -r '.deployment.address // .address // .variant.address // empty' "$acct" 2>/dev/null || true)
  if [ -z "$addr" ] || [ "$addr" = "null" ]; then
    # Fallback: try to parse from file
    addr=$(grep -o '0x[0-9a-fA-F]\{10,\}' "$acct" | head -1 || true)
  fi
  echo "$name: $addr"
}

echo "RPC_URL: $RPC_URL"
for a in "${admins[@]}"; do
  create_one "$a"
done

echo
echo "Admin account files in: $GEN_DIR"
ls -1 "$GEN_DIR" | sed 's/^/  - /'
echo "Keystores in: $KS_DIR"
ls -1 "$KS_DIR" | sed 's/^/  - /'

echo
echo "Next steps:"
echo "1) Fund each printed address with ~0.01 STRK on Sepolia (for account deploy + future admin txs)."
echo "2) Deploy each account on-chain, e.g.:"
echo "   starkli account deploy $GEN_DIR/cdc_pool.account.json --keystore $KS_DIR/cdc_pool.keystore.json --rpc $RPC_URL --watch"
echo "3) After deployment, we can declare and deploy CDC Pool, Job Manager, Reputation Manager, and Governance Treasury using these admins."


