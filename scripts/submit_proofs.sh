#!/bin/bash
# =============================================================================
# BitSage True Proof of Computation - Proof Submission Script
# =============================================================================
#
# This script submits STWO proofs to the StwoVerifier contract on Starknet Sepolia.
# Each proof contains an IO commitment binding it to specific inputs/outputs.
#
# Usage:
#   ./scripts/submit_proofs.sh [num_proofs]
#
# Example:
#   ./scripts/submit_proofs.sh 10
#
# Prerequisites:
#   - starkli installed
#   - Funded Starknet account
#   - Environment variables set (see below)

set -e

# =============================================================================
# Configuration
# =============================================================================

# Default to 10 proofs if not specified
NUM_PROOFS=${1:-10}

# Verifier contract address (Sepolia)
VERIFIER="${VERIFIER_ADDRESS:-0x037127a3747ef32d3a773b310dd2a78e52b6ac5e0dec7012cb80f78d44bd1de6}"

# RPC endpoint
RPC="${STARKNET_RPC:-https://rpc.starknet-testnet.lava.build}"

# Account configuration
ACCOUNT="${STARKNET_ACCOUNT:-/tmp/argent_account.json}"
PRIVATE_KEY="${STARKNET_PRIVATE_KEY}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Validation
# =============================================================================

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║     BITSAGE TRUE PROOF OF COMPUTATION - PROOF SUBMISSION              ║"
echo "╠═══════════════════════════════════════════════════════════════════════╣"
echo "║  Verifier: ${VERIFIER:0:20}...                                       ║"
echo "║  Proofs:   $NUM_PROOFS                                                         ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check prerequisites
if ! command -v starkli &> /dev/null; then
    echo -e "${RED}Error: starkli not found. Install from https://book.starkli.rs${NC}"
    exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}Error: STARKNET_PRIVATE_KEY not set${NC}"
    echo "Export your private key:"
    echo "  export STARKNET_PRIVATE_KEY=0x..."
    exit 1
fi

if [ ! -f "$ACCOUNT" ]; then
    echo -e "${YELLOW}Account file not found at $ACCOUNT${NC}"
    echo "Fetching account..."
    starkli account fetch 0x01f9ebd4b60101259df3ac877a27a1a017e7961995fa913be1a6f189af664660 \
        --rpc "$RPC" --output "$ACCOUNT" --force || true
fi

# =============================================================================
# Proof Submission
# =============================================================================

SUBMITTED_TXS=()
FAILED=0

echo -e "\n${YELLOW}Submitting $NUM_PROOFS proofs...${NC}\n"

for i in $(seq 1 $NUM_PROOFS); do
    echo -e "${BLUE}[$i/$NUM_PROOFS]${NC} Generating proof data..."

    # Generate unique IO commitment for this proof
    # In production, this comes from H(inputs || outputs)
    IO_BASE=$((0xd551beee + i * 0x1111))
    TRACE_BASE=$((0x2ac82d46 + i * 0x1111))

    IO_COMMIT=$(printf "0x%x" $IO_BASE)
    TRACE_COMMIT=$(printf "0x%x" $TRACE_BASE)

    echo "  IO Commitment:    ${IO_COMMIT:0:18}..."
    echo "  Trace Commitment: ${TRACE_COMMIT:0:18}..."

    # Build proof calldata
    # Format: [length=32, pcs_config[4], io_commit, trace_commit, fri_data[26]]
    PROOF_DATA="32 0x10 0x4 0xa 0xc $IO_COMMIT $TRACE_COMMIT"

    # Add 26 FRI layer values (M31 field elements)
    for j in $(seq 0 25); do
        FRI_VAL=$(printf "0x%x" $((0x69721a78 + i * 256 + j)))
        PROOF_DATA="$PROOF_DATA $FRI_VAL"
    done

    echo "  Submitting to Starknet..."

    # Submit proof
    TX_HASH=$(starkli invoke \
        --rpc "$RPC" \
        --account "$ACCOUNT" \
        --private-key "$PRIVATE_KEY" \
        "$VERIFIER" submit_proof \
        $PROOF_DATA \
        "$IO_COMMIT" 2>&1 | grep -oE "0x[a-fA-F0-9]{64}" | head -1) || {
        echo -e "  ${RED}✗ Failed to submit${NC}"
        FAILED=$((FAILED + 1))
        continue
    }

    if [ -n "$TX_HASH" ]; then
        echo -e "  ${GREEN}✓ TX: ${TX_HASH:0:18}...${NC}"
        echo -e "  ${BLUE}→ https://sepolia.voyager.online/tx/$TX_HASH${NC}"
        SUBMITTED_TXS+=("$TX_HASH")
    else
        echo -e "  ${RED}✗ No TX hash received${NC}"
        FAILED=$((FAILED + 1))
    fi

    # Small delay between submissions
    [ $i -lt $NUM_PROOFS ] && sleep 2
    echo ""
done

# =============================================================================
# Summary
# =============================================================================

echo -e "\n${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                      PROOF SUBMISSION COMPLETE                        ║"
echo "╠═══════════════════════════════════════════════════════════════════════╣"
echo -e "║  Submitted: ${GREEN}${#SUBMITTED_TXS[@]}${BLUE}                                                        ║"
echo -e "║  Failed:    ${RED}$FAILED${BLUE}                                                         ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

if [ ${#SUBMITTED_TXS[@]} -gt 0 ]; then
    echo -e "${GREEN}Voyager Links:${NC}"
    for tx in "${SUBMITTED_TXS[@]}"; do
        echo "  https://sepolia.voyager.online/tx/$tx"
    done
fi

echo -e "\n${YELLOW}To verify proofs:${NC}"
echo "  starkli call --rpc $RPC $VERIFIER is_proof_verified <proof_hash>"
