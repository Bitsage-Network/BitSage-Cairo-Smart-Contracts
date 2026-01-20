#!/bin/bash
# BitSage Network - Account Setup for Sepolia Deployment
# This script helps you create a new Starknet account

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

RPC_URL="https://rpc.starknet-testnet.lava.build"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Starknet Account Setup (Sepolia)     ${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Generate a new private key using OpenSSL
echo -e "${YELLOW}Generating new private key...${NC}"
PRIVATE_KEY="0x$(openssl rand -hex 32)"
echo -e "${GREEN}Private Key: $PRIVATE_KEY${NC}"
echo ""

# For Starknet, we need to compute the public key and account address
# The account address depends on the account contract class hash (OpenZeppelin Account)
# Using the standard OZ Account class hash for Sepolia

# OpenZeppelin Account v0.8.1 class hash on Sepolia
OZ_ACCOUNT_CLASS_HASH="0x061dac032f228abef9c6626f995015233097ae253a7f72d68552db02f2971b8f"

echo -e "${YELLOW}To complete account setup:${NC}"
echo ""
echo "1. Save your private key securely:"
echo -e "   ${GREEN}export DEPLOYER_PRIVATE_KEY=$PRIVATE_KEY${NC}"
echo ""
echo "2. Compute your account address using sncast:"
echo -e "   ${BLUE}sncast account create --name bitsage_deployer --class-hash $OZ_ACCOUNT_CLASS_HASH${NC}"
echo ""
echo "3. Fund your account with Sepolia ETH from a faucet:"
echo "   - https://starknet-faucet.vercel.app/"
echo "   - https://faucet.goerli.starknet.io/ (select Sepolia)"
echo ""
echo "4. Deploy your account contract:"
echo -e "   ${BLUE}sncast account deploy --name bitsage_deployer --max-fee 0.01${NC}"
echo ""
echo "5. Export your account address:"
echo -e "   ${GREEN}export DEPLOYER_ADDRESS=<your_account_address>${NC}"
echo ""
echo "6. Run the deployment script:"
echo -e "   ${BLUE}./deployment/deploy_sepolia.sh${NC}"
echo ""
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}  IMPORTANT: Save your private key!    ${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""
echo "Private Key: $PRIVATE_KEY"
echo ""
echo "This key controls your deployment account. Store it securely!"
