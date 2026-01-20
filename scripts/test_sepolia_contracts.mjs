import { RpcProvider, Contract, json } from 'starknet';
import { readFileSync } from 'fs';

// Sepolia RPC
const provider = new RpcProvider({
    nodeUrl: 'https://rpc.starknet-testnet.lava.build'
});

// Contract addresses (deployed 2025-12-31)
const CONTRACTS = {
    OTC_ORDERBOOK: "0x07dc7794611840bf2682ac9fedbc9e735297f49b3adecac75a912c8a6d058034",
    PRIVACY_POOLS: "0x03e6b8684b1b1d55b88bd917b08df820fa3f23c92e19bab168e569bda430ef73",
    CONFIDENTIAL_SWAP: "0x00f4bfe6593c88fbbc95b30f32347a556db2c1be4a34982d8b3161f9e62a2ef1",
    REFERRAL_SYSTEM: "0x00ca4865931c8f9e31b4ad60fec050a6103d2029a719d438f1e2d00608596eb",
    FAUCET: "0x07943ad334da99ab3dd138ff14d2045a7d962f1a426a4dd909fda026f37acf9f",
    SAGE_TOKEN: "0x04321b7282ae6aa354988eed57f2ff851314af8524de8b1f681a128003cc4ea5",
};

// Simple call helper
async function callContract(address, entrypoint, calldata = []) {
    try {
        const result = await provider.callContract({
            contractAddress: address,
            entrypoint,
            calldata
        });
        return result;
    } catch (err) {
        return { error: err.message };
    }
}

async function testOTCOrderbook() {
    console.log('\n=== Testing OTC Orderbook ===');
    console.log('Address:', CONTRACTS.OTC_ORDERBOOK);

    // Test get_config
    const config = await callContract(CONTRACTS.OTC_ORDERBOOK, 'get_config');
    if (config.error) {
        console.log('get_config: ERROR -', config.error);
    } else {
        console.log('get_config:', {
            maker_fee_bps: parseInt(config[0], 16),
            taker_fee_bps: parseInt(config[1], 16),
            default_expiry: parseInt(config[2], 16),
            max_orders_per_user: parseInt(config[3], 16),
            paused: config[4] !== '0x0'
        });
    }

    // Test get_pair_count
    const pairCount = await callContract(CONTRACTS.OTC_ORDERBOOK, 'get_pair_count');
    if (!pairCount.error) {
        console.log('Pair count:', parseInt(pairCount[0], 16));
    }

    // Test get_owner
    const owner = await callContract(CONTRACTS.OTC_ORDERBOOK, 'get_owner');
    if (!owner.error) {
        console.log('Owner:', owner[0]);
    }
}

async function testPrivacyPools() {
    console.log('\n=== Testing Privacy Pools ===');
    console.log('Address:', CONTRACTS.PRIVACY_POOLS);

    // Test is_initialized
    const initialized = await callContract(CONTRACTS.PRIVACY_POOLS, 'is_initialized');
    if (initialized.error) {
        console.log('is_initialized: ERROR -', initialized.error);
    } else {
        console.log('is_initialized:', initialized[0] !== '0x0');
    }

    // Test get_owner
    const owner = await callContract(CONTRACTS.PRIVACY_POOLS, 'get_owner');
    if (!owner.error) {
        console.log('Owner:', owner[0]);
    }

    // Test get_global_deposit_root
    const root = await callContract(CONTRACTS.PRIVACY_POOLS, 'get_global_deposit_root');
    if (!root.error) {
        console.log('Global deposit root:', root[0]);
    }
}

async function testConfidentialSwap() {
    console.log('\n=== Testing Confidential Swap ===');
    console.log('Address:', CONTRACTS.CONFIDENTIAL_SWAP);

    // Test get_owner
    const owner = await callContract(CONTRACTS.CONFIDENTIAL_SWAP, 'get_owner');
    if (owner.error) {
        console.log('get_owner: ERROR -', owner.error);
    } else {
        console.log('Owner:', owner[0]);
    }

    // Test is_paused
    const paused = await callContract(CONTRACTS.CONFIDENTIAL_SWAP, 'is_paused');
    if (!paused.error) {
        console.log('Is paused:', paused[0] !== '0x0');
    }

    // Test get_order_count
    const orderCount = await callContract(CONTRACTS.CONFIDENTIAL_SWAP, 'get_order_count');
    if (!orderCount.error) {
        console.log('Order count:', parseInt(orderCount[0], 16));
    }
}

async function testReferralSystem() {
    console.log('\n=== Testing Referral System ===');
    console.log('Address:', CONTRACTS.REFERRAL_SYSTEM);

    // Test get_config
    const config = await callContract(CONTRACTS.REFERRAL_SYSTEM, 'get_config');
    if (config.error) {
        console.log('get_config: ERROR -', config.error);
    } else {
        console.log('get_config (raw):', config.slice(0, 5));
    }

    // Test get_owner
    const owner = await callContract(CONTRACTS.REFERRAL_SYSTEM, 'get_owner');
    if (!owner.error) {
        console.log('Owner:', owner[0]);
    }
}

async function testFaucet() {
    console.log('\n=== Testing Faucet ===');
    console.log('Address:', CONTRACTS.FAUCET);

    // Test get_config
    const config = await callContract(CONTRACTS.FAUCET, 'get_config');
    if (config.error) {
        console.log('get_config: ERROR -', config.error);
    } else {
        const dripAmount = BigInt(config[0]);
        console.log('get_config:', {
            drip_amount: (dripAmount / BigInt(10**18)).toString() + ' SAGE',
            cooldown: parseInt(config[1], 16) + ' seconds',
            max_claims: parseInt(config[2], 16),
            paused: config[3] !== '0x0'
        });
    }

    // Test get_balance
    const balance = await callContract(CONTRACTS.FAUCET, 'get_balance');
    if (!balance.error) {
        const bal = BigInt(balance[0]);
        console.log('Faucet balance:', (bal / BigInt(10**18)).toString() + ' SAGE');
    }
}

async function testSAGEToken() {
    console.log('\n=== Testing SAGE Token ===');
    console.log('Address:', CONTRACTS.SAGE_TOKEN);

    // Test name
    const name = await callContract(CONTRACTS.SAGE_TOKEN, 'name');
    if (!name.error) {
        // Decode felt252 to string
        const decoded = Buffer.from(name[0].replace('0x', ''), 'hex').toString().replace(/\0/g, '');
        console.log('Name:', decoded || name[0]);
    }

    // Test symbol
    const symbol = await callContract(CONTRACTS.SAGE_TOKEN, 'symbol');
    if (!symbol.error) {
        const decoded = Buffer.from(symbol[0].replace('0x', ''), 'hex').toString().replace(/\0/g, '');
        console.log('Symbol:', decoded || symbol[0]);
    }

    // Test total_supply
    const supply = await callContract(CONTRACTS.SAGE_TOKEN, 'total_supply');
    if (!supply.error) {
        const totalSupply = BigInt(supply[0]);
        console.log('Total supply:', (totalSupply / BigInt(10**18)).toString() + ' SAGE');
    }
}

async function main() {
    console.log('BitSage Sepolia Contract Tests');
    console.log('==============================');

    const chainId = await provider.getChainId();
    console.log('Chain ID:', chainId);
    console.log('Network: Starknet Sepolia');

    await testSAGEToken();
    await testOTCOrderbook();
    await testPrivacyPools();
    await testConfidentialSwap();
    await testReferralSystem();
    await testFaucet();

    console.log('\n==============================');
    console.log('Tests complete!');
}

main().catch(console.error);
