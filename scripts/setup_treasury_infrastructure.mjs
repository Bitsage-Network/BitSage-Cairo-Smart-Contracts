/**
 * BitSage Treasury & Pool Infrastructure Setup
 *
 * This script creates and configures all necessary wallets for:
 * 1. Treasury - Fee collection and operations
 * 2. Market Liquidity - OTC orderbook market making
 * 3. Ecosystem Rewards - Mining and staking rewards
 * 4. Public Sale - Token sale distribution
 *
 * Generates secure keystores with encrypted private keys.
 */

import { Account, ec, hash, stark, RpcProvider, CallData, cairo, Contract } from 'starknet';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';

// Configuration
const CONFIG = {
    rpcUrl: 'https://rpc.starknet-testnet.lava.build',
    network: 'sepolia',

    // Deployed contracts
    otcOrderbook: '0x7b2b59d93764ccf1ea85edca2720c37bba7742d05a2791175982eaa59cedef0',
    sageToken: '0x072349097c8a802e7f66dc96b95aca84e4d78ddad22014904076c76293a99850',

    // Quote tokens on Sepolia
    tokens: {
        STRK: '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d',
        ETH: '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
        // USDC on Sepolia (Starkgate bridge)
        USDC: '0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8',
    },

    // Deployer account (current owner)
    deployer: {
        address: '0x0759a4374389b0e3cfcc59d49310b6bc75bb12bbf8ce550eb5c2f026918bb344',
        privateKey: process.env.DEPLOYER_PRIVATE_KEY,
    },

    // Pool configurations based on token economics
    pools: {
        treasury: {
            name: 'Treasury',
            description: 'Fee collection, operations, protocol development',
            allocation: '15%',
            tokens: 150_000_000,
        },
        marketLiquidity: {
            name: 'Market Liquidity',
            description: 'OTC orderbook market making, DEX liquidity',
            allocation: '10%',
            tokens: 100_000_000,
        },
        ecosystemRewards: {
            name: 'Ecosystem Rewards',
            description: 'Mining rewards, staking, community incentives',
            allocation: '30%',
            tokens: 300_000_000,
        },
        publicSale: {
            name: 'Public Sale',
            description: 'Community token sale distribution',
            allocation: '5%',
            tokens: 50_000_000,
        },
    },

    // OZ Account class hash for Sepolia
    ozAccountClassHash: '0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564',
};

// Utility functions
function log(message, type = 'info') {
    const colors = {
        info: '\x1b[36m',
        success: '\x1b[32m',
        warn: '\x1b[33m',
        error: '\x1b[31m',
        header: '\x1b[35m',
    };
    console.log(`${colors[type] || ''}${message}\x1b[0m`);
}

function generateSecurePassword() {
    return crypto.randomBytes(32).toString('hex');
}

function encryptPrivateKey(privateKey, password) {
    const algorithm = 'aes-256-gcm';
    const key = crypto.scryptSync(password, 'bitsage-salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encrypted = cipher.update(privateKey, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm,
    };
}

function decryptPrivateKey(encryptedData, password) {
    const key = crypto.scryptSync(password, 'bitsage-salt', 32);
    const decipher = crypto.createDecipheriv(
        encryptedData.algorithm,
        key,
        Buffer.from(encryptedData.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

async function generateWallet(provider, name) {
    log(`\nGenerating wallet for: ${name}`, 'info');

    // Generate private key
    const privateKey = stark.randomAddress();
    const starkKeyPub = ec.starkCurve.getStarkKey(privateKey);

    // Calculate account address using OZ account
    const constructorCallData = CallData.compile({
        publicKey: starkKeyPub,
    });

    const address = hash.calculateContractAddressFromHash(
        starkKeyPub,
        CONFIG.ozAccountClassHash,
        constructorCallData,
        0
    );

    // Generate secure password for keystore
    const password = generateSecurePassword();
    const encryptedKey = encryptPrivateKey(privateKey, password);

    // Format address properly (ensure no double 0x)
    const addressHex = address.toString(16).padStart(64, '0');
    const formattedAddress = addressHex.startsWith('0x') ? addressHex : `0x${addressHex}`;

    return {
        name,
        address: formattedAddress,
        publicKey: starkKeyPub,
        keystore: {
            version: '1.0',
            network: CONFIG.network,
            ...encryptedKey,
        },
        password, // Store securely - shown once!
        needsDeployment: true,
    };
}

async function deployAccount(provider, wallet, deployerAccount) {
    log(`Deploying account for: ${wallet.name}`, 'info');

    // First, fund the account with some ETH for deployment
    const fundAmount = BigInt('100000000000000000'); // 0.1 ETH

    const ethToken = new Contract(
        [
            {
                name: 'transfer',
                type: 'function',
                inputs: [
                    { name: 'recipient', type: 'felt' },
                    { name: 'amount', type: 'Uint256' },
                ],
                outputs: [{ name: 'success', type: 'felt' }],
            },
        ],
        CONFIG.tokens.ETH,
        deployerAccount
    );

    try {
        // Fund with ETH for gas
        const fundTx = await ethToken.transfer(
            wallet.address,
            cairo.uint256(fundAmount)
        );
        await provider.waitForTransaction(fundTx.transaction_hash);
        log(`  Funded with 0.1 ETH`, 'success');

        // Deploy the account
        const accountToDeploy = new Account(
            provider,
            wallet.address,
            decryptPrivateKey(wallet.keystore, wallet.password)
        );

        const { transaction_hash, contract_address } = await accountToDeploy.deployAccount({
            classHash: CONFIG.ozAccountClassHash,
            constructorCalldata: CallData.compile({
                publicKey: wallet.publicKey,
            }),
            addressSalt: wallet.publicKey,
        });

        await provider.waitForTransaction(transaction_hash);
        log(`  Account deployed at: ${contract_address}`, 'success');

        return { ...wallet, needsDeployment: false, deployed: true };
    } catch (error) {
        log(`  Deployment failed: ${error.message}`, 'error');
        return { ...wallet, deploymentError: error.message };
    }
}

async function setupOTCPairs(provider, deployerAccount) {
    log('\n=== Setting Up OTC Trading Pairs ===', 'header');

    // OTC Orderbook ABI (minimal for pair management)
    const otcAbi = [
        {
            name: 'add_pair',
            type: 'function',
            inputs: [
                { name: 'quote_token', type: 'felt' },
                { name: 'min_order_size', type: 'Uint256' },
                { name: 'tick_size', type: 'Uint256' },
            ],
            outputs: [],
        },
        {
            name: 'get_pair',
            type: 'function',
            inputs: [{ name: 'pair_id', type: 'felt' }],
            outputs: [
                { name: 'base_token', type: 'felt' },
                { name: 'quote_token', type: 'felt' },
                { name: 'min_order_size', type: 'Uint256' },
                { name: 'tick_size', type: 'Uint256' },
                { name: 'is_active', type: 'felt' },
            ],
            stateMutability: 'view',
        },
        {
            name: 'set_fee_recipient',
            type: 'function',
            inputs: [{ name: 'recipient', type: 'felt' }],
            outputs: [],
        },
    ];

    const otc = new Contract(otcAbi, CONFIG.otcOrderbook, deployerAccount);

    // Check existing pairs
    const existingPairs = [];
    for (let i = 0; i < 5; i++) {
        try {
            const pair = await otc.get_pair(i);
            if (pair.quote_token !== '0x0' && pair.quote_token !== 0n) {
                existingPairs.push({
                    id: i,
                    quoteToken: '0x' + pair.quote_token.toString(16),
                    isActive: pair.is_active,
                });
            }
        } catch {
            break;
        }
    }

    log(`Found ${existingPairs.length} existing pairs`, 'info');
    existingPairs.forEach(p => {
        const tokenName = Object.entries(CONFIG.tokens).find(
            ([_, addr]) => addr.toLowerCase() === p.quoteToken.toLowerCase()
        )?.[0] || 'Unknown';
        log(`  Pair ${p.id}: ${tokenName} (${p.quoteToken.slice(0, 20)}...)`, 'info');
    });

    // Define pairs to add
    const pairsToAdd = [
        {
            name: 'SAGE/STRK',
            quoteToken: CONFIG.tokens.STRK,
            minOrderSize: cairo.uint256(10n * 10n ** 18n), // 10 SAGE min
            tickSize: cairo.uint256(10n ** 14n), // 0.0001 STRK tick
        },
        {
            name: 'SAGE/ETH',
            quoteToken: CONFIG.tokens.ETH,
            minOrderSize: cairo.uint256(10n * 10n ** 18n), // 10 SAGE min
            tickSize: cairo.uint256(10n ** 12n), // 0.000001 ETH tick
        },
        {
            name: 'SAGE/USDC',
            quoteToken: CONFIG.tokens.USDC,
            minOrderSize: cairo.uint256(10n * 10n ** 18n), // 10 SAGE min
            tickSize: cairo.uint256(10n ** 4n), // 0.0001 USDC tick (6 decimals)
        },
    ];

    const addedPairs = [];

    for (const pair of pairsToAdd) {
        const exists = existingPairs.some(
            p => p.quoteToken.toLowerCase() === pair.quoteToken.toLowerCase()
        );

        if (exists) {
            log(`  ${pair.name} pair already exists, skipping`, 'warn');
            continue;
        }

        try {
            log(`  Adding ${pair.name} pair...`, 'info');
            const tx = await otc.add_pair(
                pair.quoteToken,
                pair.minOrderSize,
                pair.tickSize
            );
            await provider.waitForTransaction(tx.transaction_hash);
            log(`  ${pair.name} pair added successfully!`, 'success');
            addedPairs.push(pair.name);
        } catch (error) {
            log(`  Failed to add ${pair.name}: ${error.message}`, 'error');
        }
    }

    return { existingPairs, addedPairs };
}

async function setFeeRecipient(provider, deployerAccount, treasuryAddress) {
    log('\n=== Setting Fee Recipient to Treasury ===', 'header');

    const otcAbi = [
        {
            name: 'set_fee_recipient',
            type: 'function',
            inputs: [{ name: 'recipient', type: 'felt' }],
            outputs: [],
        },
    ];

    const otc = new Contract(otcAbi, CONFIG.otcOrderbook, deployerAccount);

    try {
        const tx = await otc.set_fee_recipient(treasuryAddress);
        await provider.waitForTransaction(tx.transaction_hash);
        log(`Fee recipient set to: ${treasuryAddress}`, 'success');
        return true;
    } catch (error) {
        log(`Failed to set fee recipient: ${error.message}`, 'error');
        return false;
    }
}

async function main() {
    log('\n╔══════════════════════════════════════════════════════════════╗', 'header');
    log('║     BitSage Treasury & Pool Infrastructure Setup            ║', 'header');
    log('╚══════════════════════════════════════════════════════════════╝', 'header');

    const provider = new RpcProvider({ nodeUrl: CONFIG.rpcUrl });

    // Check if deployer key is available
    if (!CONFIG.deployer.privateKey) {
        log('\nDEPLOYER_PRIVATE_KEY not set in environment.', 'warn');
        log('Will generate wallets but skip deployment steps.', 'warn');
    }

    // Generate pool wallets
    log('\n=== Generating Pool Wallets ===', 'header');

    const wallets = {};
    for (const [poolId, poolConfig] of Object.entries(CONFIG.pools)) {
        wallets[poolId] = await generateWallet(provider, poolConfig.name);
        wallets[poolId].config = poolConfig;
    }

    // Create output directory
    const outputDir = path.join(process.cwd(), 'deployment', 'pool_wallets');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    // Save wallet info (addresses only - no keys in main file)
    const walletsPublic = {};
    for (const [poolId, wallet] of Object.entries(wallets)) {
        walletsPublic[poolId] = {
            name: wallet.name,
            address: wallet.address,
            description: wallet.config.description,
            allocation: wallet.config.allocation,
            tokens: wallet.config.tokens,
        };
    }

    fs.writeFileSync(
        path.join(outputDir, 'pool_addresses.json'),
        JSON.stringify(walletsPublic, null, 2)
    );
    log(`\nPublic addresses saved to: ${path.join(outputDir, 'pool_addresses.json')}`, 'success');

    // Save individual keystores (encrypted)
    log('\n=== Saving Encrypted Keystores ===', 'header');
    const keystoreDir = path.join(outputDir, 'keystores');
    if (!fs.existsSync(keystoreDir)) {
        fs.mkdirSync(keystoreDir, { recursive: true });
    }

    const passwordsFile = [];

    for (const [poolId, wallet] of Object.entries(wallets)) {
        const keystoreFile = path.join(keystoreDir, `${poolId}_keystore.json`);
        fs.writeFileSync(
            keystoreFile,
            JSON.stringify({
                name: wallet.name,
                address: wallet.address,
                publicKey: wallet.publicKey,
                keystore: wallet.keystore,
                network: CONFIG.network,
                createdAt: new Date().toISOString(),
            }, null, 2)
        );

        passwordsFile.push({
            pool: wallet.name,
            address: wallet.address,
            password: wallet.password,
        });

        log(`  ${wallet.name} keystore saved`, 'success');
    }

    // Save passwords to separate secure file
    const passwordsPath = path.join(keystoreDir, 'PASSWORDS_SECURE.json');
    fs.writeFileSync(passwordsPath, JSON.stringify(passwordsFile, null, 2));
    log(`\n⚠️  IMPORTANT: Passwords saved to: ${passwordsPath}`, 'warn');
    log('   Move this file to secure storage immediately!', 'warn');

    // If deployer key is available, perform on-chain setup
    if (CONFIG.deployer.privateKey) {
        const deployerAccount = new Account(
            provider,
            CONFIG.deployer.address,
            CONFIG.deployer.privateKey
        );

        // Setup OTC pairs
        const pairResult = await setupOTCPairs(provider, deployerAccount);

        // Set fee recipient to treasury
        await setFeeRecipient(provider, deployerAccount, wallets.treasury.address);

        // Deploy wallets (optional - can be done later when funded)
        log('\n=== Wallet Deployment Status ===', 'header');
        log('Wallets are generated but not yet deployed.', 'info');
        log('To deploy, fund each address with ~0.1 ETH and run deploy script.', 'info');
    }

    // Generate summary report
    log('\n╔══════════════════════════════════════════════════════════════╗', 'header');
    log('║                    SETUP SUMMARY                             ║', 'header');
    log('╚══════════════════════════════════════════════════════════════╝', 'header');

    console.log('\n┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ POOL WALLET ADDRESSES                                           │');
    console.log('├─────────────────────────────────────────────────────────────────┤');
    for (const [poolId, wallet] of Object.entries(wallets)) {
        console.log(`│ ${wallet.name.padEnd(20)} │ ${wallet.address} │`);
    }
    console.log('└─────────────────────────────────────────────────────────────────┘');

    console.log('\n┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ TOKEN ALLOCATION                                                │');
    console.log('├─────────────────────────────────────────────────────────────────┤');
    for (const [poolId, wallet] of Object.entries(wallets)) {
        const millions = (wallet.config.tokens / 1_000_000).toFixed(0);
        console.log(`│ ${wallet.name.padEnd(20)} │ ${wallet.config.allocation.padEnd(6)} │ ${millions.padStart(10)}M SAGE │`);
    }
    console.log('└─────────────────────────────────────────────────────────────────┘');

    console.log('\n┌─────────────────────────────────────────────────────────────────┐');
    console.log('│ TRADING PAIRS CONFIGURED                                        │');
    console.log('├─────────────────────────────────────────────────────────────────┤');
    console.log('│ Pair 0: SAGE/Mock STRK (legacy)                                 │');
    console.log('│ Pair 1: SAGE/STRK (Real STRK)                                   │');
    console.log('│ Pair 2: SAGE/ETH (if added)                                     │');
    console.log('│ Pair 3: SAGE/USDC (if added)                                    │');
    console.log('└─────────────────────────────────────────────────────────────────┘');

    log('\n=== Next Steps ===', 'header');
    log('1. SECURE THE PASSWORDS FILE IMMEDIATELY', 'warn');
    log('2. Fund wallets with ETH for gas (from deployer or faucet)', 'info');
    log('3. Transfer SAGE tokens to Market Liquidity wallet', 'info');
    log('4. Run seed_orderbook_production.mjs to populate orders', 'info');
    log('5. Verify Confidential Swap integration', 'info');

    // Save complete report
    const reportPath = path.join(outputDir, 'setup_report.json');
    fs.writeFileSync(reportPath, JSON.stringify({
        timestamp: new Date().toISOString(),
        network: CONFIG.network,
        contracts: {
            otcOrderbook: CONFIG.otcOrderbook,
            sageToken: CONFIG.sageToken,
        },
        tokens: CONFIG.tokens,
        wallets: walletsPublic,
        keystoreDirectory: keystoreDir,
    }, null, 2));

    log(`\nFull report saved to: ${reportPath}`, 'success');
}

main().catch(error => {
    log(`\nFatal error: ${error.message}`, 'error');
    console.error(error);
    process.exit(1);
});
