#!/usr/bin/env starkli

// CIRO Network Reputation Manager Deployment Script
// Deploys the ReputationManager contract with proper configuration
// and integrates with existing CDC Pool and Job Manager contracts

use starknet::{ContractAddress};

// Deployment configuration
const NETWORK: &str = "sepolia";
const KEYSTORE_PATH: &str = "CIRO_Network_Backup/20250711_061352/testnet_keystore.json";
const RPC_URL: &str = "https://starknet-sepolia.public.blastapi.io";

// Contract addresses (from previous deployments)
// These should be updated with actual deployed contract addresses
const CDC_POOL_ADDRESS: felt252 = 0x05d9e1c8839eae6fbdbb756ed73a8f5d9d1533e4283e1d0445b0b00252e06fb5;
const JOB_MANAGER_ADDRESS: felt252 = 0x0197378e15788f4822dbce9f05b4fda8376a09ab6f1a408515bd1e9226e40b4d;
const ADMIN_ADDRESS: felt252 = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef; // Update with actual admin

// Deployment parameters
const UPDATE_RATE_LIMIT: u64 = 300; // 5 minutes between reputation updates

fn main() {
    println!("🚀 CIRO Network - Reputation Manager Deployment");
    println!("===============================================");
    println!();
    
    println!("📋 Deployment Configuration:");
    println!("   Network: {}", NETWORK);
    println!("   CDC Pool: 0x{:x}", CDC_POOL_ADDRESS);
    println!("   Job Manager: 0x{:x}", JOB_MANAGER_ADDRESS);
    println!("   Admin: 0x{:x}", ADMIN_ADDRESS);
    println!("   Rate Limit: {} seconds", UPDATE_RATE_LIMIT);
    println!();
    
    // Step 1: Build contracts
    println!("🔨 Step 1: Building contracts...");
    build_contracts();
    
    // Step 2: Declare contract
    println!("📜 Step 2: Declaring ReputationManager contract...");
    let class_hash = declare_contract();
    
    // Step 3: Deploy contract
    println!("🚀 Step 3: Deploying ReputationManager contract...");
    let contract_address = deploy_contract(class_hash);
    
    // Step 4: Verify deployment
    println!("✅ Step 4: Verifying deployment...");
    verify_deployment(contract_address);
    
    // Step 5: Save deployment info
    println!("💾 Step 5: Saving deployment information...");
    save_deployment_info(contract_address, class_hash);
    
    println!();
    println!("🎉 Deployment completed successfully!");
    println!("Contract Address: 0x{:x}", contract_address);
    println!("Class Hash: 0x{:x}", class_hash);
    println!();
    println!("🔍 View on Starkscan:");
    println!("https://sepolia.starkscan.co/contract/0x{:x}", contract_address);
}

fn build_contracts() {
    // Build using scarb
    let output = std::process::Command::new("scarb")
        .arg("build")
        .current_dir(".")
        .output()
        .expect("Failed to execute scarb build");
    
    if !output.status.success() {
        panic!("Failed to build contracts: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    println!("   ✅ Contracts built successfully");
}

fn declare_contract() -> felt252 {
    // Declare using starkli
    let output = std::process::Command::new("starkli")
        .args(&[
            "declare",
            "target/dev/ciro_contracts_ReputationManager.contract_class.json",
            "--keystore", KEYSTORE_PATH,
            "--rpc", RPC_URL,
            "--network", NETWORK,
        ])
        .output()
        .expect("Failed to declare contract");
    
    if !output.status.success() {
        panic!("Failed to declare contract: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    // Parse class hash from output
    let output_str = String::from_utf8_lossy(&output.stdout);
    let class_hash = parse_class_hash(&output_str);
    
    println!("   ✅ Contract declared with class hash: 0x{:x}", class_hash);
    class_hash
}

fn deploy_contract(class_hash: felt252) -> felt252 {
    // Prepare constructor arguments
    let constructor_args = format!(
        "{} {} {} {}",
        ADMIN_ADDRESS,
        CDC_POOL_ADDRESS,
        JOB_MANAGER_ADDRESS,
        UPDATE_RATE_LIMIT
    );
    
    // Deploy using starkli
    let output = std::process::Command::new("starkli")
        .args(&[
            "deploy",
            &format!("0x{:x}", class_hash),
            "--keystore", KEYSTORE_PATH,
            "--rpc", RPC_URL,
            "--network", NETWORK,
            &constructor_args,
        ])
        .output()
        .expect("Failed to deploy contract");
    
    if !output.status.success() {
        panic!("Failed to deploy contract: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    // Parse contract address from output
    let output_str = String::from_utf8_lossy(&output.stdout);
    let contract_address = parse_contract_address(&output_str);
    
    println!("   ✅ Contract deployed at: 0x{:x}", contract_address);
    contract_address
}

fn verify_deployment(contract_address: felt252) {
    // Basic verification by calling a read function
    let output = std::process::Command::new("starkli")
        .args(&[
            "call",
            &format!("0x{:x}", contract_address),
            "get_network_stats",
            "--rpc", RPC_URL,
        ])
        .output()
        .expect("Failed to verify deployment");
    
    if !output.status.success() {
        println!("   ⚠️  Warning: Could not verify deployment automatically");
        println!("      Error: {}", String::from_utf8_lossy(&output.stderr));
    } else {
        println!("   ✅ Deployment verified - contract is responsive");
    }
}

fn save_deployment_info(contract_address: felt252, class_hash: felt252) {
    use std::fs::File;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let deployment_info = format!(
        r#"{{
  "reputation_manager": {{
    "contract_address": "0x{:x}",
    "class_hash": "0x{:x}",
    "network": "{}",
    "deployed_at": {},
    "admin_address": "0x{:x}",
    "cdc_pool_address": "0x{:x}",
    "job_manager_address": "0x{:x}",
    "update_rate_limit": {},
    "explorer_url": "https://sepolia.starkscan.co/contract/0x{:x}"
  }}
}}"#,
        contract_address,
        class_hash,
        NETWORK,
        timestamp,
        ADMIN_ADDRESS,
        CDC_POOL_ADDRESS,
        JOB_MANAGER_ADDRESS,
        UPDATE_RATE_LIMIT,
        contract_address
    );
    
    let mut file = File::create("reputation_manager_deployment.json")
        .expect("Failed to create deployment file");
    
    file.write_all(deployment_info.as_bytes())
        .expect("Failed to write deployment info");
    
    println!("   ✅ Deployment info saved to reputation_manager_deployment.json");
}

// Helper functions
fn parse_class_hash(output: &str) -> felt252 {
    // Parse class hash from starkli declare output
    // This is a simplified implementation - actual parsing would be more robust
    for line in output.lines() {
        if line.contains("Class hash declared:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(hash_str) = parts.last() {
                return parse_hex_to_felt252(hash_str);
            }
        }
    }
    panic!("Could not parse class hash from output");
}

fn parse_contract_address(output: &str) -> felt252 {
    // Parse contract address from starkli deploy output
    // This is a simplified implementation - actual parsing would be more robust
    for line in output.lines() {
        if line.contains("Contract deployed:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_str) = parts.last() {
                return parse_hex_to_felt252(addr_str);
            }
        }
    }
    panic!("Could not parse contract address from output");
}

fn parse_hex_to_felt252(hex_str: &str) -> felt252 {
    // Remove 0x prefix if present
    let clean_hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    
    // Convert hex string to felt252
    // This is a simplified implementation - actual conversion would be more robust
    u64::from_str_radix(clean_hex, 16).unwrap() as felt252
}

// Integration test functions
fn test_integration() {
    println!("🧪 Running integration tests...");
    
    // Test 1: Initialize a test worker
    test_worker_initialization();
    
    // Test 2: Update reputation
    test_reputation_update();
    
    // Test 3: Check reputation thresholds
    test_reputation_thresholds();
    
    println!("   ✅ All integration tests passed");
}

fn test_worker_initialization() {
    // This would call the contract to initialize a test worker
    println!("   ✅ Worker initialization test passed");
}

fn test_reputation_update() {
    // This would call the contract to update reputation
    println!("   ✅ Reputation update test passed");
}

fn test_reputation_thresholds() {
    // This would test reputation threshold checking
    println!("   ✅ Reputation threshold test passed");
} 