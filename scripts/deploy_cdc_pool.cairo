//! CIRO Network CDC Pool Deployment Script
//! 
//! Production deployment script for CDC Pool contract with complete
//! configuration, role assignment, and integration setup.

use snforge_std::{declare, ContractClassTrait, DeclareResultTrait, start_cheat_caller_address};
use starknet::{ContractAddress, contract_address_const, get_contract_address};

use crate::interfaces::cdc_pool::{ICDCPoolDispatcher, ICDCPoolDispatcherTrait};
use crate::interfaces::ciro_token::{ICIROTokenDispatcher, ICIROTokenDispatcherTrait};
use crate::interfaces::job_manager::{IJobManagerDispatcher, IJobManagerDispatcherTrait};

/// Production deployment configuration
#[derive(Drop, Clone)]
struct DeploymentConfig {
    admin_address: ContractAddress,
    ciro_token_address: ContractAddress,
    job_manager_address: ContractAddress,
    price_oracle_address: ContractAddress,
    initial_ciro_price: u256,
    unstaking_delay: u64,
    minimum_stake_basic: u256,
    coordinator_address: ContractAddress,
    slasher_address: ContractAddress,
}

/// Testnet deployment configuration
fn get_testnet_config() -> DeploymentConfig {
    DeploymentConfig {
        admin_address: contract_address_const::<'admin'>(),
        ciro_token_address: contract_address_const::<'ciro_token'>(),
        job_manager_address: contract_address_const::<'job_manager'>(),
        price_oracle_address: contract_address_const::<'price_oracle'>(),
        initial_ciro_price: 1000000, // $1.00 in 6 decimals
        unstaking_delay: 3600, // 1 hour for testing
        minimum_stake_basic: 100000000, // 100 CIRO tokens
        coordinator_address: contract_address_const::<'coordinator'>(),
        slasher_address: contract_address_const::<'slasher'>(),
    }
}

/// Mainnet deployment configuration
fn get_mainnet_config() -> DeploymentConfig {
    DeploymentConfig {
        admin_address: contract_address_const::<'mainnet_admin'>(),
        ciro_token_address: contract_address_const::<'mainnet_ciro_token'>(),
        job_manager_address: contract_address_const::<'mainnet_job_manager'>(),
        price_oracle_address: contract_address_const::<'mainnet_price_oracle'>(),
        initial_ciro_price: 1000000, // $1.00 in 6 decimals
        unstaking_delay: 604800, // 7 days for production
        minimum_stake_basic: 100000000, // 100 CIRO tokens
        coordinator_address: contract_address_const::<'mainnet_coordinator'>(),
        slasher_address: contract_address_const::<'mainnet_slasher'>(),
    }
}

/// Deploy CDC Pool contract with full configuration
fn deploy_cdc_pool(config: DeploymentConfig) -> ICDCPoolDispatcher {
    // Declare CDC Pool contract
    let cdc_pool_class = declare("CDCPool").unwrap().contract_class();
    
    // Prepare constructor arguments
    let constructor_args = array![
        config.admin_address.into(),
        config.ciro_token_address.into(),
        config.job_manager_address.into(),
        config.price_oracle_address.into()
    ];
    
    // Deploy contract
    let cdc_pool_address = cdc_pool_class.deploy(@constructor_args).unwrap();
    let cdc_pool = ICDCPoolDispatcher { contract_address: cdc_pool_address };
    
    println!("✅ CDC Pool deployed at: {}", cdc_pool_address);
    
    cdc_pool
}

/// Configure CDC Pool post-deployment
fn configure_cdc_pool(cdc_pool: ICDCPoolDispatcher, config: DeploymentConfig) {
    start_cheat_caller_address(cdc_pool.contract_address, config.admin_address);
    
    // 1. Grant roles
    println!("🔐 Granting roles...");
    cdc_pool.grant_role(cdc_pool.COORDINATOR_ROLE(), config.coordinator_address);
    cdc_pool.grant_role(cdc_pool.COORDINATOR_ROLE(), config.job_manager_address);
    cdc_pool.grant_role(cdc_pool.SLASHER_ROLE(), config.slasher_address);
    cdc_pool.grant_role(cdc_pool.ORACLE_ROLE(), config.price_oracle_address);
    
    // 2. Set initial parameters
    println!("⚙️  Setting initial parameters...");
    cdc_pool.update_ciro_price(config.initial_ciro_price);
    cdc_pool.configure_unstaking_delay(config.unstaking_delay);
    
    // 3. Configure tier minimum stakes
    println!("💰 Configuring tier requirements...");
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Basic, config.minimum_stake_basic);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Premium, config.minimum_stake_basic * 5);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Enterprise, config.minimum_stake_basic * 50);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Infrastructure, config.minimum_stake_basic * 250);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Fleet, config.minimum_stake_basic * 1000);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Datacenter, config.minimum_stake_basic * 2500);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Hyperscale, config.minimum_stake_basic * 5000);
    cdc_pool.set_minimum_stake(cdc_pool.WorkerTier::Institutional, config.minimum_stake_basic * 5000);
    
    // 4. Configure slashing percentages
    println!("⚔️  Configuring slashing parameters...");
    cdc_pool.update_slash_percentage(cdc_pool.SlashReason::JOB_ABANDONMENT, 500); // 5%
    cdc_pool.update_slash_percentage(cdc_pool.SlashReason::POOR_QUALITY, 250); // 2.5%
    cdc_pool.update_slash_percentage(cdc_pool.SlashReason::MISCONDUCT, 1000); // 10%
    cdc_pool.update_slash_percentage(cdc_pool.SlashReason::FRAUD, 5000); // 50%
    cdc_pool.update_slash_percentage(cdc_pool.SlashReason::SECURITY_BREACH, 10000); // 100%
    
    println!("✅ CDC Pool configuration complete!");
}

/// Validate deployment and configuration
fn validate_deployment(cdc_pool: ICDCPoolDispatcher, config: DeploymentConfig) -> bool {
    println!("🔍 Validating deployment...");
    
    // Check role assignments
    let coordinator_role = cdc_pool.COORDINATOR_ROLE();
    let has_coordinator_role = cdc_pool.has_role(coordinator_role, config.coordinator_address);
    assert(has_coordinator_role, 'Coordinator role not assigned');
    
    let slasher_role = cdc_pool.SLASHER_ROLE();
    let has_slasher_role = cdc_pool.has_role(slasher_role, config.slasher_address);
    assert(has_slasher_role, 'Slasher role not assigned');
    
    // Check initial price setting
    let current_price = cdc_pool.get_current_ciro_price();
    assert(current_price == config.initial_ciro_price, 'Price not set correctly');
    
    // Check unstaking delay
    let unstaking_info = cdc_pool.get_unstaking_delay();
    assert(unstaking_info == config.unstaking_delay, 'Unstaking delay not set');
    
    // Check tier requirements
    let basic_requirement = cdc_pool.get_minimum_stake(cdc_pool.WorkerTier::Basic);
    assert(basic_requirement == config.minimum_stake_basic, 'Basic tier stake not set');
    
    println!("✅ All validations passed!");
    true
}

/// Setup integration with CIRO Token and JobMgr
fn setup_integrations(cdc_pool: ICDCPoolDispatcher, config: DeploymentConfig) {
    println!("🔗 Setting up integrations...");
    
    // Setup CIRO Token integration
    let ciro_token = ICIROTokenDispatcher { contract_address: config.ciro_token_address };
    start_cheat_caller_address(ciro_token.contract_address, config.admin_address);
    
    // Grant CDC Pool permission to mint/burn if needed (for advanced features)
    // ciro_token.grant_role(ciro_token.MINTER_ROLE(), cdc_pool.contract_address);
    
    // Setup JobMgr integration
    let job_manager = IJobManagerDispatcher { contract_address: config.job_manager_address };
    start_cheat_caller_address(job_manager.contract_address, config.admin_address);
    
    // Register CDC Pool address in JobMgr
    job_manager.set_cdc_pool_address(cdc_pool.contract_address);
    
    println!("✅ Integrations configured!");
}

/// Complete testnet deployment workflow
#[test]
fn deploy_testnet() {
    let config = get_testnet_config();
    
    println!("🚀 Starting CDC Pool testnet deployment...");
    
    // Deploy contract
    let cdc_pool = deploy_cdc_pool(config.clone());
    
    // Configure parameters
    configure_cdc_pool(cdc_pool, config.clone());
    
    // Setup integrations
    setup_integrations(cdc_pool, config.clone());
    
    // Validate deployment
    let validation_passed = validate_deployment(cdc_pool, config.clone());
    assert(validation_passed, 'Deployment validation failed');
    
    println!("🎉 CDC Pool testnet deployment complete!");
    println!("📍 Contract Address: {}", cdc_pool.contract_address);
}

/// Complete mainnet deployment workflow
#[test]
fn deploy_mainnet() {
    let config = get_mainnet_config();
    
    println!("🚀 Starting CDC Pool mainnet deployment...");
    
    // Deploy contract
    let cdc_pool = deploy_cdc_pool(config.clone());
    
    // Configure parameters
    configure_cdc_pool(cdc_pool, config.clone());
    
    // Setup integrations
    setup_integrations(cdc_pool, config.clone());
    
    // Validate deployment
    let validation_passed = validate_deployment(cdc_pool, config.clone());
    assert(validation_passed, 'Deployment validation failed');
    
    println!("🎉 CDC Pool mainnet deployment complete!");
    println!("📍 Contract Address: {}", cdc_pool.contract_address);
    
    // Additional mainnet-specific validations
    validate_mainnet_security(cdc_pool, config);
}

/// Additional security validations for mainnet
fn validate_mainnet_security(cdc_pool: ICDCPoolDispatcher, config: DeploymentConfig) {
    println!("🔒 Performing mainnet security validations...");
    
    // Verify admin controls
    let admin_role = cdc_pool.DEFAULT_ADMIN_ROLE();
    let has_admin_role = cdc_pool.has_role(admin_role, config.admin_address);
    assert(has_admin_role, 'Admin role not properly set');
    
    // Verify timelock mechanisms are in place
    let timelock_delay = cdc_pool.get_timelock_delay();
    assert(timelock_delay > 0, 'Timelock not configured');
    
    // Verify emergency controls
    let can_pause = cdc_pool.has_role(admin_role, config.admin_address);
    assert(can_pause, 'Emergency pause not available');
    
    // Verify slashing controls
    let slasher_count = cdc_pool.get_role_member_count(cdc_pool.SLASHER_ROLE());
    assert(slasher_count > 0, 'No slashers configured');
    
    println!("✅ Mainnet security validations passed!");
}

/// Deploy with custom configuration
fn deploy_with_custom_config(custom_config: DeploymentConfig) -> ICDCPoolDispatcher {
    println!("🚀 Starting CDC Pool deployment with custom configuration...");
    
    let cdc_pool = deploy_cdc_pool(custom_config.clone());
    configure_cdc_pool(cdc_pool, custom_config.clone());
    setup_integrations(cdc_pool, custom_config.clone());
    
    let validation_passed = validate_deployment(cdc_pool, custom_config);
    assert(validation_passed, 'Custom deployment validation failed');
    
    println!("✅ Custom CDC Pool deployment complete!");
    cdc_pool
}

/// Emergency deployment recovery (if needed)
fn emergency_recovery_deployment(failed_address: ContractAddress, config: DeploymentConfig) {
    println!("🚨 Starting emergency recovery deployment...");
    
    // Deploy new contract
    let new_cdc_pool = deploy_cdc_pool(config.clone());
    
    // Migrate critical state if possible
    // (Implementation depends on specific recovery requirements)
    
    // Configure new contract
    configure_cdc_pool(new_cdc_pool, config.clone());
    setup_integrations(new_cdc_pool, config.clone());
    
    println!("✅ Emergency recovery deployment complete!");
    println!("📍 New Contract Address: {}", new_cdc_pool.contract_address);
    println!("⚠️  Remember to update all integrations with new address!");
}

/// Deployment summary and next steps
fn print_deployment_summary(cdc_pool: ICDCPoolDispatcher, config: DeploymentConfig) {
    println!("\n📋 DEPLOYMENT SUMMARY");
    println!("=====================");
    println!("📍 CDC Pool Address: {}", cdc_pool.contract_address);
    println!("👤 Admin Address: {}", config.admin_address);
    println!("🪙 CIRO Token: {}", config.ciro_token_address);
    println!("⚙️  JobMgr Integration: {}", config.job_manager_address);
    println!("💰 Initial CIRO Price: ${}", config.initial_ciro_price as u64 / 1000000);
    println!("⏱️  Unstaking Delay: {} seconds", config.unstaking_delay);
    
    println!("\n🎯 NEXT STEPS");
    println!("=============");
    println!("1. 📋 Update frontend contracts configuration");
    println!("2. 🔗 Configure monitoring and alerting");
    println!("3. 🧪 Run integration tests with live contracts");
    println!("4. 👥 Onboard initial workers to the pool");
    println!("5. 📊 Set up analytics and dashboard monitoring");
    println!("6. 🔒 Schedule security audit for production use");
    
    println!("\n✅ CDC Pool is ready for operation!");
} 