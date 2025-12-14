// =============================================================================
// ESCROW CONTRACT - BitSage Network
// =============================================================================
//
// Implements escrow mechanism for job payments:
//
// 1. Client submits job request → Funds locked in escrow
// 2. Worker completes job → Escrow verifies completion
// 3. Job verified → Funds released via FeeManager
//
// Inspired by Gonka's escrow and refund mechanism.
//
// =============================================================================

use starknet::ContractAddress;

// =============================================================================
// Data Types
// =============================================================================

/// Escrow entry for a job
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EscrowEntry {
    /// Client who deposited funds
    pub client: ContractAddress,
    /// Assigned worker (zero if unassigned)
    pub worker: ContractAddress,
    /// Total amount locked
    pub amount: u256,
    /// Maximum cost (based on max completion tokens)
    pub max_cost: u256,
    /// Actual cost (set after completion)
    pub actual_cost: u256,
    /// Status: 0 = locked, 1 = assigned, 2 = completed, 3 = refunded, 4 = disputed
    pub status: u8,
    /// Timestamp of escrow creation
    pub created_at: u64,
    /// Deadline for completion
    pub deadline: u64,
}

/// Escrow statistics
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct EscrowStats {
    /// Total funds currently locked
    pub total_locked: u256,
    /// Total funds released to workers
    pub total_released: u256,
    /// Total refunded to clients
    pub total_refunded: u256,
    /// Number of active escrows
    pub active_count: u64,
    /// Number of completed escrows
    pub completed_count: u64,
}

// =============================================================================
// Interface
// =============================================================================

#[starknet::interface]
pub trait IEscrow<TContractState> {
    // === Client Functions ===
    /// Create escrow for a job
    fn create_escrow(
        ref self: TContractState,
        job_id: u256,
        max_cost: u256,
        deadline: u64,
    );
    
    /// Request refund (if deadline passed and not completed)
    fn request_refund(ref self: TContractState, job_id: u256);
    
    // === Worker Functions ===
    /// Claim assignment for a job
    fn accept_job(ref self: TContractState, job_id: u256);
    
    // === Job Manager Functions ===
    /// Complete job and release funds
    fn complete_job(
        ref self: TContractState,
        job_id: u256,
        actual_cost: u256,
        worker: ContractAddress,
    );
    
    /// Cancel job and refund
    fn cancel_job(ref self: TContractState, job_id: u256);
    
    // === Admin Functions ===
    fn set_fee_manager(ref self: TContractState, fee_manager: ContractAddress);
    fn set_job_manager(ref self: TContractState, job_manager: ContractAddress);
    fn resolve_dispute(ref self: TContractState, job_id: u256, refund_client: bool);
    
    // === View Functions ===
    fn get_escrow(self: @TContractState, job_id: u256) -> EscrowEntry;
    fn get_stats(self: @TContractState) -> EscrowStats;
    fn can_refund(self: @TContractState, job_id: u256) -> bool;
}

// =============================================================================
// Contract Implementation
// =============================================================================

#[starknet::contract]
mod Escrow {
    use super::{IEscrow, EscrowEntry, EscrowStats};
    use starknet::{
        ContractAddress, get_caller_address, get_block_timestamp,
    };
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        StorageMapReadAccess, StorageMapWriteAccess,
        Map,
    };
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    // Status constants
    const STATUS_LOCKED: u8 = 0;
    const STATUS_ASSIGNED: u8 = 1;
    const STATUS_COMPLETED: u8 = 2;
    const STATUS_REFUNDED: u8 = 3;
    const STATUS_DISPUTED: u8 = 4;

    // =========================================================================
    // Storage
    // =========================================================================
    
    #[storage]
    struct Storage {
        /// Contract owner
        owner: ContractAddress,
        /// CIRO token address
        ciro_token: ContractAddress,
        /// Fee manager contract
        fee_manager: ContractAddress,
        /// Job manager contract
        job_manager: ContractAddress,
        /// Escrow entries by job ID
        escrows: Map<u256, EscrowEntry>,
        /// Statistics
        stats: EscrowStats,
    }

    // =========================================================================
    // Events
    // =========================================================================
    
    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        EscrowCreated: EscrowCreated,
        JobAccepted: JobAccepted,
        JobCompleted: JobCompleted,
        EscrowRefunded: EscrowRefunded,
        DisputeResolved: DisputeResolved,
    }

    #[derive(Drop, starknet::Event)]
    struct EscrowCreated {
        #[key]
        job_id: u256,
        client: ContractAddress,
        max_cost: u256,
        deadline: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct JobAccepted {
        #[key]
        job_id: u256,
        worker: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct JobCompleted {
        #[key]
        job_id: u256,
        worker: ContractAddress,
        actual_cost: u256,
        refund_to_client: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct EscrowRefunded {
        #[key]
        job_id: u256,
        client: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct DisputeResolved {
        #[key]
        job_id: u256,
        refund_to_client: bool,
    }

    // =========================================================================
    // Constructor
    // =========================================================================
    
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        ciro_token: ContractAddress,
    ) {
        self.owner.write(owner);
        self.ciro_token.write(ciro_token);
        
        self.stats.write(EscrowStats {
            total_locked: 0,
            total_released: 0,
            total_refunded: 0,
            active_count: 0,
            completed_count: 0,
        });
    }

    // =========================================================================
    // Implementation
    // =========================================================================
    
    #[abi(embed_v0)]
    impl EscrowImpl of IEscrow<ContractState> {
        fn create_escrow(
            ref self: ContractState,
            job_id: u256,
            max_cost: u256,
            deadline: u64,
        ) {
            let caller = get_caller_address();
            
            // Verify escrow doesn't exist
            let existing = self.escrows.read(job_id);
            assert(existing.amount == 0, 'Escrow already exists');
            
            // Transfer max cost to contract
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.transfer_from(caller, starknet::get_contract_address(), max_cost);
            
            // Create escrow
            let zero_addr: ContractAddress = 0.try_into().unwrap();
            let escrow = EscrowEntry {
                client: caller,
                worker: zero_addr,
                amount: max_cost,
                max_cost,
                actual_cost: 0,
                status: STATUS_LOCKED,
                created_at: get_block_timestamp(),
                deadline,
            };
            
            self.escrows.write(job_id, escrow);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_locked = stats.total_locked + max_cost;
            stats.active_count = stats.active_count + 1;
            self.stats.write(stats);
            
            self.emit(EscrowCreated {
                job_id,
                client: caller,
                max_cost,
                deadline,
            });
        }

        fn request_refund(ref self: ContractState, job_id: u256) {
            let caller = get_caller_address();
            let mut escrow = self.escrows.read(job_id);
            
            assert(escrow.client == caller, 'Not escrow owner');
            assert(escrow.status == STATUS_LOCKED || escrow.status == STATUS_ASSIGNED, 'Invalid status');
            assert(get_block_timestamp() > escrow.deadline, 'Deadline not passed');
            
            let refund_amount = escrow.amount;
            escrow.status = STATUS_REFUNDED;
            escrow.amount = 0;
            self.escrows.write(job_id, escrow);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_locked = stats.total_locked - refund_amount;
            stats.total_refunded = stats.total_refunded + refund_amount;
            stats.active_count = stats.active_count - 1;
            self.stats.write(stats);
            
            // Transfer back to client
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.transfer(caller, refund_amount);
            
            self.emit(EscrowRefunded {
                job_id,
                client: caller,
                amount: refund_amount,
            });
        }

        fn accept_job(ref self: ContractState, job_id: u256) {
            let caller = get_caller_address();
            let mut escrow = self.escrows.read(job_id);
            
            assert(escrow.status == STATUS_LOCKED, 'Job not available');
            assert(get_block_timestamp() < escrow.deadline, 'Deadline passed');
            
            escrow.worker = caller;
            escrow.status = STATUS_ASSIGNED;
            self.escrows.write(job_id, escrow);
            
            self.emit(JobAccepted {
                job_id,
                worker: caller,
            });
        }

        fn complete_job(
            ref self: ContractState,
            job_id: u256,
            actual_cost: u256,
            worker: ContractAddress,
        ) {
            let caller = get_caller_address();
            assert(
                caller == self.job_manager.read() || caller == self.owner.read(),
                'Unauthorized'
            );
            
            let mut escrow = self.escrows.read(job_id);
            assert(escrow.status == STATUS_ASSIGNED || escrow.status == STATUS_LOCKED, 'Invalid status');
            assert(actual_cost <= escrow.max_cost, 'Cost exceeds max');
            
            // Calculate refund
            let refund = escrow.max_cost - actual_cost;
            
            escrow.actual_cost = actual_cost;
            escrow.status = STATUS_COMPLETED;
            escrow.worker = worker;
            escrow.amount = 0;
            self.escrows.write(job_id, escrow);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_locked = stats.total_locked - escrow.max_cost;
            stats.total_released = stats.total_released + actual_cost;
            if refund > 0 {
                stats.total_refunded = stats.total_refunded + refund;
            }
            stats.active_count = stats.active_count - 1;
            stats.completed_count = stats.completed_count + 1;
            self.stats.write(stats);
            
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            
            // Transfer actual cost to fee manager for processing
            let fee_manager_addr = self.fee_manager.read();
            let zero_addr: ContractAddress = 0.try_into().unwrap();
            if fee_manager_addr != zero_addr {
                token.transfer(fee_manager_addr, actual_cost);
                // Note: Fee manager will distribute to worker with fee deduction
            } else {
                // Fallback: pay worker directly if no fee manager
                token.transfer(worker, actual_cost);
            }
            
            // Refund excess to client
            if refund > 0 {
                token.transfer(escrow.client, refund);
            }
            
            self.emit(JobCompleted {
                job_id,
                worker,
                actual_cost,
                refund_to_client: refund,
            });
        }

        fn cancel_job(ref self: ContractState, job_id: u256) {
            let caller = get_caller_address();
            assert(
                caller == self.job_manager.read() || caller == self.owner.read(),
                'Unauthorized'
            );
            
            let mut escrow = self.escrows.read(job_id);
            assert(escrow.status == STATUS_LOCKED || escrow.status == STATUS_ASSIGNED, 'Invalid status');
            
            let refund_amount = escrow.amount;
            escrow.status = STATUS_REFUNDED;
            escrow.amount = 0;
            self.escrows.write(job_id, escrow);
            
            // Update stats
            let mut stats = self.stats.read();
            stats.total_locked = stats.total_locked - refund_amount;
            stats.total_refunded = stats.total_refunded + refund_amount;
            stats.active_count = stats.active_count - 1;
            self.stats.write(stats);
            
            // Refund to client
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            token.transfer(escrow.client, refund_amount);
            
            self.emit(EscrowRefunded {
                job_id,
                client: escrow.client,
                amount: refund_amount,
            });
        }

        fn set_fee_manager(ref self: ContractState, fee_manager: ContractAddress) {
            self._only_owner();
            self.fee_manager.write(fee_manager);
        }

        fn set_job_manager(ref self: ContractState, job_manager: ContractAddress) {
            self._only_owner();
            self.job_manager.write(job_manager);
        }

        fn resolve_dispute(ref self: ContractState, job_id: u256, refund_client: bool) {
            self._only_owner();
            
            let mut escrow = self.escrows.read(job_id);
            assert(escrow.status == STATUS_DISPUTED, 'Not disputed');
            
            let token = IERC20Dispatcher { contract_address: self.ciro_token.read() };
            let mut stats = self.stats.read();
            
            if refund_client {
                token.transfer(escrow.client, escrow.amount);
                stats.total_refunded = stats.total_refunded + escrow.amount;
                escrow.status = STATUS_REFUNDED;
            } else {
                token.transfer(escrow.worker, escrow.amount);
                stats.total_released = stats.total_released + escrow.amount;
                escrow.status = STATUS_COMPLETED;
                stats.completed_count = stats.completed_count + 1;
            }
            
            stats.total_locked = stats.total_locked - escrow.amount;
            stats.active_count = stats.active_count - 1;
            self.stats.write(stats);
            
            escrow.amount = 0;
            self.escrows.write(job_id, escrow);
            
            self.emit(DisputeResolved {
                job_id,
                refund_to_client: refund_client,
            });
        }

        fn get_escrow(self: @ContractState, job_id: u256) -> EscrowEntry {
            self.escrows.read(job_id)
        }

        fn get_stats(self: @ContractState) -> EscrowStats {
            self.stats.read()
        }

        fn can_refund(self: @ContractState, job_id: u256) -> bool {
            let escrow = self.escrows.read(job_id);
            (escrow.status == STATUS_LOCKED || escrow.status == STATUS_ASSIGNED)
                && get_block_timestamp() > escrow.deadline
        }
    }

    // =========================================================================
    // Internal Functions
    // =========================================================================
    
    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _only_owner(self: @ContractState) {
            assert(get_caller_address() == self.owner.read(), 'Only owner');
        }
    }
}

