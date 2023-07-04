pub mod declare;
pub mod declare_v2;
pub mod deploy;
pub mod deploy_account;
pub mod error;
pub mod fee;
pub mod invoke_function;
pub mod l1_handler;

pub use declare::Declare;
pub use declare_v2::DeclareV2;
pub use deploy::Deploy;
pub use deploy_account::DeployAccount;
pub use invoke_function::InvokeFunction;
pub use l1_handler::L1Handler;

use crate::{
    definitions::block_context::BlockContext,
    execution::TransactionExecutionInfo,
    state::state_api::{State, StateReader},
    utils::Address,
};
use error::TransactionError;

/// Represents a transaction inside the starknet network.
/// The transaction are actions that may modified the state of the network.
/// it can be one of:
/// - Declare
/// - DeclareV2
/// - Deploy
/// - DeployAccount
/// - InvokeFunction
/// - L1Handler
pub enum Transaction {
    /// A declare transaction.
    Declare(Declare),
    /// A declare transaction.
    DeclareV2(Box<DeclareV2>),
    /// A deploy transaction.
    Deploy(Deploy),
    /// A deploy account transaction.
    DeployAccount(DeployAccount),
    /// An invoke transaction.
    InvokeFunction(InvokeFunction),
    /// An L1 handler transaction.
    L1Handler(L1Handler),
}

impl Transaction {
    /// returns the contract address of the transaction.
    pub fn contract_address(&self) -> Address {
        match self {
            Transaction::Deploy(tx) => tx.contract_address.clone(),
            Transaction::InvokeFunction(tx) => tx.contract_address().clone(),
            Transaction::Declare(tx) => tx.sender_address.clone(),
            Transaction::DeclareV2(tx) => tx.sender_address.clone(),
            Transaction::DeployAccount(tx) => tx.contract_address().clone(),
            Transaction::L1Handler(tx) => tx.contract_address().clone(),
        }
    }

    /// execute the transaction in cairo-vm and returns a TransactionExecutionInfo structure.
    ///## Parameters:
    ///- state: a structure that implements State and StateReader traits.
    ///- block_context: The block context of the transaction that is about to be executed.
    ///- remaining_gas: The gas supplied to execute the transaction.
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        block_context: &BlockContext,
        remaining_gas: u128,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Declare(tx) => tx.execute(state, block_context),
            Transaction::DeclareV2(tx) => tx.execute(state, block_context),
            Transaction::Deploy(tx) => tx.execute(state, block_context),
            Transaction::DeployAccount(tx) => tx.execute(state, block_context),
            Transaction::InvokeFunction(tx) => tx.execute(state, block_context, remaining_gas),
            Transaction::L1Handler(tx) => tx.execute(state, block_context, remaining_gas),
        }
    }
    /// It creates a new transaction structure modificating the skip flags. It is meant to be used only to run a simulation
    ///## Parameters:
    ///- skip_validate: the transaction will not be verificatedi.
    ///- skip_execute: the transaction will not be executed in the cairo vmi.
    ///- skip_fee_transfer: the transaction will not consume gas as it will skip fee_transfer.
    pub fn create_for_simulation(
        &self,
        skip_validate: bool,
        skip_execute: bool,
        skip_fee_transfer: bool,
    ) -> Self {
        match self {
            Transaction::Declare(tx) => {
                tx.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer)
            }
            Transaction::DeclareV2(tx) => {
                tx.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer)
            }
            Transaction::Deploy(tx) => {
                tx.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer)
            }
            Transaction::DeployAccount(tx) => {
                tx.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer)
            }
            Transaction::InvokeFunction(tx) => {
                tx.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer)
            }
            Transaction::L1Handler(tx) => tx.create_for_simulation(skip_validate, skip_execute),
        }
    }
}
