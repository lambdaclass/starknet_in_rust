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
    definitions::general_config::TransactionContext,
    execution::TransactionExecutionInfo,
    state::state_api::{State, StateReader},
};
use error::TransactionError;

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
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        general_config: &TransactionContext,
        remaining_gas: u128,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Declare(tx) => tx.execute(state, general_config),
            Transaction::DeclareV2(tx) => tx.execute(state, general_config),
            Transaction::Deploy(tx) => tx.execute(state, general_config),
            Transaction::DeployAccount(tx) => tx.execute(state, general_config),
            Transaction::InvokeFunction(tx) => tx.execute(state, general_config),
            Transaction::L1Handler(tx) => tx.execute(state, general_config, remaining_gas),
        }
    }
}
