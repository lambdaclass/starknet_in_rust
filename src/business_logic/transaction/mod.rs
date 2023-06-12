pub mod declare;
pub mod declare_v2;
pub mod deploy;
pub mod deploy_account;
pub mod error;
pub mod fee;
pub mod invoke_function;

pub use declare::Declare;
pub use declare_v2::DeclareV2;
pub use deploy::Deploy;
pub use deploy_account::DeployAccount;
pub use invoke_function::InvokeFunction;

use crate::{
    business_logic::{
        execution::TransactionExecutionInfo,
        state::state_api::{State, StateReader},
    },
    definitions::general_config::TransactionContext,
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
}

impl Transaction {
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        general_config: &TransactionContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Declare(tx) => tx.execute(state, general_config),
            // TODO: Remove remaining gas and set it internally to a proper value
            Transaction::DeclareV2(tx) => tx.execute(state, general_config, 0),
            Transaction::Deploy(tx) => tx.execute(state, general_config),
            Transaction::DeployAccount(tx) => tx.execute(state, general_config),
            Transaction::InvokeFunction(tx) => tx.execute(state, general_config),
        }
    }
}
