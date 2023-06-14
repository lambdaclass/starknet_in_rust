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
    definitions::general_config::BlockContext,
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
        tx_context: &BlockContext,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Declare(tx) => tx.execute(state, tx_context),
            Transaction::DeclareV2(tx) => tx.execute(state, tx_context),
            Transaction::Deploy(tx) => tx.execute(state, tx_context),
            Transaction::DeployAccount(tx) => tx.execute(state, tx_context),
            Transaction::InvokeFunction(tx) => tx.execute(state, tx_context),
        }
    }
}
