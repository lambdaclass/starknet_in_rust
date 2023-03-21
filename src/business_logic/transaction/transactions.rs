use crate::{
    business_logic::{
        execution::objects::TransactionExecutionInfo,
        state::state_api::{State, StateReader},
    },
    definitions::general_config::StarknetGeneralConfig,
    utils::{Address, ClassHash},
};

use super::{
    error::TransactionError,
    objects::{internal_deploy::InternalDeploy, internal_invoke_function::InternalInvokeFunction},
};

pub(crate) enum Transaction {
    Deploy(InternalDeploy),
    InvokeFunction(InternalInvokeFunction),
}

impl Transaction {
    pub fn contract_hash(&self) -> ClassHash {
        match self {
            Transaction::Deploy(tx) => tx.contract_hash,
            _ => [0; 32],
        }
    }

    pub fn contract_address(&self) -> Address {
        match self {
            Transaction::Deploy(tx) => tx.contract_address.clone(),
            Transaction::InvokeFunction(tx) => tx.contract_address().clone(),
        }
    }

    pub fn execute<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Deploy(tx) => tx.execute(state, general_config),
            Transaction::InvokeFunction(tx) => tx.execute(state, general_config),
        }
    }
}
