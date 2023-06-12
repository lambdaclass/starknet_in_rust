use crate::{
    business_logic::{
        execution::TransactionExecutionInfo,
        state::state_api::{State, StateReader},
    },
    definitions::general_config::TransactionContext,
    utils::{Address, ClassHash},
};

use super::{error::TransactionError, l1_handler::L1Handler, Deploy, InvokeFunction};

pub enum Transaction {
    Deploy(Deploy),
    InvokeFunction(InvokeFunction),
    L1Handler(L1Handler),
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
            Transaction::L1Handler(tx) => tx.contract_address().clone(),
        }
    }

    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        general_config: &TransactionContext,
        remaining_gas: u128,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Deploy(tx) => tx.execute(state, general_config),
            Transaction::InvokeFunction(tx) => tx.execute(state, general_config),
            Transaction::L1Handler(tx) => tx.execute(state, general_config, remaining_gas),
        }
    }
}
