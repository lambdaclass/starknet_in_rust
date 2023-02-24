use crate::{
    business_logic::{
        execution::objects::TransactionExecutionInfo,
        fact_state::in_memory_state_reader::InMemoryStateReader, state::cached_state::CachedState,
    },
    definitions::general_config::StarknetGeneralConfig,
    utils::Address,
};

use super::{
    internal_objects::InternalDeploy, objects::internal_invoke_function::InternalInvokeFunction,
};

pub(crate) enum Transaction {
    Deploy(InternalDeploy),
    InvokeFunction(InternalInvokeFunction),
}

impl Transaction {
    pub fn contract_hash(&self) -> [u8; 32] {
        match self {
            Transaction::Deploy(tx) => tx.contract_hash,
            _ => [0; 32],
        }
    }

    pub fn contract_address(&self) -> Address {
        match self {
            Transaction::Deploy(tx) => tx.contract_address.clone(),
            Transaction::InvokeFunction(tx) => tx.contract_address.clone(),
        }
    }

    pub fn apply_state_updates(
        &self,
        _state_copy: CachedState<InMemoryStateReader>,
        _general_config: &StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        todo!()
    }
}
