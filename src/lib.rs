#![deny(warnings)]

use business_logic::{
    execution::{
        execution_entry_point::ExecutionEntryPoint,
        objects::{CallType, TransactionExecutionContext, TransactionExecutionInfo},
    },
    fact_state::state::ExecutionResourcesManager,
    state::{
        cached_state::CachedState,
        state_api::{State, StateReader},
    },
    transaction::{error::TransactionError, transactions::Transaction},
};
use definitions::general_config::StarknetGeneralConfig;
use felt::Felt;
use services::api::contract_class::EntryPointType;
use utils::{Address, ClassHash};

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod business_logic;
pub mod core;
pub mod definitions;
pub mod hash_utils;
pub mod public;
pub mod services;
pub mod starknet_runner;
pub mod starknet_storage;
pub mod starkware_utils;
pub mod testing;
pub mod utils;

type TransactionResult<T> = Result<T, TransactionError>;

#[derive(Debug)]
pub struct ContractCall {
    contract_address: Address,
    entry_point_selector: Felt,
    calldata: Vec<Felt>,
    caller_address: Address,
    entrypoint_type: EntryPointType,
    call_type: CallType,
    class_hash: ClassHash,
}

pub struct Starknet {}

impl Starknet {
    pub fn call_contract<T>(
        state: &mut CachedState<T>,
        call: ContractCall,
        resources_manager: &mut ExecutionResourcesManager,
        config: &StarknetGeneralConfig,
        tx_execution_context: &TransactionExecutionContext,
    ) -> TransactionResult<Vec<Felt>>
    where
        T: State + StateReader + Clone + Default,
    {
        let entrypoint = ExecutionEntryPoint::new(
            call.contract_address,
            call.calldata,
            call.entry_point_selector,
            call.caller_address,
            call.entrypoint_type,
            Some(call.call_type),
            Some(call.class_hash),
        );

        let call_info =
            entrypoint.execute(state, config, resources_manager, tx_execution_context)?;

        Ok(call_info.retdata)
    }

    pub fn estimate_fee<T>(
        state: &CachedState<T>,
        tx: Transaction,
        config: &StarknetGeneralConfig,
    ) -> TransactionResult<u64>
    where
        T: State + StateReader + Clone + Default,
    {
        let mut state_copy = state.clone();
        tx.execute(&mut state_copy, config)
            .map(|tx_exec| tx_exec.actual_fee)
            .map_err(Into::into)
    }

    pub fn execute_tx<T>(
        &self,
        state: &mut CachedState<T>,
        tx: Transaction,
        config: &StarknetGeneralConfig,
    ) -> TransactionResult<TransactionExecutionInfo>
    where
        T: State + StateReader + Clone + Default,
    {
        tx.execute(state, config).map_err(Into::into)
    }
}
