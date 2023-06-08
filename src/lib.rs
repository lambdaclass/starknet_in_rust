#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use business_logic::{
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    fact_state::state::ExecutionResourcesManager,
    state::state_api::{State, StateReader},
    transaction::error::TransactionError,
};
use cairo_vm::felt::Felt252;
use definitions::general_config::StarknetGeneralConfig;
use starknet_contract_class::EntryPointType;
use utils::Address;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

pub mod business_logic;
pub mod core;
pub mod definitions;
pub mod hash_utils;
pub mod parser_errors;
pub mod runner;
pub mod serde_structs;
pub mod services;
pub mod storage;
pub mod syscalls;
pub mod testing;
pub mod utils;

pub fn call_contract<T: State + StateReader>(
    contract_address: Felt252,
    entrypoint_selector: Felt252,
    calldata: Vec<Felt252>,
    state: &mut T,
    config: StarknetGeneralConfig,
) -> Result<Vec<Felt252>, TransactionError> {
    let contract_address = Address(contract_address);
    let class_hash = state.get_class_hash_at(&contract_address)?;
    let nonce = state.get_nonce_at(&contract_address)?;

    // TODO: Revisit these parameters
    let transaction_hash = 0.into();
    let signature = vec![];
    let max_fee = 1000000000;
    let initial_gas = 1000000000;
    let caller_address = Address(0.into());
    let version = 0;

    let execution_entrypoint = ExecutionEntryPoint::new(
        contract_address.clone(),
        calldata,
        entrypoint_selector,
        caller_address,
        EntryPointType::External,
        Some(CallType::Call),
        Some(class_hash),
        initial_gas,
    );

    let tx_execution_context = TransactionExecutionContext::new(
        contract_address,
        transaction_hash,
        signature,
        max_fee,
        nonce,
        config.invoke_tx_max_n_steps(),
        version,
    );

    let call_info = execution_entrypoint.execute(
        state,
        &config,
        &mut ExecutionResourcesManager::default(),
        &tx_execution_context,
        false,
    )?;

    Ok(call_info.retdata)
}
