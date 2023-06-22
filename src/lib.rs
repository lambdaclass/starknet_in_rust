#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use crate::{
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    state::{
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    transaction::{error::TransactionError, Transaction},
};

use cairo_vm::felt::Felt252;
use definitions::block_context::BlockContext;
use starknet_contract_class::EntryPointType;
use state::cached_state::CachedState;
use transaction::L1Handler;
use utils::Address;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

// Re-exports
pub use cairo_lang_starknet::casm_contract_class::CasmContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;

pub mod core;
pub mod definitions;
pub mod execution;
pub mod hash_utils;
pub mod parser_errors;
pub mod runner;
pub mod serde_structs;
pub mod services;
pub mod state;
pub mod storage;
pub mod syscalls;
pub mod testing;
pub mod transaction;
pub mod utils;

/// Estimate the fee associated with transaction
pub fn estimate_fee<T>(
    transaction: &Transaction,
    state: T,
    block_context: &BlockContext,
) -> Result<(u128, usize), TransactionError>
where
    T: StateReader,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T>::new(state, None, None);

    // Check if the contract is deployed.
    cached_state.get_class_hash_at(&transaction.contract_address())?;

    // execute the transaction with the fake state.
    let transaction_result = transaction.execute(&mut cached_state, block_context, 1_000_000)?;
    if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
        let actual_fee = transaction_result.actual_fee;
        Ok((actual_fee, *gas_usage))
    } else {
        Err(TransactionError::ResourcesError)
    }
}

pub fn call_contract<T: State + StateReader>(
    contract_address: Felt252,
    entrypoint_selector: Felt252,
    calldata: Vec<Felt252>,
    state: &mut T,
    block_context: BlockContext,
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
        Some(CallType::Delegate),
        Some(class_hash),
        initial_gas,
    );

    let mut tx_execution_context = TransactionExecutionContext::new(
        contract_address,
        transaction_hash,
        signature,
        max_fee,
        nonce,
        block_context.invoke_tx_max_n_steps(),
        version.into(),
    );

    let call_info = execution_entrypoint.execute(
        state,
        &block_context,
        &mut ExecutionResourcesManager::default(),
        &mut tx_execution_context,
        false,
    )?;

    Ok(call_info.retdata)
}

/// Estimate the fee associated with L1Handler
pub fn estimate_message_fee<T>(
    l1_handler: &L1Handler,
    state: T,
    block_context: &BlockContext,
) -> Result<(u128, usize), TransactionError>
where
    T: StateReader,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T>::new(state, None, None);

    // Check if the contract is deployed.
    cached_state.get_class_hash_at(l1_handler.contract_address())?;

    // execute the transaction with the fake state.
    let transaction_result = l1_handler.execute(&mut cached_state, block_context, 1_000_000)?;
    if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
        let actual_fee = transaction_result.actual_fee;
        Ok((actual_fee, *gas_usage))
    } else {
        Err(TransactionError::ResourcesError)
    }
}

pub fn execute_transaction<T: State + StateReader>(
    tx: Transaction,
    state: &mut T,
    block_context: BlockContext,
    remaining_gas: u128,
) -> Result<TransactionExecutionInfo, TransactionError> {
    tx.execute(state, &block_context, remaining_gas)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use crate::definitions::block_context::StarknetChainId;
    use crate::estimate_fee;
    use crate::services::api::contract_classes::deprecated_contract_class::ContractClass;
    use crate::testing::{create_account_tx_test_state, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH};
    use crate::transaction::{InvokeFunction, Transaction};
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::felt::Felt252;
    use num_traits::Zero;
    use starknet_contract_class::EntryPointType;

    use crate::{
        call_contract,
        definitions::block_context::BlockContext,
        state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader},
        utils::{Address, ClassHash},
    };

    #[test]
    fn estimate_fee_test() {
        let contract_class: ContractClass =
            ContractClass::try_from(PathBuf::from(TEST_CONTRACT_PATH)).unwrap();

        let entrypoints = contract_class.entry_points_by_type;
        let entrypoint_selector = &entrypoints.get(&EntryPointType::External).unwrap()[0].selector;

        let (transaction_context, state) = create_account_tx_test_state().unwrap();

        let calldata = [1.into(), 1.into(), 10.into()].to_vec();
        let invoke_function = InvokeFunction::new(
            TEST_CONTRACT_ADDRESS.clone(),
            entrypoint_selector.clone(),
            100_000_000,
            1.into(),
            calldata,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            Some(0.into()),
            None,
        )
        .unwrap();
        let transaction = Transaction::InvokeFunction(invoke_function);

        let estimated_fee = estimate_fee(&transaction, state, &transaction_context).unwrap();
        assert_eq!(estimated_fee, (0, 0));
    }

    #[test]
    fn call_contract_fibonacci_with_10_should_return_89() {
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");
        let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
        let entrypoints = contract_class.clone().entry_points_by_type;
        let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

        let mut contract_class_cache = HashMap::new();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::zero();

        contract_class_cache.insert(class_hash, contract_class);
        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));
        let calldata = [1.into(), 1.into(), 10.into()].to_vec();

        let retdata = call_contract(
            address.0,
            entrypoint_selector.into(),
            calldata,
            &mut state,
            BlockContext::default(),
        )
        .unwrap();

        assert_eq!(retdata, vec![89.into()]);
    }
}
