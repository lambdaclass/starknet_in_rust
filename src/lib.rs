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

use definitions::block_context::BlockContext;
use state::cached_state::CachedState;
use transaction::InvokeFunction;
use transaction::L1Handler;
use utils::Address;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

// Re-exports
pub use cairo_lang_starknet::casm_contract_class::CasmContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
pub use cairo_vm::felt::Felt252;
pub use starknet_contract_class::EntryPointType;

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

pub fn simulate_transaction<S: StateReader>(
    transactions: &[InvokeFunction],
    state: S,
    block_context: BlockContext,
    remaining_gas: u128,
    skip_validate: bool,
    skip_execute: bool,
) -> Result<Vec<TransactionExecutionInfo>, TransactionError> {
    let mut cache_state = CachedState::new(state, None, None);
    let mut result = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        let tx_for_simulation = transaction
            .clone()
            .create_for_simulation(skip_validate, skip_execute);
        let tx_result =
            tx_for_simulation.execute(&mut cache_state, &block_context, remaining_gas)?;
        result.push(tx_result);
    }

    Ok(result)
}

/// Estimate the fee associated with transaction
pub fn estimate_fee<T>(
    transactions: &[Transaction],
    state: T,
    block_context: &BlockContext,
) -> Result<Vec<(u128, usize)>, TransactionError>
where
    T: StateReader,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T>::new(state, None, None);

    let mut result = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        // Check if the contract is deployed.
        cached_state.get_class_hash_at(&transaction.contract_address())?;
        // execute the transaction with the fake state.

        let transaction_result =
            transaction.execute(&mut cached_state, block_context, 1_000_000)?;
        if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
            result.push((transaction_result.actual_fee, *gas_usage));
        } else {
            return Err(TransactionError::ResourcesError);
        };
    }

    Ok(result)
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

    use crate::core::contract_address::compute_deprecated_class_hash;
    use crate::definitions::block_context::StarknetChainId;
    use crate::definitions::constants::EXECUTE_ENTRY_POINT_SELECTOR;
    use crate::estimate_fee;
    use crate::estimate_message_fee;
    use crate::services::api::contract_classes::deprecated_contract_class::ContractClass;
    use crate::testing::{create_account_tx_test_state, TEST_CONTRACT_ADDRESS, TEST_CONTRACT_PATH};
    use crate::transaction::{InvokeFunction, L1Handler, Transaction};
    use crate::utils::felt_to_hash;
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::felt::{felt_str, Felt252};
    use num_traits::{Num, One, Zero};
    use starknet_contract_class::EntryPointType;

    use crate::{
        call_contract,
        definitions::block_context::BlockContext,
        simulate_transaction,
        state::{
            cached_state::CachedState, in_memory_state_reader::InMemoryStateReader,
            ExecutionResourcesManager,
        },
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

        let estimated_fee = estimate_fee(&[transaction], state, &transaction_context).unwrap();
        assert_eq!(estimated_fee, vec![(0, 0)]);
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

    #[test]
    fn test_estimate_message_fee() {
        let l1_handler = L1Handler::new(
            Address(0.into()),
            Felt252::from_str_radix(
                "c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                16,
            )
            .unwrap(),
            vec![
                Felt252::from_str_radix("8359E4B0152ed5A731162D3c7B0D8D56edB165A0", 16).unwrap(),
                1.into(),
                10.into(),
            ],
            0.into(),
            0.into(),
            Some(10000.into()),
        )
        .unwrap();

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class =
            ContractClass::try_from(PathBuf::from("starknet_programs/l1l2.json")).unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None, None);

        // Initialize state.contract_classes
        let contract_classes = HashMap::from([(class_hash, contract_class)]);
        state.set_contract_classes(contract_classes).unwrap();

        let mut block_context = BlockContext::default();
        block_context.cairo_resource_fee_weights = HashMap::from([
            (String::from("l1_gas_usage"), 0.into()),
            (String::from("pedersen_builtin"), 16.into()),
            (String::from("range_check_builtin"), 70.into()),
        ]);
        block_context.starknet_os_config.gas_price = 1;

        let estimated_fee = estimate_message_fee(&l1_handler, state, &block_context).unwrap();
        assert_eq!(estimated_fee, (0, 18471));
    }

    #[test]
    fn test_skip_validation_flag() {
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

        let invoke = InvokeFunction::new(
            address,
            entrypoint_selector.into(),
            1000000,
            Felt252::zero(),
            calldata,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            None,
            None,
        )
        .unwrap();

        let block_context = BlockContext::default();
        let simul_invoke = invoke.create_for_simulation(true, false);

        let call_info = simul_invoke
            .run_validate_entrypoint(
                &mut state,
                &mut ExecutionResourcesManager::default(),
                &block_context,
            )
            .unwrap();

        assert!(call_info.is_none());
    }

    #[test]
    fn test_skip_execute_flag() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

        //  ------------ contract data --------------------
        // hack store account contract
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let acc_class_hash = felt_to_hash(&hash);
        let entrypoint_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

        // test with fibonacci
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");
        let casm_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::one();

        let mut state_reader = InMemoryStateReader::default();

        // store data in the state reader
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), acc_class_hash);

        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        // simulate deploy
        state_reader
            .class_hash_to_contract_class_mut()
            .insert(acc_class_hash, contract_class);

        let hash = felt_str!(
            "134328839377938040543570691566621575472567895629741043448357033688476792132"
        );
        let fib_address = felt_to_hash(&hash);
        state_reader
            .class_hash_to_compiled_class_hash_mut()
            .insert(fib_address, class_hash);
        state_reader
            .casm_contract_classes
            .insert(fib_address, casm_contract_class);

        let calldata = [
            address.0.clone(),
            entrypoint_selector.clone(),
            3.into(),
            1.into(),
            1.into(),
            10.into(),
        ]
        .to_vec();

        let invoke_1 = InvokeFunction::new(
            address.clone(),
            entrypoint_selector.clone(),
            1000000,
            Felt252::one(),
            calldata.clone(),
            vec![],
            StarknetChainId::TestNet.to_felt(),
            Some(1.into()),
            None,
        )
        .unwrap();

        let invoke_2 = InvokeFunction::new(
            address.clone(),
            entrypoint_selector.clone(),
            1000000,
            Felt252::one(),
            calldata.clone(),
            vec![],
            StarknetChainId::TestNet.to_felt(),
            Some(2.into()),
            None,
        )
        .unwrap();

        let invoke_3 = InvokeFunction::new(
            address,
            entrypoint_selector,
            1000000,
            Felt252::one(),
            calldata,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            Some(3.into()),
            None,
        )
        .unwrap();
        let block_context = BlockContext::default();

        let context = simulate_transaction(
            &[invoke_1, invoke_2, invoke_3],
            state_reader,
            block_context,
            1000,
            false,
            true,
        )
        .unwrap();

        assert!(context[0].validate_info.is_some());
        assert!(context[0].call_info.is_none());
        assert!(context[0].fee_transfer_info.is_none());
        assert!(context[1].validate_info.is_some());
        assert!(context[1].call_info.is_none());
        assert!(context[1].fee_transfer_info.is_none());
        assert!(context[2].validate_info.is_some());
        assert!(context[2].call_info.is_none());
        assert!(context[2].fee_transfer_info.is_none());
    }

    #[test]
    fn test_skip_execute_and_validate_flags() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

        //  ------------ contract data --------------------
        // hack store account contract
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let acc_class_hash = felt_to_hash(&hash);
        let entrypoint_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

        // test with fibonacci
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");
        let casm_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::one();

        let mut state_reader = InMemoryStateReader::default();

        // store data in the state reader
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), acc_class_hash);

        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        // simulate deploy
        state_reader
            .class_hash_to_contract_class_mut()
            .insert(acc_class_hash, contract_class);

        let hash = felt_str!(
            "134328839377938040543570691566621575472567895629741043448357033688476792132"
        );
        let fib_address = felt_to_hash(&hash);
        state_reader
            .class_hash_to_compiled_class_hash_mut()
            .insert(fib_address, class_hash);
        state_reader
            .casm_contract_classes
            .insert(fib_address, casm_contract_class);

        let calldata = [
            address.0.clone(),
            entrypoint_selector.clone(),
            3.into(),
            1.into(),
            1.into(),
            10.into(),
        ]
        .to_vec();

        let invoke = InvokeFunction::new(
            address,
            entrypoint_selector,
            1000000,
            Felt252::one(),
            calldata,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            Some(1.into()),
            None,
        )
        .unwrap();

        let block_context = BlockContext::default();

        let context =
            simulate_transaction(&[invoke], state_reader, block_context, 1000, true, true).unwrap();

        assert!(context[0].validate_info.is_none());
        assert!(context[0].call_info.is_none());
        assert!(context[0].fee_transfer_info.is_none());
    }
}
