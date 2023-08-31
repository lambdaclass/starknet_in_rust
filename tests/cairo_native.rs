#![cfg(not(feature = "cairo_1_tests"))]
#![deny(warnings)]

use cairo_vm::felt::Felt252;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_bigint::BigUint;
use num_traits::Zero;
use starknet_in_rust::definitions::block_context::BlockContext;
use starknet_in_rust::EntryPointType;
use starknet_in_rust::{
    definitions::constants::TRANSACTION_VERSION,
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::cached_state::CachedState,
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
};
use std::sync::Arc;
use std::{collections::HashMap, path::PathBuf};

#[test]
fn integration_test() {
    // ---------------------------------------------------------
    //  Create program and entry point types for contract class
    // ---------------------------------------------------------

    let path = PathBuf::from("starknet_programs/fibonacci.json");
    let contract_class = ContractClass::from_path(path).unwrap();
    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    let fib_entrypoint_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(0)
        .unwrap()
        .selector()
        .clone();

    //* --------------------------------------------
    //*    Create state reader with class hash data
    //* --------------------------------------------

    let mut contract_class_cache = HashMap::new();

    //  ------------ contract data --------------------

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

    //* ---------------------------------------
    //*    Create state with previous data
    //* ---------------------------------------

    let mut state =
        CachedState::new(Arc::new(state_reader)).set_contract_classes_cache(contract_class_cache);

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let calldata = [1.into(), 1.into(), 10.into()].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata.clone(),
        fib_entrypoint_selector.clone(),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        0,
    );

    //* --------------------
    //*   Execute contract
    //* ---------------------
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
        true,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(fib_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata,
        retdata: [144.into()].to_vec(),
        class_hash: Some(class_hash),
        execution_resources: Some(ExecutionResources {
            n_steps: 94,
            ..Default::default()
        }),
        ..Default::default()
    };

    assert_eq!(
        exec_entry_point
            .execute(
                &mut state,
                &block_context,
                &mut resources_manager,
                &mut tx_execution_context,
                false,
                block_context.invoke_tx_max_n_steps(),
            )
            .unwrap()
            .call_info
            .unwrap(),
        expected_call_info
    );
}

#[test]
fn integration_test_erc20() {
    let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/erc20.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    let entrypoints = sierra_contract_class.clone().entry_points_by_type;
    let constructor_entry_point_selector = &entrypoints.constructor.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut sierra_contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    sierra_contract_class_cache.insert(class_hash, sierra_contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader))
        .set_sierra_programs_cache(sierra_contract_class_cache);

    /*
        1 recipient
        2 name
        3 decimals
        4 initial_supply
        5 symbol
    */
    let calldata = [1.into(), 2.into(), 3.into(), 4.into(), 5.into()].to_vec();

    let result = execute(
        &mut state,
        constructor_entry_point_selector,
        &calldata,
        EntryPointType::Constructor,
    );

    assert_eq!(result.caller_address, Address(123456789.into()));
    assert_eq!(result.call_type, Some(CallType::Delegate));
    assert_eq!(result.contract_address, Address(1111.into()));
    assert_eq!(
        result.entry_point_selector,
        Some(Felt252::new(constructor_entry_point_selector))
    );
    assert_eq!(result.entry_point_type, Some(EntryPointType::Constructor));
    assert_eq!(result.calldata, calldata);
    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [].to_vec());
    assert_eq!(result.execution_resources, None);
    assert_eq!(result.class_hash, Some(class_hash));
    assert_eq!(result.gas_consumed, 0);

    let get_decimals_entry_point_selector = &entrypoints.external.get(1).unwrap().selector;
    let calldata = [].to_vec();

    let result = execute(
        &mut state,
        get_decimals_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [3.into()].to_vec());

    let allowance_entry_point_selector = &entrypoints.external.get(3).unwrap().selector;
    let calldata = [123456789.into(), 1.into()].to_vec();

    let result = execute(
        &mut state,
        allowance_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [0.into()].to_vec());

    let increase_allowance_entry_point_selector = &entrypoints.external.get(2).unwrap().selector;
    let calldata = [1.into(), 10_000.into()].to_vec();

    let result = execute(
        &mut state,
        increase_allowance_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [].to_vec());

    let calldata = [123456789.into(), 1.into()].to_vec();

    let result = execute(
        &mut state,
        allowance_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert_eq!(result.retdata, [10_000.into()].to_vec());
}

fn execute(
    state: &mut CachedState<InMemoryStateReader>,
    selector: &BigUint,
    calldata: &[Felt252],
    entrypoint_type: EntryPointType,
) -> CallInfo {
    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];

    // Dummy calldata
    let caller_address = Address(123456789.into());
    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata.to_vec(),
        Felt252::new(selector),
        caller_address,
        entrypoint_type,
        Some(CallType::Delegate),
        Some(class_hash),
        u128::MAX,
    );

    // Execute the entrypoint
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
        true,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    exec_entry_point
        .execute(
            state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
        )
        .unwrap()
        .call_info
        .unwrap()
}
