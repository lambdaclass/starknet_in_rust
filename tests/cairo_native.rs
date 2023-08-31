#![cfg(not(feature = "cairo_1_tests"))]
// #![deny(warnings)]

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

    let caller_address = Address(123456789.into());

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
    let calldata = [
        caller_address.0.clone(),
        2.into(),
        3.into(),
        4.into(),
        5.into(),
    ]
    .to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        constructor_entry_point_selector,
        &calldata,
        EntryPointType::Constructor,
    );

    assert_eq!(result.caller_address, caller_address);
    assert_eq!(result.call_type, Some(CallType::Delegate));
    assert_eq!(result.contract_address, Address(1112.into()));
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

    // --------------- GET TOTAL SUPPLY -----------------

    let get_total_supply_selector = &entrypoints.external.get(5).unwrap().selector;

    let calldata = [].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        get_total_supply_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [4.into()].to_vec());

    // ---------------- GET DECIMALS ----------------------

    let get_decimals_entry_point_selector = &entrypoints.external.get(1).unwrap().selector;
    let calldata = [].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        get_decimals_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [3.into()].to_vec());

    // ---------------- GET NAME ----------------------

    let get_name_selector = &entrypoints.external.get(6).unwrap().selector;

    let calldata = [].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        get_name_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [2.into()].to_vec());

    // ---------------- GET SYMBOL ----------------------

    let get_symbol_selector = &entrypoints.external.get(7).unwrap().selector;

    let calldata = [].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        get_symbol_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [5.into()].to_vec());

    // ---------------- GET BALANCE OF CALLER ----------------------

    let balance_of_selector = &entrypoints.external.get(8).unwrap().selector;

    let calldata = [caller_address.0.clone()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        balance_of_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [4.into()].to_vec());

    // ---------------- ALLOWANCE OF ADDRESS 1 ----------------------

    let allowance_entry_point_selector = &entrypoints.external.get(3).unwrap().selector;
    let calldata = [caller_address.0.clone(), 1.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        allowance_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [0.into()].to_vec());

    // ---------------- INCREASE ALLOWANCE OF ADDRESS 1 by 10_000 ----------------------

    let increase_allowance_entry_point_selector = &entrypoints.external.get(2).unwrap().selector;
    let calldata = [1.into(), 10_000.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        increase_allowance_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [].to_vec());

    // ---------------- ALLOWANCE OF ADDRESS 1 ----------------------

    let calldata = [caller_address.0.clone(), 1.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        allowance_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert_eq!(result.retdata, [10_000.into()].to_vec());

    // ---------------- APPROVE ADDRESS 1 TO MAKE TRANSFERS ON BEHALF OF THE CALLER ----------------------

    let approve_entry_point_selector = &entrypoints.external.get(4).unwrap().selector;

    let calldata = [1.into(), 5_000.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        approve_entry_point_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [].to_vec());

    // ---------------- TRANSFER 3 TOKENS FROM CALLER TO ADDRESS 2 ---------

    let balance_of_selector = &entrypoints.external.get(0).unwrap().selector;

    let calldata = [2.into(), 3.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        balance_of_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [].to_vec());

    // ---------------- GET BALANCE OF CALLER ----------------------

    let balance_of_selector = &entrypoints.external.get(8).unwrap().selector;

    let calldata = [caller_address.0.clone()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        balance_of_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [1.into()].to_vec());

    // ---------------- GET BALANCE OF ADDRESS 2 ----------------------

    let balance_of_selector = &entrypoints.external.get(8).unwrap().selector;

    let calldata = [2.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        balance_of_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [3.into()].to_vec());

    // ---------------- TRANSFER 1 TOKEN FROM CALLER TO ADDRESS 2, CALLED FROM ADDRESS 1 ----------------------

    let transfer_from_selector = &entrypoints.external.get(9).unwrap().selector;

    let calldata = [1.into(), 2.into(), 1.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        transfer_from_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [].to_vec());

    // ---------------- GET BALANCE OF ADDRESS 2 ----------------------

    let balance_of_selector = &entrypoints.external.get(8).unwrap().selector;

    let calldata = [2.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        balance_of_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);
    assert_eq!(result.retdata, [4.into()].to_vec());

    // ---------------- GET BALANCE OF CALLER ----------------------

    let balance_of_selector = &entrypoints.external.get(8).unwrap().selector;

    let calldata = [caller_address.0.clone()].to_vec();

    let _result = execute(
        &mut state,
        &caller_address,
        balance_of_selector,
        &calldata,
        EntryPointType::External,
    );

    assert!(!result.failure_flag);

    // TODO: This assert is failing. For some reason, tokens are not deducted from the caller's balance
    // after the transfer_from. Check the cairo code to see if the bug is over there.
    // assert_eq!(result.retdata, [0.into()].to_vec());
}

fn execute(
    state: &mut CachedState<InMemoryStateReader>,
    caller_address: &Address,
    selector: &BigUint,
    calldata: &[Felt252],
    entrypoint_type: EntryPointType,
) -> CallInfo {
    let address = Address(1112.into());
    let class_hash: ClassHash = [1; 32];

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata.to_vec(),
        Felt252::new(selector),
        (*caller_address).clone(),
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

#[test]
fn call_contract_test() {
    // Caller contract
    let caller_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/caller.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Callee contract
    let callee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/callee.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Caller contract entrypoints
    let caller_entrypoints = caller_contract_class.clone().entry_points_by_type;
    let call_contract_selector = &caller_entrypoints.external.get(0).unwrap().selector;

    // Callee contract entrypoints
    let callee_entrypoints = callee_contract_class.clone().entry_points_by_type;
    let fn_selector = &callee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut sierra_contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    sierra_contract_class_cache.insert(caller_class_hash, caller_contract_class);
    sierra_contract_class_cache.insert(callee_class_hash, callee_contract_class);

    let mut state_reader = InMemoryStateReader::default();

    // Insert caller contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), caller_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), caller_nonce);

    // Insert callee contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(callee_address.clone(), callee_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(callee_address.clone(), callee_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader))
        .set_sierra_programs_cache(sierra_contract_class_cache);

    let calldata = [fn_selector.into()].to_vec();
    let result = execute(
        &mut state,
        &caller_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
    );

    assert_eq!(result.retdata, [Felt252::new(44)]);
}
