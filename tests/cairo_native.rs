#![cfg(all(feature = "cairo-native", not(feature = "cairo_1_tests")))]

use crate::CallType::Call;
use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use num_traits::Zero;
use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
#[cfg(feature = "cairo-native")]
use starknet_api::block::Block;
use starknet_api::hash::StarkHash;
use starknet_in_rust::definitions::block_context::BlockContext;
use starknet_in_rust::execution::{Event, OrderedEvent};
use starknet_in_rust::services::api::contract_classes::compiled_class::CompiledClass;
use starknet_in_rust::CasmContractClass;
use starknet_in_rust::EntryPointType::{self, External};
use starknet_in_rust::{
    definitions::constants::TRANSACTION_VERSION,
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    state::cached_state::CachedState,
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::println;
use std::sync::Arc;

#[test]
#[cfg(feature = "cairo-native")]
fn get_block_hash_test() {
    use starknet_in_rust::utils::felt_to_hash;

    let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/get_block_hash_basic.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    let casm_data = include_bytes!("../starknet_programs/cairo2/get_block_hash_basic.casm");
    let casm_contract_class: CasmContractClass = serde_json::from_slice(casm_data).unwrap();

    let native_entrypoints = sierra_contract_class.clone().entry_points_by_type;
    let native_external_selector = &native_entrypoints.external.get(0).unwrap().selector;

    let casm_entrypoints = casm_contract_class.clone().entry_points_by_type;
    let casm_external_selector = &casm_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let native_class_hash: ClassHash = [1; 32];
    let casm_class_hash: ClassHash = [2; 32];
    let caller_address = Address(1.into());

    contract_class_cache.insert(
        native_class_hash,
        CompiledClass::Sierra(Arc::new(sierra_contract_class)),
    );
    contract_class_cache.insert(
        casm_class_hash,
        CompiledClass::Casm(Arc::new(casm_contract_class)),
    );

    let mut state_reader = InMemoryStateReader::default();
    let nonce = Felt252::zero();

    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), casm_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let state_reader = Arc::new(state_reader);
    let mut state_vm = CachedState::new(state_reader.clone(), contract_class_cache.clone());
    state_vm.cache_mut().storage_initial_values_mut().insert(
        (Address(1.into()), felt_to_hash(&Felt252::from(10))),
        Felt252::from_bytes_be(StarkHash::new([5; 32]).unwrap().bytes()),
    );
    let mut state_native = CachedState::new(state_reader, contract_class_cache);
    state_native
        .cache_mut()
        .storage_initial_values_mut()
        .insert(
            (Address(1.into()), felt_to_hash(&Felt252::from(10))),
            Felt252::from_bytes_be(StarkHash::new([5; 32]).unwrap().bytes()),
        );
    /*
        1 recipient
    */

    let calldata = [10.into()].to_vec();

    println!("Native execution");
    let native_result = execute(
        &mut state_native,
        &caller_address,
        &caller_address,
        native_external_selector,
        &calldata,
        EntryPointType::External,
        &native_class_hash,
    );

    println!("VM execution");
    let vm_result = execute(
        &mut state_vm,
        &caller_address,
        &caller_address,
        casm_external_selector,
        &calldata,
        EntryPointType::External,
        &casm_class_hash,
    );

    assert_eq!(vm_result.caller_address, caller_address);
    assert_eq!(vm_result.call_type, Some(CallType::Delegate));
    assert_eq!(vm_result.contract_address, caller_address);
    assert_eq!(
        vm_result.entry_point_selector,
        Some(Felt252::new(casm_external_selector))
    );
    assert_eq!(vm_result.entry_point_type, Some(EntryPointType::External));
    assert_eq!(vm_result.calldata, calldata);
    assert!(!vm_result.failure_flag);
    assert_eq!(
        vm_result.retdata,
        [Felt252::from_bytes_be(
            StarkHash::new([5; 32]).unwrap().bytes()
        )]
        .to_vec()
    );
    assert_eq!(vm_result.class_hash, Some(casm_class_hash));

    assert_eq!(native_result.caller_address, caller_address);
    assert_eq!(native_result.call_type, Some(CallType::Delegate));
    assert_eq!(native_result.contract_address, caller_address);
    assert_eq!(
        native_result.entry_point_selector,
        Some(Felt252::new(native_external_selector))
    );
    assert_eq!(
        native_result.entry_point_type,
        Some(EntryPointType::External)
    );
    assert_eq!(native_result.calldata, calldata);
    assert!(!native_result.failure_flag);
    assert_eq!(
        native_result.retdata,
        [Felt252::from_bytes_be(
            StarkHash::new([5; 32]).unwrap().bytes()
        )]
        .to_vec()
    );
    assert_eq!(native_result.execution_resources, None);
    assert_eq!(native_result.class_hash, Some(native_class_hash));
    //assert_eq!(native_result.gas_consumed, 0);

    assert_eq!(vm_result.events, native_result.events);
    assert_eq!(
        vm_result.accessed_storage_keys,
        native_result.accessed_storage_keys
    );
    assert_eq!(vm_result.l2_to_l1_messages, native_result.l2_to_l1_messages);
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

    let casm_data = include_bytes!("../starknet_programs/cairo2/erc20.casm");
    let casm_contract_class: CasmContractClass = serde_json::from_slice(casm_data).unwrap();

    let native_entrypoints = sierra_contract_class.clone().entry_points_by_type;
    let native_constructor_selector = &native_entrypoints.constructor.get(0).unwrap().selector;

    let casm_entrypoints = casm_contract_class.clone().entry_points_by_type;
    let casm_constructor_selector = &casm_entrypoints.constructor.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let native_class_hash: ClassHash = [1; 32];
    let casm_class_hash: ClassHash = [2; 32];

    let caller_address = Address(123456789.into());

    contract_class_cache.insert(
        native_class_hash,
        CompiledClass::Sierra(Arc::new(sierra_contract_class)),
    );
    contract_class_cache.insert(
        casm_class_hash,
        CompiledClass::Casm(Arc::new(casm_contract_class)),
    );
    let mut state_reader = InMemoryStateReader::default();
    let nonce = Felt252::zero();

    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), casm_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let state_reader = Arc::new(state_reader);
    let mut state_vm = CachedState::new(state_reader.clone(), contract_class_cache.clone());
    let mut state_native = CachedState::new(state_reader, contract_class_cache);

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

    let vm_result = execute(
        &mut state_vm,
        &caller_address,
        &caller_address,
        casm_constructor_selector,
        &calldata,
        EntryPointType::Constructor,
        &casm_class_hash,
    );

    let native_result = execute(
        &mut state_native,
        &caller_address,
        &caller_address,
        native_constructor_selector,
        &calldata,
        EntryPointType::Constructor,
        &native_class_hash,
    );

    assert_eq!(vm_result.caller_address, caller_address);
    assert_eq!(vm_result.call_type, Some(CallType::Delegate));
    assert_eq!(vm_result.contract_address, caller_address);
    assert_eq!(
        vm_result.entry_point_selector,
        Some(Felt252::new(casm_constructor_selector))
    );
    assert_eq!(
        vm_result.entry_point_type,
        Some(EntryPointType::Constructor)
    );
    assert_eq!(vm_result.calldata, calldata);
    assert!(!vm_result.failure_flag);
    assert_eq!(vm_result.retdata, [].to_vec());
    assert_eq!(vm_result.class_hash, Some(casm_class_hash));

    assert_eq!(native_result.caller_address, caller_address);
    assert_eq!(native_result.call_type, Some(CallType::Delegate));
    assert_eq!(native_result.contract_address, caller_address);
    assert_eq!(
        native_result.entry_point_selector,
        Some(Felt252::new(native_constructor_selector))
    );
    assert_eq!(
        native_result.entry_point_type,
        Some(EntryPointType::Constructor)
    );
    assert_eq!(native_result.calldata, calldata);
    assert!(!native_result.failure_flag);
    assert_eq!(native_result.retdata, [].to_vec());
    assert_eq!(native_result.execution_resources, None);
    assert_eq!(native_result.class_hash, Some(native_class_hash));
    assert_eq!(native_result.gas_consumed, 18446744073709551615); // (u64::MAX)

    assert_eq!(vm_result.events, native_result.events);
    assert_eq!(
        vm_result.accessed_storage_keys,
        native_result.accessed_storage_keys
    );
    assert_eq!(vm_result.l2_to_l1_messages, native_result.l2_to_l1_messages);
    // TODO: Make these asserts work
    // assert_eq!(vm_result.execution_resources, native_result.execution_resources);
    // assert_eq!(vm_result.gas_consumed, native_result.gas_consumed);

    // --------------- GET TOTAL SUPPLY -----------------

    let native_get_total_supply_selector = &native_entrypoints.external.get(5).unwrap().selector;
    let casm_get_total_supply_selector = &casm_entrypoints.external.get(5).unwrap().selector;

    let calldata = [].to_vec();

    let vm_result = execute(
        &mut state_vm,
        &caller_address,
        &caller_address,
        casm_get_total_supply_selector,
        &calldata,
        EntryPointType::External,
        &casm_class_hash,
    );

    println!("BEFORE");
    let native_result = execute(
        &mut state_native,
        &caller_address,
        &caller_address,
        native_get_total_supply_selector,
        &calldata,
        EntryPointType::External,
        &native_class_hash,
    );
    println!("AFTER");

    assert!(!vm_result.failure_flag);
    assert_eq!(vm_result.retdata, [4.into()].to_vec());

    assert!(!native_result.failure_flag);
    assert_eq!(native_result.retdata, [4.into()].to_vec());

    assert_eq!(vm_result.events, native_result.events);
    assert_eq!(
        vm_result.accessed_storage_keys,
        native_result.accessed_storage_keys
    );
    assert_eq!(vm_result.l2_to_l1_messages, native_result.l2_to_l1_messages);
    // TODO: Make these asserts work
    // assert_eq!(vm_result.execution_resources, native_result.execution_resources);
    // assert_eq!(vm_result.gas_consumed, native_result.gas_consumed);

    // // ---------------- GET DECIMALS ----------------------

    // let native_get_decimals_selector = &native_entrypoints.external.get(1).unwrap().selector;
    // let casm_get_decimals_selector = &casm_entrypoints.external.get(1).unwrap().selector;
    // let calldata = [].to_vec();

    // let vm_result = execute(
    //     &mut state_vm,
    //     &caller_address,
    //     &caller_address,
    //     casm_get_decimals_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &casm_class_hash,
    // );

    // let native_result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     native_get_decimals_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!vm_result.failure_flag);
    // assert_eq!(vm_result.retdata, [3.into()].to_vec());

    // assert!(!native_result.failure_flag);
    // assert_eq!(native_result.retdata, [3.into()].to_vec());

    // assert_eq!(vm_result.events, native_result.events);
    // assert_eq!(
    //     vm_result.accessed_storage_keys,
    //     native_result.accessed_storage_keys
    // );
    // assert_eq!(vm_result.l2_to_l1_messages, native_result.l2_to_l1_messages);
    // // TODO: Make these asserts work
    // // assert_eq!(vm_result.execution_resources, native_result.execution_resources);
    // // assert_eq!(vm_result.gas_consumed, native_result.gas_consumed);

    // // ---------------- GET NAME ----------------------

    // let get_name_selector = &native_entrypoints.external.get(6).unwrap().selector;

    // let calldata = [].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     get_name_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [2.into()].to_vec());

    // // ---------------- GET SYMBOL ----------------------

    // let get_symbol_selector = &native_entrypoints.external.get(7).unwrap().selector;

    // let calldata = [].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     get_symbol_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [5.into()].to_vec());

    // // ---------------- GET BALANCE OF CALLER ----------------------

    // let balance_of_selector = &native_entrypoints.external.get(8).unwrap().selector;

    // let calldata = [caller_address.0.clone()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     balance_of_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [4.into()].to_vec());

    // // ---------------- ALLOWANCE OF ADDRESS 1 ----------------------

    // let allowance_entry_point_selector = &native_entrypoints.external.get(3).unwrap().selector;
    // let calldata = [caller_address.0.clone(), 1.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     allowance_entry_point_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [0.into()].to_vec());

    // // ---------------- INCREASE ALLOWANCE OF ADDRESS 1 by 10_000 ----------------------

    // let increase_allowance_entry_point_selector =
    //     &native_entrypoints.external.get(2).unwrap().selector;
    // let calldata = [1.into(), 10_000.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     increase_allowance_entry_point_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [].to_vec());

    // // ---------------- ALLOWANCE OF ADDRESS 1 ----------------------

    // let calldata = [caller_address.0.clone(), 1.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     allowance_entry_point_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert_eq!(result.retdata, [10_000.into()].to_vec());

    // // ---------------- APPROVE ADDRESS 1 TO MAKE TRANSFERS ON BEHALF OF THE CALLER ----------------------

    // let approve_entry_point_selector = &native_entrypoints.external.get(4).unwrap().selector;

    // let calldata = [1.into(), 5_000.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     approve_entry_point_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [].to_vec());

    // // ---------------- TRANSFER 3 TOKENS FROM CALLER TO ADDRESS 2 ---------

    // let balance_of_selector = &native_entrypoints.external.get(0).unwrap().selector;

    // let calldata = [2.into(), 3.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     balance_of_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [].to_vec());

    // // ---------------- GET BALANCE OF CALLER ----------------------

    // let balance_of_selector = &native_entrypoints.external.get(8).unwrap().selector;

    // let calldata = [caller_address.0.clone()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     balance_of_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [1.into()].to_vec());

    // // ---------------- GET BALANCE OF ADDRESS 2 ----------------------

    // let balance_of_selector = &native_entrypoints.external.get(8).unwrap().selector;

    // let calldata = [2.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     balance_of_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [3.into()].to_vec());

    // // ---------------- TRANSFER 1 TOKEN FROM CALLER TO ADDRESS 2, CALLED FROM ADDRESS 1 ----------------------

    // let transfer_from_selector = &native_entrypoints.external.get(9).unwrap().selector;

    // let calldata = [1.into(), 2.into(), 1.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     transfer_from_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [].to_vec());

    // // ---------------- GET BALANCE OF ADDRESS 2 ----------------------

    // let balance_of_selector = &native_entrypoints.external.get(8).unwrap().selector;

    // let calldata = [2.into()].to_vec();

    // let result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     balance_of_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);
    // assert_eq!(result.retdata, [4.into()].to_vec());

    // // ---------------- GET BALANCE OF CALLER ----------------------

    // let balance_of_selector = &native_entrypoints.external.get(8).unwrap().selector;

    // let calldata = [caller_address.0.clone()].to_vec();

    // let _result = execute(
    //     &mut state_native,
    //     &caller_address,
    //     &caller_address,
    //     balance_of_selector,
    //     &calldata,
    //     EntryPointType::External,
    //     &native_class_hash,
    // );

    // assert!(!result.failure_flag);

    // // TODO: This assert is failing. For some reason, tokens are not deducted from the caller's balance
    // // after the transfer_from. Check the cairo code to see if the bug is over there.
    // // assert_eq!(result.retdata, [0.into()].to_vec());
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
    let mut contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    contract_class_cache.insert(
        caller_class_hash,
        CompiledClass::Sierra(Arc::new(caller_contract_class)),
    );
    contract_class_cache.insert(
        callee_class_hash,
        CompiledClass::Sierra(Arc::new(callee_contract_class)),
    );

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
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [fn_selector.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        &callee_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
        &caller_class_hash,
    );

    assert_eq!(result.retdata, [Felt252::new(44)]);
}

#[test]
fn call_echo_contract_test() {
    // Caller contract
    let caller_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/echo_caller.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Callee contract
    let callee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/echo.sierra")
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
    let mut contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    contract_class_cache.insert(
        caller_class_hash,
        CompiledClass::Sierra(Arc::new(caller_contract_class)),
    );

    contract_class_cache.insert(
        callee_class_hash,
        CompiledClass::Sierra(Arc::new(callee_contract_class)),
    );

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
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [fn_selector.into(), 99999999.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        &callee_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
        &caller_class_hash,
    );

    assert_eq!(result.retdata, [Felt252::new(99999999)]);
}

#[test]
#[cfg(feature = "cairo-native")]
fn call_events_contract_test() {
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
            std::fs::read_to_string("starknet_programs/cairo2/event_emitter.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Caller contract entrypoints
    let caller_entrypoints = caller_contract_class.clone().entry_points_by_type;
    let call_contract_selector = &caller_entrypoints.external.get(0).unwrap().selector;

    // Event emmitter contract entrypoints
    let callee_entrypoints = callee_contract_class.clone().entry_points_by_type;
    let fn_selector = &callee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    contract_class_cache.insert(
        caller_class_hash,
        CompiledClass::Sierra(Arc::new(caller_contract_class)),
    );

    contract_class_cache.insert(
        callee_class_hash,
        CompiledClass::Sierra(Arc::new(callee_contract_class)),
    );

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
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [fn_selector.into()].to_vec();

    let result = execute(
        &mut state,
        &caller_address,
        &callee_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
        &caller_class_hash,
    );

    let internal_call = CallInfo {
        caller_address: Address(1111.into()),
        call_type: Some(Call),
        contract_address: Address(1112.into()),
        code_address: None,
        class_hash: Some([
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2,
        ]),
        entry_point_selector: Some(fn_selector.into()),
        entry_point_type: Some(External),
        calldata: Vec::new(),
        retdata: vec![1234.into()],
        execution_resources: None,
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![110.into()],
            data: vec![1.into()],
        }],
        l2_to_l1_messages: Vec::new(),
        storage_read_values: Vec::new(),
        accessed_storage_keys: HashSet::new(),
        internal_calls: Vec::new(),
        gas_consumed: 340282366920938463463374607431768211455, // TODO: fix gas consumed
        failure_flag: false,
    };

    let event = Event {
        from_address: Address(1112.into()),
        keys: vec![110.into()],
        data: vec![1.into()],
    };

    assert_eq!(result.retdata, [1234.into()]);
    assert_eq!(result.events, []);
    assert_eq_sorted!(result.internal_calls, [internal_call]);

    let sorted_events = result.get_sorted_events().unwrap();
    assert_eq!(sorted_events, vec![event]);
}

fn execute(
    state: &mut CachedState<InMemoryStateReader>,
    caller_address: &Address,
    callee_address: &Address,
    selector: &BigUint,
    calldata: &[Felt252],
    entrypoint_type: EntryPointType,
    class_hash: &ClassHash,
) -> CallInfo {
    let exec_entry_point = ExecutionEntryPoint::new(
        (*callee_address).clone(),
        calldata.to_vec(),
        Felt252::new(selector),
        (*caller_address).clone(),
        entrypoint_type,
        Some(CallType::Delegate),
        Some(*class_hash),
        u64::MAX.into(), // gas is u64 in cairo-native and sierra
    );

    // Execute the entrypoint
    // Todo: Insert block with custom adress and custom hash to check is obtained correctly

    let mut block_context = BlockContext::default();
    block_context.blocks_mut().insert(10, Block::default());

    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
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
