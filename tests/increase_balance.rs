#![deny(warnings)]

use cairo_vm::felt::Felt252;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use num_traits::Zero;
use starknet_in_rust::EntryPointType;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{cached_state::CachedState, state_cache::StorageEntry},
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{calculate_sn_keccak, Address},
};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

#[test]
fn hello_starknet_increase_balance() {
    // ---------------------------------------------------------
    //  Create program and entry point types for contract class
    // ---------------------------------------------------------

    let path = PathBuf::from("starknet_programs/increase_balance.json");
    let contract_class = ContractClass::from_path(path).unwrap();
    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    // External entry point, increase_balance function increase_balance.cairo:L13
    let increase_balance_selector = entry_points_by_type
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
    let class_hash = [1; 32];
    let nonce = Felt252::zero();
    let storage_entry: StorageEntry = (address.clone(), [1; 32]);
    let storage = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);
    state_reader
        .address_to_storage_mut()
        .insert(storage_entry, storage);

    //* ---------------------------------------
    //*    Create state with previous data
    //* ---------------------------------------

    let mut state =
        CachedState::new(Arc::new(state_reader)).set_contract_classes_cache(contract_class_cache);

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let calldata = [1.into()].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata.clone(),
        increase_balance_selector.clone(),
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
        false,
    );
    let mut resources_manager = ExecutionResourcesManager::default();
    let expected_key = calculate_sn_keccak("balance".as_bytes());

    let mut expected_accessed_storage_keys = HashSet::new();
    expected_accessed_storage_keys.insert(expected_key);
    let expected_storage_read_values = vec![Felt252::zero()];

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(increase_balance_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata,
        retdata: [].to_vec(),
        execution_resources: Some(ExecutionResources {
            n_steps: 65,
            ..Default::default()
        }),
        class_hash: Some(class_hash),
        accessed_storage_keys: expected_accessed_storage_keys,
        storage_read_values: expected_storage_read_values,
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
                block_context.invoke_tx_max_n_steps()
            )
            .unwrap()
            .call_info
            .unwrap(),
        expected_call_info
    );
}
