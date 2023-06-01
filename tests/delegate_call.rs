#![deny(warnings)]

mod cairo_1_syscalls;

use cairo_vm::felt::Felt252;
use num_traits::{One, Zero};
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallType, TransactionExecutionContext},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_classes::deprecated_contract_class::{ContractClass, EntryPointType},
    utils::Address,
};
use std::{collections::HashMap, path::PathBuf};

#[test]
fn delegate_call() {
    //* --------------------------------------------
    //*    Create state reader with class hash data
    //* --------------------------------------------

    let mut contract_class_cache = HashMap::new();
    let nonce = Felt252::zero();

    // Add get_number.cairo contract to the state

    let path = PathBuf::from("starknet_programs/get_number.json");
    let contract_class = ContractClass::try_from(path).unwrap();

    let address = Address(Felt252::one()); // const CONTRACT_ADDRESS = 1;
    let class_hash = [2; 32];

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address, nonce.clone());

    // ---------------------------------------------------------
    //  Create program and entry point types for contract class
    // ---------------------------------------------------------

    let path = PathBuf::from("starknet_programs/delegate_call.json");
    let contract_class = ContractClass::try_from(path).unwrap();
    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    // External entry point, delegate_call function delegate.cairo:L13
    let test_delegate_call_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(0)
        .unwrap()
        .selector()
        .clone();

    //  ------------ contract data --------------------

    let address = Address(1111.into());
    let class_hash = [1; 32];

    contract_class_cache.insert(class_hash, contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    //* ---------------------------------------
    //*    Create state with previous data
    //* ---------------------------------------

    let mut state = CachedState::new(state_reader, Some(contract_class_cache), None);

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let calldata = [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        test_delegate_call_selector,
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        0,
    );

    //* --------------------
    //*   Execute contract
    //* ---------------------
    let general_config = StarknetGeneralConfig::default();
    let tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    // assert!(
    //     exec_entry_point
    //         .execute(
    //             &mut state,
    //             &general_config,
    //             &mut resources_manager,
    //             &tx_execution_context,
    //             false,
    //         )
    //         .is_ok()
    // );
}
