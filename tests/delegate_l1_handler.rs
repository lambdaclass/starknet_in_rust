#![deny(warnings)]

mod cairo_1_syscalls;

use cairo_vm::felt::{felt_str, Felt252};
use num_traits::{One, Zero};
use starknet_in_rust::EntryPointType;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{
        cached_state::CachedState, in_memory_state_reader::InMemoryStateReader,
        ExecutionResourcesManager,
    },
    utils::Address,
};
use std::{collections::HashMap, path::PathBuf};

#[test]
fn delegate_l1_handler() {
    //* --------------------------------------------
    //*    Create state reader with class hash data
    //* --------------------------------------------
    let mut contract_class_cache = HashMap::new();
    let nonce = Felt252::zero();

    // Add get_number.cairo contract to the state

    let path = PathBuf::from("starknet_programs/get_number_l1_handler.json");
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

    let path = PathBuf::from("starknet_programs/delegate_l1_handler.json");
    let contract_class = ContractClass::try_from(path).unwrap();

    // External entry point, delegate_call function delegate.cairo:L13
    let test_delegate_l1_handler_selector =
        felt_str!("517623934924705024901038305335656287487647971342355715053765242809192309107");

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
        test_delegate_l1_handler_selector,
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
    );
    let mut resources_manager = ExecutionResourcesManager::default();
    assert!(exec_entry_point
        .execute(
            &mut state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
        )
        .is_ok());
}
