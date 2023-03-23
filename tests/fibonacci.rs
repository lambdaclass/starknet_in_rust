#![deny(warnings)]

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt252;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{Address, ClassHash},
};
use std::{collections::HashMap, path::PathBuf};

#[test]
fn integration_test() {
    // ---------------------------------------------------------
    //  Create program and entry point types for contract class
    // ---------------------------------------------------------

    let path = PathBuf::from("starknet_programs/fibonacci.json");
    let contract_class = ContractClass::try_from(path).unwrap();
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

    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

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

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(fib_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata,
        retdata: [144.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        ..Default::default()
    };

    assert_eq!(
        exec_entry_point
            .execute(
                &mut state,
                &general_config,
                &mut resources_manager,
                &tx_execution_context
            )
            .unwrap(),
        expected_call_info
    );
}
