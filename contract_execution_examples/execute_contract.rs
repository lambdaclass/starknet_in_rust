#![deny(warnings)]

use felt::Felt;
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext},
        },
        fact_state::{
            contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    definitions::{
        constants::TRANSACTION_VERSION,
        general_config::StarknetGeneralConfig,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    starknet_storage::dict_storage::DictStorage,
    utils::{calculate_sn_keccak, Address},
};
use std::path::Path;

fn test_contract(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    call_data: Vec<Felt>,
    return_data: impl Into<Vec<Felt>>,
) {
    let contract_class = ContractClass::try_from(contract_path.as_ref().to_path_buf())
        .expect("Could not load contract from JSON");



    //* --------------------------------------------
    //*       Create a default contract data
    //* --------------------------------------------

    let contract_address = Address(1111.into());
    let class_hash = [1; 32];

    //* --------------------------------------------
    //*          Create default context
    //* --------------------------------------------

    let general_config = StarknetGeneralConfig::default();

    let tx_execution_context =
        TransactionExecutionContext::create_for_testing(
            Address(0.into()),
            10,
            0.into(),
            general_config.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION,
        );

    //* --------------------------------------------
    //*  Create starknet state with the contract
    //*  (This would be the equivalent of
    //*  declaring and deploying the contract)
    //* -------------------------------------------

    let contract_state = ContractState::new(
        class_hash,
        tx_execution_context.nonce().clone(),
        Default::default(),
    );
    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);

    let mut state = CachedState::new(
        state_reader,
        Some([(class_hash, contract_class)].into_iter().collect()),
    );

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let caller_address = Address(0.into());

    let entry_point_selector = Felt::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));
    let entry_point = ExecutionEntryPoint::new(
        contract_address.clone(),
        call_data.clone(),
        entry_point_selector.clone(),
        caller_address.clone(),
        EntryPointType::External,
        CallType::Delegate.into(),
        class_hash.into(),
    );

    let mut resources_manager = ExecutionResourcesManager::default();

    assert_eq!(
        entry_point
            .execute(
                &mut state,
                &general_config,
                &mut resources_manager,
                &tx_execution_context,
            )
            .expect("Could not execute contract"),
        CallInfo {
            contract_address,
            caller_address,
            entry_point_type: EntryPointType::External.into(),
            call_type: CallType::Delegate.into(),
            class_hash: class_hash.into(),
            entry_point_selector: Some(entry_point_selector),
            calldata: call_data.into(),
            retdata: return_data.into(),
            ..Default::default()
        },
    );
}

#[test]
fn test_fibonacci(){
    test_contract(
        "starknet_programs/fibonacci.json",
        "fib",
        [1.into(), 1.into(), 10.into()].to_vec(),
        [144.into()].to_vec(),
    );
}

#[test]
fn test_factorial(){
    test_contract("starknet_programs/factorial.json",
        "factorial",
        [10.into()].to_vec(),
        [3628800.into()].to_vec()
    );
}
