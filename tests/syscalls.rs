#![deny(warnings)]

use felt::{felt_str, Felt};
use serde_json::Value;
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
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, EntryPointType},
    starknet_storage::dict_storage::DictStorage,
    utils::Address,
};
use std::{fs::read_to_string, path::Path};

// Workaround until the ABI is available.
fn find_entry_point_index(contract_path: impl AsRef<Path>, entry_point: &str) -> usize {
    let contract_data = read_to_string(contract_path).unwrap();
    let contract_data: Value = serde_json::from_str(&contract_data).unwrap();

    contract_data
        .get("abi")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .find_map(|(i, x)| (x.get("name").unwrap().as_str().unwrap() == entry_point).then_some(i))
        .unwrap()
}

fn test_contract(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    class_hash: [u8; 32],
    nonce: usize,
    contract_address: Address,
    caller_address: Address,
    return_data: impl Into<Vec<Felt>>,
) {
    let entry_point_index = find_entry_point_index(&contract_path, entry_point);

    let contract_class = ContractClass::try_from(contract_path.as_ref().to_path_buf())
        .expect("Could not load contract from JSON");

    let contract_state = ContractState::new(class_hash, nonce.into(), Default::default());
    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    let mut state = CachedState::new(
        state_reader,
        Some([(class_hash, contract_class.clone())].into_iter().collect()),
    );

    let entry_point_selector = contract_class
        .entry_points_by_type()
        .get(&EntryPointType::External)
        .map(|x| x[entry_point_index].selector().clone())
        .unwrap();
    let entry_point = ExecutionEntryPoint::new(
        Address(1111.into()),
        vec![],
        entry_point_selector.clone(),
        caller_address.clone(),
        EntryPointType::External,
        CallType::Delegate.into(),
        class_hash.into(),
    );

    let general_config = StarknetGeneralConfig::default();
    let tx_execution_context = TransactionExecutionContext::create_for_testing(
        Address(0.into()),
        10,
        nonce.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
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
            retdata: return_data.into(),
            ..Default::default()
        },
    );
}

#[test]
fn get_block_number_syscall() {
    test_contract(
        "tests/syscalls.json",
        "test_get_block_number",
        [1; 32],
        3,
        Address(1111.into()),
        Address(0.into()),
        [felt_str!("1"), felt_str!("0")],
    )
}

#[test]
fn get_block_timestamp_syscall() {
    test_contract(
        "tests/syscalls.json",
        "test_get_block_timestamp",
        [1; 32],
        3,
        Address(1111.into()),
        Address(0.into()),
        [felt_str!("1"), felt_str!("0")],
    )
}
