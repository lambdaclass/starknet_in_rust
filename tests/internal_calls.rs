#![deny(warnings)]

use felt::Felt;
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallType, TransactionExecutionContext},
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
    utils::{calculate_sn_keccak, Address},
};
use std::path::PathBuf;

#[test]
fn test_internal_calls() {
    let contract_class =
        ContractClass::try_from(PathBuf::from("starknet_programs/internal_calls.json"))
            .expect("Could not load contract from JSON");

    let general_config = StarknetGeneralConfig::default();
    let tx_execution_context = TransactionExecutionContext::create_for_testing(
        Address(0.into()),
        10,
        0.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );

    let contract_state = ContractState::new(
        [0x01; 32],
        tx_execution_context.nonce().clone(),
        Default::default(),
    );
    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    state_reader
        .contract_states_mut()
        .insert(Address(1111.into()), contract_state);

    let mut state = CachedState::new(
        state_reader,
        Some([([0x01; 32], contract_class)].into_iter().collect()),
    );

    let entry_point_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"a"));
    let entry_point = ExecutionEntryPoint::new(
        Address(1111.into()),
        vec![],
        entry_point_selector,
        Address(1111.into()),
        EntryPointType::External,
        CallType::Delegate.into(),
        Some([0x01; 32]),
    );

    let mut resources_manager = ExecutionResourcesManager::default();

    let call_info = entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
        )
        .expect("Could not execute contract");

    assert_eq!(call_info.internal_calls.len(), 1);
    assert_eq!(call_info.internal_calls[0].internal_calls.len(), 1);
    assert!(call_info.internal_calls[0].internal_calls[0]
        .internal_calls
        .is_empty());
}
