#![deny(warnings)]

use felt::Felt;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallType, TransactionExecutionContext},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{
            cached_state::CachedState,
            state_cache::StorageEntry,
        }
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, Address, ClassHash},
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

    let address = Address(1111.into());
    let class_hash: ClassHash = [0; 32].into();
    let nonce = Felt::zero();
    let storage_entry: StorageEntry = (address.clone(), [1; 32]).into();
    let storage = Felt::zero();

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash
        .insert(address.clone(), class_hash.clone());
    state_reader
        .address_to_nonce
        .insert(address.clone(), nonce.clone());
    state_reader
        .address_to_storage
        .insert(storage_entry.clone(), storage.clone());

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
