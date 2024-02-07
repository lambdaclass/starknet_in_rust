#![deny(warnings)]

use cairo_vm::Felt252;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState,
        contract_class_cache::{ContractClassCache, PermanentContractClassCache},
        in_memory_state_reader::InMemoryStateReader,
        state_cache::StorageEntry,
        ExecutionResourcesManager,
    },
    transaction::{Address, ClassHash},
    utils::calculate_sn_keccak,
    EntryPointType,
};
use std::sync::Arc;

#[test]
fn test_internal_calls() {
    let contract_class = ContractClass::from_path("starknet_programs/internal_calls.json")
        .expect("Could not load contract from JSON");

    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::create_for_testing(
        Address(0.into()),
        0.into(),
        block_context.invoke_tx_max_n_steps(),
        *TRANSACTION_VERSION,
    );

    let address = Address(1111.into());
    let class_hash: ClassHash = ClassHash([1; 32]);
    let nonce = Felt252::ZERO;
    let storage_entry: StorageEntry = (address.clone(), [1; 32]);
    let storage = Felt252::ZERO;

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader.address_to_nonce_mut().insert(address, nonce);
    state_reader
        .address_to_storage_mut()
        .insert(storage_entry, storage);

    let mut state = CachedState::new(
        Arc::new(state_reader),
        Arc::new({
            let cache = PermanentContractClassCache::default();
            cache.set_contract_class(
                ClassHash([0x01; 32]),
                CompiledClass::Deprecated(Arc::new(contract_class)),
            );
            cache
        }),
    );

    let entry_point_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"a"));
    let entry_point = ExecutionEntryPoint::new(
        Address(1111.into()),
        vec![],
        entry_point_selector,
        Address(1111.into()),
        EntryPointType::External,
        CallType::Delegate.into(),
        Some(ClassHash([1; 32])),
        0,
    );

    let mut resources_manager = ExecutionResourcesManager::default();

    let call_info = entry_point
        .execute(
            &mut state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
            #[cfg(feature = "cairo-native")]
            None,
        )
        .expect("Could not execute contract");

    let call_info = call_info.call_info.unwrap();

    assert_eq!(call_info.internal_calls.len(), 1);
    assert_eq!(call_info.internal_calls[0].internal_calls.len(), 1);
    assert!(call_info.internal_calls[0].internal_calls[0]
        .internal_calls
        .is_empty());
}
