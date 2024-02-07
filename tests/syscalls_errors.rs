#![deny(warnings)]

use assert_matches::assert_matches;
use cairo_vm::Felt252;
use starknet_in_rust::transaction::ClassHash;
use starknet_in_rust::{
    core::errors::state_errors::StateError,
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
        state_api::State,
        ExecutionResourcesManager,
    },
    transaction::Address,
    utils::{calculate_sn_keccak, felt_to_hash},
    EntryPointType,
};
use std::{path::Path, sync::Arc};

#[allow(clippy::too_many_arguments)]
fn test_contract<'a>(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    class_hash: ClassHash,
    contract_address: Address,
    caller_address: Address,
    block_context: BlockContext,
    tx_execution_context_option: Option<TransactionExecutionContext>,
    extra_contracts: impl Iterator<
        Item = (
            ClassHash,
            &'a Path,
            Option<(Address, Vec<(&'a str, Felt252)>)>,
        ),
    >,
    arguments: impl Into<Vec<Felt252>>,
    error_msg: &str,
) {
    let contract_class =
        ContractClass::from_path(contract_path).expect("Could not load contract from JSON");

    let mut tx_execution_context = tx_execution_context_option.unwrap_or_else(|| {
        TransactionExecutionContext::create_for_testing(
            Address(0.into()),
            0.into(),
            block_context.invoke_tx_max_n_steps(),
            *TRANSACTION_VERSION,
        )
    });

    let nonce = *tx_execution_context.nonce();

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(contract_address.clone(), nonce);
    state_reader.class_hash_to_compiled_class_mut().insert(
        class_hash,
        CompiledClass::Deprecated(Arc::new(contract_class)),
    );

    let mut storage_entries = Vec::new();
    let contract_class_cache = {
        let contract_class_cache = PermanentContractClassCache::default();

        for (class_hash, contract_path, contract_address) in extra_contracts {
            let contract_class = ContractClass::from_path(contract_path)
                .expect("Could not load extra contract from JSON");

            contract_class_cache.set_contract_class(
                class_hash,
                CompiledClass::Deprecated(Arc::new(contract_class.clone())),
            );

            if let Some((contract_address, data)) = contract_address {
                storage_entries.extend(data.into_iter().map(|(name, value)| {
                    (
                        contract_address.clone(),
                        calculate_sn_keccak(name.as_bytes()),
                        value,
                    )
                }));

                state_reader
                    .address_to_class_hash_mut()
                    .insert(contract_address.clone(), class_hash);
                state_reader.class_hash_to_compiled_class_mut().insert(
                    class_hash,
                    CompiledClass::Deprecated(Arc::new(contract_class.clone())),
                );
            }
        }

        contract_class_cache
    };
    let mut state = CachedState::new(Arc::new(state_reader), Arc::new(contract_class_cache));
    storage_entries
        .into_iter()
        .for_each(|(a, b, c)| state.set_storage_at(&(a, b), c));

    let calldata = arguments.into();

    let entry_point_selector = Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));
    let entry_point = ExecutionEntryPoint::new(
        contract_address,
        calldata,
        entry_point_selector,
        caller_address,
        EntryPointType::External,
        CallType::Delegate.into(),
        Some(class_hash),
        0,
    );

    let mut resources_manager = ExecutionResourcesManager::default();

    let result = entry_point.execute(
        &mut state,
        &block_context,
        &mut resources_manager,
        &mut tx_execution_context,
        false,
        block_context.invoke_tx_max_n_steps(),
        #[cfg(feature = "cairo-native")]
        None,
    );

    assert_matches!(result, Err(e) if e.to_string().contains(error_msg));
}

#[test]
fn call_contract_with_extra_arguments() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_call_contract",
        ClassHash([1; 32]),
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [(
            ClassHash([2u8; 32]),
            Path::new("starknet_programs/syscalls-lib.json"),
            Some((Address(2222.into()), vec![("lib_state", 10.into())])),
        )]
        .into_iter(),
        [2222.into(), 2.into()],
        "An ASSERT_EQ instruction failed: 11:1 != 11:2",
    );
}

#[test]
fn call_contract_not_deployed() {
    let contract_address = Address(2222.into());
    let wrong_address = contract_address.0 - Felt252::from(2); // another address
    let error_msg = format!(
        "Contract address {:?} is not deployed",
        felt_to_hash(&wrong_address)
    );
    test_contract(
        "starknet_programs/syscalls.json",
        "test_call_contract",
        ClassHash([1; 32]),
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [(
            ClassHash([2u8; 32]),
            Path::new("starknet_programs/syscalls-lib.json"),
            Some((contract_address, vec![("lib_state", 10.into())])),
        )]
        .into_iter(),
        [wrong_address],
        &error_msg,
    );
}

#[test]
fn library_call_not_declared_contract() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_library_call",
        ClassHash([1; 32]),
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [].into_iter(),
        [],
        "Missing compiled class after fetching",
    );
}

#[test]
fn deploy_not_declared_class_hash() {
    let not_declared_class_hash = ClassHash([2u8; 32]);
    test_contract(
        "starknet_programs/syscalls.json",
        "test_deploy",
        ClassHash([1; 32]),
        Address(11111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [].into_iter(),
        [Felt252::from_bytes_be(&not_declared_class_hash.0), 0.into()],
        &StateError::NoneCompiledHash(not_declared_class_hash).to_string(),
    );
}
