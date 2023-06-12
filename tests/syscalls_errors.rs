#![deny(warnings)]

use cairo_vm::felt::Felt252;
use starknet_contract_class::EntryPointType;
use starknet_rs::{
    core::errors::state_errors::StateError,
    definitions::{constants::TRANSACTION_VERSION, general_config::TransactionContext},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::State,
    },
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{calculate_sn_keccak, Address, ClassHash},
};
use std::path::Path;

use assert_matches::assert_matches;

#[allow(clippy::too_many_arguments)]
fn test_contract<'a>(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    class_hash: ClassHash,
    contract_address: Address,
    caller_address: Address,
    general_config: TransactionContext,
    tx_context: Option<TransactionExecutionContext>,
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
    let contract_class = ContractClass::try_from(contract_path.as_ref().to_path_buf())
        .expect("Could not load contract from JSON");

    let tx_execution_context = tx_context.unwrap_or_else(|| {
        TransactionExecutionContext::create_for_testing(
            Address(0.into()),
            10,
            0.into(),
            general_config.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION,
        )
    });

    let nonce = tx_execution_context.nonce().clone();

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(contract_address.clone(), nonce);
    state_reader
        .class_hash_to_contract_class_mut()
        .insert(class_hash, contract_class);

    let mut storage_entries = Vec::new();
    let contract_class_cache = {
        let mut contract_class_cache = ContractClassCache::new();

        for (class_hash, contract_path, contract_address) in extra_contracts {
            let contract_class = ContractClass::try_from(contract_path.to_path_buf())
                .expect("Could not load extra contract from JSON");

            contract_class_cache.insert(class_hash, contract_class.clone());

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
                state_reader
                    .class_hash_to_contract_class_mut()
                    .insert(class_hash, contract_class.clone());
            }
        }

        Some(contract_class_cache)
    };
    let mut state = CachedState::new(state_reader, contract_class_cache, None);
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
        &general_config,
        &mut resources_manager,
        &tx_execution_context,
        false,
    );

    assert_matches!(result, Err(e) if e.to_string().contains(error_msg));
}

#[test]
fn call_contract_with_extra_arguments() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_call_contract",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        TransactionContext::default(),
        None,
        [(
            [2u8; 32],
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
    test_contract(
        "starknet_programs/syscalls.json",
        "test_call_contract",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        TransactionContext::default(),
        None,
        [(
            [2u8; 32],
            Path::new("starknet_programs/syscalls-lib.json"),
            Some((contract_address.clone(), vec![("lib_state", 10.into())])),
        )]
        .into_iter(),
        [contract_address.0 - Felt252::new(2)], // Wrong address
        "Contract address [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] is not deployed",
    );
}

#[test]
fn library_call_not_declared_contract() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_library_call",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        TransactionContext::default(),
        None,
        [].into_iter(),
        [],
        "Missing compiled class after fetching",
    );
}

#[test]
fn deploy_not_declared_class_hash() {
    let not_declared_class_hash = [2u8; 32];
    test_contract(
        "starknet_programs/syscalls.json",
        "test_deploy",
        [1; 32],
        Address(11111.into()),
        Address(0.into()),
        TransactionContext::default(),
        None,
        [].into_iter(),
        [
            Felt252::from_bytes_be(not_declared_class_hash.as_ref()),
            0.into(),
        ],
        &StateError::NoneCompiledHash(not_declared_class_hash).to_string(),
    );
}
