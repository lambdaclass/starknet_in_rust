#![deny(warnings)]

use felt::{felt_str, Felt};
use sha3::{Digest, Keccak256};
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
use std::path::Path;

fn find_entry_point_selector(entry_point: &str) -> Felt {
    let mut selector: [u8; 32] = Keccak256::new()
        .chain_update(entry_point.as_bytes())
        .finalize()
        .into();
    selector[0] &= 3;

    Felt::from_bytes_be(&selector)
}

#[allow(clippy::too_many_arguments)]
fn test_contract(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    class_hash: [u8; 32],
    nonce: usize,
    contract_address: Address,
    caller_address: Address,
    general_config: StarknetGeneralConfig,
    return_data: impl Into<Vec<Felt>>,
) {
    let contract_class = ContractClass::try_from(contract_path.as_ref().to_path_buf())
        .expect("Could not load contract from JSON");

    let contract_state = ContractState::new(class_hash, nonce.into(), Default::default());
    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    let mut state = CachedState::new(
        state_reader,
        Some([(class_hash, contract_class)].into_iter().collect()),
    );

    let entry_point_selector = find_entry_point_selector(entry_point);
    let entry_point = ExecutionEntryPoint::new(
        Address(1111.into()),
        vec![],
        entry_point_selector.clone(),
        caller_address.clone(),
        EntryPointType::External,
        CallType::Delegate.into(),
        class_hash.into(),
    );

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
    let run = |block_number| {
        let mut general_config = StarknetGeneralConfig::default();
        general_config.block_info_mut().block_number = block_number;

        test_contract(
            "tests/syscalls.json",
            "test_get_block_number",
            [1; 32],
            3,
            Address(1111.into()),
            Address(0.into()),
            general_config,
            [felt_str!("1"), block_number.into()],
        );
    };

    run(0);
    run(5);
    run(1000);
}
