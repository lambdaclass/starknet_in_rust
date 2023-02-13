use felt::Felt;
use num_traits::Num;
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

#[test]
fn get_block_number_syscall() -> Result<(), Box<dyn std::error::Error>> {
    let contract_path = Path::new("tests/syscalls.json");
    let contract_class = ContractClass::try_from(contract_path.to_path_buf())?;

    let class_hash = [1; 32];
    let contract_state = ContractState::new(class_hash, 3.into(), Default::default());
    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    state_reader
        .contract_states_mut()
        .insert(Address(1111.into()), contract_state);
    let state = CachedState::new(
        state_reader,
        Some([(class_hash, contract_class.clone())].into_iter().collect()),
    );

    let entry_point = ExecutionEntryPoint::new(
        Address(1111.into()),
        vec![],
        contract_class
            .entry_points_by_type()
            .get(&EntryPointType::External)
            .and_then(|x| x.first().map(|x| x.selector().clone()))
            .unwrap(),
        Address(0000.into()),
        EntryPointType::External,
        CallType::Delegate.into(),
        class_hash.into(),
    );

    let general_config = StarknetGeneralConfig::default();
    let tx_execution_context = TransactionExecutionContext::create_for_testing(
        Address(0.into()),
        10,
        0.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    assert_eq!(
        entry_point.execute(
            state,
            general_config,
            &mut resources_manager,
            tx_execution_context,
        )?,
        CallInfo {
            contract_address: Address(1111.into()),
            caller_address: Address(0.into()),
            entry_point_type: EntryPointType::External.into(),
            call_type: CallType::Delegate.into(),
            class_hash: class_hash.into(),
            entry_point_selector: contract_class
                .entry_points_by_type()
                .get(&EntryPointType::External)
                .and_then(|x| x.first().map(|x| x.selector().clone())),
            retdata: vec![
                Felt::from_str_radix("1", 10,).unwrap(),
                Felt::from_str_radix("0", 10,).unwrap(),
            ],
            ..Default::default()
        },
    );

    Ok(())
}
