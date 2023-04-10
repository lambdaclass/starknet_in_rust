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
    utils::{calculate_sn_keccak, Address},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

#[test]
fn integration_storage_test() {
    // ---------------------------------------------------------
    //  Create program and entry point types for contract class
    // ---------------------------------------------------------

    let path = PathBuf::from("starknet_programs/storage.json");
    let contract_class = ContractClass::try_from(path).unwrap();
    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    let storage_entrypoint_selector = entry_points_by_type
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
    let class_hash = [1; 32];
    let nonce = Felt252::new(88);
    let storage_entry = (address.clone(), [90; 32]);
    let storage_value = Felt252::new(10902);

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);
    state_reader
        .address_to_storage_mut()
        .insert(storage_entry, storage_value);

    //* ---------------------------------------
    //*    Create state with previous data
    //* ---------------------------------------

    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let calldata = [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address.clone(),
        calldata.clone(),
        storage_entrypoint_selector.clone(),
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

    let expected_key = calculate_sn_keccak("_counter".as_bytes());

    let mut expected_accessed_storage_keys = HashSet::new();
    expected_accessed_storage_keys.insert(expected_key);

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(storage_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata,
        retdata: [42.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        storage_read_values: vec![42.into()],
        accessed_storage_keys: expected_accessed_storage_keys,
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

    assert!(!state.cache().storage_writes().is_empty());
    assert_eq!(
        state
            .cache()
            .storage_writes()
            .get(&(address, expected_key))
            .cloned(),
        Some(Felt252::new(42))
    );
}
