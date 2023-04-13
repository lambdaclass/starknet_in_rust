use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt252;
use num_bigint::BigUint;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{cached_state::CachedState, state_api::StateReader},
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::{calculate_sn_keccak, Address},
};

use crate::complex_contracts::utils::*;

#[test]
fn normalize_big_address_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/starknet_libs_storage.json",
        &[],
        &general_config,
    )
    .unwrap();
    let address = BigUint::pow(&BigUint::from(2_u8), 251);
    let calldata = [address.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let entry_point_selector = Some(Felt252::from_bytes_be(&calculate_sn_keccak(b"normalize")));
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector,
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [256.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        ..Default::default()
    };

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert_eq!(
        execute_entry_point("normalize", &calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn normalize_small_address_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/starknet_libs_storage.json",
        &[],
        &general_config,
    )
    .unwrap();
    let address = 128;
    let calldata = [address.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let entry_point_selector = Some(Felt252::from_bytes_be(&calculate_sn_keccak(b"normalize")));
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector,
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [address.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        ..Default::default()
    };

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert_eq!(
        execute_entry_point("normalize", &calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}
