#![deny(warnings)]

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use num_traits::Zero;
use starknet_crypto::FieldElement;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::state::ExecutionResourcesManager,
        state::state_api::StateReader,
        transaction::error::TransactionError,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::Address,
};

use crate::erc721::utils::*;

pub enum ERC721EntryPoints {
    Constructor,
}

impl From<ERC721EntryPoints> for usize {
    fn from(val: ERC721EntryPoints) -> Self {
        match val {
            ERC721EntryPoints::Constructor => 0,
        }
    }
}

fn contructor(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point(ERC721EntryPoints::Constructor.into(), calldata, call_config)
}

fn name(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point(9, calldata, call_config)
}

fn symbol(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point(4, calldata, call_config)
}

#[test]
fn erc721_constructor_test() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/ERC721.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let name = Felt::from_bytes_be("some-nft".as_bytes());
    let symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [name, symbol, to].to_vec();
    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::Constructor;

    let entrypoint_selector = entry_points_by_type
        .get(&entry_point_type)
        .unwrap()
        .get(ERC721EntryPoints::Constructor as usize)
        .unwrap()
        .selector()
        .clone();

    let interfaces = vec![
        vec![FieldElement::from_hex_be("80ac58cd").unwrap()],
        vec![FieldElement::from_hex_be("5b5e139f").unwrap()],
    ];

    let mut accessed_storage_keys = get_accessed_keys("ERC721_name", vec![]);
    accessed_storage_keys.extend(&get_accessed_keys("ERC721_symbol", vec![]));
    accessed_storage_keys.extend(&get_accessed_keys(
        "ERC165_supported_interfaces",
        interfaces,
    ));
    accessed_storage_keys.extend(&get_accessed_keys(
        "ERC721_balances",
        vec![vec![666_u32.into()]],
    ));
    accessed_storage_keys.extend(&get_accessed_keys(
        "ERC721_owners",
        vec![vec![FieldElement::from(1_u8)]],
    ));

    let _expected_call_info = CallInfo {
        caller_address: Address(666.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::Constructor),
        calldata: calldata.clone(),
        retdata: [].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: accessed_storage_keys.clone(),
        storage_read_values: vec![Felt::zero(), Felt::zero(), Felt::zero()],
        ..Default::default()
    };

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    dbg!();

    assert_eq!(
        contructor(&calldata, &mut call_config)
            .unwrap()
            .accessed_storage_keys,
        accessed_storage_keys
    );
}

#[test]
fn erc721_name_test() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/ERC721.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    // First we initialize the contract
    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name, symbol, to].to_vec();

    let entry_point_type_constructor = EntryPointType::Constructor;
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type_constructor,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    contructor(&calldata, &mut call_config).unwrap();

    call_config.entry_point_type = &entry_point_type;

    let entrypoint_selector = entry_points_by_type
        .get(&entry_point_type)
        .unwrap()
        .get(9)
        .unwrap()
        .selector()
        .clone();

    let expected_read_result = Felt::from_bytes_be("some-nft".as_bytes());

    let expected_call_info = CallInfo {
        caller_address: Address(666.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: [].to_vec(),
        retdata: vec![expected_read_result.clone()],
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: get_accessed_keys("ERC721_name", vec![]),
        storage_read_values: vec![expected_read_result],
        ..Default::default()
    };

    assert_eq!(name(&[], &mut call_config).unwrap(), expected_call_info);
}

#[test]
fn erc721_symbol_test() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/ERC721.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name, collection_symbol, to].to_vec();

    let entry_point_type_constructor = EntryPointType::Constructor;
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type_constructor,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    contructor(&calldata, &mut call_config).unwrap();

    call_config.entry_point_type = &entry_point_type;

    let entrypoint_selector = entry_points_by_type
        .get(&entry_point_type)
        .unwrap()
        .get(4)
        .unwrap()
        .selector()
        .clone();

    let expected_read_result = Felt::from(555);

    let expected_call_info = CallInfo {
        caller_address: Address(666.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: [].to_vec(),
        retdata: vec![expected_read_result.clone()],
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: get_accessed_keys("ERC721_symbol", vec![]),
        storage_read_values: vec![expected_read_result],
        ..Default::default()
    };

    assert_eq!(symbol(&[], &mut call_config).unwrap(), expected_call_info);
}
