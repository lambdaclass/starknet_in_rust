use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use num_traits::Zero;
use starknet_crypto::FieldElement;
use starknet_rs::business_logic::state::cached_state::CachedState;
use starknet_rs::services::api::contract_class::ContractClass;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, OrderedEvent},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::state_api::StateReader,
        transaction::error::TransactionError,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::{calculate_sn_keccak, Address},
};

use crate::complex_contracts::utils::*;

fn contructor(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("constructor", calldata, call_config)
}

fn name(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point("name", calldata, call_config)
}

fn symbol(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point("symbol", calldata, call_config)
}

fn balance_of(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("balanceOf", calldata, call_config)
}

fn owner_of(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point("ownerOf", calldata, call_config)
}

fn get_approved(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("getApproved", calldata, call_config)
}

fn is_approved_for_all(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("isApprovedForAll", calldata, call_config)
}

fn approve(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point("approve", calldata, call_config)
}

fn set_approval_for_all(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("setApprovalForAll", calldata, call_config)
}

fn transfer_from(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("transferFrom", calldata, call_config)
}

fn safe_transfer_from(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("safeTransferFrom", calldata, call_config)
}

#[test]
fn erc721_constructor_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();
    let entry_point_type = EntryPointType::External;
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &Address(111.into()),
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    let result_get_name = name(&[], &mut call_config).unwrap();
    assert_eq!(result_get_name.retdata, vec![collection_name]);

    let result_get_symbol = symbol(&[], &mut call_config).unwrap();
    assert_eq!(result_get_symbol.retdata, vec![collection_symbol]);
}

#[test]
fn erc721_balance_of_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_point_type_constructor = EntryPointType::Constructor;
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type_constructor,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    //owner to check balance
    let calldata = [Felt::from(666)].to_vec();

    call_config.entry_point_type = &entry_point_type;

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"balanceOf"));

    //expected result should be 1,0 in uint256. So in Felt it should be [1,0]
    let expected_read_result = vec![Felt::from(1_u8), Felt::from(0_u8)];

    let mut accessed_storage_keys = HashSet::new();
    let mut balance = get_accessed_keys("ERC721_balances", vec![vec![666_u32.into()]])
        .drain()
        .collect::<Vec<[u8; 32]>>()[0];
    accessed_storage_keys.insert(balance);
    balance[31] += 1;
    accessed_storage_keys.insert(balance);

    let expected_call_info = CallInfo {
        caller_address: Address(666.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result.clone(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values: expected_read_result,
        ..Default::default()
    };

    assert_eq!(
        balance_of(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_test_owner_of() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    //tokenId to ask for owner
    let calldata = [Felt::from(1), Felt::from(0)].to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"ownerOf"));

    let expected_read_result = vec![Felt::from(666)];

    let accessed_storage_keys =
        get_accessed_keys("ERC721_owners", vec![vec![1_u32.into(), 0_u32.into()]]);

    let expected_call_info = CallInfo {
        caller_address: Address(666.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result.clone(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values: expected_read_result,
        ..Default::default()
    };

    assert_eq!(
        owner_of(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_test_get_approved() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // The address given approval to transfer the token
    let to = Felt::from(777);
    let calldata_approve = [to, Felt::from(1), Felt::from(0)].to_vec();
    call_config.entry_point_type = &entry_point_type;

    approve(&calldata_approve, &mut call_config).unwrap();

    // tokenId (uint256) to check if it is approved
    let calldata = [Felt::from(1), Felt::from(0)].to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"getApproved"));

    // expected result is 0 because it is not approved
    let expected_read_result = vec![Felt::from(777)];

    // First checks if the token is owned by anyone and then checks if it is approved
    let storage_read_values = vec![Felt::from(666), Felt::from(777)];

    let mut accessed_storage_keys = get_accessed_keys(
        "ERC721_token_approvals",
        vec![vec![1_u32.into(), 0_u32.into()]],
    );
    accessed_storage_keys.extend(get_accessed_keys(
        "ERC721_owners",
        vec![vec![1_u8.into(), 0_u8.into()]],
    ));

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values,
        ..Default::default()
    };

    assert_eq!(
        get_approved(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_test_is_approved_for_all() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // The address given approval to transfer the token
    let to = Felt::from(777);
    let calldata_set_approve_all = [to, Felt::from(1)].to_vec();

    set_approval_for_all(&calldata_set_approve_all, &mut call_config).unwrap();

    // Owner of tokens who is approving the operator to have control of all his tokens
    let owner = Felt::from(666);
    // The address in control for the approvals
    let operator = Felt::from(777);
    let calldata = [owner, operator].to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"isApprovedForAll"));

    // expected result is 0 because it is not approved
    let expected_read_result = vec![Felt::from(1)];

    // Checks only the storage variable ERC721_operator_approvals
    let storage_read_values = vec![Felt::from(1)];

    let accessed_storage_keys = get_accessed_keys(
        "ERC721_operator_approvals",
        vec![vec![666_u32.into(), 777_u32.into()]],
    );

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values,
        ..Default::default()
    };

    assert_eq!(
        is_approved_for_all(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_test_approve() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };
    // The address given approval to transfer the token
    let to = Felt::from(777);
    let calldata = [to, Felt::from(1), Felt::from(0)].to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"approve"));

    let expected_read_result = vec![];

    // Checks only the storage variable ERC721_operator_approvals
    let storage_read_values = vec![Felt::from(666), Felt::from(666)];

    // Ask for the owner of the token
    let mut accessed_storage_keys =
        get_accessed_keys("ERC721_owners", vec![vec![1_u32.into(), 0_u32.into()]]);
    // Writes the new approval
    accessed_storage_keys.extend(get_accessed_keys(
        "ERC721_token_approvals",
        vec![vec![1_u32.into(), 0_u32.into()]],
    ));

    let event_hash = Felt::from_bytes_be(&calculate_sn_keccak("Approval".as_bytes()));
    let expected_events = vec![OrderedEvent::new(
        0,
        vec![event_hash],
        vec![
            Felt::from(666),
            Felt::from(777),
            Felt::from(1),
            Felt::zero(),
        ],
    )];

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values,
        events: expected_events,
        ..Default::default()
    };

    assert_eq!(
        approve(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_set_approval_for_all() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // The address given approval to transfer the token
    let to = Felt::from(777);
    let calldata = [to, Felt::from(1)].to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"setApprovalForAll"));

    // set only no return value
    let expected_read_result = vec![];

    // Only writes in operator_approvals
    let storage_read_values = vec![];

    // Writes to the operator the new set value
    let accessed_storage_keys = get_accessed_keys(
        "ERC721_operator_approvals",
        vec![vec![666_u32.into(), 777_u32.into()]],
    );

    let event_hash = Felt::from_bytes_be(&calculate_sn_keccak("ApprovalForAll".as_bytes()));
    let expected_events = vec![OrderedEvent::new(
        0,
        vec![event_hash],
        vec![Felt::from(666), Felt::from(777), Felt::from(1)],
    )];

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values,
        events: expected_events,
        ..Default::default()
    };

    assert_eq!(
        set_approval_for_all(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_transfer_from_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    let calldata = [
        Felt::from(666),
        Felt::from(777),
        Felt::from(1),
        Felt::zero(),
    ]
    .to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"transferFrom"));

    let mut accessed_storage_keys = get_accessed_keys(
        "ERC721_owners",
        vec![vec![FieldElement::from(1_u8), FieldElement::from(0_u8)]],
    );
    accessed_storage_keys.extend(get_accessed_keys(
        "ERC721_token_approvals",
        vec![vec![FieldElement::from(1_u8), FieldElement::from(0_u8)]],
    ));

    let mut balance_from = get_accessed_keys("ERC721_balances", vec![vec![666_u32.into()]])
        .drain()
        .collect::<Vec<[u8; 32]>>()[0];
    accessed_storage_keys.insert(balance_from);
    balance_from[31] += 1;
    accessed_storage_keys.insert(balance_from);

    let mut balance_to = get_accessed_keys("ERC721_balances", vec![vec![777_u32.into()]])
        .drain()
        .collect::<Vec<[u8; 32]>>()[0];
    accessed_storage_keys.insert(balance_to);
    balance_to[31] += 1;
    accessed_storage_keys.insert(balance_to);

    let expected_read_values = vec![
        Felt::from(666),
        Felt::from(666),
        Felt::from(666),
        Felt::from(666),
        Felt::from(1),
        Felt::zero(),
        Felt::zero(),
        Felt::zero(),
    ];

    let approval_event_hash = Felt::from_bytes_be(&calculate_sn_keccak("Approval".as_bytes()));
    let approval_event = OrderedEvent::new(
        0,
        vec![approval_event_hash],
        vec![Felt::from(666), Felt::zero(), Felt::from(1), Felt::zero()],
    );
    let transfer_event_hash = Felt::from_bytes_be(&calculate_sn_keccak("Transfer".as_bytes()));
    let transfer_event = OrderedEvent::new(
        1,
        vec![transfer_event_hash],
        vec![
            Felt::from(666),
            Felt::from(777),
            Felt::from(1),
            Felt::zero(),
        ],
    );
    let expected_events = vec![approval_event, transfer_event];

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values: expected_read_values,
        events: expected_events,
        ..Default::default()
    };

    assert_eq!(
        transfer_from(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_transfer_from_and_get_owner_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    let calldata = [
        Felt::from(666),
        Felt::from(777),
        Felt::from(1),
        Felt::zero(),
    ]
    .to_vec();
    transfer_from(&calldata, &mut call_config).unwrap();

    // Now we call ownerOf
    let calldata = [Felt::from(1), Felt::from(0)].to_vec();

    let entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"ownerOf"));

    let expected_read_result = vec![Felt::from(777)];

    let accessed_storage_keys =
        get_accessed_keys("ERC721_owners", vec![vec![1_u32.into(), 0_u32.into()]]);

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_read_result.clone(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        storage_read_values: expected_read_result,
        ..Default::default()
    };

    assert_eq!(
        owner_of(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn erc721_safe_transfer_from_should_fail_test() {
    let contract_address = Address(0.into());
    let contract_class_hash = [1; 32];
    let erc165_address = Address(1000000.into());
    let mut erc165_class_hash = [0; 32];
    erc165_class_hash[31] = 1;

    // Create program and entry point types for contract class
    let contract_path = PathBuf::from("starknet_programs/ERC721.json");
    let contract_class = ContractClass::try_from(contract_path).unwrap();

    let erc165_path = PathBuf::from("starknet_programs/ERC165.json");
    let erc165_class = ContractClass::try_from(erc165_path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(erc165_class_hash, erc165_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), contract_class_hash);
    state_reader
        .address_to_class_hash_mut()
        .insert(erc165_address, erc165_class_hash);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let entry_points_by_type = state
        .get_contract_class(&contract_class_hash)
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
    let constructor_calldata = [collection_name, symbol, to].to_vec();

    let entry_point_type_constructor = EntryPointType::Constructor;
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &contract_class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type_constructor,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    contructor(&constructor_calldata, &mut call_config).unwrap();

    call_config.entry_point_type = &entry_point_type;

    // data_len = 0 then there is no need to sent *felt for data
    let calldata = [
        Felt::from(666),
        Felt::from(1000000),
        Felt::from(1),
        Felt::zero(),
        Felt::zero(),
    ]
    .to_vec();

    // The contract will fail because the receiver address is not a IERC721Receiver contract.
    assert!(safe_transfer_from(&calldata, &mut call_config).is_err());
}

#[test]
fn erc721_calling_constructor_twice_should_fail_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::Constructor;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert!(contructor(&calldata, &mut call_config).is_err());
}

#[test]
#[should_panic]
fn erc721_constructor_should_fail_with_to_equal_zero() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(0);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );
}

#[test]
fn erc721_transfer_fail_to_zero_address() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    let calldata = [Felt::from(666), Felt::zero(), Felt::from(1), Felt::zero()].to_vec();
    assert!(transfer_from(&calldata, &mut call_config).is_err());
}

#[test]
fn erc721_transfer_fail_not_owner() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));

    let collection_name = Felt::from_bytes_be("some-nft".as_bytes());
    let collection_symbol = Felt::from(555);
    let to = Felt::from(666);
    let calldata = [collection_name.clone(), collection_symbol.clone(), to].to_vec();

    let (contract_address, class_hash) = deploy(
        &mut state,
        "starknet_programs/ERC721.json",
        &calldata,
        &general_config,
    );

    let caller_address = Address(666.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let entry_point_type = EntryPointType::External;

    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        entry_point_type: &entry_point_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    let calldata = [
        Felt::from(777),
        Felt::from(777),
        Felt::from(1),
        Felt::zero(),
    ]
    .to_vec();

    assert!(transfer_from(&calldata, &mut call_config).is_err());
}
