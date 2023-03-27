use std::collections::HashSet;

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
        transaction::error::TransactionError,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::EntryPointType,
    utils::{calculate_sn_keccak, Address},
};

use crate::amm_contracts::utils::*;

fn init_pool(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("init_pool", calldata, call_config)
}

fn add_demo_token(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("add_demo_token", calldata, call_config)
}

fn get_pool_token_balance(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point("get_pool_token_balance", calldata, call_config)
}

fn swap(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point("swap", calldata, call_config)
}

#[test]
fn amm_init_pool_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let amm_entrypoint_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"init_pool"));

    let accessed_storage_keys =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
        ..Default::default()
    };

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert_eq!(
        init_pool(&calldata, &mut call_config).unwrap(),
        expected_call_info
    );
}

#[test]
fn amm_add_demo_tokens_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&calldata, &mut call_config).unwrap();

    let calldata_add_demo_token = [100.into(), 100.into()].to_vec();

    let add_demo_token_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"add_demo_token"));

    let accessed_storage_keys_add_demo_token = get_accessed_keys(
        "account_balance",
        vec![
            vec![0_u8.into(), 1_u8.into()],
            vec![0_u8.into(), 2_u8.into()],
        ],
    );

    let expected_call_info_add_demo_token = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(add_demo_token_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata_add_demo_token.clone(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: accessed_storage_keys_add_demo_token,
        storage_read_values: vec![Felt::zero(), Felt::zero()],
        ..Default::default()
    };

    assert_eq!(
        add_demo_token(&calldata_add_demo_token, &mut call_config).unwrap(),
        expected_call_info_add_demo_token
    );
}

#[test]
fn amm_get_pool_token_balance() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&calldata, &mut call_config).unwrap();

    let calldata_get_pool_token_balance = [1.into()].to_vec();

    let get_pool_token_balance_selector =
        Felt::from_bytes_be(&calculate_sn_keccak(b"get_pool_token_balance"));

    let accessed_storage_keys_get_pool_token_balance =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()]]);

    let expected_call_info_get_pool_token_balance = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(get_pool_token_balance_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata_get_pool_token_balance.clone(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: accessed_storage_keys_get_pool_token_balance,
        storage_read_values: vec![10000.into()],
        retdata: [10000.into()].to_vec(),
        ..Default::default()
    };

    assert_eq!(
        get_pool_token_balance(&calldata_get_pool_token_balance, &mut call_config).unwrap(),
        expected_call_info_get_pool_token_balance
    );
}

#[test]
fn amm_swap_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&calldata, &mut call_config).unwrap();

    //add tokens to user
    let calldata_add_demo_token = [100.into(), 100.into()].to_vec();
    add_demo_token(&calldata_add_demo_token, &mut call_config).unwrap();

    let calldata_swap = [1.into(), 10.into()].to_vec();

    let expected_return = [9.into()].to_vec();

    let swap_selector = Felt::from_bytes_be(&calculate_sn_keccak(b"swap"));

    //access keys are all keys in pool balance and only this users balance but thats checked in account
    let accessed_storage_keys_pool_balance =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);
    //access keys balance of user. In account balance we ask for users address as key
    let accessed_storage_keys_user_balance = get_accessed_keys(
        "account_balance",
        vec![
            vec![0_u8.into(), 1_u8.into()],
            vec![0_u8.into(), 2_u8.into()],
        ],
    );

    //make the two hashsets as one
    let mut accessed_storage_keys = HashSet::new();
    accessed_storage_keys.extend(accessed_storage_keys_pool_balance);
    accessed_storage_keys.extend(accessed_storage_keys_user_balance);

    let expected_call_info_swap = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: contract_address.clone(),
        entry_point_selector: Some(swap_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata_swap.clone(),
        retdata: expected_return,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: accessed_storage_keys,
        storage_read_values: [
            100.into(),
            10000.into(),
            10000.into(),
            100.into(),
            100.into(),
        ]
        .to_vec(),
        ..Default::default()
    };

    assert_eq!(
        swap(&calldata_swap, &mut call_config).unwrap(),
        expected_call_info_swap
    );
}

#[test]
fn amm_init_pool_should_fail_with_amount_out_of_bounds() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [Felt::new(2_u32.pow(30)), Felt::new(2_u32.pow(30))].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert!(init_pool(&calldata, &mut call_config).is_err());
}

#[test]
fn amm_swap_should_fail_with_unexistent_token() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(InMemoryStateReader::default(), Some(Default::default()));
    // Deploy contract
    let (contract_address, class_hash) =
        deploy(&mut state, "starknet_programs/amm.json", &general_config);

    let calldata = [Felt::zero(), Felt::new(10)].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &contract_address,
        class_hash: &class_hash,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert!(swap(&calldata, &mut call_config).is_err());
}
