use crate::complex_contracts::utils::*;
use cairo_vm::felt::Felt252;
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use starknet_crypto::FieldElement;
use starknet_rs::services::api::contract_classes::deprecated_contract_class::ContractClass;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{cached_state::CachedState, state_api::StateReader},
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_classes::deprecated_contract_class::EntryPointType,
    utils::{calculate_sn_keccak, Address},
};
use std::collections::{HashMap, HashSet};

#[test]
fn amm_proxy_init_pool_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(
        InMemoryStateReader::default(),
        Some(Default::default()),
        None,
    );
    // Deploy contract
    let (contract_address, contract_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();
    // Deploy proxy
    let (proxy_address, proxy_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm_proxy.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();

    let proxy_entry_points_by_type =
        TryInto::<ContractClass>::try_into(state.get_contract_class(&proxy_class_hash).unwrap())
            .unwrap()
            .entry_points_by_type()
            .clone();

    let calldata = [contract_address.0.clone(), 555.into(), 666.into()].to_vec();
    let caller_address = Address(1000000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    let result = execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();
    let amm_proxy_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_init_pool"));
    let amm_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"init_pool"));

    let accessed_storage_keys =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    let internal_calls = vec![CallInfo {
        caller_address: proxy_address.clone(),
        call_type: Some(CallType::Call),
        contract_address,
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone()[1..].to_vec(),
        retdata: [].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(contract_class_hash),
        accessed_storage_keys,
        ..Default::default()
    }];

    let expected_call_info = CallInfo {
        caller_address,
        call_type: Some(CallType::Delegate),
        contract_address: proxy_address,
        entry_point_selector: Some(amm_proxy_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [].to_vec(),
        execution_resources: ExecutionResources {
            n_memory_holes: 20,
            builtin_instance_counter: HashMap::from([
                ("pedersen_builtin".to_string(), 2),
                ("range_check_builtin".to_string(), 14),
            ]),
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}

#[test]
fn amm_proxy_get_pool_token_balance_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(
        InMemoryStateReader::default(),
        Some(Default::default()),
        None,
    );
    // Deploy contract
    let (contract_address, contract_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();
    // Deploy proxy
    let (proxy_address, proxy_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm_proxy.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();

    let proxy_entry_points_by_type =
        TryInto::<ContractClass>::try_into(state.get_contract_class(&proxy_class_hash).unwrap())
            .unwrap()
            .entry_points_by_type()
            .clone();

    let calldata = [contract_address.0.clone(), 555.into(), 666.into()].to_vec();
    let caller_address = Address(1000000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add pool balance
    execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();

    let calldata = [contract_address.0.clone(), 1.into()].to_vec();
    let result =
        execute_entry_point("proxy_get_pool_token_balance", &calldata, &mut call_config).unwrap();

    let amm_proxy_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_get_pool_token_balance"));
    let amm_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"get_pool_token_balance"));

    let accessed_storage_keys = get_accessed_keys("pool_balance", vec![vec![1_u8.into()]]);

    let internal_calls = vec![CallInfo {
        caller_address: proxy_address.clone(),
        call_type: Some(CallType::Call),
        contract_address,
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone()[1..].to_vec(),
        retdata: [555.into()].to_vec(),
        storage_read_values: [555.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(contract_class_hash),
        accessed_storage_keys,
        ..Default::default()
    }];

    let expected_call_info = CallInfo {
        caller_address,
        call_type: Some(CallType::Delegate),
        contract_address: proxy_address,
        entry_point_selector: Some(amm_proxy_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [555.into()].to_vec(),
        execution_resources: ExecutionResources {
            n_memory_holes: 10,
            builtin_instance_counter: HashMap::from([
                ("pedersen_builtin".to_string(), 1),
                ("range_check_builtin".to_string(), 3),
            ]),
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}

#[test]
fn amm_proxy_add_demo_token_test() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(
        InMemoryStateReader::default(),
        Some(Default::default()),
        None,
    );
    // Deploy contract
    let (contract_address, contract_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();
    // Deploy proxy
    let (proxy_address, proxy_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm_proxy.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();

    let proxy_entry_points_by_type =
        TryInto::<ContractClass>::try_into(state.get_contract_class(&proxy_class_hash).unwrap())
            .unwrap()
            .entry_points_by_type()
            .clone();

    let calldata = [contract_address.0.clone(), 555.into(), 666.into()].to_vec();
    let caller_address = Address(1000000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add pool balance
    execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();

    let calldata = [contract_address.0.clone(), 55.into(), 66.into()].to_vec();
    let amm_proxy_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_add_demo_token"));
    let result = execute_entry_point("proxy_add_demo_token", &calldata, &mut call_config).unwrap();

    let amm_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"add_demo_token"));

    let mut felt_slice: [u8; 32] = [0; 32];
    felt_slice[0..32].copy_from_slice(proxy_address.0.clone().to_bytes_be().get(0..32).unwrap());
    let proxy_addres_felt = FieldElement::from_bytes_be(&felt_slice).unwrap();

    let accessed_storage_keys = get_accessed_keys(
        "account_balance",
        vec![
            vec![proxy_addres_felt, 1_u32.into()],
            vec![proxy_addres_felt, 2_u32.into()],
        ],
    );

    let internal_calls = vec![CallInfo {
        caller_address: proxy_address.clone(),
        call_type: Some(CallType::Call),
        contract_address,
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone()[1..].to_vec(),
        storage_read_values: vec![0.into(), 0.into()],
        execution_resources: ExecutionResources::default(),
        class_hash: Some(contract_class_hash),
        accessed_storage_keys,
        ..Default::default()
    }];

    let expected_call_info = CallInfo {
        caller_address,
        call_type: Some(CallType::Delegate),
        contract_address: proxy_address,
        entry_point_selector: Some(amm_proxy_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        execution_resources: ExecutionResources {
            n_memory_holes: 42,
            builtin_instance_counter: HashMap::from([
                ("pedersen_builtin".to_string(), 8),
                ("range_check_builtin".to_string(), 20),
            ]),
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}

#[test]
fn amm_proxy_get_account_token_balance() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(
        InMemoryStateReader::default(),
        Some(Default::default()),
        None,
    );
    // Deploy contract
    let (contract_address, contract_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();
    // Deploy proxy
    let (proxy_address, proxy_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm_proxy.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();

    let proxy_entry_points_by_type =
        TryInto::<ContractClass>::try_into(state.get_contract_class(&proxy_class_hash).unwrap())
            .unwrap()
            .entry_points_by_type()
            .clone();

    let calldata = [contract_address.0.clone(), 100.into(), 200.into()].to_vec();
    let caller_address = Address(1000000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add account balance for the proxy contract in the amm contract
    execute_entry_point("proxy_add_demo_token", &calldata, &mut call_config).unwrap();

    //First argument is the amm contract address
    //Second argument is the account address, in this case the proxy address
    //Third argument is the token id
    let calldata = [
        contract_address.0.clone(),
        proxy_address.0.clone(),
        2.into(),
    ]
    .to_vec();
    let amm_proxy_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_get_account_token_balance"));
    let result = execute_entry_point(
        "proxy_get_account_token_balance",
        &calldata,
        &mut call_config,
    )
    .unwrap();

    let amm_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"get_account_token_balance"));

    let mut felt_slice: [u8; 32] = [0; 32];
    felt_slice[0..32].copy_from_slice(proxy_address.0.clone().to_bytes_be().get(0..32).unwrap());
    let proxy_addres_felt = FieldElement::from_bytes_be(&felt_slice).unwrap();

    let accessed_storage_keys = get_accessed_keys(
        "account_balance",
        vec![vec![proxy_addres_felt, 2_u8.into()]],
    );

    let internal_calls = vec![CallInfo {
        caller_address: proxy_address.clone(),
        call_type: Some(CallType::Call),
        contract_address,
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone()[1..].to_vec(),
        retdata: [200.into()].to_vec(),
        storage_read_values: [200.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(contract_class_hash),
        accessed_storage_keys,
        ..Default::default()
    }];

    let expected_call_info = CallInfo {
        caller_address,
        call_type: Some(CallType::Delegate),
        contract_address: proxy_address,
        entry_point_selector: Some(amm_proxy_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: [200.into()].to_vec(),
        execution_resources: ExecutionResources {
            n_memory_holes: 10,
            builtin_instance_counter: HashMap::from([
                ("pedersen_builtin".to_string(), 2),
                ("range_check_builtin".to_string(), 3),
            ]),
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}

#[test]
fn amm_proxy_swap() {
    let general_config = StarknetGeneralConfig::default();
    let mut state = CachedState::new(
        InMemoryStateReader::default(),
        Some(Default::default()),
        None,
    );
    // Deploy contract
    let (contract_address, contract_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();
    // Deploy proxy
    let (proxy_address, proxy_class_hash) = deploy(
        &mut state,
        "starknet_programs/amm_proxy.json",
        &[],
        &general_config,
        None,
    )
    .unwrap();

    let proxy_entry_points_by_type =
        TryInto::<ContractClass>::try_into(state.get_contract_class(&proxy_class_hash).unwrap())
            .unwrap()
            .entry_points_by_type()
            .clone();

    let calldata = [contract_address.0.clone(), 100.into(), 200.into()].to_vec();
    let caller_address = Address(1000000.into());
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        entry_point_type: &EntryPointType::External,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add account balance for the proxy contract in the amm contract
    execute_entry_point("proxy_add_demo_token", &calldata, &mut call_config).unwrap();

    //Init pool to have 1000 tokens of each type
    let calldata = [contract_address.0.clone(), 1000.into(), 1000.into()].to_vec();
    execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();

    //Swap 100 tokens of type 1 for type 2
    //First argument is the amm contract address
    //Second argunet is the token to swap (type 1)
    //Third argument is the amount of tokens to swap (100)
    let calldata = [contract_address.0.clone(), 1.into(), 100.into()].to_vec();
    let expected_result = [90.into()].to_vec();
    let result = execute_entry_point("proxy_swap", &calldata, &mut call_config).unwrap();

    let amm_proxy_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_swap"));

    let amm_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"swap"));
    //checked for amm contract both tokens balances
    let accessed_storage_keys_pool_balance =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    let mut felt_slice: [u8; 32] = [0; 32];
    felt_slice[0..32].copy_from_slice(proxy_address.0.clone().to_bytes_be().get(0..32).unwrap());
    let proxy_addres_felt = FieldElement::from_bytes_be(&felt_slice).unwrap();

    //checked for proxy account both tokens balances
    let accessed_storage_keys_user_balance = get_accessed_keys(
        "account_balance",
        vec![
            vec![proxy_addres_felt, 1_u8.into()],
            vec![proxy_addres_felt, 2_u8.into()],
        ],
    );

    let mut accessed_storage_keys = HashSet::new();
    accessed_storage_keys.extend(accessed_storage_keys_pool_balance);
    accessed_storage_keys.extend(accessed_storage_keys_user_balance);

    let internal_calls = vec![CallInfo {
        caller_address: proxy_address.clone(),
        call_type: Some(CallType::Call),
        contract_address,
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone()[1..].to_vec(),
        retdata: [90.into()].to_vec(),
        storage_read_values: [100.into(), 1000.into(), 1000.into(), 100.into(), 200.into()]
            .to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(contract_class_hash),
        accessed_storage_keys,
        ..Default::default()
    }];

    let expected_call_info = CallInfo {
        caller_address: caller_address.clone(),
        call_type: Some(CallType::Delegate),
        contract_address: proxy_address.clone(),
        entry_point_selector: Some(amm_proxy_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata.clone(),
        retdata: expected_result,
        execution_resources: ExecutionResources {
            n_memory_holes: 93,
            builtin_instance_counter: HashMap::from([
                ("pedersen_builtin".to_string(), 14),
                ("range_check_builtin".to_string(), 41),
            ]),
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}
