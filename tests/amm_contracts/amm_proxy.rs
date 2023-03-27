use crate::amm_contracts::utils::{execute_entry_point, get_accessed_keys, CallConfig};
use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt252;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{cached_state::CachedState, state_api::StateReader},
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, Address},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

#[test]
fn amm_proxy_init_pool_test() {
    let contract_address = Address(0.into());
    let contract_class_hash = [1; 32];
    let proxy_address = Address(1000000.into());
    let mut proxy_class_hash = [0; 32];
    proxy_class_hash[31] = 1;

    // Create program and entry point types for contract class
    let contract_path = PathBuf::from("starknet_programs/amm.json");
    let contract_class = ContractClass::try_from(contract_path).unwrap();

    let proxy_path = PathBuf::from("starknet_programs/amm_proxy.json");
    let proxy_class = ContractClass::try_from(proxy_path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), contract_class_hash);
    state_reader
        .address_to_class_hash_mut()
        .insert(proxy_address.clone(), proxy_class_hash);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [0.into(), 555.into(), 666.into()].to_vec();
    let caller_address = Address(1000000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
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
                ("pedersen".to_string(), 2),
                ("range_check".to_string(), 14),
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
    let contract_address = Address(0.into());
    let contract_class_hash = [1; 32];
    let proxy_address = Address(1000000.into());
    let mut proxy_class_hash = [0; 32];
    proxy_class_hash[31] = 1;

    // Create program and entry point types for contract class
    let contract_path = PathBuf::from("starknet_programs/amm.json");
    let contract_class = ContractClass::try_from(contract_path).unwrap();

    let proxy_path = PathBuf::from("starknet_programs/amm_proxy.json");
    let proxy_class = ContractClass::try_from(proxy_path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), contract_class_hash);
    state_reader
        .address_to_class_hash_mut()
        .insert(proxy_address.clone(), proxy_class_hash);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [0.into(), 555.into(), 666.into()].to_vec();
    let caller_address = Address(1000000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add pool balance
    execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();

    let calldata = [0.into(), 1.into()].to_vec();
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
                ("pedersen".to_string(), 1),
                ("range_check".to_string(), 3),
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
    let contract_address = Address(0.into());
    let contract_class_hash = [1; 32];
    let proxy_address = Address(1000000.into());
    let mut proxy_class_hash = [0; 32];
    proxy_class_hash[31] = 1;

    // Create program and entry point types for contract class
    let contract_path = PathBuf::from("starknet_programs/amm.json");
    let contract_class = ContractClass::try_from(contract_path).unwrap();

    let proxy_path = PathBuf::from("starknet_programs/amm_proxy.json");
    let proxy_class = ContractClass::try_from(proxy_path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), contract_class_hash);
    state_reader
        .address_to_class_hash_mut()
        .insert(proxy_address.clone(), proxy_class_hash);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [0.into(), 555.into(), 666.into()].to_vec();
    let caller_address = Address(1000000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add pool balance
    execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();

    let calldata = [0.into(), 55.into(), 66.into()].to_vec();
    let amm_proxy_entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_add_demo_token"));
    let result = execute_entry_point("proxy_add_demo_token", &calldata, &mut call_config).unwrap();

    let amm_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"add_demo_token"));

    let accessed_storage_keys = get_accessed_keys(
        "account_balance",
        vec![
            vec![1000000_u32.into(), 1_u32.into()],
            vec![1000000_u32.into(), 2_u32.into()],
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
                ("pedersen".to_string(), 8),
                ("range_check".to_string(), 20),
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
    let contract_address = Address(0.into());
    let contract_class_hash = [1; 32];
    let proxy_address = Address(1000000.into());
    let mut proxy_class_hash = [0; 32];
    proxy_class_hash[31] = 1;

    // Create program and entry point types for contract class
    let contract_path = PathBuf::from("starknet_programs/amm.json");
    let contract_class = ContractClass::try_from(contract_path).unwrap();

    let proxy_path = PathBuf::from("starknet_programs/amm_proxy.json");
    let proxy_class = ContractClass::try_from(proxy_path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), contract_class_hash);
    state_reader
        .address_to_class_hash_mut()
        .insert(proxy_address.clone(), proxy_class_hash);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [0.into(), 100.into(), 200.into()].to_vec();
    let caller_address = Address(1000000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add account balance for the proxy contract in the amm contract
    execute_entry_point("proxy_add_demo_token", &calldata, &mut call_config).unwrap();

    //First argument is the amm contract address
    //Second argument is the account address, in this case the proxy address
    //Third argument is the token id
    let calldata = [0.into(), 1000000.into(), 2.into()].to_vec();
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

    let accessed_storage_keys = get_accessed_keys(
        "account_balance",
        vec![vec![1000000_u32.into(), 2_u8.into()]],
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
            n_memory_holes: 11,
            builtin_instance_counter: HashMap::from([
                ("pedersen".to_string(), 2),
                ("range_check".to_string(), 3),
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
fn amm_proxyswap() {
    let contract_address = Address(0.into());
    let contract_class_hash = [1; 32];
    let proxy_address = Address(1000000.into());
    let mut proxy_class_hash = [0; 32];
    proxy_class_hash[31] = 1;

    // Create program and entry point types for contract class
    let contract_path = PathBuf::from("starknet_programs/amm.json");
    let contract_class = ContractClass::try_from(contract_path).unwrap();

    let proxy_path = PathBuf::from("starknet_programs/amm_proxy.json");
    let proxy_class = ContractClass::try_from(proxy_path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), contract_class_hash);
    state_reader
        .address_to_class_hash_mut()
        .insert(proxy_address.clone(), proxy_class_hash);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [0.into(), 100.into(), 200.into()].to_vec();
    let caller_address = Address(1000000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &proxy_address,
        class_hash: &proxy_class_hash,
        entry_points_by_type: &proxy_entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    // Add account balance for the proxy contract in the amm contract
    execute_entry_point("proxy_add_demo_token", &calldata, &mut call_config).unwrap();

    //Init pool to have 1000 tokens of each type
    let calldata = [0.into(), 1000.into(), 1000.into()].to_vec();
    execute_entry_point("proxy_init_pool", &calldata, &mut call_config).unwrap();

    //Swap 100 tokens of type 1 for type 2
    //First argument is the amm contract address
    //Second argunet is the token to swap (type 1)
    //Third argument is the amount of tokens to swap (100)
    let calldata = [0.into(), 1.into(), 100.into()].to_vec();
    let expected_result = [90.into()].to_vec();
    let result = execute_entry_point("proxy_swap", &calldata, &mut call_config).unwrap();

    let amm_proxy_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"proxy_swap"));

    let amm_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"swap"));
    //checked for amm contract both tokens balances
    let accessed_storage_keys_pool_balance =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    //checked for proxy account both tokens balances
    let accessed_storage_keys_user_balance = get_accessed_keys(
        "account_balance",
        vec![
            vec![1000000_u32.into(), 1_u8.into()],
            vec![1000000_u32.into(), 2_u8.into()],
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
            n_memory_holes: 92,
            builtin_instance_counter: HashMap::from([
                ("pedersen".to_string(), 14),
                ("range_check".to_string(), 41),
            ]),
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}
