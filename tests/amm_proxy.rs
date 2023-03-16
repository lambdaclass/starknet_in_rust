#![deny(warnings)]

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType},
        fact_state::{
            contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            state::ExecutionResourcesManager,
        },
        state::{cached_state::CachedState, state_api::StateReader},
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::Address,
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

mod utils;
use crate::utils::{execute_entry_point, get_accessed_keys, CallConfig};

mod amm;
use crate::amm::AmmEntryPoints;

enum ProxyAmmEntryPoints {
    AddDemoToken,
    InitPool,
    Swap,
    GetPoolTokenBalance,
    GetAccountTokenBalance,
}

impl Into<usize> for ProxyAmmEntryPoints {
    fn into(self) -> usize {
        match self {
            ProxyAmmEntryPoints::AddDemoToken => 0,
            ProxyAmmEntryPoints::InitPool => 1,
            ProxyAmmEntryPoints::Swap => 2,
            ProxyAmmEntryPoints::GetPoolTokenBalance => 3,
            ProxyAmmEntryPoints::GetAccountTokenBalance => 4,
        }
    }
}

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
    let contract_state = ContractState::new(contract_class_hash, 0.into(), HashMap::new());
    let proxy_state = ContractState::new(proxy_class_hash, 0.into(), HashMap::new());
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    state_reader
        .contract_states_mut()
        .insert(proxy_address.clone(), proxy_state);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let contract_entry_points_by_type = state
        .get_contract_class(&contract_class_hash)
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

    let result = execute_entry_point(
        ProxyAmmEntryPoints::InitPool.into(),
        &calldata,
        &mut call_config,
    )
    .unwrap();
    let index_entry_point_proxy_init_pool: usize = ProxyAmmEntryPoints::InitPool.into();
    let amm_proxy_entrypoint_selector = proxy_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_proxy_init_pool)
        .unwrap()
        .selector()
        .clone();

    let index_entry_point_init_pool: usize = AmmEntryPoints::InitPool.into();

    let amm_entrypoint_selector = contract_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_init_pool)
        .unwrap()
        .selector()
        .clone();

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
    let contract_state = ContractState::new(contract_class_hash, 0.into(), HashMap::new());
    let proxy_state = ContractState::new(proxy_class_hash, 0.into(), HashMap::new());
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    state_reader
        .contract_states_mut()
        .insert(proxy_address.clone(), proxy_state);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let contract_entry_points_by_type = state
        .get_contract_class(&contract_class_hash)
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
    execute_entry_point(
        ProxyAmmEntryPoints::InitPool.into(),
        &calldata,
        &mut call_config,
    )
    .unwrap();

    let calldata = [0.into(), 1.into()].to_vec();
    let index_entry_point_proxy_get_pool_token_balance: usize =
        ProxyAmmEntryPoints::GetPoolTokenBalance.into();
    let result = execute_entry_point(
        index_entry_point_proxy_get_pool_token_balance,
        &calldata,
        &mut call_config,
    )
    .unwrap();

    let amm_proxy_entrypoint_selector = proxy_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_proxy_get_pool_token_balance)
        .unwrap()
        .selector()
        .clone();

    let index_entry_point_get_pool_token_balance: usize =
        AmmEntryPoints::GetPoolTokenBalance.into();
    let amm_entrypoint_selector = contract_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_get_pool_token_balance)
        .unwrap()
        .selector()
        .clone();

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
    let contract_state = ContractState::new(contract_class_hash, 0.into(), HashMap::new());
    let proxy_state = ContractState::new(proxy_class_hash, 0.into(), HashMap::new());
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    state_reader
        .contract_states_mut()
        .insert(proxy_address.clone(), proxy_state);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let contract_entry_points_by_type = state
        .get_contract_class(&contract_class_hash)
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
    execute_entry_point(
        ProxyAmmEntryPoints::InitPool.into(),
        &calldata,
        &mut call_config,
    )
    .unwrap();

    let calldata = [0.into(), 55.into(), 66.into()].to_vec();
    let index_entry_point_proxy_add_demo_token: usize = ProxyAmmEntryPoints::AddDemoToken.into();
    let result = execute_entry_point(
        index_entry_point_proxy_add_demo_token,
        &calldata,
        &mut call_config,
    )
    .unwrap();

    let amm_proxy_entrypoint_selector = proxy_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_proxy_add_demo_token)
        .unwrap()
        .selector()
        .clone();

    let index_entry_point_add_demo_token: usize = AmmEntryPoints::AddDemoToken.into();
    let amm_entrypoint_selector = contract_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_add_demo_token)
        .unwrap()
        .selector()
        .clone();

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
    let contract_state = ContractState::new(contract_class_hash, 0.into(), HashMap::new());
    let proxy_state = ContractState::new(proxy_class_hash, 0.into(), HashMap::new());
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    state_reader
        .contract_states_mut()
        .insert(proxy_address.clone(), proxy_state);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let contract_entry_points_by_type = state
        .get_contract_class(&contract_class_hash)
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
    execute_entry_point(
        ProxyAmmEntryPoints::AddDemoToken.into(),
        &calldata,
        &mut call_config,
    )
    .unwrap();

    //First argument is the amm contract address
    //Second argument is the account address, in this case the proxy address
    //Third argument is the token id
    let calldata = [0.into(), 1000000.into(), 2.into()].to_vec();
    let index_entry_point_get_account_balance: usize =
        ProxyAmmEntryPoints::GetAccountTokenBalance.into();
    let result = execute_entry_point(4, &calldata, &mut call_config).unwrap();

    let amm_proxy_entrypoint_selector = proxy_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_get_account_balance)
        .unwrap()
        .selector()
        .clone();

    let index_entry_point_get_account_balance: usize =
        AmmEntryPoints::_GetAccountTokenBalance.into();

    let amm_entrypoint_selector = contract_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_get_account_balance)
        .unwrap()
        .selector()
        .clone();

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
    let contract_state = ContractState::new(contract_class_hash, 0.into(), HashMap::new());
    let proxy_state = ContractState::new(proxy_class_hash, 0.into(), HashMap::new());
    contract_class_cache.insert(contract_class_hash, contract_class);
    contract_class_cache.insert(proxy_class_hash, proxy_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);
    state_reader
        .contract_states_mut()
        .insert(proxy_address.clone(), proxy_state);

    // Create state with previous data
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let proxy_entry_points_by_type = state
        .get_contract_class(&proxy_class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let contract_entry_points_by_type = state
        .get_contract_class(&contract_class_hash)
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
    execute_entry_point(
        ProxyAmmEntryPoints::AddDemoToken.into(),
        &calldata,
        &mut call_config,
    )
    .unwrap();

    //Init pool to have 1000 tokens of each type
    let calldata = [0.into(), 1000.into(), 1000.into()].to_vec();
    execute_entry_point(
        ProxyAmmEntryPoints::InitPool.into(),
        &calldata,
        &mut call_config,
    )
    .unwrap();

    //Swap 100 tokens of type 1 for type 2
    //First argument is the amm contract address
    //Second argunet is the token to swap (type 1)
    //Third argument is the amount of tokens to swap (100)
    let calldata = [0.into(), 1.into(), 100.into()].to_vec();
    let index_entry_point_proxyswap = ProxyAmmEntryPoints::Swap.into();
    let expected_result = [90.into()].to_vec();
    let result =
        execute_entry_point(index_entry_point_proxyswap, &calldata, &mut call_config).unwrap();

    let amm_proxy_entrypoint_selector = proxy_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_point_proxyswap)
        .unwrap()
        .selector()
        .clone();

    let index_entry_pointswap: usize = AmmEntryPoints::Swap.into();
    let amm_entrypoint_selector = contract_entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_entry_pointswap)
        .unwrap()
        .selector()
        .clone();

    //checked for amm contract both tokens balances
    let accessed_storage_keys_pool_balance =
        utils::get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    //checked for proxy account both tokens balances
    let accessed_storage_keys_user_balance = utils::get_accessed_keys(
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
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}
