#![deny(warnings)]

use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use num_traits::Zero;
use starknet_crypto::{pedersen_hash, FieldElement};
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
        state::{cached_state::CachedState, state_api::StateReader},
        transaction::error::TransactionError,
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, Address},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
enum AmmEntryPoints {
    GetAccountTokenBalance,
    Swap,
    AddDemoToken,
    GetPoolTokenBalance,
    InitPool,
}

impl Into<usize> for AmmEntryPoints {
    fn into(self) -> usize {
        match self {
            AmmEntryPoints::GetAccountTokenBalance => 0,
            AmmEntryPoints::Swap => 1,
            AmmEntryPoints::AddDemoToken => 2,
            AmmEntryPoints::GetPoolTokenBalance => 3,
            AmmEntryPoints::InitPool => 4,
        }
    }
}

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

struct CallConfig<'a> {
    state: &'a mut CachedState<InMemoryStateReader>,
    caller_address: &'a Address,
    address: &'a Address,
    class_hash: &'a [u8; 32],
    entry_points_by_type: &'a HashMap<
        EntryPointType,
        Vec<starknet_rs::services::api::contract_class::ContractEntryPoint>,
    >,
    general_config: &'a StarknetGeneralConfig,
    resources_manager: &'a mut ExecutionResourcesManager,
}

fn get_accessed_keys(variable_name: &str, fields: Vec<Vec<FieldElement>>) -> HashSet<[u8; 32]> {
    let variable_hash = calculate_sn_keccak(variable_name.as_bytes());
    let variable_hash = FieldElement::from_bytes_be(&variable_hash).unwrap();

    let keys = fields
        .iter()
        .map(|field| {
            field
                .iter()
                .fold(variable_hash, |hash, f| pedersen_hash(&hash, f))
        })
        .collect::<Vec<FieldElement>>();

    let mut accessed_storage_keys: HashSet<[u8; 32]> = HashSet::new();

    for key in keys {
        accessed_storage_keys.insert(key.to_bytes_be());
    }

    accessed_storage_keys
}

fn get_entry_points(
    entry_points_by_type: &HashMap<
        EntryPointType,
        Vec<starknet_rs::services::api::contract_class::ContractEntryPoint>,
    >,
    index_selector: usize,
    address: &Address,
    class_hash: &[u8; 32],
    calldata: &[Felt],
    caller_address: &Address,
) -> (ExecutionEntryPoint, Felt) {
    //* ------------------------------------
    //*    Create entry point selector
    //* ------------------------------------
    let entrypoint_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(index_selector)
        .unwrap()
        .selector()
        .clone();

    //* ------------------------------------
    //*    Create execution entry point
    //* ------------------------------------

    let entry_point_type = EntryPointType::External;

    (
        ExecutionEntryPoint::new(
            address.clone(),
            calldata.to_vec(),
            entrypoint_selector.clone(),
            caller_address.clone(),
            entry_point_type,
            Some(CallType::Delegate),
            Some(*class_hash),
        ),
        entrypoint_selector,
    )
}

fn setup_contract(
    path: &str,
    address: &Address,
    class_hash: [u8; 32],
) -> CachedState<InMemoryStateReader> {
    // Create program and entry point types for contract class
    let path = PathBuf::from(path);
    let contract_class = ContractClass::try_from(path).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    let contract_state = ContractState::new(class_hash, 0.into(), HashMap::new());
    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(address.clone(), contract_state);

    // Create state with previous data
    CachedState::new(state_reader, Some(contract_class_cache))
}

fn execute_entry_point(
    index_selector: usize,
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    // Entry point for init pool
    let (exec_entry_point, _) = get_entry_points(
        call_config.entry_points_by_type,
        index_selector as usize,
        call_config.address,
        call_config.class_hash,
        calldata,
        call_config.caller_address,
    );

    //* --------------------
    //*   Execute contract
    //* ---------------------
    let tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt::zero(),
        Vec::new(),
        0,
        10.into(),
        call_config.general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );

    exec_entry_point.execute(
        call_config.state,
        call_config.general_config,
        call_config.resources_manager,
        &tx_execution_context,
    )
}

fn init_pool(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point(AmmEntryPoints::InitPool.into(), calldata, call_config)
}

fn get_pool_token_balance(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point(
        AmmEntryPoints::GetPoolTokenBalance.into(),
        calldata,
        call_config,
    )
}

fn add_demo_token(
    calldata: &[Felt],
    call_config: &mut CallConfig,
) -> Result<CallInfo, TransactionError> {
    execute_entry_point(AmmEntryPoints::AddDemoToken.into(), calldata, call_config)
}

// Swap function to execute swap between two tokens
fn swap(calldata: &[Felt], call_config: &mut CallConfig) -> Result<CallInfo, TransactionError> {
    execute_entry_point(AmmEntryPoints::Swap.into(), calldata, call_config)
}
#[test]
fn amm_init_pool_test() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let amm_entrypoint_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(AmmEntryPoints::InitPool as usize)
        .unwrap()
        .selector()
        .clone();

    let accessed_storage_keys =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
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
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
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
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let accessed_storage_keys_add_demo_token = get_accessed_keys(
        "account_balance",
        vec![
            vec![0_u8.into(), 1_u8.into()],
            vec![0_u8.into(), 2_u8.into()],
        ],
    );

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&calldata, &mut call_config).unwrap();

    let calldata_add_demo_token = [100.into(), 100.into()].to_vec();

    let add_demo_token_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(AmmEntryPoints::AddDemoToken as usize)
        .unwrap()
        .selector()
        .clone();

    let expected_call_info_add_demo_token = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
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
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&calldata, &mut call_config).unwrap();

    let calldata_getter = [1.into()].to_vec();

    let get_pool_balance_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(AmmEntryPoints::GetPoolTokenBalance as usize)
        .unwrap()
        .selector()
        .clone();

    let result = get_pool_token_balance(&calldata_getter, &mut call_config);

    let accessed_storage_keys_pool_balance =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()]]);

    let expected_call_info_getter = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(get_pool_balance_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata_getter,
        retdata: [10000.into()].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: accessed_storage_keys_pool_balance,
        storage_read_values: [10000.into()].to_vec(),
        ..Default::default()
    };

    assert_eq!(result.unwrap(), expected_call_info_getter);
}

//test swap functionality
//first we set up the contract
//second we init the pool
//third we add tokens to the user
//fourth we swap tokens
//check if its what we expected
#[test]
fn ammswap_test() {
    //set up contract
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();

    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&calldata, &mut call_config).unwrap();

    //add tokens to user
    let calldata_add_demo_token = [100.into(), 100.into()].to_vec();
    add_demo_token(&calldata_add_demo_token, &mut call_config).unwrap();

    //swap tokens. Token 1 with 10 in amount
    let calldataswap = [1.into(), 10.into()].to_vec();

    //expected return value 9
    let expected_return = [9.into()].to_vec();

    let result = swap(&calldataswap, &mut call_config);

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

    let swap_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(AmmEntryPoints::Swap as usize)
        .unwrap()
        .selector()
        .clone();

    let expected_call_infoswap = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(swap_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldataswap,
        retdata: expected_return,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
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

    assert_eq!(result.unwrap(), expected_call_infoswap);
}

#[test]
fn amm_init_pool_should_fail_with_amount_out_of_bounds() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [Felt::new(2_u32.pow(30)), Felt::new(2_u32.pow(30))].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert!(init_pool(&calldata, &mut call_config).is_err());
}

#[test]
fn ammswap_should_fail_with_unexistent_token() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [Felt::zero(), Felt::new(10)].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert!(swap(&calldata, &mut call_config).is_err());
}

#[test]
fn ammswap_should_fail_with_amount_out_of_bounds() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [Felt::new(1), Felt::new(2_u32.pow(30))].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    assert!(swap(&calldata, &mut call_config).is_err());
}

#[test]
fn ammswap_should_fail_when_user_does_not_have_enough_funds() {
    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state = setup_contract("starknet_programs/amm.json", &address, class_hash);
    let entry_points_by_type = state
        .get_contract_class(&class_hash)
        .unwrap()
        .entry_points_by_type()
        .clone();

    let calldata = [Felt::new(1), Felt::new(100)].to_vec();
    let caller_address = Address(0000.into());
    let general_config = StarknetGeneralConfig::default();
    let mut resources_manager = ExecutionResourcesManager::default();
    let mut call_config = CallConfig {
        state: &mut state,
        caller_address: &caller_address,
        address: &address,
        class_hash: &class_hash,
        entry_points_by_type: &entry_points_by_type,
        general_config: &general_config,
        resources_manager: &mut resources_manager,
    };

    init_pool(&[Felt::new(1000), Felt::new(1000)], &mut call_config).unwrap();
    add_demo_token(&[Felt::new(10), Felt::new(10)], &mut call_config).unwrap();

    assert!(swap(&calldata, &mut call_config).is_err());
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
        AmmEntryPoints::GetAccountTokenBalance.into();

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
            ..Default::default()
        },
        class_hash: Some(proxy_class_hash),
        internal_calls,
        ..Default::default()
    };

    assert_eq!(result, expected_call_info);
}
