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
        state::cached_state::CachedState,
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
    utils::{calculate_sn_keccak, Address},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

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
) -> (
    CachedState<InMemoryStateReader>,
    HashMap<EntryPointType, Vec<ContractEntryPoint>>,
) {
    // Create program and entry point types for contract class
    let path = PathBuf::from(path);
    let contract_class = ContractClass::try_from(path).unwrap();
    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    let contract_state = ContractState::new(class_hash.clone(), 0.into(), HashMap::new());
    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(address.clone(), contract_state);

    // Create state with previous data
    (
        CachedState::new(state_reader, Some(contract_class_cache)),
        entry_points_by_type,
    )
}

#[test]
fn amm_init_pool_test() {
    //  ------------ contract data --------------------

    let address = Address(1111.into());
    let class_hash = [1; 32];
    let mut state: CachedState<InMemoryStateReader>;
    let entry_points_by_type;
    (state, entry_points_by_type) =
        setup_contract("starknet_programs/amm.json", &address, class_hash);

    //* ------------------------------------
    let calldata = [10000.into(), 10000.into()].to_vec();
    let caller_address = Address(0000.into());

    let (exec_entry_point, amm_entrypoint_selector) = get_entry_points(
        &entry_points_by_type,
        4,
        &address,
        &class_hash,
        &calldata,
        &caller_address,
    );

    //* --------------------
    //*   Execute contract
    //* ---------------------
    let general_config = StarknetGeneralConfig::default();
    let tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt::zero(),
        Vec::new(),
        0,
        10.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    let accessed_storage_keys =
        get_accessed_keys("pool_balance", vec![vec![1_u8.into()], vec![2_u8.into()]]);

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(amm_entrypoint_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata,
        retdata: [].to_vec(),
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys,
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

    //* ------------------------------------
    //*    Create entry points
    //* ------------------------------------

    let calldata_getter = [1.into()].to_vec();
    let caller_address_getter = Address(0000.into());

    let (exec_entry_point_getter, get_pool_balance_selector) = get_entry_points(
        &entry_points_by_type,
        3,
        &address,
        &class_hash,
        &calldata_getter,
        &caller_address_getter,
    );

    let tx_execution_context_getter = TransactionExecutionContext::new(
        Address(0.into()),
        Felt::zero(),
        Vec::new(),
        0,
        11.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );

    let result = exec_entry_point_getter
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context_getter,
        )
        .unwrap();

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

    assert_eq!(result, expected_call_info_getter);

    //ADD DEMO TOKEN

    //* ------------------------------------
    //*    Create entry points
    //* ------------------------------------

    let calldata_add_demo_token = [100.into(), 100.into()].to_vec();
    let caller_address_add_demo_token = Address(0000.into());

    let (exec_entry_point_add_demo_token, add_demo_token_selector) = get_entry_points(
        &entry_points_by_type,
        2,
        &address,
        &class_hash,
        &calldata_add_demo_token,
        &caller_address_add_demo_token,
    );

    let tx_execution_context_add_demo_token = TransactionExecutionContext::new(
        Address(0.into()),
        Felt::zero(),
        Vec::new(),
        0,
        12.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );

    let result_add_demo_token = exec_entry_point_add_demo_token
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context_add_demo_token,
        )
        .unwrap();

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
        contract_address: Address(1111.into()),
        entry_point_selector: Some(add_demo_token_selector),
        entry_point_type: Some(EntryPointType::External),
        calldata: calldata_add_demo_token,
        execution_resources: ExecutionResources::default(),
        class_hash: Some(class_hash),
        accessed_storage_keys: accessed_storage_keys_add_demo_token,
        ..Default::default()
    };

    assert_eq!(result_add_demo_token, expected_call_info_add_demo_token);
}
