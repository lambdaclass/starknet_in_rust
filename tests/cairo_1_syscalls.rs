use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    vec,
};

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::{
    felt::{felt_str, Felt252},
    vm::runners::{builtin_runner::RANGE_CHECK_BUILTIN_NAME, cairo_runner::ExecutionResources},
};
use num_bigint::BigUint;
use num_traits::{Num, One, Zero};
use starknet_contract_class::EntryPointType;
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, OrderedEvent,
            OrderedL2ToL1Message, TransactionExecutionContext,
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{cached_state::CachedState, state_api::StateReader},
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    utils::{Address, ClassHash},
};

#[test]
fn storage_write_read() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/simple_wallet.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let constructor_entrypoint_selector = &entrypoints.constructor.get(0).unwrap().selector;
    let get_balance_entrypoint_selector = &entrypoints.external.get(1).unwrap().selector;
    let increase_balance_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

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

    let create_execute_extrypoint = |selector: &BigUint,
                                     calldata: Vec<Felt252>,
                                     entry_point_type: EntryPointType|
     -> ExecutionEntryPoint {
        ExecutionEntryPoint::new(
            address.clone(),
            calldata,
            Felt252::new(selector.clone()),
            Address(0000.into()),
            entry_point_type,
            Some(CallType::Delegate),
            Some(class_hash),
            100000,
        )
    };

    // RUN CONSTRUCTOR
    // Create an execution entry point
    let calldata = [25.into()].to_vec();
    let constructor_exec_entry_point = create_execute_extrypoint(
        constructor_entrypoint_selector,
        calldata,
        EntryPointType::Constructor,
    );

    // Run constructor entrypoint
    constructor_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    // RUN GET_BALANCE
    // Create an execution entry point
    let calldata = [].to_vec();
    let get_balance_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
    );

    // Run get_balance entrypoint
    let call_info = get_balance_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(call_info.retdata, [25.into()]);

    // RUN INCREASE_BALANCE
    // Create an execution entry point
    let calldata = [100.into()].to_vec();
    let increase_balance_entry_point = create_execute_extrypoint(
        increase_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
    );

    // Run increase_balance entrypoint
    increase_balance_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    // RUN GET_BALANCE
    // Create an execution entry point
    let calldata = [].to_vec();
    let get_balance_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
    );

    // Run get_balance entrypoint
    let call_info = get_balance_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(call_info.retdata, [125.into()])
}

#[test]
fn library_call() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/square_root.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Add lib contract to the state

    let lib_program_data = include_bytes!("../starknet_programs/cairo1/math_lib.casm");
    let lib_contract_class: CasmContractClass = serde_json::from_slice(lib_program_data).unwrap();

    let lib_address = Address(1112.into());
    let lib_class_hash: ClassHash = [2; 32];
    let lib_nonce = Felt252::zero();

    contract_class_cache.insert(lib_class_hash, lib_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(lib_address.clone(), lib_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(lib_address, lib_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // Create an execution entry point
    let calldata = [25.into(), Felt252::from_bytes_be(&lib_class_hash)].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata.clone(),
        Felt252::new(entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100000,
    );

    // Execute the entrypoint
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
    let mut expected_execution_resources = ExecutionResources::default();
    expected_execution_resources
        .builtin_instance_counter
        .insert(RANGE_CHECK_BUILTIN_NAME.to_string(), 7);
    expected_execution_resources.n_memory_holes = 6;

    // expected results
    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: Address(1111.into()),
        entry_point_selector: Some(Felt252::new(entrypoint_selector)),
        entry_point_type: Some(EntryPointType::External),
        calldata,
        retdata: [5.into()].to_vec(),
        execution_resources: expected_execution_resources,
        class_hash: Some(class_hash),
        internal_calls: vec![CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Delegate),
            contract_address: Address(1111.into()),
            entry_point_selector: Some(
                Felt252::from_str_radix(
                    "544923964202674311881044083303061611121949089655923191939299897061511784662",
                    10,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![25.into()],
            retdata: [5.into()].to_vec(),
            execution_resources: ExecutionResources::default(),
            class_hash: Some(lib_class_hash),
            gas_consumed: 0,
            ..Default::default()
        }],
        code_address: None,
        events: vec![],
        l2_to_l1_messages: vec![],
        storage_read_values: vec![],
        accessed_storage_keys: HashSet::new(),
        gas_consumed: 78980,
        ..Default::default()
    };

    assert_eq!(
        exec_entry_point
            .execute(
                &mut state,
                &general_config,
                &mut resources_manager,
                &tx_execution_context,
                false,
            )
            .unwrap(),
        expected_call_info
    );
}

#[test]
fn call_contract_storage_write_read() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/wallet_wrapper.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let get_balance_entrypoint_selector = &entrypoints.external.get(1).unwrap().selector;
    let increase_balance_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Add simple_wallet contract to the state

    let simple_wallet_program_data =
        include_bytes!("../starknet_programs/cairo1/simple_wallet.casm");
    let simple_wallet_contract_class: CasmContractClass =
        serde_json::from_slice(simple_wallet_program_data).unwrap();
    let simple_wallet_constructor_entrypoint_selector = simple_wallet_contract_class
        .entry_points_by_type
        .constructor
        .get(0)
        .unwrap()
        .selector
        .clone();

    let simple_wallet_address = Address(1112.into());
    let simple_wallet_class_hash: ClassHash = [2; 32];
    let simple_wallet_nonce = Felt252::zero();

    contract_class_cache.insert(simple_wallet_class_hash, simple_wallet_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(simple_wallet_address.clone(), simple_wallet_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(simple_wallet_address.clone(), simple_wallet_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

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

    let create_execute_extrypoint = |selector: &BigUint,
                                     calldata: Vec<Felt252>,
                                     entry_point_type: EntryPointType,
                                     class_hash: [u8; 32],
                                     address: Address|
     -> ExecutionEntryPoint {
        ExecutionEntryPoint::new(
            address,
            calldata,
            Felt252::new(selector.clone()),
            Address(0000.into()),
            entry_point_type,
            Some(CallType::Delegate),
            Some(class_hash),
            u64::MAX.into(),
        )
    };

    // RUN SIMPLE_WALLET CONSTRUCTOR
    // Create an execution entry point
    let calldata = [25.into()].to_vec();
    let constructor_exec_entry_point = create_execute_extrypoint(
        &simple_wallet_constructor_entrypoint_selector,
        calldata,
        EntryPointType::Constructor,
        simple_wallet_class_hash,
        simple_wallet_address.clone(),
    );

    // Run constructor entrypoint
    constructor_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    // RUN GET_BALANCE
    // Create an execution entry point
    let calldata = [simple_wallet_address.0.clone()].to_vec();
    let get_balance_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
        class_hash,
        address.clone(),
    );

    // Run get_balance entrypoint
    let call_info = get_balance_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(call_info.retdata, [25.into()]);

    // RUN INCREASE_BALANCE
    // Create an execution entry point
    let calldata = [100.into(), simple_wallet_address.0.clone()].to_vec();
    let increase_balance_entry_point = create_execute_extrypoint(
        increase_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
        class_hash,
        address.clone(),
    );

    // Run increase_balance entrypoint
    increase_balance_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    // RUN GET_BALANCE
    // Create an execution entry point
    let calldata = [simple_wallet_address.0].to_vec();
    let get_balance_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
        class_hash,
        address,
    );

    // Run get_balance entrypoint
    let call_info = get_balance_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(call_info.retdata, [125.into()])
}

#[test]
fn emit_event() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/emit_event.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // Create an execution entry point
    let calldata = [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100000,
    );

    // Execute the entrypoint
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
    let call_info = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(
        call_info.events,
        vec![
            OrderedEvent {
                order: 0,
                keys: vec![Felt252::from_str_radix(
                    "1533133552972353850845856330693290141476612241335297758062928121906575244541",
                    10
                )
                .unwrap()],
                data: vec![1.into()]
            },
            OrderedEvent {
                order: 1,
                keys: vec![Felt252::from_str_radix(
                    "1533133552972353850845856330693290141476612241335297758062928121906575244541",
                    10
                )
                .unwrap()],
                data: vec![2.into()]
            },
            OrderedEvent {
                order: 2,
                keys: vec![Felt252::from_str_radix(
                    "1533133552972353850845856330693290141476612241335297758062928121906575244541",
                    10
                )
                .unwrap()],
                data: vec![3.into()]
            }
        ]
    )
}

#[test]
fn deploy() {
    // data to deploy
    let test_class_hash: ClassHash = [2; 32];
    let test_felt_hash = Felt252::from_bytes_be(&test_class_hash);
    let salt = Felt252::zero();
    let test_data = include_bytes!("../starknet_programs/cairo1/contract_a.casm");
    let test_contract_class: CasmContractClass = serde_json::from_slice(test_data).unwrap();

    // Create the deploy contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/deploy.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    contract_class_cache.insert(test_class_hash, test_contract_class.clone());

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // arguments of deploy contract
    let calldata: Vec<_> = [test_felt_hash, salt].to_vec();

    // set up remaining structures

    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100_000_000,
    );

    // Execute the entrypoint
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

    let call_info = exec_entry_point.execute(
        &mut state,
        &general_config,
        &mut resources_manager,
        &tx_execution_context,
        false,
    );

    assert!(call_info.is_ok());

    let ret_address = Address(felt_str!(
        "619464431559909356793718633071398796109800070568878623926447195121629120356"
    ));

    let ret_class_hash = state.get_class_hash_at(&ret_address).unwrap();
    let ret_casm_class = match state.get_contract_class(&ret_class_hash).unwrap() {
        CompiledClass::Casm(class) => *class,
        CompiledClass::Deprecated(_) => unreachable!(),
    };

    assert_eq!(ret_casm_class, test_contract_class);
}

#[test]
fn test_send_message_to_l1_syscall() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/send_message_to_l1.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let external_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    let create_execute_extrypoint = |selector: &BigUint,
                                     calldata: Vec<Felt252>,
                                     entry_point_type: EntryPointType|
     -> ExecutionEntryPoint {
        ExecutionEntryPoint::new(
            address.clone(),
            calldata,
            Felt252::new(selector.clone()),
            Address(0000.into()),
            entry_point_type,
            Some(CallType::Delegate),
            Some(class_hash),
            100000,
        )
    };

    // RUN SEND_MSG
    // Create an execution entry point
    let send_message_exec_entry_point = create_execute_extrypoint(
        external_entrypoint_selector,
        vec![],
        EntryPointType::External,
    );

    // Execute the entrypoint
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

    // Run send_msg entrypoint
    let call_info = send_message_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    let l2_to_l1_messages = vec![OrderedL2ToL1Message {
        order: 0,
        to_address: Address(444.into()),
        payload: vec![555.into(), 666.into()],
    }];

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: address.clone(),
        class_hash: Some(class_hash),
        entry_point_selector: Some(external_entrypoint_selector.into()),
        entry_point_type: Some(EntryPointType::External),
        l2_to_l1_messages,
        gas_consumed: 10040,
        ..Default::default()
    };

    assert_eq!(call_info, expected_call_info);
}

#[test]
fn replace_class_internal() {
    // This test only checks that the contract is updated in the storage, see `replace_class_contract_call`
    //  Create program and entry point types for contract class
    let program_data_a = include_bytes!("../starknet_programs/cairo1/get_number_a.casm");
    let contract_class_a: CasmContractClass = serde_json::from_slice(program_data_a).unwrap();
    let entrypoints_a = contract_class_a.clone().entry_points_by_type;
    let upgrade_selector = &entrypoints_a.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash_a: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash_a, contract_class_a);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash_a);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Add get_number_b contract to the state (only its contract_class)

    let program_data_b = include_bytes!("../starknet_programs/cairo1/get_number_b.casm");
    let contract_class_b: CasmContractClass = serde_json::from_slice(program_data_b).unwrap();

    let class_hash_b: ClassHash = [2; 32];

    contract_class_cache.insert(class_hash_b, contract_class_b.clone());

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // Run upgrade entrypoint and check that the storage was updated with the new contract class
    // Create an execution entry point
    let calldata = [Felt252::from_bytes_be(&class_hash_b)].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address.clone(),
        calldata,
        Felt252::new(upgrade_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash_a),
        100000,
    );

    // Execute the entrypoint
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

    exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    // Check that the class was indeed replaced in storage
    assert_eq!(state.get_class_hash_at(&address).unwrap(), class_hash_b);
    // Check that the class_hash_b leads to contract_class_b for soundness
    assert_eq!(
        state.get_contract_class(&class_hash_b).unwrap(),
        CompiledClass::Casm(Box::new(contract_class_b))
    );
}

#[test]
fn replace_class_contract_call() {
    /* Test Outline:
       - Add `get_number_a.cairo` contract at address 2 and `get_number_b.cairo` contract without an address
       - Call `get_number` function of `get_number_wrapper.cairo` and expect to get an answer from `get_number_a` (25)
       - Call `upgrade` function of `get_number_wrapper.cairo` with `get_number_b.cairo`'s class_hash
       - Call `get_number` function of `get_number_wrapper.cairo` and expect to get an answer from `get_number_b` (17)
    */

    // SET GET_NUMBER_A
    // Add get_number_a.cairo to storage
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_a.casm");
    let contract_class_a: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(Felt252::one());
    let class_hash_a: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash_a, contract_class_a);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash_a);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce.clone());

    // SET GET_NUMBER_B

    // Add get_number_b contract to the state (only its contract_class)

    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_b.casm");
    let contract_class_b: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    let class_hash_b: ClassHash = [2; 32];

    contract_class_cache.insert(class_hash_b, contract_class_b);

    // SET GET_NUMBER_WRAPPER

    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_wrapper.casm");
    let wrapper_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = wrapper_contract_class.clone().entry_points_by_type;
    let get_number_entrypoint_selector = &entrypoints.external.get(1).unwrap().selector;
    let upgrade_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    let wrapper_address = Address(Felt252::from(2));
    let wrapper_class_hash: ClassHash = [3; 32];

    contract_class_cache.insert(wrapper_class_hash, wrapper_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(wrapper_address.clone(), wrapper_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(wrapper_address, nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // INITIALIZE STARKNET CONFIG
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

    // CALL GET_NUMBER BEFORE REPLACE_CLASS

    let calldata = [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address.clone(),
        calldata,
        Felt252::new(get_number_entrypoint_selector.clone()),
        caller_address.clone(),
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        100000,
    );

    let result = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(result.retdata, vec![25.into()]);

    // REPLACE_CLASS

    let calldata = [Felt252::from_bytes_be(&class_hash_b)].to_vec();

    let exec_entry_point = ExecutionEntryPoint::new(
        address.clone(),
        calldata,
        Felt252::new(upgrade_entrypoint_selector.clone()),
        caller_address.clone(),
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        100000,
    );

    exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();

    // CALL GET_NUMBER AFTER REPLACE_CLASS

    let calldata = [].to_vec();

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(get_number_entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        100000,
    );

    let result = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(result.retdata, vec![17.into()]);
}

#[test]
fn replace_class_contract_call_same_transaction() {
    /* Test Outline:
       - Add `get_number_a.cairo` contract at address 2 and `get_number_b.cairo` contract without an address
       - Call `get_numbers_old_new` function of `get_number_wrapper.cairo` and expect to get both answers from `get_number_a`, and 'get_number_b' (25, 17)
    */

    // SET GET_NUMBER_A
    // Add get_number_a.cairo to storage
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_a.casm");
    let contract_class_a: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(Felt252::one());
    let class_hash_a: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash_a, contract_class_a);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash_a);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce.clone());

    // SET GET_NUMBER_B

    // Add get_number_b contract to the state (only its contract_class)

    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_b.casm");
    let contract_class_b: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    let class_hash_b: ClassHash = [2; 32];

    contract_class_cache.insert(class_hash_b, contract_class_b);

    // SET GET_NUMBER_WRAPPER

    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_wrapper.casm");
    let wrapper_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = wrapper_contract_class.clone().entry_points_by_type;
    let get_numbers_entrypoint_selector = &entrypoints.external.get(2).unwrap().selector;

    let wrapper_address = Address(Felt252::from(2));
    let wrapper_class_hash: ClassHash = [3; 32];

    contract_class_cache.insert(wrapper_class_hash, wrapper_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(wrapper_address.clone(), wrapper_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(wrapper_address, nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // INITIALIZE STARKNET CONFIG
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

    // CALL GET_NUMBERS_OLD_NEW

    let calldata = [Felt252::from_bytes_be(&class_hash_b)].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(get_numbers_entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        u64::MAX.into(),
    );

    let result = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(result.retdata, vec![25.into(), 17.into()]);
}

#[test]
fn call_contract_upgrade_cairo_0_to_cairo_1_same_transaction() {
    /* Test Outline:
       - Add `get_number_c.cairo` contract at address 2 and `get_number_b.cairo` contract without an address
       - Call `get_numbers_old_new` function of `get_number_wrapper.cairo` and expect to get both answers from `get_number_c`, and 'get_number_b' (33, 17)
    */

    // SET GET_NUMBER_C

    // Add get_number_a.cairo to storage

    let path = PathBuf::from("starknet_programs/get_number_c.json");
    let contract_class_c = ContractClass::try_from(path).unwrap();

    // Create state reader with class hash data
    let mut casm_contract_class_cache = HashMap::new();
    let mut deprecated_contract_class_cache = HashMap::new();

    let address = Address(Felt252::one());
    let class_hash_c: ClassHash = Felt252::one().to_be_bytes();
    let nonce = Felt252::zero();

    deprecated_contract_class_cache.insert(class_hash_c, contract_class_c);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash_c);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce.clone());

    // SET GET_NUMBER_B

    // Add get_number_b contract to the state (only its contract_class)

    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_b.casm");
    let contract_class_b: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    let class_hash_b: ClassHash = Felt252::from(2).to_be_bytes();

    casm_contract_class_cache.insert(class_hash_b, contract_class_b);

    // SET GET_NUMBER_WRAPPER

    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_wrapper.casm");
    let wrapper_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = wrapper_contract_class.clone().entry_points_by_type;
    let get_numbers_entrypoint_selector = &entrypoints.external.get(2).unwrap().selector;

    let wrapper_address = Address(Felt252::from(2));
    let wrapper_class_hash: ClassHash = [3; 32];

    casm_contract_class_cache.insert(wrapper_class_hash, wrapper_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(wrapper_address.clone(), wrapper_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(wrapper_address, nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        state_reader,
        Some(deprecated_contract_class_cache),
        Some(casm_contract_class_cache),
    );

    // INITIALIZE STARKNET CONFIG
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

    // CALL GET_NUMBERS_OLD_NEW

    let calldata = [Felt252::from_bytes_be(&class_hash_b)].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(get_numbers_entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        u64::MAX.into(),
    );

    let result = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(result.retdata, vec![33.into(), 17.into()]);
}

#[test]
fn call_contract_downgrade_cairo_1_to_cairo_0_same_transaction() {
    /* Test Outline:
       - Add `get_number_b.cairo` contract at address 2 and `get_number_c.cairo` contract without an address
       - Call `get_numbers_old_new` function of `get_number_wrapper.cairo` and expect to get both answers from `get_number_b`, and 'get_number_c' (17, 33)
    */

    // SET GET_NUMBER_C
    // Add get_number_a.cairo to the state (only its contract_class)
    let path = PathBuf::from("starknet_programs/get_number_c.json");
    let contract_class_c = ContractClass::try_from(path).unwrap();

    // Create state reader with class hash data
    let mut casm_contract_class_cache = HashMap::new();
    let mut deprecated_contract_class_cache = HashMap::new();

    let address = Address(Felt252::one());
    let class_hash_c: ClassHash = Felt252::one().to_be_bytes();
    let nonce = Felt252::zero();

    deprecated_contract_class_cache.insert(class_hash_c, contract_class_c);

    // SET GET_NUMBER_B

    // Add get_number_b contract to the state

    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_b.casm");
    let contract_class_b: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    let class_hash_b: ClassHash = Felt252::from(2).to_be_bytes();

    casm_contract_class_cache.insert(class_hash_b, contract_class_b);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash_b);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce.clone());

    // SET GET_NUMBER_WRAPPER

    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_wrapper.casm");
    let wrapper_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = wrapper_contract_class.clone().entry_points_by_type;
    let get_numbers_entrypoint_selector = &entrypoints.external.get(2).unwrap().selector;

    let wrapper_address = Address(Felt252::from(2));
    let wrapper_class_hash: ClassHash = [3; 32];

    casm_contract_class_cache.insert(wrapper_class_hash, wrapper_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(wrapper_address.clone(), wrapper_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(wrapper_address, nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        state_reader,
        Some(deprecated_contract_class_cache),
        Some(casm_contract_class_cache),
    );

    // INITIALIZE STARKNET CONFIG
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

    // CALL GET_NUMBERS_OLD_NEW

    let calldata = [Felt252::from_bytes_be(&class_hash_c)].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(get_numbers_entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        u64::MAX.into(),
    );

    let result = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(result.retdata, vec![17.into(), 33.into()]);
}

#[test]
fn call_contract_replace_class_cairo_0() {
    /* Test Outline:
       - Add `get_number_d.cairo` contract at address 2 and `get_number_c.cairo` contract without an address
       - Call `get_numbers_old_new` function of `get_number_wrapper.cairo` and expect to get both answers from `get_number_d`, and 'get_number_c' (64, 33)
    */

    // SET GET_NUMBER_C
    // Add get_number_a.cairo to the state (only its contract_class)
    let path = PathBuf::from("starknet_programs/get_number_c.json");
    let contract_class_c = ContractClass::try_from(path).unwrap();

    // Create state reader with class hash data
    let mut casm_contract_class_cache = HashMap::new();
    let mut deprecated_contract_class_cache = HashMap::new();

    let address = Address(Felt252::one());
    let class_hash_c: ClassHash = Felt252::one().to_be_bytes();
    let nonce = Felt252::zero();

    deprecated_contract_class_cache.insert(class_hash_c, contract_class_c);

    // SET GET_NUMBER_B

    // Add get_number_b contract to the state

    let path = PathBuf::from("starknet_programs/get_number_d.json");
    let contract_class_d = ContractClass::try_from(path).unwrap();

    let class_hash_d: ClassHash = Felt252::from(2).to_be_bytes();

    deprecated_contract_class_cache.insert(class_hash_d, contract_class_d);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash_d);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce.clone());

    // SET GET_NUMBER_WRAPPER

    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/get_number_wrapper.casm");
    let wrapper_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = wrapper_contract_class.clone().entry_points_by_type;
    let get_numbers_entrypoint_selector = &entrypoints.external.get(2).unwrap().selector;

    let wrapper_address = Address(Felt252::from(2));
    let wrapper_class_hash: ClassHash = [3; 32];

    casm_contract_class_cache.insert(wrapper_class_hash, wrapper_contract_class);
    state_reader
        .address_to_class_hash_mut()
        .insert(wrapper_address.clone(), wrapper_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(wrapper_address, nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        state_reader,
        Some(deprecated_contract_class_cache),
        Some(casm_contract_class_cache),
    );

    // INITIALIZE STARKNET CONFIG
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

    // CALL GET_NUMBERS_OLD_NEW

    let calldata = [Felt252::from_bytes_be(&class_hash_c)].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(get_numbers_entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(wrapper_class_hash),
        u64::MAX.into(),
    );

    let result = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(result.retdata, vec![64.into(), 33.into()]);
}

#[test]
fn test_out_of_gas_failure() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/emit_event.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));

    // Create an execution entry point
    let calldata = [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    // Purposefully set initial gas to 0 so that the syscall fails
    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector.clone()),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        0,
    );

    // Execute the entrypoint
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
    let call_info = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(
        call_info.retdata,
        vec![Felt252::from_bytes_be("Out of gas".as_bytes())]
    );
    assert!(call_info.failure_flag)
}
