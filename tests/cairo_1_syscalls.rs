use std::{
    collections::{HashMap, HashSet},
    vec,
};

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::{
    felt::Felt252,
    vm::runners::{builtin_runner::RANGE_CHECK_BUILTIN_NAME, cairo_runner::ExecutionResources},
};
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::contract_classes::deprecated_contract_class::EntryPointType,
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
    let view_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
    );

    // Run get_balance entrypoint
    let call_info = view_exec_entry_point
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
    let external_exec_entry_point = create_execute_extrypoint(
        increase_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
    );

    // Run increase_balance entrypoint
    external_exec_entry_point
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
    let view_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
    );

    // Run get_balance entrypoint
    let call_info = view_exec_entry_point
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
            ..Default::default()
        }],
        code_address: None,
        events: vec![],
        l2_to_l1_messages: vec![],
        storage_read_values: vec![],
        accessed_storage_keys: HashSet::new(),
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
    let _increase_balance_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

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
                                     entry_point_type: EntryPointType, class_hash: [u8; 32]|
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

    // RUN SIMPLE_WALLET CONSTRUCTOR
    // Create an execution entry point
    let calldata = [25.into(), simple_wallet_address.clone().0.clone()].to_vec();
    let constructor_exec_entry_point = create_execute_extrypoint(
        &simple_wallet_constructor_entrypoint_selector,
        calldata,
        EntryPointType::Constructor,
        simple_wallet_class_hash
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
    let calldata = [simple_wallet_address.clone().0.clone()].to_vec();
    let view_exec_entry_point = create_execute_extrypoint(
        get_balance_entrypoint_selector,
        calldata,
        EntryPointType::External,
        class_hash
    );

    // Run get_balance entrypoint
    let call_info = view_exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )
        .unwrap();
    assert_eq!(call_info.retdata, [25.into()]);

    // // RUN INCREASE_BALANCE
    // // Create an execution entry point
    // let calldata = [100.into(), simple_wallet_address.clone().0.clone()].to_vec();
    // let external_exec_entry_point = create_execute_extrypoint(
    //     increase_balance_entrypoint_selector,
    //     calldata,
    //     EntryPointType::External,
    // );

    // // Run increase_balance entrypoint
    // external_exec_entry_point
    //     .execute(
    //         &mut state,
    //         &general_config,
    //         &mut resources_manager,
    //         &tx_execution_context,
    //         false,
    //     )
    //     .unwrap();

    // // RUN GET_BALANCE
    // // Create an execution entry point
    // let calldata = [simple_wallet_address.clone().0.clone()].to_vec();
    // let view_exec_entry_point =
    //     create_execute_extrypoint(get_balance_entrypoint_selector, calldata, EntryPointType::External);

    // // Run get_balance entrypoint
    // let call_info = view_exec_entry_point
    //     .execute(
    //         &mut state,
    //         &general_config,
    //         &mut resources_manager,
    //         &tx_execution_context,
    //         false,
    //     )
    //     .unwrap();
    // assert_eq!(call_info.retdata, [125.into()])
}
