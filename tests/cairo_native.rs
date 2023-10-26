#![cfg(all(feature = "cairo-native", not(feature = "cairo_1_tests")))]

use crate::CallType::Call;
use num_traits::One;
use cairo_lang_starknet::casm_contract_class::CasmContractEntryPoints;
use cairo_lang_starknet::contract_class::ContractEntryPoints;
use cairo_vm::felt::Felt252;
use num_bigint::BigUint;
use num_traits::Zero;
use pretty_assertions_sorted::{assert_eq, assert_eq_sorted};
use starknet_in_rust::definitions::block_context::BlockContext;
use starknet_in_rust::execution::{Event, OrderedEvent};
use starknet_in_rust::services::api::contract_classes::compiled_class::CompiledClass;
use starknet_in_rust::CasmContractClass;
use starknet_in_rust::EntryPointType::{self, External};
use starknet_in_rust::{
    definitions::constants::TRANSACTION_VERSION,
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    state::cached_state::CachedState,
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use starknet_in_rust::hash_utils::calculate_contract_address;

#[test]
fn integration_test_erc20() {
    let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/erc20.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    let casm_data = include_bytes!("../starknet_programs/cairo2/erc20.casm");
    let casm_contract_class: CasmContractClass = serde_json::from_slice(casm_data).unwrap();

    let native_entrypoints = sierra_contract_class.clone().entry_points_by_type;
    let native_constructor_selector = &native_entrypoints.constructor.get(0).unwrap().selector;

    let casm_entrypoints = casm_contract_class.clone().entry_points_by_type;
    let casm_constructor_selector = &casm_entrypoints.constructor.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    static NATIVE_CLASS_HASH: ClassHash = [1; 32];
    static CASM_CLASS_HASH: ClassHash = [2; 32];

    let caller_address = Address(123456789.into());

    contract_class_cache.insert(
        NATIVE_CLASS_HASH,
        CompiledClass::Sierra(Arc::new(sierra_contract_class)),
    );
    contract_class_cache.insert(
        CASM_CLASS_HASH,
        CompiledClass::Casm(Arc::new(casm_contract_class)),
    );
    let mut state_reader = InMemoryStateReader::default();
    let nonce = Felt252::zero();

    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), CASM_CLASS_HASH);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let state_reader = Arc::new(state_reader);
    let mut state_vm = CachedState::new(state_reader.clone(), contract_class_cache.clone());
    let mut state_native = CachedState::new(state_reader, contract_class_cache);

    /*
        1 recipient
        2 name
        3 decimals
        4 initial_supply
        5 symbol
    */
    let calldata = [
        caller_address.0.clone(),
        2.into(),
        3.into(),
        4.into(),
        5.into(),
    ]
    .to_vec();

    let vm_result = execute(
        &mut state_vm,
        &caller_address,
        &caller_address,
        casm_constructor_selector,
        &calldata,
        EntryPointType::Constructor,
        &CASM_CLASS_HASH,
    );

    let native_result = execute(
        &mut state_native,
        &caller_address,
        &caller_address,
        native_constructor_selector,
        &calldata,
        EntryPointType::Constructor,
        &NATIVE_CLASS_HASH,
    );

    assert_eq!(vm_result.caller_address, caller_address);
    assert_eq!(vm_result.call_type, Some(CallType::Delegate));
    assert_eq!(vm_result.contract_address, caller_address);
    assert_eq!(
        vm_result.entry_point_selector,
        Some(Felt252::new(casm_constructor_selector))
    );
    assert_eq!(
        vm_result.entry_point_type,
        Some(EntryPointType::Constructor)
    );
    assert_eq!(vm_result.calldata, calldata);
    assert!(!vm_result.failure_flag);
    assert_eq!(vm_result.retdata, [].to_vec());
    assert_eq!(vm_result.class_hash, Some(CASM_CLASS_HASH));

    assert_eq!(native_result.caller_address, caller_address);
    assert_eq!(native_result.call_type, Some(CallType::Delegate));
    assert_eq!(native_result.contract_address, caller_address);
    assert_eq!(
        native_result.entry_point_selector,
        Some(Felt252::new(native_constructor_selector))
    );
    assert_eq!(
        native_result.entry_point_type,
        Some(EntryPointType::Constructor)
    );
    assert_eq!(native_result.calldata, calldata);
    assert!(!native_result.failure_flag);
    assert_eq!(native_result.retdata, [].to_vec());
    assert_eq!(native_result.execution_resources, None);
    assert_eq!(native_result.class_hash, Some(NATIVE_CLASS_HASH));
    assert_eq!(native_result.gas_consumed, 18446744073709551615); // (u64::MAX)

    assert_eq!(vm_result.events, native_result.events);
    assert_eq!(
        vm_result.accessed_storage_keys,
        native_result.accessed_storage_keys
    );
    assert_eq!(vm_result.l2_to_l1_messages, native_result.l2_to_l1_messages);
    // TODO: Make these asserts work
    // assert_eq!(vm_result.execution_resources, native_result.execution_resources);
    // assert_eq!(vm_result.gas_consumed, native_result.gas_consumed);

    fn compare_results(
        state_vm: &mut CachedState<InMemoryStateReader>,
        state_native: &mut CachedState<InMemoryStateReader>,
        selector_idx: usize,
        native_entrypoints: &ContractEntryPoints,
        casm_entrypoints: &CasmContractEntryPoints,
        calldata: &[Felt252],
        caller_address: &Address,
    ) {
        let native_selector = &native_entrypoints
            .external
            .get(selector_idx)
            .unwrap()
            .selector;
        let casm_selector = &casm_entrypoints
            .external
            .get(selector_idx)
            .unwrap()
            .selector;

        let vm_result = execute(
            state_vm,
            caller_address,
            caller_address,
            casm_selector,
            calldata,
            EntryPointType::External,
            &CASM_CLASS_HASH,
        );

        let native_result = execute(
            state_native,
            caller_address,
            caller_address,
            native_selector,
            calldata,
            EntryPointType::External,
            &NATIVE_CLASS_HASH,
        );

        assert_eq!(vm_result.failure_flag, native_result.failure_flag);
        assert_eq!(vm_result.retdata, native_result.retdata);
        assert_eq!(vm_result.events, native_result.events);
        assert_eq!(
            vm_result.accessed_storage_keys,
            native_result.accessed_storage_keys
        );
        assert_eq!(vm_result.l2_to_l1_messages, native_result.l2_to_l1_messages);

        // TODO: Make these asserts work
        // assert_eq!(vm_result.gas_consumed, native_result.gas_consumed);

        // This assert is probably impossible to make work because native doesn't track resources.
        // assert_eq!(vm_result.execution_resources, native_result.execution_resources);
    }

    // --------------- GET TOTAL SUPPLY -----------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        5,
        &native_entrypoints,
        &casm_entrypoints,
        &[],
        &caller_address,
    );

    // ---------------- GET DECIMALS ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        1,
        &native_entrypoints,
        &casm_entrypoints,
        &[],
        &caller_address,
    );

    // ---------------- GET NAME ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        6,
        &native_entrypoints,
        &casm_entrypoints,
        &[],
        &caller_address,
    );

    // // ---------------- GET SYMBOL ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        7,
        &native_entrypoints,
        &casm_entrypoints,
        &[],
        &caller_address,
    );

    // ---------------- GET BALANCE OF CALLER ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        8,
        &native_entrypoints,
        &casm_entrypoints,
        &[caller_address.0.clone()],
        &caller_address,
    );

    // // ---------------- ALLOWANCE OF ADDRESS 1 ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        3,
        &native_entrypoints,
        &casm_entrypoints,
        &[caller_address.0.clone(), 1.into()],
        &caller_address,
    );

    // // ---------------- INCREASE ALLOWANCE OF ADDRESS 1 by 10_000 ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        2,
        &native_entrypoints,
        &casm_entrypoints,
        &[1.into(), 10_000.into()],
        &caller_address,
    );

    // ---------------- ALLOWANCE OF ADDRESS 1 ----------------------

    // Checking again because allowance changed with previous call.
    compare_results(
        &mut state_vm,
        &mut state_native,
        3,
        &native_entrypoints,
        &casm_entrypoints,
        &[caller_address.0.clone(), 1.into()],
        &caller_address,
    );

    // ---------------- APPROVE ADDRESS 1 TO MAKE TRANSFERS ON BEHALF OF THE CALLER ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        4,
        &native_entrypoints,
        &casm_entrypoints,
        &[1.into(), 5000.into()],
        &caller_address,
    );

    // ---------------- TRANSFER 3 TOKENS FROM CALLER TO ADDRESS 2 ---------

    compare_results(
        &mut state_vm,
        &mut state_native,
        0,
        &native_entrypoints,
        &casm_entrypoints,
        &[2.into(), 3.into()],
        &caller_address,
    );

    // // ---------------- GET BALANCE OF CALLER ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        8,
        &native_entrypoints,
        &casm_entrypoints,
        &[caller_address.0.clone()],
        &caller_address,
    );

    // // ---------------- GET BALANCE OF ADDRESS 2 ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        8,
        &native_entrypoints,
        &casm_entrypoints,
        &[2.into()],
        &caller_address,
    );

    // // ---------------- TRANSFER 1 TOKEN FROM CALLER TO ADDRESS 2, CALLED FROM ADDRESS 1 ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        9,
        &native_entrypoints,
        &casm_entrypoints,
        &[1.into(), 2.into(), 1.into()],
        &caller_address,
    );

    // // ---------------- GET BALANCE OF ADDRESS 2 ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        8,
        &native_entrypoints,
        &casm_entrypoints,
        &[2.into()],
        &caller_address,
    );

    // // ---------------- GET BALANCE OF CALLER ----------------------

    compare_results(
        &mut state_vm,
        &mut state_native,
        8,
        &native_entrypoints,
        &casm_entrypoints,
        &[caller_address.0.clone()],
        &caller_address,
    );
}

#[test]
fn call_contract_test() {
    // Caller contract
    let caller_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/caller.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Callee contract
    let callee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/callee.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Caller contract entrypoints
    let caller_entrypoints = caller_contract_class.clone().entry_points_by_type;
    let call_contract_selector = &caller_entrypoints.external.get(0).unwrap().selector;

    // Callee contract entrypoints
    let callee_entrypoints = callee_contract_class.clone().entry_points_by_type;
    let fn_selector = &callee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    contract_class_cache.insert(
        caller_class_hash,
        CompiledClass::Sierra(Arc::new(caller_contract_class)),
    );
    contract_class_cache.insert(
        callee_class_hash,
        CompiledClass::Sierra(Arc::new(callee_contract_class)),
    );

    let mut state_reader = InMemoryStateReader::default();

    // Insert caller contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), caller_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), caller_nonce);

    // Insert callee contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(callee_address.clone(), callee_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(callee_address.clone(), callee_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [fn_selector.into()].to_vec();
    let result = execute(
        &mut state,
        &caller_address,
        &callee_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
        &caller_class_hash,
    );

    assert_eq!(result.retdata, [Felt252::new(44)]);
}

#[test]
fn call_echo_contract_test() {
    // Caller contract
    let caller_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/echo_caller.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Callee contract
    let callee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/echo.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Caller contract entrypoints
    let caller_entrypoints = caller_contract_class.clone().entry_points_by_type;
    let call_contract_selector = &caller_entrypoints.external.get(0).unwrap().selector;

    // Callee contract entrypoints
    let callee_entrypoints = callee_contract_class.clone().entry_points_by_type;
    let fn_selector = &callee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    contract_class_cache.insert(
        caller_class_hash,
        CompiledClass::Sierra(Arc::new(caller_contract_class)),
    );

    contract_class_cache.insert(
        callee_class_hash,
        CompiledClass::Sierra(Arc::new(callee_contract_class)),
    );

    let mut state_reader = InMemoryStateReader::default();

    // Insert caller contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), caller_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), caller_nonce);

    // Insert callee contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(callee_address.clone(), callee_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(callee_address.clone(), callee_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [fn_selector.into(), 99999999.into()].to_vec();
    let result = execute(
        &mut state,
        &caller_address,
        &callee_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
        &caller_class_hash,
    );

    assert_eq!(result.retdata, [Felt252::new(99999999)]);
}

#[test]
#[cfg(feature = "cairo-native")]
fn call_events_contract_test() {
    // Caller contract
    let caller_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/caller.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Callee contract
    let callee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/event_emitter.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Caller contract entrypoints
    let caller_entrypoints = caller_contract_class.clone().entry_points_by_type;
    let call_contract_selector = &caller_entrypoints.external.get(0).unwrap().selector;

    // Event emmitter contract entrypoints
    let callee_entrypoints = callee_contract_class.clone().entry_points_by_type;
    let fn_selector = &callee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    // Caller contract data
    let caller_address = Address(1111.into());
    let caller_class_hash: ClassHash = [1; 32];
    let caller_nonce = Felt252::zero();

    // Callee contract data
    let callee_address = Address(1112.into());
    let callee_class_hash: ClassHash = [2; 32];
    let callee_nonce = Felt252::zero();

    contract_class_cache.insert(
        caller_class_hash,
        CompiledClass::Sierra(Arc::new(caller_contract_class)),
    );

    contract_class_cache.insert(
        callee_class_hash,
        CompiledClass::Sierra(Arc::new(callee_contract_class)),
    );

    let mut state_reader = InMemoryStateReader::default();

    // Insert caller contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), caller_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), caller_nonce);

    // Insert callee contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(callee_address.clone(), callee_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(callee_address.clone(), callee_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [fn_selector.into()].to_vec();
    let result = execute(
        &mut state,
        &caller_address,
        &callee_address,
        call_contract_selector,
        &calldata,
        EntryPointType::External,
        &caller_class_hash,
    );

    let internal_call = CallInfo {
        caller_address: Address(1111.into()),
        call_type: Some(Call),
        contract_address: Address(1112.into()),
        code_address: None,
        class_hash: Some([
            2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
            2, 2, 2,
        ]),
        entry_point_selector: Some(fn_selector.into()),
        entry_point_type: Some(External),
        calldata: Vec::new(),
        retdata: vec![1234.into()],
        execution_resources: None,
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![110.into()],
            data: vec![1.into()],
        }],
        l2_to_l1_messages: Vec::new(),
        storage_read_values: Vec::new(),
        accessed_storage_keys: HashSet::new(),
        internal_calls: Vec::new(),
        gas_consumed: 340282366920938463463374607431768211455, // TODO: fix gas consumed
        failure_flag: false,
    };

    let event = Event {
        from_address: Address(1112.into()),
        keys: vec![110.into()],
        data: vec![1.into()],
    };

    assert_eq!(result.retdata, [1234.into()]);
    assert_eq!(result.events, []);
    assert_eq_sorted!(result.internal_calls, [internal_call]);

    let sorted_events = result.get_sorted_events().unwrap();
    assert_eq!(sorted_events, vec![event]);
}

fn execute(
    state: &mut CachedState<InMemoryStateReader>,
    caller_address: &Address,
    callee_address: &Address,
    selector: &BigUint,
    calldata: &[Felt252],
    entrypoint_type: EntryPointType,
    class_hash: &ClassHash,
) -> CallInfo {
    let exec_entry_point = ExecutionEntryPoint::new(
        (*callee_address).clone(),
        calldata.to_vec(),
        Felt252::new(selector),
        (*caller_address).clone(),
        entrypoint_type,
        Some(CallType::Delegate),
        Some(*class_hash),
        u64::MAX.into(), // gas is u64 in cairo-native and sierra
    );

    // Execute the entrypoint
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    exec_entry_point
        .execute(
            state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
        )
        .unwrap()
        .call_info
        .unwrap()
}

fn execute_deploy(
    state: &mut CachedState<InMemoryStateReader>,
    caller_address: &Address,
    selector: &BigUint,
    calldata: &[Felt252],
    entrypoint_type: EntryPointType,
    class_hash: &ClassHash,
) -> CallInfo {
    let exec_entry_point = ExecutionEntryPoint::new(
        (*caller_address).clone(),
        calldata.to_vec(),
        Felt252::new(selector),
        (*caller_address).clone(),
        entrypoint_type,
        Some(CallType::Delegate),
        Some(*class_hash),
        u64::MAX.into(), // gas is u64 in cairo-native and sierra
    );

    // Execute the entrypoint
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    exec_entry_point
        .execute(
            state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
        )
        .unwrap()
        .call_info
        .unwrap()
}

#[test]
#[cfg(feature = "cairo-native")]
fn deploy_syscall_test() {
    // Deployer contract

    use cairo_vm::felt::felt_str;
    let deployer_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/deploy.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Deployee contract
    let deployee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/echo.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // deployer contract entrypoints
    let deployer_entrypoints = deployer_contract_class.clone().entry_points_by_type;
    let deploy_contract_selector = &deployer_entrypoints.external.get(0).unwrap().selector;

    // Echo contract entrypoints
    let deployee_entrypoints = deployee_contract_class.clone().entry_points_by_type;
    let fn_selector = &deployee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    // Deployer contract data
    let deployer_address = Address(1111.into());
    let deployer_class_hash: ClassHash = [1; 32];
    let deployer_nonce = Felt252::zero();

    // Deployee contract data
    let deployee_class_hash: ClassHash = [0; 32];
    let deployee_nonce = Felt252::zero();

    contract_class_cache.insert(
        deployer_class_hash,
        CompiledClass::Sierra(Arc::new(deployer_contract_class)),
    );

    contract_class_cache.insert(
        deployee_class_hash,
        CompiledClass::Sierra(Arc::new(deployee_contract_class)),
    );

    let mut state_reader = InMemoryStateReader::default();

    // Insert deployer contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(deployer_address.clone(), deployer_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(deployer_address.clone(), deployer_nonce);


    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [Felt252::from_bytes_be(&deployee_class_hash), Felt252::one()].to_vec();
    let result = execute_deploy(
        &mut state,
        &deployer_address,
        deploy_contract_selector,
        &calldata,
        EntryPointType::External,
        &deployer_class_hash,
    );
    let expected_deployed_contract_address = Address(
        calculate_contract_address(
            &Felt252::one(),
            &Felt252::from_bytes_be(&deployee_class_hash),
            &vec![100.into()],
            deployer_address,
        ).unwrap()
    );

    assert_eq!(result.retdata, [expected_deployed_contract_address.0]);
    assert_eq!(result.events, []);
    assert!(result.internal_calls.is_empty());

    let sorted_events = result.get_sorted_events().unwrap();
    assert_eq!(sorted_events, vec![]);
    assert_eq!(result.failure_flag, false)
}

#[test]
#[cfg(feature = "cairo-native")]
fn deploy_syscall_address_unavailable_test() {
    // Deployer contract

    use cairo_vm::felt::felt_str;
    use starknet_in_rust::utils::felt_to_hash;
    let deployer_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/deploy.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // Deployee contract
    let deployee_contract_class: cairo_lang_starknet::contract_class::ContractClass =
        serde_json::from_str(
            std::fs::read_to_string("starknet_programs/cairo2/echo.sierra")
                .unwrap()
                .as_str(),
        )
        .unwrap();

    // deployer contract entrypoints
    let deployer_entrypoints = deployer_contract_class.clone().entry_points_by_type;
    let deploy_contract_selector = &deployer_entrypoints.external.get(0).unwrap().selector;

    // Echo contract entrypoints
    let deployee_entrypoints = deployee_contract_class.clone().entry_points_by_type;
    let fn_selector = &deployee_entrypoints.external.get(0).unwrap().selector;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    // Deployer contract data
    let deployer_address = Address(1111.into());
    let deployer_class_hash: ClassHash = [2;32];
    let deployer_nonce = Felt252::zero();

    // Deployee contract data
    let deployee_class_hash: ClassHash = felt_to_hash(&Felt252::one());;
    let deployee_nonce = Felt252::zero();
    let expected_deployed_contract_address = Address(
        calculate_contract_address(
            &Felt252::one(),
            &Felt252::from_bytes_be(&deployee_class_hash),
            &vec![100.into()],
            deployer_address.clone(),
        ).unwrap()
    );
    // Insert contract to be deployed so that its address is taken
    let deployee_address = expected_deployed_contract_address;


    contract_class_cache.insert(
        deployer_class_hash,
        CompiledClass::Sierra(Arc::new(deployer_contract_class)),
    );

    contract_class_cache.insert(
        deployee_class_hash,
        CompiledClass::Sierra(Arc::new(deployee_contract_class)),
    );

    let mut state_reader = InMemoryStateReader::default();

    // Insert deployer contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(deployer_address.clone(), deployer_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(deployer_address.clone(), deployer_nonce);

    // Insert deployee contract info into state reader
    state_reader
        .address_to_class_hash_mut()
        .insert(deployee_address.clone(), deployee_class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(deployee_address.clone(), deployee_nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

    let calldata = [Felt252::from_bytes_be(&deployee_class_hash), Felt252::one()].to_vec();
    let result = execute_deploy(
        &mut state,
        &deployer_address,
        deploy_contract_selector,
        &calldata,
        EntryPointType::External,
        &deployer_class_hash,
    );

    assert_eq!(std::str::from_utf8(&result.retdata[0].to_be_bytes()).unwrap().trim_start_matches('\0'), "Result::unwrap failed.");
    assert_eq!(result.events, []);
    assert!(result.internal_calls.is_empty());
}
