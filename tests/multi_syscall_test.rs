use std::{
    collections::HashMap,
    vec,
};

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::{
    felt::Felt252,
};
use num_bigint::BigUint;
use num_traits::{Num, Zero};
use starknet_contract_class::EntryPointType;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, OrderedEvent,
        TransactionExecutionContext,
    },
    state::{cached_state::CachedState},
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
};


#[test]
fn test_multiple_syscall() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/multi_syscall_test.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;

    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    contract_class_cache.insert(class_hash, contract_class.clone());
    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce.clone());

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(state_reader.clone(), None, Some(contract_class_cache.clone()));

    // Create an execution entry point
    let calldata= [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    // Block for get_caller_address.
    {
        let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
        assert_eq!(call_info.events, vec![])
    }

    // Block for get_contract_address.
    {
        let entrypoint_selector = &entrypoints.external.get(1).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
        assert_eq!(call_info.events, vec![])
       
    }
    
    // Block for get_execution_info_syscall.
    {
        let entrypoint_selector = &entrypoints.external.get(2).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
            assert_eq!(
                call_info.events, vec![]);
       
    }

     // Block for library_call_syscall
     {
         let entrypoint_selector = &entrypoints.external.get(3).unwrap().selector;
         let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
         assert_eq!(call_info.events, vec![])
     }

     // Block for call_contract_syscall
     {
        let entrypoint_selector = &entrypoints.external.get(4).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
        assert_eq!(call_info.events, vec![])
    }

    // Block for send_message_to_l1_syscall
    {
        let entrypoint_selector = &entrypoints.external.get(5).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
        assert_eq!(call_info.events, vec![])
    }

    // Block for replace_class_syscall
    {
        let entrypoint_selector = &entrypoints.external.get(6).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
        assert_eq!(call_info.events, vec![])
    }

    // Block for read write
    {
        let entrypoint_selector = &entrypoints.external.get(7).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
        assert_eq!(call_info.events, vec![])
    }

    // Block for emit
    {
        let entrypoint_selector = &entrypoints.external.get(8).unwrap().selector;
        let call_info = test_syscall(entrypoint_selector,
            address.clone(), calldata.clone(),  caller_address.clone(), entry_point_type, class_hash, &mut state);
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

    // Block for deploy syscall
    {
        // data to deploy
        let test_class_hash: ClassHash = [2; 32];
        // let test_felt_hash = Felt252::from_bytes_be(&test_class_hash);
        // let salt = Felt252::zero();
        let test_data = include_bytes!("../starknet_programs/cairo1/contract_a.casm");
        let test_contract_class: CasmContractClass = serde_json::from_slice(test_data).unwrap();

        // Create the deploy contract class
        let _entrypoint_selector = &entrypoints.external.get(9).unwrap().selector;

        contract_class_cache.insert(class_hash, contract_class);
        contract_class_cache.insert(test_class_hash, test_contract_class.clone());
       
        // Create state from the state_reader and contract cache.
        let _state = CachedState::new(state_reader, None, Some(contract_class_cache));
 
    }
}

fn test_syscall(entrypoint_selector: &BigUint, address: Address, calldata: Vec<Felt252>, caller_address:Address, 
    entry_point_type: EntryPointType,class_hash: [u8; 32], state: &mut CachedState<InMemoryStateReader>)-> CallInfo {
    let exec_entry_point = ExecutionEntryPoint::new(
        address.clone(),
        calldata.clone(),
        Felt252::new(entrypoint_selector.clone()),
        caller_address.clone(),
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100000,
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
    let call_info = exec_entry_point
    .execute(
        state,
        &block_context,
        &mut resources_manager,
        &mut tx_execution_context,
        false,
    )
    .unwrap();
    call_info
}