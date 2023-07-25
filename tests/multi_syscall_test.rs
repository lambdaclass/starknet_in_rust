use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::felt::Felt252;
use num_traits::{Num, Zero};
use starknet_in_rust::utils::calculate_sn_keccak;
use starknet_in_rust::EntryPointType;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, OrderedEvent,
        TransactionExecutionContext,
    },
    state::cached_state::CachedState,
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
};
use std::{collections::HashMap, sync::Arc, vec};

#[test]
fn test_multiple_syscall() {
    //  Create program and entry point types for contract class
    let program_data = include_bytes!("../starknet_programs/cairo1/multi_syscall_test.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    // Create state reader with class hash data
    let mut contract_class_cache: HashMap<[u8; 32], _> = HashMap::new();

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
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        Arc::new(state_reader),
        None,
        Some(contract_class_cache.clone()),
    );

    // Create an execution entry point
    let calldata = [].to_vec();
    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    // Block for get_caller_address.
    {
        let call_info = test_syscall(
            "caller_address",
            address.clone(),
            calldata.clone(),
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.retdata, vec![caller_address.clone().0])
    }

    // Block for get_contact_address.
    {
        let call_info = test_syscall(
            "contract_address",
            address.clone(),
            calldata.clone(),
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.events, vec![])
    }
    // Block for get_execution_info_syscall.
    {
        let call_info = test_syscall(
            "execution_info_syscall",
            address.clone(),
            calldata.clone(),
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.events, vec![]);
    }

    // Block for library_call_syscall
    {
        let call_info = test_syscall(
            "replace_class_syscall_test",
            address.clone(),
            calldata.clone(),
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.events, vec![])
    }

    // Block for call_contract_syscall
    {
        let entrypoint_selector =
            Felt252::from_bytes_be(&calculate_sn_keccak("get_number".as_bytes()));
        let new_call_data = vec![
            Felt252::from_bytes_be(&class_hash),
            entrypoint_selector,
            Felt252::from(25),
        ];
        let call_info = test_syscall(
            "test_library_call_syscall_test",
            address.clone(),
            new_call_data,
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.retdata, vec![25.into()])
    }

    // Block for replace_class_syscall
    {
        let entrypoint_selector =
            Felt252::from_bytes_be(&calculate_sn_keccak("get_number".as_bytes()));
        let new_call_data = vec![entrypoint_selector, Felt252::from(25)];
        let call_info = test_syscall(
            "test_call_contract_syscall",
            address.clone(),
            new_call_data,
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.retdata, vec![25.into()])
    }

    // Block for send_message_to_l1_syscall
    {
        let new_call_data = vec![2222.into(), Felt252::from(25), Felt252::from(30)];
        let call_info = test_syscall(
            "test_send_message_to_l1",
            address.clone(),
            new_call_data,
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.events, vec![])
    }

    // Block for read write
    {
        let call_info = test_syscall(
            "read",
            address.clone(),
            calldata.clone(),
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.events, vec![])
    }

    // Block for emit
    {
        let call_info = test_syscall(
            "trigger_events",
            address.clone(),
            calldata.clone(),
            caller_address.clone(),
            entry_point_type,
            class_hash,
            &mut state,
        );
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
        let test_data = include_bytes!("../starknet_programs/cairo1/contract_a.casm");
        let test_contract_class: CasmContractClass = serde_json::from_slice(test_data).unwrap();

        // Create the deploy contract class
        contract_class_cache.insert(class_hash, contract_class);
        contract_class_cache.insert(test_class_hash, test_contract_class);
        let call_info = test_syscall(
            "deploy_test",
            address,
            calldata,
            caller_address,
            entry_point_type,
            class_hash,
            &mut state,
        );
        assert_eq!(call_info.events, vec![])
    }
}

fn test_syscall(
    entrypoint_selector: &str,
    address: Address,
    calldata: Vec<Felt252>,
    caller_address: Address,
    entry_point_type: EntryPointType,
    class_hash: [u8; 32],
    state: &mut CachedState<InMemoryStateReader>,
) -> CallInfo {
    let entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(entrypoint_selector.as_bytes()));
    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector),
        caller_address,
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
