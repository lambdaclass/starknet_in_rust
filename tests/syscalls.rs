#![deny(warnings)]

use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::{
    felt::{felt_str, Felt252},
    vm::runners::cairo_runner::ExecutionResources,
};
use num_traits::{Num, One, Zero};
use starknet_contract_class::EntryPointType;
use starknet_rs::{
    definitions::{
        block_context::{BlockContext, StarknetChainId},
        constants::{CONSTRUCTOR_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION},
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, OrderedEvent,
        OrderedL2ToL1Message, TransactionExecutionContext,
    },
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::{State, StateReader},
    },
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{calculate_sn_keccak, Address, ClassHash},
};
use std::{
    collections::{HashMap, HashSet},
    iter::empty,
    path::Path,
};

#[allow(clippy::too_many_arguments)]
fn test_contract<'a>(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    class_hash: ClassHash,
    contract_address: Address,
    caller_address: Address,
    block_context: BlockContext,
    tx_execution_context_option: Option<TransactionExecutionContext>,
    events: impl Into<Vec<OrderedEvent>>,
    l2_to_l1_messages: impl Into<Vec<OrderedL2ToL1Message>>,
    storage_read_values: impl Into<Vec<Felt252>>,
    accessed_storage_keys: impl Iterator<Item = ClassHash>,
    extra_contracts: impl Iterator<
        Item = (
            ClassHash,
            &'a Path,
            Option<(Address, Vec<(&'a str, Felt252)>)>,
        ),
    >,
    arguments: impl Into<Vec<Felt252>>,
    internal_calls: impl Into<Vec<CallInfo>>,
    return_data: impl Into<Vec<Felt252>>,
    execution_resources: ExecutionResources,
) {
    let contract_class = ContractClass::try_from(contract_path.as_ref().to_path_buf())
        .expect("Could not load contract from JSON");

    let mut tx_execution_context = tx_execution_context_option.unwrap_or_else(|| {
        TransactionExecutionContext::create_for_testing(
            Address(0.into()),
            10,
            0.into(),
            block_context.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION.clone(),
        )
    });

    let nonce = tx_execution_context.nonce().clone();

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(contract_address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(contract_address.clone(), nonce);
    state_reader
        .class_hash_to_contract_class_mut()
        .insert(class_hash, contract_class);

    let mut storage_entries = Vec::new();
    let contract_class_cache = {
        let mut contract_class_cache = ContractClassCache::new();

        for (class_hash, contract_path, contract_address) in extra_contracts {
            let contract_class = ContractClass::try_from(contract_path.to_path_buf())
                .expect("Could not load extra contract from JSON");

            contract_class_cache.insert(class_hash, contract_class.clone());

            if let Some((contract_address, data)) = contract_address {
                storage_entries.extend(data.into_iter().map(|(name, value)| {
                    (
                        contract_address.clone(),
                        calculate_sn_keccak(name.as_bytes()),
                        value,
                    )
                }));

                state_reader
                    .address_to_class_hash_mut()
                    .insert(contract_address.clone(), class_hash);
                state_reader
                    .class_hash_to_contract_class_mut()
                    .insert(class_hash, contract_class.clone());
            }
        }

        Some(contract_class_cache)
    };
    let mut state = CachedState::new(state_reader, contract_class_cache, None);
    storage_entries
        .into_iter()
        .for_each(|(a, b, c)| state.set_storage_at(&(a, b), c));

    let calldata = arguments.into();

    let entry_point_selector = Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));
    let entry_point = ExecutionEntryPoint::new(
        contract_address.clone(),
        calldata.clone(),
        entry_point_selector.clone(),
        caller_address.clone(),
        EntryPointType::External,
        CallType::Delegate.into(),
        Some(class_hash),
        0,
    );

    let mut resources_manager = ExecutionResourcesManager::default();

    assert_eq!(
        entry_point
            .execute(
                &mut state,
                &block_context,
                &mut resources_manager,
                &mut tx_execution_context,
                false,
            )
            .expect("Could not execute contract"),
        CallInfo {
            contract_address,
            caller_address,
            entry_point_type: EntryPointType::External.into(),
            call_type: CallType::Delegate.into(),
            class_hash: class_hash.into(),
            entry_point_selector: Some(entry_point_selector),
            events: events.into(),
            l2_to_l1_messages: l2_to_l1_messages.into(),
            storage_read_values: storage_read_values.into(),
            accessed_storage_keys: accessed_storage_keys.collect(),
            calldata,
            retdata: return_data.into(),
            internal_calls: internal_calls.into(),
            execution_resources,
            ..Default::default()
        },
    );
}

#[test]
fn call_contract_syscall() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_call_contract",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [],
        [10.into()],
        [calculate_sn_keccak("lib_state".as_bytes())].into_iter(),
        [(
            [2u8; 32],
            Path::new("starknet_programs/syscalls-lib.json"),
            Some((Address(2222.into()), vec![("lib_state", 10.into())])),
        )]
        .into_iter(),
        [2222.into()],
        [
            CallInfo {
                caller_address: Address(1111.into()),
                call_type: Some(CallType::Call),
                contract_address: Address(2222.into()),
                class_hash: Some([2; 32]),
                entry_point_selector: Some(felt_str!(
                    "546798550696557601108301130560784308389743068254417260590354407164968886745"
                )),
                entry_point_type: Some(EntryPointType::External),
                calldata: vec![21.into(), 2.into()],
                retdata: vec![42.into()],
                execution_resources: ExecutionResources {
                    n_steps: 24,
                    ..Default::default()
                },
                ..Default::default()
            },
            CallInfo {
                caller_address: Address(1111.into()),
                call_type: Some(CallType::Call),
                contract_address: Address(2222.into()),
                class_hash: Some([2; 32]),
                entry_point_selector: Some(felt_str!(
                    "1785358123477195475640323002883645042461033713657726545236059599395452130340"
                )),
                entry_point_type: Some(EntryPointType::External),
                storage_read_values: vec![10.into()],
                accessed_storage_keys: [[
                    3, 189, 169, 58, 108, 116, 165, 116, 249, 48, 17, 133, 28, 149, 186, 141, 157,
                    76, 34, 41, 77, 210, 154, 246, 164, 151, 207, 138, 139, 182, 155, 161,
                ]]
                .into_iter()
                .collect(),
                execution_resources: ExecutionResources {
                    n_steps: 63,
                    ..Default::default()
                },
                ..Default::default()
            },
            CallInfo {
                caller_address: Address(1111.into()),
                call_type: Some(CallType::Call),
                contract_address: Address(2222.into()),
                class_hash: Some([2; 32]),
                entry_point_selector: Some(felt_str!(
                    "112922190346416634085028859628276991723232552244844834791336220661833684932"
                )),
                entry_point_type: Some(EntryPointType::External),
                calldata: vec![],
                retdata: vec![2222.into()],
                execution_resources: ExecutionResources {
                    n_steps: 26,
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
        [],
        ExecutionResources {
            n_steps: 279,
            ..Default::default()
        },
    );
}

#[test]
fn emit_event_syscall() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_emit_event",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [
            OrderedEvent {
                order: 0,
                keys: vec![Felt252::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [1, 2, 3].map(Felt252::from).to_vec(),
            },
            OrderedEvent {
                order: 1,
                keys: vec![Felt252::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [2, 4, 6].map(Felt252::from).to_vec(),
            },
            OrderedEvent {
                order: 2,
                keys: vec![Felt252::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [1234, 5678, 9012].map(Felt252::from).to_vec(),
            },
            OrderedEvent {
                order: 3,
                keys: vec![Felt252::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [2468].map(Felt252::from).to_vec(),
            },
        ],
        [],
        [],
        empty(),
        empty(),
        [],
        [],
        [],
        ExecutionResources {
            n_steps: 144,
            ..Default::default()
        },
    );
}

#[test]
fn get_block_number_syscall() {
    let run = |block_number| {
        let mut block_context = BlockContext::default();
        block_context.block_info_mut().block_number = block_number;

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_block_number",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            block_context,
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [block_number.into()],
            ExecutionResources {
                n_steps: 26,
                ..Default::default()
            },
        );
    };

    run(0);
    run(5);
    run(1000);
}

#[test]
fn get_block_timestamp_syscall() {
    let run = |block_timestamp| {
        let mut block_context = BlockContext::default();
        block_context.block_info_mut().block_timestamp = block_timestamp;

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_block_timestamp",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            block_context,
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [block_timestamp.into()],
            ExecutionResources {
                n_steps: 26,
                ..Default::default()
            },
        );
    };

    run(0);
    run(5);
    run(1000);
}

#[test]
fn get_caller_address_syscall() {
    let run = |caller_address: Felt252| {
        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_caller_address",
            [1; 32],
            Address(1111.into()),
            Address(caller_address.clone()),
            BlockContext::default(),
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [caller_address],
            ExecutionResources {
                n_steps: 26,
                ..Default::default()
            },
        );
    };

    run(0.into());
    run(5.into());
    run(1000.into());
}

#[test]
fn get_contract_address_syscall() {
    let run = |contract_address: Felt252| {
        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_contract_address",
            [1; 32],
            Address(contract_address.clone()),
            Address(0.into()),
            BlockContext::default(),
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [contract_address],
            ExecutionResources {
                n_steps: 26,
                ..Default::default()
            },
        );
    };

    run(1.into());
    run(5.into());
    run(1000.into());
}

#[test]
fn get_sequencer_address_syscall() {
    let run = |sequencer_address: Felt252| {
        let mut block_context = BlockContext::default();
        block_context.block_info_mut().sequencer_address = Address(sequencer_address.clone());

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_sequencer_address",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            block_context,
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [sequencer_address],
            ExecutionResources {
                n_steps: 26,
                ..Default::default()
            },
        );
    };

    run(0.into());
    run(5.into());
    run(1000.into());
}

#[test]
fn get_tx_info_syscall() {
    let run = |version: Felt252,
               account_contract_address: Address,
               max_fee,
               signature: Vec<Felt252>,
               transaction_hash: Felt252,
               chain_id,
               execution_resources: ExecutionResources| {
        let mut block_context = BlockContext::default();
        *block_context.starknet_os_config_mut().chain_id_mut() = chain_id;

        let n_steps = block_context.invoke_tx_max_n_steps();
        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_tx_info",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            block_context,
            Some(TransactionExecutionContext::new(
                account_contract_address.clone(),
                transaction_hash.clone(),
                signature.clone(),
                max_fee,
                3.into(),
                n_steps,
                version.clone(),
            )),
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [
                version,
                account_contract_address.0,
                max_fee.into(),
                signature.len().into(),
                signature
                    .into_iter()
                    .reduce(|a, b| a + b)
                    .unwrap_or_default(),
                transaction_hash,
                chain_id.to_felt(),
            ],
            execution_resources,
        );
    };

    run(
        0.into(),
        Address::default(),
        12,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
        ExecutionResources {
            n_steps: 49,
            ..Default::default()
        },
    );
    run(
        10.into(),
        Address::default(),
        12,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
        ExecutionResources {
            n_steps: 49,
            ..Default::default()
        },
    );
    run(
        10.into(),
        Address(1111.into()),
        12,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
        ExecutionResources {
            n_steps: 49,
            ..Default::default()
        },
    );
    run(
        10.into(),
        Address(1111.into()),
        50,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
        ExecutionResources {
            n_steps: 49,
            ..Default::default()
        },
    );
    run(
        10.into(),
        Address(1111.into()),
        50,
        [0x12, 0x34, 0x56, 0x78].map(Felt252::from).to_vec(),
        0.into(),
        StarknetChainId::TestNet,
        ExecutionResources {
            n_steps: 77,
            ..Default::default()
        },
    );
    run(
        10.into(),
        Address(1111.into()),
        50,
        [0x12, 0x34, 0x56, 0x78].map(Felt252::from).to_vec(),
        12345678.into(),
        StarknetChainId::TestNet,
        ExecutionResources {
            n_steps: 77,
            ..Default::default()
        },
    );
    run(
        10.into(),
        Address(1111.into()),
        50,
        [0x12, 0x34, 0x56, 0x78].map(Felt252::from).to_vec(),
        12345678.into(),
        StarknetChainId::TestNet2,
        ExecutionResources {
            n_steps: 77,
            ..Default::default()
        },
    );
}

#[test]
fn get_tx_signature_syscall() {
    let run = |signature: Vec<Felt252>| {
        let block_context = BlockContext::default();
        let n_steps = block_context.invoke_tx_max_n_steps();
        let resources_n_steps = if signature.is_empty() { 41 } else { 69 };

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_tx_signature",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            block_context,
            Some(TransactionExecutionContext::new(
                Address::default(),
                0.into(),
                signature.clone(),
                12,
                3.into(),
                n_steps,
                0.into(),
            )),
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [
                signature.len().into(),
                signature
                    .into_iter()
                    .reduce(|a, b| a + b)
                    .unwrap_or_default(),
            ],
            ExecutionResources {
                n_steps: resources_n_steps,
                ..Default::default()
            },
        );
    };

    run(vec![]);
    run([0x12, 0x34, 0x56, 0x78].map(Felt252::from).to_vec());
    run([0x9A, 0xBC, 0xDE, 0xF0].map(Felt252::from).to_vec());
}

#[test]
fn library_call_syscall() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_library_call",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [],
        [11.into()],
        [calculate_sn_keccak("lib_state".as_bytes())].into_iter(),
        [(
            [2; 32],
            Path::new("starknet_programs/syscalls-lib.json"),
            Default::default(),
        )]
        .into_iter(),
        [],
        [
            CallInfo {
                caller_address: Address(0.into()),
                call_type: Some(CallType::Delegate),
                contract_address: Address(1111.into()),
                class_hash: Some([2; 32]),
                entry_point_selector: Some(felt_str!(
                    "546798550696557601108301130560784308389743068254417260590354407164968886745"
                )),
                entry_point_type: Some(EntryPointType::External),
                calldata: vec![21.into(), 2.into()],
                retdata: vec![42.into()],
                execution_resources: ExecutionResources {
                    n_steps: 24,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::default(),
                },
                ..Default::default()
            },
            CallInfo {
                caller_address: Address(0.into()),
                call_type: Some(CallType::Delegate),
                contract_address: Address(1111.into()),
                class_hash: Some([2; 32]),
                entry_point_selector: Some(felt_str!(
                    "1785358123477195475640323002883645042461033713657726545236059599395452130340"
                )),
                entry_point_type: Some(EntryPointType::External),
                storage_read_values: vec![10.into()],
                accessed_storage_keys: [[
                    3, 189, 169, 58, 108, 116, 165, 116, 249, 48, 17, 133, 28, 149, 186, 141, 157,
                    76, 34, 41, 77, 210, 154, 246, 164, 151, 207, 138, 139, 182, 155, 161,
                ]]
                .into_iter()
                .collect(),
                execution_resources: ExecutionResources {
                    n_steps: 63,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::default(),
                },
                ..Default::default()
            },
            CallInfo {
                caller_address: Address(0.into()),
                call_type: Some(CallType::Delegate),
                contract_address: Address(1111.into()),
                class_hash: Some([2; 32]),
                entry_point_selector: Some(felt_str!(
                    "112922190346416634085028859628276991723232552244844834791336220661833684932"
                )),
                entry_point_type: Some(EntryPointType::External),
                calldata: vec![],
                retdata: vec![1111.into()],
                execution_resources: ExecutionResources {
                    n_steps: 26,
                    n_memory_holes: 0,
                    builtin_instance_counter: HashMap::default(),
                },
                ..Default::default()
            },
        ],
        [],
        ExecutionResources {
            n_steps: 284,
            ..Default::default()
        },
    );
}

#[test]
fn library_call_l1_handler_syscall() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_library_call_l1_handler",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [],
        [5.into()],
        [calculate_sn_keccak("lib_state".as_bytes())].into_iter(),
        [(
            [2; 32],
            Path::new("starknet_programs/syscalls-lib.json"),
            Default::default(),
        )]
        .into_iter(),
        [],
        [CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Delegate),
            contract_address: Address(1111.into()),
            class_hash: Some([2; 32]),
            entry_point_selector: Some(felt_str!(
                "656009366490248190408749506916536936590180267800242448338092634532990158199"
            )),
            entry_point_type: Some(EntryPointType::L1Handler),
            calldata: vec![5.into()],
            accessed_storage_keys: [[
                3, 189, 169, 58, 108, 116, 165, 116, 249, 48, 17, 133, 28, 149, 186, 141, 157, 76,
                34, 41, 77, 210, 154, 246, 164, 151, 207, 138, 139, 182, 155, 161,
            ]]
            .into_iter()
            .collect(),
            execution_resources: ExecutionResources {
                n_steps: 40,
                ..Default::default()
            },
            ..Default::default()
        }],
        [],
        ExecutionResources {
            n_steps: 103,
            ..Default::default()
        },
    );
}

#[test]
fn send_message_to_l1_syscall() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_send_message_to_l1",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [
            OrderedL2ToL1Message {
                order: 0,
                to_address: Address(1111.into()),
                payload: [1, 2, 3].map(Felt252::from).to_vec(),
            },
            OrderedL2ToL1Message {
                order: 1,
                to_address: Address(1111.into()),
                payload: [2, 4].map(Felt252::from).to_vec(),
            },
            OrderedL2ToL1Message {
                order: 2,
                to_address: Address(1111.into()),
                payload: [3].map(Felt252::from).to_vec(),
            },
        ],
        [],
        empty(),
        empty(),
        [],
        [],
        [],
        ExecutionResources {
            n_steps: 68,
            ..Default::default()
        },
    );
}

#[test]
fn deploy_syscall() {
    let deploy_address =
        felt_str!("2771739216117269195266211756239816992170608283088994568066688164855938378843");

    let deploy_class_hash = [2u8; 32];
    test_contract(
        "starknet_programs/syscalls.json",
        "test_deploy",
        [1; 32],
        Address(11111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [],
        [],
        [].into_iter(),
        [(
            deploy_class_hash,
            Path::new("starknet_programs/storage.json"),
            None,
        )]
        .into_iter(),
        [Felt252::from_bytes_be(deploy_class_hash.as_ref()), 0.into()],
        vec![CallInfo {
            caller_address: Address(0.into()),
            contract_address: Address(deploy_address.clone()),
            entry_point_type: Some(EntryPointType::Constructor),
            entry_point_selector: Some(CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone()),
            call_type: Some(CallType::Call),
            class_hash: Some(deploy_class_hash),
            ..Default::default()
        }],
        [deploy_address],
        ExecutionResources {
            n_steps: 39,
            n_memory_holes: 2,
            ..Default::default()
        },
    );
}

#[test]
fn deploy_with_constructor_syscall() {
    let deploy_address = Felt252::from_str_radix(
        "61956907203782517318335437536462535199340115817938156158070235163997828534",
        10,
    )
    .unwrap();

    let deploy_class_hash = [2u8; 32];
    test_contract(
        "starknet_programs/syscalls.json",
        "test_deploy_with_constructor",
        [1; 32],
        Address(11111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [],
        [],
        [].into_iter(),
        [(
            deploy_class_hash,
            Path::new("starknet_programs/storage_var_and_constructor.json"),
            None,
        )]
        .into_iter(),
        [
            Felt252::from_bytes_be(deploy_class_hash.as_ref()),
            0.into(),
            550.into(),
        ],
        [],
        [deploy_address],
        ExecutionResources {
            n_steps: 84,
            n_memory_holes: 2,
            ..Default::default()
        },
    );
}

#[test]
fn test_deploy_and_call_contract_syscall() {
    let constructor_constant = Felt252::new(550);
    let new_constant = Felt252::new(3);
    let constant_storage_key: ClassHash = [
        2, 63, 76, 85, 114, 157, 43, 172, 36, 175, 107, 126, 158, 121, 114, 77, 194, 27, 162, 147,
        169, 199, 107, 53, 94, 246, 206, 221, 169, 114, 215, 255,
    ];
    let deploy_class_hash = [2u8; 32];
    let deploy_address = Address(
        Felt252::from_str_radix(
            "61956907203782517318335437536462535199340115817938156158070235163997828534",
            10,
        )
        .unwrap(),
    );
    test_contract(
        "starknet_programs/syscalls.json",
        "test_deploy_and_call_contract",
        [1; 32],
        Address(11111.into()),
        Address(0.into()),
        BlockContext::default(),
        None,
        [],
        [],
        [],
        [].into_iter(),
        [(
            deploy_class_hash,
            Path::new("starknet_programs/storage_var_and_constructor.json"),
            None,
        )]
        .into_iter(),
        [
            Felt252::from_bytes_be(deploy_class_hash.as_ref()),
            0.into(),
            constructor_constant.clone(),
            new_constant.clone(),
        ],
        [
        // Invoke storage_var_and_constructor.cairo mult_constant function
        CallInfo {
            caller_address: Address(11111.into()),
            call_type: Some(CallType::Call),
            contract_address: deploy_address.clone(),
            code_address: None,
            class_hash: Some(deploy_class_hash),
            entry_point_selector: Some(
                Felt252::from_str_radix(
                    "1576037374104670872807053137865113122553607263175471701007015754752102201893",
                    10,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![4.into()],
            retdata: vec![(constructor_constant.clone() * Felt252::new(4))],
            storage_read_values: vec![constructor_constant],
            accessed_storage_keys: HashSet::from([constant_storage_key]),
            execution_resources: ExecutionResources {
                n_steps: 52,
                ..Default::default()
            },
            ..Default::default()
        },
        // Invoke storage_var_and_constructor.cairo set_constant function
        CallInfo {
            caller_address: Address(11111.into()),
            call_type: Some(CallType::Call),
            contract_address: deploy_address.clone(),
            code_address: None,
            class_hash: Some(deploy_class_hash),
            entry_point_selector: Some(
                Felt252::from_str_radix(
                    "1201037417712951658445715615949920673423990292207294106968654696818998525373",
                    10,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![new_constant.clone()],
            retdata: vec![],
            storage_read_values: vec![],
            accessed_storage_keys: HashSet::from([constant_storage_key]),
            execution_resources: ExecutionResources {
                n_steps: 40,
                ..Default::default()
            },
            ..Default::default()
        },
        // Invoke storage_var_and_constructor.cairo get_constant function
        CallInfo {
            caller_address: Address(11111.into()),
            call_type: Some(CallType::Call),
            contract_address: deploy_address,
            code_address: None,
            class_hash: Some(deploy_class_hash),
            entry_point_selector: Some(
                Felt252::from_str_radix(
                    "915547745133109687566886827729966789818200062539892992518817034473866315209",
                    10,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![],
            retdata: vec![new_constant.clone()],
            storage_read_values: vec![new_constant.clone()],
            accessed_storage_keys: HashSet::from([constant_storage_key]),
            execution_resources: ExecutionResources {
                n_steps: 46,
                ..Default::default()
            },
            ..Default::default()
        }        ],
        [new_constant],
        ExecutionResources {
            n_steps: 325,
            n_memory_holes: 2,
            builtin_instance_counter: HashMap::default()},
    );
}

#[test]
fn deploy_cairo1_from_cairo0_with_constructor() {
    // Create the deploy contract class
    let contract_path = Path::new("starknet_programs/syscalls.json");
    let contract_class: ContractClass =
        ContractClass::try_from(contract_path.to_path_buf()).unwrap();
    let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(
        "test_deploy_with_constructor".as_bytes(),
    ));

    // Create the deploy test data
    let salt = Felt252::zero();
    let test_class_hash: ClassHash = [2; 32];
    let test_felt_hash = Felt252::from_bytes_be(&test_class_hash);
    let program_data = include_bytes!("../starknet_programs/cairo1/contract_a.casm");
    let test_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    // Create state reader with class hash data
    let mut casm_contract_class_cache = HashMap::new();
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    // simulate contract declare
    casm_contract_class_cache.insert(test_class_hash, test_contract_class.clone());
    contract_class_cache.insert(class_hash, contract_class);

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_contract_class_cache),
    );

    // arguments of deploy contract
    let calldata: Vec<_> = [test_felt_hash, salt, Felt252::one()].to_vec();

    // set up remaining structures

    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100_000_000,
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

    let call_info = exec_entry_point.execute(
        &mut state,
        &block_context,
        &mut resources_manager,
        &mut tx_execution_context,
        false,
    );

    assert!(call_info.is_ok());

    let ret_address = Address(felt_str!(
        "3454846966442443238250078711203511197245006224544295074402370433368003323361"
    ));

    let ret_class_hash = state.get_class_hash_at(&ret_address).unwrap();
    let ret_casm_class = match state.get_contract_class(&ret_class_hash).unwrap() {
        CompiledClass::Casm(class) => *class,
        CompiledClass::Deprecated(_) => unreachable!(),
    };

    assert_eq!(ret_casm_class, test_contract_class);
}

#[test]
fn deploy_cairo1_from_cairo0_without_constructor() {
    // Create the deploy contract class
    let contract_path = Path::new("starknet_programs/syscalls.json");
    let contract_class: ContractClass =
        ContractClass::try_from(contract_path.to_path_buf()).unwrap();
    let entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak("test_deploy".as_bytes()));

    // Create the deploy test data
    let salt = Felt252::zero();
    let test_class_hash: ClassHash = [2; 32];
    let test_felt_hash = Felt252::from_bytes_be(&test_class_hash);
    let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");
    let test_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    // Create state reader with class hash data
    let mut casm_contract_class_cache = HashMap::new();
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    // simulate contract declare
    casm_contract_class_cache.insert(test_class_hash, test_contract_class.clone());
    contract_class_cache.insert(class_hash, contract_class);

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_contract_class_cache),
    );

    // arguments of deploy contract
    let calldata: Vec<_> = [test_felt_hash, salt].to_vec();

    // set up remaining structures

    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100_000_000,
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

    let _call_info = exec_entry_point
        .execute(
            &mut state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
        )
        .unwrap();

    //assert!(call_info.is_ok());

    let ret_address = Address(felt_str!(
        "2771739216117269195266211756239816992170608283088994568066688164855938378843"
    ));

    let ret_class_hash = state.get_class_hash_at(&ret_address).unwrap();
    let ret_casm_class = match state.get_contract_class(&ret_class_hash).unwrap() {
        CompiledClass::Casm(class) => *class,
        CompiledClass::Deprecated(_) => unreachable!(),
    };

    assert_eq!(ret_casm_class, test_contract_class);
}

#[test]
fn deploy_cairo1_and_invoke() {
    // Create the deploy contract class
    let contract_path = Path::new("starknet_programs/syscalls.json");
    let contract_class: ContractClass =
        ContractClass::try_from(contract_path.to_path_buf()).unwrap();
    let entrypoint_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak("test_deploy".as_bytes()));

    // Create the deploy test data
    let salt = Felt252::zero();
    let test_class_hash: ClassHash = [2; 32];
    let test_felt_hash = Felt252::from_bytes_be(&test_class_hash);
    let program_data = include_bytes!("../starknet_programs/cairo1/factorial.casm");
    let test_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

    // Create state reader with class hash data
    let mut casm_contract_class_cache = HashMap::new();
    let mut contract_class_cache = HashMap::new();

    let address = Address(1111.into());
    let class_hash: ClassHash = [1; 32];
    let nonce = Felt252::zero();

    // simulate contract declare
    casm_contract_class_cache.insert(test_class_hash, test_contract_class.clone());
    contract_class_cache.insert(class_hash, contract_class);

    let mut state_reader = InMemoryStateReader::default();
    state_reader
        .address_to_class_hash_mut()
        .insert(address.clone(), class_hash);
    state_reader
        .address_to_nonce_mut()
        .insert(address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_contract_class_cache),
    );

    // arguments of deploy contract
    let calldata: Vec<_> = [test_felt_hash, salt].to_vec();

    // set up remaining structures

    let caller_address = Address(0000.into());
    let entry_point_type = EntryPointType::External;

    let exec_entry_point = ExecutionEntryPoint::new(
        address,
        calldata,
        Felt252::new(entrypoint_selector),
        caller_address.clone(),
        entry_point_type,
        Some(CallType::Delegate),
        Some(class_hash),
        100_000_000,
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

    let call_info = exec_entry_point.execute(
        &mut state,
        &block_context,
        &mut resources_manager,
        &mut tx_execution_context,
        false,
    );

    assert!(call_info.is_ok());

    let ret_address = Address(felt_str!(
        "2771739216117269195266211756239816992170608283088994568066688164855938378843"
    ));

    let ret_class_hash = state.get_class_hash_at(&ret_address).unwrap();
    let ret_casm_class = match state.get_contract_class(&ret_class_hash).unwrap() {
        CompiledClass::Casm(class) => *class,
        CompiledClass::Deprecated(_) => unreachable!(),
    };

    assert_eq!(ret_casm_class, test_contract_class);

    let calldata = [3.into()].to_vec();
    let entrypoints = test_contract_class.entry_points_by_type;
    let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    let exec_entry_point = ExecutionEntryPoint::new(
        ret_address,
        calldata,
        Felt252::new(entrypoint_selector),
        caller_address,
        entry_point_type,
        Some(CallType::Delegate),
        Some(test_class_hash),
        100_000_000,
    );

    let call_info = exec_entry_point
        .execute(
            &mut state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
        )
        .unwrap();

    let retdata = call_info.retdata;

    // expected result 3! = 6
    assert_eq!(retdata, [6.into()].to_vec());
}
