#![deny(warnings)]

use felt::{felt_str, Felt};
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{
                CallInfo, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
            },
        },
        fact_state::{
            contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            state::ExecutionResourcesManager,
        },
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::State,
        },
    },
    definitions::{
        constants::TRANSACTION_VERSION,
        general_config::{StarknetChainId, StarknetGeneralConfig},
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    starknet_storage::dict_storage::DictStorage,
    utils::{calculate_sn_keccak, Address},
};
use std::{iter::empty, path::Path};

#[allow(clippy::too_many_arguments)]
fn test_contract<'a>(
    contract_path: impl AsRef<Path>,
    entry_point: &str,
    class_hash: [u8; 32],
    contract_address: Address,
    caller_address: Address,
    general_config: StarknetGeneralConfig,
    tx_context: Option<TransactionExecutionContext>,
    events: impl Into<Vec<OrderedEvent>>,
    l2_to_l1_messages: impl Into<Vec<OrderedL2ToL1Message>>,
    storage_read_values: impl Into<Vec<Felt>>,
    accessed_storage_keys: impl Iterator<Item = [u8; 32]>,
    extra_contracts: impl Iterator<Item = ([u8; 32], &'a Path, Option<(Address, Vec<(&'a str, Felt)>)>)>,
    arguments: impl Into<Vec<Felt>>,
    internal_calls: impl Into<Vec<CallInfo>>,
    return_data: impl Into<Vec<Felt>>,
) {
    let contract_class = ContractClass::try_from(contract_path.as_ref().to_path_buf())
        .expect("Could not load contract from JSON");

    let tx_execution_context = tx_context.unwrap_or_else(|| {
        TransactionExecutionContext::create_for_testing(
            Address(0.into()),
            10,
            0.into(),
            general_config.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION,
        )
    });

    let contract_state = ContractState::new(
        class_hash,
        tx_execution_context.nonce().clone(),
        Default::default(),
    );
    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
    state_reader
        .contract_states_mut()
        .insert(contract_address.clone(), contract_state);

    let mut storage_entries = Vec::new();
    let contract_class_cache = {
        let mut contract_class_cache = ContractClassCache::new();
        contract_class_cache.insert(class_hash, contract_class);

        for (class_hash, contract_path, contract_address) in extra_contracts {
            let contract_class = ContractClass::try_from(contract_path.to_path_buf())
                .expect("Could not load extra contract from JSON");

            contract_class_cache.insert(class_hash, contract_class);

            if let Some((contract_address, data)) = contract_address {
                storage_entries.extend(data.into_iter().map(|(name, value)| {
                    (
                        contract_address.clone(),
                        calculate_sn_keccak(name.as_bytes()),
                        value,
                    )
                }));

                state_reader.contract_states_mut().insert(
                    contract_address,
                    ContractState::new(class_hash, Felt::zero(), Default::default()),
                );
            }
        }

        Some(contract_class_cache)
    };
    let mut state = CachedState::new(state_reader, contract_class_cache);
    storage_entries
        .into_iter()
        .for_each(|(a, b, c)| state.set_storage_at(&(a, b), c));

    let calldata = arguments.into();

    let entry_point_selector = Felt::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));
    let entry_point = ExecutionEntryPoint::new(
        contract_address.clone(),
        calldata.clone(),
        entry_point_selector.clone(),
        caller_address.clone(),
        EntryPointType::External,
        CallType::Delegate.into(),
        Some(class_hash),
    );

    let mut resources_manager = ExecutionResourcesManager::default();

    assert_eq!(
        entry_point
            .execute(
                &mut state,
                &general_config,
                &mut resources_manager,
                &tx_execution_context,
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
        StarknetGeneralConfig::default(),
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
                ..Default::default()
            },
        ],
        [],
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
        StarknetGeneralConfig::default(),
        None,
        [
            OrderedEvent {
                order: 0,
                keys: vec![Felt::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [1, 2, 3].map(Felt::from).to_vec(),
            },
            OrderedEvent {
                order: 1,
                keys: vec![Felt::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [2, 4, 6].map(Felt::from).to_vec(),
            },
            OrderedEvent {
                order: 2,
                keys: vec![Felt::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [1234, 5678, 9012].map(Felt::from).to_vec(),
            },
            OrderedEvent {
                order: 3,
                keys: vec![Felt::from_bytes_be(&calculate_sn_keccak(
                    "test_event".as_bytes(),
                ))],
                data: [2468].map(Felt::from).to_vec(),
            },
        ],
        [],
        [],
        empty(),
        empty(),
        [],
        [],
        [],
    );
}

#[test]
fn get_block_number_syscall() {
    let run = |block_number| {
        let mut general_config = StarknetGeneralConfig::default();
        general_config.block_info_mut().block_number = block_number;

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_block_number",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            general_config,
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [block_number.into()],
        );
    };

    run(0);
    run(5);
    run(1000);
}

#[test]
fn get_block_timestamp_syscall() {
    let run = |block_timestamp| {
        let mut general_config = StarknetGeneralConfig::default();
        general_config.block_info_mut().block_timestamp = block_timestamp;

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_block_timestamp",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            general_config,
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [block_timestamp.into()],
        );
    };

    run(0);
    run(5);
    run(1000);
}

#[test]
fn get_caller_address_syscall() {
    let run = |caller_address: Felt| {
        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_caller_address",
            [1; 32],
            Address(1111.into()),
            Address(caller_address.clone()),
            StarknetGeneralConfig::default(),
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [caller_address],
        );
    };

    run(0.into());
    run(5.into());
    run(1000.into());
}

#[test]
fn get_contract_address_syscall() {
    let run = |contract_address: Felt| {
        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_contract_address",
            [1; 32],
            Address(contract_address.clone()),
            Address(0.into()),
            StarknetGeneralConfig::default(),
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [contract_address],
        );
    };

    run(1.into());
    run(5.into());
    run(1000.into());
}

#[test]
fn get_sequencer_address_syscall() {
    let run = |sequencer_address: Felt| {
        let mut general_config = StarknetGeneralConfig::default();
        general_config.block_info_mut().sequencer_address = Address(sequencer_address.clone());

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_sequencer_address",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            general_config,
            None,
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [sequencer_address],
        );
    };

    run(0.into());
    run(5.into());
    run(1000.into());
}

#[test]
fn get_tx_info_syscall() {
    let run = |version,
               account_contract_address: Address,
               max_fee,
               signature: Vec<Felt>,
               transaction_hash: Felt,
               chain_id| {
        let mut general_config = StarknetGeneralConfig::default();
        *general_config.starknet_os_config_mut().chain_id_mut() = chain_id;

        let n_steps = general_config.invoke_tx_max_n_steps();
        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_tx_info",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            general_config,
            Some(TransactionExecutionContext::new(
                account_contract_address.clone(),
                transaction_hash.clone(),
                signature.clone(),
                max_fee,
                3.into(),
                n_steps,
                version,
            )),
            [],
            [],
            [],
            empty(),
            empty(),
            [],
            [],
            [
                version.into(),
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
        );
    };

    run(
        0,
        Address::default(),
        12,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
    );
    run(
        10,
        Address::default(),
        12,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
    );
    run(
        10,
        Address(1111.into()),
        12,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
    );
    run(
        10,
        Address(1111.into()),
        50,
        vec![],
        0.into(),
        StarknetChainId::TestNet,
    );
    run(
        10,
        Address(1111.into()),
        50,
        [0x12, 0x34, 0x56, 0x78].map(Felt::from).to_vec(),
        0.into(),
        StarknetChainId::TestNet,
    );
    run(
        10,
        Address(1111.into()),
        50,
        [0x12, 0x34, 0x56, 0x78].map(Felt::from).to_vec(),
        12345678.into(),
        StarknetChainId::TestNet,
    );
    run(
        10,
        Address(1111.into()),
        50,
        [0x12, 0x34, 0x56, 0x78].map(Felt::from).to_vec(),
        12345678.into(),
        StarknetChainId::TestNet2,
    );
}

#[test]
fn get_tx_signature_syscall() {
    let run = |signature: Vec<Felt>| {
        let general_config = StarknetGeneralConfig::default();
        let n_steps = general_config.invoke_tx_max_n_steps();

        test_contract(
            "starknet_programs/syscalls.json",
            "test_get_tx_signature",
            [1; 32],
            Address(1111.into()),
            Address(0.into()),
            general_config,
            Some(TransactionExecutionContext::new(
                Address::default(),
                0.into(),
                signature.clone(),
                12,
                3.into(),
                n_steps,
                0,
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
        );
    };

    run(vec![]);
    run([0x12, 0x34, 0x56, 0x78].map(Felt::from).to_vec());
    run([0x9A, 0xBC, 0xDE, 0xF0].map(Felt::from).to_vec());
}

#[test]
fn library_call_syscall() {
    test_contract(
        "starknet_programs/syscalls.json",
        "test_library_call",
        [1; 32],
        Address(1111.into()),
        Address(0.into()),
        StarknetGeneralConfig::default(),
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
                ..Default::default()
            },
        ],
        [],
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
        StarknetGeneralConfig::default(),
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
            ..Default::default()
        }],
        [],
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
        StarknetGeneralConfig::default(),
        None,
        [],
        [
            OrderedL2ToL1Message {
                order: 0,
                to_address: Address(1111.into()),
                payload: [1, 2, 3].map(Felt::from).to_vec(),
            },
            OrderedL2ToL1Message {
                order: 1,
                to_address: Address(1111.into()),
                payload: [2, 4].map(Felt::from).to_vec(),
            },
            OrderedL2ToL1Message {
                order: 2,
                to_address: Address(1111.into()),
                payload: [3].map(Felt::from).to_vec(),
            },
        ],
        [],
        empty(),
        empty(),
        [],
        [],
        [],
    );
}
