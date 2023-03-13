use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::{Num, Zero};
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, OrderedEvent, TransactionExecutionInfo},
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::StateReader,
            state_api_objects::BlockInfo,
            state_cache::StateCache,
        },
        transaction::objects::{
            internal_declare::InternalDeclare, internal_invoke_function::InternalInvokeFunction,
        },
    },
    definitions::{
        constants::{
            EXECUTE_ENTRY_POINT_SELECTOR, TRANSFER_ENTRY_POINT_SELECTOR,
            VALIDATE_DECLARE_ENTRY_POINT_NAME,
        },
        general_config::{StarknetChainId, StarknetGeneralConfig, StarknetOsConfig},
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, felt_to_hash, Address},
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
const TEST_CONTRACT_PATH: &str = "starknet_programs/test_contract.json";
const TEST_EMPTY_CONTRACT_PATH: &str = "starknet_programs/empty_contract.json";

lazy_static! {
    // Addresses.
    static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("257"));
    static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("256"));
    pub static ref TEST_SEQUENCER_ADDRESS: Address =
    Address(felt_str!("4096"));
    pub static ref TEST_ERC20_CONTRACT_ADDRESS: Address =
    Address(felt_str!("4097"));


    // Class hashes.
    static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt = felt_str!("273");
    static ref TEST_CLASS_HASH: Felt = felt_str!("272");
    static ref TEST_EMPTY_CONTRACT_CLASS_HASH: Felt = felt_str!("274");
    static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt = felt_str!("4112");

    // Storage keys.
    static ref TEST_ERC20_ACCOUNT_BALANCE_KEY: Felt =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617515");
    static ref TEST_ERC20_SEQUENCER_BALANCE_KEY: Felt =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768274");

    // Others.
    static ref ACTUAL_FEE: Felt = 2.into();
}

fn get_contract_class<P>(path: P) -> Result<ContractClass, Box<dyn std::error::Error>>
where
    P: Into<PathBuf>,
{
    Ok(ContractClass::try_from(path.into())?)
}

pub fn new_starknet_general_config_for_testing() -> StarknetGeneralConfig {
    StarknetGeneralConfig::new(
        StarknetOsConfig::new(
            StarknetChainId::TestNet,
            TEST_ERC20_CONTRACT_ADDRESS.clone(),
            0,
        ),
        0,
        0,
        1_000_000,
        BlockInfo::empty(TEST_SEQUENCER_ADDRESS.clone()),
    )
}

#[allow(dead_code)]
fn create_account_tx_test_state(
) -> Result<(StarknetGeneralConfig, CachedState<InMemoryStateReader>), Box<dyn std::error::Error>> {
    let general_config = new_starknet_general_config_for_testing();

    let test_contract_class_hash = TEST_CLASS_HASH.clone();
    let test_account_class_hash = TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone();
    let test_erc20_class_hash = TEST_ERC20_CONTRACT_CLASS_HASH.clone();
    let class_hash_to_class = HashMap::from([
        (
            test_account_class_hash.clone(),
            get_contract_class(ACCOUNT_CONTRACT_PATH)?,
        ),
        (
            test_contract_class_hash.clone(),
            get_contract_class(TEST_CONTRACT_PATH)?,
        ),
        (
            test_erc20_class_hash.clone(),
            get_contract_class(ERC20_CONTRACT_PATH)?,
        ),
    ]);

    let test_contract_address = TEST_CONTRACT_ADDRESS.clone();
    let test_account_address = TEST_ACCOUNT_CONTRACT_ADDRESS.clone();
    let test_erc20_address = general_config
        .starknet_os_config()
        .fee_token_address()
        .clone();
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (test_account_address, test_account_class_hash),
        (test_erc20_address.clone(), test_erc20_class_hash),
    ]);

    let test_erc20_account_balance_key = TEST_ERC20_ACCOUNT_BALANCE_KEY.clone();
    let storage_view = HashMap::from([(
        (test_erc20_address, test_erc20_account_balance_key),
        ACTUAL_FEE.clone(),
    )]);

    let cached_state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());

            for (contract_address, class_hash) in address_to_class_hash {
                let storage_keys = storage_view
                    .iter()
                    .filter_map(|((address, storage_key), storage_value)| {
                        (address == &contract_address)
                            .then_some((storage_key.clone(), storage_value.clone()))
                    })
                    .collect();

                state_reader.contract_states_mut().insert(
                    contract_address,
                    ContractState::new(felt_to_hash(&class_hash), Felt::zero(), storage_keys),
                );
            }
            for (class_hash, contract_class) in class_hash_to_class {
                state_reader
                    .class_hash_to_contract_class_mut()
                    .insert(felt_to_hash(&class_hash), contract_class);
            }

            state_reader
        },
        Some(HashMap::new()),
    );

    Ok((general_config, cached_state))
}

fn expected_state_before_tx() -> CachedState<InMemoryStateReader> {
    let in_memory_state_reader = InMemoryStateReader::new(
        HashMap::from([
            (
                TEST_CONTRACT_ADDRESS.clone(),
                ContractState::new(felt_to_hash(&TEST_CLASS_HASH), Felt::zero(), HashMap::new()),
            ),
            (
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                ContractState::new(
                    felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                    Felt::zero(),
                    HashMap::new(),
                ),
            ),
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                ContractState::new(
                    felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                    Felt::zero(),
                    HashMap::from([(TEST_ERC20_ACCOUNT_BALANCE_KEY.clone(), Felt::from(2))]),
                ),
            ),
        ]),
        HashMap::from([
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                get_contract_class(ERC20_CONTRACT_PATH).unwrap(),
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                get_contract_class(ACCOUNT_CONTRACT_PATH).unwrap(),
            ),
            (
                felt_to_hash(&TEST_CLASS_HASH),
                get_contract_class(TEST_CONTRACT_PATH).unwrap(),
            ),
        ]),
    );

    let state_cache = ContractClassCache::new();

    CachedState::new(in_memory_state_reader, Some(state_cache))
}

fn expected_state_after_tx() -> CachedState<InMemoryStateReader> {
    let in_memory_state_reader = initial_in_memory_state_reader();

    let contract_classes_cache = ContractClassCache::new();

    CachedState::new_for_testing(
        in_memory_state_reader,
        Some(contract_classes_cache),
        state_cache_after_invoke_tx(),
    )
}

fn state_cache_after_invoke_tx() -> StateCache {
    let class_hash_initial_values = HashMap::from([
        (
            TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone()),
        ),
        (
            TEST_CONTRACT_ADDRESS.clone(),
            felt_to_hash(&TEST_CLASS_HASH.clone()),
        ),
        (
            TEST_ERC20_CONTRACT_ADDRESS.clone(),
            felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH.clone()),
        ),
    ]);

    let nonce_initial_values =
        HashMap::from([(TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt::zero())]);

    let storage_initial_values = HashMap::from([
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY.clone()),
            ),
            Felt::from(2),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY.clone()),
            ),
            Felt::from(2),
        ),
        // blockifier has two more storage initial values
    ]);

    let class_hash_writes = HashMap::new();

    let nonce_writes = HashMap::from([(TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt::from(1))]);
    // storage_writes: {
    //     (ContractAddress(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000001001"))),
    //     StorageKey(PatriciaKey(StarkFelt("0x0723973208639b7839ce298f7ffea61e3f9533872defd7abdb91023db4658812")))):
    //     StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000002"),
    //     (ContractAddress(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000001001"))),
    //     StorageKey(PatriciaKey(StarkFelt("0x02a2c49c4dba0d91b34f2ade85d41d09561f9a77884c15ba2ab0f2241b080dec")))):
    //     StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000000"),
    //     (ContractAddress(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000001001"))),
    //     StorageKey(PatriciaKey(StarkFelt("0x02a2c49c4dba0d91b34f2ade85d41d09561f9a77884c15ba2ab0f2241b080deb")))):
    //     StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000000"),
    //     (ContractAddress(PatriciaKey(StarkFelt("0x0000000000000000000000000000000000000000000000000000000000001001"))),
    //     StorageKey(PatriciaKey(StarkFelt("0x0723973208639b7839ce298f7ffea61e3f9533872defd7abdb91023db4658813")))):
    //     StarkFelt("0x0000000000000000000000000000000000000000000000000000000000000000")
    // }
    let storage_writes = HashMap::from([
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY.clone()),
            ),
            Felt::from(2),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY.clone()),
            ),
            Felt::from(0),
        ),
    ]);

    StateCache::new_for_testing(
        class_hash_initial_values,
        nonce_initial_values,
        storage_initial_values,
        class_hash_writes,
        nonce_writes,
        storage_writes,
    )
}

fn initial_in_memory_state_reader() -> InMemoryStateReader {
    InMemoryStateReader::new(
        HashMap::from([
            (
                TEST_CONTRACT_ADDRESS.clone(),
                ContractState::new(felt_to_hash(&TEST_CLASS_HASH), Felt::zero(), HashMap::new()),
            ),
            (
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                ContractState::new(
                    felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                    Felt::zero(),
                    HashMap::new(),
                ),
            ),
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                ContractState::new(
                    felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                    Felt::zero(),
                    HashMap::from([(TEST_ERC20_ACCOUNT_BALANCE_KEY.clone(), Felt::from(2))]),
                ),
            ),
        ]),
        HashMap::from([
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                get_contract_class(ERC20_CONTRACT_PATH).unwrap(),
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                get_contract_class(ACCOUNT_CONTRACT_PATH).unwrap(),
            ),
            (
                felt_to_hash(&TEST_CLASS_HASH),
                get_contract_class(TEST_CONTRACT_PATH).unwrap(),
            ),
        ]),
    )
}

#[test]
fn test_create_account_tx_test_state() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();
    assert_eq!(&state, &expected_state_before_tx());

    let value = state
        .get_storage_at(&(
            general_config
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(value, &2.into());

    let class_hash = state.get_class_hash_at(&TEST_CONTRACT_ADDRESS).unwrap();
    assert_eq!(class_hash, &felt_to_hash(&TEST_CLASS_HASH));

    let contract_class = state
        .get_contract_class(&felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH))
        .unwrap();
    assert_eq!(
        contract_class,
        get_contract_class(ERC20_CONTRACT_PATH).unwrap()
    );
}

fn invoke_tx(calldata: Vec<Felt>) -> InternalInvokeFunction {
    InternalInvokeFunction::new(
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        EXECUTE_ENTRY_POINT_SELECTOR.clone(),
        1,
        calldata,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(Felt::zero()),
    )
    .unwrap()
}

fn expected_fee_transfer_info() -> CallInfo {
    CallInfo {
        caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        call_type: Some(CallType::Call),
        contract_address: Address(Felt::from(4097)),
        code_address: None,
        class_hash: Some([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 16, 16,
        ]),
        entry_point_selector: Some(
            Felt::from_str_radix(
                "0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
                16,
            )
            .unwrap(),
        ),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![Felt::from(4096), Felt::zero(), Felt::zero()],
        retdata: vec![Felt::from(1)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![Felt::from_str_radix(
                "0099cd8bde557814842a3121e8ddfd433a539b8c9f14bf31ebf108d12e6196e9",
                16,
            )
            .unwrap()],
            data: vec![
                Felt::from(257),
                Felt::from(4096),
                Felt::zero(),
                Felt::zero(),
            ],
        }],
        storage_read_values: vec![Felt::from(2)],
        accessed_storage_keys: HashSet::from([
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 18,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 236,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 19,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 235,
            ],
        ]),
    }
}
fn declare_tx() -> InternalDeclare {
    InternalDeclare {
        contract_class: get_contract_class(TEST_EMPTY_CONTRACT_PATH).unwrap(),
        class_hash: felt_to_hash(&TEST_EMPTY_CONTRACT_CLASS_HASH),
        sender_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        tx_type: TransactionType::Declare,
        validate_entry_point_selector: VALIDATE_DECLARE_ENTRY_POINT_NAME.clone(),
        version: 1,
        max_fee: 2,
        signature: vec![],
        nonce: 0.into(),
        hash_value: 0.into(),
    }
}
#[test]
fn test_declare_tx() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();
    assert_eq!(state, expected_state_before_tx());
    let declare_tx = declare_tx();
    // Check ContractClass is not set before the declare_tx
    assert!(state.get_contract_class(&declare_tx.class_hash).is_err());
    // Execute declare_tx
    let result = declare_tx.execute(&mut state, &general_config).unwrap();
    // Check ContractClass is set after the declare_tx
    assert!(state.get_contract_class(&declare_tx.class_hash).is_ok());

    assert_eq!(result.tx_type, Some(TransactionType::Declare));

    // Check result validate_info
    let validate_info = result.validate_info.unwrap();

    assert_eq!(
        validate_info.class_hash,
        Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH))
    );

    assert_eq!(
        validate_info.entry_point_type,
        Some(EntryPointType::External)
    );
    assert_eq!(
        validate_info.entry_point_selector,
        Some(VALIDATE_DECLARE_ENTRY_POINT_NAME.clone())
    );

    assert_eq!(validate_info.call_type, Some(CallType::Call));

    assert_eq!(
        validate_info.calldata,
        vec![TEST_EMPTY_CONTRACT_CLASS_HASH.clone()]
    );
    assert_eq!(
        validate_info.contract_address,
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone()
    );
    assert_eq!(validate_info.caller_address, Address(0.into()));
    assert_eq!(validate_info.internal_calls, Vec::new());
    assert_eq!(validate_info.retdata, Vec::new());
    assert_eq!(validate_info.events, Vec::new());
    assert_eq!(validate_info.storage_read_values, Vec::new());
    assert_eq!(validate_info.accessed_storage_keys, HashSet::new());
    assert_eq!(validate_info.l2_to_l1_messages, Vec::new());

    // Check result call_info
    assert_eq!(result.call_info, None);

    // Check result fee_transfer_info
    let fee_transfer_info = result.fee_transfer_info.unwrap();

    assert_eq!(
        fee_transfer_info.class_hash,
        Some(felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH))
    );

    assert_eq!(fee_transfer_info.call_type, Some(CallType::Call));

    assert_eq!(
        fee_transfer_info.entry_point_type,
        Some(EntryPointType::External)
    );
    assert_eq!(
        fee_transfer_info.entry_point_selector,
        Some(TRANSFER_ENTRY_POINT_SELECTOR.clone())
    );

    assert_eq!(
        fee_transfer_info.calldata,
        vec![TEST_SEQUENCER_ADDRESS.0.clone(), Felt::zero(), Felt::zero()]
    );

    assert_eq!(
        fee_transfer_info.contract_address,
        TEST_ERC20_CONTRACT_ADDRESS.clone()
    );

    assert_eq!(fee_transfer_info.retdata, vec![1.into()]);

    assert_eq!(
        fee_transfer_info.caller_address,
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone()
    );
    assert_eq!(
        fee_transfer_info.events,
        vec![OrderedEvent::new(
            0,
            vec![felt_str!(
                "271746229759260285552388728919865295615886751538523744128730118297934206697"
            )],
            vec![
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone().0,
                TEST_SEQUENCER_ADDRESS.clone().0,
                0.into(),
                0.into()
            ]
        )]
    );

    assert_eq!(fee_transfer_info.internal_calls, Vec::new());

    assert_eq!(fee_transfer_info.storage_read_values, vec![2.into()]);
    assert_eq!(
        fee_transfer_info.accessed_storage_keys,
        HashSet::from([
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 236,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 18,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 19,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 235,
            ]
        ])
    );
    assert_eq!(fee_transfer_info.l2_to_l1_messages, Vec::new());
}

fn expected_execute_call_info() -> CallInfo {
    CallInfo {
        caller_address: Address(Felt::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        code_address: None,
        class_hash: Some([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 17,
        ]),
        entry_point_selector: Some(
            Felt::from_str_radix(
                "015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
                16,
            )
            .unwrap(),
        ),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt::from(256),
            Felt::from_str_radix(
                "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                16,
            )
            .unwrap(),
            Felt::from(1),
            Felt::from(2),
        ],
        retdata: vec![Felt::from(2)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![CallInfo {
            caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            call_type: Some(CallType::Call),
            class_hash: Some([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 1, 16,
            ]),
            entry_point_selector: Some(
                Felt::from_str_radix(
                    "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                    16,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![Felt::from(2)],
            retdata: vec![Felt::from(2)],
            events: vec![],
            l2_to_l1_messages: vec![],
            internal_calls: vec![],
            execution_resources: ExecutionResources::default(),
            contract_address: TEST_CONTRACT_ADDRESS.clone(),
            code_address: None,
            ..Default::default()
        }],
        events: vec![],
        ..Default::default()
    }
}

fn expected_validate_call_info() -> CallInfo {
    CallInfo {
        caller_address: Address(Felt::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        code_address: None,
        class_hash: Some([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 17,
        ]),
        entry_point_selector: Some(
            Felt::from_str_radix(
                "0162da33a4585851fe8d3af3c2a9c60b557814e221e0d4f30ff0b2189d9c7775",
                16,
            )
            .unwrap(),
        ),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt::from(256),
            Felt::from_str_radix(
                "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                16,
            )
            .unwrap(),
            Felt::from(1),
            Felt::from(2),
        ],
        retdata: vec![],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![],
        ..Default::default()
    }
}

fn expected_transaction_execution_info() -> TransactionExecutionInfo {
    TransactionExecutionInfo::new(
        Some(expected_validate_call_info()),
        Some(expected_execute_call_info()),
        Some(expected_fee_transfer_info()),
        0,
        HashMap::from([("l1_gas_usage".to_string(), 0)]),
        Some(TransactionType::InvokeFunction),
    )
}

#[test]
fn test_invoke_tx() {
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();
    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();
    let calldata = vec![
        test_contract_address,                                       // CONTRACT_ADDRESS
        Felt::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt::from(1),                                               // CONTRACT_CALLDATA LEN
        Felt::from(2),                                               // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata);
    println!(
        "contract_Address invokefunction: {:#?}",
        invoke_tx.contract_address
    );

    // Extract invoke transaction fields for testing, as it is consumed when creating an account
    // transaction.
    let result = invoke_tx.execute(state, starknet_general_config).unwrap();
    let expected_execution_info = expected_transaction_execution_info();

    assert_eq!(result, expected_execution_info);
}

#[test]
fn test_invoke_tx_state() {
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();
    let expected_initial_state = expected_state_before_tx();
    assert_eq!(state, &expected_initial_state);

    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();
    let calldata = vec![
        test_contract_address,                                       // CONTRACT_ADDRESS
        Felt::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt::from(1),                                               // CONTRACT_CALLDATA LEN
        Felt::from(2),                                               // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata);

    invoke_tx.execute(state, starknet_general_config).unwrap();

    let expected_final_state = expected_state_after_tx();

    assert_eq!(state.state_reader, expected_final_state.state_reader);
    assert_eq!(state.cache, expected_final_state.cache);
    assert_eq!(
        state.contract_classes,
        expected_final_state.contract_classes
    );
}
