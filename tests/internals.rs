// This module tests our code against the blockifier to ensure they work in the same way.
use assert_matches::assert_matches;
use cairo_rs::vm::{
    errors::{
        cairo_run_errors::CairoRunError, vm_errors::VirtualMachineError, vm_exception::VmException,
    },
    runners::cairo_runner::ExecutionResources,
};
use felt::{felt_str, Felt252};
use lazy_static::lazy_static;
use num_traits::{Num, One, ToPrimitive, Zero};
use starknet_rs::core::errors::state_errors::StateError;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, OrderedEvent, TransactionExecutionInfo},
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::{State, StateReader},
            state_api_objects::BlockInfo,
            state_cache::StateCache,
            state_cache::StorageEntry,
        },
        transaction::{
            error::TransactionError,
            objects::{
                internal_deploy_account::InternalDeployAccount,
                {
                    internal_declare::InternalDeclare,
                    internal_invoke_function::InternalInvokeFunction,
                },
            },
        },
    },
    definitions::{
        constants::{
            CONSTRUCTOR_ENTRY_POINT_SELECTOR, EXECUTE_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION,
            TRANSFER_ENTRY_POINT_SELECTOR, TRANSFER_EVENT_SELECTOR,
            VALIDATE_DECLARE_ENTRY_POINT_SELECTOR, VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR,
        },
        general_config::{StarknetChainId, StarknetGeneralConfig, StarknetOsConfig},
        transaction_type::TransactionType,
    },
    public::abi::VALIDATE_ENTRY_POINT_SELECTOR,
    services::api::contract_classes::deprecated_contract_class::{ContractClass, EntryPointType},
    utils::{calculate_sn_keccak, felt_to_hash, Address, ClassHash},
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
    static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt252 = felt_str!("273");
    static ref TEST_CLASS_HASH: Felt252 = felt_str!("272");
    static ref TEST_EMPTY_CONTRACT_CLASS_HASH: Felt252 = felt_str!("274");
    static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt252 = felt_str!("4112");

    // Storage keys.
    static ref TEST_ERC20_ACCOUNT_BALANCE_KEY: Felt252 =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617515");
    static ref TEST_ERC20_SEQUENCER_BALANCE_KEY: Felt252 =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768274");
    static ref TEST_ERC20_BALANCE_KEY_1: Felt252 =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617516");
    static ref TEST_ERC20_BALANCE_KEY_2: Felt252 =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768275");

    static ref TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY: Felt252 =
        felt_str!("2542253978940891427830343982984992363331567580652119103860970381451088310289");

    // Others.
    // Blockifier had this value hardcoded to 2.
    static ref ACTUAL_FEE: Felt252 = Felt252::zero();
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
        Default::default(),
        1_000_000,
        0,
        BlockInfo::empty(TEST_SEQUENCER_ADDRESS.clone()),
    )
}

fn create_account_tx_test_state(
) -> Result<(StarknetGeneralConfig, CachedState<InMemoryStateReader>), Box<dyn std::error::Error>> {
    let general_config = new_starknet_general_config_for_testing();

    let test_contract_class_hash = felt_to_hash(&TEST_CLASS_HASH.clone());
    let test_account_contract_class_hash = felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone());
    let test_erc20_class_hash = felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH.clone());
    let class_hash_to_class = HashMap::from([
        (
            test_account_contract_class_hash,
            get_contract_class(ACCOUNT_CONTRACT_PATH)?,
        ),
        (
            test_contract_class_hash,
            get_contract_class(TEST_CONTRACT_PATH)?,
        ),
        (
            test_erc20_class_hash,
            get_contract_class(ERC20_CONTRACT_PATH)?,
        ),
    ]);

    let test_contract_address = TEST_CONTRACT_ADDRESS.clone();
    let test_account_contract_address = TEST_ACCOUNT_CONTRACT_ADDRESS.clone();
    let test_erc20_address = general_config
        .starknet_os_config()
        .fee_token_address()
        .clone();
    let address_to_class_hash = HashMap::from([
        (test_contract_address, test_contract_class_hash),
        (
            test_account_contract_address,
            test_account_contract_class_hash,
        ),
        (test_erc20_address.clone(), test_erc20_class_hash),
    ]);

    let test_erc20_account_balance_key = TEST_ERC20_ACCOUNT_BALANCE_KEY.clone();

    let storage_view = HashMap::from([(
        (test_erc20_address, test_erc20_account_balance_key),
        ACTUAL_FEE.clone(),
    )]);

    let cached_state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::default();
            for (contract_address, class_hash) in address_to_class_hash {
                let storage_keys: HashMap<(Address, ClassHash), Felt252> = storage_view
                    .iter()
                    .filter_map(|((address, storage_key), storage_value)| {
                        (address == &contract_address).then_some((
                            (address.clone(), felt_to_hash(storage_key)),
                            storage_value.clone(),
                        ))
                    })
                    .collect();

                let stored: HashMap<StorageEntry, Felt252> = storage_keys;

                state_reader
                    .address_to_class_hash_mut()
                    .insert(contract_address.clone(), class_hash);

                state_reader
                    .address_to_nonce_mut()
                    .insert(contract_address.clone(), Felt252::zero());
                state_reader.address_to_storage_mut().extend(stored);
            }
            for (class_hash, contract_class) in class_hash_to_class {
                state_reader
                    .class_hash_to_contract_class_mut()
                    .insert(class_hash, contract_class);
            }
            state_reader
        },
        Some(HashMap::new()),
        None,
    );

    Ok((general_config, cached_state))
}

fn expected_state_before_tx() -> CachedState<InMemoryStateReader> {
    let in_memory_state_reader = initial_in_memory_state_reader();

    let state_cache = ContractClassCache::new();

    CachedState::new(in_memory_state_reader, Some(state_cache), None)
}

fn expected_state_after_tx() -> CachedState<InMemoryStateReader> {
    let in_memory_state_reader = initial_in_memory_state_reader();

    let contract_classes_cache = ContractClassCache::from([
        (
            felt_to_hash(&TEST_CLASS_HASH.clone()),
            get_contract_class(TEST_CONTRACT_PATH).unwrap(),
        ),
        (
            felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone()),
            get_contract_class(ACCOUNT_CONTRACT_PATH).unwrap(),
        ),
        (
            felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH.clone()),
            get_contract_class(ERC20_CONTRACT_PATH).unwrap(),
        ),
    ]);

    CachedState::new_for_testing(
        in_memory_state_reader,
        Some(contract_classes_cache),
        state_cache_after_invoke_tx(),
        None,
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
        HashMap::from([(TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt252::zero())]);

    let storage_initial_values = HashMap::from([
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY.clone()),
            ),
            Felt252::zero(),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY.clone()),
            ),
            Felt252::zero(),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_BALANCE_KEY_1.clone()),
            ),
            Felt252::zero(),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_BALANCE_KEY_2.clone()),
            ),
            Felt252::zero(),
        ),
    ]);

    let class_hash_writes = HashMap::new();

    let nonce_writes = HashMap::from([(TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt252::from(1))]);

    let storage_writes = HashMap::from([
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY.clone()),
            ),
            Felt252::from(0),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY.clone()),
            ),
            Felt252::from(0),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_BALANCE_KEY_1.clone()),
            ),
            Felt252::from(0),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_BALANCE_KEY_2.clone()),
            ),
            Felt252::from(0),
        ),
    ]);

    let compiled_class_hash = HashMap::new();

    StateCache::new_for_testing(
        class_hash_initial_values,
        nonce_initial_values,
        storage_initial_values,
        class_hash_writes,
        nonce_writes,
        storage_writes,
        compiled_class_hash,
    )
}

fn initial_in_memory_state_reader() -> InMemoryStateReader {
    InMemoryStateReader::new(
        HashMap::from([
            (
                TEST_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_CLASS_HASH),
            ),
            (
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
            ),
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
            ),
        ]),
        HashMap::from([
            (TEST_CONTRACT_ADDRESS.clone(), Felt252::zero()),
            (TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt252::zero()),
            (TEST_ERC20_CONTRACT_ADDRESS.clone(), Felt252::zero()),
        ]),
        HashMap::from([(
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY.clone()),
            ),
            Felt252::from(0),
        )]),
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
        HashMap::new(),
        HashMap::new(),
    )
}

fn expected_validate_call_info(
    entry_point_selector: Felt252,
    calldata: Vec<Felt252>,
    storage_address: Address,
) -> CallInfo {
    CallInfo {
        entry_point_type: EntryPointType::External.into(),
        entry_point_selector: entry_point_selector.into(),
        calldata,
        contract_address: storage_address,

        // Entries **not** in blockifier.
        class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
        call_type: Some(CallType::Call),

        ..Default::default()
    }
}

fn expected_fee_transfer_call_info(
    general_config: &StarknetGeneralConfig,
    account_address: &Address,
    actual_fee: u64,
) -> CallInfo {
    CallInfo {
        entry_point_type: EntryPointType::External.into(),
        entry_point_selector: TRANSFER_ENTRY_POINT_SELECTOR.clone().into(),
        calldata: vec![
            general_config.block_info().sequencer_address.0.clone(),
            actual_fee.into(),
            Felt252::zero(),
        ],
        contract_address: general_config
            .starknet_os_config()
            .fee_token_address()
            .clone(),
        caller_address: account_address.clone(),
        retdata: vec![Felt252::one()],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![TRANSFER_EVENT_SELECTOR.clone()],
            data: vec![
                account_address.0.clone(),
                general_config.block_info().sequencer_address.0.clone(),
                actual_fee.into(),
                Felt252::zero(),
            ],
        }],

        // Entries **not** in blockifier.
        class_hash: Some(felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH)),
        call_type: Some(CallType::Call),
        accessed_storage_keys: HashSet::from([
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 19,
            ],
            [
                5, 158, 221, 96, 243, 245, 236, 116, 233, 4, 68, 137, 231, 149, 207, 133, 23, 150,
                101, 24, 93, 212, 49, 126, 49, 102, 131, 144, 118, 15, 48, 18,
            ],
            [
                5, 158, 221, 96, 243, 245, 236, 116, 233, 4, 68, 137, 231, 149, 207, 133, 23, 150,
                101, 24, 93, 212, 49, 126, 49, 102, 131, 144, 118, 15, 48, 17,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 18,
            ],
        ]),
        storage_read_values: vec![
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
        ],

        ..Default::default()
    }
}

fn validate_final_balances<S>(
    state: &mut S,
    general_config: &StarknetGeneralConfig,
    expected_sequencer_balance: &Felt252,
    erc20_account_balance_storage_key: &ClassHash,
) where
    S: State + StateReader,
{
    let account_balance = state
        .get_storage_at(&(
            general_config
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            *erc20_account_balance_storage_key,
        ))
        .unwrap();
    assert_eq!(account_balance, &Felt252::zero());

    let sequencer_balance = state
        .get_storage_at(&(
            general_config
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(sequencer_balance, expected_sequencer_balance);
}

#[test]
fn test_create_account_tx_test_state() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    assert_eq!(state, expected_state_before_tx());

    let value = state
        .get_storage_at(&(
            general_config
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(value, &*ACTUAL_FEE);

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

fn invoke_tx(calldata: Vec<Felt252>) -> InternalInvokeFunction {
    InternalInvokeFunction::new(
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        EXECUTE_ENTRY_POINT_SELECTOR.clone(),
        2,
        calldata,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(Felt252::zero()),
    )
    .unwrap()
}

fn expected_fee_transfer_info() -> CallInfo {
    CallInfo {
        failure_flag: false,
        gas_consumed: 0,
        caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        call_type: Some(CallType::Call),
        contract_address: Address(Felt252::from(4097)),
        code_address: None,
        class_hash: Some(felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH)),
        entry_point_selector: Some(TRANSFER_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![Felt252::from(4096), Felt252::zero(), Felt252::zero()],
        retdata: vec![Felt252::from(1)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![TRANSFER_EVENT_SELECTOR.clone()],
            data: vec![
                Felt252::from(257),
                Felt252::from(4096),
                Felt252::zero(),
                Felt252::zero(),
            ],
        }],
        storage_read_values: vec![
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
        ],
        accessed_storage_keys: HashSet::from([
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 235,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 19,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 18,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 236,
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
        validate_entry_point_selector: VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone(),
        version: 1,
        max_fee: 2,
        signature: vec![],
        nonce: 0.into(),
        hash_value: 0.into(),
    }
}

fn expected_declare_fee_transfer_info() -> CallInfo {
    CallInfo {
        caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        call_type: Some(CallType::Call),
        contract_address: TEST_ERC20_CONTRACT_ADDRESS.clone(),
        class_hash: Some(felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH)),
        entry_point_selector: Some(TRANSFER_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            TEST_SEQUENCER_ADDRESS.0.clone(),
            Felt252::zero(),
            Felt252::zero(),
        ],
        retdata: vec![1.into()],
        events: vec![OrderedEvent::new(
            0,
            vec![felt_str!(
                "271746229759260285552388728919865295615886751538523744128730118297934206697"
            )],
            vec![
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone().0,
                TEST_SEQUENCER_ADDRESS.clone().0,
                0.into(),
                0.into(),
            ],
        )],
        storage_read_values: vec![
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
        ],
        accessed_storage_keys: HashSet::from([
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
            ],
        ]),
        ..Default::default()
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

    let expected_execution_info = TransactionExecutionInfo::new(
        Some(CallInfo {
            call_type: Some(CallType::Call),
            contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
            entry_point_selector: Some(VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone()),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![TEST_EMPTY_CONTRACT_CLASS_HASH.clone()],
            ..Default::default()
        }),
        None,
        Some(expected_declare_fee_transfer_info()),
        0,
        HashMap::from([
            ("range_check_builtin".to_string(), 57),
            ("pedersen_builtin".to_string(), 15),
            ("l1_gas_usage".to_string(), 0),
        ]),
        Some(TransactionType::Declare),
    );

    assert_eq!(result, expected_execution_info);
}

fn expected_execute_call_info() -> CallInfo {
    CallInfo {
        caller_address: Address(Felt252::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        code_address: None,
        class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone())),
        entry_point_selector: Some(EXECUTE_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt252::from(256),
            Felt252::from_str_radix(
                "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                16,
            )
            .unwrap(),
            Felt252::from(1),
            Felt252::from(2),
        ],
        retdata: vec![Felt252::from(2)],
        execution_resources: ExecutionResources::default(),
        l2_to_l1_messages: vec![],
        internal_calls: vec![CallInfo {
            caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            call_type: Some(CallType::Call),
            class_hash: Some(felt_to_hash(&TEST_CLASS_HASH.clone())),
            entry_point_selector: Some(
                Felt252::from_str_radix(
                    "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                    16,
                )
                .unwrap(),
            ),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![Felt252::from(2)],
            retdata: vec![Felt252::from(2)],
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

fn expected_validate_call_info_2() -> CallInfo {
    CallInfo {
        caller_address: Address(Felt252::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone())),
        entry_point_selector: Some(VALIDATE_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt252::from(256),
            Felt252::from_str_radix(
                "039a1491f76903a16feed0a6433bec78de4c73194944e1118e226820ad479701",
                16,
            )
            .unwrap(),
            Felt252::from(1),
            Felt252::from(2),
        ],
        ..Default::default()
    }
}

fn expected_transaction_execution_info() -> TransactionExecutionInfo {
    TransactionExecutionInfo::new(
        Some(expected_validate_call_info_2()),
        Some(expected_execute_call_info()),
        Some(expected_fee_transfer_info()),
        0,
        HashMap::from([
            ("pedersen_builtin".to_string(), 16),
            ("range_check".to_string(), 2),
            ("l1_gas_usage".to_string(), 0),
            ("range_check_builtin".to_string(), 70),
        ]),
        Some(TransactionType::InvokeFunction),
    )
}

#[test]
fn test_invoke_tx() {
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();
    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();
    let calldata = vec![
        test_contract_address, // CONTRACT_ADDRESS
        Felt252::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt252::from(1),                                               // CONTRACT_CALLDATA LEN
        Felt252::from(2),                                               // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata);

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
        test_contract_address, // CONTRACT_ADDRESS
        Felt252::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt252::from(1),                                               // CONTRACT_CALLDATA LEN
        Felt252::from(2),                                               // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata);

    invoke_tx.execute(state, starknet_general_config).unwrap();

    let expected_final_state = expected_state_after_tx();

    assert_eq!(*state, expected_final_state);
}

#[test]
fn test_deploy_account() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    let deploy_account_tx = InternalDeployAccount::new(
        felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
        2,
        TRANSACTION_VERSION,
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        StarknetChainId::TestNet,
    )
    .unwrap();

    state.set_storage_at(
        &(
            general_config
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY),
        ),
        ACTUAL_FEE.clone(),
    );

    let (state_before, state_after) = expected_deploy_account_states();

    assert_eq!(state, state_before);

    // Statement **not** in blockifier.
    state.cache_mut().nonce_initial_values_mut().insert(
        deploy_account_tx.contract_address().clone(),
        Felt252::zero(),
    );

    let tx_info = deploy_account_tx
        .execute(&mut state, &general_config)
        .unwrap();

    assert_eq!(state, state_after);

    let expected_validate_call_info = expected_validate_call_info(
        VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
        [
            Felt252::from_bytes_be(deploy_account_tx.class_hash()),
            deploy_account_tx.contract_address_salt().0.clone(),
        ]
        .into_iter()
        .chain(deploy_account_tx.constructor_calldata().clone())
        .collect(),
        deploy_account_tx.contract_address().clone(),
    );

    let expected_execute_call_info = CallInfo {
        entry_point_type: EntryPointType::Constructor.into(),
        entry_point_selector: CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone().into(),
        contract_address: deploy_account_tx.contract_address().clone(),

        // Entries **not** in blockifier.
        class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
        call_type: Some(CallType::Call),

        ..Default::default()
    };

    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        &general_config,
        deploy_account_tx.contract_address(),
        ACTUAL_FEE.to_u64().unwrap(),
    );

    let expected_execution_info = TransactionExecutionInfo::new(
        expected_validate_call_info.into(),
        expected_execute_call_info.into(),
        expected_fee_transfer_call_info.into(),
        ACTUAL_FEE.to_u64().unwrap(),
        // Entry **not** in blockifier.
        // Default::default(),
        [
            ("l1_gas_usage", 3672),
            ("range_check_builtin", 74),
            ("pedersen_builtin", 23),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
        TransactionType::DeployAccount.into(),
    );
    assert_eq!(tx_info, expected_execution_info);

    let nonce_from_state = state
        .get_nonce_at(deploy_account_tx.contract_address())
        .unwrap();
    assert_eq!(nonce_from_state, &Felt252::one());

    let hash = &felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY);

    validate_final_balances(&mut state, &general_config, &Felt252::zero(), hash);

    let class_hash_from_state = state
        .get_class_hash_at(deploy_account_tx.contract_address())
        .unwrap();
    assert_eq!(class_hash_from_state, deploy_account_tx.class_hash());
}

fn expected_deploy_account_states() -> (
    CachedState<InMemoryStateReader>,
    CachedState<InMemoryStateReader>,
) {
    let mut state_before = CachedState::new(
        InMemoryStateReader::new(
            HashMap::from([
                (
                    Address(0x101.into()),
                    felt_to_hash(&0x111.into()),
                ),
                (
                    Address(0x100.into()),
                    felt_to_hash(&0x110.into()),
                ),
                (
                    Address(0x1001.into()),
                    felt_to_hash(&0x1010.into()),
                )]),

                HashMap::from([
                    (
                        Address(0x101.into()),
                        Default::default(),
                    ),
                    (
                        Address(0x100.into()),
                        Default::default(),
                    ),
                    (
                        Address(0x1001.into()),
                        Default::default(),
                    )]),
                HashMap::from([
                    (
                        (Address(0x1001.into()),
                        felt_to_hash(&felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617515"))),
                        Felt252::zero(),
                    ),
                        ]),
            HashMap::from([
                (felt_to_hash(&0x110.into()), ContractClass::try_from(PathBuf::from(TEST_CONTRACT_PATH)).unwrap()),
                (felt_to_hash(&0x111.into()), ContractClass::try_from(PathBuf::from(ACCOUNT_CONTRACT_PATH)).unwrap()),
                (felt_to_hash(&0x1010.into()), ContractClass::try_from(PathBuf::from(ERC20_CONTRACT_PATH)).unwrap()),
            ]),
            HashMap::new(),
            HashMap::new()
        ),
        Some(ContractClassCache::new()),
        None
    );
    state_before.set_storage_at(
        &(
            Address(0x1001.into()),
            felt_to_hash(&felt_str!(
                "2542253978940891427830343982984992363331567580652119103860970381451088310289"
            )),
        ),
        0.into(),
    );

    let mut state_after = state_before.clone();
    state_after.cache_mut().nonce_initial_values_mut().insert(
        Address(felt_str!(
            "386181506763903095743576862849245034886954647214831045800703908858571591162"
        )),
        Felt252::zero(),
    );
    state_after
        .cache_mut()
        .class_hash_initial_values_mut()
        .insert(Address(0x1001.into()), felt_to_hash(&0x1010.into()));
    state_after
        .cache_mut()
        .class_hash_initial_values_mut()
        .insert(
            Address(felt_str!(
                "386181506763903095743576862849245034886954647214831045800703908858571591162"
            )),
            [0; 32],
        );
    state_after.cache_mut().storage_initial_values_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&felt_str!(
                "2542253978940891427830343982984992363331567580652119103860970381451088310290"
            )),
        ),
        Felt252::zero(),
    );
    state_after.cache_mut().storage_initial_values_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&TEST_ERC20_BALANCE_KEY_2),
        ),
        Felt252::zero(),
    );
    state_after.cache_mut().storage_initial_values_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&felt_str!(
                "3229073099929281304021185011369329892856197542079132996799046100564060768274"
            )),
        ),
        Felt252::zero(),
    );
    state_after.cache_mut().nonce_writes_mut().insert(
        Address(felt_str!(
            "386181506763903095743576862849245034886954647214831045800703908858571591162"
        )),
        1.into(),
    );
    state_after.cache_mut().class_hash_writes_mut().insert(
        Address(felt_str!(
            "386181506763903095743576862849245034886954647214831045800703908858571591162"
        )),
        felt_to_hash(&0x111.into()),
    );
    state_after.cache_mut().storage_writes_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&felt_str!(
                "2542253978940891427830343982984992363331567580652119103860970381451088310290"
            )),
        ),
        Felt252::zero(),
    );
    state_after.cache_mut().storage_writes_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&felt_str!(
                "2542253978940891427830343982984992363331567580652119103860970381451088310289"
            )),
        ),
        Felt252::zero(),
    );
    state_after.cache_mut().storage_writes_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&TEST_ERC20_BALANCE_KEY_2),
        ),
        Felt252::zero(),
    );
    state_after.cache_mut().storage_writes_mut().insert(
        (
            Address(0x1001.into()),
            felt_to_hash(&felt_str!(
                "3229073099929281304021185011369329892856197542079132996799046100564060768274"
            )),
        ),
        Felt252::zero(),
    );
    state_after
        .set_contract_class(
            &felt_to_hash(&0x1010.into()),
            &ContractClass::try_from(PathBuf::from(ERC20_CONTRACT_PATH)).unwrap(),
        )
        .unwrap();
    state_after
        .set_contract_class(
            &felt_to_hash(&0x111.into()),
            &ContractClass::try_from(PathBuf::from(ACCOUNT_CONTRACT_PATH)).unwrap(),
        )
        .unwrap();

    (state_before, state_after)
}

#[test]
fn test_state_for_declare_tx() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    let declare_tx = declare_tx();
    // Check ContractClass is not set before the declare_tx
    assert!(state.get_contract_class(&declare_tx.class_hash).is_err());
    assert_eq!(
        state.get_nonce_at(&declare_tx.sender_address),
        Ok(&0.into())
    );
    // Execute declare_tx
    assert!(declare_tx.execute(&mut state, &general_config).is_ok());
    assert_eq!(
        state.get_nonce_at(&declare_tx.sender_address),
        Ok(&1.into())
    );

    // Check state.state_reader
    let mut state_reader = state.state_reader().clone();

    assert_eq!(
        state_reader.address_to_class_hash_mut(),
        &mut HashMap::from([
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH)
            ),
            (
                TEST_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_CLASS_HASH)
            ),
            (
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)
            ),
        ]),
    );

    assert_eq!(
        state_reader.address_to_nonce_mut(),
        &mut HashMap::from([
            (TEST_ERC20_CONTRACT_ADDRESS.clone(), Felt252::zero()),
            (TEST_CONTRACT_ADDRESS.clone(), Felt252::zero()),
            (TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt252::zero()),
        ]),
    );

    assert_eq!(
        state_reader.address_to_storage_mut(),
        &mut HashMap::from([(
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY)
            ),
            Felt252::zero()
        ),]),
    );

    assert_eq!(
        state_reader.class_hash_to_contract_class_mut(),
        &mut HashMap::from([
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                get_contract_class(ERC20_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_CLASS_HASH),
                get_contract_class(TEST_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                get_contract_class(ACCOUNT_CONTRACT_PATH).unwrap()
            ),
        ])
    );

    // Check state.cache
    assert_eq!(
        state.cache(),
        &StateCache::new(
            HashMap::from([
                (
                    TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)
                ),
                (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH)
                )
            ]),
            HashMap::from([(
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                0.into()
            )]),
            HashMap::from([
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768275"))
                    ),
                    0.into()
                ),
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617516"))
                    ),
                    0.into()
                ),
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY)
                    ),
                    0.into()
                ),
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY)
                    ),
                    0.into()
                )
            ]),
            HashMap::new(),
            HashMap::from([(
                TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
                1.into()
            )]),
            HashMap::from([
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768275"))
                    ),
                    0.into()
                ),
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617516"))
                    ),
                    0.into()
                ),
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY)
                    ),
                    0.into() //Fee, 2 in blockifier
                ),
                (
                    (
                    TEST_ERC20_CONTRACT_ADDRESS.clone(),
                    felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY)
                    ),
                    0.into()
                ),
            ]),
            HashMap::new()
        ),
    );

    // Check state.contract_classes
    assert_eq!(
        state.contract_classes(),
        &Some(HashMap::from([
            (
                felt_to_hash(&TEST_EMPTY_CONTRACT_CLASS_HASH),
                get_contract_class(TEST_EMPTY_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                get_contract_class(ERC20_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                get_contract_class(ACCOUNT_CONTRACT_PATH).unwrap()
            ),
        ]))
    );
}

#[test]
fn test_invoke_tx_wrong_call_data() {
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();

    // Calldata with missing inputs
    let calldata = vec![
        TEST_CONTRACT_ADDRESS.clone().0, // CONTRACT_ADDRESS
        Felt252::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt252::from(1),                                               // CONTRACT_CALLDATA LEN
                                                                        // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata);

    // Execute transaction
    let result = invoke_tx.execute(state, starknet_general_config);

    // Assert error
    assert_matches!(
        result,
        Err(TransactionError::CairoRunner(CairoRunError::VmException(
            VmException {
                inner_exc: VirtualMachineError::DiffAssertValues(..),
                ..
            }
        )))
    );
}

#[test]
fn test_invoke_tx_wrong_entrypoint() {
    let (starknet_general_config, state) = &mut create_account_tx_test_state().unwrap();
    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();

    // Invoke transaction with an entrypoint that doesn't exists
    let invoke_tx = InternalInvokeFunction::new(
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        // Entrypoiont that doesnt exits in the contract
        Felt252::from_bytes_be(&calculate_sn_keccak(b"none_function")),
        1,
        vec![
            test_contract_address, // CONTRACT_ADDRESS
            Felt252::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
            Felt252::from(1),                                               // CONTRACT_CALLDATA LEN
            Felt252::from(2),                                               // CONTRACT_CALLDATA
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(Felt252::zero()),
    )
    .unwrap();

    // Execute transaction
    let result = invoke_tx.execute(state, starknet_general_config);

    // Assert error
    assert_matches!(result, Err(TransactionError::EntryPointNotFound));
}

#[test]
fn test_deploy_undeclared_account() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    let not_deployed_class_hash = [1; 32];
    // Deploy transaction with a not_deployed_class_hash class_hash
    let deploy_account_tx = InternalDeployAccount::new(
        not_deployed_class_hash,
        2,
        TRANSACTION_VERSION,
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        StarknetChainId::TestNet,
    )
    .unwrap();

    // Check not_deployed_class_hash
    assert!(state.get_contract_class(&not_deployed_class_hash).is_err());

    // Execute transaction
    let result = deploy_account_tx.execute(&mut state, &general_config);

    // Execute transaction
    assert_matches!(
        result,
        Err(TransactionError::State(StateError::MissingClassHash()))
    );
}
