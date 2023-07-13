// This module tests our code against the blockifier to ensure they work in the same way.
use assert_matches::assert_matches;
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_vm::felt::{felt_str, Felt252};
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, RANGE_CHECK_BUILTIN_NAME};
use cairo_vm::vm::{
    errors::{
        cairo_run_errors::CairoRunError, vm_errors::VirtualMachineError, vm_exception::VmException,
    },
    runners::cairo_runner::ExecutionResources,
};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Num, One, Zero};
use starknet_in_rust::core::contract_address::compute_sierra_class_hash;
use starknet_in_rust::core::errors::state_errors::StateError;
use starknet_in_rust::definitions::constants::{
    DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, VALIDATE_ENTRY_POINT_SELECTOR,
};
use starknet_in_rust::execution::execution_entry_point::ExecutionEntryPoint;
use starknet_in_rust::execution::TransactionExecutionContext;
use starknet_in_rust::services::api::contract_classes::deprecated_contract_class::ContractClass;
use starknet_in_rust::state::ExecutionResourcesManager;
use starknet_in_rust::transaction::fee::calculate_tx_fee;
use starknet_in_rust::transaction::{DeclareV2, Deploy};
use starknet_in_rust::CasmContractClass;
use starknet_in_rust::EntryPointType;
use starknet_in_rust::{
    definitions::{
        block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
        constants::{
            CONSTRUCTOR_ENTRY_POINT_SELECTOR, EXECUTE_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION,
            TRANSFER_ENTRY_POINT_SELECTOR, TRANSFER_EVENT_SELECTOR,
            VALIDATE_DECLARE_ENTRY_POINT_SELECTOR, VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR,
        },
        transaction_type::TransactionType,
    },
    execution::{CallInfo, CallType, OrderedEvent, TransactionExecutionInfo},
    state::in_memory_state_reader::InMemoryStateReader,
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::{State, StateReader},
        state_cache::StateCache,
        state_cache::StorageEntry,
        BlockInfo,
    },
    transaction::{
        error::TransactionError,
        DeployAccount,
        {invoke_function::InvokeFunction, Declare},
    },
    utils::{calculate_sn_keccak, felt_to_hash, Address, ClassHash},
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
const TEST_CONTRACT_PATH: &str = "starknet_programs/test_contract.json";
const TEST_EMPTY_CONTRACT_PATH: &str = "starknet_programs/empty_contract.json";

lazy_static! {
    // Addresses.
    static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("257"));
    static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("256"));
    static ref TEST_FIB_CONTRACT_ADDRESS: Address = Address(felt_str!("27728"));
    pub static ref TEST_SEQUENCER_ADDRESS: Address =
    Address(felt_str!("4096"));
    pub static ref TEST_ERC20_CONTRACT_ADDRESS: Address =
    Address(felt_str!("4097"));


    // Class hashes.
    static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt252 = felt_str!("273");
    static ref TEST_CLASS_HASH: Felt252 = felt_str!("272");
    static ref TEST_EMPTY_CONTRACT_CLASS_HASH: Felt252 = felt_str!("274");
    static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt252 = felt_str!("4112");
    static ref TEST_FIB_COMPILED_CONTRACT_CLASS_HASH: Felt252 = felt_str!("27727");

    // Storage keys.
    // NOTE: this key corresponds to the lower 128 bits of an U256
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
    static ref INITIAL_BALANCE: Felt252 = Felt252::from_u128(100000).unwrap();
    static ref GAS_PRICE: u128 = 1;
}

pub fn new_starknet_block_context_for_testing() -> BlockContext {
    BlockContext::new(
        StarknetOsConfig::new(
            StarknetChainId::TestNet,
            TEST_ERC20_CONTRACT_ADDRESS.clone(),
            *GAS_PRICE,
        ),
        0,
        0,
        DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
        1_000_000,
        0,
        BlockInfo::empty(TEST_SEQUENCER_ADDRESS.clone()),
        HashMap::default(),
        true,
    )
}

fn create_account_tx_test_state(
) -> Result<(BlockContext, CachedState<InMemoryStateReader>), Box<dyn std::error::Error>> {
    let block_context = new_starknet_block_context_for_testing();

    let test_contract_class_hash = felt_to_hash(&TEST_CLASS_HASH.clone());
    let test_account_contract_class_hash = felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone());
    let test_erc20_class_hash = felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH.clone());
    let class_hash_to_class = HashMap::from([
        (
            test_account_contract_class_hash,
            ContractClass::from_path(ACCOUNT_CONTRACT_PATH)?,
        ),
        (
            test_contract_class_hash,
            ContractClass::from_path(TEST_CONTRACT_PATH)?,
        ),
        (
            test_erc20_class_hash,
            ContractClass::from_path(ERC20_CONTRACT_PATH)?,
        ),
    ]);

    let test_contract_address = TEST_CONTRACT_ADDRESS.clone();
    let test_account_contract_address = TEST_ACCOUNT_CONTRACT_ADDRESS.clone();
    let test_erc20_address = block_context
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
        INITIAL_BALANCE.clone(),
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
            Arc::new(state_reader)
        },
        Some(HashMap::new()),
        Some(HashMap::new()),
    );

    Ok((block_context, cached_state))
}

fn expected_state_before_tx() -> CachedState<InMemoryStateReader> {
    let in_memory_state_reader = initial_in_memory_state_reader();

    let state_cache = ContractClassCache::new();

    CachedState::new(
        Arc::new(in_memory_state_reader),
        Some(state_cache),
        Some(HashMap::new()),
    )
}

fn expected_state_after_tx(fee: u128) -> CachedState<InMemoryStateReader> {
    let in_memory_state_reader = initial_in_memory_state_reader();

    let contract_classes_cache = ContractClassCache::from([
        (
            felt_to_hash(&TEST_CLASS_HASH.clone()),
            ContractClass::from_path(TEST_CONTRACT_PATH).unwrap(),
        ),
        (
            felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone()),
            ContractClass::from_path(ACCOUNT_CONTRACT_PATH).unwrap(),
        ),
        (
            felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH.clone()),
            ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap(),
        ),
    ]);

    CachedState::new_for_testing(
        Arc::new(in_memory_state_reader),
        Some(contract_classes_cache),
        state_cache_after_invoke_tx(fee),
        Some(HashMap::new()),
    )
}

fn state_cache_after_invoke_tx(fee: u128) -> StateCache {
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
            INITIAL_BALANCE.clone(),
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
            Felt252::from(fee),
        ),
        (
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY.clone()),
            ),
            INITIAL_BALANCE.clone() - Felt252::from(fee),
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

    let compiled_class_hash_initial_values = HashMap::new();
    let compiled_class_hash_writes = HashMap::new();
    let compiled_class_hash = HashMap::new();

    StateCache::new_for_testing(
        class_hash_initial_values,
        compiled_class_hash_initial_values,
        nonce_initial_values,
        storage_initial_values,
        class_hash_writes,
        compiled_class_hash_writes,
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
            INITIAL_BALANCE.clone(),
        )]),
        HashMap::from([
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap(),
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                ContractClass::from_path(ACCOUNT_CONTRACT_PATH).unwrap(),
            ),
            (
                felt_to_hash(&TEST_CLASS_HASH),
                ContractClass::from_path(TEST_CONTRACT_PATH).unwrap(),
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
        execution_resources: ExecutionResources {
            n_steps: 13,
            ..Default::default()
        },

        ..Default::default()
    }
}

fn expected_fee_transfer_call_info(
    block_context: &BlockContext,
    account_address: &Address,
    actual_fee: u64,
) -> CallInfo {
    CallInfo {
        entry_point_type: EntryPointType::External.into(),
        entry_point_selector: TRANSFER_ENTRY_POINT_SELECTOR.clone().into(),
        calldata: vec![
            block_context.block_info().sequencer_address.0.clone(),
            actual_fee.into(),
            Felt252::zero(),
        ],
        contract_address: block_context
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
                block_context.block_info().sequencer_address.0.clone(),
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
            INITIAL_BALANCE.clone(),
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
        ],
        execution_resources: ExecutionResources {
            n_steps: 529,
            n_memory_holes: 57,
            builtin_instance_counter: HashMap::from([
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
                (HASH_BUILTIN_NAME.to_string(), 4),
            ]),
        },
        ..Default::default()
    }
}

fn validate_final_balances<S>(
    state: &mut S,
    block_context: &BlockContext,
    erc20_account_balance_storage_key: &ClassHash,
    fee: u128,
) where
    S: State + StateReader,
{
    let account_balance = state
        .get_storage_at(&(
            block_context
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            *erc20_account_balance_storage_key,
        ))
        .unwrap();
    assert_eq!(
        account_balance,
        INITIAL_BALANCE.clone() - Felt252::from(fee)
    );

    let sequencer_balance = state
        .get_storage_at(&(
            block_context
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(sequencer_balance, fee.into());
}

#[test]
fn test_create_account_tx_test_state() {
    let (block_context, state) = create_account_tx_test_state().unwrap();

    assert_eq!(state, expected_state_before_tx());

    let value = state
        .get_storage_at(&(
            block_context
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(value, *INITIAL_BALANCE);

    let class_hash = state.get_class_hash_at(&TEST_CONTRACT_ADDRESS).unwrap();
    assert_eq!(class_hash, felt_to_hash(&TEST_CLASS_HASH));

    let contract_class: ContractClass = state
        .get_contract_class(&felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        contract_class,
        ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap()
    );
}

fn invoke_tx(calldata: Vec<Felt252>) -> InvokeFunction {
    InvokeFunction::new(
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        EXECUTE_ENTRY_POINT_SELECTOR.clone(),
        5000,
        TRANSACTION_VERSION.clone(),
        calldata,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(Felt252::zero()),
    )
    .unwrap()
}

fn expected_fee_transfer_info(fee: u128) -> CallInfo {
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
        calldata: vec![Felt252::from(4096), Felt252::from(fee), Felt252::zero()],
        retdata: vec![Felt252::from(1)],
        execution_resources: ExecutionResources {
            n_steps: 525,
            n_memory_holes: 59,
            builtin_instance_counter: HashMap::from([
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
                (HASH_BUILTIN_NAME.to_string(), 4),
            ]),
        },
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![TRANSFER_EVENT_SELECTOR.clone()],
            data: vec![
                Felt252::from(257),
                Felt252::from(4096),
                Felt252::from(fee),
                Felt252::zero(),
            ],
        }],
        storage_read_values: vec![
            INITIAL_BALANCE.clone(),
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
        ],
        accessed_storage_keys: HashSet::from([
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 19,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 236,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 18,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 235,
            ],
        ]),
    }
}

fn expected_fib_fee_transfer_info(fee: u128) -> CallInfo {
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
        calldata: vec![Felt252::from(4096), Felt252::from(fee), Felt252::zero()],
        retdata: vec![Felt252::from(1)],
        execution_resources: ExecutionResources {
            n_steps: 525,
            n_memory_holes: 59,
            builtin_instance_counter: HashMap::from([
                ("range_check_builtin".to_string(), 21),
                ("pedersen_builtin".to_string(), 4),
            ]),
        },
        l2_to_l1_messages: vec![],
        internal_calls: vec![],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![TRANSFER_EVENT_SELECTOR.clone()],
            data: vec![
                Felt252::from(257),
                Felt252::from(4096),
                Felt252::from(fee),
                Felt252::zero(),
            ],
        }],
        storage_read_values: vec![
            INITIAL_BALANCE.clone() - Felt252::from(10),
            Felt252::zero(),
            Felt252::from(10),
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

fn declare_tx() -> Declare {
    Declare {
        contract_class: ContractClass::from_path(TEST_EMPTY_CONTRACT_PATH).unwrap(),
        class_hash: felt_to_hash(&TEST_EMPTY_CONTRACT_CLASS_HASH),
        sender_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        tx_type: TransactionType::Declare,
        validate_entry_point_selector: VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone(),
        version: 1.into(),
        max_fee: 100000,
        signature: vec![],
        nonce: 0.into(),
        hash_value: 0.into(),
        skip_execute: false,
        skip_fee_transfer: false,
        skip_validate: false,
    }
}

fn declarev2_tx() -> DeclareV2 {
    #[cfg(not(feature = "cairo_1_tests"))]
    let program_data = include_bytes!("../starknet_programs/cairo2/fibonacci.sierra");
    #[cfg(feature = "cairo_1_tests")]
    let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.sierra");
    let sierra_contract_class: SierraContractClass = serde_json::from_slice(program_data).unwrap();
    let sierra_class_hash = compute_sierra_class_hash(&sierra_contract_class).unwrap();

    DeclareV2 {
        sender_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        tx_type: TransactionType::Declare,
        validate_entry_point_selector: VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone(),
        version: 1.into(),
        max_fee: 5000,
        signature: vec![],
        nonce: 0.into(),
        hash_value: 0.into(),
        compiled_class_hash: TEST_FIB_COMPILED_CONTRACT_CLASS_HASH.clone(),
        sierra_contract_class,
        sierra_class_hash,
        casm_class: Default::default(),
        skip_execute: false,
        skip_fee_transfer: false,
        skip_validate: false,
    }
}

fn deploy_fib_syscall() -> Deploy {
    Deploy {
        hash_value: 0.into(),
        version: 1.into(),
        contract_address: TEST_FIB_CONTRACT_ADDRESS.clone(),
        contract_address_salt: 0.into(),
        contract_hash: felt_to_hash(&TEST_FIB_COMPILED_CONTRACT_CLASS_HASH.clone()),
        constructor_calldata: Vec::new(),
        tx_type: TransactionType::Deploy,
        skip_execute: false,
        skip_fee_transfer: false,
        skip_validate: false,
    }
}

fn expected_declare_fee_transfer_info(fee: u128) -> CallInfo {
    CallInfo {
        caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        call_type: Some(CallType::Call),
        contract_address: TEST_ERC20_CONTRACT_ADDRESS.clone(),
        class_hash: Some(felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH)),
        entry_point_selector: Some(TRANSFER_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            TEST_SEQUENCER_ADDRESS.0.clone(),
            Felt252::from(fee),
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
                Felt252::from(fee),
                0.into(),
            ],
        )],
        storage_read_values: vec![
            INITIAL_BALANCE.clone(),
            Felt252::zero(),
            Felt252::zero(),
            Felt252::zero(),
        ],
        accessed_storage_keys: HashSet::from([
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 18,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 235,
            ],
            [
                7, 35, 151, 50, 8, 99, 155, 120, 57, 206, 41, 143, 127, 254, 166, 30, 63, 149, 51,
                135, 45, 239, 215, 171, 219, 145, 2, 61, 180, 101, 136, 19,
            ],
            [
                2, 162, 196, 156, 77, 186, 13, 145, 179, 79, 42, 222, 133, 212, 29, 9, 86, 31, 154,
                119, 136, 76, 21, 186, 42, 176, 242, 36, 27, 8, 13, 236,
            ],
        ]),
        execution_resources: ExecutionResources {
            n_steps: 525,
            n_memory_holes: 59,
            builtin_instance_counter: HashMap::from([
                (RANGE_CHECK_BUILTIN_NAME.to_string(), 21),
                (HASH_BUILTIN_NAME.to_string(), 4),
            ]),
        },
        ..Default::default()
    }
}

#[test]
fn test_declare_tx() {
    let (block_context, mut state) = create_account_tx_test_state().unwrap();
    assert_eq!(state, expected_state_before_tx());
    let declare_tx = declare_tx();
    // Check ContractClass is not set before the declare_tx
    assert!(state.get_contract_class(&declare_tx.class_hash).is_err());
    // Execute declare_tx
    let result = declare_tx.execute(&mut state, &block_context).unwrap();
    // Check ContractClass is set after the declare_tx
    assert!(state.get_contract_class(&declare_tx.class_hash).is_ok());

    let resources = HashMap::from([
        ("range_check_builtin".to_string(), 57),
        ("pedersen_builtin".to_string(), 15),
        ("l1_gas_usage".to_string(), 0),
    ]);
    let fee = calculate_tx_fee(&resources, *GAS_PRICE, &block_context).unwrap();

    let expected_execution_info = TransactionExecutionInfo::new(
        Some(CallInfo {
            call_type: Some(CallType::Call),
            contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
            entry_point_selector: Some(VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone()),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![TEST_EMPTY_CONTRACT_CLASS_HASH.clone()],
            execution_resources: ExecutionResources {
                n_steps: 12,
                ..Default::default()
            },
            ..Default::default()
        }),
        None,
        Some(expected_declare_fee_transfer_info(fee)),
        fee,
        resources,
        Some(TransactionType::Declare),
    );

    assert_eq!(result, expected_execution_info);
}

#[test]
fn test_declarev2_tx() {
    let (block_context, mut state) = create_account_tx_test_state().unwrap();
    assert_eq!(state, expected_state_before_tx());
    let declare_tx = declarev2_tx();
    // Check ContractClass is not set before the declare_tx
    assert!(state
        .get_contract_class(&felt_to_hash(&declare_tx.compiled_class_hash))
        .is_err());
    // Execute declare_tx
    let result = declare_tx.execute(&mut state, &block_context).unwrap();
    // Check ContractClass is set after the declare_tx
    assert!(state
        .get_contract_class(&declare_tx.compiled_class_hash.to_be_bytes())
        .is_ok());

    let resources = HashMap::from([
        ("range_check_builtin".to_string(), 57),
        ("pedersen_builtin".to_string(), 15),
        ("l1_gas_usage".to_string(), 0),
    ]);
    let fee = calculate_tx_fee(&resources, *GAS_PRICE, &block_context).unwrap();

    let expected_execution_info = TransactionExecutionInfo::new(
        Some(CallInfo {
            call_type: Some(CallType::Call),
            contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH)),
            entry_point_selector: Some(VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone()),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![TEST_FIB_COMPILED_CONTRACT_CLASS_HASH.clone()],
            execution_resources: ExecutionResources {
                n_steps: 12,
                ..Default::default()
            },
            ..Default::default()
        }),
        None,
        Some(expected_declare_fee_transfer_info(fee)),
        fee,
        resources,
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
            contract_address: TEST_CONTRACT_ADDRESS.clone(),
            code_address: None,
            execution_resources: ExecutionResources {
                n_steps: 22,
                ..Default::default()
            },
            ..Default::default()
        }],
        events: vec![],
        execution_resources: ExecutionResources {
            n_steps: 61,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        },
        ..Default::default()
    }
}

fn expected_fib_execute_call_info() -> CallInfo {
    CallInfo {
        caller_address: Address(Felt252::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        code_address: None,
        class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone())),
        entry_point_selector: Some(EXECUTE_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt252::from(27728),
            Felt252::from_bytes_be(&calculate_sn_keccak(b"fib")),
            Felt252::from(3),
            Felt252::from(42),
            Felt252::from(0),
            Felt252::from(0),
        ],
        retdata: vec![Felt252::from(42)],
        execution_resources: ExecutionResources {
            #[cfg(not(feature = "cairo_1_tests"))]
            n_steps: 157,
            #[cfg(feature = "cairo_1_tests")]
            n_steps: 160,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([("range_check_builtin".to_string(), 4)]),
        },
        l2_to_l1_messages: vec![],
        internal_calls: vec![CallInfo {
            caller_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            call_type: Some(CallType::Call),
            class_hash: Some(felt_to_hash(&TEST_FIB_COMPILED_CONTRACT_CLASS_HASH.clone())),
            entry_point_selector: Some(Felt252::from_bytes_be(&calculate_sn_keccak(b"fib"))),
            entry_point_type: Some(EntryPointType::External),
            calldata: vec![Felt252::from(42), Felt252::from(0), Felt252::from(0)],
            retdata: vec![Felt252::from(42)],
            events: vec![],
            l2_to_l1_messages: vec![],
            internal_calls: vec![],
            contract_address: TEST_FIB_CONTRACT_ADDRESS.clone(),
            code_address: None,
            #[cfg(not(feature = "cairo_1_tests"))]
            gas_consumed: 4380,
            #[cfg(feature = "cairo_1_tests")]
            gas_consumed: 4710,
            execution_resources: ExecutionResources {
                #[cfg(not(feature = "cairo_1_tests"))]
                n_steps: 118,
                #[cfg(feature = "cairo_1_tests")]
                n_steps: 121,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::from([("range_check_builtin".to_string(), 3)]),
            },
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
        execution_resources: ExecutionResources {
            n_steps: 21,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(RANGE_CHECK_BUILTIN_NAME.to_string(), 1)]),
        },
        ..Default::default()
    }
}

fn expected_fib_validate_call_info_2() -> CallInfo {
    CallInfo {
        caller_address: Address(Felt252::zero()),
        call_type: Some(CallType::Call),
        contract_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        class_hash: Some(felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone())),
        entry_point_selector: Some(VALIDATE_ENTRY_POINT_SELECTOR.clone()),
        entry_point_type: Some(EntryPointType::External),
        calldata: vec![
            Felt252::from(27728),
            Felt252::from_bytes_be(&calculate_sn_keccak(b"fib")),
            Felt252::from(3),
            Felt252::from(42),
            Felt252::from(0),
            Felt252::from(0),
        ],
        execution_resources: ExecutionResources {
            n_steps: 21,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([("range_check_builtin".to_string(), 1)]),
        },
        ..Default::default()
    }
}

fn expected_transaction_execution_info(block_context: &BlockContext) -> TransactionExecutionInfo {
    let resources = HashMap::from([
        ("pedersen_builtin".to_string(), 16),
        ("l1_gas_usage".to_string(), 0),
        ("range_check_builtin".to_string(), 72),
    ]);
    let fee = calculate_tx_fee(&resources, *GAS_PRICE, block_context).unwrap();
    TransactionExecutionInfo::new(
        Some(expected_validate_call_info_2()),
        Some(expected_execute_call_info()),
        Some(expected_fee_transfer_info(fee)),
        fee,
        resources,
        Some(TransactionType::InvokeFunction),
    )
}

fn expected_fib_transaction_execution_info(
    block_context: &BlockContext,
) -> TransactionExecutionInfo {
    let resources = HashMap::from([
        ("l1_gas_usage".to_string(), 4896),
        ("pedersen_builtin".to_string(), 16),
        ("range_check_builtin".to_string(), 75),
    ]);
    let fee = calculate_tx_fee(&resources, *GAS_PRICE, block_context).unwrap();
    TransactionExecutionInfo::new(
        Some(expected_fib_validate_call_info_2()),
        Some(expected_fib_execute_call_info()),
        Some(expected_fib_fee_transfer_info(fee)),
        fee,
        resources,
        Some(TransactionType::InvokeFunction),
    )
}

#[test]
fn test_invoke_tx() {
    let (block_context, state) = &mut create_account_tx_test_state().unwrap();
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
    let result = invoke_tx.execute(state, block_context, 0).unwrap();
    let expected_execution_info = expected_transaction_execution_info(block_context);

    assert_eq!(result, expected_execution_info);
}

#[test]
fn test_invoke_tx_state() {
    let (starknet_general_context, state) = &mut create_account_tx_test_state().unwrap();
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

    let result = invoke_tx
        .execute(state, starknet_general_context, 0)
        .unwrap();

    let expected_final_state = expected_state_after_tx(result.actual_fee);

    assert_eq!(*state, expected_final_state);
}

#[test]
fn test_invoke_with_declarev2_tx() {
    let (block_context, state) = &mut create_account_tx_test_state().unwrap();
    let expected_initial_state = expected_state_before_tx();
    assert_eq!(state, &expected_initial_state);

    // Declare the fibonacci contract
    let declare_tx = declarev2_tx();
    declare_tx.execute(state, block_context).unwrap();

    // Deploy the fibonacci contract
    let deploy = deploy_fib_syscall();
    deploy.execute(state, block_context).unwrap();

    let Address(test_contract_address) = TEST_FIB_CONTRACT_ADDRESS.clone();
    let calldata = vec![
        test_contract_address,                                // CONTRACT ADDRESS
        Felt252::from_bytes_be(&calculate_sn_keccak(b"fib")), // CONTRACT FUNCTION SELECTOR
        Felt252::from(3),                                     // CONTRACT CALLDATA LEN
        Felt252::from(42),                                    // a
        Felt252::from(0),                                     // b
        Felt252::from(0),                                     // n
    ];
    let invoke_tx = invoke_tx(calldata);

    let expected_gas_consumed = 4908;
    let result = invoke_tx
        .execute(state, block_context, expected_gas_consumed)
        .unwrap();

    let expected_execution_info = expected_fib_transaction_execution_info(block_context);
    assert_eq!(result, expected_execution_info);
}

#[test]
fn test_deploy_account() {
    let (block_context, mut state) = create_account_tx_test_state().unwrap();

    let expected_fee = 3684;

    let deploy_account_tx = DeployAccount::new(
        felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
        expected_fee,
        TRANSACTION_VERSION.clone(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        StarknetChainId::TestNet.to_felt(),
    )
    .unwrap();

    state.set_storage_at(
        &(
            block_context
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY),
        ),
        INITIAL_BALANCE.clone(),
    );

    let (state_before, state_after) = expected_deploy_account_states();

    assert_eq!(state, state_before);

    // Statement **not** in blockifier.
    state.cache_mut().nonce_initial_values_mut().insert(
        deploy_account_tx.contract_address().clone(),
        Felt252::zero(),
    );

    let tx_info = deploy_account_tx
        .execute(&mut state, &block_context)
        .unwrap();

    assert_eq!(state.contract_classes(), state_after.contract_classes());
    assert_eq!(
        state.casm_contract_classes(),
        state_after.casm_contract_classes()
    );
    assert_eq!(state.state_reader, state_after.state_reader);
    assert_eq!(state.cache(), state_after.cache());

    let expected_validate_call_info = expected_validate_call_info(
        VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
        [
            Felt252::from_bytes_be(deploy_account_tx.class_hash()),
            deploy_account_tx.contract_address_salt().clone(),
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
        class_hash: Some(TEST_ACCOUNT_CONTRACT_CLASS_HASH.to_be_bytes()),
        call_type: Some(CallType::Call),

        ..Default::default()
    };

    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        &block_context,
        deploy_account_tx.contract_address(),
        expected_fee as u64,
    );

    let resources = HashMap::from([
        ("range_check_builtin".to_string(), 74),
        ("pedersen_builtin".to_string(), 23),
        ("l1_gas_usage".to_string(), 3672),
    ]);

    let fee = calculate_tx_fee(&resources, *GAS_PRICE, &block_context).unwrap();

    assert_eq!(fee, expected_fee);

    let expected_execution_info = TransactionExecutionInfo::new(
        expected_validate_call_info.into(),
        expected_execute_call_info.into(),
        expected_fee_transfer_call_info.into(),
        fee,
        // Entry **not** in blockifier.
        // Default::default(),
        resources,
        TransactionType::DeployAccount.into(),
    );
    assert_eq!(tx_info, expected_execution_info);

    let nonce_from_state = state
        .get_nonce_at(deploy_account_tx.contract_address())
        .unwrap();
    assert_eq!(nonce_from_state, Felt252::one());

    let hash = TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY.to_be_bytes();

    validate_final_balances(&mut state, &block_context, &hash, fee);

    let class_hash_from_state = state
        .get_class_hash_at(deploy_account_tx.contract_address())
        .unwrap();
    assert_eq!(class_hash_from_state, *deploy_account_tx.class_hash());
}

fn expected_deploy_account_states() -> (
    CachedState<InMemoryStateReader>,
    CachedState<InMemoryStateReader>,
) {
    let fee = Felt252::from(3684);
    let mut state_before = CachedState::new(
        Arc::new(InMemoryStateReader::new(
            HashMap::from([
                (Address(0x101.into()), felt_to_hash(&0x111.into())),
                (Address(0x100.into()), felt_to_hash(&0x110.into())),
                (Address(0x1001.into()), felt_to_hash(&0x1010.into())),
            ]),
            HashMap::from([
                (Address(0x101.into()), Default::default()),
                (Address(0x100.into()), Default::default()),
                (Address(0x1001.into()), Default::default()),
            ]),
            HashMap::from([(
                (
                    Address(0x1001.into()),
                    felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY),
                ),
                INITIAL_BALANCE.clone(),
            )]),
            HashMap::from([
                (
                    felt_to_hash(&0x110.into()),
                    ContractClass::from_path(TEST_CONTRACT_PATH).unwrap(),
                ),
                (
                    felt_to_hash(&0x111.into()),
                    ContractClass::from_path(ACCOUNT_CONTRACT_PATH).unwrap(),
                ),
                (
                    felt_to_hash(&0x1010.into()),
                    ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap(),
                ),
            ]),
            HashMap::new(),
            HashMap::new(),
        )),
        Some(ContractClassCache::new()),
        Some(HashMap::new()),
    );
    state_before.set_storage_at(
        &(
            Address(0x1001.into()),
            felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY),
        ),
        INITIAL_BALANCE.clone(),
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
            felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY),
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
            felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY),
        ),
        INITIAL_BALANCE.clone() - &fee,
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
            felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY),
        ),
        fee,
    );
    state_after
        .set_contract_class(
            &felt_to_hash(&0x1010.into()),
            &ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap(),
        )
        .unwrap();
    state_after
        .set_contract_class(
            &felt_to_hash(&0x111.into()),
            &ContractClass::from_path(ACCOUNT_CONTRACT_PATH).unwrap(),
        )
        .unwrap();

    (state_before, state_after)
}

#[test]
fn test_state_for_declare_tx() {
    let (block_context, mut state) = create_account_tx_test_state().unwrap();

    let declare_tx = declare_tx();
    // Check ContractClass is not set before the declare_tx
    assert!(state.get_contract_class(&declare_tx.class_hash).is_err());
    assert!(state
        .get_nonce_at(&declare_tx.sender_address)
        .unwrap()
        .is_zero());
    // Execute declare_tx
    assert!(declare_tx.execute(&mut state, &block_context).is_ok());
    assert!(state
        .get_nonce_at(&declare_tx.sender_address)
        .unwrap()
        .is_one());

    // Check state.state_reader
    let state_reader = state.state_reader.clone();

    assert_eq!(
        state_reader.address_to_class_hash,
        HashMap::from([
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
        state_reader.address_to_nonce,
        HashMap::from([
            (TEST_ERC20_CONTRACT_ADDRESS.clone(), Felt252::zero()),
            (TEST_CONTRACT_ADDRESS.clone(), Felt252::zero()),
            (TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), Felt252::zero()),
        ]),
    );

    assert_eq!(
        state_reader.address_to_storage,
        HashMap::from([(
            (
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY)
            ),
            INITIAL_BALANCE.clone()
        ),]),
    );

    assert_eq!(
        state_reader.class_hash_to_contract_class,
        HashMap::from([
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_CLASS_HASH),
                ContractClass::from_path(TEST_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                ContractClass::from_path(ACCOUNT_CONTRACT_PATH).unwrap()
            ),
        ])
    );

    let fee = Felt252::from(10);

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
            HashMap::new(),
            HashMap::from([(TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), 0.into())]),
            HashMap::from([
                (
                    (
                        TEST_ERC20_CONTRACT_ADDRESS.clone(),
                        felt_to_hash(&TEST_ERC20_BALANCE_KEY_2)
                    ),
                    0.into()
                ),
                (
                    (
                        TEST_ERC20_CONTRACT_ADDRESS.clone(),
                        felt_to_hash(&TEST_ERC20_BALANCE_KEY_1)
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
                    INITIAL_BALANCE.clone()
                )
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(TEST_ACCOUNT_CONTRACT_ADDRESS.clone(), 1.into())]),
            HashMap::from([
                (
                    (
                        TEST_ERC20_CONTRACT_ADDRESS.clone(),
                        felt_to_hash(&TEST_ERC20_BALANCE_KEY_2)
                    ),
                    0.into()
                ),
                (
                    (
                        TEST_ERC20_CONTRACT_ADDRESS.clone(),
                        felt_to_hash(&TEST_ERC20_BALANCE_KEY_1)
                    ),
                    0.into()
                ),
                (
                    (
                        TEST_ERC20_CONTRACT_ADDRESS.clone(),
                        felt_to_hash(&TEST_ERC20_SEQUENCER_BALANCE_KEY)
                    ),
                    fee.clone(),
                ),
                (
                    (
                        TEST_ERC20_CONTRACT_ADDRESS.clone(),
                        felt_to_hash(&TEST_ERC20_ACCOUNT_BALANCE_KEY)
                    ),
                    INITIAL_BALANCE.clone() - &fee,
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
                ContractClass::from_path(TEST_EMPTY_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_ERC20_CONTRACT_CLASS_HASH),
                ContractClass::from_path(ERC20_CONTRACT_PATH).unwrap()
            ),
            (
                felt_to_hash(&TEST_ACCOUNT_CONTRACT_CLASS_HASH),
                ContractClass::from_path(ACCOUNT_CONTRACT_PATH).unwrap()
            ),
        ]))
    );
}

#[test]
fn test_invoke_tx_wrong_call_data() {
    let (starknet_general_context, state) = &mut create_account_tx_test_state().unwrap();

    // Calldata with missing inputs
    let calldata = vec![
        TEST_CONTRACT_ADDRESS.clone().0, // CONTRACT_ADDRESS
        Felt252::from_bytes_be(&calculate_sn_keccak(b"return_result")), // CONTRACT FUNCTION SELECTOR
        Felt252::from(1),                                               // CONTRACT_CALLDATA LEN
                                                                        // CONTRACT_CALLDATA
    ];
    let invoke_tx = invoke_tx(calldata);

    // Execute transaction
    let result = invoke_tx.execute(state, starknet_general_context, 0);

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
    let (starknet_general_context, state) = &mut create_account_tx_test_state().unwrap();
    let Address(test_contract_address) = TEST_CONTRACT_ADDRESS.clone();

    // Invoke transaction with an entrypoint that doesn't exists
    let invoke_tx = InvokeFunction::new(
        TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        // Entrypoiont that doesnt exits in the contract
        Felt252::from_bytes_be(&calculate_sn_keccak(b"none_function")),
        1,
        TRANSACTION_VERSION.clone(),
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
    let result = invoke_tx.execute(state, starknet_general_context, 0);

    // Assert error
    assert_matches!(result, Err(TransactionError::EntryPointNotFound));
}

#[test]
fn test_deploy_undeclared_account() {
    let (block_context, mut state) = create_account_tx_test_state().unwrap();

    let not_deployed_class_hash = [1; 32];
    // Deploy transaction with a not_deployed_class_hash class_hash
    let deploy_account_tx = DeployAccount::new(
        not_deployed_class_hash,
        2,
        TRANSACTION_VERSION.clone(),
        Default::default(),
        Default::default(),
        Default::default(),
        Default::default(),
        StarknetChainId::TestNet.to_felt(),
    )
    .unwrap();

    // Check not_deployed_class_hash
    assert!(state.get_contract_class(&not_deployed_class_hash).is_err());

    // Execute transaction
    let result = deploy_account_tx.execute(&mut state, &block_context);

    // Execute transaction
    assert_matches!(
        result,
        Err(TransactionError::State(StateError::NoneCompiledHash(_)))
    );
}

#[test]
fn test_library_call_with_declare_v2() {
    let (block_context, state) = &mut create_account_tx_test_state().unwrap();

    // Declare the fibonacci contract
    let declare_tx = declarev2_tx();
    declare_tx.execute(state, block_context).unwrap();

    // Deploy the fibonacci contract
    let deploy = deploy_fib_syscall();
    deploy.execute(state, block_context).unwrap();

    //  Create program and entry point types for contract class
    #[cfg(not(feature = "cairo_1_tests"))]
    let program_data = include_bytes!("../starknet_programs/cairo2/fibonacci_dispatcher.casm");
    #[cfg(feature = "cairo_1_tests")]
    let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci_dispatcher.casm");
    let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
    let entrypoints = contract_class.clone().entry_points_by_type;
    let external_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

    let address = Address(6666.into());
    let mut class_hash: ClassHash = [0; 32];
    class_hash[0] = 1;
    let nonce = Felt252::zero();

    state
        .cache_mut()
        .class_hash_initial_values_mut()
        .insert(address.clone(), class_hash);

    state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(address.clone(), nonce);

    state
        .set_compiled_class(&Felt252::from_bytes_be(&class_hash), contract_class)
        .unwrap();

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
            1000000000,
        )
    };

    // Create an execution entry point
    let calldata = vec![
        TEST_FIB_COMPILED_CONTRACT_CLASS_HASH.clone(),
        Felt252::from_bytes_be(&calculate_sn_keccak(b"fib")),
        1.into(),
        1.into(),
        10.into(),
    ];
    let send_message_exec_entry_point = create_execute_extrypoint(
        external_entrypoint_selector,
        calldata.clone(),
        EntryPointType::External,
    );

    // Execute the entrypoint
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        100000000,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    // Run send_msg entrypoint
    let call_info = send_message_exec_entry_point
        .execute(
            state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
        )
        .unwrap();

    let expected_internal_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: address.clone(),
        class_hash: Some(TEST_FIB_COMPILED_CONTRACT_CLASS_HASH.clone().to_be_bytes()),
        entry_point_selector: Some(external_entrypoint_selector.into()),
        entry_point_type: Some(EntryPointType::External),
        #[cfg(not(feature = "cairo_1_tests"))]
        gas_consumed: 30080,
        #[cfg(feature = "cairo_1_tests")]
        gas_consumed: 30410,
        calldata: vec![1.into(), 1.into(), 10.into()],
        retdata: vec![89.into()], // fib(10)
        execution_resources: ExecutionResources {
            #[cfg(not(feature = "cairo_1_tests"))]
            n_steps: 368,
            #[cfg(feature = "cairo_1_tests")]
            n_steps: 371,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([("range_check_builtin".to_string(), 13)]),
        },
        ..Default::default()
    };

    let expected_call_info = CallInfo {
        caller_address: Address(0.into()),
        call_type: Some(CallType::Delegate),
        contract_address: address.clone(),
        class_hash: Some(class_hash),
        entry_point_selector: Some(external_entrypoint_selector.into()),
        entry_point_type: Some(EntryPointType::External),
        #[cfg(not(feature = "cairo_1_tests"))]
        gas_consumed: 112490,
        #[cfg(feature = "cairo_1_tests")]
        gas_consumed: 113480,
        calldata,
        retdata: vec![89.into()], // fib(10)
        execution_resources: ExecutionResources {
            #[cfg(not(feature = "cairo_1_tests"))]
            n_steps: 578,
            #[cfg(feature = "cairo_1_tests")]
            n_steps: 587,
            n_memory_holes: 1,
            builtin_instance_counter: HashMap::from([("range_check_builtin".to_string(), 16)]),
        },
        internal_calls: vec![expected_internal_call_info],
        ..Default::default()
    };

    assert_eq!(call_info, expected_call_info);
}
