use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::{One, ToPrimitive, Zero};
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, CallType, OrderedEvent, TransactionExecutionInfo},
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
            state_api_objects::BlockInfo,
        },
        transaction::objects::{
            internal_declare::InternalDeclare, internal_deploy_account::InternalDeployAccount,
        },
    },
    definitions::{
        constants::{
            CONSTRUCTOR_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION, TRANSFER_ENTRY_POINT_SELECTOR,
            TRANSFER_EVENT_SELECTOR, VALIDATE_DECLARE_ENTRY_POINT_SELECTOR,
            VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR,
        },
        general_config::{StarknetChainId, StarknetGeneralConfig, StarknetOsConfig},
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{felt_to_hash, Address},
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
    pub static ref TEST_SEQUENCER_ADDRESS: Felt =
    felt_str!("4096");
pub static ref TEST_ERC20_CONTRACT_ADDRESS: Felt =
    felt_str!("4097");


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

    static ref TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY: Felt =
        felt_str!("2542253978940891427830343982984992363331567580652119103860970381451088310289");

    // Others.
    // Blockifier had this value hardcoded to 2.
    static ref ACTUAL_FEE: Felt = Felt::zero();
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
            Address(TEST_ERC20_CONTRACT_ADDRESS.clone()),
            0,
        ),
        0,
        0,
        1_000_000,
        BlockInfo::empty(Address(TEST_SEQUENCER_ADDRESS.clone())),
    )
}

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
    let test_erc20_sequencer_balance_key = TEST_ERC20_SEQUENCER_BALANCE_KEY.clone();
    let storage_view = HashMap::from([
        (
            (test_erc20_address.clone(), test_erc20_sequencer_balance_key),
            Felt::zero(),
        ),
        (
            (test_erc20_address, test_erc20_account_balance_key),
            ACTUAL_FEE.clone(),
        ),
    ]);

    let cached_state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());

            for (contract_address, class_hash) in address_to_class_hash {
                let storage_keys = storage_view
                    .iter()
                    .filter_map(|((k0, k1), v)| {
                        (k0 == &contract_address).then_some((k1.clone(), v.clone()))
                    })
                    .collect();

                state_reader.contract_states_mut().insert(
                    contract_address,
                    ContractState::new(felt_to_hash(&class_hash), Felt::zero(), storage_keys),
                );
            }

            state_reader
        },
        Some(
            class_hash_to_class
                .into_iter()
                .map(|(k, v)| (felt_to_hash(&k), v))
                .collect(),
        ),
    );

    Ok((general_config, cached_state))
}

fn expected_validate_call_info(
    entry_point_selector: Felt,
    calldata: Vec<Felt>,
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
            Felt::zero(),
        ],
        contract_address: general_config
            .starknet_os_config()
            .fee_token_address()
            .clone(),
        caller_address: account_address.clone(),
        retdata: vec![Felt::one()],
        events: vec![OrderedEvent {
            order: 0,
            keys: vec![TRANSFER_EVENT_SELECTOR.clone()],
            data: vec![
                account_address.0.clone(),
                general_config.block_info().sequencer_address.0.clone(),
                actual_fee.into(),
                Felt::zero(),
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
        storage_read_values: vec![Felt::zero(), Felt::zero()],

        ..Default::default()
    }
}

fn validate_final_balances<S>(
    state: &mut S,
    general_config: &StarknetGeneralConfig,
    expected_sequencer_balance: &Felt,
    erc20_account_balance_storage_key: &[u8; 32],
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
    assert_eq!(account_balance, &Felt::zero());

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
#[test]
fn test_declare_tx() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

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
        Some(VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone())
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
        vec![TEST_SEQUENCER_ADDRESS.clone(), 0.into(), 0.into()]
    );

    assert_eq!(
        fee_transfer_info.contract_address,
        Address(TEST_ERC20_CONTRACT_ADDRESS.clone())
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
                TEST_SEQUENCER_ADDRESS.clone(),
                0.into(),
                0.into()
            ]
        )]
    );

    assert_eq!(fee_transfer_info.internal_calls, Vec::new());

    assert_eq!(
        fee_transfer_info.storage_read_values,
        vec![0.into(), 0.into()]
    );
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

    // Statement **not** in blockifier.
    state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(deploy_account_tx.contract_address().clone(), Felt::zero());

    let tx_info = deploy_account_tx
        .execute(&mut state, &general_config)
        .unwrap();

    let expected_validate_call_info = expected_validate_call_info(
        VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
        [
            Felt::from_bytes_be(deploy_account_tx.class_hash()),
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
        [("l1_gas_usage", 3672)]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        TransactionType::DeployAccount.into(),
    );
    assert_eq!(tx_info, expected_execution_info);

    let nonce_from_state = state
        .get_nonce_at(deploy_account_tx.contract_address())
        .unwrap();
    assert_eq!(nonce_from_state, &Felt::one());

    validate_final_balances(
        &mut state,
        &general_config,
        &Felt::zero(),
        &felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY),
    );

    let class_hash_from_state = state
        .get_class_hash_at(deploy_account_tx.contract_address())
        .unwrap();
    assert_eq!(class_hash_from_state, deploy_account_tx.class_hash());
}
