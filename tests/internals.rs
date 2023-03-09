use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        execution::objects::{CallType, OrderedEvent},
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{cached_state::CachedState, state_api::StateReader, state_api_objects::BlockInfo},
        transaction::objects::internal_declare::InternalDeclare,
    },
    definitions::{
        constants::{TRANSFER_ENTRY_POINT_SELECTOR, VALIDATE_DECLARE_ENTRY_POINT_NAME},
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
            Address(TEST_ERC20_CONTRACT_ADDRESS.clone()),
            0,
        ),
        0,
        0,
        1_000_000,
        BlockInfo::empty(Address(TEST_SEQUENCER_ADDRESS.clone())),
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
            let mut state_reader = InMemoryStateReader::default();

            for (contract_address, class_hash) in address_to_class_hash {
                let storage_keys: HashMap<(Address, [u8; 32]), Felt> = dbg!(storage_view
                    .iter()
                    .filter_map(|((address, storage_key), storage_value)| {
                        (address == &contract_address).then_some((
                            (address.clone(), felt_to_hash(&storage_key)),
                            storage_value.clone(),
                        ))
                    }))
                .collect();

                let h: HashMap<StorageEntry, Felt> = HashMap::from(storage_keys);

                state_reader
                    .address_to_class_hash
                    .insert(contract_address.clone(), felt_to_hash(&class_hash.clone())); // or maybe insert address_to_class_hash
                state_reader
                    .address_to_nonce
                    .insert(contract_address.clone(), Felt::zero());
                state_reader.address_to_storage.extend(h);
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
        vec![2.into(), 0.into()]
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
