use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{cached_state::CachedState, state_api::StateReader},
        transaction::objects::internal_declare::InternalDeclare,
    },
    definitions::{general_config::StarknetGeneralConfig, transaction_type::TransactionType},
    services::api::contract_class::ContractClass,
    utils::{felt_to_hash, Address},
};
use std::{collections::HashMap, path::PathBuf};

const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
const TEST_CONTRACT_PATH: &str = "starknet_programs/test_contract.json";
const TEST_EMPTY_CONTRACT_PATH: &str = "starknet_programs/empty_contract.json";

lazy_static! {
    // Addresses.
    static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("257"));
    static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("256"));

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

#[allow(dead_code)]
fn create_account_tx_test_state(
) -> Result<(StarknetGeneralConfig, CachedState<InMemoryStateReader>), Box<dyn std::error::Error>> {
    let general_config = StarknetGeneralConfig::new_for_testing();

    let test_contract_class_hash = TEST_CLASS_HASH.clone();
    let test_account_class_hash = TEST_ACCOUNT_CONTRACT_CLASS_HASH.clone();
    let test_erc20_class_hash = TEST_ERC20_CONTRACT_CLASS_HASH.clone();
    let test_empty_contract_class_hash = TEST_EMPTY_CONTRACT_CLASS_HASH.clone();
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
        // (
        //     test_empty_contract_class_hash.clone(),
        //     get_contract_class(TEST_EMPTY_CONTRACT_PATH)?,
        // ),
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

    // let contract_class2 = state
    //     .get_contract_class(&felt_to_hash(&*TEST_EMPTY_CONTRACT_CLASS_HASH))
    //     .unwrap();
    // assert_eq!(
    //     contract_class2,
    //     get_contract_class(TEST_EMPTY_CONTRACT_PATH).unwrap()
    // );
}
fn declare_tx() -> InternalDeclare {
    InternalDeclare {
        class_hash: felt_to_hash(&*TEST_EMPTY_CONTRACT_CLASS_HASH),
        sender_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
        tx_type: TransactionType::Declare,
        validate_entry_point_selector: felt_str!(
            "1148189391774113786911959041662034419554430000171893651982484995704491697075"
        ),
        version: 0,
        max_fee: 0,
        signature: vec![],
        nonce: 0.into(),
        hash_value: 0.into(),
    }
}
#[test]
fn test_declare_tx() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    let declare_tx = declare_tx();
    assert!(state.get_contract_class(&declare_tx.class_hash).is_err());
    let result = declare_tx.execute(&mut state, general_config).unwrap();
    dbg!(&result);
    assert!(state.get_contract_class(&declare_tx.class_hash).is_ok());

    todo!()
}
