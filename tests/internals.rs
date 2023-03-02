use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::{One, ToPrimitive, Zero};
use starknet_rs::{
    business_logic::{
        execution::objects::{CallInfo, OrderedEvent, TransactionExecutionInfo},
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
        },
        transaction::internal_objects::InternalDeployAccount,
    },
    definitions::{
        constants::{
            CONSTRUCTOR_ENTRY_POINT_SELECTOR, TRANSACTION_VERSION, TRANSFER_ENTRY_POINT_SELECTOR,
            TRANSFER_EVENT_SELECTOR, VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR,
        },
        general_config::{StarknetChainId, StarknetGeneralConfig},
        transaction_type::TransactionType,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    utils::{felt_to_hash, Address},
};
use std::{collections::HashMap, path::PathBuf};

const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
const TEST_CONTRACT_PATH: &str = "starknet_programs/test_contract.json";

lazy_static! {
    // Addresses.
    static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("257"));
    static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("256"));

    // Class hashes.
    static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt = felt_str!("273");
    static ref TEST_CLASS_HASH: Felt = felt_str!("272");
    static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt = felt_str!("4112");

    // Storage keys.
    static ref TEST_ERC20_ACCOUNT_BALANCE_KEY: Felt =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617515");
    static ref TEST_ERC20_SEQUENCER_BALANCE_KEY: Felt =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768274");

    static ref TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY: Felt =
        felt_str!("2542253978940891427830343982984992363331567580652119103860970381451088310289");

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
            felt_to_hash(&*TEST_ERC20_ACCOUNT_BALANCE_KEY),
        ))
        .unwrap();
    assert_eq!(value, &2.into());

    let class_hash = state.get_class_hash_at(&*TEST_CONTRACT_ADDRESS).unwrap();
    assert_eq!(class_hash, &felt_to_hash(&*TEST_CLASS_HASH));

    let contract_class = state
        .get_contract_class(&felt_to_hash(&*TEST_ERC20_CONTRACT_CLASS_HASH))
        .unwrap();
    assert_eq!(
        contract_class,
        get_contract_class(ERC20_CONTRACT_PATH).unwrap()
    );
}

#[test]
fn test_deploy_account() {
    let (general_config, mut state) = create_account_tx_test_state().unwrap();

    let deploy_account_tx = InternalDeployAccount::new(
        felt_to_hash(&*TEST_ACCOUNT_CONTRACT_CLASS_HASH),
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

    let tx_info = deploy_account_tx
        ._apply_specific_concurrent_changes(&mut state, &general_config)
        .unwrap();

    let expected_validate_call_info = expected_validate_call_info(
        VALIDATE_DEPLOY_ENTRY_POINT_SELECTOR.clone(),
        [
            Felt::from_bytes_be(&deploy_account_tx.class_hash),
            deploy_account_tx.contract_address_salt.0.clone(),
        ]
        .into_iter()
        .chain(deploy_account_tx.constructor_calldata.clone())
        .collect(),
        deploy_account_tx.contract_address.clone(),
    );

    let expected_execute_call_info = CallInfo {
        entry_point_type: EntryPointType::Constructor.into(),
        entry_point_selector: CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone().into(),
        contract_address: deploy_account_tx.contract_address.clone(),
        ..Default::default()
    };

    let expected_fee_transfer_call_info = expected_fee_transfer_call_info(
        &general_config,
        &deploy_account_tx.contract_address,
        ACTUAL_FEE.to_u64().unwrap(),
    );

    let expected_execution_info = TransactionExecutionInfo::new(
        expected_validate_call_info.into(),
        expected_execute_call_info.into(),
        expected_fee_transfer_call_info.into(),
        ACTUAL_FEE.to_u64().unwrap(),
        Default::default(),
        TransactionType::DeployAccount.into(),
    );
    assert_eq!(tx_info, expected_execution_info);

    let nonce_from_state = state
        .get_nonce_at(&deploy_account_tx.contract_address)
        .unwrap();
    assert_eq!(nonce_from_state, &Felt::one());

    validate_final_balances(
        &mut state,
        &general_config,
        &Felt::zero(),
        &felt_to_hash(&TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY),
    );

    let class_hash_from_state = state
        .get_class_hash_at(&deploy_account_tx.contract_address)
        .unwrap();
    assert_eq!(class_hash_from_state, &deploy_account_tx.class_hash);
}
