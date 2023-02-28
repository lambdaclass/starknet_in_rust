use felt::{felt_str, Felt};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_rs::{
    business_logic::{
        fact_state::{contract_state::ContractState, in_memory_state_reader::InMemoryStateReader},
        state::cached_state::CachedState,
    },
    definitions::general_config::StarknetGeneralConfig,
    services::api::contract_class::ContractClass,
    starknet_storage::{
        dict_storage::{DictStorage, Prefix},
        storage::Storage,
    },
    utils::{felt_to_hash, Address},
};
use std::{collections::HashMap, path::PathBuf};

const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validations.json";
const ERC20_CONTRACT_PATH: &str = "starknet_programs/erc20_contract_without_some_syscalls.json";
const TEST_CONTRACT_PATH: &str = "starknet_programs/test_contract.json";

lazy_static! {
    // Addresses.
    static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("0x101"));
    static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("0x100"));

    // Class hashes.
    static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt = felt_str!("0x111");
    static ref TEST_CLASS_HASH: Felt = felt_str!("0x110");
    static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt = felt_str!("0x1010");

    // Storage keys.
    static ref TEST_ERC20_ACCOUNT_BALANCE_KEY: Felt =
        felt_str!("0x2a2c49c4dba0d91b34f2ade85d41d09561f9a77884c15ba2ab0f2241b080deb");
    static ref TEST_ERC20_SEQUENCER_BALANCE_KEY: Felt =
        felt_str!("0x723973208639b7839ce298f7ffea61e3f9533872defd7abdb91023db4658812");

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
) -> Result<CachedState<InMemoryStateReader>, Box<dyn std::error::Error>> {
    let general_config = StarknetGeneralConfig::default();

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

    Ok(CachedState::new(
        InMemoryStateReader::new(
            {
                let mut storage = DictStorage::new();

                for (contract_address, class_hash) in address_to_class_hash {
                    let storage_keys = storage_view
                        .iter()
                        .filter_map(|((k0, k1), v)| {
                            (k0 == &contract_address).then_some((felt_to_hash(k1), v.clone()))
                        })
                        .collect();

                    storage.set_value(
                        &(Prefix::ContractState, felt_to_hash(&contract_address.0)),
                        serde_json::to_vec(&ContractState::new(
                            felt_to_hash(&class_hash),
                            Felt::zero(),
                            storage_keys,
                        ))?,
                    )?;
                }

                storage
            },
            DictStorage::new(),
        ),
        Some(
            class_hash_to_class
                .into_iter()
                .map(|(k, v)| (felt_to_hash(&k), v))
                .collect(),
        ),
    ))
}
