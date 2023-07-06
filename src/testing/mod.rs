pub mod erc20;
pub mod state;
pub mod state_error;
pub mod type_utils;

use std::collections::HashMap;

use cairo_vm::felt::{felt_str, Felt252};
use lazy_static::lazy_static;
use num_traits::Zero;

use crate::{
    definitions::{
        block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
        constants::DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS,
    },
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{
        cached_state::CachedState, in_memory_state_reader::InMemoryStateReader,
        state_cache::StorageEntry, BlockInfo,
    },
    utils::{felt_to_hash, Address, ClassHash},
};

pub const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
pub const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
pub const TEST_CONTRACT_PATH: &str = "starknet_programs/fibonacci.json";

lazy_static! {
    // Addresses.
    pub static ref TEST_ACCOUNT_CONTRACT_ADDRESS: Address = Address(felt_str!("257"));
    pub static ref TEST_CONTRACT_ADDRESS: Address = Address(felt_str!("256"));
    pub static ref TEST_SEQUENCER_ADDRESS: Address =
    Address(felt_str!("4096"));
    pub static ref TEST_ERC20_CONTRACT_ADDRESS: Address =
    Address(felt_str!("4097"));


    // Class hashes.
    pub static ref TEST_ACCOUNT_CONTRACT_CLASS_HASH: Felt252 = felt_str!("273");
    pub static ref TEST_CLASS_HASH: Felt252 = felt_str!("272");
    pub static ref TEST_EMPTY_CONTRACT_CLASS_HASH: Felt252 = felt_str!("274");
    pub static ref TEST_ERC20_CONTRACT_CLASS_HASH: Felt252 = felt_str!("4112");
    pub static ref TEST_FIB_COMPILED_CONTRACT_CLASS_HASH: Felt252 = felt_str!("27727");

    // Storage keys.
    pub static ref TEST_ERC20_ACCOUNT_BALANCE_KEY: Felt252 =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617515");
    pub static ref TEST_ERC20_SEQUENCER_BALANCE_KEY: Felt252 =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768274");
    pub static ref TEST_ERC20_BALANCE_KEY_1: Felt252 =
        felt_str!("1192211877881866289306604115402199097887041303917861778777990838480655617516");
    pub static ref TEST_ERC20_BALANCE_KEY_2: Felt252 =
        felt_str!("3229073099929281304021185011369329892856197542079132996799046100564060768275");

    pub static ref TEST_ERC20_DEPLOYED_ACCOUNT_BALANCE_KEY: Felt252 =
        felt_str!("2542253978940891427830343982984992363331567580652119103860970381451088310289");

    // Others.
    // Blockifier had this value hardcoded to 2.
    pub static ref ACTUAL_FEE: Felt252 = Felt252::from(10000000);
}

pub fn new_starknet_block_context_for_testing() -> BlockContext {
    BlockContext::new(
        StarknetOsConfig::new(
            StarknetChainId::TestNet,
            TEST_ERC20_CONTRACT_ADDRESS.clone(),
            1,
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

pub fn create_account_tx_test_state(
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
        Some(HashMap::new()),
    );

    Ok((block_context, cached_state))
}
