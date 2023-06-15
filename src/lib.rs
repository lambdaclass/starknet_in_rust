// #![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

use business_logic::{
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    state::{
        cached_state::CachedState,
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    transaction::{error::TransactionError, Transaction},
};
use definitions::general_config::TransactionContext;
use utils::Address;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

// Re-exports
pub use cairo_lang_starknet::casm_contract_class::CasmContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
pub use cairo_vm::felt::Felt252;
pub use starknet_contract_class::EntryPointType;

pub mod business_logic;
pub mod core;
pub mod definitions;
pub mod hash_utils;
pub mod parser_errors;
pub mod runner;
pub mod serde_structs;
pub mod services;
pub mod storage;
pub mod syscalls;
pub mod testing;
pub mod utils;

/// Estimate the fee associated with transaction
pub fn estimate_fee<T>(
    transaction: &Transaction,
    state: T,
) -> Result<(u128, usize), TransactionError>
where
    T: StateReader + std::fmt::Debug,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T> {
        state_reader: state,
        cache: Default::default(),
        contract_classes: Default::default(),
        casm_contract_classes: Default::default(),
    };

    println!("cached state copy created: {:?}", cached_state);

    // Check if the contract is deployed.
    cached_state.get_class_hash_at(&transaction.contract_address())?;

    // execute the transaction with the fake state.
    let transaction_result =
        transaction.execute(&mut cached_state, &TransactionContext::default(), 1_000_000)?;

    if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
        let actual_fee = transaction_result.actual_fee;
        Ok((actual_fee, *gas_usage))
    } else {
        Err(TransactionError::ResourcesError)
    }
}
pub fn call_contract<T: State + StateReader>(
    contract_address: Felt252,
    entrypoint_selector: Felt252,
    calldata: Vec<Felt252>,
    state: &mut T,
    config: TransactionContext,
) -> Result<Vec<Felt252>, TransactionError> {
    let contract_address = Address(contract_address);
    let class_hash = state.get_class_hash_at(&contract_address)?;
    let nonce = state.get_nonce_at(&contract_address)?;

    // TODO: Revisit these parameters
    let transaction_hash = 0.into();
    let signature = vec![];
    let max_fee = 1000000000;
    let initial_gas = 1000000000;
    let caller_address = Address(0.into());
    let version = 0;

    let execution_entrypoint = ExecutionEntryPoint::new(
        contract_address.clone(),
        calldata,
        entrypoint_selector,
        caller_address,
        EntryPointType::External,
        Some(CallType::Delegate),
        Some(class_hash),
        initial_gas,
    );

    let tx_execution_context = TransactionExecutionContext::new(
        contract_address,
        transaction_hash,
        signature,
        max_fee,
        nonce,
        config.invoke_tx_max_n_steps(),
        version.into(),
    );

    let call_info = execution_entrypoint.execute(
        state,
        &config,
        &mut ExecutionResourcesManager::default(),
        &tx_execution_context,
        false,
    )?;

    Ok(call_info.retdata)
}

pub fn execute_transaction<T: State + StateReader>(
    tx: Transaction,
    state: &mut T,
    config: TransactionContext,
    remaining_gas: u128,
) -> Result<TransactionExecutionInfo, TransactionError> {
    tx.execute(state, &config, remaining_gas)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_vm::felt::{Felt252, felt_str};
    use num_traits::Zero;
    use starknet_contract_class::EntryPointType;

    use crate::business_logic::state::BlockInfo;
    use crate::business_logic::state::state_cache::StorageEntry;
    use crate::business_logic::transaction::Transaction;
    use crate::definitions::constants::DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS;
    use crate::definitions::general_config::StarknetOsConfig;
    use crate::services::api::contract_classes::deprecated_contract_class::ContractClass;
    use crate::utils::felt_to_hash;
    use crate::{
        business_logic::{
            state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader},
            transaction::InvokeFunction,
        },
        call_contract,
        definitions::general_config::{StarknetChainId, TransactionContext},
        estimate_fee,
        utils::{Address, ClassHash},
    };
    use lazy_static::lazy_static;

    const ACCOUNT_CONTRACT_PATH: &str = "starknet_programs/account_without_validation.json";
    const ERC20_CONTRACT_PATH: &str = "starknet_programs/ERC20.json";
    const TEST_CONTRACT_PATH: &str = "starknet_programs/fibonacci.json";

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
        static ref TEST_FIB_COMPILED_CONTRACT_CLASS_HASH: Felt252 = felt_str!("27727");

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

    pub fn new_starknet_general_config_for_testing() -> TransactionContext {
        TransactionContext::new(
            StarknetOsConfig::new(
                StarknetChainId::TestNet,
                TEST_ERC20_CONTRACT_ADDRESS.clone(),
                0,
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

    fn get_contract_class<P>(path: P) -> Result<ContractClass, Box<dyn std::error::Error>>
where
    P: Into<PathBuf>,
{
    Ok(ContractClass::try_from(path.into())?)
}

    fn create_account_tx_test_state(
    ) -> Result<(TransactionContext, CachedState<InMemoryStateReader>), Box<dyn std::error::Error>> {
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
            Some(HashMap::new()),
        );
    
        Ok((general_config, cached_state))
    }
    

    #[test]
    fn estimate_fee_test() {
        let contract_class: ContractClass = ContractClass::try_from(PathBuf::from(TEST_CONTRACT_PATH)).unwrap();
    
        let entrypoints = contract_class.clone().entry_points_by_type;
        let entrypoint_selector = &entrypoints.get(&EntryPointType::External).unwrap()[0].selector;
        println!("entrypoint selector: {:?}", entrypoint_selector);

        let (_transaction_context, state) = create_account_tx_test_state().unwrap();
    
        println!("state: {:?}", state);
        let calldata = [1.into(), 1.into(), 10.into()].to_vec();
        let invoke_function = InvokeFunction::new(
            TEST_CONTRACT_ADDRESS.clone(),
            entrypoint_selector.clone(),
            100_000_000,
            1.into(),
            calldata,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            Some(0.into()),
            None,
        )
        .unwrap();
        let transaction = Transaction::InvokeFunction(invoke_function);

        let estimated_fee = estimate_fee(&transaction, state).unwrap();
        assert_eq!(estimated_fee, (0, 0))
    }

    #[test]
    fn call_contract_fibonacci_with_10_should_return_89() {
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");
        let contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();
        let entrypoints = contract_class.clone().entry_points_by_type;
        let entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

        let mut contract_class_cache = HashMap::new();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::zero();

        contract_class_cache.insert(class_hash, contract_class);
        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        let mut state = CachedState::new(state_reader, None, Some(contract_class_cache));
        let calldata = [1.into(), 1.into(), 10.into()].to_vec();

        let retdata = call_contract(
            address.0,
            entrypoint_selector.into(),
            calldata,
            &mut state,
            TransactionContext::default(),
        )
        .unwrap();

        assert_eq!(retdata, vec![89.into()]);
    }
}
