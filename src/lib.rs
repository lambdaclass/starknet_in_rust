#![deny(warnings)]
#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]
use std::collections::HashMap;

use crate::{
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
        TransactionExecutionInfo,
    },
    state::{
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    transaction::{error::TransactionError, Transaction},
};

use cairo_vm::felt::Felt252;
use definitions::block_context::BlockContext;
use state::cached_state::CachedState;
use transaction::{fee::calculate_tx_fee, L1Handler};
use utils::Address;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

// Re-exports
pub use crate::services::api::contract_classes::deprecated_contract_class::{
    ContractEntryPoint, EntryPointType,
};
pub use cairo_lang_starknet::casm_contract_class::CasmContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass;
pub use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
pub use cairo_vm::felt;

pub mod core;
pub mod definitions;
pub mod execution;
pub mod hash_utils;
pub mod parser_errors;
pub mod runner;
pub mod serde_structs;
pub mod services;
pub mod state;
pub mod syscalls;
pub mod testing;
pub mod transaction;
pub mod utils;

pub fn simulate_transaction<S: StateReader>(
    transactions: &[&Transaction],
    state: S,
    block_context: &BlockContext,
    remaining_gas: u128,
    skip_validate: bool,
    skip_execute: bool,
    skip_fee_transfer: bool,
) -> Result<Vec<TransactionExecutionInfo>, TransactionError> {
    let mut cache_state = CachedState::new(state, None, Some(HashMap::new()));
    let mut result = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        let tx_for_simulation =
            transaction.create_for_simulation(skip_validate, skip_execute, skip_fee_transfer);
        let tx_result =
            tx_for_simulation.execute(&mut cache_state, block_context, remaining_gas)?;
        result.push(tx_result);
    }

    Ok(result)
}

/// Estimate the fee associated with transaction
pub fn estimate_fee<T>(
    transactions: &[Transaction],
    state: T,
    block_context: &BlockContext,
) -> Result<Vec<(u128, usize)>, TransactionError>
where
    T: StateReader,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T>::new(state, None, None);

    let mut result = Vec::with_capacity(transactions.len());
    for transaction in transactions {
        // Check if the contract is deployed.
        cached_state.get_class_hash_at(&transaction.contract_address())?;
        // execute the transaction with the fake state.

        // This is important, since we're interested in the fee estimation even if the account does not currently have sufficient funds.
        let tx_for_simulation = transaction.create_for_simulation(false, false, true);

        let transaction_result =
            tx_for_simulation.execute(&mut cached_state, block_context, 100_000_000)?;
        if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
            result.push((transaction_result.actual_fee, *gas_usage));
        } else {
            return Err(TransactionError::ResourcesError);
        };
    }

    Ok(result)
}

pub fn call_contract<T: State + StateReader>(
    contract_address: Felt252,
    entrypoint_selector: Felt252,
    calldata: Vec<Felt252>,
    state: &mut T,
    block_context: BlockContext,
    caller_address: Address,
) -> Result<Vec<Felt252>, TransactionError> {
    let contract_address = Address(contract_address);
    let class_hash = state.get_class_hash_at(&contract_address)?;
    let nonce = state.get_nonce_at(&contract_address)?;

    // TODO: Revisit these parameters
    let transaction_hash = 0.into();
    let signature = vec![];
    let max_fee = 1000000000;
    let initial_gas = 1000000000;
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

    let mut tx_execution_context = TransactionExecutionContext::new(
        contract_address,
        transaction_hash,
        signature,
        max_fee,
        nonce,
        block_context.invoke_tx_max_n_steps(),
        version.into(),
    );

    let call_info = execution_entrypoint.execute(
        state,
        &block_context,
        &mut ExecutionResourcesManager::default(),
        &mut tx_execution_context,
        false,
    )?;

    Ok(call_info.retdata)
}

/// Estimate the fee associated with L1Handler
pub fn estimate_message_fee<T>(
    l1_handler: &L1Handler,
    state: T,
    block_context: &BlockContext,
) -> Result<(u128, usize), TransactionError>
where
    T: StateReader,
{
    // This is used as a copy of the original state, we can update this cached state freely.
    let mut cached_state = CachedState::<T>::new(state, None, None);

    // Check if the contract is deployed.
    cached_state.get_class_hash_at(l1_handler.contract_address())?;

    // execute the transaction with the fake state.
    let transaction_result = l1_handler.execute(&mut cached_state, block_context, 1_000_000)?;
    let tx_fee = calculate_tx_fee(
        &transaction_result.actual_resources,
        block_context.starknet_os_config.gas_price,
        block_context,
    )?;
    if let Some(gas_usage) = transaction_result.actual_resources.get("l1_gas_usage") {
        Ok((tx_fee, *gas_usage))
    } else {
        Err(TransactionError::ResourcesError)
    }
}

pub fn execute_transaction<T: State + StateReader>(
    tx: Transaction,
    state: &mut T,
    block_context: BlockContext,
    remaining_gas: u128,
) -> Result<TransactionExecutionInfo, TransactionError> {
    tx.execute(state, &block_context, remaining_gas)
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use crate::core::contract_address::{compute_deprecated_class_hash, compute_sierra_class_hash};
    use crate::definitions::constants::INITIAL_GAS_COST;
    use crate::definitions::{
        block_context::StarknetChainId,
        constants::{
            EXECUTE_ENTRY_POINT_SELECTOR, VALIDATE_DECLARE_ENTRY_POINT_SELECTOR,
            VALIDATE_ENTRY_POINT_SELECTOR,
        },
        transaction_type::TransactionType,
    };
    use crate::estimate_fee;
    use crate::estimate_message_fee;
    use crate::hash_utils::calculate_contract_address;
    use crate::services::api::contract_classes::deprecated_contract_class::ContractClass;
    use crate::services::api::contract_classes::deprecated_contract_class::EntryPointType;
    use crate::state::state_api::State;
    use crate::testing::{
        create_account_tx_test_state, TEST_ACCOUNT_CONTRACT_ADDRESS, TEST_CONTRACT_ADDRESS,
        TEST_CONTRACT_PATH, TEST_FIB_COMPILED_CONTRACT_CLASS_HASH,
    };
    use crate::transaction::{
        Declare, DeclareV2, Deploy, DeployAccount, InvokeFunction, L1Handler, Transaction,
    };
    use crate::utils::felt_to_hash;
    use cairo_lang_starknet::casm_contract_class::CasmContractClass;
    use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
    use cairo_vm::felt::{felt_str, Felt252};
    use num_traits::{Num, One, Zero};

    use crate::{
        call_contract,
        definitions::block_context::BlockContext,
        simulate_transaction,
        state::{
            cached_state::CachedState, in_memory_state_reader::InMemoryStateReader,
            ExecutionResourcesManager,
        },
        utils::{Address, ClassHash},
    };

    use lazy_static::lazy_static;

    lazy_static! {
        // include_str! doesn't seem to work in CI
        static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
            "starknet_programs/account_without_validation.json",
        )
        .unwrap();
        static ref CLASS_HASH: Felt252 = compute_deprecated_class_hash(&CONTRACT_CLASS).unwrap();
        static ref CLASS_HASH_BYTES: [u8; 32] = CLASS_HASH.clone().to_be_bytes();
        static ref SALT: Felt252 = felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        );
        static ref CONTRACT_ADDRESS: Address = Address(calculate_contract_address(&SALT.clone(), &CLASS_HASH.clone(), &[], Address(0.into())).unwrap());
        static ref SIGNATURE: Vec<Felt252> = vec![
            felt_str!("3233776396904427614006684968846859029149676045084089832563834729503047027074"),
            felt_str!("707039245213420890976709143988743108543645298941971188668773816813012281203"),
        ];
        pub static ref TRANSACTION_VERSION: Felt252 = 1.into();
    }

    #[test]
    fn estimate_fee_test() {
        let contract_class: ContractClass = ContractClass::from_path(TEST_CONTRACT_PATH).unwrap();

        let entrypoints = contract_class.entry_points_by_type;
        let entrypoint_selector = entrypoints.get(&EntryPointType::External).unwrap()[0].selector();

        let (block_context, state) = create_account_tx_test_state().unwrap();

        // Fibonacci
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
        )
        .unwrap();
        let transaction = Transaction::InvokeFunction(invoke_function);

        let estimated_fee = estimate_fee(&[transaction], state, &block_context).unwrap();
        assert_eq!(estimated_fee[0], (12, 0));
    }

    #[test]
    fn call_contract_fibonacci_with_10_should_return_89() {
        #[cfg(not(feature = "cairo_1_tests"))]
        let program_data = include_bytes!("../starknet_programs/cairo2/fibonacci.casm");
        #[cfg(feature = "cairo_1_tests")]
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
            BlockContext::default(),
            Address(0.into()),
        )
        .unwrap();

        assert_eq!(retdata, vec![89.into()]);
    }

    #[test]
    fn test_estimate_message_fee() {
        let l1_handler = L1Handler::new(
            Address(0.into()),
            Felt252::from_str_radix(
                "c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                16,
            )
            .unwrap(),
            vec![
                Felt252::from_str_radix("8359E4B0152ed5A731162D3c7B0D8D56edB165A0", 16).unwrap(),
                1.into(),
                10.into(),
            ],
            0.into(),
            0.into(),
            Some(10000.into()),
        )
        .unwrap();

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/l1l2.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None, None);

        // Initialize state.contract_classes
        let contract_classes = HashMap::from([(class_hash, contract_class)]);
        state.set_contract_classes(contract_classes).unwrap();

        let mut block_context = BlockContext::default();
        block_context.cairo_resource_fee_weights = HashMap::from([
            (String::from("l1_gas_usage"), 0.into()),
            (String::from("pedersen_builtin"), 16.into()),
            (String::from("range_check_builtin"), 70.into()),
        ]);
        block_context.starknet_os_config.gas_price = 1;

        let estimated_fee = estimate_message_fee(&l1_handler, state, &block_context).unwrap();
        assert_eq!(estimated_fee, (20081, 18471));
    }

    #[test]
    fn test_skip_validation_flag() {
        #[cfg(not(feature = "cairo_1_tests"))]
        let program_data = include_bytes!("../starknet_programs/cairo2/fibonacci.casm");
        #[cfg(feature = "cairo_1_tests")]
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

        let invoke = InvokeFunction::new(
            address,
            entrypoint_selector.into(),
            1000000,
            Felt252::zero(),
            calldata,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            None,
        )
        .unwrap();

        let block_context = BlockContext::default();
        let Transaction::InvokeFunction(simul_invoke) =
            invoke.create_for_simulation(true, false, false) else {
                unreachable!()
            };

        let call_info = simul_invoke
            .run_validate_entrypoint(
                &mut state,
                &mut ExecutionResourcesManager::default(),
                &block_context,
            )
            .unwrap();

        assert!(call_info.is_none());
    }

    #[test]
    fn test_skip_execute_flag() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        //  ------------ contract data --------------------
        // hack store account contract
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let acc_class_hash = felt_to_hash(&hash);
        let entrypoint_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

        // test with fibonacci
        #[cfg(not(feature = "cairo_1_tests"))]
        let program_data = include_bytes!("../starknet_programs/cairo2/fibonacci.casm");
        #[cfg(feature = "cairo_1_tests")]
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");

        let casm_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::one();

        let mut state_reader = InMemoryStateReader::default();

        // store data in the state reader
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), acc_class_hash);

        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        // simulate deploy
        state_reader
            .class_hash_to_contract_class_mut()
            .insert(acc_class_hash, contract_class);

        let hash = felt_str!(
            "134328839377938040543570691566621575472567895629741043448357033688476792132"
        );
        let fib_address = felt_to_hash(&hash);
        state_reader
            .class_hash_to_compiled_class_hash_mut()
            .insert(fib_address, class_hash);
        state_reader
            .casm_contract_classes
            .insert(fib_address, casm_contract_class);

        let calldata = [
            address.0.clone(),
            entrypoint_selector.clone(),
            3.into(),
            1.into(),
            1.into(),
            10.into(),
        ]
        .to_vec();

        let invoke_1 = Transaction::InvokeFunction(
            InvokeFunction::new(
                address.clone(),
                entrypoint_selector.clone(),
                1000000,
                Felt252::one(),
                calldata.clone(),
                vec![],
                StarknetChainId::TestNet.to_felt(),
                Some(1.into()),
            )
            .unwrap(),
        );

        let invoke_2 = Transaction::InvokeFunction(
            InvokeFunction::new(
                address.clone(),
                entrypoint_selector.clone(),
                1000000,
                Felt252::one(),
                calldata.clone(),
                vec![],
                StarknetChainId::TestNet.to_felt(),
                Some(2.into()),
            )
            .unwrap(),
        );

        let invoke_3 = Transaction::InvokeFunction(
            InvokeFunction::new(
                address,
                entrypoint_selector,
                1000000,
                Felt252::one(),
                calldata,
                vec![],
                StarknetChainId::TestNet.to_felt(),
                Some(3.into()),
            )
            .unwrap(),
        );
        let block_context = BlockContext::default();

        let context = simulate_transaction(
            &[&invoke_1, &invoke_2, &invoke_3],
            state_reader,
            &block_context,
            1000,
            false,
            true,
            true,
        )
        .unwrap();

        assert!(context[0].validate_info.is_some());
        assert!(context[0].call_info.is_none());
        assert!(context[0].fee_transfer_info.is_none());
        assert!(context[1].validate_info.is_some());
        assert!(context[1].call_info.is_none());
        assert!(context[1].fee_transfer_info.is_none());
        assert!(context[2].validate_info.is_some());
        assert!(context[2].call_info.is_none());
        assert!(context[2].fee_transfer_info.is_none());
    }

    #[test]
    fn test_skip_execute_and_validate_flags() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::from_path(path).unwrap();

        //  ------------ contract data --------------------
        // hack store account contract
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let acc_class_hash = felt_to_hash(&hash);
        let entrypoint_selector = EXECUTE_ENTRY_POINT_SELECTOR.clone();

        // test with fibonacci
        #[cfg(not(feature = "cairo_1_tests"))]
        let program_data = include_bytes!("../starknet_programs/cairo2/fibonacci.casm");
        #[cfg(feature = "cairo_1_tests")]
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.casm");

        let casm_contract_class: CasmContractClass = serde_json::from_slice(program_data).unwrap();

        let address = Address(1111.into());
        let class_hash: ClassHash = [1; 32];
        let nonce = Felt252::one();

        let mut state_reader = InMemoryStateReader::default();

        // store data in the state reader
        state_reader
            .address_to_class_hash_mut()
            .insert(address.clone(), acc_class_hash);

        state_reader
            .address_to_nonce_mut()
            .insert(address.clone(), nonce);

        // simulate deploy
        state_reader
            .class_hash_to_contract_class_mut()
            .insert(acc_class_hash, contract_class);

        let hash = felt_str!(
            "134328839377938040543570691566621575472567895629741043448357033688476792132"
        );
        let fib_address = felt_to_hash(&hash);
        state_reader
            .class_hash_to_compiled_class_hash_mut()
            .insert(fib_address, class_hash);
        state_reader
            .casm_contract_classes
            .insert(fib_address, casm_contract_class);

        let calldata = [
            address.0.clone(),
            entrypoint_selector.clone(),
            3.into(),
            1.into(),
            1.into(),
            10.into(),
        ]
        .to_vec();

        let invoke = Transaction::InvokeFunction(
            InvokeFunction::new(
                address,
                entrypoint_selector,
                1000000,
                Felt252::one(),
                calldata,
                vec![],
                StarknetChainId::TestNet.to_felt(),
                Some(1.into()),
            )
            .unwrap(),
        );

        let block_context = BlockContext::default();

        let context = simulate_transaction(
            &[&invoke],
            state_reader,
            &block_context,
            1000,
            true,
            true,
            true,
        )
        .unwrap();

        assert!(context[0].validate_info.is_none());
        assert!(context[0].call_info.is_none());
        assert!(context[0].fee_transfer_info.is_none());
    }

    #[test]
    fn test_simulate_deploy() {
        let state_reader = InMemoryStateReader::default();
        let mut state = CachedState::new(state_reader, Some(Default::default()), None);

        state
            .set_contract_class(&CLASS_HASH_BYTES, &CONTRACT_CLASS)
            .unwrap();

        let block_context = &Default::default();
        let salt = felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        );
        // new consumes more execution time than raw struct instantiation
        let internal_deploy = Transaction::Deploy(
            Deploy::new(
                salt,
                CONTRACT_CLASS.clone(),
                vec![],
                StarknetChainId::TestNet.to_felt(),
                0.into(),
            )
            .unwrap(),
        );

        simulate_transaction(
            &[&internal_deploy],
            state,
            block_context,
            100_000_000,
            false,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn test_simulate_declare() {
        let state_reader = InMemoryStateReader::default();
        let state = CachedState::new(state_reader, Some(Default::default()), None);

        let block_context = &Default::default();

        let class = CONTRACT_CLASS.clone();
        let address = CONTRACT_ADDRESS.clone();
        // new consumes more execution time than raw struct instantiation
        let declare_tx = Transaction::Declare(
            Declare::new(
                class,
                StarknetChainId::TestNet.to_felt(),
                address,
                0,
                0.into(),
                vec![],
                Felt252::zero(),
            )
            .expect("couldn't create transaction"),
        );

        simulate_transaction(
            &[&declare_tx],
            state,
            block_context,
            100_000_000,
            false,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn test_simulate_invoke() {
        let state_reader = InMemoryStateReader::default();
        let mut state = CachedState::new(state_reader, Some(Default::default()), None);

        state
            .set_contract_class(&CLASS_HASH_BYTES, &CONTRACT_CLASS)
            .unwrap();

        let block_context = Default::default();

        let salt = felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        );
        let class = CONTRACT_CLASS.clone();
        let deploy = Deploy::new(
            salt,
            class,
            vec![],
            StarknetChainId::TestNet.to_felt(),
            0.into(),
        )
        .unwrap();

        let _deploy_exec_info = deploy.execute(&mut state, &block_context).unwrap();

        let selector = VALIDATE_ENTRY_POINT_SELECTOR.clone();
        let calldata = vec![
            CONTRACT_ADDRESS.0.clone(),
            selector.clone(),
            Felt252::zero(),
        ];
        // new consumes more execution time than raw struct instantiation
        let invoke_tx = Transaction::InvokeFunction(
            InvokeFunction::new(
                CONTRACT_ADDRESS.clone(),
                selector,
                0,
                TRANSACTION_VERSION.clone(),
                calldata,
                SIGNATURE.clone(),
                StarknetChainId::TestNet.to_felt(),
                Some(Felt252::zero()),
            )
            .unwrap(),
        );

        simulate_transaction(
            &[&invoke_tx],
            state,
            &block_context,
            100_000_000,
            false,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn test_simulate_deploy_account() {
        let state_reader = InMemoryStateReader::default();
        let mut state = CachedState::new(state_reader, Some(Default::default()), None);

        state
            .set_contract_class(&CLASS_HASH_BYTES, &CONTRACT_CLASS)
            .unwrap();

        let block_context = &Default::default();

        // new consumes more execution time than raw struct instantiation
        let deploy_account_tx = Transaction::DeployAccount(
            DeployAccount::new(
                *CLASS_HASH_BYTES,
                0,
                0.into(),
                Felt252::zero(),
                vec![],
                SIGNATURE.clone(),
                SALT.clone(),
                StarknetChainId::TestNet.to_felt(),
            )
            .unwrap(),
        );

        simulate_transaction(
            &[&deploy_account_tx],
            state,
            block_context,
            100_000_000,
            false,
            false,
            false,
        )
        .unwrap();
    }

    fn declarev2_tx() -> DeclareV2 {
        let program_data = include_bytes!("../starknet_programs/cairo1/fibonacci.sierra");
        let sierra_contract_class: SierraContractClass =
            serde_json::from_slice(program_data).unwrap();

        let sierra_class_hash = compute_sierra_class_hash(&sierra_contract_class).unwrap();

        DeclareV2 {
            sender_address: TEST_ACCOUNT_CONTRACT_ADDRESS.clone(),
            tx_type: TransactionType::Declare,
            validate_entry_point_selector: VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone(),
            version: 1.into(),
            max_fee: INITIAL_GAS_COST,
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

    #[test]
    fn test_simulate_declare_v2() {
        let (block_context, state) = create_account_tx_test_state().unwrap();
        let declare_tx = Transaction::DeclareV2(Box::new(declarev2_tx()));

        simulate_transaction(
            &[&declare_tx],
            state,
            &block_context,
            100_000_000,
            false,
            false,
            true,
        )
        .unwrap();
    }

    #[test]
    fn test_simulate_l1_handler() {
        let l1_handler_tx = Transaction::L1Handler(
            L1Handler::new(
                Address(0.into()),
                Felt252::from_str_radix(
                    "c73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                    16,
                )
                .unwrap(),
                vec![
                    Felt252::from_str_radix("8359E4B0152ed5A731162D3c7B0D8D56edB165A0", 16)
                        .unwrap(),
                    1.into(),
                    10.into(),
                ],
                0.into(),
                0.into(),
                Some(10000.into()),
            )
            .unwrap(),
        );

        // Instantiate CachedState
        let mut state_reader = InMemoryStateReader::default();
        // Set contract_class
        let class_hash = [1; 32];
        let contract_class = ContractClass::from_path("starknet_programs/l1l2.json").unwrap();
        // Set contact_state
        let contract_address = Address(0.into());
        let nonce = Felt252::zero();

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let mut state = CachedState::new(state_reader.clone(), None, None);

        // Initialize state.contract_classes
        state.set_contract_classes(HashMap::new()).unwrap();

        state
            .set_contract_class(&class_hash, &contract_class)
            .unwrap();

        let mut block_context = BlockContext::default();
        block_context.cairo_resource_fee_weights = HashMap::from([
            (String::from("l1_gas_usage"), 0.into()),
            (String::from("pedersen_builtin"), 16.into()),
            (String::from("range_check_builtin"), 70.into()),
        ]);
        block_context.starknet_os_config.gas_price = 1;

        simulate_transaction(
            &[&l1_handler_tx],
            state,
            &block_context,
            100_000_000,
            false,
            false,
            false,
        )
        .unwrap();
    }

    #[test]
    fn test_deploy_and_invoke_simulation() {
        let state_reader = InMemoryStateReader::default();
        let mut state = CachedState::new(state_reader, Some(Default::default()), None);

        state
            .set_contract_class(&CLASS_HASH_BYTES, &CONTRACT_CLASS)
            .unwrap();

        let block_context = &Default::default();

        let salt = felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        );
        let class = CONTRACT_CLASS.clone();
        let deploy = Transaction::Deploy(
            Deploy::new(
                salt,
                class,
                vec![],
                StarknetChainId::TestNet.to_felt(),
                0.into(),
            )
            .unwrap(),
        );

        let selector = VALIDATE_ENTRY_POINT_SELECTOR.clone();
        let calldata = vec![
            CONTRACT_ADDRESS.0.clone(),
            selector.clone(),
            Felt252::zero(),
        ];
        // new consumes more execution time than raw struct instantiation
        let invoke_tx = Transaction::InvokeFunction(
            InvokeFunction::new(
                CONTRACT_ADDRESS.clone(),
                selector,
                0,
                TRANSACTION_VERSION.clone(),
                calldata,
                SIGNATURE.clone(),
                StarknetChainId::TestNet.to_felt(),
                Some(Felt252::zero()),
            )
            .unwrap(),
        );

        simulate_transaction(
            &[&deploy, &invoke_tx],
            state.clone(),
            block_context,
            100_000_000,
            false,
            false,
            false,
        )
        .unwrap();

        assert_eq!(
            estimate_fee(&[deploy, invoke_tx], state, block_context,).unwrap(),
            [(0, 1224), (0, 0)]
        );
    }

    #[test]
    fn test_declare_v2_with_invalid_compiled_class_hash() {
        let (block_context, mut state) = create_account_tx_test_state().unwrap();
        let mut declare_v2 = declarev2_tx();
        declare_v2.compiled_class_hash = Felt252::from(1);
        let declare_tx = Transaction::DeclareV2(Box::new(declare_v2));

        let err = declare_tx
            .execute(&mut state, &block_context, INITIAL_GAS_COST)
            .unwrap_err();

        assert_eq!(err.to_string(), "Invalid compiled class, expected class hash: \"1948962768849191111780391610229754715773924969841143100991524171924131413970\", but received: \"1\"".to_string());
    }
}
