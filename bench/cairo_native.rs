#![cfg(not(feature = "cairo_1_tests"))]

use cairo_native::cache::ProgramCache;
use cairo_native::context::NativeContext;
use cairo_vm::felt::felt_str;
use cairo_vm::felt::Felt252;
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_in_rust::definitions::block_context::BlockContext;
use starknet_in_rust::definitions::block_context::StarknetChainId;
use starknet_in_rust::services::api::contract_classes::compiled_class::CompiledClass;
use starknet_in_rust::state::state_api::State;
use starknet_in_rust::transaction::DeployAccount;
use starknet_in_rust::CasmContractClass;
use starknet_in_rust::EntryPointType;
use starknet_in_rust::utils::calculate_sn_keccak;
use starknet_in_rust::{
    definitions::constants::TRANSACTION_VERSION,
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    state::cached_state::CachedState,
    state::{in_memory_state_reader::InMemoryStateReader, ExecutionResourcesManager},
    utils::{Address, ClassHash},
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    dbg!(args.clone());
    match args.get(3).map(|s| s.as_str()) {
        Some("fibo") => bench_fibo(
            args.get(1)
                .and_then(|x| usize::from_str_radix(x, 10).ok())
                .unwrap_or(1),
            args.get(2) == Some(&"native".to_string()),
        ),
        Some("fact") => bench_fact(
            args.get(1)
                .and_then(|x| usize::from_str_radix(x, 10).ok())
                .unwrap_or(1),
            args.get(2) == Some(&"native".to_string()),
        ),
        _ => {
            println!("Executing ERC20 benchmark");
            bench_erc20(
            args.get(1)
                .and_then(|x| usize::from_str_radix(x, 10).ok())
                .unwrap_or(1),
            args.get(2) == Some(&"native".to_string()),
        )
        
    },
    }
}

fn bench_fibo(executions: usize, native: bool) {
    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    static CASM_CLASS_HASH: ClassHash = [2; 32];

    let (contract_class, constructor_selector) = match native {
        true => {
            let sierra_data = include_bytes!("../starknet_programs/cairo2/fibonacci.sierra");
            let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
                serde_json::from_slice(sierra_data).unwrap();

            let entrypoints = sierra_contract_class.clone().entry_points_by_type;
            let constructor_selector = entrypoints.external.get(0).unwrap().selector.clone();

            (
                CompiledClass::Sierra(Arc::new(sierra_contract_class)),
                constructor_selector,
            )
        }
        false => {
            let casm_data = include_bytes!("../starknet_programs/cairo2/fibonacci.casm");
            let casm_contract_class: CasmContractClass = serde_json::from_slice(casm_data).unwrap();

            let entrypoints = casm_contract_class.clone().entry_points_by_type;
            let constructor_selector = entrypoints.external.get(0).unwrap().selector.clone();

            (
                CompiledClass::Casm(Arc::new(casm_contract_class)),
                constructor_selector,
            )
        }
    };

    let caller_address = Address(123456789.into());

    contract_class_cache.insert(CASM_CLASS_HASH, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    let nonce = Felt252::zero();

    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), CASM_CLASS_HASH);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let state_reader = Arc::new(state_reader);
    let state = CachedState::new(state_reader, contract_class_cache);

    /* f0, f1, N */
    let mut calldata = [1.into(), 1.into(), 2000000.into()];

    let native_ctx = NativeContext::new();
    let program_cache = Rc::new(RefCell::new(ProgramCache::new(&native_ctx)));

    for _ in 0..executions {
        calldata[2] = &calldata[2] + 1usize;
        let result = execute(
            &mut state.clone(),
            &caller_address,
            &caller_address,
            &Felt252::new(constructor_selector.clone()),
            &calldata,
            EntryPointType::External,
            &CASM_CLASS_HASH,
            program_cache.clone(),
        );

        _ = std::hint::black_box(result);
    }
}

fn bench_fact(executions: usize, native: bool) {
    // Create state reader with class hash data
    let mut contract_class_cache = HashMap::new();
    static CASM_CLASS_HASH: ClassHash = [2; 32];

    let (contract_class, constructor_selector) = match native {
        true => {
            let sierra_data = include_bytes!("../starknet_programs/cairo2/factorial_tr.sierra");
            let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
                serde_json::from_slice(sierra_data).unwrap();

            let entrypoints = sierra_contract_class.clone().entry_points_by_type;
            let constructor_selector = entrypoints.external.get(0).unwrap().selector.clone();

            (
                CompiledClass::Sierra(Arc::new(sierra_contract_class)),
                constructor_selector,
            )
        }
        false => {
            let casm_data = include_bytes!("../starknet_programs/cairo2/factorial_tr.casm");
            let casm_contract_class: CasmContractClass = serde_json::from_slice(casm_data).unwrap();

            let entrypoints = casm_contract_class.clone().entry_points_by_type;
            let constructor_selector = entrypoints.external.get(0).unwrap().selector.clone();

            (
                CompiledClass::Casm(Arc::new(casm_contract_class)),
                constructor_selector,
            )
        }
    };

    let caller_address = Address(123456789.into());
    // FACT 1M
    // FIBO 2M

    contract_class_cache.insert(CASM_CLASS_HASH, contract_class);
    let mut state_reader = InMemoryStateReader::default();
    let nonce = Felt252::zero();

    state_reader
        .address_to_class_hash_mut()
        .insert(caller_address.clone(), CASM_CLASS_HASH);
    state_reader
        .address_to_nonce_mut()
        .insert(caller_address.clone(), nonce);

    // Create state from the state_reader and contract cache.
    let state_reader = Arc::new(state_reader);
    let state = CachedState::new(state_reader, contract_class_cache);

    /* N */
    let mut calldata = [2000000.into()];

    let native_ctx = NativeContext::new();
    let program_cache = Rc::new(RefCell::new(ProgramCache::new(&native_ctx)));

    for _ in 0..executions {
        calldata[0] = &calldata[0] + 1usize;
        let result = execute(
            &mut state.clone(),
            &caller_address,
            &caller_address,
            &Felt252::new(constructor_selector.clone()),
            &calldata,
            EntryPointType::External,
            &CASM_CLASS_HASH,
            program_cache.clone(),
        );

        _ = std::hint::black_box(result);
    }
}

fn bench_erc20(executions: usize, native: bool) {
    // 1. setup ERC20 contract and state.
    // Create state reader and preload the contract classes.
    let mut contract_class_cache = HashMap::new();
    static ERC20_CLASS_HASH: ClassHash = [2; 32];
    static DEPLOYER_CLASS_HASH: ClassHash = [10; 32];
    static ACCOUNT1_CLASS_HASH: ClassHash = [1; 32];
    lazy_static! {
        static ref DEPLOYER_ADDRESS: Address = Address(1111.into());
        static ref ERC20_NAME: Felt252 = Felt252::from_bytes_be(b"some-token");
        static ref ERC20_SYMBOL: Felt252 = Felt252::from_bytes_be(b"my-super-awesome-token");
        static ref ERC20_DECIMALS: Felt252 = Felt252::from(24);
        static ref ERC20_INITIAL_SUPPLY: Felt252 = Felt252::from(1_000_000);
        static ref ERC20_RECIPIENT: Felt252 =
            felt_str!("397149464972449753182583229366244826403270781177748543857889179957856017275");
        static ref ERC20_SALT: Felt252 = felt_str!("1234");
        static ref ERC20_DEPLOYER_CALLDATA: [Felt252; 7] = [
            Felt252::from_bytes_be(&ERC20_CLASS_HASH),
            ERC20_SALT.clone(),
            ERC20_RECIPIENT.clone(),
            ERC20_NAME.clone(),
            ERC20_DECIMALS.clone(),
            ERC20_INITIAL_SUPPLY.clone(),
            ERC20_SYMBOL.clone(),
        ];
        static ref ERC20_DEPLOYMENT_CALLER_ADDRESS: Address = Address(0000.into());
    }

    println!("Deploying ERC20");
    let (erc20_address, mut state): (Address, CachedState<InMemoryStateReader>) = match native {
        true => {
            let erc20_sierra_class = include_bytes!("../starknet_programs/cairo2/erc20.sierra");
            let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
                serde_json::from_slice(erc20_sierra_class).unwrap();
            let erc20_contract_class = CompiledClass::Sierra(Arc::new(sierra_contract_class));

            // we also need to read the contract class of the deployERC20 contract.
            // this contract is used as a deployer of the erc20.
            let erc20_deployer_code =
                include_bytes!("../starknet_programs/cairo2/deploy_erc20.casm");
            let erc20_deployer_class: CasmContractClass =
                serde_json::from_slice(erc20_deployer_code).unwrap();
            let entrypoints = erc20_deployer_class.clone().entry_points_by_type;
            let deploy_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

            // insert deployer and erc20 classes into the cache.
            contract_class_cache.insert(
                DEPLOYER_CLASS_HASH,
                CompiledClass::Casm(Arc::new(erc20_deployer_class)),
            );
            contract_class_cache.insert(ERC20_CLASS_HASH, erc20_contract_class);

            let mut state_reader = InMemoryStateReader::default();
            // setup deployer nonce and address into the state reader
            state_reader
                .address_to_class_hash_mut()
                .insert(DEPLOYER_ADDRESS.clone(), DEPLOYER_CLASS_HASH);
            state_reader
                .address_to_nonce_mut()
                .insert(DEPLOYER_ADDRESS.clone(), Felt252::zero());

            // Create state from the state_reader and contract cache.
            let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

            // deploy the erc20 contract by calling the deployer contract.

            let exec_entry_point = ExecutionEntryPoint::new(
                DEPLOYER_ADDRESS.clone(),
                ERC20_DEPLOYER_CALLDATA.to_vec(),
                Felt252::new(deploy_entrypoint_selector.clone()),
                ERC20_DEPLOYMENT_CALLER_ADDRESS.clone(),
                EntryPointType::External,
                Some(CallType::Delegate),
                Some(DEPLOYER_CLASS_HASH),
                100_000_000_000,
            );

            // create required structures for execution
            let block_context = BlockContext::default();
            let mut tx_execution_context = TransactionExecutionContext::new(
                Address(0.into()),
                Felt252::zero(),
                Vec::new(),
                0,
                10.into(),
                block_context.invoke_tx_max_n_steps(),
                1.into(),
            );
            let mut resources_manager = ExecutionResourcesManager::default();

            // execute the deployment
            let call_info = exec_entry_point
                .execute(
                    &mut state,
                    &block_context,
                    &mut resources_manager,
                    &mut tx_execution_context,
                    false,
                    block_context.invoke_tx_max_n_steps(),
                )
                .unwrap();

            // obtain the address of the deployed erc20 contract
            let erc20_address = call_info.call_info.unwrap().retdata.get(0).unwrap().clone();

            (Address(erc20_address), state)
        }
        false => {
            // read the ERC20 contract class
            let erc20_casm_class = include_bytes!("../starknet_programs/cairo2/erc20.casm");
            let casm_contract_class: CasmContractClass =
                serde_json::from_slice(erc20_casm_class).unwrap();
            let erc20_contract_class = CompiledClass::Casm(Arc::new(casm_contract_class));

            // we also need to read the contract class of the deployERC20 contract.
            // this contract is used as a deployer of the erc20.
            let erc20_deployer_code =
                include_bytes!("../starknet_programs/cairo2/deploy_erc20.casm");
            let erc20_deployer_class: CasmContractClass =
                serde_json::from_slice(erc20_deployer_code).unwrap();
            let entrypoints = erc20_deployer_class.clone().entry_points_by_type;
            let deploy_entrypoint_selector = &entrypoints.external.get(0).unwrap().selector;

            // insert deployer and erc20 classes into the cache.
            contract_class_cache.insert(
                DEPLOYER_CLASS_HASH,
                CompiledClass::Casm(Arc::new(erc20_deployer_class)),
            );
            contract_class_cache.insert(ERC20_CLASS_HASH, erc20_contract_class);

            let mut state_reader = InMemoryStateReader::default();
            // setup deployer nonce and address into the state reader
            state_reader
                .address_to_class_hash_mut()
                .insert(DEPLOYER_ADDRESS.clone(), DEPLOYER_CLASS_HASH);
            state_reader
                .address_to_nonce_mut()
                .insert(DEPLOYER_ADDRESS.clone(), Felt252::zero());

            // Create state from the state_reader and contract cache.
            let mut state = CachedState::new(Arc::new(state_reader), contract_class_cache);

            // deploy the erc20 contract by calling the deployer contract.

            let exec_entry_point = ExecutionEntryPoint::new(
                DEPLOYER_ADDRESS.clone(),
                ERC20_DEPLOYER_CALLDATA.to_vec(),
                Felt252::new(deploy_entrypoint_selector.clone()),
                ERC20_DEPLOYMENT_CALLER_ADDRESS.clone(),
                EntryPointType::External,
                Some(CallType::Delegate),
                Some(DEPLOYER_CLASS_HASH),
                100_000_000_000,
            );

            // create required structures for execution
            let block_context = BlockContext::default();
            let mut tx_execution_context = TransactionExecutionContext::new(
                Address(0.into()),
                Felt252::zero(),
                Vec::new(),
                0,
                10.into(),
                block_context.invoke_tx_max_n_steps(),
                1.into(),
            );
            let mut resources_manager = ExecutionResourcesManager::default();

            // execute the deployment
            let call_info = exec_entry_point
                .execute(
                    &mut state,
                    &block_context,
                    &mut resources_manager,
                    &mut tx_execution_context,
                    false,
                    block_context.invoke_tx_max_n_steps(),
                )
                .unwrap();

            // obtain the address of the deployed erc20 contract
            let erc20_address = call_info.call_info.unwrap().retdata.get(0).unwrap().clone();

            (Address(erc20_address), state)
        }
    };


    // 2. setup accounts (here we need to execute a deploy_account,
    //    so we execute it in the vm only).
    //    Further executions (transfers) will be executed with Native.
    //    (or the VM, depending on configuration)
    // 2a. setup for first account:
    println!("Deploying accounts");
    let account_casm_file = include_bytes!("../starknet_programs/cairo2/hello_world_account.casm");
    let account_contract_class: CasmContractClass =
        serde_json::from_slice(account_casm_file).unwrap();

    state
        .set_contract_class(
            &ACCOUNT1_CLASS_HASH,
            &CompiledClass::Casm(Arc::new(account_contract_class)),
        )
        .unwrap();
    state
        .set_compiled_class_hash(
            &Felt252::from_bytes_be(&ACCOUNT1_CLASS_HASH),
            &Felt252::from_bytes_be(&ACCOUNT1_CLASS_HASH),
        )
        .unwrap();

    let contract_address_salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");

    // create a transaction for deploying the first account
    let account1_deploy_tx = DeployAccount::new(
        ACCOUNT1_CLASS_HASH, // class hash
        0,                   // max fee
        1.into(),            // tx version
        Felt252::zero(),     // nonce
        vec![2.into()],      // constructor calldata
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ], // signature
        contract_address_salt.clone(), // salt
        StarknetChainId::TestNet.to_felt(), // network
    )
    .unwrap();

    // execute the deploy_account transaction.
    // this will create the account and after that,
    // we can extract its address.
    let account1_address = account1_deploy_tx
        .execute(&mut state, &Default::default())
        .expect("failed to execute the deployment of account 1")
        .validate_info
        .expect("validate_info missing")
        .contract_address;

    // now we need to deploy account2
    let account2_deploy_tx = DeployAccount::new(
        ACCOUNT1_CLASS_HASH, // class hash
        0,                   // max fee
        1.into(),            // tx version
        Felt252::zero(),     // nonce
        vec![3.into()],      // constructor calldata
        vec![
            felt_str!(
                "3233776396904427614006684968846859029149676045084089832563834729503047027074"
            ),
            felt_str!(
                "707039245213420890976709143988743108543645298941971188668773816813012281203"
            ),
        ], // signature
        contract_address_salt, // salt
        StarknetChainId::TestNet.to_felt(), // network
    )
    .unwrap();

    // execute the deploy_account transaction and retrieve the deployed account address.
    let account2_address = account2_deploy_tx
        .execute(&mut state, &Default::default())
        .expect("failed to execute the deployment of account 2")
        .validate_info
        .expect("validate_info missing")
        .contract_address;

    // 4. do transfers between the accounts

    let transfer_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"transfer"));
    // calldata for transfering 123 tokens from account1 to account2
    let calldata = vec![account2_address.clone().0, Felt252::from(123)];

    let native_ctx = NativeContext::new();
    let program_cache = Rc::new(RefCell::new(ProgramCache::new(&native_ctx)));

    println!("Executing transfers...");
    for _ in 0..executions {
        let result = execute(
            &mut state.clone(),
            &account1_address,
            &erc20_address,
            &transfer_entrypoint_selector.clone(),
            &calldata.clone(),
            EntryPointType::External,
            &ERC20_CLASS_HASH,
            program_cache.clone(),
        );
        dbg!(&result);
        _ = std::hint::black_box(result);
        
    }
}

#[inline(never)]
fn execute(
    state: &mut CachedState<InMemoryStateReader>,
    caller_address: &Address,
    callee_address: &Address,
    selector: &Felt252,
    calldata: &[Felt252],
    entrypoint_type: EntryPointType,
    class_hash: &ClassHash,
    program_cache: Rc<RefCell<ProgramCache<'_, ClassHash>>>,
) -> CallInfo {
    let exec_entry_point = ExecutionEntryPoint::new(
        (*callee_address).clone(),
        calldata.to_vec(),
        selector.clone(),
        (*caller_address).clone(),
        entrypoint_type,
        Some(CallType::Delegate),
        Some(*class_hash),
        u64::MAX.into(), // gas is u64 in cairo-native and sierra
    );

    // Execute the entrypoint
    let block_context = BlockContext::default();
    let mut tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt252::zero(),
        Vec::new(),
        0,
        10.into(),
        block_context.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION.clone(),
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    exec_entry_point
        .execute_with_native_cache(
            state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
            program_cache,
        )
        .unwrap()
        .call_info
        .unwrap()
}
