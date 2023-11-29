// Usage:
// For executing the binary with cairo native you can run it like:
// $ native_bench <n_executions> native
// otherwise it will run it using the Cairo VM
// native_bench <n_executions>
// You can also choose which benchmark to run by passing the name of the benchmark as the third argument:
// $ native_bench <n_executions> native <fibo|fact>
// where fibo executes a fibonacci function and fact a factorial n times.

use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_native::{cache::ProgramCache, context::NativeContext};
use cairo_vm::felt::{felt_str, Felt252};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_in_rust::{
    definitions::{
        block_context::{BlockContext, StarknetChainId},
        constants::TRANSACTION_VERSION,
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallInfo, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{
        cached_state::CachedState,
        contract_class_cache::{ContractClassCache, PermanentContractClassCache},
        in_memory_state_reader::InMemoryStateReader,
        state_api::State,
        ExecutionResourcesManager,
    },
    transaction::DeployAccount,
    utils::{calculate_sn_keccak, get_native_context, Address, ClassHash},
    CasmContractClass, EntryPointType,
};
use std::{cell::RefCell, rc::Rc, sync::Arc};

macro_rules! load_contract {
    ( $is_native:expr, $casm_path:literal, $sierra_path:literal ) => {{
        let casm_contract_class = Arc::new(
            serde_json::from_slice::<CasmContractClass>(include_bytes!($casm_path)).unwrap(),
        );

        let sierra_contract_class = $is_native
            .then(|| {
                let sierra_contract_class =
                    serde_json::from_slice::<SierraContractClass>(include_bytes!($sierra_path))
                        .unwrap();

                (
                    sierra_contract_class.extract_sierra_program().unwrap(),
                    sierra_contract_class.entry_points_by_type,
                )
            })
            .map(Arc::new);

        let constructor_selector = match &sierra_contract_class {
            Some(sierra_contract_class) => sierra_contract_class
                .1
                .external
                .first()
                .unwrap()
                .selector
                .clone(),
            None => casm_contract_class
                .entry_points_by_type
                .external
                .first()
                .unwrap()
                .selector
                .clone(),
        };

        (
            CompiledClass::Casm {
                casm: casm_contract_class,
                sierra: sierra_contract_class,
            },
            constructor_selector,
        )
    }};
}

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(3).map(|s| s.as_str()) {
        Some("fibo") => bench_fibo(
            args.get(1)
                .and_then(|x| x.parse::<usize>().ok())
                .unwrap_or(1),
            args.get(2) == Some(&"native".to_string()),
        ),
        Some("fact") => bench_fact(
            args.get(1)
                .and_then(|x| x.parse::<usize>().ok())
                .unwrap_or(1),
            args.get(2) == Some(&"native".to_string()),
        ),
        _ => bench_erc20(
            args.get(1)
                .and_then(|x| x.parse::<usize>().ok())
                .unwrap_or(1),
            args.get(2) == Some(&"native".to_string()),
        ),
    }
}

fn bench_fibo(executions: usize, native: bool) {
    // Create state reader with class hash data
    let contract_class_cache = PermanentContractClassCache::default();
    static CASM_CLASS_HASH: ClassHash = ClassHash([2; 32]);

    let (contract_class, constructor_selector) = load_contract!(
        native,
        "../starknet_programs/cairo2/fibonacci.casm",
        "../starknet_programs/cairo2/fibonacci.sierra"
    );

    let caller_address = Address(123456789.into());

    contract_class_cache.set_contract_class(CASM_CLASS_HASH, contract_class);
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
    let state = CachedState::new(state_reader, Arc::new(contract_class_cache));

    /* f0, f1, N */
    let mut calldata = [1.into(), 1.into(), 2000000.into()];

    let native_ctx = NativeContext::new();
    let program_cache = Rc::new(RefCell::new(ProgramCache::new(&native_ctx)));

    for _ in 0..executions {
        calldata[2] = &calldata[2] + 1usize;
        let result = execute(
            &mut state.clone_for_testing(),
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
    let contract_class_cache = PermanentContractClassCache::default();
    static CASM_CLASS_HASH: ClassHash = ClassHash([2; 32]);

    let (contract_class, constructor_selector) = load_contract!(
        native,
        "../starknet_programs/cairo2/factorial_tr.sierra",
        "../starknet_programs/cairo2/factorial_tr.casm"
    );

    let caller_address = Address(123456789.into());
    // FACT 1M
    // FIBO 2M

    contract_class_cache.set_contract_class(CASM_CLASS_HASH, contract_class);
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
    let state = CachedState::new(state_reader, Arc::new(contract_class_cache));

    /* N */
    let mut calldata = [2000000.into()];

    let native_ctx = NativeContext::new();
    let program_cache = Rc::new(RefCell::new(ProgramCache::new(&native_ctx)));

    for _ in 0..executions {
        calldata[0] = &calldata[0] + 1usize;
        let result = execute(
            &mut state.clone_for_testing(),
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
    let contract_class_cache = PermanentContractClassCache::default();

    lazy_static! {
        static ref ERC20_CLASS_HASH: ClassHash = ClassHash::from(felt_str!("2"));
        static ref DEPLOYER_CLASS_HASH: ClassHash = ClassHash::from(felt_str!("10"));
        static ref ACCOUNT1_CLASS_HASH: ClassHash = ClassHash::from(felt_str!("1"));
        static ref DEPLOYER_ADDRESS: Address = Address(1111.into());
        static ref ERC20_NAME: Felt252 = Felt252::from_bytes_be(b"be");
        static ref ERC20_SYMBOL: Felt252 = Felt252::from_bytes_be(b"be");
        static ref ERC20_DECIMALS: Felt252 = Felt252::from(24);
        static ref ERC20_INITIAL_SUPPLY: Felt252 = Felt252::from(1_000_000);
        static ref ERC20_RECIPIENT: Felt252 = felt_str!("111");
        static ref ERC20_SALT: Felt252 = felt_str!("1234");
        static ref ERC20_DEPLOYER_CALLDATA: [Felt252; 7] = [
            Felt252::from_bytes_be(ERC20_CLASS_HASH.to_bytes_be()),
            ERC20_SALT.clone(),
            ERC20_RECIPIENT.clone(),
            ERC20_NAME.clone(),
            ERC20_DECIMALS.clone(),
            ERC20_INITIAL_SUPPLY.clone(),
            ERC20_SYMBOL.clone(),
        ];
        static ref ERC20_DEPLOYMENT_CALLER_ADDRESS: Address = Address(0000.into());
    }

    let program_cache = Rc::new(RefCell::new(ProgramCache::new(get_native_context())));
    let (erc20_address, mut state) = {
        let erc20_casm = serde_json::from_slice::<CasmContractClass>(include_bytes!(
            "../starknet_programs/cairo2/erc20.casm"
        ))
        .unwrap();
        let erc20_sierra = native.then(|| {
            serde_json::from_slice::<SierraContractClass>(include_bytes!(
                "../starknet_programs/cairo2/erc20.sierra"
            ))
            .unwrap()
        });

        let (erc20_deployer, erc20_deployer_selector) = load_contract!(
            native,
            "../starknet_programs/cairo2/deploy_erc20.casm",
            "../starknet_programs/cairo2/deploy_erc20.sierra"
        );

        contract_class_cache.set_contract_class(*DEPLOYER_CLASS_HASH, erc20_deployer);
        contract_class_cache.set_contract_class(
            *ERC20_CLASS_HASH,
            CompiledClass::Casm {
                casm: Arc::new(erc20_casm),
                sierra: erc20_sierra
                    .map(|sierra_contract_class| {
                        (
                            sierra_contract_class.extract_sierra_program().unwrap(),
                            sierra_contract_class.entry_points_by_type,
                        )
                    })
                    .map(Arc::new),
            },
        );

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(DEPLOYER_ADDRESS.clone(), *DEPLOYER_CLASS_HASH);
        state_reader
            .address_to_nonce_mut()
            .insert(DEPLOYER_ADDRESS.clone(), Felt252::zero());

        let mut state = CachedState::new(Arc::new(state_reader), Arc::new(contract_class_cache));

        let block_context = BlockContext::default();
        let call_info = ExecutionEntryPoint::new(
            DEPLOYER_ADDRESS.clone(),
            ERC20_DEPLOYER_CALLDATA.to_vec(),
            Felt252::new(erc20_deployer_selector),
            ERC20_DEPLOYMENT_CALLER_ADDRESS.clone(),
            EntryPointType::External,
            Some(CallType::Delegate),
            Some(*DEPLOYER_CLASS_HASH),
            100_000_000_000,
        )
        .execute(
            &mut state,
            &block_context,
            &mut ExecutionResourcesManager::default(),
            &mut TransactionExecutionContext::new(
                Address(0.into()),
                Felt252::zero(),
                Vec::new(),
                0,
                10.into(),
                block_context.invoke_tx_max_n_steps(),
                1.into(),
            ),
            false,
            block_context.invoke_tx_max_n_steps(),
            Some(program_cache.clone()),
        )
        .unwrap();

        (
            Address(
                call_info
                    .call_info
                    .unwrap()
                    .retdata
                    .first()
                    .unwrap()
                    .clone(),
            ),
            state,
        )
    };

    // 2. setup accounts (here we need to execute a deploy_account,
    //    so we execute it in the vm only).
    //    Further executions (transfers) will be executed with Native.
    //    (or the VM, depending on configuration)
    // 2a. setup for first account:
    let account_casm_class = serde_json::from_slice::<CasmContractClass>(include_bytes!(
        "../starknet_programs/cairo2/hello_world_account.casm"
    ))
    .unwrap();
    let account_sierra_class = native.then(|| {
        serde_json::from_slice::<SierraContractClass>(include_bytes!(
            "../starknet_programs/cairo2/hello_world_account.sierra"
        ))
        .unwrap()
    });

    state
        .set_contract_class(
            &ACCOUNT1_CLASS_HASH,
            &CompiledClass::Casm {
                casm: Arc::new(account_casm_class),
                sierra: account_sierra_class
                    .map(|sierra_contract_class| {
                        (
                            sierra_contract_class.extract_sierra_program().unwrap(),
                            sierra_contract_class.entry_points_by_type,
                        )
                    })
                    .map(Arc::new),
            },
        )
        .unwrap();
    state
        .set_compiled_class_hash(
            &Felt252::from_bytes_be(ACCOUNT1_CLASS_HASH.to_bytes_be()),
            &Felt252::from_bytes_be(ACCOUNT1_CLASS_HASH.to_bytes_be()),
        )
        .unwrap();

    let contract_address_salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");

    // create a transaction for deploying the first account
    let account1_deploy_tx = DeployAccount::new(
        *ACCOUNT1_CLASS_HASH, // class hash
        0,                    // max fee
        1.into(),             // tx version
        Felt252::zero(),      // nonce
        vec![2.into()],       // constructor calldata
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
        .execute(&mut state, &Default::default(), Some(program_cache.clone()))
        .expect("failed to execute the deployment of account 1")
        .validate_info
        .expect("validate_info missing")
        .contract_address;

    // now we need to deploy account2
    let account2_deploy_tx = DeployAccount::new(
        *ACCOUNT1_CLASS_HASH, // class hash
        0,                    // max fee
        1.into(),             // tx version
        Felt252::zero(),      // nonce
        vec![3.into()],       // constructor calldata
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
    let _account2_address = account2_deploy_tx
        .execute(&mut state, &Default::default(), Some(program_cache.clone()))
        .expect("failed to execute the deployment of account 2")
        .validate_info
        .expect("validate_info missing")
        .contract_address;

    // 4. do transfers between the accounts

    let transfer_entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"transfer"));
    // calldata for transfering 123 tokens from account1 to account2
    let calldata = vec![Felt252::from(12), Felt252::from(123)];

    for _ in 0..executions {
        let result = execute(
            &mut state.clone_for_testing(),
            &account1_address,
            &erc20_address,
            &transfer_entrypoint_selector.clone(),
            &calldata.clone(),
            EntryPointType::External,
            &ERC20_CLASS_HASH,
            program_cache.clone(),
        );

        _ = std::hint::black_box(result);
    }
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn execute(
    state: &mut CachedState<InMemoryStateReader, PermanentContractClassCache>,
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
        .execute(
            state,
            &block_context,
            &mut resources_manager,
            &mut tx_execution_context,
            false,
            block_context.invoke_tx_max_n_steps(),
            Some(program_cache),
        )
        .unwrap()
        .call_info
        .unwrap()
}
