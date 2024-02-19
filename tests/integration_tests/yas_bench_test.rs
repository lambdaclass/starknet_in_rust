/* This test replicates the code in bench/yas.rs
It runs the benchmark logic using both the VM and the cairo native compiler (in jit mode),
comparing the account balances and the state after each swap in order to verify that the execution is correct and the benchmark is valid
 */
#![deny(warnings)]
#![cfg(feature = "cairo-native")]

use std::default::Default;

use cairo_vm::Felt252;
use lazy_static::lazy_static;
use starknet::core::utils::get_selector_from_name;
use starknet_in_rust::definitions::constants::EXECUTE_ENTRY_POINT_SELECTOR;
use starknet_in_rust::{
    core::contract_address::compute_casm_class_hash,
    definitions::block_context::{BlockContext, StarknetChainId},
    state::{
        cached_state::CachedState, contract_class_cache::ContractClassCache, state_api::StateReader,
    },
    transaction::{Address, ClassHash, Declare, InvokeFunction},
};
use tracing::info;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use {
    cairo_native::cache::{JitProgramCache, ProgramCache},
    starknet_in_rust::utils::get_native_context,
    std::{cell::RefCell, rc::Rc},
};

lazy_static! {
    static ref ACCOUNT_ADDRESS: Felt252 = 4321.into();
    static ref OWNER_ADDRESS: Felt252 = 4321.into();
}

#[allow(clippy::too_many_lines)]
#[test]
fn compare_yas_bench() -> Result<(), Box<dyn std::error::Error>> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let mut state_vm = utils::default_state()?;
    let mut state_jit = utils::default_state()?;
    let program_cache_vm = None;
    let program_cache_jit = Some(Rc::new(RefCell::new(ProgramCache::from(
        JitProgramCache::new(get_native_context()),
    ))));
    // Execute pre-swap operations
    // Declare ERC20, YASFactory, YASPool and YASRouter contracts.
    info!("Declaring the ERC20 contract.");
    let erc20_class_hash_jit = declare_erc20(&mut state_jit, program_cache_jit.clone())?;
    let erc20_class_hash_vm = declare_erc20(&mut state_vm, program_cache_vm.clone())?;
    info!("Declaring the YASFactory contract.");
    let yas_factory_class_hash_jit =
        declare_yas_factory(&mut state_jit, program_cache_jit.clone())?;
    let yas_factory_class_hash_vm = declare_yas_factory(&mut state_vm, program_cache_vm.clone())?;
    info!("Declaring the YASRouter contract.");
    let yas_router_class_hash_jit = declare_yas_router(&mut state_jit, program_cache_jit.clone())?;
    let yas_router_class_hash_vm = declare_yas_router(&mut state_vm, program_cache_vm.clone())?;
    info!("Declaring the YASPool contract.");
    let yas_pool_class_hash_jit = declare_yas_pool(&mut state_jit, program_cache_jit.clone())?;
    let yas_pool_class_hash_vm = declare_yas_pool(&mut state_vm, program_cache_vm.clone())?;

    // Deploy two ERC20 contracts.
    info!("Deploying TYAS0 token on ERC20.");
    let yas0_token_address_jit = deploy_erc20(
        &mut state_jit,
        program_cache_jit.clone(),
        &erc20_class_hash_jit,
        "TYAS0",
        "$YAS0",
        (0x3782_dace_9d90_0000, 0),
        *OWNER_ADDRESS,
    )?;
    let yas0_token_address_vm = deploy_erc20(
        &mut state_vm,
        program_cache_vm.clone(),
        &erc20_class_hash_vm,
        "TYAS0",
        "$YAS0",
        (0x3782_dace_9d90_0000, 0),
        *OWNER_ADDRESS,
    )?;
    info!("Deploying TYAS1 token on ERC20.");
    let yas1_token_address_jit = deploy_erc20(
        &mut state_jit,
        program_cache_jit.clone(),
        &erc20_class_hash_jit,
        "TYAS1",
        "$YAS1",
        (0x3782_dace_9d90_0000, 0),
        *OWNER_ADDRESS,
    )?;
    let yas1_token_address_vm = deploy_erc20(
        &mut state_vm,
        program_cache_vm.clone(),
        &erc20_class_hash_vm,
        "TYAS1",
        "$YAS1",
        (0x3782_dace_9d90_0000, 0),
        *OWNER_ADDRESS,
    )?;

    // Deploy YASFactory contract.
    info!("Deploying YASFactory contract.");
    let yas_factory_address_jit = deploy_yas_factory(
        &mut state_jit,
        program_cache_jit.clone(),
        &yas_factory_class_hash_jit,
        *OWNER_ADDRESS,
        yas_pool_class_hash_jit,
    )?;
    let yas_factory_address_vm = deploy_yas_factory(
        &mut state_vm,
        program_cache_vm.clone(),
        &yas_factory_class_hash_vm,
        *OWNER_ADDRESS,
        yas_pool_class_hash_vm,
    )?;

    // Deploy YASRouter contract.
    info!("Deploying YASRouter contract.");
    let yas_router_address_jit = deploy_yas_router(
        &mut state_jit,
        program_cache_jit.clone(),
        &yas_router_class_hash_jit,
    )?;
    let yas_router_address_vm = deploy_yas_router(
        &mut state_vm,
        program_cache_vm.clone(),
        &yas_router_class_hash_vm,
    )?;

    // Deploy YASPool contract.
    info!("Deploying YASPool contract.");
    let yas_pool_address_jit = deploy_yas_pool(
        &mut state_jit,
        program_cache_jit.clone(),
        &yas_pool_class_hash_jit,
        yas_factory_address_jit,
        yas0_token_address_jit,
        yas1_token_address_jit,
        0x0bb8,
        0x3c,
    )?;
    let yas_pool_address_vm = deploy_yas_pool(
        &mut state_vm,
        program_cache_vm.clone(),
        &yas_pool_class_hash_vm,
        yas_factory_address_vm,
        yas0_token_address_vm,
        yas1_token_address_vm,
        0x0bb8,
        0x3c,
    )?;

    // Initialize pool (invoke).
    info!("Initializing pool.");
    initialize_pool(
        &mut state_jit,
        program_cache_jit.clone(),
        &yas_pool_address_jit,
        (79_228_162_514_264_337_593_543_950_336, 0),
        false,
    )?;
    initialize_pool(
        &mut state_vm,
        program_cache_vm.clone(),
        &yas_pool_address_vm,
        (79_228_162_514_264_337_593_543_950_336, 0),
        false,
    )?;

    // Approve (invoke).
    info!("Approving tokens.");
    approve_max(
        &mut state_jit,
        program_cache_jit.clone(),
        &ACCOUNT_ADDRESS,
        yas0_token_address_jit,
        yas_router_address_jit,
    )?;
    approve_max(
        &mut state_jit,
        program_cache_jit.clone(),
        &ACCOUNT_ADDRESS,
        yas1_token_address_jit,
        yas_router_address_jit,
    )?;
    approve_max(
        &mut state_vm,
        program_cache_vm.clone(),
        &ACCOUNT_ADDRESS,
        yas0_token_address_vm,
        yas_router_address_vm,
    )?;
    approve_max(
        &mut state_vm,
        program_cache_vm.clone(),
        &ACCOUNT_ADDRESS,
        yas1_token_address_vm,
        yas_router_address_vm,
    )?;

    // Mint (invoke).
    info!("Minting tokens.");
    mint(
        &mut state_jit,
        program_cache_jit.clone(),
        &ACCOUNT_ADDRESS,
        yas_router_address_jit,
        yas_pool_address_jit,
        *OWNER_ADDRESS,
        -887_220,
        887_220,
        2_000_000_000_000_000_000,
    )?;
    mint(
        &mut state_vm,
        program_cache_vm.clone(),
        &ACCOUNT_ADDRESS,
        yas_router_address_vm,
        yas_pool_address_vm,
        *OWNER_ADDRESS,
        -887_220,
        887_220,
        2_000_000_000_000_000_000,
    )?;

    // Execute swaps

    for _ in 0..5 {
        swap(
            &mut state_jit,
            program_cache_jit.clone(),
            &ACCOUNT_ADDRESS,
            yas_router_address_jit,
            yas_pool_address_jit,
            *OWNER_ADDRESS,
            true,
            (500_000_000_000_000_000, 0, true),
            (4_295_128_740, 0, false),
        )?;

        swap(
            &mut state_vm,
            program_cache_vm.clone(),
            &ACCOUNT_ADDRESS,
            yas_router_address_vm,
            yas_pool_address_vm,
            *OWNER_ADDRESS,
            true,
            (500_000_000_000_000_000, 0, true),
            (4_295_128_740, 0, false),
        )?;

        // Check the token balances for each run

        let tyas0_jit = balance_of(
            &mut state_jit,
            program_cache_jit.clone(),
            &yas0_token_address_jit,
            *OWNER_ADDRESS,
        )?;
        let tyas1_jit = balance_of(
            &mut state_jit,
            program_cache_jit.clone(),
            &yas0_token_address_jit,
            *OWNER_ADDRESS,
        )?;

        let tyas0_vm = balance_of(
            &mut state_vm,
            program_cache_vm.clone(),
            &yas0_token_address_vm,
            *OWNER_ADDRESS,
        )?;
        let tyas1_vm = balance_of(
            &mut state_vm,
            program_cache_vm.clone(),
            &yas0_token_address_vm,
            *OWNER_ADDRESS,
        )?;

        assert_eq!(tyas0_jit, tyas0_vm);
        assert_eq!(tyas1_jit, tyas1_vm);

        // Check the state of each run
        assert_eq!(state_jit.cache(), state_vm.cache());
    }

    Ok(())
}

fn declare_erc20<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("ERC20")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = Declare::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash,
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        Default::default(),
        2.into(),
        vec![],
        nonce,
    )?
    .execute(state, &BlockContext::default(), program_cache)?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn declare_yas_factory<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASFactory")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = Declare::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash,
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        Default::default(),
        2.into(),
        vec![],
        nonce,
    )?
    .execute(state, &BlockContext::default(), program_cache)?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn declare_yas_router<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASRouter")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = Declare::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash,
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        Default::default(),
        2.into(),
        vec![],
        nonce,
    )?
    .execute(state, &BlockContext::default(), program_cache)?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn declare_yas_pool<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASPool")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = Declare::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash,
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        Default::default(),
        2.into(),
        vec![],
        nonce,
    )?
    .execute(state, &BlockContext::default(), program_cache)?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn deploy_erc20<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    erc20_class_hash: &Felt252,
    name: &str,
    symbol: &str,
    initial_supply: (u128, u128),
    recipient: Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let contract_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        Default::default(),
        Felt252::ZERO,
        vec![
            *erc20_class_hash,
            nonce,
            5.into(),
            Felt252::from_bytes_be_slice(name.as_bytes()),
            Felt252::from_bytes_be_slice(symbol.as_bytes()),
            initial_supply.0.into(),
            initial_supply.1.into(),
            recipient,
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        None,
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0])
}

fn deploy_yas_factory<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    yas_factory_class_hash: &Felt252,
    owner_address: Felt252,
    pool_class_hash: Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let contract_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        Default::default(),
        Felt252::ZERO,
        vec![
            *yas_factory_class_hash,
            nonce,
            2.into(),
            owner_address,
            pool_class_hash,
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        None,
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0])
}

fn deploy_yas_router<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    yas_router_class_hash: &Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let contract_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        Default::default(),
        Felt252::ZERO,
        vec![*yas_router_class_hash, nonce, Felt252::ZERO],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        None,
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0])
}

#[allow(clippy::too_many_arguments)]
fn deploy_yas_pool<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    yas_pool_class_hash: &Felt252,
    yas_factory_address: Felt252,
    yas0_token_address: Felt252,
    yas1_token_address: Felt252,
    fee: u32,
    tick_spacing: i32,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let contract_address = Address(*ACCOUNT_ADDRESS);
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        Default::default(),
        Felt252::ZERO,
        vec![
            *yas_pool_class_hash,
            nonce,
            6.into(),
            yas_factory_address,
            yas0_token_address,
            yas1_token_address,
            fee.into(),
            tick_spacing.into(),
            0.into(),
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        None,
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0])
}

fn initialize_pool<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    yas_pool_address: &Felt252,
    price_sqrt: (u128, u128),
    sign: bool,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let contract_address = *yas_pool_address;
    let contract_entrypoint =
        Felt252::from_bytes_be(&get_selector_from_name("initialize").unwrap().to_bytes_be());
    let nonce = state.get_nonce_at(&Address(*ACCOUNT_ADDRESS)).unwrap();

    let tx_execution_info = InvokeFunction::new(
        Address(*ACCOUNT_ADDRESS),
        *EXECUTE_ENTRY_POINT_SELECTOR,
        Default::default(),
        Felt252::ONE,
        vec![
            Felt252::ONE,
            contract_address,
            contract_entrypoint,
            Felt252::THREE,
            price_sqrt.0.into(),
            price_sqrt.1.into(),
            u32::from(sign).into(),
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

fn approve_max<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    account_address: &Felt252,
    token_address: Felt252,
    wallet_address: Felt252,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let account_address = Address(*account_address);
    let nonce = state.get_nonce_at(&account_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        account_address,
        Felt252::from_bytes_be(&get_selector_from_name("__execute__").unwrap().to_bytes_be()),
        Default::default(),
        Felt252::ONE,
        vec![
            1.into(),
            token_address,
            Felt252::from_bytes_be(&get_selector_from_name("approve").unwrap().to_bytes_be()),
            3.into(),
            wallet_address,
            u128::MAX.into(),
            u128::MAX.into(),
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mint<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    account_address: &Felt252,
    yas_router_address: Felt252,
    yas_pool_address: Felt252,
    recipient: Felt252,
    tick_lower: i32,
    tick_upper: i32,
    amount: u128,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let account_address = Address(*account_address);
    let nonce = state.get_nonce_at(&account_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        account_address,
        Felt252::from_bytes_be(&get_selector_from_name("__execute__").unwrap().to_bytes_be()),
        Default::default(),
        Felt252::ONE,
        vec![
            1.into(),
            yas_router_address,
            Felt252::from_bytes_be(&get_selector_from_name("mint").unwrap().to_bytes_be()),
            7.into(),
            yas_pool_address,
            recipient,
            tick_lower.unsigned_abs().into(),
            u32::from(tick_lower.is_negative()).into(),
            tick_upper.unsigned_abs().into(),
            u32::from(tick_upper.is_negative()).into(),
            amount.into(),
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn swap<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    account_address: &Felt252,
    yas_router_address: Felt252,
    yas_pool_address: Felt252,
    recipient: Felt252,
    zero_for_one: bool,
    amount_specified: (u128, u128, bool),
    price_limit_sqrt: (u128, u128, bool),
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let account_address = Address(*account_address);
    let nonce = state.get_nonce_at(&account_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        account_address,
        Felt252::from_bytes_be(&get_selector_from_name("__execute__").unwrap().to_bytes_be()),
        Default::default(),
        Felt252::ONE,
        vec![
            1.into(),
            yas_router_address,
            Felt252::from_bytes_be(&get_selector_from_name("swap").unwrap().to_bytes_be()),
            9.into(),
            yas_pool_address,
            recipient,
            u32::from(zero_for_one).into(),
            amount_specified.0.into(),
            amount_specified.1.into(),
            u32::from(amount_specified.2).into(),
            price_limit_sqrt.0.into(),
            price_limit_sqrt.1.into(),
            u32::from(price_limit_sqrt.2).into(),
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

fn balance_of<S, C>(
    state: &mut CachedState<S, C>,
    program_cache: Option<Rc<RefCell<ProgramCache<ClassHash>>>>,
    token_address: &Felt252,
    wallet_address: Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
    C: ContractClassCache,
{
    let contract_address = *token_address;
    let contract_entrypoint =
        Felt252::from_bytes_be(&get_selector_from_name("balanceOf").unwrap().to_bytes_be());
    let nonce = state.get_nonce_at(&Address(*ACCOUNT_ADDRESS)).unwrap();

    let tx_execution_info = InvokeFunction::new(
        Address(*ACCOUNT_ADDRESS),
        *EXECUTE_ENTRY_POINT_SELECTOR,
        Default::default(),
        Felt252::ONE,
        vec![
            Felt252::ONE,
            contract_address,
            contract_entrypoint,
            Felt252::ONE,
            wallet_address,
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        program_cache,
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0])
}

mod utils {
    use crate::integration_tests::yas_bench_test::ACCOUNT_ADDRESS;
    use cairo_vm::Felt252;
    use starknet_in_rust::{
        core::contract_address::{compute_casm_class_hash, compute_sierra_class_hash},
        services::api::contract_classes::compiled_class::CompiledClass,
        state::{
            cached_state::CachedState, contract_class_cache::PermanentContractClassCache,
            in_memory_state_reader::InMemoryStateReader, state_api::State,
        },
        transaction::Address,
        transaction::ClassHash,
        CasmContractClass, ContractClass as SierraContractClass,
    };
    use std::{fs, path::Path, sync::Arc};

    const BASE_DIR: &str = "bench/yas/";

    pub fn panic_with_cairo_error(retdata: &[Felt252]) {
        panic!(
            "{:#?}",
            retdata
                .iter()
                .map(|x| String::from_utf8(Felt252::to_bytes_be(x).to_vec()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        )
    }

    pub fn default_state() -> Result<
        CachedState<InMemoryStateReader, PermanentContractClassCache>,
        Box<dyn std::error::Error>,
    > {
        let (sierra_contract_class, casm_contract_class) = load_contract("YasCustomAccount")?;
        let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?.to_bytes_be();
        let sierra_class_hash = compute_sierra_class_hash(&sierra_contract_class)?.to_bytes_be();

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(Address(*ACCOUNT_ADDRESS), ClassHash(casm_class_hash));
        state_reader
            .address_to_nonce_mut()
            .insert(Address(*ACCOUNT_ADDRESS), Felt252::ONE);

        let mut cached_state = CachedState::new(Arc::new(state_reader), {
            let cache = PermanentContractClassCache::default();
            cache.extend([(
                ClassHash(casm_class_hash),
                CompiledClass::Casm {
                    casm: Arc::new(casm_contract_class),
                    sierra: Some(Arc::new((
                        sierra_contract_class.extract_sierra_program()?,
                        sierra_contract_class.entry_points_by_type,
                    ))),
                },
            )]);

            Arc::new(cache)
        });
        cached_state.set_compiled_class_hash(
            &Felt252::from_bytes_be(&casm_class_hash),
            &Felt252::from_bytes_be(&sierra_class_hash),
        )?;

        Ok(cached_state)
    }

    pub fn load_contract(
        name: &str,
    ) -> Result<(SierraContractClass, CasmContractClass), Box<dyn std::error::Error>> {
        let sierra_contract_class = serde_json::from_str::<SierraContractClass>(
            &fs::read_to_string(Path::new(BASE_DIR).join(name).with_extension("sierra.json"))?,
        )?;
        let casm_contract_class = serde_json::from_str::<CasmContractClass>(&fs::read_to_string(
            Path::new(BASE_DIR).join(name).with_extension("json"),
        )?)?;

        Ok((sierra_contract_class, casm_contract_class))
    }
}
