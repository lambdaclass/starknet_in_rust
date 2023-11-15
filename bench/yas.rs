#![deny(clippy::pedantic)]
#![deny(warnings)]

use cairo_vm::felt::Felt252;
use lazy_static::lazy_static;
use num_traits::{One, Zero};
use starknet::core::utils::get_selector_from_name;
use starknet_in_rust::{
    core::contract_address::compute_casm_class_hash,
    definitions::block_context::{BlockContext, StarknetChainId},
    state::{cached_state::CachedState, state_api::StateReader},
    transaction::{DeclareV2, InvokeFunction},
    utils::Address,
};
use std::time::{Duration, Instant};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[cfg(feature = "cairo-native")]
use {
    cairo_native::cache::ProgramCache,
    starknet_in_rust::utils::{get_native_context, ClassHash},
    std::{cell::RefCell, rc::Rc},
};

const WARMUP_TIME: Duration = Duration::from_secs(3);
const BENCHMARK_TIME: Duration = Duration::from_secs(5);

lazy_static! {
    static ref ACCOUNT_ADDRESS: Felt252 = 4321.into();
    static ref OWNER_ADDRESS: Felt252 = 4321.into();
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let mut state = utils::default_state()?;
    #[cfg(feature = "cairo-native")]
    let program_cache = Rc::new(RefCell::new(ProgramCache::new(get_native_context())));

    // Declare ERC20, YASFactory, YASPool and YASRouter contracts.
    info!("Declaring the ERC20 contract.");
    let erc20_class_hash = declare_erc20(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    )?;
    info!("Declaring the YASFactory contract.");
    let yas_factory_class_hash = declare_yas_factory(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    )?;
    info!("Declaring the YASRouter contract.");
    let yas_router_class_hash = declare_yas_router(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    )?;
    info!("Declaring the YASPool contract.");
    let yas_pool_class_hash = declare_yas_pool(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    )?;

    // Deploy two ERC20 contracts.
    info!("Deploying TYAS0 token on ERC20.");
    let yas0_token_address = deploy_erc20(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &erc20_class_hash,
        "TYAS0",
        "$YAS0",
        (0x3782_dace_9d90_0000, 0),
        OWNER_ADDRESS.clone(),
    )?;
    info!("Deploying TYAS1 token on ERC20.");
    let yas1_token_address = deploy_erc20(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &erc20_class_hash,
        "TYAS1",
        "$YAS1",
        (0x3782_dace_9d90_0000, 0),
        OWNER_ADDRESS.clone(),
    )?;

    // Deploy YASFactory contract.
    info!("Deploying YASFactory contract.");
    let yas_factory_address = deploy_yas_factory(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &yas_factory_class_hash,
        OWNER_ADDRESS.clone(),
        yas_pool_class_hash.clone(),
    )?;

    // Deploy YASRouter contract.
    info!("Deploying YASRouter contract.");
    let yas_router_address = deploy_yas_router(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &yas_router_class_hash,
    )?;

    // Deploy YASPool contract.
    info!("Deploying YASPool contract.");
    let yas_pool_address = deploy_yas_pool(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &yas_pool_class_hash,
        yas_factory_address,
        yas0_token_address.clone(),
        yas1_token_address.clone(),
        0x0bb8,
        0x3c,
    )?;

    // Initialize pool (invoke).
    info!("Initializing pool.");
    initialize_pool(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &yas_pool_address,
        (79_228_162_514_264_337_593_543_950_336, 0),
        false,
    )?;

    debug!(
        "TYAS0 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas0_token_address,
            OWNER_ADDRESS.clone()
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            OWNER_ADDRESS.clone()
        )?
    );

    // Approve (invoke).
    info!("Approving tokens.");
    approve_max(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &ACCOUNT_ADDRESS,
        yas0_token_address.clone(),
        yas_router_address.clone(),
    )?;
    approve_max(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &ACCOUNT_ADDRESS,
        yas1_token_address.clone(),
        yas_router_address.clone(),
    )?;

    debug!(
        "TYAS0 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas0_token_address,
            OWNER_ADDRESS.clone()
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            OWNER_ADDRESS.clone()
        )?
    );

    // Mint (invoke).
    info!("Minting tokens.");
    mint(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &ACCOUNT_ADDRESS,
        yas_router_address.clone(),
        yas_pool_address.clone(),
        OWNER_ADDRESS.clone(),
        -887_220,
        887_220,
        2_000_000_000_000_000_000,
    )?;

    debug!(
        "TYAS0 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas0_token_address,
            OWNER_ADDRESS.clone()
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            OWNER_ADDRESS.clone()
        )?
    );

    let mut delta_t = Duration::ZERO;
    let mut num_runs = 0;
    let mut state = loop {
        let mut state = state.clone();

        let yas_router_address = yas_router_address.clone();
        let yas_pool_address = yas_pool_address.clone();

        // Swap (invoke).
        info!("Swapping tokens.");
        let t0 = Instant::now();
        swap(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &ACCOUNT_ADDRESS,
            yas_router_address,
            yas_pool_address,
            OWNER_ADDRESS.clone(),
            true,
            (500_000_000_000_000_000, 0, true),
            (4_295_128_740, 0, false),
        )?;
        let t1 = Instant::now();

        delta_t += t1.duration_since(t0);
        if delta_t >= WARMUP_TIME {
            num_runs += 1;

            if delta_t >= (WARMUP_TIME + BENCHMARK_TIME) {
                break state;
            }
        }
    };

    let delta_t = (delta_t - WARMUP_TIME).as_secs_f64();
    println!(
        "Executed {num_runs} swaps taking {delta_t} seconds ({} #/s, or {} s/#)",
        f64::from(num_runs) / delta_t,
        delta_t / f64::from(num_runs),
    );

    debug!(
        "TYAS0 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas0_token_address,
            OWNER_ADDRESS.clone()
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            OWNER_ADDRESS.clone()
        )?
    );

    Ok(())
}

fn declare_erc20<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("ERC20")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        0,
        2.into(),
        vec![],
        nonce,
    )?
    .execute(
        state,
        &BlockContext::default(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn declare_yas_factory<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASFactory")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        0,
        2.into(),
        vec![],
        nonce,
    )?
    .execute(
        state,
        &BlockContext::default(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn declare_yas_router<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASRouter")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        0,
        2.into(),
        vec![],
        nonce,
    )?
    .execute(
        state,
        &BlockContext::default(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn declare_yas_pool<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let (sierra_contract_class, casm_contract_class) = utils::load_contract("YASPool")?;
    let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?;

    let sender_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&sender_address).unwrap();

    let tx_execution_info = DeclareV2::new(
        &sierra_contract_class,
        Some(casm_contract_class),
        casm_class_hash.clone(),
        StarknetChainId::TestNet.to_felt(),
        sender_address,
        0,
        2.into(),
        vec![],
        nonce,
    )?
    .execute(
        state,
        &BlockContext::default(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let validate_info = tx_execution_info.validate_info.unwrap();
    if validate_info.failure_flag {
        utils::panic_with_cairo_error(&validate_info.retdata);
    }

    Ok(casm_class_hash)
}

fn deploy_erc20<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    erc20_class_hash: &Felt252,
    name: &str,
    symbol: &str,
    initial_supply: (u128, u128),
    recipient: Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let contract_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        0,
        Felt252::one(),
        vec![
            erc20_class_hash.clone(),
            nonce.clone(),
            5.into(),
            utils::str_to_felt252(name),
            utils::str_to_felt252(symbol),
            initial_supply.0.into(),
            initial_supply.1.into(),
            recipient,
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0].clone())
}

fn deploy_yas_factory<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    yas_factory_class_hash: &Felt252,
    owner_address: Felt252,
    pool_class_hash: Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let contract_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        0,
        Felt252::one(),
        vec![
            yas_factory_class_hash.clone(),
            nonce.clone(),
            2.into(),
            owner_address,
            pool_class_hash,
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0].clone())
}

fn deploy_yas_router<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    yas_router_class_hash: &Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let contract_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        0,
        Felt252::one(),
        vec![
            yas_router_class_hash.clone(),
            nonce.clone(),
            Felt252::zero(),
        ],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0].clone())
}

#[allow(clippy::too_many_arguments)]
fn deploy_yas_pool<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    yas_pool_class_hash: &Felt252,
    yas_factory_address: Felt252,
    yas0_token_address: Felt252,
    yas1_token_address: Felt252,
    fee: u32,
    tick_spacing: i32,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let contract_address = Address(ACCOUNT_ADDRESS.clone());
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("deploy")?.to_bytes_be()),
        0,
        Felt252::one(),
        vec![
            yas_pool_class_hash.clone(),
            nonce.clone(),
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
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0].clone())
}

fn initialize_pool<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    yas_pool_address: &Felt252,
    price_sqrt: (u128, u128),
    sign: bool,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let contract_address = Address(yas_pool_address.clone());
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("initialize").unwrap().to_bytes_be()),
        0,
        Felt252::one(),
        vec![
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

fn approve_max<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    account_address: &Felt252,
    token_address: Felt252,
    wallet_address: Felt252,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let account_address = Address(account_address.clone());
    let nonce = state.get_nonce_at(&account_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        account_address,
        Felt252::from_bytes_be(&get_selector_from_name("__execute__").unwrap().to_bytes_be()),
        0,
        Felt252::one(),
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mint<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
{
    let account_address = Address(account_address.clone());
    let nonce = state.get_nonce_at(&account_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        account_address,
        Felt252::from_bytes_be(&get_selector_from_name("__execute__").unwrap().to_bytes_be()),
        0,
        Felt252::one(),
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn swap<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
{
    let account_address = Address(account_address.clone());
    let nonce = state.get_nonce_at(&account_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        account_address,
        Felt252::from_bytes_be(&get_selector_from_name("__execute__").unwrap().to_bytes_be()),
        0,
        Felt252::one(),
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(())
}

fn balance_of<S>(
    state: &mut CachedState<S>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
    token_address: &Felt252,
    wallet_address: Felt252,
) -> Result<Felt252, Box<dyn std::error::Error>>
where
    S: StateReader,
{
    let contract_address = Address(token_address.clone());
    let nonce = state.get_nonce_at(&contract_address).unwrap();

    let tx_execution_info = InvokeFunction::new(
        contract_address,
        Felt252::from_bytes_be(&get_selector_from_name("balanceOf").unwrap().to_bytes_be()),
        0,
        Felt252::one(),
        vec![wallet_address],
        vec![],
        StarknetChainId::TestNet.to_felt(),
        Some(nonce),
    )?
    .execute(
        state,
        &BlockContext::default(),
        u64::MAX.into(),
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0].clone())
}

mod utils {
    use crate::ACCOUNT_ADDRESS;
    use cairo_vm::felt::Felt252;
    use num_traits::{One, Zero};
    use starknet_in_rust::{
        core::contract_address::{compute_casm_class_hash, compute_sierra_class_hash},
        services::api::contract_classes::compiled_class::CompiledClass,
        state::{
            cached_state::CachedState, in_memory_state_reader::InMemoryStateReader,
            state_api::State,
        },
        utils::Address,
        CasmContractClass, ContractClass as SierraContractClass,
    };
    use std::{collections::HashMap, fs, path::Path, sync::Arc};

    const BASE_DIR: &str = "bench/yas/";

    pub fn str_to_felt252(value: &str) -> Felt252 {
        assert!(value.len() < 32);
        value
            .bytes()
            .fold(Felt252::zero(), |acc, ch| (acc << 8u32) + u32::from(ch))
    }

    pub fn panic_with_cairo_error(retdata: &[Felt252]) {
        panic!(
            "{:#?}",
            retdata
                .iter()
                .map(Felt252::to_bytes_be)
                .map(String::from_utf8)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        )
    }

    pub fn default_state() -> Result<CachedState<InMemoryStateReader>, Box<dyn std::error::Error>> {
        let (sierra_contract_class, casm_contract_class) = load_contract("YasCustomAccount")?;
        let casm_class_hash = compute_casm_class_hash(&casm_contract_class)?.to_be_bytes();

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(Address(ACCOUNT_ADDRESS.clone()), casm_class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(Address(ACCOUNT_ADDRESS.clone()), Felt252::one());

        let mut cached_state = CachedState::new(
            Arc::new(state_reader),
            HashMap::from([(
                casm_class_hash,
                CompiledClass::Casm(Arc::new(casm_contract_class)),
            )]),
        );

        let sierra_class_hash = compute_sierra_class_hash(&sierra_contract_class)?.to_be_bytes();
        cached_state.set_sierra_program(
            &Felt252::from_bytes_be(&sierra_class_hash),
            Arc::new((
                sierra_contract_class.extract_sierra_program()?,
                sierra_contract_class.entry_points_by_type,
            )),
        );
        cached_state.set_compiled_class_hash(
            &Felt252::from_bytes_be(&sierra_class_hash),
            &Felt252::from_bytes_be(&casm_class_hash),
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
