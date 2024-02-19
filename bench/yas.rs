/*
Usage:
    With cairo-native feature enabled:
        * Running the bench by itself will default to JIT mode
        * You can choose to run either in JIT (Just in time) or AOT (Ahead of time) mode
        by passing either "jit" or "aot" as an argument when running the bench
        * Example:
            `cargo bench --features cairo-native --bench yas aot`
    Without cairo-native feature enabled:
        * Runs the bench using cairo_vm, no customization args
*/
#![deny(warnings)]

use cairo_vm::Felt252;
use lazy_static::lazy_static;
use starknet::core::utils::get_selector_from_name;
use starknet_in_rust::{
    core::contract_address::compute_casm_class_hash,
    definitions::{
        block_context::{BlockContext, StarknetChainId},
        constants::EXECUTE_ENTRY_POINT_SELECTOR,
    },
    state::{
        cached_state::CachedState, contract_class_cache::ContractClassCache, state_api::StateReader,
    },
    transaction::{Address, Declare, InvokeFunction},
};
use std::time::{Duration, Instant};
use tracing::{debug, info};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[cfg(feature = "cairo-native")]
use {
    cairo_native::cache::{AotProgramCache, JitProgramCache, ProgramCache},
    starknet_in_rust::transaction::ClassHash,
    starknet_in_rust::utils::get_native_context,
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
    #[cfg(feature = "cairo-native")]
    let mut jit_run: bool = true;
    #[cfg(feature = "cairo-native")]
    let args: Vec<String> = std::env::args().collect();
    #[cfg(feature = "cairo-native")]
    if args.len() < 2 {
        info!("No mode selected, running in JIT mode");
    } else {
        match &*args[1] {
            "jit" => {
                info!("Running in JIT mode");
            }
            "aot" => {
                info!("Running in AOT mode");
                jit_run = false;
            }
            arg => {
                info!("Invalid mode {}, running in JIT mode", arg);
            }
        }
    }

    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let mut state = utils::default_state()?;
    #[cfg(feature = "cairo-native")]
    let cache = if jit_run {
        ProgramCache::from(JitProgramCache::new(get_native_context()))
    } else {
        ProgramCache::from(AotProgramCache::new(get_native_context()))
    };
    #[cfg(feature = "cairo-native")]
    let program_cache = Rc::new(RefCell::new(cache));

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
        *OWNER_ADDRESS,
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
        *OWNER_ADDRESS,
    )?;

    // Deploy YASFactory contract.
    info!("Deploying YASFactory contract.");
    let yas_factory_address = deploy_yas_factory(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &yas_factory_class_hash,
        *OWNER_ADDRESS,
        yas_pool_class_hash,
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
        yas0_token_address,
        yas1_token_address,
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
            *OWNER_ADDRESS
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            *OWNER_ADDRESS
        )?
    );

    // Approve (invoke).
    info!("Approving tokens.");
    approve_max(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &ACCOUNT_ADDRESS,
        yas0_token_address,
        yas_router_address,
    )?;
    approve_max(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &ACCOUNT_ADDRESS,
        yas1_token_address,
        yas_router_address,
    )?;

    debug!(
        "TYAS0 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas0_token_address,
            *OWNER_ADDRESS
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            *OWNER_ADDRESS
        )?
    );

    // Mint (invoke).
    info!("Minting tokens.");
    mint(
        &mut state,
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
        &ACCOUNT_ADDRESS,
        yas_router_address,
        yas_pool_address,
        *OWNER_ADDRESS,
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
            *OWNER_ADDRESS
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            *OWNER_ADDRESS
        )?
    );

    let mut delta_t = Duration::ZERO;
    let mut num_runs = 0;
    let mut state = loop {
        let mut state = state.clone();

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
            *OWNER_ADDRESS,
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
    let bench_mode = {
        #[cfg(feature = "cairo-native")]
        match jit_run {
            true => "JIT",
            false => "AOT",
        }
        #[cfg(not(feature = "cairo-native"))]
        "VM"
    };

    println!(
        "[{}] Executed {num_runs} swaps taking {delta_t} seconds ({} #/s, or {} s/#): benchmark",
        bench_mode,
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
            *OWNER_ADDRESS
        )?
    );
    debug!(
        "TYAS1 balance: {}",
        balance_of(
            &mut state,
            #[cfg(feature = "cairo-native")]
            program_cache.clone(),
            &yas1_token_address,
            *OWNER_ADDRESS
        )?
    );

    Ok(())
}

fn declare_erc20<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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

fn declare_yas_factory<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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

fn declare_yas_router<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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

fn declare_yas_pool<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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

fn deploy_erc20<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
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
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
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
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
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
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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

fn approve_max<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
fn mint<S, C>(
    state: &mut CachedState<S, C>,
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
fn swap<S, C>(
    state: &mut CachedState<S, C>,
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

fn balance_of<S, C>(
    state: &mut CachedState<S, C>,
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
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
        #[cfg(feature = "cairo-native")]
        Some(program_cache),
    )?;

    // Ensure the execution was successful.
    let call_info = tx_execution_info.call_info.unwrap();
    if call_info.failure_flag {
        utils::panic_with_cairo_error(&call_info.retdata);
    }

    Ok(call_info.retdata[0])
}

mod utils {
    use crate::ACCOUNT_ADDRESS;
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
