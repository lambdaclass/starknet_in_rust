/*
Usage:
    With cairo-native feature enabled:
        * Running the bench by itself will default to JIT mode
        * You can choose to run either in JIT (Just in time) or AOT (Ahead of time) mode
        by passing either "jit" or "aot" as an argument when running the bench
        * Example:
            `cargo bench --features cairo-native --bench internals aot`
    Without cairo-native feature enabled:
        * Runs the bench using cairo_vm, no customization args
*/

#![deny(warnings)]
#[cfg(feature = "cairo-native")]
use {
    cairo_native::cache::{AotProgramCache, JitProgramCache, ProgramCache},
    starknet_in_rust::utils::get_native_context,
    tracing::info,
};

use cairo_vm::Felt252;
use lazy_static::lazy_static;
use starknet_in_rust::{
    core::contract_address::compute_deprecated_class_hash,
    definitions::{
        block_context::StarknetChainId,
        constants::{TRANSACTION_VERSION, VALIDATE_ENTRY_POINT_SELECTOR},
    },
    hash_utils::calculate_contract_address,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState, contract_class_cache::PermanentContractClassCache,
        in_memory_state_reader::InMemoryStateReader, state_api::State,
    },
    transaction::{
        declare_deprecated::DeclareDeprecated, Address, ClassHash, Deploy, DeployAccount,
        InvokeFunction,
    },
};
use std::{hint::black_box, sync::Arc};

#[cfg(feature = "cairo-native")]
use std::{cell::RefCell, rc::Rc};

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
        "starknet_programs/account_without_validation.json",
    ).unwrap();
    static ref CLASS_HASH_FELT: Felt252 = compute_deprecated_class_hash(&CONTRACT_CLASS).unwrap();
    static ref CLASS_HASH: ClassHash = ClassHash(CLASS_HASH_FELT.to_bytes_be());
    static ref SALT: Felt252 = Felt252::from_dec_str(
        "2669425616857739096022668060305620640217901643963991674344872184515580705509"
    ).unwrap();
    static ref CONTRACT_ADDRESS: Address = Address(calculate_contract_address(&SALT, &CLASS_HASH_FELT, &[], Address(0.into())).unwrap());
    static ref SIGNATURE: Vec<Felt252> = vec![
        Felt252::from_dec_str("3233776396904427614006684968846859029149676045084089832563834729503047027074").unwrap(),
        Felt252::from_dec_str("707039245213420890976709143988743108543645298941971188668773816813012281203").unwrap(),
    ];
}

// This function just executes the given function. This adds a stack level
// to the flamegraph with the label "scope".
#[inline(never)]
fn scope<T>(f: impl FnOnce() -> T) -> T {
    f()
}

// We don't use the cargo test harness because it uses
// FnOnce calls for each test, that are merged in the flamegraph.
fn main() {
    #[cfg(feature = "cairo-native")]
    let program_cache = {
        let mut jit_run: bool = true;
        let args: Vec<String> = std::env::args().collect();
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
        let cache = if jit_run {
            ProgramCache::from(JitProgramCache::new(get_native_context()))
        } else {
            ProgramCache::from(AotProgramCache::new(get_native_context()))
        };
        Rc::new(RefCell::new(cache))
    };

    deploy_account(
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    );
    declare(
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    );
    deploy(
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    );
    invoke(
        #[cfg(feature = "cairo-native")]
        program_cache.clone(),
    );

    // The black_box ensures there's no tail-call optimization.
    // If not, the flamegraph ends up less nice.
    black_box(());
}

#[inline(never)]
pub fn deploy_account(
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) {
    const RUNS: usize = 500;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    state
        .set_contract_class(
            &CLASS_HASH,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();

    let block_context = &Default::default();

    for _ in 0..RUNS {
        let mut state_copy = state.clone_for_testing();
        let class_hash = *CLASS_HASH;
        let signature = SIGNATURE.clone();
        scope(|| {
            // new consumes more execution time than raw struct instantiation
            let internal_deploy_account = DeployAccount::new(
                class_hash,
                Default::default(),
                1.into(),
                Felt252::ZERO,
                vec![],
                signature,
                *SALT,
                StarknetChainId::TestNet.to_felt(),
            )
            .unwrap();
            internal_deploy_account.execute(
                &mut state_copy,
                block_context,
                #[cfg(feature = "cairo-native")]
                Some(program_cache.clone()),
            )
        })
        .unwrap();
    }
}

#[inline(never)]
pub fn declare(
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) {
    const RUNS: usize = 5;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    let block_context = &Default::default();

    for _ in 0..RUNS {
        let mut cloned_state = state.clone_for_testing();
        let class = CONTRACT_CLASS.clone();
        let address = CONTRACT_ADDRESS.clone();
        scope(|| {
            // new consumes more execution time than raw struct instantiation
            let declare_tx = DeclareDeprecated::new(
                class,
                StarknetChainId::TestNet.to_felt(),
                address,
                0,
                0.into(),
                vec![],
                Felt252::ZERO,
            )
            .expect("couldn't create transaction");

            declare_tx.execute(
                &mut cloned_state,
                block_context,
                #[cfg(feature = "cairo-native")]
                Some(program_cache.clone()),
            )
        })
        .unwrap();
    }
}

#[inline(never)]
pub fn deploy(
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) {
    const RUNS: usize = 8;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    state
        .set_contract_class(
            &CLASS_HASH,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();

    let block_context = &Default::default();

    for _ in 0..RUNS {
        let mut state_copy = state.clone_for_testing();
        let salt = Felt252::from_dec_str(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509",
        )
        .unwrap();
        let class = CONTRACT_CLASS.clone();
        scope(|| {
            // new consumes more execution time than raw struct instantiation
            let internal_deploy = Deploy::new(
                salt,
                class,
                vec![],
                StarknetChainId::TestNet.to_felt(),
                0.into(),
            )
            .unwrap();
            internal_deploy.execute(
                &mut state_copy,
                block_context,
                #[cfg(feature = "cairo-native")]
                Some(program_cache.clone()),
            )
        })
        .unwrap();
    }
}

#[inline(never)]
pub fn invoke(
    #[cfg(feature = "cairo-native")] program_cache: Rc<RefCell<ProgramCache<ClassHash>>>,
) {
    const RUNS: usize = 100;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    state
        .set_contract_class(
            &CLASS_HASH,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();

    let block_context = &Default::default();

    let salt = Felt252::from_dec_str(
        "2669425616857739096022668060305620640217901643963991674344872184515580705509",
    )
    .unwrap();
    let class = CONTRACT_CLASS.clone();
    let deploy = Deploy::new(
        salt,
        class,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        0.into(),
    )
    .unwrap();

    let _deploy_exec_info = deploy
        .execute(
            &mut state,
            block_context,
            #[cfg(feature = "cairo-native")]
            Some(program_cache.clone()),
        )
        .unwrap();

    for _ in 0..RUNS {
        let mut state_copy = state.clone_for_testing();
        let address = CONTRACT_ADDRESS.clone();
        let selector = *VALIDATE_ENTRY_POINT_SELECTOR;
        let signature = SIGNATURE.clone();
        let calldata = vec![address.0, selector, Felt252::ZERO];
        scope(|| {
            // new consumes more execution time than raw struct instantiation
            let internal_invoke = InvokeFunction::new(
                address,
                selector,
                Default::default(),
                *TRANSACTION_VERSION,
                calldata,
                signature,
                StarknetChainId::TestNet.to_felt(),
                Some(Felt252::ZERO),
            )
            .unwrap();
            internal_invoke.execute(
                &mut state_copy,
                block_context,
                2_000_000,
                #[cfg(feature = "cairo-native")]
                Some(program_cache.clone()),
            )
        })
        .unwrap();
    }
}
