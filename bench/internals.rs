#![deny(warnings)]
#[cfg(feature = "cairo-native")]
use cairo_native::cache::{JitProgramCache, ProgramCache};

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
    state::{cached_state::CachedState, state_api::State},
    state::{
        contract_class_cache::PermanentContractClassCache,
        in_memory_state_reader::InMemoryStateReader,
    },
    transaction::{declare::Declare, Deploy, DeployAccount, InvokeFunction},
    utils::{Address, ClassHash},
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
    {
        let program_cache = Rc::new(RefCell::new(ProgramCache::Jit(JitProgramCache::new(
            starknet_in_rust::utils::get_native_context(),
        ))));

        deploy_account(program_cache.clone());
        declare(program_cache.clone());
        deploy(program_cache.clone());
        invoke(program_cache.clone());
    }

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
                0,
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
            let declare_tx = Declare::new(
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
                0,
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
