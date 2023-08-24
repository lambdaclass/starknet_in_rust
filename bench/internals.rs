#![deny(warnings)]

use cairo_vm::felt;
use felt::{felt_str, Felt252};
use lazy_static::lazy_static;
use num_traits::Zero;
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
    state::in_memory_state_reader::InMemoryStateReader,
    state::{cached_state::CachedState, state_api::State},
    transaction::{declare::Declare, Deploy, DeployAccount, InvokeFunction},
    utils::Address,
};
use std::{
    collections::HashMap,
    hint::black_box,
    sync::{Arc, RwLock},
};

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
        "starknet_programs/account_without_validation.json",
    ).unwrap();
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
    deploy_account();
    declare();
    deploy();
    invoke();

    // The black_box ensures there's no tail-call optimization.
    // If not, the flamegraph ends up less nice.
    black_box(());
}

#[inline(never)]
fn deploy_account() {
    const RUNS: usize = 500;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(state_reader, Arc::new(RwLock::new(HashMap::new())));

    state
        .set_contract_class(
            &CLASS_HASH_BYTES,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();

    let block_context = &Default::default();

    for _ in 0..RUNS {
        let mut state_copy = state.clone();
        let class_hash = *CLASS_HASH_BYTES;
        let signature = SIGNATURE.clone();
        scope(|| {
            // new consumes more execution time than raw struct instantiation
            let internal_deploy_account = DeployAccount::new(
                class_hash,
                0,
                0.into(),
                Felt252::zero(),
                vec![],
                signature,
                SALT.clone(),
                StarknetChainId::TestNet.to_felt(),
            )
            .unwrap();
            internal_deploy_account.execute(&mut state_copy, block_context)
        })
        .unwrap();
    }
}

#[inline(never)]
fn declare() {
    const RUNS: usize = 5;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let state = CachedState::new(state_reader, Arc::new(RwLock::new(HashMap::new())));

    let block_context = &Default::default();

    for _ in 0..RUNS {
        let mut cloned_state = state.clone();
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
                Felt252::zero(),
            )
            .expect("couldn't create transaction");

            declare_tx.execute(&mut cloned_state, block_context)
        })
        .unwrap();
    }
}

#[inline(never)]
fn deploy() {
    const RUNS: usize = 8;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(state_reader, Arc::new(RwLock::new(HashMap::new())));

    state
        .set_contract_class(
            &CLASS_HASH_BYTES,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();

    let block_context = &Default::default();

    for _ in 0..RUNS {
        let mut state_copy = state.clone();
        let salt = felt_str!(
            "2669425616857739096022668060305620640217901643963991674344872184515580705509"
        );
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
            internal_deploy.execute(&mut state_copy, block_context)
        })
        .unwrap();
    }
}

#[inline(never)]
fn invoke() {
    const RUNS: usize = 100;

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(state_reader, Arc::new(RwLock::new(HashMap::new())));

    state
        .set_contract_class(
            &CLASS_HASH_BYTES,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();

    let block_context = &Default::default();

    let salt =
        felt_str!("2669425616857739096022668060305620640217901643963991674344872184515580705509");
    let class = CONTRACT_CLASS.clone();
    let deploy = Deploy::new(
        salt,
        class,
        vec![],
        StarknetChainId::TestNet.to_felt(),
        0.into(),
    )
    .unwrap();

    let _deploy_exec_info = deploy.execute(&mut state, block_context).unwrap();

    for _ in 0..RUNS {
        let mut state_copy = state.clone();
        let address = CONTRACT_ADDRESS.clone();
        let selector = VALIDATE_ENTRY_POINT_SELECTOR.clone();
        let signature = SIGNATURE.clone();
        let calldata = vec![address.0.clone(), selector.clone(), Felt252::zero()];
        scope(|| {
            // new consumes more execution time than raw struct instantiation
            let internal_invoke = InvokeFunction::new(
                address,
                selector,
                0,
                TRANSACTION_VERSION.clone(),
                calldata,
                signature,
                StarknetChainId::TestNet.to_felt(),
                Some(Felt252::zero()),
            )
            .unwrap();
            internal_invoke.execute(&mut state_copy, block_context, 2_000_000)
        })
        .unwrap();
    }
}
