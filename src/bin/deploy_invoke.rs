use cairo_vm::felt::{felt_str, Felt252};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState, contract_class_cache::PermanentContractClassCache,
        in_memory_state_reader::InMemoryStateReader, state_api::State,
    },
    transaction::{Deploy, InvokeFunction, Transaction},
    utils::Address,
};
use std::{path::PathBuf, sync::Arc};

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
        "starknet_programs/first_contract.json",
    ).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/first_contract.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [5, 133, 114, 83, 104, 231, 159, 23, 87, 255, 235, 75, 170, 4, 84, 140, 49, 77, 101, 41, 147, 198, 201, 231, 38, 189, 215, 84, 231, 141, 140, 122];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref INCREASE_BALANCE_SELECTOR: Felt252 = felt_str!("1530486729947006463063166157847785599120665941190480211966374137237989315360");

    static ref GET_BALANCE_SELECTOR: Felt252 = felt_str!("1636223440827086009537493065587328807418413867743950350615962740049133672085");
}

fn main() {
    const RUNS: usize = 10000;

    let block_context = BlockContext::default();
    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    let call_data = vec![];
    let contract_address_salt = 1.into();
    let chain_id = block_context.starknet_os_config().chain_id().clone();

    let deploy = Deploy::new(
        contract_address_salt,
        CONTRACT_CLASS.clone(),
        call_data,
        block_context.starknet_os_config().chain_id().clone(),
        TRANSACTION_VERSION.clone(),
    )
    .unwrap();

    let contract_address = deploy.contract_address.clone();
    state
        .set_contract_class(
            &deploy.contract_hash,
            &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
        )
        .unwrap();
    let deploy_tx = Transaction::Deploy(deploy);

    let _tx_exec_info = deploy_tx.execute(&mut state, &block_context, 0).unwrap();

    let signature = Vec::new();

    // Statement **not** in blockifier.
    state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(contract_address.clone(), Felt252::zero());

    for i in 0..RUNS {
        let nonce_first = Felt252::from(i * 2);
        let nonce_second = Felt252::from((i * 2) + 1);

        let invoke_first = InvokeFunction::new(
            contract_address.clone(),
            INCREASE_BALANCE_SELECTOR.clone(),
            0,
            TRANSACTION_VERSION.clone(),
            vec![1000.into()],
            signature.clone(),
            chain_id.clone(),
            Some(nonce_first),
        )
        .unwrap();

        let tx = Transaction::InvokeFunction(invoke_first);
        tx.execute(&mut state, &block_context, 0).unwrap();

        let invoke_second = InvokeFunction::new(
            contract_address.clone(),
            GET_BALANCE_SELECTOR.clone(),
            0,
            TRANSACTION_VERSION.clone(),
            vec![],
            signature.clone(),
            chain_id.clone(),
            Some(nonce_second),
        )
        .unwrap();

        let tx = Transaction::InvokeFunction(invoke_second);
        let tx_exec_info = tx.execute(&mut state, &block_context, 0).unwrap();

        assert_eq!(
            tx_exec_info.call_info.unwrap().retdata,
            vec![((1000 * i) + 1000).into()]
        );
    }
}
