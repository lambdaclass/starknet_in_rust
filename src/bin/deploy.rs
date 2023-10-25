use lazy_static::lazy_static;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    services::api::contract_classes::compiled_class::CompiledClass,
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    state::{cached_state::CachedState, in_memory_state_reader::InMemoryStateReader},
    state::{contract_class_cache::PermanentContractClassCache, state_api::State},
    transaction::{Deploy, Transaction},
};
use std::sync::Arc;

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
}

fn main() {
    const RUNS: usize = 100;

    let block_context = BlockContext::default();
    let state_reader = Arc::new(InMemoryStateReader::default());

    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );
    let call_data = vec![];

    for n in 0..RUNS {
        let contract_address_salt = n.into();

        let deploy = Deploy::new(
            contract_address_salt,
            CONTRACT_CLASS.clone(),
            call_data.clone(),
            block_context.starknet_os_config().chain_id().clone(),
            TRANSACTION_VERSION.clone(),
        )
        .unwrap();

        state
            .set_contract_class(
                &deploy.contract_hash,
                &CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
            )
            .unwrap();
        let tx = Transaction::Deploy(deploy);

        tx.execute(&mut state, &block_context, 0).unwrap();
    }
}
