use cairo_vm::felt::{felt_str, Felt252};
use lazy_static::lazy_static;
use num_traits::Zero;
use starknet_in_rust::{
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState, contract_class_cache::PermanentContractClassCache,
        in_memory_state_reader::InMemoryStateReader,
    },
    testing::state::StarknetState,
    utils::Address,
};
use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

#[cfg(feature = "with_mimalloc")]
use mimalloc::MiMalloc;

#[cfg(feature = "with_mimalloc")]
#[global_allocator]
static ALLOC: MiMalloc = MiMalloc;

lazy_static! {
    // include_str! doesn't seem to work in CI
    static ref CONTRACT_CLASS: ContractClass = ContractClass::from_path(
        "starknet_programs/fibonacci.json",
    ).unwrap();

    static ref CONTRACT_PATH: PathBuf = PathBuf::from("starknet_programs/fibonacci.json");

    static ref CONTRACT_CLASS_HASH: [u8; 32] = [1; 32];

    static ref CONTRACT_ADDRESS: Address = Address(1.into());

    static ref FIB_SELECTOR: Felt252 = felt_str!("485685360977693822178494178685050472186234432883326654755380582597179924681");

    static ref EXPECTED_RES: Felt252 = felt_str!("222450955505511890955301767713383614666194461405743219770606958667979327682");
}

fn main() {
    const RUNS: usize = 1000;
    let cached_state = create_initial_state();

    let mut starknet_state = StarknetState::new_with_states(Default::default(), cached_state);

    starknet_state
        .state
        .cache_mut()
        .nonce_initial_values_mut()
        .insert(CONTRACT_ADDRESS.clone(), Felt252::zero());

    for i in 0..RUNS {
        let tx_exec_info = starknet_state
            .invoke_raw(
                CONTRACT_ADDRESS.clone(),
                FIB_SELECTOR.clone(),
                [1.into(), 1.into(), 1000.into()].into(),
                0,
                Some(Vec::new()),
                Some(Felt252::from(i)),
                None,
                0,
            )
            .unwrap();

        assert_eq!(
            tx_exec_info.call_info.unwrap().retdata,
            vec![EXPECTED_RES.clone()]
        )
    }
}

fn create_initial_state() -> CachedState<InMemoryStateReader, PermanentContractClassCache> {
    let cached_state = CachedState::new(
        {
            let mut state_reader = InMemoryStateReader::default();
            state_reader
                .address_to_class_hash_mut()
                .insert(CONTRACT_ADDRESS.clone(), *CONTRACT_CLASS_HASH);

            state_reader
                .address_to_nonce_mut()
                .insert(CONTRACT_ADDRESS.clone(), Felt252::zero());
            state_reader.class_hash_to_compiled_class_mut().insert(
                *CONTRACT_CLASS_HASH,
                CompiledClass::Deprecated(Arc::new(CONTRACT_CLASS.clone())),
            );

            state_reader
                .address_to_storage_mut()
                .insert((CONTRACT_ADDRESS.clone(), [0; 32]), Felt252::zero());
            Arc::new(state_reader)
        },
        Arc::new(RwLock::new(PermanentContractClassCache::default())),
    );

    cached_state
}
