#![deny(warnings)]

use cairo_vm::felt::Felt252;
use lru::LruCache;
use starknet_in_rust::{
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::contract_class_cache::ContractClassCache,
    testing::state::StarknetState,
    utils::{calculate_sn_keccak, Address, ClassHash},
};
use std::{
    num::NonZeroUsize,
    path::Path,
    sync::{Arc, Mutex},
};

fn main() {
    let shared_cache = Arc::new(LruContractCache::new(NonZeroUsize::new(64).unwrap()));

    let ret_data = run_contract(
        "starknet_programs/factorial.json",
        "factorial",
        [10.into()],
        shared_cache,
    );

    println!("{ret_data:?}");
}

fn run_contract(
    contract_path: impl AsRef<Path>,
    entry_point: impl AsRef<str>,
    calldata: impl Into<Vec<Felt252>>,
    contract_cache: Arc<LruContractCache>,
) -> Vec<Felt252> {
    let mut state = StarknetState::new(None, contract_cache.clone());

    let contract_class = ContractClass::from_path(contract_path.as_ref()).unwrap();
    state.declare(contract_class.clone()).unwrap();

    let (contract_address, _) = state
        .deploy(contract_class, vec![], Felt252::default(), None, 0)
        .unwrap();

    let entry_point_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_ref().as_bytes()));
    let caller_address = Address::default();

    let call_info = state
        .execute_entry_point_raw(
            contract_address,
            entry_point_selector,
            calldata.into(),
            caller_address,
        )
        .unwrap();

    // Store the local cache changes into the shared cache. This updates the shared cache with all
    // the contracts used on this state.
    contract_cache.extend(state.state.drain_private_contract_class_cache());

    call_info.retdata
}

pub struct LruContractCache {
    storage: Mutex<LruCache<ClassHash, CompiledClass>>,
}

impl LruContractCache {
    pub fn new(cap: NonZeroUsize) -> Self {
        Self {
            storage: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn extend<I>(&self, other: I)
    where
        I: IntoIterator<Item = (ClassHash, CompiledClass)>,
    {
        other.into_iter().for_each(|(k, v)| {
            self.storage.lock().unwrap().put(k, v);
        });
    }
}

impl ContractClassCache for LruContractCache {
    fn get_contract_class(&self, class_hash: ClassHash) -> Option<CompiledClass> {
        self.storage.lock().unwrap().get(&class_hash).cloned()
    }

    fn set_contract_class(&self, class_hash: ClassHash, compiled_class: CompiledClass) {
        self.storage.lock().unwrap().put(class_hash, compiled_class);
    }
}
