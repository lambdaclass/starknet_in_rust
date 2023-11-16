// #![deny(warnings)]

use cairo_vm::felt::Felt252;
use lru::LruCache;
use starknet_in_rust::{
    definitions::{block_context::BlockContext, constants::TRANSACTION_VERSION},
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::CachedState,
        contract_class_cache::{ContractClassCache, PermanentContractClassCache},
        in_memory_state_reader::InMemoryStateReader,
    },
    transaction::{Declare, Deploy, InvokeFunction},
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
    let block_context = BlockContext::default();
    let chain_id = block_context.starknet_os_config().chain_id().clone();
    let sender_address = Address(1.into());
    let signature = vec![];

    let state_reader = Arc::new(InMemoryStateReader::default());
    let mut state = CachedState::new(
        state_reader,
        Arc::new(PermanentContractClassCache::default()),
    );

    let contract_class = ContractClass::from_path(contract_path.as_ref()).unwrap();

    let declare_tx = Declare::new(
        contract_class.clone(),
        chain_id.clone(),
        sender_address,
        0,
        0.into(),
        signature.clone(),
        0.into(),
    )
    .unwrap();

    declare_tx
        .execute(
            &mut state,
            &block_context,
            #[cfg(feature = "cairo-native")]
            None,
        )
        .unwrap();

    let deploy_tx = Deploy::new(
        Default::default(),
        contract_class,
        Vec::new(),
        block_context.starknet_os_config().chain_id().clone(),
        TRANSACTION_VERSION.clone(),
    )
    .unwrap();

    deploy_tx
        .execute(
            &mut state,
            &block_context,
            #[cfg(feature = "cairo-native")]
            None,
        )
        .unwrap();

    let entry_point_selector =
        Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_ref().as_bytes()));

    let invoke_tx = InvokeFunction::new(
        deploy_tx.contract_address.clone(),
        entry_point_selector,
        0,
        TRANSACTION_VERSION.clone(),
        calldata.into(),
        signature,
        chain_id,
        Some(0.into()),
    )
    .unwrap();

    let invoke_tx_execution_info = invoke_tx
        .execute(
            &mut state,
            &block_context,
            0,
            #[cfg(feature = "cairo-native")]
            None,
        )
        .unwrap();

    // Store the local cache changes into the shared cache. This updates the shared cache with all
    // the contracts used on this state.
    contract_cache.extend(state.drain_private_contract_class_cache().unwrap());

    invoke_tx_execution_info.call_info.unwrap().retdata
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
