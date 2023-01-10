use std::collections::HashMap;

use felt::Felt;

use crate::services::api::contract_class::ContractClass;

use super::{state_api::SyncState, state_api_objects::BlockInfo, state_cache::StorageEntry};

// An implementation of the SyncState API that wraps another SyncState object and contains a cache.
// All requests are delegated to the wrapped SyncState, and caches are maintained for storage reads
// and writes.

// The goal of this implementation is to allow more precise and fair computation of the number of
// storage-writes a single transaction preforms for the purposes of transaction fee calculation.
// That is, if a given transaction writes to the same storage address multiple times, this should
// be counted as a single storage-write. Additionally, if a transaction writes a value to storage
// which is equal to the initial value previously contained in that address, then no change needs
// to be done and this should not count as a storage-write.
pub(crate) struct UpdatesTrackerState<T: SyncState> {
    pub(crate) state: T,
    pub(crate) storage_initial_values: HashMap<StorageEntry, u64>,
    pub(crate) storage_writes: HashMap<StorageEntry, u64>,
}

impl<T: SyncState> UpdatesTrackerState<T> {
    pub fn new(state: T) -> Self {
        UpdatesTrackerState {
            state,
            storage_initial_values: HashMap::new(),
            storage_writes: HashMap::new(),
        }
    }

    pub fn get_storage_at(&self, contract_address: u64, key: usize) {
        todo!()
    }

    pub fn block_info(&self) -> &BlockInfo {
        self.state.block_info()
    }

    pub fn update_block_info(&self, mut block_info: BlockInfo) {
        self.state.update_block_info(block_info)
    }

    pub fn get_contract_class(&self, class_hash: Felt) -> ContractClass {
        self.state.get_contract_class(class_hash)
    }

    pub fn get_nonce_at(&self, contract_address: u64) -> Felt {
        self.state.get_nonce_at(contract_address)
    }

    pub fn set_contract_class(&self, class_hash: &Felt, contract_class: ContractClass) {
        self.state.set_contract_class(class_hash, contract_class)
    }

    pub fn deploy_contract(&self, contract_address: u64, class_hash: &Felt) {
        self.state.deploy_contract(contract_address, class_hash)
    }

    pub fn increment_nonce(&self, contract_address: u64) {
        self.state.increment_nonce(contract_address)
    }

    pub fn count_actual_storage_changes(&self) -> (usize, usize) {
        todo!()
    }

    fn was_accessed(&self, address_key_pair: StorageEntry) -> bool {
        self.storage_initial_values.contains_key(&address_key_pair)
            || self.storage_writes.contains_key(&address_key_pair)
    }
}
