use std::collections::HashMap;

use felt::Felt;
use num_traits::ToPrimitive;
use serde_json::value;

use crate::{
    core::errors::state_errors::StateError, services::api::contract_class::ContractClass,
    starknet_storage::storage, utils::Address,
};

use super::{
    state_api::{State, StateReader},
    state_api_objects::BlockInfo,
    state_cache::StorageEntry,
};

// An implementation of the SyncState API that wraps another SyncState object and contains a cache.
// All requests are delegated to the wrapped SyncState, and caches are maintained for storage reads
// and writes.

// The goal of this implementation is to allow more precise and fair computation of the number of
// storage-writes a single transaction preforms for the purposes of transaction fee calculation.
// That is, if a given transaction writes to the same storage address multiple times, this should
// be counted as a single storage-write. Additionally, if a transaction writes a value to storage
// which is equal to the initial value previously contained in that address, then no change needs
// to be done and this should not count as a storage-write.
pub(crate) struct UpdatesTrackerState<T: State> {
    pub(crate) state: T,
    pub(crate) storage_initial_values: HashMap<StorageEntry, u64>,
    pub(crate) storage_writes: HashMap<StorageEntry, u64>,
}

impl<T: State + StateReader> UpdatesTrackerState<T> {
    pub fn new(state: T) -> Self {
        UpdatesTrackerState {
            state,
            storage_initial_values: HashMap::new(),
            storage_writes: HashMap::new(),
        }
    }

    // This method writes to a storage cell and updates the cache accordingly. If this is the first
    // access to the cell (read or write), the method first reads the value at that cell and caches
    // it.
    // This read operation is necessary for fee calculation. Because if the transaction writes a
    // value to storage that is identical to the value previously held at that address, then no
    // change is made to that cell and it does not count as a storage-change in fee calculation.

    pub fn set_storage_at(
        &mut self,
        contract_address: Address,
        key: [u8; 32],
        value: Felt,
    ) -> Result<(), StateError> {
        let address_key_pair = (contract_address, key);
        if !self.was_accessed(&address_key_pair) {
            let val = self.state.get_storage_at(&address_key_pair)?;
            let value = val
                .to_u64()
                .ok_or_else(|| StateError::ConversionError(value.clone()))?;
            self.storage_initial_values
                .insert(address_key_pair.clone(), value);
        }

        let store_value = value
            .to_u64()
            .ok_or_else(|| StateError::ConversionError(value.clone()))?;
        self.storage_writes
            .insert(address_key_pair.clone(), store_value);
        self.state.set_storage_at(&address_key_pair, value);
        Ok(())
    }

    pub fn get_storage_at(
        &mut self,
        contract_address: Address,
        key: [u8; 32],
    ) -> Result<Felt, StateError> {
        let address_key_pair = (contract_address.clone(), key);
        let was_not_accessed = !self.was_accessed(&address_key_pair);

        let return_value = self.state.get_storage_at(&(contract_address, key))?;

        if was_not_accessed {
            let value = return_value
                .to_u64()
                .ok_or_else(|| StateError::ConversionError(return_value.clone()))?;
            self.storage_initial_values.insert(address_key_pair, value);
        }
        Ok(return_value.clone())
    }

    pub fn block_info(&self) -> &BlockInfo {
        self.state.block_info()
    }

    pub fn update_block_info(&mut self, mut block_info: BlockInfo) {
        self.state.update_block_info(block_info)
    }

    pub fn get_contract_class(
        &mut self,
        class_hash: &[u8; 32],
    ) -> Result<ContractClass, StateError> {
        self.state.get_contract_class(class_hash)
    }

    pub fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt, StateError> {
        self.state.get_nonce_at(contract_address)
    }

    pub fn set_contract_class(&mut self, class_hash: &[u8], contract_class: &ContractClass) {
        self.state.set_contract_class(class_hash, contract_class)
    }

    pub fn deploy_contract(
        &mut self,
        contract_address: Address,
        class_hash: Vec<u8>,
    ) -> Result<(), StateError> {
        self.state.deploy_contract(contract_address, class_hash)
    }

    pub fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError> {
        self.state.increment_nonce(contract_address)
    }

    pub fn count_actual_storage_changes(&self) -> (usize, usize) {
        let storage_updates = self
            .storage_writes
            .clone()
            .into_iter()
            .filter(|(k, _v)| !self.storage_initial_values.contains_key(k))
            .collect::<HashMap<StorageEntry, u64>>();

        let modified_contrats = storage_updates.clone().into_iter().map(|(k, _v)| k.0);

        (modified_contrats.len(), storage_updates.len())
    }

    fn was_accessed(&mut self, address_key_pair: &StorageEntry) -> bool {
        self.storage_initial_values.contains_key(address_key_pair)
            || self.storage_writes.contains_key(address_key_pair)
    }
}
