use std::collections::{HashMap, HashSet};

use num_bigint::BigInt;

use crate::core::errors::state_errors::StateError;
use crate::services::api::contract_class::ContractClass;

use super::state_api_objects::BlockInfo;

use super::state_api::StateReader;

/// (contract_address, key)
pub(crate) type StorageEntry = (BigInt, [u8; 32]);

pub(crate) type ContractClassCache = HashMap<Vec<u8>, ContractClass>;

#[derive(Debug, Default, Clone)]
pub(crate) struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell)
    class_hash_initial_values: HashMap<BigInt, Vec<u8>>,
    nonce_initial_values: HashMap<BigInt, BigInt>,
    storage_initial_values: HashMap<StorageEntry, BigInt>,

    // Writer's cached information.
    class_hash_writes: HashMap<BigInt, Vec<u8>>,
    nonce_writes: HashMap<BigInt, BigInt>,
    storage_writes: HashMap<StorageEntry, BigInt>,
}

impl StateCache {
    pub(crate) fn get_address_to_class_hash(&self) -> HashMap<BigInt, Vec<u8>> {
        let mut address_to_class_hash = self.class_hash_initial_values.clone();
        address_to_class_hash.extend(self.class_hash_writes.clone());
        address_to_class_hash
    }

    pub(crate) fn get_address_to_nonce(&self) -> HashMap<BigInt, BigInt> {
        let mut address_to_nonce = self.nonce_initial_values.clone();
        address_to_nonce.extend(self.nonce_writes.clone());
        address_to_nonce
    }

    pub(crate) fn get_storage_view(&self) -> HashMap<StorageEntry, BigInt> {
        let mut storage_view = self.storage_initial_values.clone();
        storage_view.extend(self.storage_writes.clone());
        storage_view
    }

    pub(crate) fn update_writes_from_other(&mut self, other: &Self) {
        self.class_hash_writes
            .extend(other.class_hash_writes.clone());
        self.nonce_writes.extend(other.nonce_writes.clone());
        self.storage_writes.extend(other.storage_writes.clone());
    }

    pub(crate) fn update_writes(
        &mut self,
        address_to_class_hash: HashMap<BigInt, Vec<u8>>,
        address_to_nonce: HashMap<BigInt, BigInt>,
        storage_updates: HashMap<StorageEntry, BigInt>,
    ) {
        self.class_hash_writes.extend(address_to_class_hash);
        self.nonce_writes.extend(address_to_nonce);
        self.storage_writes.extend(storage_updates);
    }

    pub(crate) fn set_initial_values(
        &mut self,
        address_to_class_hash: HashMap<BigInt, Vec<u8>>,
        address_to_nonce: HashMap<BigInt, BigInt>,
        storage_updates: HashMap<StorageEntry, BigInt>,
    ) -> Result<(), StateError> {
        if !(self.get_address_to_class_hash().is_empty()
            && self.get_address_to_nonce().is_empty()
            && self.get_storage_view().is_empty())
        {
            return Err(StateError::StateCacheAlreadyInitialized);
        }
        self.update_writes(address_to_class_hash, address_to_nonce, storage_updates);
        Ok(())
    }

    pub(crate) fn get_accessed_contract_addresses(&self) -> HashSet<BigInt> {
        let mut set: HashSet<BigInt> = HashSet::with_capacity(self.class_hash_writes.len());
        set.extend(self.class_hash_writes.keys().cloned());
        set.extend(self.nonce_writes.keys().cloned());
        set.extend(self.storage_writes.keys().map(|x| x.0.clone()));
        set
    }
}

pub(crate) struct CachedState<T: StateReader> {
    block_info: BlockInfo,
    pub(crate) state_reader: T,
    pub(crate) cache: StateCache,
    contract_classes: Option<ContractClassCache>,
}

impl<T: StateReader> CachedState<T> {
    pub(crate) fn new(
        block_info: BlockInfo,
        state_reader: T,
        contract_class_cache: Option<ContractClassCache>,
    ) -> Self {
        Self {
            block_info,
            cache: StateCache::default(),
            contract_classes: contract_class_cache,
            state_reader,
        }
    }

    pub(crate) fn block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    pub(crate) fn contract_classes(&self) -> Result<&ContractClassCache, StateError> {
        self.contract_classes
            .as_ref()
            .ok_or(StateError::MissingContractClassCache)
    }

    pub(crate) fn update_block_info(&mut self, block_info: BlockInfo) {
        self.block_info = block_info;
    }

    pub(crate) fn set_contract_class_cache(
        &mut self,
        contract_classes: ContractClassCache,
    ) -> Result<(), StateError> {
        if self.contract_classes.is_some() {
            return Err(StateError::AssignedContractClassCache);
        }
        self.contract_classes = Some(contract_classes);
        Ok(())
    }

    pub(crate) fn get_contract_class(&self, class_hash: &[u8]) -> ContractClass {
        todo!()
    }

    pub(crate) fn get_class_hash_at(&self, contract_address: &BigInt) -> Vec<u8> {
        todo!()
    }

    pub(crate) fn get_nonce_at(&self, contract_address: &BigInt) -> BigInt {
        todo!()
    }

    pub(crate) fn get_storage_at(&self, contract_address: &BigInt, key: &[u8; 32]) -> BigInt {
        todo!()
    }

    pub(crate) fn set_contract_class(&mut self, class_hash: &[u8], contract_class: ContractClass) {
        if let Some(contract_classes) = &mut self.contract_classes {
            contract_classes.insert(Vec::from(class_hash), contract_class);
        }
    }

    pub(crate) fn deploy_contract(&self, contract_address: &BigInt, class_hash: &[u8]) {
        todo!()
    }

    pub(crate) fn set_storage_at(
        &self,
        contract_address: &BigInt,
        key: &[u8; 32],
        value: BigInt,
    ) -> BigInt {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint;

    use super::*;

    #[test]
    fn test_statecache() {
        let mut cache = StateCache::default();
        cache.set_initial_values(
            HashMap::from([(bigint!(1), Vec::new())]),
            HashMap::from([(bigint!(2), bigint!(2))]),
            HashMap::from([((bigint!(3), [0; 32]), bigint!(2))]),
        );

        assert!(cache.class_hash_writes.get(&bigint!(1)).is_some());
        assert!(cache.nonce_writes.get(&bigint!(2)).is_some());
        assert!(cache.storage_writes.get(&(bigint!(3), [0; 32])).is_some());

        let set = cache.get_accessed_contract_addresses();

        assert!(set.contains(&bigint!(1)));
        assert!(set.contains(&bigint!(2)));
        assert!(set.contains(&bigint!(3)));
    }
}
