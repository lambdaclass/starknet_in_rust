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
    pub(crate) fn new() -> Self {
        Self {
            class_hash_initial_values: HashMap::new(),
            nonce_initial_values: HashMap::new(),
            storage_initial_values: HashMap::new(),
            class_hash_writes: HashMap::new(),
            nonce_writes: HashMap::new(),
            storage_writes: HashMap::new(),
        }
    }
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
        address_to_class_hash: &HashMap<BigInt, Vec<u8>>,
        address_to_nonce: &HashMap<BigInt, BigInt>,
        storage_updates: &HashMap<StorageEntry, BigInt>,
    ) {
        self.class_hash_writes.extend(address_to_class_hash.clone());
        self.nonce_writes.extend(address_to_nonce.clone());
        self.storage_writes.extend(storage_updates.clone());
    }

    pub(crate) fn set_initial_values(
        &mut self,
        address_to_class_hash: &HashMap<BigInt, Vec<u8>>,
        address_to_nonce: &HashMap<BigInt, BigInt>,
        storage_updates: &HashMap<StorageEntry, BigInt>,
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

    pub(crate) fn get_contract_classes(&self) -> Result<&ContractClassCache, StateError> {
        self.contract_classes
            .as_ref()
            .ok_or(StateError::MissingContractClassCache)
    }

    pub(crate) fn insert_contract_class(
        &mut self,
        key: Vec<u8>,
        value: ContractClass,
    ) -> Result<(), StateError> {
        self.contract_classes
            .as_mut()
            .ok_or(StateError::MissingContractClassCache)?
            .insert(key, value);

        Ok(())
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

    pub(crate) fn update_block_info(&mut self, block_info: BlockInfo) {
        self.block_info = block_info;
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

impl<T: StateReader> StateReader for CachedState<T> {
    fn get_contract_class(&mut self, class_hash: &[u8]) -> Result<ContractClass, StateError> {
        if !(self.get_contract_classes()?.contains_key(class_hash)) {
            let contract_class = &self.state_reader.get_contract_class(class_hash)?;
            self.insert_contract_class(class_hash.to_vec(), contract_class.to_owned());
        }
        self.get_contract_class(class_hash)
    }

    fn get_class_hash_at(&mut self, contract_address: &BigInt) -> Result<Vec<u8>, StateError> {
        if !(self
            .cache
            .get_address_to_class_hash()
            .contains_key(contract_address))
        {
            let class_hash = self.state_reader.get_class_hash_at(contract_address)?;
            self.cache
                .class_hash_initial_values
                .insert(contract_address.clone(), class_hash);
        }

        // Safe unwrap
        Ok(self
            .cache
            .get_address_to_class_hash()
            .get(contract_address)
            .unwrap()
            .to_vec())
    }

    fn get_nonce_at(&mut self, contract_address: &BigInt) -> Result<BigInt, StateError> {
        if !(self
            .cache
            .get_address_to_nonce()
            .contains_key(contract_address))
        {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache
                .nonce_initial_values
                .insert(contract_address.clone(), nonce);
        }
        // Safe unwrap
        Ok(self
            .cache
            .get_address_to_nonce()
            .get(contract_address)
            .unwrap()
            .to_owned())
    }

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<BigInt, StateError> {
        if !(self.cache.get_storage_view().contains_key(storage_entry)) {
            let value = self.state_reader.get_storage_at(storage_entry)?;
            self.cache
                .storage_initial_values
                .insert(storage_entry.clone(), value);
        }

        // Safe unwrap
        Ok(self
            .cache
            .get_storage_view()
            .get(storage_entry)
            .unwrap()
            .clone())
    }
}
#[cfg(test)]
mod tests {
    use crate::{bigint, state};

    use super::*;

    #[test]
    fn state_chache_set_initial_values() {
        let mut state_cache = StateCache::new();
        let address_to_class_hash = HashMap::from([(bigint!(10), b"pedersen".to_vec())]);
        let address_to_nonce = HashMap::from([(bigint!(9), bigint!(12))]);
        let storage_updates = HashMap::from([((bigint!(20), [1; 32]), bigint!(18))]);
        assert!(state_cache
            .set_initial_values(&address_to_class_hash, &address_to_nonce, &storage_updates)
            .is_ok());

        assert_eq!(state_cache.class_hash_writes, address_to_class_hash);
        assert_eq!(state_cache.nonce_writes, address_to_nonce);
        assert_eq!(state_cache.storage_writes, storage_updates);

        assert_eq!(
            state_cache.get_accessed_contract_addresses(),
            HashSet::from([bigint!(10), bigint!(9), bigint!(20)])
        );
    }

    #[test]
    fn state_chache_update_writes_from_other() {
        let mut state_cache = StateCache::new();
        let address_to_class_hash = HashMap::from([(bigint!(10), b"pedersen".to_vec())]);
        let address_to_nonce = HashMap::from([(bigint!(9), bigint!(12))]);
        let storage_updates = HashMap::from([((bigint!(20), [1; 32]), bigint!(18))]);
        state_cache
            .set_initial_values(&address_to_class_hash, &address_to_nonce, &storage_updates)
            .expect("Error setting StateCache values");

        let mut other_state_cache = StateCache::new();
        let other_address_to_class_hash = HashMap::from([(bigint!(10), b"sha-3".to_vec())]);
        let other_address_to_nonce = HashMap::from([(bigint!(401), bigint!(100))]);
        let other_storage_updates = HashMap::from([((bigint!(4002), [2; 32]), bigint!(101))]);
        other_state_cache
            .set_initial_values(
                &other_address_to_class_hash,
                &other_address_to_nonce,
                &other_storage_updates,
            )
            .expect("Error setting StateCache values");

        state_cache.update_writes_from_other(&other_state_cache);

        assert_eq!(
            state_cache.get_address_to_class_hash(),
            other_address_to_class_hash
        );
        assert_eq!(
            state_cache.get_address_to_nonce(),
            HashMap::from([(bigint!(9), bigint!(12)), (bigint!(401), bigint!(100))])
        );
        assert_eq!(
            state_cache.get_storage_view(),
            HashMap::from([
                ((bigint!(20), [1; 32]), bigint!(18)),
                ((bigint!(4002), [2; 32]), bigint!(101))
            ])
        );
    }
}
