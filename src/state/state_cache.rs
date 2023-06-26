use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::compiled_class::CompiledClass,
    utils::{Address, ClassHash, CompiledClassHash},
};
use cairo_vm::felt::Felt252;
use getset::{Getters, MutGetters};
use std::collections::{HashMap, HashSet};

/// (contract_address, key)
// TODO: Change [u8; 32] to Felt252.
pub type StorageEntry = (Address, [u8; 32]);

#[derive(Default, Clone, Debug, Eq, Getters, MutGetters, PartialEq)]
pub struct StateCache {
    // Reader's cached information; initial values, read before any write operation (per cell)
    #[get_mut = "pub"]
    pub(crate) class_hash_initial_values: HashMap<Address, ClassHash>,
    #[get_mut = "pub"]
    pub(crate) compiled_class_hash_initial_values: HashMap<ClassHash, CompiledClass>,
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) nonce_initial_values: HashMap<Address, Felt252>,
    #[get_mut = "pub"]
    pub(crate) storage_initial_values: HashMap<StorageEntry, Felt252>,

    // Writer's cached information.
    #[get_mut = "pub"]
    pub(crate) class_hash_writes: HashMap<Address, ClassHash>,
    #[get_mut = "pub"]
    pub(crate) compiled_class_hash_writes: HashMap<ClassHash, CompiledClass>,
    #[get_mut = "pub"]
    pub(crate) nonce_writes: HashMap<Address, Felt252>,
    #[getset(get = "pub", get_mut = "pub")]
    pub(crate) storage_writes: HashMap<StorageEntry, Felt252>,
    #[get_mut = "pub"]
    pub(crate) class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
}

impl StateCache {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_hash_initial_values: HashMap<Address, ClassHash>,
        compiled_class_hash_initial_values: HashMap<ClassHash, CompiledClass>,
        nonce_initial_values: HashMap<Address, Felt252>,
        storage_initial_values: HashMap<StorageEntry, Felt252>,
        class_hash_writes: HashMap<Address, ClassHash>,
        compiled_class_hash_writes: HashMap<ClassHash, CompiledClass>,
        nonce_writes: HashMap<Address, Felt252>,
        storage_writes: HashMap<StorageEntry, Felt252>,
        class_hash_to_compiled_class_hash: HashMap<ClassHash, ClassHash>,
    ) -> Self {
        Self {
            class_hash_initial_values,
            compiled_class_hash_initial_values,
            nonce_initial_values,
            storage_initial_values,
            class_hash_writes,
            compiled_class_hash_writes,
            nonce_writes,
            storage_writes,
            class_hash_to_compiled_class_hash,
        }
    }

    pub(crate) fn default() -> Self {
        Self {
            class_hash_initial_values: HashMap::new(),
            compiled_class_hash_initial_values: HashMap::new(),
            nonce_initial_values: HashMap::new(),
            storage_initial_values: HashMap::new(),
            class_hash_writes: HashMap::new(),
            compiled_class_hash_writes: HashMap::new(),
            nonce_writes: HashMap::new(),
            storage_writes: HashMap::new(),
            class_hash_to_compiled_class_hash: HashMap::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_for_testing(
        class_hash_initial_values: HashMap<Address, [u8; 32]>,
        compiled_class_hash_initial_values: HashMap<ClassHash, CompiledClass>,
        nonce_initial_values: HashMap<Address, Felt252>,
        storage_initial_values: HashMap<StorageEntry, Felt252>,
        class_hash_writes: HashMap<Address, [u8; 32]>,
        compiled_class_hash_writes: HashMap<ClassHash, CompiledClass>,
        nonce_writes: HashMap<Address, Felt252>,
        storage_writes: HashMap<(Address, [u8; 32]), Felt252>,
        class_hash_to_compiled_class_hash: HashMap<ClassHash, ClassHash>,
    ) -> Self {
        Self {
            class_hash_initial_values,
            compiled_class_hash_initial_values,
            nonce_initial_values,
            storage_initial_values,
            class_hash_writes,
            compiled_class_hash_writes,
            nonce_writes,
            storage_writes,
            class_hash_to_compiled_class_hash,
        }
    }

    pub(crate) fn get_class_hash(&self, contract_address: &Address) -> Option<&ClassHash> {
        if self.class_hash_writes.contains_key(contract_address) {
            return self.class_hash_writes.get(contract_address);
        }
        self.class_hash_initial_values.get(contract_address)
    }

    #[allow(dead_code)]
    pub(crate) fn get_compiled_class_hash(&self, class_hash: &ClassHash) -> Option<&CompiledClass> {
        if self.compiled_class_hash_writes.contains_key(class_hash) {
            return self.compiled_class_hash_writes.get(class_hash);
        }
        self.compiled_class_hash_initial_values.get(class_hash)
    }

    pub(crate) fn get_nonce(&self, contract_address: &Address) -> Option<&Felt252> {
        if self.nonce_writes.contains_key(contract_address) {
            return self.nonce_writes.get(contract_address);
        }
        self.nonce_initial_values.get(contract_address)
    }

    pub(crate) fn get_storage(&self, storage_entry: &StorageEntry) -> Option<&Felt252> {
        if self.storage_writes.contains_key(storage_entry) {
            return self.storage_writes.get(storage_entry);
        }
        self.storage_initial_values.get(storage_entry)
    }

    pub(crate) fn update_writes(
        &mut self,
        address_to_class_hash: &HashMap<Address, ClassHash>,
        class_hash_to_compiled_class_hash: &HashMap<ClassHash, CompiledClass>,
        address_to_nonce: &HashMap<Address, Felt252>,
        storage_updates: &HashMap<StorageEntry, Felt252>,
    ) {
        self.class_hash_writes.extend(address_to_class_hash.clone());
        self.compiled_class_hash_writes
            .extend(class_hash_to_compiled_class_hash.clone());
        self.nonce_writes.extend(address_to_nonce.clone());
        self.storage_writes.extend(storage_updates.clone());
    }

    pub fn set_initial_values(
        &mut self,
        address_to_class_hash: &HashMap<Address, ClassHash>,
        class_hash_to_compiled_class: &HashMap<ClassHash, CompiledClass>,
        address_to_nonce: &HashMap<Address, Felt252>,
        storage_updates: &HashMap<StorageEntry, Felt252>,
    ) -> Result<(), StateError> {
        if !(self.class_hash_initial_values.is_empty()
            && self.class_hash_writes.is_empty()
            && self.nonce_initial_values.is_empty()
            && self.nonce_writes.is_empty()
            && self.storage_initial_values.is_empty()
            && self.storage_writes.is_empty())
        {
            return Err(StateError::StateCacheAlreadyInitialized);
        }
        self.update_writes(
            address_to_class_hash,
            class_hash_to_compiled_class,
            address_to_nonce,
            storage_updates,
        );
        Ok(())
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn get_accessed_contract_addresses(&self) -> HashSet<Address> {
        let mut set: HashSet<Address> = HashSet::with_capacity(self.class_hash_writes.len());
        set.extend(self.class_hash_writes.keys().cloned());
        set.extend(self.nonce_writes.keys().cloned());
        set.extend(self.storage_writes.keys().map(|x| x.0.clone()));
        set
    }
}

#[cfg(test)]
mod tests {

    use cairo_vm::types::program::Program;

    use crate::services::api::contract_classes::deprecated_contract_class::ContractClass;

    use super::*;

    #[test]
    fn state_chache_set_initial_values() {
        let mut state_cache = StateCache::default();
        let address_to_class_hash = HashMap::from([(Address(10.into()), [8; 32])]);
        let program_json: serde_json::Value = serde_json::Value::from("{}");
        let compiled_class = CompiledClass::Deprecated(Box::new(
            ContractClass::new(program_json, Program::default(), HashMap::new(), None).unwrap(),
        ));
        let class_hash_to_compiled_class_hash = HashMap::from([([8; 32], compiled_class)]);
        let address_to_nonce = HashMap::from([(Address(9.into()), 12.into())]);
        let storage_updates = HashMap::from([((Address(4.into()), [1; 32]), 18.into())]);

        assert!(state_cache
            .set_initial_values(
                &address_to_class_hash,
                &class_hash_to_compiled_class_hash,
                &address_to_nonce,
                &storage_updates
            )
            .is_ok());

        assert_eq!(state_cache.class_hash_writes, address_to_class_hash);
        assert_eq!(
            state_cache.compiled_class_hash_writes,
            class_hash_to_compiled_class_hash
        );
        assert_eq!(state_cache.nonce_writes, address_to_nonce);
        assert_eq!(state_cache.storage_writes, storage_updates);

        assert_eq!(
            state_cache.get_accessed_contract_addresses(),
            HashSet::from([Address(10.into()), Address(9.into()), Address(4.into())])
        );
    }
}
