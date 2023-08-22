use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::{
        cached_state::{CasmClassCache, UNINITIALIZED_CLASS_HASH},
        state_api::StateReader,
        state_cache::StorageEntry,
    },
    utils::{Address, ClassHash, CompiledClassHash},
};
use cairo_vm::felt::Felt252;
use getset::{Getters, MutGetters};
use num_traits::Zero;
use std::{collections::HashMap, sync::Arc};

/// A [StateReader] that holds all the data in memory.
///
/// This implementation is used for testing and debugging.
/// It uses HashMaps to store the data.
#[derive(Debug, MutGetters, Getters, PartialEq, Clone, Default)]
pub struct InMemoryStateReader {
    #[getset(get_mut = "pub")]
    pub address_to_class_hash: HashMap<Address, ClassHash>,
    #[getset(get_mut = "pub")]
    pub address_to_nonce: HashMap<Address, Felt252>,
    #[getset(get_mut = "pub")]
    pub address_to_storage: HashMap<StorageEntry, Felt252>,
    #[getset(get_mut = "pub")]
    pub class_hash_to_contract_class: HashMap<ClassHash, ContractClass>,
    #[getset(get_mut = "pub")]
    pub(crate) casm_contract_classes: CasmClassCache,
    #[getset(get_mut = "pub")]
    pub(crate) class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
}

impl InMemoryStateReader {
    /// Creates a new InMemoryStateReader.
    ///
    /// # Parameters
    /// - `address_to_class_hash` - A HashMap from contract addresses to their class hashes.
    /// - `address_to_nonce` - A HashMap from contract addresses to their nonces.
    /// - `address_to_storage` - A HashMap from storage entries to their values.
    /// - `class_hash_to_contract_class` - A HashMap from class hashes to their contract classes.
    /// - `casm_contract_classes` - A [CasmClassCache].
    /// - `class_hash_to_compiled_class_hash` - A HashMap from class hashes to their compiled class hashes.
    pub fn new(
        address_to_class_hash: HashMap<Address, ClassHash>,
        address_to_nonce: HashMap<Address, Felt252>,
        address_to_storage: HashMap<StorageEntry, Felt252>,
        class_hash_to_contract_class: HashMap<ClassHash, ContractClass>,
        casm_contract_classes: CasmClassCache,
        class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
    ) -> Self {
        Self {
            address_to_class_hash,
            address_to_nonce,
            address_to_storage,
            class_hash_to_contract_class,
            casm_contract_classes,
            class_hash_to_compiled_class_hash,
        }
    }

    /// Gets the [CompiledClass] with the given [CompiledClassHash].
    ///
    /// It looks for the [CompiledClass] both in the cache and the storage.
    ///
    /// # Parameters
    /// - `compiled_class_hash` - The [CompiledClassHash] of the [CompiledClass] to get.
    ///
    /// # Errors
    /// - [StateError::NoneCompiledClass] - If the [CompiledClass] is not found.
    ///
    /// # Returns
    /// The [CompiledClass] with the given [CompiledClassHash].
    fn get_compiled_class(
        &self,
        compiled_class_hash: &CompiledClassHash,
    ) -> Result<CompiledClass, StateError> {
        if let Some(compiled_class) = self.casm_contract_classes.get(compiled_class_hash) {
            return Ok(CompiledClass::Casm(Arc::new(compiled_class.clone())));
        }
        if let Some(compiled_class) = self.class_hash_to_contract_class.get(compiled_class_hash) {
            return Ok(CompiledClass::Deprecated(Arc::new(compiled_class.clone())));
        }
        Err(StateError::NoneCompiledClass(*compiled_class_hash))
    }
}

impl StateReader for InMemoryStateReader {
    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let class_hash = self
            .address_to_class_hash
            .get(contract_address)
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()));
        class_hash.cloned()
    }

    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
        let default = Felt252::zero();
        let nonce = self
            .address_to_nonce
            .get(contract_address)
            .unwrap_or(&default);
        Ok(nonce.clone())
    }

    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let storage = self
            .address_to_storage
            .get(storage_entry)
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()));
        storage.cloned()
    }

    fn get_compiled_class_hash(
        &self,
        class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError> {
        self.class_hash_to_compiled_class_hash
            .get(class_hash)
            .ok_or(StateError::NoneCompiledHash(*class_hash))
            .copied()
    }

    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        // Deprecated contract classes dont have a compiled_class_hash, we dont need to fetch it
        if let Some(compiled_class) = self.class_hash_to_contract_class.get(class_hash) {
            return Ok(CompiledClass::Deprecated(Arc::new(compiled_class.clone())));
        }
        let compiled_class_hash = self.get_compiled_class_hash(class_hash)?;
        if compiled_class_hash != *UNINITIALIZED_CLASS_HASH {
            let compiled_class = self.get_compiled_class(&compiled_class_hash)?;
            Ok(compiled_class)
        } else {
            Err(StateError::MissingCasmClass(compiled_class_hash))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_contract_state_test() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(37810.into());
        let class_hash = [1; 32];
        let nonce = Felt252::new(109);
        let storage_entry = (contract_address.clone(), [8; 32]);
        let storage_value = Felt252::new(800);

        state_reader
            .address_to_class_hash
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address.clone(), nonce.clone());
        state_reader
            .address_to_storage
            .insert(storage_entry.clone(), storage_value.clone());

        assert_eq!(
            state_reader.get_class_hash_at(&contract_address).unwrap(),
            class_hash
        );
        assert_eq!(state_reader.get_nonce_at(&contract_address).unwrap(), nonce);
        assert_eq!(
            state_reader.get_storage_at(&storage_entry).unwrap(),
            storage_value
        );
    }

    #[test]
    fn get_contract_class_test() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_class_key = [0; 32];
        let contract_class =
            ContractClass::from_path("starknet_programs/raw_contract_classes/class_with_abi.json")
                .unwrap();

        state_reader
            .class_hash_to_contract_class
            .insert([0; 32], contract_class.clone());
        assert_eq!(
            state_reader
                .get_contract_class(&contract_class_key)
                .unwrap()
                .try_into(),
            Ok(contract_class)
        )
    }
}
