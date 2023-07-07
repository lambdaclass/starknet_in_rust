use cairo_vm::felt::Felt252;

use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    utils::{Address, ClassHash, CompiledClassHash},
};

use super::{
    cached_state::CachedState,
    state_api::{State, StateReader},
    state_cache::StorageEntry,
};

/// Wraps a mutable reference to a `State` object, exposing its API.
/// Used to pass ownership to a `CachedState`.
#[derive(Debug)]
pub struct MutRefState<'a, S: State + StateReader + ?Sized>(&'a mut S);

impl<'a, S: State + StateReader + ?Sized> MutRefState<'a, S> {
    pub fn new(state: &'a mut S) -> Self {
        Self(state)
    }
}

/// Proxies inner object to expose `State` functionality.
impl<'a, S: State + StateReader + ?Sized> StateReader for MutRefState<'a, S> {
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        self.0.get_storage_at(storage_entry)
    }

    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<Felt252, StateError> {
        self.0.get_nonce_at(contract_address)
    }

    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<ClassHash, StateError> {
        self.0.get_class_hash_at(contract_address)
    }

    /// Return the class hash of the given casm contract class
    fn get_compiled_class_hash(
        &mut self,
        class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError> {
        self.0.get_compiled_class_hash(class_hash)
    }

    /// Returns the contract class of the given class hash or compiled class hash.
    fn get_contract_class(&mut self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        self.0.get_contract_class(class_hash)
    }
}

impl<'a, S: State + StateReader + ?Sized> State for MutRefState<'a, S> {
    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt252) {
        self.0.set_storage_at(storage_entry, value)
    }

    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError> {
        self.0.increment_nonce(contract_address)
    }

    fn set_class_hash_at(
        &mut self,
        contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError> {
        self.0.set_class_hash_at(contract_address, class_hash)
    }

    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: &ContractClass,
    ) -> Result<(), StateError> {
        self.0.set_contract_class(class_hash, contract_class)
    }

    fn set_compiled_class_hash(
        &mut self,
        class_hash: &Felt252,
        compiled_class_hash: &Felt252,
    ) -> Result<(), StateError> {
        self.0
            .set_compiled_class_hash(class_hash, compiled_class_hash)
    }

    fn deploy_contract(
        &mut self,
        contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError> {
        self.0.deploy_contract(contract_address, class_hash)
    }

    fn set_compiled_class(
        &mut self,
        compiled_class_hash: &Felt252,
        casm_class: cairo_lang_starknet::casm_contract_class::CasmContractClass,
    ) -> Result<(), StateError> {
        self.0.set_compiled_class(compiled_class_hash, casm_class)
    }

    fn apply_state_update(&mut self, sate_updates: &super::StateDiff) -> Result<(), StateError> {
        self.0.apply_state_update(sate_updates)
    }

    fn count_actual_storage_changes(&mut self) -> (usize, usize) {
        self.0.count_actual_storage_changes()
    }
}

pub type TransactionalState<'a, S> = CachedState<MutRefState<'a, CachedState<S>>>;

/// Adds the ability to perform a transactional execution.
impl<'a, S: StateReader> TransactionalState<'a, S> {
    /// Commits changes in the child (wrapping) state to its parent.
    pub fn commit(self) {
        let child_cache = self.cache;
        let parent_cache = &mut self.state_reader.0.cache;

        parent_cache.nonce_writes.extend(child_cache.nonce_writes);
        parent_cache
            .class_hash_writes
            .extend(child_cache.class_hash_writes);
        parent_cache
            .storage_writes
            .extend(child_cache.storage_writes);
        parent_cache
            .compiled_class_hash_writes
            .extend(child_cache.compiled_class_hash_writes);
        self.state_reader
            .0
            .contract_classes
            .as_mut()
            .unwrap()
            .extend(self.contract_classes.unwrap());
    }

    /// Drops `self`.
    pub fn abort(self) {}
}
