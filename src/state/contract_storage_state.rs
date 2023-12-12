use super::{
    cached_state::CachedState,
    contract_class_cache::ContractClassCache,
    state_api::{State, StateReader},
};
use crate::{
    core::errors::state_errors::StateError,
    utils::{Address, ClassHash},
};
use cairo_vm::felt::Felt252;
use std::collections::HashSet;

#[derive(Debug)]
pub(crate) struct ContractStorageState<'a, S: StateReader, C: ContractClassCache> {
    pub(crate) state: &'a mut CachedState<S, C>,
    pub(crate) contract_address: Address,
    /// Maintain all read request values in chronological order
    pub(crate) read_values: Vec<Felt252>,
    pub(crate) accessed_keys: HashSet<ClassHash>,
}

impl<'a, S: StateReader, C: ContractClassCache> ContractStorageState<'a, S, C> {
    pub(crate) fn new(state: &'a mut CachedState<S, C>, contract_address: Address) -> Self {
        Self {
            state,
            contract_address,
            read_values: Vec::new(),
            accessed_keys: HashSet::new(),
        }
    }

    /// Read a value from contract storage given an address.
    pub(crate) fn read(&mut self, address: Address) -> Result<Felt252, StateError> {
        self.accessed_keys
            .insert(ClassHash::from(address.0.clone()));
        let value = self
            .state
            .get_storage_at(&(self.contract_address.clone(), (address).0.to_be_bytes()))?;

        self.read_values.push(value.clone());
        Ok(value)
    }

    /// Write a value to contract storage at a given address.
    pub(crate) fn write(&mut self, address: Address, value: Felt252) {
        self.accessed_keys
            .insert(ClassHash::from(address.0.clone()));
        self.state.set_storage_at(
            &(self.contract_address.clone(), (address).0.to_be_bytes()),
            value,
        );
    }
}
