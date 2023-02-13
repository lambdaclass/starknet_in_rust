use super::state_api::{State, StateReader};
use crate::{core::errors::state_errors::StateError, utils::Address};
use felt::Felt;
use std::collections::HashSet;

pub(crate) struct ContractStorageState<T: State + StateReader> {
    pub(crate) state: T,
    pub(crate) contract_address: Address,
    /// Maintain all read request values in chronological order
    pub(crate) read_values: Vec<Felt>,
    pub(crate) accessed_keys: HashSet<[u8; 32]>,
}

impl<T: State + StateReader> ContractStorageState<T> {
    pub(crate) fn new(state: T, contract_address: Address) -> Self {
        Self {
            state,
            contract_address,
            read_values: Vec::new(),
            accessed_keys: HashSet::new(),
        }
    }

    pub(crate) fn read(&mut self, address: &[u8; 32]) -> Result<&Felt, StateError> {
        self.accessed_keys.insert(*address);
        let value = self
            .state
            .get_storage_at(&(self.contract_address.clone(), *address))?;

        self.read_values.push(value.clone());
        Ok(value)
    }

    pub(crate) fn write(&mut self, address: &[u8; 32], value: Felt) {
        self.accessed_keys.insert(*address);
        self.state
            .set_storage_at(&(self.contract_address.clone(), *address), value);
    }
}
