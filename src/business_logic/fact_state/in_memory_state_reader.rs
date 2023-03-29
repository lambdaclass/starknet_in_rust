use crate::{
    business_logic::state::{state_api::StateReader, state_cache::StorageEntry},
    core::errors::state_errors::StateError,
    services::api::contract_class::ContractClass,
    utils::{Address, ClassHash},
};
use felt::Felt252;
use getset::{Getters, MutGetters};
use std::collections::HashMap;

#[derive(Clone, Debug, Default, MutGetters, Getters, PartialEq)]
pub struct InMemoryStateReader {
    #[getset(get_mut = "pub")]
    pub address_to_class_hash: HashMap<Address, ClassHash>,
    #[getset(get_mut = "pub")]
    pub address_to_nonce: HashMap<Address, Felt252>,
    #[getset(get_mut = "pub")]
    pub address_to_storage: HashMap<StorageEntry, Felt252>,
    #[getset(get_mut = "pub")]
    pub class_hash_to_contract_class: HashMap<ClassHash, ContractClass>,
}

impl InMemoryStateReader {
    pub fn new(
        address_to_class_hash: HashMap<Address, ClassHash>,
        address_to_nonce: HashMap<Address, Felt252>,
        address_to_storage: HashMap<StorageEntry, Felt252>,
        class_hash_to_contract_class: HashMap<ClassHash, ContractClass>,
    ) -> Self {
        Self {
            address_to_class_hash,
            address_to_nonce,
            address_to_storage,
            class_hash_to_contract_class,
        }
    }
}

impl StateReader for InMemoryStateReader {
    fn get_contract_class(&mut self, class_hash: &ClassHash) -> Result<ContractClass, StateError> {
        let contract_class = self
            .class_hash_to_contract_class
            .get(class_hash)
            .ok_or(StateError::MissingClassHash())
            .cloned()?;
        contract_class.validate()?;
        Ok(contract_class)
    }

    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<&ClassHash, StateError> {
        let class_hash = self
            .address_to_class_hash
            .get(contract_address)
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()));
        class_hash
    }

    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt252, StateError> {
        let nonce = self
            .address_to_nonce
            .get(contract_address)
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()));
        nonce
    }

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<&Felt252, StateError> {
        let storage = self
            .address_to_storage
            .get(storage_entry)
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()));
        storage
    }

    fn count_actual_storage_changes(&mut self) -> (usize, usize) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::api::contract_class::{ContractEntryPoint, EntryPointType};
    use cairo_rs::types::program::Program;

    #[test]
    fn get_contract_state_test() {
        let mut state_reader = InMemoryStateReader::new(
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
            state_reader.get_class_hash_at(&contract_address),
            Ok(&class_hash)
        );
        assert_eq!(state_reader.get_nonce_at(&contract_address), Ok(&nonce));
        assert_eq!(
            state_reader.get_storage_at(&storage_entry),
            Ok(&storage_value)
        );
    }

    #[test]
    fn get_contract_class_test() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_class_key = [0; 32];
        let contract_class = ContractClass::new(
            Program::default(),
            HashMap::from([(
                EntryPointType::Constructor,
                vec![ContractEntryPoint::default()],
            )]),
            None,
        )
        .expect("Error creating contract class");

        state_reader
            .class_hash_to_contract_class
            .insert([0; 32], contract_class.clone());
        assert_eq!(
            state_reader.get_contract_class(&contract_class_key),
            Ok(contract_class)
        )
    }
}
