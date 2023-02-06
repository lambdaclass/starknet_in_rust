use std::{clone, collections::HashMap};

use felt::Felt;

use crate::{
    business_logic::state::{
        state_api::{ContractStorageKey, StateReader},
        state_cache::StorageEntry,
    },
    core::errors::state_errors::StateError,
    services::api::contract_class::ContractClass,
    starknet_storage::{
        dict_storage::{DictStorage, Prefix},
        storage::Storage,
    },
    utils::{Address, ClassHash},
};

use super::contract_state::{self, ContractState};

#[derive(Clone, Debug)]
pub(crate) struct InMemoryStateReader {
    pub contract_storage: HashMap<ContractStorageKey, Felt>,
    pub address_to_nonce: HashMap<Address, Felt>,
    pub address_to_class_hash: HashMap<Address, ClassHash>,
    pub class_hash_to_class: HashMap<ClassHash, ContractClass>,
}

impl InMemoryStateReader {
    //TODO: Which arguments should I expect?
    pub(crate) fn new(ffc: DictStorage, contract_class_storage: DictStorage) -> Self {
        Self {
            contract_storage: HashMap::new(),
            address_to_nonce: HashMap::new(),
            address_to_class_hash: HashMap::new(),
            class_hash_to_class: HashMap::new(),
        }
    }
}

impl StateReader for InMemoryStateReader {
    fn get_contract_class(&mut self, class_hash: &[u8; 32]) -> Result<ContractClass, StateError> {
        let contract_class = match self.class_hash_to_class.get(class_hash) {
            Some(it) => it,
            //TODO: Check where to fetch Address or which error to return
            None => return Err(StateError::NoneClassHash(Address::default())),
        };
        contract_class.validate()?;
        Ok(*contract_class)
    }
    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<&[u8; 32], StateError> {
        Ok(match self.address_to_class_hash.get(contract_address) {
            Some(it) => it,
            None => return Err(StateError::NoneClassHash(*contract_address)),
        })
    }

    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt, StateError> {
        let result = match self.address_to_nonce.get(contract_address) {
            Some(it) => it,
            None => return Err(StateError::NoneNonce((*contract_address))),
        };
        Ok(result)
    }

    fn get_storage_at(&mut self, storage_entry: &ContractStorageKey) -> Result<&Felt, StateError> {
        let contract_state = match self.contract_storage.get(storage_entry) {
            Some(it) => it,
            None => return Err(StateError::NoneStorage((*storage_entry))),
        };
        Ok(contract_state)
    }
}
#[cfg(test)]
mod tests {
    use cairo_rs::types::program::Program;

    use crate::{
        business_logic::state::cached_state,
        services::api::contract_class::{self, ContractEntryPoint, EntryPointType},
        starknet_storage::dict_storage::DictStorage,
    };

    use super::*;

    #[test]
    fn get_contract_class_test() {
        let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());

        let contract_class_key = [0; 32];
        let class_hash = [0; 32];
        let contract_class = ContractClass::new(
            Program::default(),
            HashMap::from([(
                EntryPointType::Constructor,
                vec![ContractEntryPoint::default()],
            )]),
            None,
        )
        .expect("Error creating contract class");

        state_reader.get_contract_class(&class_hash);
        assert_eq!(
            state_reader.get_contract_class(&contract_class_key),
            Ok(contract_class)
        );
    }
}
