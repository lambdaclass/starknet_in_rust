use crate::{
    business_logic::state::{
        cached_state::CasmClassCache, state_api::StateReader, state_cache::StorageEntry,
    },
    core::errors::state_errors::StateError,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    utils::{Address, ClassHash, CompiledClassHash},
};
use cairo_vm::felt::Felt252;
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
    #[getset(get_mut = "pub")]
    pub(crate) casm_contract_classes: CasmClassCache,
    #[getset(get_mut = "pub")]
    class_hash_to_compiled_class_hash: HashMap<ClassHash, CompiledClassHash>,
}

impl InMemoryStateReader {
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

    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let class_hash = self
            .address_to_class_hash
            .get(contract_address)
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()));
        class_hash.cloned()
    }

    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<Felt252, StateError> {
        let nonce = self
            .address_to_nonce
            .get(contract_address)
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()));
        nonce.cloned()
    }

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let storage = self
            .address_to_storage
            .get(storage_entry)
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()));
        storage.cloned()
    }

    fn count_actual_storage_changes(&mut self) -> (usize, usize) {
        todo!()
    }

    fn get_compiled_class(
        &mut self,
        compiled_class_hash: &CompiledClassHash,
    ) -> Result<CompiledClass, StateError> {
        if let Some(compiled_class) = self.casm_contract_classes.get(compiled_class_hash) {
            return Ok(CompiledClass::Casm(Box::new(compiled_class.clone())));
        }
        if let Some(compiled_class) = self.class_hash_to_contract_class.get(compiled_class_hash) {
            return Ok(CompiledClass::Deprecated(Box::new(compiled_class.clone())));
        }
        Err(StateError::NoneCompiledClass(*compiled_class_hash))
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError> {
        self.class_hash_to_compiled_class_hash
            .get(class_hash)
            .ok_or(StateError::NoneCompiledHash(*class_hash))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::api::contract_classes::deprecated_contract_class::{
        ContractEntryPoint, EntryPointType,
    };
    use cairo_vm::types::program::Program;

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
            state_reader.get_class_hash_at(&contract_address),
            Ok(class_hash)
        );
        assert_eq!(state_reader.get_nonce_at(&contract_address), Ok(nonce));
        assert_eq!(
            state_reader.get_storage_at(&storage_entry),
            Ok(storage_value)
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

    #[test]
    #[should_panic]
    fn count_actual_storage_changes_is_a_wip() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        state_reader.count_actual_storage_changes();
    }
}
