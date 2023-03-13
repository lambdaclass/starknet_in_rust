use super::{
    state_api::{State, StateReader},
    state_cache::{StateCache, StorageEntry},
};
use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_class::ContractClass,
    utils::{subtract_mappings, Address},
};
use felt::Felt;
use getset::Getters;
use std::collections::HashMap;

// K: class_hash V: ContractClass
pub type ContractClassCache = HashMap<[u8; 32], ContractClass>;

pub(crate) const UNINITIALIZED_CLASS_HASH: &[u8; 32] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

#[derive(Debug, Clone, Default, Getters)]
pub struct CachedState<T: StateReader + Clone> {
    pub(crate) state_reader: T,
    #[get = "pub"]
    pub(crate) cache: StateCache,
    pub(crate) contract_classes: Option<ContractClassCache>,
}

impl<T: StateReader + Clone> CachedState<T> {
    pub fn new(state_reader: T, contract_class_cache: Option<ContractClassCache>) -> Self {
        Self {
            cache: StateCache::default(),
            contract_classes: contract_class_cache,
            state_reader,
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub(crate) fn set_contract_classes(
        &mut self,
        contract_classes: ContractClassCache,
    ) -> Result<(), StateError> {
        if self.contract_classes.is_some() {
            return Err(StateError::AssignedContractClassCache);
        }
        self.contract_classes = Some(contract_classes);
        Ok(())
    }

    pub(crate) fn get_contract_classes(&self) -> Result<&ContractClassCache, StateError> {
        self.contract_classes
            .as_ref()
            .ok_or(StateError::MissingContractClassCache)
    }

    /// Apply updates to parent state.
    pub(crate) fn apply(&mut self, parent: &mut CachedState<T>) {
        // TODO assert: if self.state_reader == parent
        parent.cache.update_writes_from_other(&self.cache);
    }

    pub(crate) fn apply_to_copy(&mut self) -> Self {
        let mut copied_state = self.clone();
        copied_state.apply(self);
        copied_state
    }
}

impl<T: StateReader + Clone> StateReader for CachedState<T> {
    fn get_contract_class(&mut self, class_hash: &[u8; 32]) -> Result<ContractClass, StateError> {
        if !(self.get_contract_classes()?.contains_key(class_hash)) {
            let contract_class = self.state_reader.get_contract_class(class_hash)?;
            self.set_contract_class(class_hash, &contract_class)?;
        }
        Ok(self
            .get_contract_classes()?
            .get(class_hash)
            .ok_or(StateError::MissingContractClassCache)?
            .to_owned())
    }

    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<&[u8; 32], StateError> {
        if self.cache.get_class_hash(contract_address).is_none() {
            let class_hash = self.state_reader.get_class_hash_at(contract_address)?;
            self.cache
                .class_hash_initial_values
                .insert(contract_address.clone(), *class_hash);
        }

        self.cache
            .get_class_hash(contract_address)
            .ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))
    }

    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt, StateError> {
        if self.cache.get_nonce(contract_address).is_none() {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache
                .nonce_initial_values
                .insert(contract_address.clone(), nonce.clone());
        }
        self.cache
            .get_nonce(contract_address)
            .ok_or_else(|| StateError::NoneNonce(contract_address.clone()))
    }

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<&Felt, StateError> {
        if self.cache.get_storage(storage_entry).is_none() {
            let value = self.state_reader.get_storage_at(storage_entry)?;
            self.cache
                .storage_initial_values
                .insert(storage_entry.clone(), value.clone());
        }

        self.cache
            .get_storage(storage_entry)
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()))
    }

    fn count_actual_storage_changes(&mut self) -> (usize, usize) {
        let storage_updates = subtract_mappings(
            self.cache.storage_writes.clone(),
            self.cache.storage_initial_values.clone(),
        );
        let modified_contracts = storage_updates.keys().map(|k| k.0.clone()).len();
        (modified_contracts, storage_updates.len())
    }
}

impl<T: StateReader + Clone> State for CachedState<T> {
    fn set_contract_class(
        &mut self,
        class_hash: &[u8; 32],
        contract_class: &ContractClass,
    ) -> Result<(), StateError> {
        self.contract_classes
            .as_mut()
            .ok_or(StateError::MissingContractClassCache)?
            .insert(*class_hash, contract_class.clone());

        Ok(())
    }

    fn deploy_contract(
        &mut self,
        deploy_contract_address: Address,
        class_hash: [u8; 32],
    ) -> Result<(), StateError> {
        if deploy_contract_address == Address(0.into()) {
            return Err(StateError::ContractAddressOutOfRangeAddress(
                deploy_contract_address.clone(),
            ));
        }

        if self.get_class_hash_at(&deploy_contract_address).is_ok() {
            return Err(StateError::ContractAddressUnavailable(
                deploy_contract_address.clone(),
            ));
        }

        self.cache
            .class_hash_writes
            .insert(deploy_contract_address, class_hash);
        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError> {
        let new_nonce = self.get_nonce_at(contract_address)? + 1;
        self.cache
            .nonce_writes
            .insert(contract_address.clone(), new_nonce);
        Ok(())
    }

    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt) {
        self.cache
            .storage_writes
            .insert(storage_entry.clone(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        business_logic::fact_state::in_memory_state_reader::InMemoryStateReader,
        services::api::contract_class::{ContractEntryPoint, EntryPointType},
    };
    use cairo_rs::types::program::Program;

    #[test]
    fn get_class_hash_and_nonce_from_state_reader() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(4242.into());
        let class_hash = [3; 32];
        let nonce = Felt::new(47602);
        let storage_entry = (contract_address.clone(), [101; 32]);
        let storage_value = Felt::new(1);

        state_reader
            .address_to_class_hash_mut()
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(contract_address.clone(), nonce.clone());
        state_reader
            .address_to_storage_mut()
            .insert(storage_entry, storage_value);

        let mut cached_state = CachedState::new(state_reader, None);

        assert_eq!(
            cached_state.get_class_hash_at(&contract_address),
            Ok(&class_hash)
        );
        assert_eq!(cached_state.get_nonce_at(&contract_address), Ok(&nonce));
        cached_state.increment_nonce(&contract_address).unwrap();
        assert_eq!(
            cached_state.get_nonce_at(&contract_address),
            Ok(&(nonce + Felt::new(1)))
        );
    }

    #[test]
    fn get_contract_class_from_state_reader() {
        let mut state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

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
            .insert([0; 32], contract_class);

        let mut cached_state = CachedState::new(state_reader, None);

        cached_state.set_contract_classes(HashMap::new()).unwrap();
        assert!(cached_state.contract_classes.is_some());

        assert_eq!(
            cached_state.get_contract_class(&[0; 32]),
            cached_state.state_reader.get_contract_class(&[0; 32])
        );
    }

    #[test]
    fn cached_state_storage_test() {
        let mut cached_state = CachedState::new(
            InMemoryStateReader::new(
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            None,
        );

        let storage_entry: StorageEntry = (Address(31.into()), [0; 32]);
        let value = Felt::new(10);
        cached_state.set_storage_at(&storage_entry, value.clone());

        assert_eq!(cached_state.get_storage_at(&storage_entry), Ok(&value));

        let storage_entry_2: StorageEntry = (Address(150.into()), [1; 32]);
        assert!(cached_state.get_storage_at(&storage_entry_2).is_err());
    }

    #[test]
    fn cached_state_deploy_contract_test() {
        let state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(32123.into());

        let mut cached_state = CachedState::new(state_reader, None);

        assert!(cached_state
            .deploy_contract(contract_address, [10; 32])
            .is_ok());
    }

    #[test]
    fn get_and_set_storage() {
        let state_reader = InMemoryStateReader::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );

        let contract_address = Address(31.into());
        let storage_key = [18; 32];
        let value = Felt::new(912);

        let mut cached_state = CachedState::new(state_reader, None);

        // set storage_key
        cached_state.set_storage_at(&(contract_address.clone(), storage_key), value.clone());
        let result = cached_state.get_storage_at(&(contract_address.clone(), storage_key));

        assert_eq!(result, Ok(&value));

        // rewrite storage_key
        let new_value = value + 3_usize;

        cached_state.set_storage_at(&(contract_address.clone(), storage_key), new_value.clone());

        let new_result = cached_state.get_storage_at(&(contract_address, storage_key));

        assert_eq!(new_result, Ok(&new_value));
    }
}
