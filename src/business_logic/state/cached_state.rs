use std::collections::HashMap;

use felt::Felt;
use num_traits::Zero;

use crate::{
    core::errors::state_errors::StateError, services::api::contract_class::ContractClass,
    utils::Address,
};

use super::{
    state_api::{State, StateReader},
    state_api_objects::BlockInfo,
    state_cache::{StateCache, StorageEntry},
};

pub(crate) type ContractClassCache = HashMap<Vec<u8>, ContractClass>;

const UNINITIALIZED_CLASS_HASH: [u8; 32] = [b'0'; 32];

#[derive(Debug, Clone)]
pub(crate) struct CachedState<T: StateReader + Clone> {
    pub(crate) block_info: BlockInfo,
    pub(crate) state_reader: T,
    pub(crate) cache: StateCache,
    pub(crate) contract_classes: Option<ContractClassCache>,
}

impl<T: StateReader + Clone> CachedState<T> {
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

    pub(crate) fn update_block_info(&mut self, block_info: BlockInfo) {
        self.block_info = block_info;
    }

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

    pub(crate) fn set_contract_class(
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

    pub(crate) fn apply(&mut self, mut parent: CachedState<T>) {
        // TODO assert: if self.state_reader == parent
        parent.block_info = self.block_info.clone();
        parent.cache.update_writes_from_other(&self.cache);
    }
}

impl<T: StateReader + Clone> StateReader for CachedState<T> {
    fn get_contract_class(&mut self, class_hash: &[u8]) -> Result<&ContractClass, StateError> {
        if !(self.get_contract_classes()?.contains_key(class_hash)) {
            let contract_class = self.state_reader.get_contract_class(class_hash)?.clone();
            self.set_contract_class(class_hash.to_vec(), contract_class);
        }
        self.get_contract_classes()?
            .get(class_hash)
            .ok_or(StateError::MissingContractClassCache)
    }

    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<&Vec<u8>, StateError> {
        if self.cache.get_class_hash(contract_address).is_none() {
            let class_hash = self.state_reader.get_class_hash_at(contract_address)?;
            self.cache
                .class_hash_initial_values
                .insert(contract_address.clone(), class_hash.clone());
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
            .ok_or_else(|| StateError::NoneNonce(contract_address.address.clone()))
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
}

impl<T: StateReader + Clone> State for CachedState<T> {
    fn get_block_info(&self) -> &BlockInfo {
        &self.block_info
    }

    fn set_contract_class(&mut self, class_hash: &[u8], contract_class: &ContractClass) {
        if let Some(contract_classes) = &mut self.contract_classes {
            contract_classes.insert(Vec::from(class_hash), contract_class.clone());
        }
    }

    fn deploy_contract(
        &mut self,
        contract_address: Address,
        class_hash: Vec<u8>,
    ) -> Result<(), StateError> {
        if contract_address.address == "0x0" {
            return Err(StateError::ContractAddressOutOfRangeAddress(
                contract_address.clone(),
            ));
        }

        let current_class_hash = self.get_class_hash_at(&contract_address)?;

        if current_class_hash == &UNINITIALIZED_CLASS_HASH.to_vec() {
            return Err(StateError::ContractAddressUnavailable(
                contract_address.clone(),
            ));
        }
        self.cache
            .class_hash_writes
            .insert(contract_address, class_hash);

        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError> {
        let new_nonce = self.get_nonce_at(contract_address)? + 1;
        self.cache
            .nonce_writes
            .insert(contract_address.clone(), new_nonce);
        Ok(())
    }

    fn update_block_info(&mut self, block_info: BlockInfo) {
        self.block_info = block_info;
    }

    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt) {
        self.cache
            .storage_writes
            .insert(storage_entry.clone(), value);
    }
}
