use std::collections::HashMap;

use num_bigint::BigInt;

use crate::{core::errors::state_errors::StateError, services::api::contract_class::ContractClass};

use super::{
    state_api::StateReader,
    state_api_objects::BlockInfo,
    state_chache::{StateCache, StorageEntry},
};

pub(crate) type ContractClassCache = HashMap<Vec<u8>, ContractClass>;

pub(crate) struct CachedState<T: StateReader> {
    block_info: BlockInfo,
    pub(crate) state_reader: T,
    pub(crate) cache: StateCache,
    contract_classes: Option<ContractClassCache>,
}

impl<T: StateReader> CachedState<T> {
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

    pub(crate) fn deploy_contract(&self, contract_address: &BigInt, class_hash: &[u8]) {
        todo!()
    }

    pub(crate) fn set_storage_at(
        &self,
        contract_address: &BigInt,
        key: &[u8; 32],
        value: BigInt,
    ) -> BigInt {
        todo!()
    }
}

impl<T: StateReader> StateReader for CachedState<T> {
    fn get_contract_class(&mut self, class_hash: &[u8]) -> Result<&ContractClass, StateError> {
        if !(self.get_contract_classes()?.contains_key(class_hash)) {
            let contract_class = self.state_reader.get_contract_class(class_hash)?.clone();
            self.set_contract_class(class_hash.to_vec(), contract_class);
        }
        self.get_contract_classes()?
            .get(class_hash)
            .ok_or(StateError::MissingContractClassCache)
    }

    fn get_class_hash_at(&mut self, contract_address: &BigInt) -> Result<&Vec<u8>, StateError> {
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

    fn get_nonce_at(&mut self, contract_address: &BigInt) -> Result<&BigInt, StateError> {
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

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<&BigInt, StateError> {
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
