use std::collections::HashMap;

use num_bigint::BigInt;

use crate::{
    bigint, core::errors::state_errors::StateError, services::api::contract_class::ContractClass,
};

use super::{
    state_api::{State, StateReader},
    state_api_objects::BlockInfo,
    state_chache::{StateCache, StorageEntry},
};

pub(crate) type ContractClassCache = HashMap<Vec<u8>, ContractClass>;

const UNINITIALIZED_CLASS_HASH: [u8; 32] = [b'0'; 32];

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

    pub(crate) fn get_contract_classes(&self) -> Result<&ContractClassCache, StateError> {
        self.contract_classes
            .as_ref()
            .ok_or(StateError::MissingContractClassCache)
    }

    pub(crate) fn insert_contract_class(
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

    pub(crate) fn set_contract_class_cache(
        &mut self,
        contract_classes: ContractClassCache,
    ) -> Result<(), StateError> {
        if self.contract_classes.is_some() {
            return Err(StateError::AssignedContractClassCache);
        }
        self.contract_classes = Some(contract_classes);
        Ok(())
    }

    pub(crate) fn update_block_info(&mut self, block_info: BlockInfo) {
        self.block_info = block_info;
    }

    pub(crate) fn set_contract_class(&mut self, class_hash: &[u8], contract_class: ContractClass) {
        if let Some(contract_classes) = &mut self.contract_classes {
            contract_classes.insert(Vec::from(class_hash), contract_class);
        }
    }
}

impl<T: StateReader> StateReader for CachedState<T> {
    fn get_contract_class(&mut self, class_hash: &[u8]) -> Result<ContractClass, StateError> {
        if !(self.get_contract_classes()?.contains_key(class_hash)) {
            let contract_class = &self.state_reader.get_contract_class(class_hash)?;
            self.insert_contract_class(class_hash.to_vec(), contract_class.to_owned());
        }
        self.get_contract_class(class_hash)
    }

    fn get_class_hash_at(&mut self, contract_address: &BigInt) -> Result<Vec<u8>, StateError> {
        if !(self
            .cache
            .get_address_to_class_hash()
            .contains_key(contract_address))
        {
            let class_hash = self.state_reader.get_class_hash_at(contract_address)?;
            self.cache
                .class_hash_initial_values
                .insert(contract_address.clone(), class_hash);
        }

        Ok(self
            .cache
            .get_address_to_class_hash()
            .get(contract_address)
            .ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?
            .to_vec())
    }

    fn get_nonce_at(&mut self, contract_address: &BigInt) -> Result<BigInt, StateError> {
        if !(self
            .cache
            .get_address_to_nonce()
            .contains_key(contract_address))
        {
            let nonce = self.state_reader.get_nonce_at(contract_address)?;
            self.cache
                .nonce_initial_values
                .insert(contract_address.clone(), nonce);
        }
        Ok(self
            .cache
            .get_address_to_nonce()
            .get(contract_address)
            .ok_or_else(|| StateError::NoneNonce(contract_address.clone()))?
            .to_owned())
    }

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<BigInt, StateError> {
        if !(self.cache.get_storage_view().contains_key(storage_entry)) {
            let value = self.state_reader.get_storage_at(storage_entry)?;
            self.cache
                .storage_initial_values
                .insert(storage_entry.clone(), value);
        }

        Ok(self
            .cache
            .get_storage_view()
            .get(storage_entry)
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()))?
            .clone())
    }
}

impl<T: StateReader> State for CachedState<T> {
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
        contract_address: BigInt,
        class_hash: Vec<u8>,
    ) -> Result<(), StateError> {
        if contract_address == bigint!(0) {
            return Err(StateError::ContractAddressOutOfRangeAddress(
                contract_address,
            ));
        }

        let current_class_hash = self.get_class_hash_at(&contract_address)?;

        if current_class_hash == UNINITIALIZED_CLASS_HASH.to_vec() {
            return Err(StateError::ContractAddressUnavailable(contract_address));
        }
        self.cache
            .class_hash_writes
            .insert(contract_address, class_hash);

        Ok(())
    }

    fn increment_nonce(&mut self, contract_address: &BigInt) -> Result<(), StateError> {
        let current_nonce = self.get_nonce_at(contract_address)?;
        self.cache
            .nonce_writes
            .insert(contract_address.clone(), current_nonce + 1);
        Ok(())
    }

    fn update_block_info(&mut self, block_info: BlockInfo) {
        self.block_info = block_info;
    }

    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: BigInt) {
        self.cache
            .storage_writes
            .insert(storage_entry.clone(), value);
    }
}
