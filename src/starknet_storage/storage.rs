use super::{
    dict_storage::{Prefix, StorageKey},
    errors::storage_errors::StorageError,
};
use crate::{
    business_logic::fact_state::contract_state::ContractState,
    services::api::contract_class::ContractClass,
};
use std::str;

/* -----------------------------------------------------------------------------------
   -----------------------------------------------------------------------------------

    This module implements the trait for the the storages operations.
    The trait default functions handle the different data types that can be stored,
    some assumptions and work arounds have been taken for this.

    * All data types are turned into Vec<u8> before being passed to the set_value function.
    This is due to rust restrictions on parameter types for the functions in traits.

    * The same is true for get_value but this returns an Option because there may be nothing in the storage for a given key.

    * float types are assumed to be f32, in case of needing to store f64, get_double and set_double functions can be implemented.

    * Strings are assumed to be UTF-8 valid encoding, using a different format falls in an error.

    * get_str returns a String type rather than a str to avoid lifetimes or reference issues.

  -----------------------------------------------------------------------------------
  -----------------------------------------------------------------------------------
*/

//* ------------------
//*   Storage Trait
//* ------------------

pub trait Storage {
    fn set_value(&mut self, key: &StorageKey, value: Vec<u8>) -> Result<(), StorageError>;
    fn get_value(&self, key: &StorageKey) -> Option<Vec<u8>>;
    fn delete_value(&mut self, key: &StorageKey) -> Result<Vec<u8>, StorageError>;

    fn get_value_or_fail(&self, key: &StorageKey) -> Result<Vec<u8>, StorageError> {
        self.get_value(key).ok_or(StorageError::ErrorFetchingData)
    }

    fn set_int(&mut self, key: &[u8; 32], value: i32) -> Result<(), StorageError> {
        let val = value.to_ne_bytes().to_vec();
        self.set_value(&(Prefix::Int, *key), val)
    }

    fn get_int(&self, key: &[u8; 32]) -> Result<i32, StorageError> {
        let value = self
            .get_value(&(Prefix::Int, *key))
            .ok_or(StorageError::ErrorFetchingData)?;
        let slice: [u8; 4] = value
            .try_into()
            .map_err(|_| StorageError::IncorrectDataSize)?;
        Ok(i32::from_ne_bytes(slice))
    }

    fn get_int_or_default(&self, key: &[u8; 32], default: i32) -> Result<i32, StorageError> {
        match self.get_value(&(Prefix::Int, *key)) {
            Some(val) => {
                let slice: [u8; 4] = val
                    .try_into()
                    .map_err(|_| StorageError::IncorrectDataSize)?;
                Ok(i32::from_ne_bytes(slice))
            }
            None => Ok(default),
        }
    }

    fn get_int_or_fail(&self, key: &[u8; 32]) -> Result<i32, StorageError> {
        let val = self.get_value_or_fail(&(Prefix::Int, *key))?;
        let slice: [u8; 4] = val
            .try_into()
            .map_err(|_| StorageError::IncorrectDataSize)?;
        Ok(i32::from_ne_bytes(slice))
    }

    fn set_float(&mut self, key: &[u8; 32], value: f64) -> Result<(), StorageError> {
        let val = value.to_bits().to_be_bytes().to_vec();
        self.set_value(&(Prefix::Float, *key), val)
    }

    fn get_float(&self, key: &[u8; 32]) -> Result<f64, StorageError> {
        let val = self
            .get_value(&(Prefix::Float, *key))
            .ok_or(StorageError::ErrorFetchingData)?;
        let float_bytes: [u8; 8] = val
            .try_into()
            .map_err(|_| StorageError::IncorrectDataSize)?;

        Ok(f64::from_bits(u64::from_be_bytes(float_bytes)))
    }

    fn set_str(&mut self, key: &[u8; 32], value: &str) -> Result<(), StorageError> {
        let val = value.as_bytes().to_vec();
        self.set_value(&(Prefix::Str, *key), val)
    }

    fn get_str(&self, key: &[u8; 32]) -> Result<String, StorageError> {
        let val = self
            .get_value(&(Prefix::Str, *key))
            .ok_or(StorageError::ErrorFetchingData)?;
        let str = str::from_utf8(&val[..]).map_err(|_| StorageError::IncorrectUtf8Enconding)?;
        Ok(String::from(str))
    }

    // TODO: Change key type to &Address.
    fn set_contract_state(
        &mut self,
        key: &[u8; 32],
        value: &ContractState,
    ) -> Result<(), StorageError> {
        let contract_state = serde_json::to_string(value)?.as_bytes().to_vec();

        self.set_value(&(Prefix::ContractState, *key), contract_state)
    }

    // TODO: Change key type to &Address.
    fn get_contract_state(&self, key: &[u8; 32]) -> Result<ContractState, StorageError> {
        let ser_contract_state = self
            .get_value(&(Prefix::ContractState, *key))
            .ok_or(StorageError::ErrorFetchingData)?;

        let contract_state: ContractState = serde_json::from_slice(&ser_contract_state)?;
        Ok(contract_state)
    }

    // TODO: Change key type to &Address.
    fn get_contract_class(&self, key: &[u8; 32]) -> Result<ContractClass, StorageError> {
        let ser_contract_class = self
            .get_value(&(Prefix::ContractClass, *key))
            .ok_or(StorageError::ErrorFetchingData)?;

        let contract_class: ContractClass = serde_json::from_slice(&ser_contract_class)?;
        Ok(contract_class)
    }

    // TODO: Change key type to &Address.
    fn set_contract_class(
        &mut self,
        key: &[u8; 32],
        value: &ContractClass,
    ) -> Result<(), StorageError> {
        let contract_class = serde_json::to_string(value)?.as_bytes().to_vec();

        self.set_value(&(Prefix::ContractClass, *key), contract_class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        services::api::contract_class::{ContractEntryPoint, EntryPointType},
        starknet_storage::dict_storage::DictStorage,
        utils::test_utils::storage_key,
    };
    use cairo_rs::types::program::Program;
    use felt::Felt;
    use std::collections::HashMap;

    #[test]
    fn get_and_set_contract_state() {
        let mut storage = DictStorage::new();

        let key = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");

        let contract_state = ContractState::new([8; 32], Felt::new(9), HashMap::new());
        storage
            .set_contract_state(&key, &contract_state)
            .expect("Error setting contract state");

        assert_eq!(Ok(contract_state), storage.get_contract_state(&key));
    }

    #[test]
    fn get_and_set_contract_class() {
        let mut storage = DictStorage::new();

        let key = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");

        let contract_class = ContractClass::new(
            Program::default(),
            HashMap::from([(
                EntryPointType::Constructor,
                vec![ContractEntryPoint::default()],
            )]),
            None,
        )
        .expect("Error creating contract class");

        storage
            .set_contract_class(&key, &contract_class)
            .expect("Error setting contract class");

        assert_eq!(Ok(contract_class), storage.get_contract_class(&key));
    }
}
