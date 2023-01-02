use super::{errors::storage_errors::StorageError, storage::Storage};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DictStorage {
    storage: HashMap<[u8; 32], Vec<u8>>,
}

impl DictStorage {
    pub fn new() -> Self {
        DictStorage {
            storage: HashMap::new(),
        }
    }
}

impl Storage for DictStorage {
    fn set_value(&mut self, key: &[u8; 32], value: Vec<u8>) -> Result<(), StorageError> {
        self.storage.insert(*key, value);
        Ok(())
    }
    fn get_value(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.storage.get(&*key).cloned()
    }
    fn delete_value(&mut self, key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        self.storage
            .remove(&*key)
            .ok_or(StorageError::RemoveMissingKey)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::test_utils::storage_key;

    use super::*;

    #[test]
    fn insert_data_in_storage() {
        let mut storage = DictStorage::new();

        let ikey = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let fkey = storage_key!("0000000000000000000000000000000000000000000000000000000000000001");
        let skey = storage_key!("0000000000000000000000000000000000000000000000000000000000000002");

        storage.set_float(&fkey, 4.0);
        storage.set_int(&ikey, 4);
        storage.set_str(&skey, "value");

        assert_eq!(storage.get_int(&ikey).unwrap(), 4);
        assert_eq!(storage.get_float(&fkey).unwrap(), 4.0);
        assert_eq!(storage.get_str(&skey).unwrap(), "value");
    }

    #[test]
    fn get_int_not_default() {
        let mut storage = DictStorage::new();
        let default = 0;
        let key = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");
        storage.set_int(&key, 1234);
        assert_eq!(storage.get_int_or_default(&key, default).unwrap(), 1234)
    }

    #[test]
    fn get_int_default() {
        let storage = DictStorage::new();
        let default = 0;
        let key = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");

        assert_eq!(storage.get_int_or_default(&key, default).unwrap(), default)
    }
    #[test]
    fn error_after_inserting_different_data_under_same_key() {
        let mut storage = DictStorage::new();

        let ikey = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let fkey = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");

        storage.set_float(&fkey, 4.0);
        storage.set_int(&ikey, 4);

        assert_eq!(
            storage.get_float(&fkey),
            Err(StorageError::IncorrectDataSize)
        );
        assert_eq!(storage.get_int(&ikey).unwrap(), 4);
    }

    #[test]
    fn error_after_getting_deleted_value() {
        let mut storage = DictStorage::new();

        let fkey = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");

        storage.set_float(&fkey, 4.0002);
        storage.delete_value(&fkey);

        assert_eq!(
            storage.get_float(&fkey),
            Err(StorageError::ErrorFetchingData)
        );
    }

    #[test]
    fn error_trying_to_delete_non_existing_or_deleted_value() {
        let mut storage = DictStorage::new();

        let fkey = storage_key!("0000000000000000000000000000000000000000000000000000000000000000");
        let ikey = storage_key!("0000000000000000000000000000000000000000000000000000000000000001");

        storage.set_float(&fkey, 534.0002);
        storage.delete_value(&fkey);

        assert_eq!(
            storage.delete_value(&fkey),
            Err(StorageError::RemoveMissingKey)
        );

        assert_eq!(
            storage.delete_value(&ikey),
            Err(StorageError::RemoveMissingKey)
        );
    }
}
