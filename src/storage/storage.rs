use super::errors::storage_errors::StorageError;

//* ------------------
//*   Storage Trait
//* ------------------

pub(crate) trait Storage {
    type T;
    fn set_value(&mut self, key: &[u8; 32], value: Vec<u8>) -> Result<(), StorageError>;
    fn get_value(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
    fn delete_value(&mut self, key: &[u8; 32]) -> Result<(), StorageError>;

    fn get_value_or_fail(&self, key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        self.get_value(key).ok_or(StorageError::ErrorFetchingData)
    }

    fn set_int(&mut self, key: &[u8; 32], value: i32) -> Result<(), StorageError> {
        let val = Vec::from(value.to_ne_bytes());
        self.set_value(key, val)
    }

    fn get_int(&self, key: &[u8; 32]) -> Result<i32, StorageError> {
        let value = self.get_value(key).ok_or(StorageError::ErrorFetchingData)?;
        let slice: [u8; 4] = value.try_into().expect("slice with incorrect length");
        Ok(i32::from_ne_bytes(slice))
    }
}
