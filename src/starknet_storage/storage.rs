use super::errors::storage_errors::StorageError;
use cairo_rs::types::instruction::Res;
use std::str;

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
        let val = value.to_ne_bytes().to_vec();
        self.set_value(key, val)
    }

    fn get_int(&self, key: &[u8; 32]) -> Result<i32, StorageError> {
        let value = self.get_value(key).ok_or(StorageError::ErrorFetchingData)?;
        let slice: [u8; 4] = value
            .try_into()
            .map_err(|_| StorageError::IncorrectDataSize)?;
        Ok(i32::from_ne_bytes(slice))
    }

    fn get_int_or_default(&self, key: &[u8; 32], default: i32) -> Result<i32, StorageError> {
        match self.get_value(key) {
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
        let val = self.get_value_or_fail(key)?;
        let slice: [u8; 4] = val
            .try_into()
            .map_err(|_| StorageError::IncorrectDataSize)?;
        Ok(i32::from_ne_bytes(slice))
    }

    fn set_float(&mut self, key: &[u8; 32], value: f32) -> Result<(), StorageError> {
        let val = value.to_bits().to_be_bytes().to_vec();
        self.set_value(key, val)
    }

    fn get_float(&self, key: &[u8; 32]) -> Result<f32, StorageError> {
        let val = self.get_value(key).ok_or(StorageError::ErrorFetchingData)?;
        let float_bytes: [u8; 4] = val
            .try_into()
            .map_err(|_| StorageError::IncorrectDataSize)?;

        Ok(f32::from_bits(u32::from_be_bytes(float_bytes)))
    }

    fn set_str(&mut self, key: &[u8; 32], value: &str) -> Result<(), StorageError> {
        let val = value.as_bytes().to_vec();
        self.set_value(key, val)
    }

    fn get_str(&self, key: &[u8; 32]) -> Result<String, StorageError> {
        let val = self.get_value(key).ok_or(StorageError::ErrorFetchingData)?;
        let str = str::from_utf8(&val[..]).map_err(|_| StorageError::IncorrectUtf8Enconding)?;
        Ok(String::from(str))
    }
}
