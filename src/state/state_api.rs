use num_bigint::BigInt;

use crate::services::api::contract_class::ContractClass;

#[derive(Debug, Clone)]
pub(crate) struct SyncStateReader {}

impl SyncStateReader {
    /// Returns the contract class of the given class hash.
    pub(crate) fn get_contract_class(&self, class_hash: &[u8]) -> ContractClass {
        todo!()
    }
    /// Returns the class hash of the contract class at the given address.
    pub(crate) fn get_class_hash_at(&self, contract_address: &BigInt) -> Vec<u8> {
        todo!()
    }
    /// Returns the nonce of the given contract instance.
    pub(crate) fn get_nonce_at(&self, contract_address: &BigInt) -> BigInt {
        todo!()
    }
    /// Returns the storage value under the given key in the given contract instance.
    pub(crate) fn get_storage_at(&self, contract_address: &BigInt, key: &BigInt) -> BigInt {
        todo!()
    }
}
