use num_bigint::BigInt;

use crate::services::api::contract_class::ContractClass;

use super::state_api_objects::BlockInfo;

pub(crate) trait StateReader {
    /// Returns the contract class of the given class hash.
    fn get_contract_class(&self, class_hash: &[u8]) -> ContractClass;
    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, contract_address: &BigInt) -> Vec<u8>;
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: &BigInt) -> BigInt;
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(&self, contract_address: &BigInt, key: &BigInt) -> BigInt;
}

pub(crate) trait State {
    fn block_info(&self) -> BlockInfo;
    fn set_contract_class(&mut self, class_hash: &[u8], contract_class: &ContractClass);
    fn deploy_contract(&self, contract_address: &BigInt, class_hash: &[u8]);
    fn increment_nonce(&mut self, contract_address: &BigInt);
    fn update_block_info(&mut self, block_info: &BlockInfo);
    fn set_storage_at(&mut self, contract_address: &BigInt, key: &BigInt, value: BigInt);
}
