use felt::Felt;

use crate::{
    core::errors::state_errors::StateError, services::api::contract_class::ContractClass,
    utils::Address,
};

use super::{state_api_objects::BlockInfo, state_cache::StorageEntry};

pub trait StateReader {
    /// Returns the contract class of the given class hash.
    fn get_contract_class(&mut self, class_hash: &[u8; 32]) -> Result<ContractClass, StateError>;
    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<&[u8; 32], StateError>;
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt, StateError>;
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<&Felt, StateError>;
}

pub trait State {
    fn block_info(&self) -> &BlockInfo;
    fn set_contract_class(
        &mut self,
        class_hash: &[u8; 32],
        contract_class: &ContractClass,
    ) -> Result<(), StateError>;
    fn deploy_contract(
        &mut self,
        contract_address: Address,
        class_hash: [u8; 32],
    ) -> Result<(), StateError>;
    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError>;
    fn update_block_info(&mut self, block_info: BlockInfo);
    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt);
}

pub trait StateComplete: StateReader + State {}
