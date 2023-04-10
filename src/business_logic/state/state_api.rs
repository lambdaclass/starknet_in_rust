use super::state_cache::StorageEntry;
use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::contract_class::DeprecatedContractClass,
    utils::{Address, ClassHash},
};
use felt::Felt252;

pub trait StateReader {
    /// Returns the contract class of the given class hash.
    fn get_contract_class(
        &mut self,
        class_hash: &ClassHash,
    ) -> Result<DeprecatedContractClass, StateError>;
    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<&ClassHash, StateError>;
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<&Felt252, StateError>;
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<&Felt252, StateError>;
    /// Counts the amount of modified contracts and the updates to the storage
    fn count_actual_storage_changes(&mut self) -> (usize, usize);
}

pub trait State {
    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: &DeprecatedContractClass,
    ) -> Result<(), StateError>;
    fn deploy_contract(
        &mut self,
        contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError>;
    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError>;
    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt252);
}
