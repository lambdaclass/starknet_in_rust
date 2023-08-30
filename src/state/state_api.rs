use super::{state_cache::StorageEntry, cached_state::SierraContractClass};
use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::StateDiff,
    utils::{Address, ClassHash, CompiledClassHash},
};
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_lang_utils::bigint::BigUintAsHex;
use cairo_vm::felt::Felt252;

pub trait StateReader {
    /// Returns the contract class of the given class hash or compiled class hash.
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError>;
    /// Returns the class hash of the contract class at the given address.
    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError>;
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError>;
    /// Returns the storage value under the given key in the given contract instance.
    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError>;
    /// Return the class hash of the given casm contract class
    fn get_compiled_class_hash(
        &self,
        class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError>;
}

pub trait State {
    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: &ContractClass,
    ) -> Result<(), StateError>;

    fn deploy_contract(
        &mut self,
        contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError>;

    fn increment_nonce(&mut self, contract_address: &Address) -> Result<(), StateError>;

    fn set_storage_at(&mut self, storage_entry: &StorageEntry, value: Felt252);

    fn set_class_hash_at(
        &mut self,
        contract_address: Address,
        class_hash: ClassHash,
    ) -> Result<(), StateError>;

    fn set_compiled_class(
        &mut self,
        compiled_class_hash: &Felt252,
        casm_class: CasmContractClass,
    ) -> Result<(), StateError>;

    fn set_compiled_class_hash(
        &mut self,
        class_hash: &Felt252,
        compiled_class_hash: &Felt252,
    ) -> Result<(), StateError>;

    fn set_sierra_program(
        &mut self,
        compiled_class_hash: &Felt252,
        sierra_program: SierraContractClass,
    ) -> Result<(), StateError>;

    fn apply_state_update(&mut self, sate_updates: &StateDiff) -> Result<(), StateError>;

    /// Counts the amount of modified contracts and the updates to the storage
    fn count_actual_storage_changes(&mut self) -> (usize, usize);

    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<ClassHash, StateError>;

    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<Felt252, StateError>;

    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<Felt252, StateError>;

    fn get_compiled_class_hash(&mut self, class_hash: &ClassHash) -> Result<ClassHash, StateError>;

    fn get_contract_class(&mut self, class_hash: &ClassHash) -> Result<CompiledClass, StateError>;

    fn get_sierra_program(
        &mut self,
        class_hash: &ClassHash,
    ) -> Result<Vec<BigUintAsHex>, StateError>;
}
