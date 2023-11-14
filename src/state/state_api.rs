use super::state_cache::StorageEntry;
use crate::{
    core::errors::state_errors::StateError,
    definitions::block_context::BlockContext,
    services::api::contract_classes::compiled_class::CompiledClass,
    state::StateDiff,
    utils::{get_erc20_balance_var_addresses, Address, ClassHash, CompiledClassHash},
};
use cairo_lang_sierra::program::Program as SierraProgram;
use cairo_lang_starknet::contract_class::ContractEntryPoints;
use cairo_vm::felt::Felt252;
use std::sync::Arc;

pub trait StateReader {
    /// Returns the contract class of the given class hash or compiled class hash.
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError>;
    /// Returns the class hash of the contract class at the given address.
    /// Returns zero by default if the value is not present
    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError>;
    /// Returns the nonce of the given contract instance.
    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError>;
    /// Returns the storage value under the given key in the given contract instance.
    /// Returns zero by default if the value is not present
    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError>;
    /// Return the class hash of the given casm contract class
    fn get_compiled_class_hash(
        &self,
        class_hash: &ClassHash,
    ) -> Result<CompiledClassHash, StateError>;
    /// Returns the storage value representing the balance (in fee token) at the given address as a (low, high) pair
    fn get_fee_token_balance(
        &mut self,
        block_context: &BlockContext,
        contract_address: &Address,
    ) -> Result<(Felt252, Felt252), StateError> {
        let (low_key, high_key) = get_erc20_balance_var_addresses(contract_address)?;
        let low = self.get_storage_at(&(
            block_context
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            low_key,
        ))?;
        let high = self.get_storage_at(&(
            block_context
                .starknet_os_config()
                .fee_token_address()
                .clone(),
            high_key,
        ))?;

        Ok((low, high))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StateChangesCount {
    pub n_storage_updates: usize,
    pub n_class_hash_updates: usize,
    pub n_compiled_class_hash_updates: usize,
    pub n_modified_contracts: usize,
}

pub trait State {
    fn set_contract_class(
        &mut self,
        class_hash: &ClassHash,
        contract_class: &CompiledClass,
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

    fn set_compiled_class_hash(
        &mut self,
        class_hash: &Felt252,
        compiled_class_hash: &Felt252,
    ) -> Result<(), StateError>;

    fn set_sierra_program(
        &mut self,
        compiled_class_hash: &Felt252,
        sierra_program: Arc<(SierraProgram, ContractEntryPoints)>,
    );

    fn apply_state_update(&mut self, sate_updates: &StateDiff) -> Result<(), StateError>;

    /// Counts the amount of state changes
    fn count_actual_state_changes(
        &mut self,
        fee_token_and_sender_address: Option<(&Address, &Address)>,
    ) -> Result<StateChangesCount, StateError>;

    /// Returns the class hash of the contract class at the given address.
    /// Returns zero by default if the value is not present
    fn get_class_hash_at(&mut self, contract_address: &Address) -> Result<ClassHash, StateError>;

    /// Default: 0 for an uninitialized contract address.
    fn get_nonce_at(&mut self, contract_address: &Address) -> Result<Felt252, StateError>;

    /// Returns storage data for a given storage entry.
    /// Returns zero as default value if missing
    fn get_storage_at(&mut self, storage_entry: &StorageEntry) -> Result<Felt252, StateError>;

    fn get_compiled_class_hash(&mut self, class_hash: &ClassHash) -> Result<ClassHash, StateError>;

    fn get_contract_class(&mut self, class_hash: &ClassHash) -> Result<CompiledClass, StateError>;

    fn get_sierra_program(
        &mut self,
        class_hash: &ClassHash,
    ) -> Option<Arc<(SierraProgram, ContractEntryPoints)>>;
}
