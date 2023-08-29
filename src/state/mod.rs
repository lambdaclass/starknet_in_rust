pub mod cached_state;
pub(crate) mod contract_storage_state;
pub mod in_memory_state_reader;
pub mod state_api;
pub mod state_cache;

use crate::{
    core::errors::state_errors::StateError,
    services::api::contract_classes::compiled_class::CompiledClass,
    utils::{
        get_keys, subtract_mappings, to_cache_state_storage_mapping, to_state_diff_storage_mapping,
    },
};
use cairo_vm::{felt::Felt252, vm::runners::cairo_runner::ExecutionResources};
use getset::Getters;
use std::{collections::HashMap, sync::Arc};

use crate::{
    transaction::error::TransactionError,
    utils::{Address, ClassHash},
};

use self::{cached_state::CachedState, state_api::StateReader};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    /// The sequence number of the last block created.
    pub block_number: u64,
    /// Timestamp of the beginning of the last block creation attempt.
    pub block_timestamp: u64,
    /// L1 gas price (in Wei) measured at the beginning of the last block creation attempt.
    pub gas_price: u64,
    /// The sequencer address of this block.
    pub sequencer_address: Address,
}

impl BlockInfo {
    pub fn empty(sequencer_address: Address) -> Self {
        BlockInfo {
            block_number: 0, // To do: In cairo-lang, this value is set to -1
            block_timestamp: 0,
            gas_price: 0,
            sequencer_address,
        }
    }

    pub fn validate_legal_progress(
        &self,
        next_block_info: &BlockInfo,
    ) -> Result<(), TransactionError> {
        if self.block_number + 1 != next_block_info.block_number {
            return Err(TransactionError::InvalidBlockNumber);
        }

        if self.block_timestamp >= next_block_info.block_timestamp {
            return Err(TransactionError::InvalidBlockTimestamp);
        }

        Ok(())
    }
}

impl Default for BlockInfo {
    fn default() -> Self {
        Self {
            block_number: 0,
            block_timestamp: 0,
            gas_price: 0,
            sequencer_address: Address(0.into()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExecutionResourcesManager {
    pub(crate) syscall_counter: HashMap<String, u64>,
    pub(crate) cairo_usage: ExecutionResources,
}

impl ExecutionResourcesManager {
    pub fn new(syscalls: Vec<String>, cairo_usage: ExecutionResources) -> Self {
        let mut syscall_counter = HashMap::new();
        for syscall in syscalls {
            syscall_counter.insert(syscall, 0);
        }
        ExecutionResourcesManager {
            syscall_counter,
            cairo_usage,
        }
    }

    pub fn increment_syscall_counter(&mut self, syscall_name: &str, amount: u64) -> Option<()> {
        self.syscall_counter
            .get_mut(syscall_name)
            .map(|val| *val += amount)
    }

    pub fn get_syscall_counter(&self, syscall_name: &str) -> Option<u64> {
        self.syscall_counter
            .get(syscall_name)
            .map(ToOwned::to_owned)
    }
}

#[derive(Default, Clone, PartialEq, Debug, Getters)]
#[getset(get = "pub")]
pub struct StateDiff {
    pub(crate) address_to_class_hash: HashMap<Address, ClassHash>,
    pub(crate) address_to_nonce: HashMap<Address, Felt252>,
    pub(crate) class_hash_to_compiled_class: HashMap<ClassHash, CompiledClass>,
    pub(crate) storage_updates: HashMap<Address, HashMap<Felt252, Felt252>>,
}

impl StateDiff {
    pub fn new(
        address_to_class_hash: HashMap<Address, ClassHash>,
        address_to_nonce: HashMap<Address, Felt252>,
        class_hash_to_compiled_class: HashMap<ClassHash, CompiledClass>,
        storage_updates: HashMap<Address, HashMap<Felt252, Felt252>>,
    ) -> Self {
        StateDiff {
            address_to_class_hash,
            address_to_nonce,
            class_hash_to_compiled_class,
            storage_updates,
        }
    }

    pub fn from_cached_state<T>(cached_state: CachedState<T>) -> Result<Self, StateError>
    where
        T: StateReader,
    {
        let state_cache = cached_state.cache().to_owned();

        let substracted_maps = subtract_mappings(
            state_cache.storage_writes.clone(),
            state_cache.storage_initial_values.clone(),
        );

        let storage_updates = to_state_diff_storage_mapping(substracted_maps);

        let address_to_nonce = subtract_mappings(
            state_cache.nonce_writes.clone(),
            state_cache.nonce_initial_values.clone(),
        );

        let class_hash_to_compiled_class = subtract_mappings(
            state_cache.compiled_class_hash_writes.clone(),
            state_cache.compiled_class_hash_initial_values.clone(),
        );

        let address_to_class_hash = subtract_mappings(
            state_cache.class_hash_writes.clone(),
            state_cache.class_hash_initial_values,
        );

        Ok(StateDiff {
            address_to_class_hash,
            address_to_nonce,
            class_hash_to_compiled_class,
            storage_updates,
        })
    }

    pub fn to_cached_state<T>(&self, state_reader: Arc<T>) -> Result<CachedState<T>, StateError>
    where
        T: StateReader + Clone,
    {
        let mut cache_state = CachedState::new(state_reader);
        let cache_storage_mapping = to_cache_state_storage_mapping(&self.storage_updates);

        cache_state.cache_mut().set_initial_values(
            &self.address_to_class_hash,
            &self.class_hash_to_compiled_class,
            &self.address_to_nonce,
            &cache_storage_mapping,
        )?;
        Ok(cache_state)
    }

    pub fn squash(&mut self, other: StateDiff) -> Self {
        self.address_to_class_hash
            .extend(other.address_to_class_hash);
        let address_to_class_hash = self.address_to_class_hash.clone();

        self.address_to_nonce.extend(other.address_to_nonce);
        let address_to_nonce = self.address_to_nonce.clone();

        self.class_hash_to_compiled_class
            .extend(other.class_hash_to_compiled_class);
        let class_hash_to_compiled_class = self.class_hash_to_compiled_class.clone();

        let mut storage_updates = HashMap::new();

        let addresses: Vec<Address> =
            get_keys(self.storage_updates.clone(), other.storage_updates.clone());

        for address in addresses {
            let default: HashMap<Felt252, Felt252> = HashMap::new();
            let mut map_a = self
                .storage_updates
                .get(&address)
                .unwrap_or(&default)
                .to_owned();
            let map_b = other
                .storage_updates
                .get(&address)
                .unwrap_or(&default)
                .to_owned();
            map_a.extend(map_b);
            storage_updates.insert(address, map_a.clone());
        }

        StateDiff {
            address_to_class_hash,
            address_to_nonce,
            class_hash_to_compiled_class,
            storage_updates,
        }
    }
}

#[test]
fn test_validate_legal_progress() {
    let first_block = BlockInfo::default();
    let next_block: BlockInfo = BlockInfo {
        block_number: 1,
        block_timestamp: 1,
        ..Default::default()
    };

    assert!(first_block.validate_legal_progress(&next_block).is_ok())
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, sync::Arc};

    use super::StateDiff;
    use crate::{
        state::in_memory_state_reader::InMemoryStateReader,
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::StateReader,
            state_cache::{StateCache, StorageEntry},
        },
        utils::Address,
    };
    use cairo_vm::felt::Felt252;

    #[test]
    fn test_from_cached_state_without_updates() {
        let mut state_reader = InMemoryStateReader::default();

        let contract_address = Address(32123.into());
        let class_hash = [9; 32];
        let nonce = Felt252::new(42);

        state_reader
            .address_to_class_hash
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let cached_state = CachedState::new(Arc::new(state_reader));

        let diff = StateDiff::from_cached_state(cached_state).unwrap();

        assert_eq!(0, diff.storage_updates.len());
    }

    #[test]
    fn execution_resources_manager_should_start_with_zero_syscall_counter() {
        let execution_resources_manager = super::ExecutionResourcesManager::new(
            vec!["syscall1".to_string(), "syscall2".to_string()],
            Default::default(),
        );

        assert_eq!(
            execution_resources_manager.get_syscall_counter("syscall1"),
            Some(0)
        );
        assert_eq!(
            execution_resources_manager.get_syscall_counter("syscall2"),
            Some(0)
        );
    }

    #[test]
    fn execution_resources_manager_should_increment_one_to_the_syscall_counter() {
        let mut execution_resources_manager = super::ExecutionResourcesManager::new(
            vec!["syscall1".to_string(), "syscall2".to_string()],
            Default::default(),
        );

        execution_resources_manager
            .increment_syscall_counter("syscall1", 1)
            .unwrap();

        assert_eq!(
            execution_resources_manager.get_syscall_counter("syscall1"),
            Some(1)
        );
        assert_eq!(
            execution_resources_manager.get_syscall_counter("syscall2"),
            Some(0)
        );
    }

    #[test]
    fn state_diff_to_cached_state_should_return_correct_cached_state() {
        let mut state_reader = InMemoryStateReader::default();

        let contract_address = Address(32123.into());
        let class_hash = [9; 32];
        let nonce = Felt252::new(42);

        state_reader
            .address_to_class_hash
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address.clone(), nonce);

        let cached_state_original = CachedState::new(Arc::new(state_reader.clone()));

        let diff = StateDiff::from_cached_state(cached_state_original.clone()).unwrap();

        let cached_state = diff.to_cached_state(Arc::new(state_reader)).unwrap();

        assert_eq!(
            cached_state_original.contract_classes(),
            cached_state.contract_classes()
        );
        assert_eq!(
            cached_state_original
                .get_nonce_at(&contract_address)
                .unwrap(),
            cached_state.get_nonce_at(&contract_address).unwrap()
        );
    }

    #[test]
    fn state_diff_squash_with_itself_should_return_same_diff() {
        let mut state_reader = InMemoryStateReader::default();

        let contract_address = Address(32123.into());
        let class_hash = [9; 32];
        let nonce = Felt252::new(42);

        state_reader
            .address_to_class_hash
            .insert(contract_address.clone(), class_hash);
        state_reader
            .address_to_nonce
            .insert(contract_address, nonce);

        let entry: StorageEntry = (Address(555.into()), [0; 32]);
        let mut storage_writes = HashMap::new();
        storage_writes.insert(entry, Felt252::new(666));
        let cache = StateCache::new(
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            storage_writes,
            HashMap::new(),
        );
        let cached_state = CachedState::new_for_testing(Arc::new(state_reader), cache)
            .set_contract_classes_cache(ContractClassCache::new());

        let mut diff = StateDiff::from_cached_state(cached_state).unwrap();

        let diff_squashed = diff.squash(diff.clone());

        assert_eq!(diff, diff_squashed);
    }
}
