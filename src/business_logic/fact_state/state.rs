use crate::{
    business_logic::state::{cached_state::CachedState, state_api::StateReader},
    core::errors::state_errors::StateError,
    starkware_utils::starkware_errors::StarkwareError,
    utils::{
        get_keys, subtract_mappings, to_cache_state_storage_mapping, to_state_diff_storage_mapping,
        Address, ClassHash,
    },
};
use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt252;
use std::collections::HashMap;

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

#[derive(Default, Clone, PartialEq, Debug)]
pub struct StateDiff {
    pub(crate) address_to_class_hash: HashMap<Address, ClassHash>,
    pub(crate) address_to_nonce: HashMap<Address, Felt252>,
    pub(crate) storage_updates: HashMap<Felt252, HashMap<ClassHash, Address>>,
}

impl StateDiff {
    pub fn from_cached_state<T>(cached_state: CachedState<T>) -> Result<Self, StateError>
    where
        T: StateReader + Clone,
    {
        let state_cache = cached_state.cache().to_owned();

        let substracted_maps = subtract_mappings(
            state_cache.storage_writes,
            state_cache.storage_initial_values,
        );

        let storage_updates = to_state_diff_storage_mapping(substracted_maps);

        let address_to_nonce =
            subtract_mappings(state_cache.nonce_writes, state_cache.nonce_initial_values);

        let address_to_class_hash = subtract_mappings(
            state_cache.class_hash_writes,
            state_cache.class_hash_initial_values,
        );

        Ok(StateDiff {
            address_to_class_hash,
            address_to_nonce,
            storage_updates,
        })
    }

    pub fn to_cached_state<T>(&self, state_reader: T) -> Result<CachedState<T>, StateError>
    where
        T: StateReader + Clone,
    {
        let mut cache_state = CachedState::new(state_reader, None, None);
        let cache_storage_mapping = to_cache_state_storage_mapping(self.storage_updates.clone());

        cache_state.cache_mut().set_initial_values(
            &self.address_to_class_hash,
            &self.address_to_nonce,
            &cache_storage_mapping,
        )?;
        Ok(cache_state)
    }

    pub fn squash(&mut self, other: StateDiff) -> Result<Self, StarkwareError> {
        self.address_to_class_hash
            .extend(other.address_to_class_hash);
        let address_to_class_hash = self.address_to_class_hash.clone();

        self.address_to_nonce.extend(other.address_to_nonce);
        let address_to_nonce = self.address_to_nonce.clone();

        let mut storage_updates = HashMap::new();

        let addresses: Vec<Felt252> =
            get_keys(self.storage_updates.clone(), other.storage_updates.clone());

        for address in addresses {
            let default: HashMap<ClassHash, Address> = HashMap::new();
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

        Ok(StateDiff {
            address_to_class_hash,
            address_to_nonce,
            storage_updates,
        })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::StateDiff;
    use crate::{
        business_logic::{
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::{
                cached_state::{CachedState, ContractClassCache},
                state_api::StateReader,
                state_cache::{StateCache, StorageEntry},
            },
        },
        utils::Address,
    };
    use felt::Felt252;

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

        let cached_state = CachedState::new(state_reader, None, None);

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

        let mut cached_state_original = CachedState::new(state_reader.clone(), None, None);

        let diff = StateDiff::from_cached_state(cached_state_original.clone()).unwrap();

        let mut cached_state = diff.to_cached_state(state_reader).unwrap();

        assert_eq!(
            cached_state_original.get_contract_classes(),
            cached_state.get_contract_classes()
        );
        assert_eq!(
            cached_state_original.get_nonce_at(&contract_address),
            cached_state.get_nonce_at(&contract_address)
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
            storage_writes,
            HashMap::new(),
        );
        let cached_state = CachedState::new_for_testing(
            state_reader,
            Some(ContractClassCache::new()),
            cache,
            None,
        );

        let mut diff = StateDiff::from_cached_state(cached_state).unwrap();

        let diff_squashed = diff.squash(diff.clone()).unwrap();

        assert_eq!(diff, diff_squashed);
    }
}
