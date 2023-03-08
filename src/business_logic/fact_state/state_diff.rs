use felt::Felt;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::utils::subtract_mappings;
use crate::{
    business_logic::state::{
        cached_state::CachedState, state_api::StateReader, state_cache::StorageEntry,
    },
    core::errors::state_errors::StateError,
    starkware_utils::starkware_errors::StarkwareError,
    utils::Address,
};

#[derive(Default)]
pub struct StateDiff {
    pub(crate) address_to_class_hash: HashMap<Address, [u8; 32]>,
    pub(crate) address_to_nonce: HashMap<Address, Felt>,
    pub(crate) storage_updates: HashMap<Address, HashMap<[u8; 32], Felt>>,
}

impl StateDiff {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn from_cached_state<T>(cached_state: CachedState<T>) -> Result<Self, StateError>
    where
        T: StateReader + Clone,
    {
        let state_cache = cached_state.cache;

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

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn to_cached_state<T>(&self, state_reader: T) -> Result<CachedState<T>, StateError>
    where
        T: StateReader + Clone,
    {
        let mut cache_state = CachedState::new(state_reader, None);
        let cache_storage_mapping = to_cache_state_storage_mapping(self.storage_updates.clone());

        cache_state.cache.set_initial_values(
            &self.address_to_class_hash,
            &self.address_to_nonce,
            &cache_storage_mapping,
        )?;
        Ok(cache_state)
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn squash(&mut self, other: StateDiff) -> Result<Self, StarkwareError> {
        self.address_to_class_hash
            .extend(other.address_to_class_hash);
        let address_to_class_hash = self.address_to_class_hash.clone();

        self.address_to_nonce.extend(other.address_to_nonce);
        let address_to_nonce = self.address_to_nonce.clone();

        let mut storage_updates = HashMap::new();

        let addresses: Vec<Address> =
            get_keys(self.storage_updates.clone(), other.storage_updates.clone());

        for address in addresses {
            let default: HashMap<[u8; 32], Felt> = HashMap::new();
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

/// Converts CachedState storage mapping to StateDiff storage mapping.
pub fn to_state_diff_storage_mapping(
    storage_writes: HashMap<StorageEntry, Felt>,
) -> HashMap<Address, HashMap<[u8; 32], Felt>> {
    let mut storage_updates: HashMap<Address, HashMap<[u8; 32], Felt>> = HashMap::new();
    for ((address, key), value) in storage_writes {
        let mut map = storage_updates.get(&address).cloned().unwrap_or_default();
        map.insert(key, value);
        storage_updates.insert(address, map);
    }
    storage_updates
}

/// Converts StateDiff storage mapping (addresses map to a key-value mapping) to CachedState
/// storage mapping (Tuple of address and key map to the associated value).
pub fn to_cache_state_storage_mapping(
    map: HashMap<Address, HashMap<[u8; 32], Felt>>,
) -> HashMap<StorageEntry, Felt> {
    let mut storage_writes = HashMap::new();
    for (address, contract_storage) in map {
        for (key, value) in contract_storage {
            storage_writes.insert((address.clone(), key), value);
        }
    }
    storage_writes
}

/// Get a vector of keys from two hashmaps
pub fn get_keys<K, V>(map_a: HashMap<K, V>, map_b: HashMap<K, V>) -> Vec<K>
where
    K: Hash + Eq,
{
    let mut keys1: HashSet<K> = map_a.into_keys().collect();
    let keys2: HashSet<K> = map_b.into_keys().collect();

    keys1.extend(keys2);

    keys1.into_iter().collect()
}

#[cfg(test)]
mod test {
    use super::{to_cache_state_storage_mapping, to_state_diff_storage_mapping, StateDiff};
    use crate::{
        business_logic::{
            fact_state::{
                contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            },
            state::cached_state::CachedState,
        },
        utils::Address,
    };
    use felt::Felt;
    use std::collections::HashMap;

    #[test]
    fn test_from_cached_state_without_updates() {
        let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());

        let contract_address = Address(32123.into());
        let contract_state = ContractState::new([8; 32], Felt::new(109), HashMap::new());

        state_reader
            .contract_states
            .insert(contract_address, contract_state);

        let cached_state = CachedState::new(state_reader, None);

        let diff = StateDiff::from_cached_state(cached_state).unwrap();

        assert_eq!(0, diff.storage_updates.len());
    }

    #[test]
    fn to_state_diff_storage_mapping_test() {
        let mut storage: HashMap<(Address, [u8; 32]), Felt> = HashMap::new();
        let address1: Address = Address(1.into());
        let key1 = [0; 32];
        let value1: Felt = 2.into();

        let address2: Address = Address(3.into());
        let key2 = [1; 32];

        let value2: Felt = 4.into();

        storage.insert((address1.clone(), key1), value1.clone());
        storage.insert((address2.clone(), key2), value2.clone());

        let map = to_state_diff_storage_mapping(storage);

        assert_eq!(*map.get(&address1).unwrap().get(&key1).unwrap(), value1);
        assert_eq!(*map.get(&address2).unwrap().get(&key2).unwrap(), value2);
    }

    #[test]
    fn to_cache_state_storage_mapping_test() {
        let mut storage: HashMap<(Address, [u8; 32]), Felt> = HashMap::new();
        let address1: Address = Address(1.into());
        let key1 = [0; 32];
        let value1: Felt = 2.into();

        let address2: Address = Address(3.into());
        let key2 = [1; 32];

        let value2: Felt = 4.into();

        storage.insert((address1.clone(), key1), value1.clone());
        storage.insert((address2.clone(), key2), value2.clone());

        let state_dff = to_state_diff_storage_mapping(storage);
        let cache_storage = to_cache_state_storage_mapping(state_dff);

        let mut expected_res = HashMap::new();

        expected_res.insert((Address(address1.0), key1), value1);
        expected_res.insert((Address(address2.0), key2), value2);

        assert_eq!(cache_storage, expected_res)
    }
}
