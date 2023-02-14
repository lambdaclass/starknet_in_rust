use super::contract_state::ContractState;
use crate::{
    business_logic::state::{
        cached_state::CachedState, state_api::StateReader, state_api_objects::BlockInfo,
    },
    core::errors::state_errors::StateError,
    definitions::general_config::StarknetGeneralConfig,
    starknet_storage::storage::{FactFetchingContext, Storage},
    starkware_utils::starkware_errors::StarkwareError,
    utils::{
        get_keys, subtract_mappings, to_cache_state_storage_mapping, to_state_diff_storage_mapping,
        Address,
    },
};
use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Default, Clone)]
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

// ----------------------
//      SHARED STATE
// ----------------------

#[derive(Debug, Clone)]
pub(crate) struct CarriedState<T>
where
    T: StateReader + Clone,
{
    parent_state: Option<Rc<RefCell<CarriedState<T>>>>,
    state: CachedState<T>,
}

impl<T: StateReader + Clone> CarriedState<T> {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn create_from_parent_state(parent_state: CarriedState<T>) -> Self {
        let cached_state = parent_state.state.clone();
        let new_state = Some(Rc::new(RefCell::new(parent_state)));
        CarriedState {
            parent_state: new_state,
            state: cached_state,
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn create_child_state_for_querying(&self) -> Result<Self, StateError> {
        match &self.parent_state {
            Some(parent_state) => Ok(CarriedState::create_from_parent_state(
                parent_state.as_ref().borrow().clone(),
            )),
            None => Err(StateError::ParentCarriedStateIsNone),
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn apply(&mut self) -> Result<(), StateError> {
        match &self.parent_state {
            Some(parent_state) => {
                self.state.apply(&mut parent_state.borrow_mut().state);
                Ok(())
            }
            None => Err(StateError::ParentCarriedStateIsNone),
        }
    }
}

// ----------------------
//      SHARED STATE
// ----------------------

// TODO: Remove warning inhibitor when finally used.
#[allow(dead_code)]
pub(crate) struct SharedState {
    contract_states: HashMap<Felt, ContractState>,
    block_info: BlockInfo,
}

impl SharedState {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn empty<S>(_ffc: FactFetchingContext<S>, _general_config: StarknetGeneralConfig) -> Self
    where
        S: Storage,
    {
        todo!()
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn to_carried_state<S, R>(&self, _ffc: FactFetchingContext<S>) -> CarriedState<R>
    where
        S: Storage,
        R: StateReader + Clone,
    {
        // let state_reader = "Patricia_state_reader"; // TODO: change it to patricia reader once it is available
        // let state = CachedState::new(self.block_info, state_reader, None);

        // CarriedState {
        //     parent_state: None,
        //     state,
        // }
        todo!()
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn apply_state_updates<S, R>(
        &self,
        ffc: FactFetchingContext<S>,
        _previous_carried_state: CarriedState<R>,
        current_carried_state: CarriedState<R>,
    ) -> Result<Self, StateError>
    where
        S: Storage,
        R: StateReader + Clone,
    {
        let state_cache = current_carried_state.state.cache;
        Ok(self.apply_updates(
            ffc,
            state_cache.class_hash_writes,
            state_cache.nonce_writes,
            to_state_diff_storage_mapping(state_cache.storage_writes),
        ))
    }

    pub fn apply_updates<S>(
        &self,
        _ffc: FactFetchingContext<S>,
        address_to_class_hash: HashMap<Address, [u8; 32]>,
        address_to_nonce: HashMap<Address, Felt>,
        storage_updates: HashMap<Felt, HashMap<[u8; 32], Address>>,
    ) -> Self
    where
        S: Storage,
    {
        let class_addresses: HashSet<Address> = address_to_class_hash.into_keys().collect();
        let nonce_addresses: HashSet<Address> = address_to_nonce.into_keys().collect();
        let storage_addresses: HashSet<Address> =
            storage_updates.into_keys().map(Address).collect();
        let mut accesed_addresses: HashSet<Address> = HashSet::new();
        accesed_addresses.extend(class_addresses);
        accesed_addresses.extend(nonce_addresses);
        accesed_addresses.extend(storage_addresses);

        // TODO:
        // let current_contract_states = self.contract_states.get_leaves(ffc, accesed_addresses)

        todo!()
    }
}

#[derive(Default)]
pub(crate) struct StateDiff {
    pub(crate) address_to_class_hash: HashMap<Address, [u8; 32]>,
    pub(crate) address_to_nonce: HashMap<Address, Felt>,
    pub(crate) storage_updates: HashMap<Felt, HashMap<[u8; 32], Address>>,
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

        let addresses: Vec<Felt> =
            get_keys(self.storage_updates.clone(), other.storage_updates.clone());

        for address in addresses {
            let default: HashMap<[u8; 32], Address> = HashMap::new();
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

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn commit<T: Storage>(
        &self,
        ffc: FactFetchingContext<T>,
        previous_state: SharedState,
    ) -> SharedState {
        previous_state.apply_updates(
            ffc,
            self.address_to_class_hash.clone(),
            self.address_to_nonce.clone(),
            self.storage_updates.clone(),
        )
    }
}

#[cfg(test)]
mod test {
    use super::StateDiff;
    use crate::{
        business_logic::{
            fact_state::{
                contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            },
            state::cached_state::CachedState,
        },
        starknet_storage::{dict_storage::DictStorage, storage::Storage},
        utils::Address,
    };
    use felt::Felt;
    use std::collections::HashMap;

    #[test]
    fn test_from_cached_state_without_updates() {
        let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());

        let contract_address = Address(32123.into());
        let contract_state = ContractState::new([8; 32], Felt::new(109), HashMap::new());

        state_reader
            .ffc
            .set_contract_state(&contract_address.to_32_bytes().unwrap(), &contract_state)
            .unwrap();

        let cached_state = CachedState::new(state_reader, None);

        let diff = StateDiff::from_cached_state(cached_state).unwrap();

        assert_eq!(0, diff.storage_updates.len());
    }
}
