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
use num_traits::Zero;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Default)]
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

// TODO: this functions should be in cairo-rs

// Returns a copy of the execution resources where all the builtins with a usage counter
// of 0 are omitted.

pub fn filter_unused_builtins(resources: ExecutionResources) -> ExecutionResources {
    ExecutionResources {
        n_steps: resources.n_steps,
        n_memory_holes: resources.n_memory_holes,
        builtin_instance_counter: resources
            .builtin_instance_counter
            .into_iter()
            .filter(|builtin| !builtin.1.is_zero())
            .collect(),
    }
}

pub fn calculate_additional_resources(
    current_resources: ExecutionResources,
    additional_resources: ExecutionResources,
) -> ExecutionResources {
    let mut builtin_instance_counter = current_resources.builtin_instance_counter.clone();

    let n_steps = current_resources.n_steps + additional_resources.n_steps;
    let n_memory_holes = current_resources.n_memory_holes + additional_resources.n_memory_holes;

    for (k, v) in additional_resources.builtin_instance_counter {
        if builtin_instance_counter.contains_key(&k) {
            let val = builtin_instance_counter.get(&k).unwrap_or(&0).to_owned();
            builtin_instance_counter.insert(k, val + v);
        } else {
            builtin_instance_counter.remove(&k);
        }
    }

    ExecutionResources {
        n_steps,
        n_memory_holes,
        builtin_instance_counter,
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
    _parent_state: Option<Rc<RefCell<CarriedState<T>>>>,
    _state: CachedState<T>,
}

impl<T: StateReader + Clone> CarriedState<T> {
    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn create_from_parent_state(parent_state: CarriedState<T>) -> Self {
        let cached_state = parent_state._state.clone();
        let new_state = Some(Rc::new(RefCell::new(parent_state)));
        CarriedState {
            _parent_state: new_state,
            _state: cached_state,
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn create_child_state_for_querying(&self) -> Result<Self, StateError> {
        match &self._parent_state {
            Some(parent_state) => Ok(CarriedState::create_from_parent_state(
                parent_state.as_ref().borrow().clone(),
            )),
            None => Err(StateError::ParentCarriedStateIsNone),
        }
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    fn apply(&mut self) -> Result<(), StateError> {
        match &self._parent_state {
            Some(parent_state) => {
                self._state.apply(&mut parent_state.borrow_mut()._state);
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
        let state_cache = current_carried_state._state.cache;
        Ok(self.apply_updates(
            ffc,
            state_cache.class_hash_writes,
            state_cache.nonce_writes,
            to_state_diff_storage_mapping(state_cache.storage_writes)?,
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
    _address_to_class_hash: HashMap<Address, [u8; 32]>,
    _address_to_nonce: HashMap<Address, Felt>,
    _storage_updates: HashMap<Felt, HashMap<[u8; 32], Address>>,
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

        let storage_updates = to_state_diff_storage_mapping(substracted_maps)?;

        let address_to_nonce =
            subtract_mappings(state_cache.nonce_writes, state_cache.nonce_initial_values);

        let address_to_class_hash = subtract_mappings(
            state_cache.class_hash_writes,
            state_cache.class_hash_initial_values,
        );

        Ok(StateDiff {
            _address_to_class_hash: address_to_class_hash,
            _address_to_nonce: address_to_nonce,
            _storage_updates: storage_updates,
        })
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn to_cached_state<T>(&self, state_reader: T) -> Result<CachedState<T>, StateError>
    where
        T: StateReader + Clone,
    {
        let mut cache_state = CachedState::new(state_reader, None);
        let cache_storage_mapping = to_cache_state_storage_mapping(self._storage_updates.clone());

        cache_state.cache.set_initial_values(
            &self._address_to_class_hash,
            &self._address_to_nonce,
            &cache_storage_mapping,
        )?;
        Ok(cache_state)
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn squash(&mut self, other: StateDiff) -> Result<Self, StarkwareError> {
        self._address_to_class_hash
            .extend(other._address_to_class_hash);
        let address_to_class_hash = self._address_to_class_hash.clone();

        self._address_to_nonce.extend(other._address_to_nonce);
        let address_to_nonce = self._address_to_nonce.clone();

        let mut storage_updates = HashMap::new();

        let addresses: Vec<Felt> = get_keys(
            self._storage_updates.clone(),
            other._storage_updates.clone(),
        );

        for address in addresses {
            let default: HashMap<[u8; 32], Address> = HashMap::new();
            let mut map_a = self
                ._storage_updates
                .get(&address)
                .unwrap_or(&default)
                .to_owned();
            let map_b = other
                ._storage_updates
                .get(&address)
                .unwrap_or(&default)
                .to_owned();
            map_a.extend(map_b);
            storage_updates.insert(address, map_a.clone());
        }

        Ok(StateDiff {
            _address_to_class_hash: address_to_class_hash,
            _address_to_nonce: address_to_nonce,
            _storage_updates: storage_updates,
        })
    }

    // TODO: Remove warning inhibitor when finally used.
    #[allow(dead_code)]
    pub fn commit<T: Storage>(
        &self,
        ffc: FactFetchingContext<T>,
        previos_state: SharedState,
    ) -> SharedState {
        previos_state.apply_updates(
            ffc,
            self._address_to_class_hash.clone(),
            self._address_to_nonce.clone(),
            self._storage_updates.clone(),
        )
    }
}
