use felt::Felt;
use patricia_tree::PatriciaTree;
use std::{borrow::Borrow, collections::HashMap, hash, ops::Deref, rc::Rc, thread::current};

use crate::{
    business_logic::state::{
        cached_state::CachedState,
        state_api::{State, StateReader},
        state_api_objects::BlockInfo,
        state_cache,
    },
    core::errors::state_errors::StateError,
    definitions::general_config::{self, StarknetGeneralConfig},
    starknet_storage::storage::{self, FactFetchingContext, Storage},
    utils::{
        get_keys, merge, subtract_mappings, to_cache_state_storage_mapping,
        to_state_diff_storage_mapping, Address,
    },
};

#[derive(Debug, Default)]
pub struct ExecutionResourcesManager(HashMap<String, u64>);

impl ExecutionResourcesManager {
    pub fn new(syscalls: Vec<String>) -> Self {
        let mut manager = HashMap::new();
        for syscall in syscalls {
            manager.insert(syscall, 0);
        }
        ExecutionResourcesManager(manager)
    }

    pub fn increment_syscall_counter(&mut self, syscall_name: &str, amount: u64) -> Option<()> {
        self.0.get_mut(syscall_name).map(|val| *val += amount)
    }

    pub fn get_syscall_counter(&self, syscall_name: &str) -> Option<u64> {
        self.0.get(syscall_name).map(ToOwned::to_owned)
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~
// ----------------------
//      SHARED STATE
// ----------------------
// ~~~~~~~~~~~~~~~~~~~~~~
#[derive(Debug, Clone)]
pub(crate) struct CarriedState<T>
where
    T: StateReader + Clone,
{
    parent_state: Option<Rc<CarriedState<T>>>,
    state: CachedState<T>,
}

impl<T: StateReader + Clone> CarriedState<T> {
    pub fn create_from_parent_state(parent_state: CarriedState<T>) -> Self {
        let cached_state = parent_state.state.clone();
        let new_state = Some(Rc::new(parent_state));
        CarriedState {
            parent_state: new_state,
            state: cached_state,
        }
    }

    pub fn create_child_state_for_querying(&self) -> Result<Self, StateError> {
        match &self.parent_state {
            Some(parent_state) => Ok(CarriedState::create_from_parent_state(
                parent_state.deref().clone(),
            )),
            None => Err(StateError::ParentCarriedStateIsNone),
        }
    }

    fn apply(&mut self) -> Result<(), StateError> {
        match &self.parent_state {
            Some(parent_state) => {
                self.state.apply(parent_state.state.clone());
                Ok(())
            }
            None => Err(StateError::ParentCarriedStateIsNone),
        }
    }

    pub fn get_block_info(&self) -> &BlockInfo {
        &self.state.block_info
    }
}

// ----------------------
//      SHARED STATE
// ----------------------

pub(crate) struct SharedState<T> {
    contract_states: PatriciaTree<T>,
    block_info: BlockInfo,
}

impl<T> SharedState<T> {
    pub fn empty<S>(ffc: FactFetchingContext<S>, general_config: StarknetGeneralConfig) -> Self
    where
        S: Storage,
    {
        todo!()
    }

    pub fn to_carried_state<S, R>(&self, ffc: FactFetchingContext<S>) -> CarriedState<R>
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

    pub fn apply_state_updates<S, R>(
        &self,
        ffc: FactFetchingContext<S>,
        previous_carried_state: CarriedState<R>,
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
            to_state_diff_storage_mapping(state_cache.storage_writes)?,
            current_carried_state.state.block_info,
        ))
    }

    pub fn apply_updates<S>(
        &self,
        ffc: FactFetchingContext<S>,
        address_to_class_hash: HashMap<Address, Vec<u8>>,
        address_to_nonce: HashMap<Address, Felt>,
        storage_updates: HashMap<Felt, HashMap<[u8; 32], Address>>,
        block_info: BlockInfo,
    ) -> Self
    where
        S: Storage,
    {
        todo!()
    }
}

pub(crate) struct StateDiff {
    address_to_class_hash: HashMap<Address, Vec<u8>>,
    address_to_nonce: HashMap<Address, Felt>,
    storage_updates: HashMap<Felt, HashMap<[u8; 32], Address>>,
    block_info: BlockInfo,
}

impl StateDiff {
    pub fn empty(block_info: BlockInfo) -> Self {
        StateDiff {
            address_to_class_hash: HashMap::new(),
            address_to_nonce: HashMap::new(),
            storage_updates: HashMap::new(),
            block_info,
        }
    }

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

        let block_info = cached_state.block_info;

        Ok(StateDiff {
            address_to_class_hash,
            address_to_nonce,
            storage_updates,
            block_info,
        })
    }

    pub fn to_cached_state<T>(&self, state_reader: T) -> CachedState<T>
    where
        T: StateReader + Clone,
    {
        let mut cache_state = CachedState::new(self.block_info.clone(), state_reader, None);
        let cache_storage_mapping = to_cache_state_storage_mapping(self.storage_updates.clone());

        cache_state.cache.set_initial_values(
            &self.address_to_class_hash,
            &self.address_to_nonce,
            &cache_storage_mapping,
        );
        cache_state
    }

    pub fn squash(&self, other: StateDiff) -> Self {
        let address_to_class_hash = merge(
            self.address_to_class_hash.clone(),
            other.address_to_class_hash,
        );

        let address_to_nonce = merge(self.address_to_nonce.clone(), other.address_to_nonce);
        let storage_updates = HashMap::new();

        let addresses: Vec<Felt> = get_keys(self.storage_updates.clone(), other.storage_updates);

        for address in addresses {
            let updates = merge(
                self.storage_updates.get((&address)),
                other.storage_updates.get(&address),
            );
            storage_updates.insert(address, updates);
        }
        self.block_info.validate_legal_progress(other.block_info);

        StateDiff {
            address_to_class_hash,
            address_to_nonce,
            storage_updates,
            block_info: other.block_info,
        }
    }
}
