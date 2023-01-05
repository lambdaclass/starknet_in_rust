use num_bigint::BigInt;
use patricia_tree::PatriciaTree;
use std::{borrow::Borrow, collections::HashMap, hash, ops::Deref, rc::Rc, thread::current};

use crate::{
    business_logic::state::{
        state_api::{State, StateReader},
        state_api_objects::BlockInfo,
        state_cache::CachedState,
    },
    core::errors::state_errors::StateError,
    definitions::general_config::{self, StarknetGeneralConfig},
    starknet_storage::storage::{FactFetchingContext, Storage},
    utils::to_state_diff_storage_mapping,
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

    pub fn block_info(&self) -> &BlockInfo {
        &self.state.block_info
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~
// ----------------------
//      SHARED STATE
// ----------------------
// ~~~~~~~~~~~~~~~~~~~~~~

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
        address_to_class_hash: HashMap<BigInt, Vec<u8>>,
        address_to_nonce: HashMap<BigInt, BigInt>,
        storage_updates: HashMap<BigInt, HashMap<[u8; 32], BigInt>>,
        block_info: BlockInfo,
    ) -> Self
    where
        S: Storage,
    {
        todo!()
    }
}
