use cairo_rs::vm::runners::cairo_runner::ExecutionResources;
use felt::Felt;
use num_traits::Zero;
use std::{borrow::Borrow, collections::HashMap, hash, ops::Deref, rc::Rc, thread::current};

use crate::{
    business_logic::state::{
        cached_state::CachedState,
        state_api::{State, StateReader},
        state_api_objects::BlockInfo,
    },
    core::errors::state_errors::StateError,
    definitions::general_config::{self, StarknetGeneralConfig},
    starknet_storage::storage::{FactFetchingContext, Storage},
    utils::{to_state_diff_storage_mapping, Address},
};

use super::contract_state::ContractState;

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

pub(crate) struct SharedState {
    contract_states: HashMap<Felt, ContractState>,
    block_info: BlockInfo,
}

impl SharedState {
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
