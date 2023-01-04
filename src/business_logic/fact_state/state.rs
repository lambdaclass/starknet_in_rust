use num_bigint::BigInt;
use patricia_tree::PatriciaTree;
use std::{collections::HashMap, hash, thread::current};

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

pub(crate) struct CarriedState<T>
where
    T: StateReader,
{
    parent_state: Option<u64>,
    state: CachedState<T>,
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
        R: StateReader,
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
        R: StateReader,
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
