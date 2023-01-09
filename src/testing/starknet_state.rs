use crate::{
    business_logic::{
        execution::objects::Event,
        state::{cached_state::CachedState, state_api::StateReader},
    },
    core::syscalls::syscall_request::EmitEventStruct,
    definitions::general_config::{self, StarknetGeneralConfig},
    services::messages::StarknetMessageToL1,
    starknet_storage::{dict_storage::DictStorage, storage::FactFetchingContext},
};
use num_bigint::BigInt;
use std::{clone, collections::HashMap, hash::Hash};

#[derive(Clone)]
pub(crate) struct StarknetState<T: StateReader + Clone> {
    state: CachedState<T>,
    general_config: StarknetGeneralConfig,
    l2_to_l1_messages: HashMap<String, BigInt>,
    l2_to_l1_messages_log: Vec<StarknetMessageToL1>,
    events: Vec<Event>,
}

impl<T: StateReader + Clone> StarknetState<T> {
    pub fn new(state: CachedState<T>, general_config: StarknetGeneralConfig) -> Self {
        let l2_to_l1_messages = HashMap::new();
        let l2_to_l1_messages_log = Vec::new();
        let events = Vec::new();
        StarknetState {
            state,
            general_config,
            l2_to_l1_messages,
            l2_to_l1_messages_log,
            events,
        }
    }

    pub fn empty(general_config: Option<StarknetGeneralConfig>) -> Self {
        let config = general_config.unwrap_or(StarknetGeneralConfig::default());
        let ffc = FactFetchingContext::new(DictStorage::new(), None);
        todo!()
    }
}
