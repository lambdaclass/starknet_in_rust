use crate::{
    business_logic::execution::objects::Event,
    core::syscalls::syscall_request::EmitEventStruct,
    definitions::general_config::{self, StarknetGeneralConfig},
    services::messages::StarknetMessageToL1,
    starknet_storage::{dict_storage::DictStorage, storage::FactFetchingContext},
    state::{cached_state::CachedState, state_api::StateReader},
};
use num_bigint::BigInt;
use std::{collections::HashMap, hash::Hash};
pub(crate) struct StarknetState<T: StateReader> {
    state: CachedState<T>,
    general_config: StarknetGeneralConfig,
    l2_to_l1_messages: HashMap<String, BigInt>,
    l2_to_l1_messages_log: Vec<StarknetMessageToL1>,
    events: Vec<Event>,
}

impl<T: StateReader> StarknetState<T> {
    pub fn new(general_config: Option<StarknetGeneralConfig>) {
        let config = general_config.unwrap_or(StarknetGeneralConfig::default());
        let ffc = FactFetchingContext::new(DictStorage::new(), None);
    }
}
