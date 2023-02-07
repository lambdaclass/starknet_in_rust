use felt::Felt;
use std::collections::HashMap;

use crate::{
    business_logic::{
        execution::objects::{CallInfo, TransactionExecutionInfo},
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
            update_tracker_state::UpdatesTrackerState,
        },
    },
    definitions::general_config::{self, StarknetGeneralConfig},
};

pub type FeeInfo = (Option<CallInfo>, u64);

pub(crate) trait InternalStateTransaction {
    // ------------------------------------------------------------
    // ------------------------------------------------------------

    fn get_state_selector_of_many(
        txs: Vec<impl InternalStateTransaction>,
        general_config: StarknetGeneralConfig,
    ) {
        todo!()
    }

    // ------------------------------------------------------------
    // ------------------------------------------------------------

    fn apply_state_updates(
        &self,
        state: CachedState<InMemoryStateReader>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        self.sync_apply_state_updates(state, general_config)
    }

    // ------------------------------------------------------------
    // ------------------------------------------------------------

    fn sync_apply_state_updates<T>(
        &self,
        state: T,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State + StateReader + Clone,
    {
        let concurrent_execution_info =
            self.apply_concurrent_changes(state.clone(), general_config.clone());

        let (fee_transfer_info, actual_fee) = self.apply_sequential_changes(
            state,
            general_config,
            concurrent_execution_info.actual_resources.clone(),
        );

        TransactionExecutionInfo::from_concurrent_state_execution_info(
            concurrent_execution_info,
            actual_fee,
            fee_transfer_info,
        )
    }

    // ------------------------------------------------------------
    // ------------------------------------------------------------

    fn apply_concurrent_changes<T>(
        &self,
        state: T,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State + StateReader,
    {
        self.apply_specific_concurrent_changes(UpdatesTrackerState::new(state), general_config)
    }

    // ------------------------------------------------------------
    // ------------------------------------------------------------

    fn apply_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo {
        self.apply_specific_sequential_changes(state, general_config, actual_resources)
    }

    // ------------------------------------------------------------
    // ------------------------------------------------------------

    // ------------------
    //  Abstract methods
    // ------------------

    fn apply_specific_concurrent_changes<T>(
        &self,
        state: UpdatesTrackerState<T>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State;

    // ------------------------------------------------------------
    // ------------------------------------------------------------

    fn apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo;
}
