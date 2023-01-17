use felt::Felt;
use std::collections::HashMap;

use crate::{
    business_logic::{
        execution::objects::{CallInfo, TransactionExecutionInfo},
        state::{state_api::State, update_tracker_state::UpdatesTrackerState},
    },
    definitions::general_config::{self, StarknetGeneralConfig},
};

type FeeInfo = (Option<CallInfo>, u64);

pub(crate) trait InternalStateTransaction {
    fn apply_state_updates(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
    ) -> Option<TransactionExecutionInfo> {
        todo!()
    }

    fn sync_apply_state_updates<T>(
        &self,
        state: T,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State + Clone,
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

    fn apply_concurrent_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        todo!()
    }

    fn apply_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, Felt>,
    ) -> FeeInfo {
        todo!()
    }

    // ------------------
    //  Abstract methods
    // ------------------

    fn _apply_specific_concurrent_changes<T>(
        &self,
        state: UpdatesTrackerState<T>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State;

    fn _apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, Felt>,
    ) -> FeeInfo;
}
