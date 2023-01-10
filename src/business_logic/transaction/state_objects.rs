use felt::Felt;
use std::collections::HashMap;

use crate::{
    business_logic::state::{
        state_api::{State, SyncState},
        update_tracker_state::UpdatesTrackerState,
    },
    core::syscalls::os_syscall_handler::{CallInfo, TransactionExecutionInfo},
    definitions::general_config::{self, StarknetGeneralConfig},
};

type FeeInfo = (Option<CallInfo>, Felt);

pub(crate) trait InternalStateTransaction {
    fn apply_state_updates(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
    ) -> Option<TransactionExecutionInfo> {
        todo!()
    }

    fn sync_apply_state_updates(
        &self,
        state: impl SyncState,
        general_config: StarknetGeneralConfig,
    ) -> Option<TransactionExecutionInfo> {
        todo!()
    }

    fn apply_concurrent_changes(
        &self,
        state: impl SyncState,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo {
        todo!()
    }

    fn apply_sequential_changes(
        &self,
        state: impl SyncState,
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
        T: SyncState;

    fn _apply_specific_sequential_changes(
        &self,
        state: impl SyncState,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, Felt>,
    ) -> FeeInfo;
}
