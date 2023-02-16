use crate::{
    business_logic::{
        execution::objects::{CallInfo, TransactionExecutionInfo},
        state::{
            cached_state::{CachedState, ContractClassCache},
            state_api::{State, StateReader},
        },
    },
    definitions::general_config::StarknetGeneralConfig,
};
use std::collections::HashMap;

pub type FeeInfo = (Option<CallInfo>, u64);

pub(crate) trait InternalStateTransaction {
    fn get_state_selector_of_many(
        _txs: Vec<impl InternalStateTransaction>,
        _general_config: StarknetGeneralConfig,
    ) {
        todo!()
    }

    fn apply_state_updates(
        &self,
        _state: impl State,
        _general_config: StarknetGeneralConfig,
    ) -> Option<TransactionExecutionInfo> {
        todo!()
    }

    fn sync_apply_state_updates<T>(
        &self,
        state: T,
        contract_classes: Option<ContractClassCache>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State + StateReader + Clone,
    {
        let concurrent_execution_info =
            self.apply_concurrent_changes(state.clone(), contract_classes, general_config.clone());

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

    fn apply_concurrent_changes<T>(
        &self,
        state: T,
        contract_classes: Option<ContractClassCache>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State + StateReader + Clone,
    {
        self._apply_specific_concurrent_changes(
            CachedState::new(state, contract_classes),
            general_config,
        )
    }

    fn apply_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo {
        self._apply_specific_sequential_changes(state, general_config, actual_resources)
    }

    // ------------------
    //  Abstract methods
    // ------------------

    fn _apply_specific_concurrent_changes<T>(
        &self,
        state: CachedState<T>,
        general_config: StarknetGeneralConfig,
    ) -> TransactionExecutionInfo
    where
        T: State + StateReader + Clone;

    fn _apply_specific_sequential_changes(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        actual_resources: HashMap<String, usize>,
    ) -> FeeInfo;
}
