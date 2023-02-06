use std::thread::panicking;

use felt::Felt;
use num_traits::{Num, Zero};

use crate::{
    business_logic::{
        execution::objects::{CallInfo, TransactionExecutionInfo},
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{
            cached_state::CachedState, state_api::StateReader,
            update_tracker_state::UpdatesTrackerState,
        },
        transaction::transaction_errors::TransactionError,
    },
    core::errors::syscall_handler_errors::SyscallHandlerError,
    definitions::{
        constants::{EXECUTE_ENTRY_POINT_SELECTOR, QUERY_VERSION_BASE, TRANSACTION_VERSION},
        transaction_type::TransactionType,
    },
    services::api::contract_class::EntryPointType,
    utils::Address,
};

pub(crate) struct InternalInvokeFunction {
    contract_address: Address,
    entry_point_selector: Felt,
    entry_point_type: EntryPointType,
    calldata: Vec<Felt>,
    tx_type: TransactionType,
    version: u64,
}

impl InternalInvokeFunction {
    fn validate_entrypoint_calldata(&self) -> &Vec<Felt> {
        &self.calldata
    }

    fn verify_version(&self) -> Result<(), TransactionError> {
        verify_version(self.version, false, Vec::new())?;

        if ((self.version != 0) || (self.version != QUERY_VERSION_BASE))
            && (self.entry_point_selector != *EXECUTE_ENTRY_POINT_SELECTOR)
        {
            return Err(TransactionError::UnauthorizedEntryPointForInvoke(
                self.entry_point_selector.clone(),
            ));
        }

        Ok(())
    }

    fn run_validate_entrypoint(&self) -> Option<CallInfo> {
        if self.entry_point_selector != *EXECUTE_ENTRY_POINT_SELECTOR {
            return None;
        }

        if self.version == 0 {
            return None;
        }

        // let call = ExecutionEntryPo
        /*
                call = ExecuteEntryPoint.create(
            contract_address=self.account_contract_address,
            entry_point_selector=self.validate_entry_point_selector,
            entry_point_type=EntryPointType.EXTERNAL,
            calldata=self.validate_entrypoint_calldata,
            caller_address=0,
        )

        call_info = call.execute(
            state=state,
            resources_manager=resources_manager,
            general_config=general_config,
            tx_execution_context=self.get_execution_context(
                n_steps=general_config.validate_max_n_steps
            ),
        )
        verify_no_calls_to_other_contracts(call_info=call_info, function_name="'validate'")

        return call_info

        */
        todo!()
    }
    /*
        def run_validate_entrypoint(
        self,
        state: SyncState,
        resources_manager: ExecutionResourcesManager,
        general_config: StarknetGeneralConfig,
    ) -> Optional[CallInfo]:
        """
        Runs the '__validate__' entry point.
        """
        if self.entry_point_selector != starknet_abi.EXECUTE_ENTRY_POINT_SELECTOR:
            return None

        return super().run_validate_entrypoint(
            state=state, resources_manager=resources_manager, general_config=general_config
        )
    */

    fn _apply_specific_concurrent_changes<T: StateReader + Clone>(
        &self,
        state: UpdatesTrackerState<CachedState<T>>,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        self.verify_version();
        let resources_manager = ExecutionResourcesManager::default();

        todo!()
    }
}

/*
    def _apply_specific_concurrent_changes(
        self, state: UpdatesTrackerState, general_config: StarknetGeneralConfig
    ) -> TransactionExecutionInfo:
        """
        Applies self to 'state' by executing the entry point and charging fee for it (if needed).
        """
        # Reject unsupported versions. This is necessary (in addition to the gateway's check)
        # since an old transaction might still reach here, e.g., in case of a re-org.
        self.verify_version()

        # Validate transaction.
        resources_manager = ExecutionResourcesManager.empty()
        validate_info = self.run_validate_entrypoint(
            state=state,
            resources_manager=resources_manager,
            general_config=general_config,
        )

        # Execute transaction.
        call_info = self.run_execute_entrypoint(
            state=state,
            resources_manager=resources_manager,
            general_config=general_config,
        )

        # Handle fee.
        actual_resources = calculate_tx_resources(
            state=state,
            resources_manager=resources_manager,
            call_infos=[call_info, validate_info],
            tx_type=self.tx_type,
        )

        return TransactionExecutionInfo.create_concurrent_stage_execution_info(
            validate_info=validate_info,
            call_info=call_info,
            actual_resources=actual_resources,
            tx_type=self.tx_type,
        )

*/
pub(crate) fn verify_version(
    version: u64,
    only_query: bool,
    old_supported_versions: Vec<u64>,
) -> Result<(), TransactionError> {
    if TRANSACTION_VERSION != 1 {
        return Err(TransactionError::InvalidTransactionVersion(version));
    }
    let mut allowed_versions = old_supported_versions;
    allowed_versions.push(version);

    if only_query {
        for v in allowed_versions.clone() {
            allowed_versions.push(QUERY_VERSION_BASE + v)
        }
    }

    if !(allowed_versions.contains(&version)) {
        return Err(TransactionError::InvalidTransactionVersion(version));
    }

    Ok(())
}
