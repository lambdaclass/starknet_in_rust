use std::thread::panicking;

use felt::Felt;
use num_traits::{Num, Zero};

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            execution_errors::ExecutionError,
            objects::{CallInfo, TransactionExecutionContext, TransactionExecutionInfo},
        },
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
        general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    services::api::contract_class::EntryPointType,
    utils::{calculate_tx_resources, Address},
};

pub(crate) struct InternalInvokeFunction {
    contract_address: Address,
    entry_point_selector: Felt,
    entry_point_type: EntryPointType,
    calldata: Vec<Felt>,
    tx_type: TransactionType,
    version: u64,
    validate_entry_point_selector: Felt,
    hash_value: Felt,
    signature: Vec<Felt>,
    max_fee: u64,
    nonce: Felt,
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

    fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.contract_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version,
        )
    }

    fn run_validate_entrypoint(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
    ) -> Result<Option<CallInfo>, ExecutionError> {
        if self.entry_point_selector != *EXECUTE_ENTRY_POINT_SELECTOR {
            return Ok(None);
        }

        if self.version == 0 {
            return Ok(None);
        }

        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.calldata.clone(),
            self.validate_entry_point_selector.clone(),
            Address(0.into()),
            EntryPointType::External,
            None,
            None,
        );

        let call_info = call.execute(
            state,
            general_config,
            resources_manager,
            &self.get_execution_context(general_config.validate_max_n_steps),
        )?;

        verify_no_calls_to_other_contracts(&call_info)?;

        Ok(Some(call_info))
    }

    ///     Builds the transaction execution context and executes the entry point.
    ///     Returns the CallInfo.
    fn run_execute_entrypoint(
        &self,
        state: &mut CachedState<InMemoryStateReader>,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
    ) -> Result<CallInfo, ExecutionError> {
        let call = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            self.calldata.clone(),
            self.entry_point_selector.clone(),
            Address(0.into()),
            EntryPointType::External,
            None,
            None,
        );

        call.execute(
            state,
            general_config,
            resources_manager,
            &self.get_execution_context(general_config.invoke_tx_max_n_steps),
        )
    }

    fn _apply_specific_concurrent_changes(
        &self,
        // Check this
        // state: UpdatesTrackerState<CachedState<InMemoryStateReader>>,
        state: &mut CachedState<InMemoryStateReader>,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, ExecutionError> {
        self.verify_version()?;
        let mut resources_manager = ExecutionResourcesManager::default();
        let validate_info =
            self.run_validate_entrypoint(state, &mut resources_manager, general_config)?;

        // Execute transaction
        let call_info =
            self.run_execute_entrypoint(state, general_config, &mut resources_manager)?;
        let updates_tracker_state = UpdatesTrackerState::new(state.clone());
        let actual_resources = calculate_tx_resources(
            resources_manager,
            &vec![Some(call_info.clone()), validate_info.clone()],
            self.tx_type.clone(),
            updates_tracker_state,
            None,
        )?;
        let transaction_execution_info =
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                validate_info,
                Some(call_info),
                actual_resources,
                Some(self.tx_type.clone()),
            );
        Ok(transaction_execution_info)
    }
}

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

fn verify_no_calls_to_other_contracts(call_info: &CallInfo) -> Result<(), TransactionError> {
    let invoked_contract_address = call_info.contract_address.clone();
    for internal_call in call_info.gen_call_topology() {
        if internal_call.contract_address != invoked_contract_address {
            return Err(TransactionError::UnauthorizedActionOnValidate);
        }
    }
    Ok(())
}
