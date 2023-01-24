use std::collections::VecDeque;

use cairo_rs::{
    types::relocatable::MaybeRelocatable,
    vm::{
        self,
        runners::cairo_runner::{CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};
use felt::Felt;
use num_traits::Zero;

use super::{
    execution_errors::ExecutionError,
    objects::{CallInfo, CallType, TransactionExecutionContext},
};
use crate::{
    business_logic::{
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
    },
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler, syscall_handler,
    },
    definitions::{
        constants::TRANSACTION_VERSION,
        general_config::{self, StarknetGeneralConfig},
    },
    services::api::contract_class::EntryPointType,
    starknet_runner::runner::StarknetRunner,
    utils::{get_deployed_address_class_hash_at_address, Address},
};

/// Represents a Cairo entry point execution of a StarkNet contract.
#[derive(Debug)]
pub(crate) struct ExecutionEntryPoint {
    call_type: CallType,
    contract_address: Address,
    code_address: Option<Address>,
    class_hash: Option<[u8; 32]>,
    calldata: VecDeque<Felt>,
    caller_address: Address,
    entry_point_selector: Option<usize>,
    entry_point_type: Option<EntryPointType>,
}

impl ExecutionEntryPoint {
    pub fn new(
        contract_address: Address,
        calldata: VecDeque<Felt>,
        entry_point_selector: Option<usize>,
        caller_address: Address,
        entry_point_type: Option<EntryPointType>,
        call_type: Option<CallType>,
        class_hash: Option<[u8; 32]>,
    ) -> Self {
        ExecutionEntryPoint {
            call_type: call_type.unwrap_or(CallType::Call),
            contract_address,
            code_address: None,
            class_hash,
            calldata,
            caller_address,
            entry_point_selector,
            entry_point_type,
        }
    }

    pub fn execute_for_testing(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        resources_manager: &mut Option<ExecutionResourcesManager>,
        tx_execution_context: Option<TransactionExecutionContext>,
    ) -> Result<CallInfo, ExecutionError> {
        let tx_context =
            tx_execution_context.unwrap_or(TransactionExecutionContext::create_for_testing(
                Address(0.into()),
                0,
                Felt::zero(),
                general_config.invoke_tx_max_n_steps,
                TRANSACTION_VERSION,
            ));

        let mut rsc_manager = resources_manager
            .clone()
            .unwrap_or(ExecutionResourcesManager::default());

        self.execute(state, general_config, &mut rsc_manager, tx_context)
    }

    /// Executes the selected entry point with the given calldata in the specified contract.
    /// The information collected from this run (number of steps required, modifications to the
    /// contract storage, etc.) is saved on the resources manager.
    /// Returns a CallInfo object that represents the execution.
    pub fn execute(
        &self,
        state: impl State,
        general_config: StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: TransactionExecutionContext,
    ) -> Result<CallInfo, ExecutionError> {
        // let previous_cairo_usage = resources_manager.cairo_usage;

        let (runner, syscall_handler) = self.run(
            state,
            resources_manager,
            general_config,
            tx_execution_context,
        );

        // TODO: add sum trait to executionResources
        let resources_manager = runner.get_execution_resources();

        let retdata = runner.get_return_values();
        // self.build_call_info(previous_cairo_usage, syscall_handler, retdata);
        todo!()
    }

    /// Runs the selected entry point with the given calldata in the code of the contract deployed
    /// at self.code_address.
    /// The execution is done in the context (e.g., storage) of the contract at
    /// self.contract_address.
    /// Returns the corresponding CairoFunctionRunner and BusinessLogicSysCallHandler in order to
    /// retrieve the execution information.
    fn run(
        &self,
        state: impl State,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: StarknetGeneralConfig,
        tx_execution_context: TransactionExecutionContext,
    ) -> (StarknetRunner, BusinessLogicSyscallHandler) {
        // Prepare input for Cairo runner.
        //  let cairo_runner = CairoRunner::new(program, "all", false);
        todo!()
    }

    fn build_call_info(
        &self,
        previous_cairo_usage: ExecutionResources,
        syscall_handler: BusinessLogicSyscallHandler,
        retdata: VecDeque<MaybeRelocatable>,
    ) -> CallInfo {
        let execution_resources =
            syscall_handler.resources_manager.cairo_usage - previous_cairo_usage;
        CallInfo {
            caller_address: self.caller_address,
            call_type: Some(self.call_type),
            contract_address: self.contract_address,
            code_address: self.code_address,
            class_hash: self.get_code_class_hash(syscall_handler.state).unwrap(),
            entry_point_selector: self.entry_point_selector,
            entry_point_type: self.entry_point_type,
            calldata: self.calldata,
            retdata,
            execution_resources: execution_resources.filter_unused_builtins(),
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
            storage_read_values: syscall_handler.starknet_storage.read_values,
            accesed_storage_keys: syscall_handler.starknet_storage.accesed_keys,
            internal_calls: syscall_handler.internal_calls,
        }
    }

    /// Returns the hash of the executed contract class.
    fn get_code_class_hash<S: State + StateReader>(
        &self,
        state: S,
    ) -> Result<Option<[u8; 32]>, ExecutionError> {
        if self.class_hash.is_some() {
            match self.call_type {
                CallType::Delegate => return Ok(self.class_hash),
                _ => return Err(ExecutionError::CallTypeIsNotDelegate),
            }
        }
        let Some(code_address) = match self.call_type {
            CallType::Call => Some(self.contract_address),
            CallType::Delegate => {
                if self.code_address.is_some() {
                    self.code_address
                } else {
                    return Err(ExecutionError::AttempToUseNoneCodeAddress);
                }
            }
        };

        get_deployed_address_class_hash_at_address(state, code_address)
    }
}
