use cairo_rs::vm::{
    self,
    runners::cairo_runner::{CairoRunner, ExecutionResources},
    vm_core::VirtualMachine,
};
use felt::Felt;
use num_traits::Zero;

use super::{
    execution_errors::ExecutionError,
    objects::{CallInfo, CallType, TransactionExecutionContext},
};
use crate::{
    business_logic::{fact_state::state::ExecutionResourcesManager, state::state_api::State},
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler, syscall_handler,
    },
    definitions::{
        constants::TRANSACTION_VERSION,
        general_config::{self, StarknetGeneralConfig},
    },
    services::api::contract_class::EntryPointType,
    utils::Address,
};

/// Represents a Cairo entry point execution of a StarkNet contract.
#[derive(Debug)]
pub(crate) struct ExecutionEntryPoint {
    call_type: CallType,
    contract_address: Address,
    code_address: Option<Address>,
    class_hash: Option<[u8; 32]>,
    calldata: Vec<Felt>,
    caller_address: Address,
    entry_point_selector: usize,
    entry_point_type: EntryPointType,
}

impl ExecutionEntryPoint {
    pub fn new(
        contract_address: Address,
        calldata: Vec<Felt>,
        entry_point_selector: usize,
        caller_address: Address,
        entry_point_type: EntryPointType,
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
        //let previous_cairo_usage = resources_manager.cairo_usage;

        let (runner, syscall_handler) = self.run(
            state,
            resources_manager,
            general_config,
            tx_execution_context,
        );

        let vm = VirtualMachine::new(false);

        // TODO: add sum trait to executionResources
        let resources_manager = runner
            .get_execution_resources(&vm)
            .map_err(|_| ExecutionError::TraceError)?;

        let retadata = get_return_values(runner);
        self.build_call_info(previous_cairo_usage, syscall_handler, retdata);
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
    ) -> (CairoRunner, BusinessLogicSyscallHandler) {
        todo!()
    }

    fn build_call_info(
        &self,
        previous_cairo_usage: ExecutionResources,
        syscall_handler: BusinessLogicSyscallHandler,
        redata: Vec<Felt>,
    ) -> CallInfo {
        todo!()
    }
}
