use std::collections::VecDeque;

use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        self,
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};
use felt::Felt;
use num_traits::{ToPrimitive, Zero};

use super::{
    execution_errors::ExecutionError,
    objects::{CallInfo, CallType, TransactionExecutionContext},
};
use crate::{
    business_logic::{
        fact_state::in_memory_state_reader::InMemoryStateReader,
        state::{cached_state::CachedState, state_api_objects::BlockInfo},
    },
    services::api::contract_class::{ContractClass, ContractEntryPoint},
    utils::get_integer_range,
};
use crate::{
    business_logic::{
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
    },
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        syscall_handler::{self, SyscallHandler, SyscallHintProcessor},
    },
    definitions::{
        constants::TRANSACTION_VERSION,
        general_config::{self, StarknetGeneralConfig},
    },
    services::api::contract_class::EntryPointType,
    starknet_runner::runner::StarknetRunner,
    utils::{get_deployed_address_class_hash_at_address, validate_contract_deployed, Address},
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
    entry_point_selector: Felt,
    entry_point_type: EntryPointType,
}

impl ExecutionEntryPoint {
    pub fn new(
        contract_address: Address,
        calldata: Vec<Felt>,
        entry_point_selector: Felt,
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

    /// Executes the selected entry point with the given calldata in the specified contract.
    /// The information collected from this run (number of steps required, modifications to the
    /// contract storage, etc.) is saved on the resources manager.
    /// Returns a CallInfo object that represents the execution.
    pub fn execute(
        &self,
        state: CachedState<InMemoryStateReader>,
        general_config: StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: TransactionExecutionContext,
    ) -> Result<CallInfo, ExecutionError> {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();

        let runner = self.run(
            state,
            resources_manager.clone(),
            general_config,
            tx_execution_context,
        )?;

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage =
            resources_manager.cairo_usage.clone() + runner.get_execution_resources()?;

        let retdata = runner.get_return_values()?;
        // let retdata = get_integer_range(&runner.vm, &ret_data_ptr, ret_data_size)?;

        self.build_call_info(
            previous_cairo_usage,
            runner.hint_processor.syscall_handler,
            retdata,
        )
    }

    /// Runs the selected entry point with the given calldata in the code of the contract deployed
    /// at self.code_address.
    /// The execution is done in the context (e.g., storage) of the contract at
    /// self.contract_address.
    /// Returns the corresponding CairoFunctionRunner and BusinessLogicSysCallHandler in order to
    /// retrieve the execution information.
    fn run(
        &self,
        mut state: CachedState<InMemoryStateReader>,
        resources_manager: ExecutionResourcesManager,
        general_config: StarknetGeneralConfig,
        tx_execution_context: TransactionExecutionContext,
    ) -> Result<StarknetRunner, ExecutionError> {
        // Prepare input for Starknet runner.
        let class_hash = self.get_code_class_hash(state.clone())?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| ExecutionError::MissigContractClass)?;

        // fetch selected entry point
        let entry_point = self.get_selected_entry_point(contract_class.clone(), class_hash)?;
        // create starknet runner

        let mut cairo_runner = CairoRunner::new(&contract_class.program, "all", false)?;

        let mut vm = VirtualMachine::new(false);

        cairo_runner.initialize_function_runner(&mut vm);

        let hint_processor = SyscallHintProcessor::new_empty();
        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        // prepare OS context
        let os_context = runner.prepare_os_context();

        println!("os: {os_context:?}");

        validate_contract_deployed(state.clone(), self.contract_address.clone())?;

        // fetch syscall_ptr
        let initial_syscall_ptr: Relocatable = match os_context.get(0) {
            Some(MaybeRelocatable::RelocatableValue(ptr)) => ptr.to_owned(),
            _ => return Err(ExecutionError::NotARelocatableValue),
        };

        let syscall_handler = BusinessLogicSyscallHandler::new(
            BlockInfo::default(),
            tx_execution_context,
            state,
            resources_manager,
            self.caller_address.clone(),
            self.contract_address.clone(),
            general_config,
            initial_syscall_ptr,
        );

        runner.hint_processor = SyscallHintProcessor::new(syscall_handler);

        // Positional arguments are passed to *args in the 'run_from_entrypoint' function.
        let data = self.calldata.clone().iter().map(|d| d.into()).collect();
        let alloc_pointer = runner
            .hint_processor
            .syscall_handler
            .allocate_segment(&mut runner.vm, data)?
            .into();

        let entry_point_args = [
            &CairoArg::Single(self.entry_point_selector.clone().into()),
            &CairoArg::Array(os_context.clone()),
            &CairoArg::Single(MaybeRelocatable::Int(self.calldata.len().into())),
            &CairoArg::Single(alloc_pointer),
        ];

        let entrypoint = entry_point.offset.to_usize().ok_or_else(|| {
            ExecutionError::ErrorInDataConversion("felt".to_string(), "usize".to_string())
        })?;

        // cairo runner entry point
        runner.run_from_entrypoint(entrypoint, &entry_point_args)?;

        runner.validate_and_process_os_context(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let args_ptr = runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(ExecutionError::InvalidInitialFp)?
            .sub_usize(entry_point_args.len() + 2)?;

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr, entry_point_args.len())?;

        Ok(runner)
    }

    /// Returns the entry point with selector corresponding with self.entry_point_selector.
    fn get_selected_entry_point(
        &self,
        contract_class: ContractClass,
        class_hash: [u8; 32],
    ) -> Result<ContractEntryPoint, ExecutionError> {
        let entry_points = contract_class
            .entry_points_by_type
            .get(&self.entry_point_type)
            .unwrap()
            .clone();
        let filtered_entry_points = entry_points
            .clone()
            .into_iter()
            .filter(|ep| ep.selector == self.entry_point_selector)
            .collect::<Vec<ContractEntryPoint>>();

        if filtered_entry_points.is_empty() && !entry_points.is_empty() {
            let first_entry_point = entry_points.get(0).unwrap().clone();

            return Ok(first_entry_point);
        }

        if filtered_entry_points.len() != 1 {
            return Err(ExecutionError::NonUniqueEntryPoint);
        }
        Ok(filtered_entry_points.get(0).unwrap().to_owned())
    }

    fn build_call_info<S: StateReader + Clone>(
        &self,
        previous_cairo_usage: ExecutionResources,
        syscall_handler: BusinessLogicSyscallHandler<CachedState<S>>,
        retdata: Vec<Felt>,
    ) -> Result<CallInfo, ExecutionError> {
        let execution_resources =
            syscall_handler.resources_manager.cairo_usage - previous_cairo_usage;

        Ok(CallInfo {
            caller_address: self.caller_address.clone(),
            call_type: Some(self.call_type.clone()),
            contract_address: self.contract_address.clone(),
            code_address: self.code_address.clone(),
            class_hash: Some(self.get_code_class_hash(syscall_handler.state)?),
            entry_point_selector: Some(self.entry_point_selector.clone()),
            entry_point_type: Some(self.entry_point_type),
            calldata: self.calldata.clone(),
            retdata,
            execution_resources: execution_resources.filter_unused_builtins(),
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
            storage_read_values: syscall_handler.starknet_storage_state.read_values,
            accesed_storage_keys: syscall_handler.starknet_storage_state.accessed_keys,
            internal_calls: syscall_handler.internal_calls,
        })
    }

    /// Returns the hash of the executed contract class.
    fn get_code_class_hash<S: StateReader>(&self, state: S) -> Result<[u8; 32], ExecutionError> {
        if self.class_hash.is_some() {
            match self.call_type {
                CallType::Delegate => return Ok(self.class_hash.unwrap()),
                _ => return Err(ExecutionError::CallTypeIsNotDelegate),
            }
        }
        let code_address = match self.call_type {
            CallType::Call => Some(self.contract_address.clone()),
            CallType::Delegate => {
                if self.code_address.is_some() {
                    self.code_address.clone()
                } else {
                    return Err(ExecutionError::AttempToUseNoneCodeAddress);
                }
            }
        };

        get_deployed_address_class_hash_at_address(state, code_address.unwrap())
    }
}
