use super::objects::{
    CallInfo, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
};
use crate::{
    business_logic::{
        fact_state::state::ExecutionResourcesManager,
        state::state_api::State,
        state::{contract_storage_state::ContractStorageState, state_api::StateReader},
        transaction::error::TransactionError,
    },
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
        deprecated_syscall_handler::{DeprecatedSyscallHandler, DeprecatedSyscallHintProcessor},
        syscall_handler::{SyscallHandler, SyscallHintProcessor},
    },
    definitions::{constants::DEFAULT_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig},
    services::api::contract_classes::{
        compiled_class::CompiledClass,
        deprecated_contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
    },
    starknet_runner::runner::StarknetRunner,
    utils::{get_deployed_address_class_hash_at_address, validate_contract_deployed, Address},
};
use cairo_lang_casm::hints::Hint;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::{
    felt::Felt252,
    serde::deserialize_program::{
        ApTracking, BuiltinName, FlowTrackingData, HintParams, ReferenceManager,
    },
    types::{
        errors::program_errors::ProgramError,
        program::Program,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};
use std::collections::HashMap;

/// Represents a Cairo entry point execution of a StarkNet contract.

// TODO:initial_gas is a new field added in the current changes, it should be checked if we delete it once the new execution entry point is done
#[derive(Debug, Clone)]
pub struct ExecutionEntryPoint {
    pub(crate) call_type: CallType,
    pub(crate) contract_address: Address,
    pub(crate) code_address: Option<Address>,
    pub(crate) class_hash: Option<[u8; 32]>,
    pub(crate) calldata: Vec<Felt252>,
    pub(crate) caller_address: Address,
    pub(crate) entry_point_selector: Felt252,
    pub(crate) entry_point_type: EntryPointType,
    #[allow(unused)]
    pub(crate) initial_gas: u64,
}
#[allow(clippy::too_many_arguments)]
impl ExecutionEntryPoint {
    pub fn new(
        contract_address: Address,
        calldata: Vec<Felt252>,
        entry_point_selector: Felt252,
        caller_address: Address,
        entry_point_type: EntryPointType,
        call_type: Option<CallType>,
        class_hash: Option<[u8; 32]>,
        initial_gas: u64,
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
            initial_gas,
        }
    }

    /// Executes the selected entry point with the given calldata in the specified contract.
    /// The information collected from this run (number of steps required, modifications to the
    /// contract storage, etc.) is saved on the resources manager.
    /// Returns a CallInfo object that represents the execution.
    pub fn execute<T>(
        &self,
        state: &mut T,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: &TransactionExecutionContext,
        support_reverted: bool,
    ) -> Result<CallInfo, TransactionError>
    where
        T: Default + State + StateReader,
    {
        let class_hash = self.get_code_class_hash(state)?;
        let contract_class = state
            .get_compiled_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;

        match contract_class {
            CompiledClass::Deprecated(contract_class) => self._execute_version0_class(
                state,
                resources_manager,
                general_config,
                tx_execution_context,
                contract_class,
                class_hash,
            ),
            CompiledClass::Casm(contract_class) => self._execute(
                state,
                resources_manager,
                general_config,
                tx_execution_context,
                contract_class,
                class_hash,
                support_reverted,
            ),
        }
    }

    /// Returns the entry point with selector corresponding with self.entry_point_selector, or the
    /// default if there is one and the requested one is not found.
    fn get_selected_entry_point_v0(
        &self,
        contract_class: &ContractClass,
        _class_hash: [u8; 32],
    ) -> Result<ContractEntryPoint, TransactionError> {
        let entry_points = contract_class
            .entry_points_by_type
            .get(&self.entry_point_type)
            .ok_or(TransactionError::InvalidEntryPoints)?;

        let mut default_entry_point = None;
        let entry_point = entry_points
            .iter()
            .filter_map(|x| {
                if x.selector == *DEFAULT_ENTRY_POINT_SELECTOR {
                    default_entry_point = Some(x);
                }

                (x.selector == self.entry_point_selector).then_some(x)
            })
            .fold(Ok(None), |acc, x| match acc {
                Ok(None) => Ok(Some(x)),
                _ => Err(TransactionError::NonUniqueEntryPoint),
            })?;

        entry_point
            .or(default_entry_point)
            .cloned()
            .ok_or(TransactionError::EntryPointNotFound)
    }

    fn get_selected_entry_point(
        &self,
        contract_class: &CasmContractClass,
        _class_hash: [u8; 32],
    ) -> Result<CasmContractEntryPoint, TransactionError> {
        let entry_points = match self.entry_point_type {
            EntryPointType::External => &contract_class.entry_points_by_type.external,
            EntryPointType::Constructor => &contract_class.entry_points_by_type.constructor,
            EntryPointType::L1Handler => &contract_class.entry_points_by_type.l1_handler,
        };

        let mut default_entry_point = None;
        let entry_point = entry_points
            .iter()
            .filter_map(|x| {
                if x.selector == DEFAULT_ENTRY_POINT_SELECTOR.to_biguint() {
                    default_entry_point = Some(x);
                }

                (x.selector == self.entry_point_selector.to_biguint()).then_some(x)
            })
            .fold(Ok(None), |acc, x| match acc {
                Ok(None) => Ok(Some(x)),
                _ => Err(TransactionError::NonUniqueEntryPoint),
            })?;
        entry_point
            .or(default_entry_point)
            .cloned()
            .ok_or(TransactionError::EntryPointNotFound)
    }

    fn build_call_info<S>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: ExecutionResourcesManager,
        starknet_storage_state: ContractStorageState<S>,
        events: Vec<OrderedEvent>,
        l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
        internal_calls: Vec<CallInfo>,
        retdata: Vec<Felt252>,
    ) -> Result<CallInfo, TransactionError>
    where
        S: State + StateReader,
    {
        let execution_resources = &resources_manager.cairo_usage - &previous_cairo_usage;

        Ok(CallInfo {
            caller_address: self.caller_address.clone(),
            call_type: Some(self.call_type.clone()),
            contract_address: self.contract_address.clone(),
            code_address: self.code_address.clone(),
            class_hash: Some(self.get_code_class_hash(starknet_storage_state.state)?),
            entry_point_selector: Some(self.entry_point_selector.clone()),
            entry_point_type: Some(self.entry_point_type),
            calldata: self.calldata.clone(),
            retdata,
            execution_resources: execution_resources.filter_unused_builtins(),
            events,
            l2_to_l1_messages,
            storage_read_values: starknet_storage_state.read_values,
            accessed_storage_keys: starknet_storage_state.accessed_keys,
            internal_calls,
            failure_flag: false,
            gas_consumed: 0,
        })
    }

    /// Returns the hash of the executed contract class.
    fn get_code_class_hash<S: StateReader>(
        &self,
        state: &mut S,
    ) -> Result<[u8; 32], TransactionError> {
        if self.class_hash.is_some() {
            match self.call_type {
                CallType::Delegate => return Ok(self.class_hash.unwrap()),
                _ => return Err(TransactionError::CallTypeIsNotDelegate),
            }
        }
        let code_address = match self.call_type {
            CallType::Call => Some(self.contract_address.clone()),
            CallType::Delegate => {
                if self.code_address.is_some() {
                    self.code_address.clone()
                } else {
                    return Err(TransactionError::AttempToUseNoneCodeAddress);
                }
            }
        };

        get_deployed_address_class_hash_at_address(state, &code_address.unwrap())
    }

    fn _execute_version0_class<T>(
        &self,
        state: &mut T,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
        tx_execution_context: &TransactionExecutionContext,
        contract_class: Box<ContractClass>,
        class_hash: [u8; 32],
    ) -> Result<CallInfo, TransactionError>
    where
        T: Default + State + StateReader,
    {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();

        // fetch selected entry point
        let entry_point = self.get_selected_entry_point_v0(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        let mut cairo_runner = CairoRunner::new(&contract_class.program, "all_cairo", false)?;

        cairo_runner.initialize_function_runner(&mut vm, false)?;

        validate_contract_deployed(state, &self.contract_address)?;

        // prepare OS context
        //let os_context = runner.prepare_os_context();
        let os_context = StarknetRunner::<
            DeprecatedSyscallHintProcessor<DeprecatedBLSyscallHandler<T>>,
        >::prepare_os_context(&cairo_runner, &mut vm);

        // fetch syscall_ptr
        let initial_syscall_ptr: Relocatable = match os_context.get(0) {
            Some(MaybeRelocatable::RelocatableValue(ptr)) => ptr.to_owned(),
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        let syscall_handler = DeprecatedBLSyscallHandler::new(
            tx_execution_context.clone(),
            state,
            resources_manager.clone(),
            self.caller_address.clone(),
            self.contract_address.clone(),
            general_config.clone(),
            initial_syscall_ptr,
        );
        let hint_processor = DeprecatedSyscallHintProcessor::new(syscall_handler);
        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        // Positional arguments are passed to *args in the 'run_from_entrypoint' function.
        let data: Vec<MaybeRelocatable> = self.calldata.iter().map(|d| d.into()).collect();
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

        // cairo runner entry point
        runner.run_from_entrypoint(entry_point.offset, &entry_point_args)?;
        runner.validate_and_process_os_context(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let args_ptr = (runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(TransactionError::MissingInitialFp)?
            - (entry_point_args.len() + 2))?;

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr, entry_point_args.len())?;

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage =
            &resources_manager.cairo_usage + &runner.get_execution_resources()?;

        let retdata = runner.get_return_values()?;
        self.build_call_info::<T>(
            previous_cairo_usage,
            runner.hint_processor.syscall_handler.resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            retdata,
        )
    }

    fn _execute<T>(
        &self,
        state: &mut T,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
        tx_execution_context: &TransactionExecutionContext,
        contract_class: Box<CasmContractClass>,
        class_hash: [u8; 32],
        support_reverted: bool,
    ) -> Result<CallInfo, TransactionError>
    where
        T: Default + State + StateReader,
    {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();
        // fetch selected entry point
        let entry_point = self.get_selected_entry_point(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        let mut cairo_runner = CairoRunner::new(
            &get_runnable_program(&contract_class, entry_point.builtins)
                .map_err(TransactionError::ProgramError)?,
            "all_cairo",
            false,
        )?;
        cairo_runner.initialize_function_runner(&mut vm, true)?;

        validate_contract_deployed(state, &self.contract_address)?;

        // prepare OS context
        let os_context =
            StarknetRunner::<SyscallHintProcessor<T>>::prepare_os_context(&cairo_runner, &mut vm);

        // fetch syscall_ptr
        let initial_syscall_ptr: Relocatable = match os_context.get(0) {
            Some(MaybeRelocatable::RelocatableValue(ptr)) => ptr.to_owned(),
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        let syscall_handler = BusinessLogicSyscallHandler::new(
            tx_execution_context.clone(),
            state,
            resources_manager.clone(),
            self.caller_address.clone(),
            self.contract_address.clone(),
            general_config.clone(),
            initial_syscall_ptr,
            support_reverted,
        );
        let hint_processor = SyscallHintProcessor::new(syscall_handler);
        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        // Positional arguments are passed to *args in the 'run_from_entrypoint' function.
        let data = self.calldata.iter().map(|d| d.into()).collect();
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

        // cairo runner entry point
        runner.run_from_entrypoint(entry_point.offset, &entry_point_args)?;
        runner.validate_and_process_os_context(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let args_ptr = (runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(TransactionError::MissingInitialFp)?
            - (entry_point_args.len() + 2))?;

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr, entry_point_args.len())?;

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage =
            &resources_manager.cairo_usage + &runner.get_execution_resources()?;

        let retdata = runner.get_return_values()?;
        self.build_call_info::<T>(
            previous_cairo_usage,
            runner.hint_processor.syscall_handler.resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            retdata,
        )
    }
}

// Helper functions
fn get_runnable_program(
    casm_contract_class: &CasmContractClass,
    entrypoint_builtins: Vec<String>,
) -> Result<Program, ProgramError> {
    Program::new(
        entrypoint_builtins
            .iter()
            .map(|v| serde_json::from_str::<BuiltinName>(v).unwrap())
            .collect(),
        casm_contract_class
            .bytecode
            .iter()
            .map(|v| MaybeRelocatable::from(Felt252::from(v.value.clone())))
            .collect(),
        None,
        collect_hints(casm_contract_class),
        ReferenceManager {
            references: Vec::new(),
        },
        Default::default(),
        Default::default(),
        Default::default(),
    )
}

fn collect_hints(casm_contract_class: &CasmContractClass) -> HashMap<usize, Vec<HintParams>> {
    casm_contract_class
        .hints
        .iter()
        .map(|(key, hints)| (*key, hints.iter().map(hint_to_hint_params).collect()))
        .collect()
}

fn hint_to_hint_params(hint: &Hint) -> HintParams {
    HintParams {
        code: hint.to_string(),
        accessible_scopes: vec![],
        flow_tracking_data: FlowTrackingData {
            ap_tracking: ApTracking::new(),
            reference_ids: HashMap::new(),
        },
    }
}
