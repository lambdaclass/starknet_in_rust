use crate::{
    definitions::{block_context::BlockContext, constants::DEFAULT_ENTRY_POINT_SELECTOR},
    runner::StarknetRunner,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::state_api::State,
    state::ExecutionResourcesManager,
    state::{contract_storage_state::ContractStorageState, state_api::StateReader},
    syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
        deprecated_syscall_handler::DeprecatedSyscallHintProcessor,
        syscall_handler::SyscallHintProcessor,
    },
    transaction::error::TransactionError,
    utils::{
        get_deployed_address_class_hash_at_address, parse_builtin_names,
        validate_contract_deployed, Address,
    },
};
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::{
    felt::Felt252,
    types::{
        program::Program,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};
use starknet_contract_class::{ContractEntryPoint, EntryPointType};

use super::{
    CallInfo, CallResult, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
};

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
    pub(crate) initial_gas: u128,
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
        initial_gas: u128,
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
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: &mut TransactionExecutionContext,
        support_reverted: bool,
    ) -> Result<CallInfo, TransactionError>
    where
        T: State + StateReader,
    {
        // lookup the compiled class from the state.
        let class_hash = self.get_code_class_hash(state)?;
        dbg!(&class_hash);
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;

        match contract_class {
            CompiledClass::Deprecated(contract_class) => self._execute_version0_class(
                state,
                resources_manager,
                block_context,
                tx_execution_context,
                contract_class,
                class_hash,
            ),
            CompiledClass::Casm(contract_class) => self._execute(
                state,
                resources_manager,
                block_context,
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
                if x.selector() == &*DEFAULT_ENTRY_POINT_SELECTOR {
                    default_entry_point = Some(x);
                }

                (x.selector() == &self.entry_point_selector).then_some(x)
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

    fn build_call_info_deprecated<S>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: &ExecutionResourcesManager,
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

    fn build_call_info<S>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: &ExecutionResourcesManager,
        starknet_storage_state: ContractStorageState<S>,
        events: Vec<OrderedEvent>,
        l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
        internal_calls: Vec<CallInfo>,
        call_result: CallResult,
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
            retdata: call_result
                .retdata
                .iter()
                .map(|n| n.get_int_ref().cloned().unwrap_or_default())
                .collect(),
            execution_resources: execution_resources.filter_unused_builtins(),
            events,
            l2_to_l1_messages,
            storage_read_values: starknet_storage_state.read_values,
            accessed_storage_keys: starknet_storage_state.accessed_keys,
            internal_calls,
            failure_flag: !call_result.is_success,
            gas_consumed: call_result.gas_consumed,
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
        block_context: &BlockContext,
        tx_execution_context: &mut TransactionExecutionContext,
        contract_class: Box<ContractClass>,
        class_hash: [u8; 32],
    ) -> Result<CallInfo, TransactionError>
    where
        T: State + StateReader,
    {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();
        // fetch selected entry point
        let entry_point = self.get_selected_entry_point_v0(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        let mut cairo_runner = CairoRunner::new(&contract_class.program, "all_cairo", false)?;
        cairo_runner.initialize_function_runner(&mut vm)?;

        validate_contract_deployed(state, &self.contract_address)?;

        // prepare OS context
        //let os_context = runner.prepare_os_context();
        let os_context =
            StarknetRunner::<DeprecatedSyscallHintProcessor<T>>::prepare_os_context_cairo0(
                &cairo_runner,
                &mut vm,
            );

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
            block_context.clone(),
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
        runner.run_from_entrypoint(entry_point.offset(), &entry_point_args, None)?;
        runner.validate_and_process_os_context_for_version0_class(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let args_ptr = (runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(TransactionError::MissingInitialFp)?
            - (entry_point_args.len() + 2))?;

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr, entry_point_args.len())?;

        *resources_manager = runner
            .hint_processor
            .syscall_handler
            .resources_manager
            .clone();

        *tx_execution_context = runner
            .hint_processor
            .syscall_handler
            .tx_execution_context
            .clone();

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage += &runner.get_execution_resources()?;

        let retdata = runner.get_return_values()?;

        self.build_call_info_deprecated::<T>(
            previous_cairo_usage,
            resources_manager,
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
        block_context: &BlockContext,
        tx_execution_context: &mut TransactionExecutionContext,
        contract_class: Box<CasmContractClass>,
        class_hash: [u8; 32],
        support_reverted: bool,
    ) -> Result<CallInfo, TransactionError>
    where
        T: State + StateReader,
    {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();

        // fetch selected entry point
        let entry_point = self.get_selected_entry_point(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        // get a program from the casm contract class
        let program: Program = contract_class.as_ref().clone().try_into()?;
        // create and initialize a cairo runner for running cairo 1 programs.
        let mut cairo_runner = CairoRunner::new(&program, "all_cairo", false)?;

        cairo_runner.initialize_function_runner_cairo_1(
            &mut vm,
            &parse_builtin_names(&entry_point.builtins)?,
        )?;
        validate_contract_deployed(state, &self.contract_address)?;
        // prepare OS context
        let os_context = StarknetRunner::<SyscallHintProcessor<T>>::prepare_os_context_cairo1(
            &cairo_runner,
            &mut vm,
            self.initial_gas.into(),
        );

        // fetch syscall_ptr (it is the last element of the os_context)
        let initial_syscall_ptr: Relocatable = match os_context.last() {
            Some(MaybeRelocatable::RelocatableValue(ptr)) => ptr.to_owned(),
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        let syscall_handler = BusinessLogicSyscallHandler::new(
            tx_execution_context.clone(),
            state,
            resources_manager.clone(),
            self.caller_address.clone(),
            self.contract_address.clone(),
            block_context.clone(),
            initial_syscall_ptr,
            support_reverted,
            self.entry_point_selector.clone(),
        );
        // create and attach a syscall hint processor to the starknet runner.
        let hint_processor = SyscallHintProcessor::new(syscall_handler, &contract_class.hints);
        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        // TODO: handle error cases
        // Load builtin costs
        let builtin_costs: Vec<MaybeRelocatable> =
            vec![0.into(), 0.into(), 0.into(), 0.into(), 0.into()];
        let builtin_costs_ptr: MaybeRelocatable = runner
            .hint_processor
            .syscall_handler
            .allocate_segment(&mut runner.vm, builtin_costs)?
            .into();

        // Load extra data
        let core_program_end_ptr =
            (runner.cairo_runner.program_base.unwrap() + program.data_len()).unwrap();
        let program_extra_data: Vec<MaybeRelocatable> =
            vec![0x208B7FFF7FFF7FFE.into(), builtin_costs_ptr];
        runner
            .vm
            .load_data(core_program_end_ptr, &program_extra_data)
            .unwrap();

        // Positional arguments are passed to *args in the 'run_from_entrypoint' function.
        let data = self.calldata.iter().map(|d| d.into()).collect();
        let alloc_pointer: MaybeRelocatable = runner
            .hint_processor
            .syscall_handler
            .allocate_segment(&mut runner.vm, data)?
            .into();

        let mut entrypoint_args: Vec<CairoArg> = os_context
            .iter()
            .map(|x| CairoArg::Single(x.into()))
            .collect();
        entrypoint_args.push(CairoArg::Single(alloc_pointer.clone()));
        entrypoint_args.push(CairoArg::Single(
            alloc_pointer.add_usize(self.calldata.len()).unwrap(),
        ));

        let ref_vec: Vec<&CairoArg> = entrypoint_args.iter().collect();

        // run the Cairo1 entrypoint
        runner.run_from_entrypoint(
            entry_point.offset,
            &ref_vec,
            Some(program.data_len() + program_extra_data.len()),
        )?;

        runner.validate_and_process_os_context(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let initial_fp = runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(TransactionError::MissingInitialFp)?;

        let args_ptr = initial_fp - (entrypoint_args.len() + 2);

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr.unwrap(), entrypoint_args.len())?;

        *resources_manager = runner
            .hint_processor
            .syscall_handler
            .resources_manager
            .clone();

        *tx_execution_context = runner
            .hint_processor
            .syscall_handler
            .tx_execution_context
            .clone();

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage += &runner.get_execution_resources()?;

        let call_result = runner.get_call_result(self.initial_gas)?;
        self.build_call_info::<T>(
            previous_cairo_usage,
            resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            call_result,
        )
    }
}
