use super::{
    CallInfo, CallResult, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
};
use crate::{
    definitions::{block_context::BlockContext, constants::DEFAULT_ENTRY_POINT_SELECTOR},
    runner::StarknetRunner,
    services::api::contract_classes::{
        compiled_class::CompiledClass,
        deprecated_contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
    },
    state::{
        cached_state::CachedState,
        contract_storage_state::ContractStorageState,
        state_api::{State, StateReader},
        ExecutionResourcesManager, StateDiff,
    },
    syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
        deprecated_syscall_handler::DeprecatedSyscallHintProcessor,
        syscall_handler::SyscallHintProcessor,
    },
    transaction::error::TransactionError,
    utils::{
        get_deployed_address_class_hash_at_address, parse_builtin_names,
        validate_contract_deployed, Address, ClassHash,
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
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources, RunResources},
        vm_core::VirtualMachine,
    },
};
use std::sync::Arc;

#[cfg(feature = "cairo-native")]
use {
    crate::syscalls::native_syscall_handler::NativeSyscallHandler,
    cairo_native::{
        context::NativeContext, execution_result::NativeExecutionResult, executor::NativeExecutor,
        metadata::syscall_handler::SyscallHandlerMeta, utils::felt252_bigint,
    },
    serde_json::Value,
};

#[derive(Debug, Default)]
pub struct ExecutionResult {
    pub call_info: Option<CallInfo>,
    pub revert_error: Option<String>,
    pub n_reverted_steps: usize,
}

/// Represents a Cairo entry point execution of a StarkNet contract.

// TODO:initial_gas is a new field added in the current changes, it should be checked if we delete it once the new execution entry point is done
#[derive(Debug, Clone)]
pub struct ExecutionEntryPoint {
    pub(crate) call_type: CallType,
    pub(crate) contract_address: Address,
    pub(crate) code_address: Option<Address>,
    pub(crate) class_hash: Option<ClassHash>,
    pub(crate) calldata: Vec<Felt252>,
    pub(crate) caller_address: Address,
    pub(crate) entry_point_selector: Felt252,
    pub(crate) entry_point_type: EntryPointType,
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
        class_hash: Option<ClassHash>,
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
        state: &mut CachedState<T>,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: &mut TransactionExecutionContext,
        support_reverted: bool,
        max_steps: u64,
    ) -> Result<ExecutionResult, TransactionError>
    where
        T: StateReader,
    {
        // lookup the compiled class from the state.
        let class_hash = self.get_code_class_hash(state)?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;
        match contract_class {
            CompiledClass::Deprecated(contract_class) => {
                let call_info = self._execute_version0_class(
                    state,
                    resources_manager,
                    block_context,
                    tx_execution_context,
                    contract_class,
                    class_hash,
                )?;
                Ok(ExecutionResult {
                    call_info: Some(call_info),
                    revert_error: None,
                    n_reverted_steps: 0,
                })
            }
            CompiledClass::Casm(contract_class) => {
                match self._execute(
                    state,
                    resources_manager,
                    block_context,
                    tx_execution_context,
                    contract_class,
                    class_hash,
                    support_reverted,
                ) {
                    Ok(call_info) => Ok(ExecutionResult {
                        call_info: Some(call_info),
                        revert_error: None,
                        n_reverted_steps: 0,
                    }),
                    Err(e) => {
                        if !support_reverted {
                            return Err(e);
                        }

                        let n_reverted_steps =
                            (max_steps as usize) - resources_manager.cairo_usage.n_steps;
                        Ok(ExecutionResult {
                            call_info: None,
                            revert_error: Some(e.to_string()),
                            n_reverted_steps,
                        })
                    }
                }
            }
            CompiledClass::Sierra(sierra_contract_class) => {
                let mut transactional_state = state.create_transactional();

                match self.native_execute(
                    &mut transactional_state,
                    sierra_contract_class,
                    tx_execution_context,
                    block_context,
                ) {
                    Ok(call_info) => {
                        state.apply_state_update(&StateDiff::from_cached_state(
                            transactional_state.cache(),
                        )?)?;

                        Ok(ExecutionResult {
                            call_info: Some(call_info),
                            revert_error: None,
                            n_reverted_steps: 0,
                        })
                    }
                    Err(e) => {
                        if !support_reverted {
                            state.apply_state_update(&StateDiff::from_cached_state(
                                transactional_state.cache(),
                            )?)?;

                            return Err(e);
                        }

                        let n_reverted_steps =
                            (max_steps as usize) - resources_manager.cairo_usage.n_steps;
                        Ok(ExecutionResult {
                            call_info: None,
                            revert_error: Some(e.to_string()),
                            n_reverted_steps,
                        })
                    }
                }
            }
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
            .filter(|x| {
                if x.selector() == &*DEFAULT_ENTRY_POINT_SELECTOR {
                    default_entry_point = Some(*x);
                }

                x.selector() == &self.entry_point_selector
            })
            .try_fold(None, |acc, x| match acc {
                None => Ok(Some(x)),
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
            .filter(|x| {
                if x.selector == DEFAULT_ENTRY_POINT_SELECTOR.to_biguint() {
                    default_entry_point = Some(*x);
                }

                x.selector == self.entry_point_selector.to_biguint()
            })
            .try_fold(None, |acc, x| match acc {
                None => Ok(Some(x)),
                _ => Err(TransactionError::NonUniqueEntryPoint),
            })?;
        entry_point
            .or(default_entry_point)
            .cloned()
            .ok_or(TransactionError::EntryPointNotFound)
    }

    fn build_call_info_deprecated<S: StateReader>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: &ExecutionResourcesManager,
        starknet_storage_state: ContractStorageState<S>,
        events: Vec<OrderedEvent>,
        l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
        internal_calls: Vec<CallInfo>,
        retdata: Vec<Felt252>,
    ) -> Result<CallInfo, TransactionError> {
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
            execution_resources: Some(execution_resources.filter_unused_builtins()),
            events,
            l2_to_l1_messages,
            storage_read_values: starknet_storage_state.read_values,
            accessed_storage_keys: starknet_storage_state.accessed_keys,
            internal_calls,
            failure_flag: false,
            gas_consumed: 0,
        })
    }

    fn build_call_info<S: StateReader>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: &ExecutionResourcesManager,
        starknet_storage_state: ContractStorageState<S>,
        events: Vec<OrderedEvent>,
        l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
        internal_calls: Vec<CallInfo>,
        call_result: CallResult,
    ) -> Result<CallInfo, TransactionError> {
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
            execution_resources: Some(execution_resources.filter_unused_builtins()),
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
    fn get_code_class_hash<S: State>(&self, state: &mut S) -> Result<ClassHash, TransactionError> {
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

    fn _execute_version0_class<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
        tx_execution_context: &mut TransactionExecutionContext,
        contract_class: Arc<ContractClass>,
        class_hash: ClassHash,
    ) -> Result<CallInfo, TransactionError> {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();
        // fetch selected entry point
        let entry_point =
            self.get_selected_entry_point_v0(&contract_class, class_hash.as_slice())?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        let mut cairo_runner = CairoRunner::new(&contract_class.program, "starknet", false)?;
        cairo_runner.initialize_function_runner(&mut vm)?;

        validate_contract_deployed(state, &self.contract_address)?;

        // prepare OS context
        //let os_context = runner.prepare_os_context();
        let os_context =
            StarknetRunner::<DeprecatedSyscallHintProcessor<S>>::prepare_os_context_cairo0(
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
        let hint_processor =
            DeprecatedSyscallHintProcessor::new(syscall_handler, RunResources::default());
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

        self.build_call_info_deprecated::<S>(
            previous_cairo_usage,
            resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            retdata,
        )
    }

    fn _execute<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
        tx_execution_context: &mut TransactionExecutionContext,
        contract_class: Arc<CasmContractClass>,
        class_hash: ClassHash,
        support_reverted: bool,
    ) -> Result<CallInfo, TransactionError> {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();

        // fetch selected entry point
        let entry_point = self.get_selected_entry_point(&contract_class, class_hash.as_slice())?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        // get a program from the casm contract class
        let program: Program = contract_class.as_ref().clone().try_into()?;
        // create and initialize a cairo runner for running cairo 1 programs.
        let mut cairo_runner = CairoRunner::new(&program, "starknet", false)?;

        cairo_runner.initialize_function_runner_cairo_1(
            &mut vm,
            &parse_builtin_names(&entry_point.builtins)?,
        )?;
        validate_contract_deployed(state, &self.contract_address)?;
        // prepare OS context
        let os_context = StarknetRunner::<SyscallHintProcessor<S>>::prepare_os_context_cairo1(
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
        let hint_processor = SyscallHintProcessor::new(
            syscall_handler,
            &contract_class.hints,
            RunResources::default(),
        );
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

        runner
            .vm
            .mark_address_range_as_accessed(core_program_end_ptr, program_extra_data.len())?;

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
        self.build_call_info::<S>(
            previous_cairo_usage,
            resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            call_result,
        )
    }

    #[cfg(not(feature = "cairo-native"))]
    #[inline(always)]
    fn native_execute<S: StateReader>(
        &self,
        _state: &mut CachedState<S>,
        _contract_class: Arc<cairo_lang_starknet::contract_class::ContractClass>,
        _tx_execution_context: &mut TransactionExecutionContext,
        _block_context: &BlockContext,
    ) -> Result<CallInfo, TransactionError> {
        Err(TransactionError::SierraCompileError(
            "This version of SiR was compiled without the Cairo Native feature".to_string(),
        ))
    }

    #[cfg(feature = "cairo-native")]
    #[inline(always)]
    fn native_execute<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        contract_class: Arc<cairo_lang_starknet::contract_class::ContractClass>,
        tx_execution_context: &TransactionExecutionContext,
        block_context: &BlockContext,
    ) -> Result<CallInfo, TransactionError> {
        use serde_json::json;

        let entry_point = match self.entry_point_type {
            EntryPointType::External => contract_class
                .entry_points_by_type
                .external
                .iter()
                .find(|entry_point| entry_point.selector == self.entry_point_selector.to_biguint())
                .unwrap(),
            EntryPointType::Constructor => contract_class
                .entry_points_by_type
                .constructor
                .iter()
                .find(|entry_point| entry_point.selector == self.entry_point_selector.to_biguint())
                .unwrap(),
            EntryPointType::L1Handler => contract_class
                .entry_points_by_type
                .l1_handler
                .iter()
                .find(|entry_point| entry_point.selector == self.entry_point_selector.to_biguint())
                .unwrap(),
        };

        let sierra_program = contract_class.extract_sierra_program().unwrap();

        let native_context = NativeContext::new();
        let mut native_program = native_context.compile(&sierra_program).unwrap();
        let contract_storage_state =
            ContractStorageState::new(state, self.contract_address.clone());

        let syscall_handler = NativeSyscallHandler {
            starknet_storage_state: contract_storage_state,
            n_emitted_events: 0,
            events: Vec::new(),
            l2_to_l1_messages: Vec::new(),
            n_sent_messages: 0,
            contract_address: self.contract_address.clone(),
            internal_calls: Vec::new(),
            caller_address: self.caller_address.clone(),
            entry_point_selector: self.entry_point_selector.clone(),
            tx_execution_context: tx_execution_context.clone(),
            block_context: block_context.clone(),
        };

        native_program
            .insert_metadata(SyscallHandlerMeta::new(&syscall_handler))
            .unwrap();

        let syscall_addr = native_program
            .get_metadata::<SyscallHandlerMeta>()
            .unwrap()
            .as_ptr()
            .as_ptr() as *const () as usize;

        let fn_id = &sierra_program
            .funcs
            .iter()
            .find(|x| x.id.id == (entry_point.function_idx as u64))
            .unwrap()
            .id;

        let required_init_gas = native_program.get_required_init_gas(fn_id);

        let calldata: Vec<_> = self
            .calldata
            .iter()
            .map(|felt| felt252_bigint(felt.to_bigint()))
            .collect();

        /*
            Below we construct `params`, the Serde value that MLIR expects. It consists of the following:

            - One `null` value for each builtin that is going to be used.
            - The maximum amout of gas allowed by the call.
            - `syscall_addr`, the address of the syscall handler.
            - `calldata`, an array of Felt arguments to the method being called.
        */

        let wrapped_calldata = vec![calldata];
        let params: Vec<Value> = sierra_program.funcs[fn_id.id as usize]
            .params
            .iter()
            .map(|param| {
                match param.ty.debug_name.as_ref().unwrap().as_str() {
                    "GasBuiltin" => {
                        json!(self.initial_gas as u64)
                    }
                    "Pedersen" | "SegmentArena" | "RangeCheck" | "Bitwise" | "Poseidon" => {
                        json!(null)
                    }
                    "System" => {
                        json!(syscall_addr)
                    }
                    // calldata
                    "core::array::Span::<core::felt252>" => json!(wrapped_calldata),
                    x => {
                        unimplemented!("unhandled param type: {:?}", x);
                    }
                }
            })
            .collect();

        let mut writer: Vec<u8> = Vec::new();
        let returns = &mut serde_json::Serializer::new(&mut writer);

        let native_executor = NativeExecutor::new(native_program);

        native_executor
            .execute(fn_id, json!(params), returns, required_init_gas)
            .map_err(|e| TransactionError::CustomError(format!("cairo-native error: {:?}", e)))?;

        let result: String = String::from_utf8(writer).unwrap();
        let value = serde_json::from_str::<NativeExecutionResult>(&result).unwrap();

        Ok(CallInfo {
            caller_address: self.caller_address.clone(),
            call_type: Some(self.call_type.clone()),
            contract_address: self.contract_address.clone(),
            code_address: self.code_address.clone(),
            class_hash: Some(
                self.get_code_class_hash(syscall_handler.starknet_storage_state.state)?,
            ),
            entry_point_selector: Some(self.entry_point_selector.clone()),
            entry_point_type: Some(self.entry_point_type),
            calldata: self.calldata.clone(),
            retdata: value.return_values,
            execution_resources: None,
            events: syscall_handler.events,
            storage_read_values: syscall_handler.starknet_storage_state.read_values,
            accessed_storage_keys: syscall_handler.starknet_storage_state.accessed_keys,
            failure_flag: value.failure_flag,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
            internal_calls: syscall_handler.internal_calls,
            // TODO: check it's correct
            gas_consumed: self.initial_gas - u128::from(value.gas_builtin.unwrap_or(0)),
        })
    }
}
