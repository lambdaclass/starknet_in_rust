use crate::{
    business_logic::{
        execution::objects::{CallInfo, CallType, TransactionExecutionContext},
        fact_state::state::ExecutionResourcesManager,
        state::state_api::State,
        state::state_api::StateReader,
        transaction::error::TransactionError,
    },
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        syscall_handler::{SyscallHandler, SyscallHintProcessor},
    },
    definitions::{constants::DEFAULT_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig},
    services::api::contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
    starknet_runner::runner::{prepare_os_context, StarknetRunner},
    utils::{get_deployed_address_class_hash_at_address, validate_contract_deployed, Address},
};
use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        vm_core::VirtualMachine,
    },
};
use felt::Felt252;

/// Represents a Cairo entry point execution of a StarkNet contract.
#[derive(Debug)]
pub struct ExecutionEntryPoint {
    call_type: CallType,
    contract_address: Address,
    code_address: Option<Address>,
    class_hash: Option<[u8; 32]>,
    calldata: Vec<Felt252>,
    caller_address: Address,
    entry_point_selector: Felt252,
    entry_point_type: EntryPointType,
}

impl ExecutionEntryPoint {
    pub fn new(
        contract_address: Address,
        calldata: Vec<Felt252>,
        entry_point_selector: Felt252,
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
    pub fn execute<T>(
        &self,
        state: &mut T,
        general_config: &StarknetGeneralConfig,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: &TransactionExecutionContext,
    ) -> Result<CallInfo, TransactionError>
    where
        T: State + StateReader,
    {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();

        let runner = self.run(
            state,
            resources_manager,
            general_config,
            tx_execution_context,
        )?;

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage =
            &resources_manager.cairo_usage + &runner.get_execution_resources()?;

        let retdata = runner.get_return_values()?;
        self.build_call_info::<T>(
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
    fn run<'a, T>(
        &self,
        state: &'a mut T,
        resources_manager: &ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
        tx_execution_context: &TransactionExecutionContext,
    ) -> Result<StarknetRunner<BusinessLogicSyscallHandler<'a, T>>, TransactionError>
    where
        T: State + StateReader,
    {
        // Prepare input for Starknet runner.
        let class_hash = self.get_code_class_hash(state)?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissigContractClass)?;

        // fetch selected entry point
        let entry_point = self.get_selected_entry_point(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        let mut cairo_runner = CairoRunner::new(contract_class.program(), "all", false)?;
        cairo_runner.initialize_function_runner(&mut vm, false)?;

        validate_contract_deployed(state, &self.contract_address)?;

        // prepare OS context
        let os_context = prepare_os_context(&mut vm, &mut cairo_runner);

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
        );

        let mut runner =
            StarknetRunner::new(cairo_runner, vm, SyscallHintProcessor::new(syscall_handler));

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

        let entrypoint = entry_point.offset;

        // cairo runner entry point
        runner.run_from_entrypoint(entrypoint, &entry_point_args)?;
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

        Ok(runner)
    }

    /// Returns the entry point with selector corresponding with self.entry_point_selector, or the
    /// default if there is one and the requested one is not found.
    fn get_selected_entry_point(
        &self,
        contract_class: &ContractClass,
        _class_hash: [u8; 32],
    ) -> Result<ContractEntryPoint, TransactionError> {
        let entry_points = contract_class
            .entry_points_by_type()
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

    fn build_call_info<S>(
        &self,
        previous_cairo_usage: ExecutionResources,
        syscall_handler: BusinessLogicSyscallHandler<S>,
        retdata: Vec<Felt252>,
    ) -> Result<CallInfo, TransactionError>
    where
        S: State + StateReader,
    {
        let execution_resources =
            &syscall_handler.resources_manager.cairo_usage - &previous_cairo_usage;

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
            retdata,
            execution_resources: execution_resources.filter_unused_builtins(),
            events: syscall_handler.events,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,
            storage_read_values: syscall_handler.starknet_storage_state.read_values,
            accessed_storage_keys: syscall_handler.starknet_storage_state.accessed_keys,
            internal_calls: syscall_handler.internal_calls,
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
}

#[cfg(test)]
mod tests {
    use crate::business_logic::fact_state::in_memory_state_reader::InMemoryStateReader;
    use crate::business_logic::{
        execution::execution_entry_point::ExecutionEntryPoint, state::cached_state::CachedState,
    };
    use crate::definitions::constants::TRANSACTION_VERSION;
    use crate::utils::calculate_sn_keccak;
    use crate::{
        business_logic::{
            execution::objects::{CallInfo, CallType, TransactionExecutionContext},
            fact_state::state::ExecutionResourcesManager,
        },
        definitions::general_config::StarknetGeneralConfig,
        services::api::contract_class::{ContractClass, EntryPointType},
        utils::Address,
    };
    use cairo_rs::with_std::collections::HashMap;
    use felt::Felt252;
    use std::path::Path;
    #[test]
    fn test_execution_entrypoint() {
        let contract_path = "starknet_programs/fibonacci.json";
        let entry_point = "fib";
        let call_data = [1.into(), 1.into(), 10.into()].to_vec();
        let return_data = [144.into()].to_vec();

        let contract_class =
            ContractClass::try_from(<str as AsRef<Path>>::as_ref(contract_path).to_path_buf())
                .expect("Could not load contract from JSON");

        //* --------------------------------------------
        //*       Create a default contract data
        //* --------------------------------------------

        let contract_address = Address(1111.into());
        let class_hash = [1; 32];

        //* --------------------------------------------
        //*          Create default context
        //* --------------------------------------------

        let general_config = StarknetGeneralConfig::default();

        let tx_execution_context = TransactionExecutionContext::create_for_testing(
            Address(0.into()),
            10,
            0.into(),
            general_config.invoke_tx_max_n_steps(),
            TRANSACTION_VERSION,
        );

        //* --------------------------------------------
        //*  Create starknet state with the contract
        //*  (This would be the equivalent of
        //*  declaring and deploying the contract)
        //* -------------------------------------------

        let mut state_reader = InMemoryStateReader::default();

        state_reader
            .address_to_class_hash
            .insert(contract_address.clone(), class_hash);

        state_reader.address_to_nonce.insert(
            contract_address.clone(),
            tx_execution_context.nonce().clone(),
        );

        state_reader
            .address_to_storage
            .insert((contract_address.clone(), [0; 32]), Felt252::new(1));

        let mut contract_class_cache = HashMap::new();
        contract_class_cache.insert(class_hash, contract_class);

        let mut state = CachedState::new(state_reader, Some(contract_class_cache));

        //* ------------------------------------
        //*    Create execution entry point
        //* ------------------------------------

        let caller_address = Address(0.into());

        let entry_point_selector =
            Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));
        let entry_point = ExecutionEntryPoint::new(
            contract_address.clone(),
            call_data.clone(),
            entry_point_selector.clone(),
            caller_address.clone(),
            EntryPointType::External,
            CallType::Delegate.into(),
            class_hash.into(),
        );

        let mut resources_manager = ExecutionResourcesManager::default();

        assert_eq!(
            entry_point
                .execute(
                    &mut state,
                    &general_config,
                    &mut resources_manager,
                    &tx_execution_context,
                )
                .expect("Could not execute contract"),
            CallInfo {
                contract_address,
                caller_address,
                entry_point_type: EntryPointType::External.into(),
                call_type: CallType::Delegate.into(),
                class_hash: class_hash.into(),
                entry_point_selector: Some(entry_point_selector),
                calldata: call_data,
                retdata: return_data,
                ..Default::default()
            },
        );
    }
}
