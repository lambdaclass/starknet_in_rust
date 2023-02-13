use std::collections::HashMap;

use cairo_rs::{
    hint_processor::hint_processor_definition::HintProcessor,
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        errors::vm_errors::VirtualMachineError,
        runners::{
            builtin_runner::BuiltinRunner,
            cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        },
        vm_core::VirtualMachine,
    },
};
use felt::Felt;
use num_traits::ToPrimitive;

use crate::{
    business_logic::{
        execution::execution_errors::ExecutionError,
        fact_state::in_memory_state_reader::InMemoryStateReader, state::cached_state::CachedState,
    },
    core::syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        syscall_handler::{self, SyscallHandler, SyscallHintProcessor},
    },
};

use super::starknet_runner_error::StarknetRunnerError;
use cairo_rs::types::relocatable::MaybeRelocatable::Int;

pub(crate) struct StarknetRunner {
    pub(crate) cairo_runner: CairoRunner,
    pub(crate) vm: VirtualMachine,
    pub(crate) hint_processor:
        SyscallHintProcessor<BusinessLogicSyscallHandler<CachedState<InMemoryStateReader>>>,
}

impl StarknetRunner {
    pub fn new(
        cairo_runner: CairoRunner,
        vm: VirtualMachine,
        hint_processor: SyscallHintProcessor<
            BusinessLogicSyscallHandler<CachedState<InMemoryStateReader>>,
        >,
    ) -> Self {
        StarknetRunner {
            cairo_runner,
            vm,
            hint_processor,
        }
    }

    pub fn run_from_entrypoint(
        &mut self,
        entrypoint: usize,
        args: &[&CairoArg],
    ) -> Result<(), ExecutionError> {
        let verify_secure = true;
        let args: Vec<&CairoArg> = args.iter().map(ToOwned::to_owned).collect();

        Ok(self.cairo_runner.run_from_entrypoint(
            entrypoint,
            &args,
            verify_secure,
            &mut self.vm,
            &mut self.hint_processor,
        )?)
    }

    pub fn get_execution_resources(&self) -> Result<ExecutionResources, ExecutionError> {
        Ok(self.cairo_runner.get_execution_resources(&self.vm)?)
    }

    pub fn get_return_values(&self) -> Result<Vec<Felt>, StarknetRunnerError> {
        self.vm
            .get_return_values(2)
            .map_err(StarknetRunnerError::MemoryException)?
            .into_iter()
            .map(|val| match val {
                Int(felt) => Ok(felt),
                MaybeRelocatable::RelocatableValue(r) => {
                    Ok(self.vm.get_integer(&r).unwrap().into_owned())
                }
            })
            .collect::<Result<Vec<Felt>, _>>()
    }

    pub(crate) fn prepare_os_context(&mut self) -> Vec<MaybeRelocatable> {
        let syscall_segment = self.vm.add_memory_segment();
        let mut os_context = [syscall_segment.into()].to_vec();
        let builtin_runners = self
            .vm
            .get_builtin_runners()
            .clone()
            .into_iter()
            .collect::<HashMap<String, BuiltinRunner>>();
        self.cairo_runner
            .get_program_builtins()
            .iter()
            .for_each(|builtin| {
                if builtin_runners.contains_key(builtin) {
                    let b_runner = builtin_runners.get(builtin).unwrap();
                    let stack = b_runner.initial_stack();
                    os_context.extend(stack);
                }
            });
        os_context
    }

    /// Returns the base and stop ptr of the OS-designated segment that starts at ptr_offset.
    pub(crate) fn get_os_segment_ptr_range(
        &self,
        ptr_offset: usize,
        os_context: Vec<MaybeRelocatable>,
    ) -> Result<(MaybeRelocatable, MaybeRelocatable), ExecutionError> {
        if ptr_offset != 0 {
            return Err(ExecutionError::IllegalOsPtrOffset);
        }

        let os_context_end = self.vm.get_ap().sub_usize(2)?;
        let final_os_context_ptr = os_context_end.sub_usize(os_context.len())?;
        let os_context_ptr = os_context
            .get(ptr_offset)
            .ok_or(ExecutionError::InvalidPtrFetch)?
            .to_owned();

        let addr = final_os_context_ptr + ptr_offset;
        let ptr_fetch_from_memory = self
            .vm
            .get_maybe(&addr)?
            .ok_or(ExecutionError::InvalidPtrFetch)?;

        Ok((os_context_ptr, ptr_fetch_from_memory))
    }

    pub(crate) fn validate_segment_pointers(
        &self,
        segment_base_ptr: MaybeRelocatable,
        segment_stop_ptr: MaybeRelocatable,
    ) -> Result<(), ExecutionError> {
        let seg_base_ptr = match segment_base_ptr {
            MaybeRelocatable::RelocatableValue(val) => {
                if val.offset != 0 {
                    return Err(ExecutionError::InvalidSegBasePtrOffset(val.offset));
                }
                val
            }
            _ => return Err(ExecutionError::NotARelocatableValue),
        };

        let expected_stop_ptr = seg_base_ptr
            + self
                .vm
                .get_segment_used_size(seg_base_ptr.segment_index as usize)
                .ok_or(ExecutionError::InvalidSegmentSize)?;

        let seg_stop_ptr: Relocatable = match segment_stop_ptr {
            MaybeRelocatable::RelocatableValue(val) => val,
            _ => return Err(ExecutionError::NotARelocatableValue),
        };

        if expected_stop_ptr != seg_stop_ptr {
            return Err(ExecutionError::InvalidStopPointer(
                expected_stop_ptr,
                seg_stop_ptr,
            ));
        }
        Ok(())
    }

    /// Validates and processes an OS context that was returned by a transaction.
    /// Returns the syscall processor object containing the accumulated syscall information.
    pub(crate) fn validate_and_process_os_context(
        &mut self,
        initial_os_context: Vec<MaybeRelocatable>,
    ) -> Result<(), ExecutionError> {
        // The returned values are os_context, retdata_size, retdata_ptr.
        let os_context_end = self.vm.get_ap().sub_usize(2)?;
        let mut stack_pointer = os_context_end;

        let stack_ptr = self
            .cairo_runner
            .get_builtins_final_stack(&mut self.vm, stack_pointer)?;

        let final_os_context_ptr = stack_ptr.sub_usize(1)?;

        if final_os_context_ptr + initial_os_context.len() != os_context_end {
            return Err(ExecutionError::OsContextPtrNotEqual);
        }

        // Validate system calls
        let (syscall_base_ptr, syscall_stop_ptr) =
            self.get_os_segment_ptr_range(0, initial_os_context)?;

        self.validate_segment_pointers(syscall_base_ptr, syscall_stop_ptr.clone())?;

        self.hint_processor
            .syscall_handler
            .post_run(&mut self.vm, syscall_stop_ptr);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
    };

    use cairo_rs::{
        types::relocatable::MaybeRelocatable,
        vm::{
            runners::cairo_runner::{CairoRunner, ExecutionResources},
            vm_core::VirtualMachine,
        },
    };
    use felt::Felt;
    use num_traits::{Num, Zero};
    use starknet_api::state::Program;

    use crate::{
        business_logic::{
            execution::{
                execution_entry_point::ExecutionEntryPoint,
                objects::{CallInfo, CallType, TransactionExecutionContext},
            },
            fact_state::{
                contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
                state::ExecutionResourcesManager,
            },
            state::{cached_state::CachedState, state_api_objects::BlockInfo},
        },
        core::syscalls::syscall_handler::{SyscallHandler, SyscallHintProcessor},
        definitions::{
            constants::TRANSACTION_VERSION,
            general_config::{self, StarknetGeneralConfig},
        },
        services::api::contract_class::{ContractClass, ContractEntryPoint, EntryPointType},
        starknet_storage::dict_storage::DictStorage,
        utils::{test_utils::vm, Address},
    };

    use super::StarknetRunner;

    #[test]
    fn get_execution_resources_test_fail() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let mut vm = VirtualMachine::new(true);
        let hint_processor = SyscallHintProcessor::new_empty();

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        assert!(runner.get_execution_resources().is_err());
    }

    #[test]
    fn prepare_os_context_test() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let mut vm = VirtualMachine::new(true);
        let hint_processor = SyscallHintProcessor::new_empty();

        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        let os_context = runner.prepare_os_context();

        // is expected to return a pointer to the first segment as there is nothing more in the vm
        let expected = Vec::from([MaybeRelocatable::from((0, 0))]);

        assert_eq!(os_context, expected);
    }

    #[test]
    fn integration_test() {
        // ---------------------------------------------------------
        //  Create program and entry point types for contract class
        // ---------------------------------------------------------

        let path = PathBuf::from("starknet_programs/fibonacci.json");
        let contract_class = ContractClass::try_from(path).unwrap();
        let mut entry_points_by_type = contract_class.entry_points_by_type.clone();

        let fib_entrypoint_selector = entry_points_by_type
            .get(&EntryPointType::External)
            .unwrap()
            .get(0)
            .unwrap()
            .selector
            .clone();

        //* --------------------------------------------
        //*    Create state reader with class hash data
        //* --------------------------------------------

        let ffc = DictStorage::new();
        let contract_class_storage = DictStorage::new();
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------

        let address = Address(1111.into());
        let class_hash = [1; 32];
        let contract_state = ContractState::create(class_hash, 3.into(), HashMap::new());

        contract_class_cache.insert(class_hash, contract_class);
        let mut state_reader = InMemoryStateReader::new(ffc, contract_class_storage);
        state_reader
            .contract_states
            .insert(address.clone(), contract_state);

        //* ---------------------------------------
        //*    Create state with previous data
        //* ---------------------------------------

        let mut state = CachedState::new(state_reader, Some(contract_class_cache));

        //* ------------------------------------
        //*    Create execution entry point
        //* ------------------------------------

        let calldata = [1.into(), 1.into(), 10.into()].to_vec();
        let caller_address = Address(0000.into());
        let entry_point_type = EntryPointType::External;

        let exec_entry_point = ExecutionEntryPoint::new(
            address,
            calldata.clone(),
            fib_entrypoint_selector.clone(),
            caller_address,
            entry_point_type,
            Some(CallType::Delegate),
            Some(class_hash),
        );

        //* --------------------
        //*   Execute contract
        //* ---------------------
        let general_config = StarknetGeneralConfig::default();
        let tx_execution_context = TransactionExecutionContext::new(
            Address(0.into()),
            Felt::zero(),
            Vec::new(),
            0,
            10.into(),
            general_config.invoke_tx_max_n_steps,
            TRANSACTION_VERSION,
        );
        let mut resources_manager = ExecutionResourcesManager::default();

        let expected_call_info = CallInfo {
            caller_address: Address(0.into()),
            call_type: Some(CallType::Delegate),
            contract_address: Address(1111.into()),
            entry_point_selector: Some(fib_entrypoint_selector),
            entry_point_type: Some(EntryPointType::External),
            calldata,
            retdata: [1.into(), 144.into()].to_vec(),
            execution_resources: ExecutionResources::default(),
            class_hash: Some(class_hash),
            ..Default::default()
        };

        assert_eq!(
            exec_entry_point
                .execute(
                    &mut state,
                    &general_config,
                    &mut resources_manager,
                    &tx_execution_context
                )
                .unwrap(),
            expected_call_info
        );
    }
}
