use super::starknet_runner_error::StarknetRunnerError;
use crate::business_logic::transaction::error::TransactionError;
use crate::core::syscalls::syscall_handler::HintProcessorPostRun;
use cairo_lang_starknet::casm_contract_class::CasmContractClass;
use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::hint_processor_definition::HintProcessor;
use cairo_vm::serde::deserialize_program::BuiltinName;
use cairo_vm::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        runners::{
            builtin_runner::BuiltinRunner,
            cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        },
        vm_core::VirtualMachine,
    },
};
use num_traits::ToPrimitive;
use std::{borrow::Cow, collections::HashMap};

pub fn get_casm_contract_builtins(
    contract_class: &CasmContractClass,
    entrypoint_offset: usize,
) -> Vec<BuiltinName> {
    contract_class
        .entry_points_by_type
        .external
        .iter()
        .find(|e| e.offset == entrypoint_offset)
        .unwrap()
        .builtins
        .iter()
        .map(|n| format!("{n}_builtin"))
        .map(|s| match &*s {
            cairo_vm::vm::runners::builtin_runner::OUTPUT_BUILTIN_NAME => BuiltinName::output,
            cairo_vm::vm::runners::builtin_runner::RANGE_CHECK_BUILTIN_NAME => {
                BuiltinName::range_check
            }
            cairo_vm::vm::runners::builtin_runner::HASH_BUILTIN_NAME => BuiltinName::pedersen,
            cairo_vm::vm::runners::builtin_runner::SIGNATURE_BUILTIN_NAME => BuiltinName::ecdsa,
            cairo_vm::vm::runners::builtin_runner::KECCAK_BUILTIN_NAME => BuiltinName::keccak,
            cairo_vm::vm::runners::builtin_runner::BITWISE_BUILTIN_NAME => BuiltinName::bitwise,
            cairo_vm::vm::runners::builtin_runner::EC_OP_BUILTIN_NAME => BuiltinName::ec_op,
            cairo_vm::vm::runners::builtin_runner::POSEIDON_BUILTIN_NAME => BuiltinName::poseidon,
            cairo_vm::vm::runners::builtin_runner::SEGMENT_ARENA_BUILTIN_NAME => {
                BuiltinName::segment_arena
            }
            _ => panic!("Invalid builtin {s}"),
        })
        .collect()
}

pub(crate) struct StarknetRunner<H>
where
    H: HintProcessor + HintProcessorPostRun,
{
    pub(crate) cairo_runner: CairoRunner,
    pub(crate) vm: VirtualMachine,
    pub(crate) hint_processor: H,
}

impl<H> StarknetRunner<H>
where
    H: HintProcessor + HintProcessorPostRun,
{
    pub fn new(cairo_runner: CairoRunner, vm: VirtualMachine, hint_processor: H) -> Self {
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
        program_segment_size: Option<usize>,
    ) -> Result<(), TransactionError> {
        let verify_secure = true;
        let args: Vec<&CairoArg> = args.iter().map(ToOwned::to_owned).collect();

        self.cairo_runner.run_from_entrypoint(
            entrypoint,
            &args,
            verify_secure,
            program_segment_size,
            &mut self.vm,
            &mut self.hint_processor,
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn run_from_cairo1_entrypoint(
        &mut self,
        contract_class: &CasmContractClass,
        entrypoint_offset: usize,
        args: &[MaybeRelocatable],
    ) -> Result<(), TransactionError> {
        let program_builtins = get_casm_contract_builtins(contract_class, entrypoint_offset);
        // TODO: investigate this line (cairo runner must be initialized once)
        self.cairo_runner
            .initialize_function_runner_cairo_1(&mut self.vm, &program_builtins)
            .unwrap();

        // Implicit Args
        // let syscall_segment = MaybeRelocatable::from(self.vm.add_memory_segment());

        // let builtins: Vec<&'static str> = self
        //     .cairo_runner
        //     .get_program_builtins()
        //     .iter()
        //     .map(|b| b.name())
        //     .collect();

        // let builtin_segment: Vec<MaybeRelocatable> = self
        //     .vm
        //     .get_builtin_runners()
        //     .iter()
        //     .filter(|b| builtins.contains(&b.name()))
        //     .flat_map(|b| b.initial_stack())
        //     .collect();

        // let initial_gas = MaybeRelocatable::from(usize::MAX);

        // let mut implicit_args = builtin_segment;
        // implicit_args.extend([initial_gas]);
        // implicit_args.extend([syscall_segment]);

        // Other args

        // Load builtin costs
        let builtin_costs: Vec<MaybeRelocatable> =
            vec![0.into(), 0.into(), 0.into(), 0.into(), 0.into()];
        let builtin_costs_ptr = self.vm.add_memory_segment();
        self.vm
            .load_data(builtin_costs_ptr, &builtin_costs)
            .unwrap();

        // Load extra data
        let core_program_end_ptr = (self.cairo_runner.program_base.unwrap()
            + self.cairo_runner.get_program().data_len())
        .unwrap();
        let program_extra_data: Vec<MaybeRelocatable> =
            vec![0x208B7FFF7FFF7FFE.into(), builtin_costs_ptr.into()];
        self.vm
            .load_data(core_program_end_ptr, &program_extra_data)
            .unwrap();

        // Load calldata
        let calldata_start = self.vm.add_memory_segment();
        let calldata_end = self.vm.load_data(calldata_start, &args.to_vec()).unwrap();

        // Create entrypoint_args
        let mut entrypoint_args: Vec<CairoArg> =
            args.iter().map(|m| CairoArg::from(m.clone())).collect();
        entrypoint_args.extend([
            MaybeRelocatable::from(calldata_start).into(),
            MaybeRelocatable::from(calldata_end).into(),
        ]);
        let entrypoint_args: Vec<&CairoArg> = entrypoint_args.iter().collect();

        // Once we have all the entrypoint args in place we can run it
        self.cairo_runner
            .run_from_entrypoint(
                entrypoint_offset,
                &entrypoint_args,
                true,
                Some(self.cairo_runner.get_program().data_len() + program_extra_data.len()),
                &mut self.vm,
                &mut self.hint_processor,
            )
            .unwrap();

        Ok(())
    }

    pub fn get_execution_resources(&self) -> Result<ExecutionResources, TransactionError> {
        Ok(self.cairo_runner.get_execution_resources(&self.vm)?)
    }

    pub fn get_return_values(&self) -> Result<Vec<Felt252>, StarknetRunnerError> {
        let ret_data = self.vm.get_return_values(2)?;

        let n_rets = ret_data[0]
            .get_int_ref()
            .ok_or(StarknetRunnerError::NotAFelt)?;

        let ret_ptr = ret_data[1]
            .get_relocatable()
            .ok_or(StarknetRunnerError::NotARelocatable)?;

        let ret_data = self
            .vm
            .get_integer_range(
                ret_ptr,
                n_rets
                    .to_usize()
                    .ok_or(StarknetRunnerError::DataConversionError)?,
            )
            .map_err(|_| StarknetRunnerError::NotAFelt)?;
        Ok(ret_data.into_iter().map(Cow::into_owned).collect())
    }

    pub fn get_return_values_cairo_1(&self) -> Result<Vec<Felt252>, StarknetRunnerError> {
        // TODO: convert unwraps in proper errors
        let return_values = self.vm.get_return_values(5).unwrap();
        let retdata_start = return_values[3].get_relocatable().unwrap();
        let retdata_end = return_values[4].get_relocatable().unwrap();
        let retdata: Vec<Felt252> = self
            .vm
            .get_integer_range(retdata_start, (retdata_end - retdata_start).unwrap())
            .unwrap()
            .iter()
            .map(|c| c.clone().into_owned())
            .collect();
        Ok(retdata)
    }

    pub fn prepare_os_context_cairo1(
        cairo_runner: &CairoRunner,
        vm: &mut VirtualMachine,
        gas: Felt252,
    ) -> Vec<MaybeRelocatable> {
        let mut os_context = vec![];
        // first, add for each builtin, its initial stack to the os_context
        let builtin_runners = vm
            .get_builtin_runners()
            .iter()
            .map(|runner| (runner.name(), runner.clone()))
            .collect::<HashMap<&str, BuiltinRunner>>();

        cairo_runner
            .get_program_builtins()
            .iter()
            .for_each(|builtin| {
                if builtin_runners.contains_key(builtin.name()) {
                    let b_runner = builtin_runners.get(builtin.name()).unwrap();
                    let stack = b_runner.initial_stack();
                    os_context.extend(stack);
                }
            });

        // add the gas
        os_context.push(gas.into());

        // finally add the syscall segment
        let syscall_segment = vm.add_memory_segment();
        os_context.push(syscall_segment.into());
        os_context
    }

    pub fn prepare_os_context_cairo0(
        cairo_runner: &CairoRunner,
        vm: &mut VirtualMachine,
    ) -> Vec<MaybeRelocatable> {
        let syscall_segment = vm.add_memory_segment();
        let mut os_context = [syscall_segment.into()].to_vec();
        let builtin_runners = vm
            .get_builtin_runners()
            .iter()
            .map(|runner| (runner.name(), runner))
            .collect::<HashMap<&str, &BuiltinRunner>>();

        cairo_runner
            .get_program_builtins()
            .iter()
            .for_each(|builtin| {
                if builtin_runners.contains_key(builtin.name()) {
                    let b_runner = builtin_runners.get(builtin.name()).unwrap();
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
    ) -> Result<(MaybeRelocatable, MaybeRelocatable), TransactionError> {
        if ptr_offset != 0 {
            return Err(TransactionError::IllegalOsPtrOffset);
        }

        let os_context_end = (self.vm.get_ap() - 2)?;
        let final_os_context_ptr = (os_context_end - os_context.len())?;
        let os_context_ptr = os_context
            .get(ptr_offset)
            .ok_or(TransactionError::InvalidPtrFetch)?
            .to_owned();

        let addr = (final_os_context_ptr + ptr_offset)?;
        let ptr_fetch_from_memory = self
            .vm
            .get_maybe(&addr)
            .ok_or(TransactionError::InvalidPtrFetch)?;

        Ok((os_context_ptr, ptr_fetch_from_memory))
    }

    pub(crate) fn validate_segment_pointers(
        &self,
        segment_base_ptr: &MaybeRelocatable,
        segment_stop_ptr: &MaybeRelocatable,
    ) -> Result<(), TransactionError> {
        let seg_base_ptr = match segment_base_ptr {
            MaybeRelocatable::RelocatableValue(val) => {
                if val.offset != 0 {
                    return Err(TransactionError::InvalidSegBasePtrOffset(val.offset));
                }
                val
            }
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        let expected_stop_ptr = seg_base_ptr
            + self
                .vm
                .get_segment_used_size(seg_base_ptr.segment_index as usize)
                .ok_or(TransactionError::InvalidSegmentSize)?;

        let seg_stop_ptr: Relocatable = match segment_stop_ptr {
            MaybeRelocatable::RelocatableValue(val) => *val,
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        if expected_stop_ptr != seg_stop_ptr {
            return Err(TransactionError::InvalidStopPointer(
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
    ) -> Result<(), TransactionError> {
        // The returned values are os_context, retdata_size, retdata_ptr.
        let os_context_end = (self.vm.get_ap() - 2)?;
        let stack_pointer = os_context_end;

        let stack_ptr = self
            .cairo_runner
            .get_builtins_final_stack(&mut self.vm, stack_pointer)?;

        let final_os_context_ptr = (stack_ptr - 1)?;

        if final_os_context_ptr + initial_os_context.len() != Ok(os_context_end) {
            return Err(TransactionError::OsContextPtrNotEqual);
        }

        // Validate system calls
        let (syscall_base_ptr, syscall_stop_ptr) =
            self.get_os_segment_ptr_range(0, initial_os_context)?;

        self.validate_segment_pointers(&syscall_base_ptr, &syscall_stop_ptr)?;

        self.hint_processor
            .post_run(&mut self.vm, syscall_stop_ptr.try_into()?)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::StarknetRunner;
    use crate::{
        business_logic::{
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::cached_state::CachedState, transaction::error::TransactionError,
        },
        core::syscalls::{
            deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
            deprecated_syscall_handler::DeprecatedSyscallHintProcessor,
            syscall_handler::SyscallHintProcessor,
        },
    };
    use cairo_vm::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
    };

    #[test]
    fn prepare_os_context_test() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let mut vm = VirtualMachine::new(true);

        let os_context = StarknetRunner::<SyscallHintProcessor<CachedState::<InMemoryStateReader>>>::prepare_os_context_cairo0(&cairo_runner, &mut vm);

        // is expected to return a pointer to the first segment as there is nothing more in the vm
        let expected = Vec::from([MaybeRelocatable::from((0, 0))]);

        assert_eq!(os_context, expected);
    }

    #[test]
    fn run_from_entrypoint_should_fail_with_no_exec_base() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        assert!(runner.run_from_entrypoint(1, &[], None).is_err())
    }

    #[test]
    fn get_os_segment_ptr_range_should_fail_when_ptr_offset_is_not_zero() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        assert_matches!(
            runner.get_os_segment_ptr_range(1, vec![]).unwrap_err(),
            TransactionError::IllegalOsPtrOffset
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_when_offset_is_not_zero() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        let relocatable = MaybeRelocatable::RelocatableValue((0, 1).into());
        assert_matches!(
            runner
                .validate_segment_pointers(&relocatable, &relocatable)
                .unwrap_err(),
            TransactionError::InvalidSegBasePtrOffset(1)
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_when_base_is_not_a_value() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        let relocatable = MaybeRelocatable::Int((1).into());
        assert_matches!(
            runner
                .validate_segment_pointers(&relocatable, &relocatable)
                .unwrap_err(),
            TransactionError::NotARelocatableValue
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_with_invalid_segment_size() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        let base = MaybeRelocatable::RelocatableValue((0, 0).into());
        assert_matches!(
            runner.validate_segment_pointers(&base, &base).unwrap_err(),
            TransactionError::InvalidSegmentSize
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_when_stop_is_not_a_value() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let mut vm = VirtualMachine::new(true);
        vm.add_memory_segment();
        vm.compute_segments_effective_sizes();

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        let base = MaybeRelocatable::RelocatableValue((0, 0).into());
        let stop = MaybeRelocatable::Int((1).into());
        assert_matches!(
            runner.validate_segment_pointers(&base, &stop).unwrap_err(),
            TransactionError::NotARelocatableValue
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_with_invalid_stop_pointer() {
        let program = cairo_vm::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all_cairo", false).unwrap();
        let mut vm = VirtualMachine::new(true);
        vm.add_memory_segment();
        vm.compute_segments_effective_sizes();

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor = DeprecatedSyscallHintProcessor::new(
            DeprecatedBLSyscallHandler::default_with(&mut state),
        );

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        let base = MaybeRelocatable::RelocatableValue((0, 0).into());
        let stop = MaybeRelocatable::RelocatableValue((0, 1).into());
        assert_matches!(
            runner.validate_segment_pointers(&base, &stop).unwrap_err(),
            TransactionError::InvalidStopPointer(
                Relocatable {
                    segment_index: 0,
                    offset: 0,
                },
                Relocatable {
                    segment_index: 0,
                    offset: 1
                },
            )
        );
    }
}
