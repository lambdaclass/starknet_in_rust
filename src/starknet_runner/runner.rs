use super::starknet_runner_error::StarknetRunnerError;
use crate::{
    business_logic::transaction::error::TransactionError,
    core::syscalls::deprecated_syscall_handler::{
        DeprecatedSyscallHandler, SyscallHandlerPostRun, SyscallHintProcessor,
    },
};
use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::{
        runners::{
            builtin_runner::BuiltinRunner,
            cairo_runner::{CairoArg, CairoRunner, ExecutionResources},
        },
        vm_core::VirtualMachine,
    },
};
use felt::Felt252;
use num_traits::ToPrimitive;
use std::{borrow::Cow, collections::HashMap};

pub(crate) struct StarknetRunner<H>
where
    H: DeprecatedSyscallHandler,
{
    pub(crate) cairo_runner: CairoRunner,
    pub(crate) vm: VirtualMachine,
    pub(crate) hint_processor: SyscallHintProcessor<H>,
}

impl<H> StarknetRunner<H>
where
    H: DeprecatedSyscallHandler,
{
    pub fn map_hint_processor<H2>(
        self,
        hint_processor: SyscallHintProcessor<H2>,
    ) -> StarknetRunner<H2>
    where
        H2: DeprecatedSyscallHandler,
    {
        StarknetRunner {
            cairo_runner: self.cairo_runner,
            vm: self.vm,
            hint_processor,
        }
    }

    pub fn new(
        cairo_runner: CairoRunner,
        vm: VirtualMachine,
        hint_processor: SyscallHintProcessor<H>,
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
    ) -> Result<(), TransactionError> {
        let verify_secure = true;
        let args: Vec<&CairoArg> = args.iter().map(ToOwned::to_owned).collect();

        self.cairo_runner.run_from_entrypoint(
            entrypoint,
            &args,
            verify_secure,
            &mut self.vm,
            &mut self.hint_processor,
        )?;
        Ok(())
    }

    pub fn get_execution_resources(&self) -> Result<ExecutionResources, TransactionError> {
        let execution_resources = self.cairo_runner.get_execution_resources(&self.vm)?;

        Ok(ExecutionResources {
            builtin_instance_counter: execution_resources
                .builtin_instance_counter
                .into_iter()
                .map(|(name, counter)| (format!("{name}_builtin"), counter))
                .collect(),
            ..execution_resources
        })
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

    pub(crate) fn prepare_os_context(&mut self) -> Vec<MaybeRelocatable> {
        let syscall_segment = self.vm.add_memory_segment();
        let mut os_context = [syscall_segment.into()].to_vec();
        let builtin_runners = self
            .vm
            .get_builtin_runners()
            .clone()
            .into_iter()
            .map(|runner| (runner.name(), runner))
            .collect::<HashMap<&str, BuiltinRunner>>();
        self.cairo_runner
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
    ) -> Result<(), TransactionError>
    where
        H: SyscallHandlerPostRun,
    {
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
            .syscall_handler
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
        core::syscalls::deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
    };
    use cairo_rs::{
        types::relocatable::{MaybeRelocatable, Relocatable},
        vm::{runners::cairo_runner::CairoRunner, vm_core::VirtualMachine},
    };
    use coverage_helper::test;

    type SyscallHintProcessor<'a> =
        crate::core::syscalls::deprecated_syscall_handler::SyscallHintProcessor<
            DeprecatedBLSyscallHandler<'a, CachedState<InMemoryStateReader>>,
        >;

    #[test]
    fn prepare_os_context_test() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        let os_context = runner.prepare_os_context();

        // is expected to return a pointer to the first segment as there is nothing more in the vm
        let expected = Vec::from([MaybeRelocatable::from((0, 0))]);

        assert_eq!(os_context, expected);
    }

    #[test]
    fn run_from_entrypoint_should_fail_with_no_exec_base() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        assert!(runner.run_from_entrypoint(1, &[]).is_err())
    }

    #[test]
    fn get_os_segment_ptr_range_should_fail_when_ptr_offset_is_not_zero() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        assert_matches!(
            runner.get_os_segment_ptr_range(1, vec![]).unwrap_err(),
            TransactionError::IllegalOsPtrOffset
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_when_offset_is_not_zero() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

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
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

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
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let vm = VirtualMachine::new(true);

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

        let runner = StarknetRunner::new(cairo_runner, vm, hint_processor);
        let base = MaybeRelocatable::RelocatableValue((0, 0).into());
        assert_matches!(
            runner.validate_segment_pointers(&base, &base).unwrap_err(),
            TransactionError::InvalidSegmentSize
        );
    }

    #[test]
    fn validate_segment_pointers_should_fail_when_stop_is_not_a_value() {
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let mut vm = VirtualMachine::new(true);
        vm.add_memory_segment();
        vm.compute_segments_effective_sizes();

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

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
        let program = cairo_rs::types::program::Program::default();
        let cairo_runner = CairoRunner::new(&program, "all", false).unwrap();
        let mut vm = VirtualMachine::new(true);
        vm.add_memory_segment();
        vm.compute_segments_effective_sizes();

        let mut state = CachedState::<InMemoryStateReader>::default();
        let hint_processor =
            SyscallHintProcessor::new(DeprecatedBLSyscallHandler::default_with(&mut state));

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
