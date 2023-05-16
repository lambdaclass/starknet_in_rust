use super::business_logic_syscall_handler::BusinessLogicSyscallHandler;
use crate::business_logic::state::state_api::{State, StateReader};
use crate::business_logic::transaction::error::TransactionError;
use cairo_vm::felt::Felt252;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;
use cairo_vm::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_vm::serde::deserialize_program::ApTracking;
use cairo_vm::types::exec_scope::ExecutionScopes;
use cairo_vm::types::relocatable::Relocatable;
use cairo_vm::vm::errors::hint_errors::HintError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::vm_core::VirtualMachine;
use std::{any::Any, boxed::Box, collections::HashMap};

pub(crate) trait HintProcessorPostRun {
    /// Performs post run syscall related tasks (if any).
    fn post_run(
        &self,
        _runner: &mut VirtualMachine,
        _syscall_stop_ptr: Relocatable,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

#[allow(unused)]
pub(crate) struct SyscallHintProcessor<'a, T: State + StateReader> {
    pub(crate) builtin_hint_processor: BuiltinHintProcessor,
    pub(crate) syscall_handler: BusinessLogicSyscallHandler<'a, T>,
}

impl<'a, T: State + StateReader> SyscallHintProcessor<'a, T> {
    pub fn new(syscall_handler: BusinessLogicSyscallHandler<'a, T>) -> Self {
        SyscallHintProcessor {
            builtin_hint_processor: BuiltinHintProcessor::new_empty(),
            syscall_handler,
        }
    }
}

impl<'a, T: State + StateReader> HintProcessor for SyscallHintProcessor<'a, T> {
    fn execute_hint(
        &mut self,
        _vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        _hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, Felt252>,
    ) -> Result<(), HintError> {
        // TODO
        Ok(())
    }

    fn compile_hint(
        &self,
        _hint_code: &str,
        _ap_tracking_data: &ApTracking,
        _reference_ids: &HashMap<String, usize>,
        _references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        // TODO
        Ok(Box::new(()))
    }
}

impl<'a, T: State + StateReader> HintProcessorPostRun for SyscallHintProcessor<'a, T> {
    fn post_run(
        &self,
        _runner: &mut VirtualMachine,
        _syscall_stop_ptr: Relocatable,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}
