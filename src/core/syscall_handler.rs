use std::any::Any;
use std::collections::HashMap;

use cairo_rs::any_box;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

pub struct SyscallHintProcessor<H: SyscallHandler> {
    builtin_hint_processor: BuiltinHintProcessor,
    syscall_handler: H,
}

impl SyscallHintProcessor<BusinessLogicSyscallHandler> {
    pub fn new_empty() -> SyscallHintProcessor<BusinessLogicSyscallHandler> {
        SyscallHintProcessor {
            builtin_hint_processor: BuiltinHintProcessor::new_empty(),
            syscall_handler: BusinessLogicSyscallHandler,
        }
    }
}
impl<H: SyscallHandler> SyscallHintProcessor<H> {
    pub fn should_run_syscall_hint(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<bool, VirtualMachineError> {
        match self
            .builtin_hint_processor
            .execute_hint(vm, exec_scopes, hint_data, constants)
        {
            Ok(()) => Ok(false),
            Err(VirtualMachineError::UnknownHint(_)) => Ok(true),
            Err(e) => Err(e),
        }
    }

    fn execute_syscall_hint(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &dyn Any,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        println!("Hello from SyscallHintProcessor");
        Err(VirtualMachineError::NotImplemented)
    }
}

impl<H: SyscallHandler> HintProcessor for SyscallHintProcessor<H> {
    fn execute_hint(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn std::any::Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        if self.should_run_syscall_hint(vm, exec_scopes, hint_data, constants)? {
            self.execute_syscall_hint(vm, exec_scopes, hint_data, constants)?
        }

        Ok(())
    }

    fn compile_hint(
        &self,
        hint_code: &str,
        ap_tracking_data: &cairo_rs::serde::deserialize_program::ApTracking,
        reference_ids: &std::collections::HashMap<String, usize>,
        references: &std::collections::HashMap<
            usize,
            cairo_rs::hint_processor::hint_processor_definition::HintReference,
        >,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        Ok(any_box!(HintProcessorData {
            code: hint_code.to_string(),
            ap_tracking: ap_tracking_data.clone(),
            ids_data: get_ids_data(reference_ids, references)?,
        }))
    }
}

fn get_ids_data(
    reference_ids: &HashMap<String, usize>,
    references: &HashMap<usize, HintReference>,
) -> Result<HashMap<String, HintReference>, VirtualMachineError> {
    let mut ids_data = HashMap::<String, HintReference>::new();
    for (path, ref_id) in reference_ids {
        let name = path
            .rsplit('.')
            .next()
            .ok_or(VirtualMachineError::FailedToGetIds)?;
        ids_data.insert(
            name.to_string(),
            references
                .get(ref_id)
                .ok_or(VirtualMachineError::FailedToGetIds)?
                .clone(),
        );
    }
    Ok(ids_data)
}

pub trait SyscallHandler {}

struct OsSyscallHandler;

pub struct BusinessLogicSyscallHandler;

impl SyscallHandler for BusinessLogicSyscallHandler {}

macro_rules! vm {
    () => {{
        VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            false,
            Vec::new(),
        )
    }};

    ($use_trace:expr) => {{
        VirtualMachine::new(
            BigInt::new(Sign::Plus, vec![1, 0, 0, 0, 0, 0, 17, 134217728]),
            $use_trace,
            Vec::new(),
        )
    }};
}

#[cfg(test)]
mod tests {
    use crate::core::syscall_handler::SyscallHintProcessor;
    use cairo_rs::any_box;
    use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
    use cairo_rs::types::exec_scope::ExecutionScopes;
    use cairo_rs::types::relocatable::MaybeRelocatable;
    use cairo_rs::vm::errors::memory_errors::MemoryError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
    use cairo_rs::vm::vm_core::VirtualMachine;
    use cairo_rs::vm::vm_memory::memory::Memory;
    use num_bigint::{BigInt, Sign};
    use std::any::Any;
    use std::collections::HashMap;

    macro_rules! mayberelocatable {
        ($val1 : expr, $val2 : expr) => {
            MaybeRelocatable::from(($val1, $val2))
        };
        ($val1 : expr) => {
            MaybeRelocatable::from((bigint!($val1)))
        };
    }

    macro_rules! memory_inner {
        ($mem:expr, ($si:expr, $off:expr), ($sival:expr, $offval: expr)) => {
            let (k, v) = (
                &mayberelocatable!($si, $off),
                &mayberelocatable!($sival, $offval),
            );
            let mut res = $mem.insert(k, v);
            while matches!(res, Err(MemoryError::UnallocatedSegment(_, _))) {
                $mem.data.push(Vec::new());
                res = $mem.insert(k, v);
            }
        };
        ($mem:expr, ($si:expr, $off:expr), $val:expr) => {
            let (k, v) = (&mayberelocatable!($si, $off), &mayberelocatable!($val));
            let mut res = $mem.insert(k, v);
            while matches!(res, Err(MemoryError::UnallocatedSegment(_, _))) {
                $mem.data.push(Vec::new());
                res = $mem.insert(k, v);
            }
        };
    }

    macro_rules! memory_from_memory {
        ($mem: expr, ( $( (($si:expr, $off:expr), $val:tt) ),* )) => {
            {
                $(
                    memory_inner!($mem, ($si, $off), $val);
                )*
            }
        };
    }

    macro_rules! memory {
        ( $( (($si:expr, $off:expr), $val:tt) ),* ) => {
            {
                let mut memory = Memory::new();
                memory_from_memory!(memory, ( $( (($si, $off), $val) ),* ));
                memory
            }
        };
    }

    macro_rules! add_segments {
        ($vm:expr, $n:expr) => {
            for _ in 0..$n {
                $vm.segments.add(&mut $vm.memory);
            }
        };
    }

    macro_rules! exec_scopes_ref {
        () => {
            &mut ExecutionScopes::new()
        };
    }

    macro_rules! run_hint {
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr, $constants:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(&mut $vm, $exec_scopes, &any_box!(hint_data), $constants)
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                $exec_scopes,
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                exec_scopes_ref!(),
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
    }

    macro_rules! run_syscall_hint {
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr, $constants:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(&mut $vm, $exec_scopes, &any_box!(hint_data), $constants)
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr, $exec_scopes:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = BuiltinHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                $exec_scopes,
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
        ($vm:expr, $ids_data:expr, $hint_code:expr) => {{
            let hint_data = HintProcessorData::new_default($hint_code.to_string(), $ids_data);
            let hint_processor = SyscallHintProcessor::new_empty();
            hint_processor.execute_hint(
                &mut $vm,
                exec_scopes_ref!(),
                &any_box!(hint_data),
                &HashMap::new(),
            )
        }};
    }

    #[test]
    fn run_alloc_hint_ap_is_not_empty() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //Add 3 segments to the memory
        add_segments!(vm, 3);
        vm.run_context.ap = 6;
        //Insert something into ap
        vm.memory = memory![((1, 6), (1, 6))];
        //ids and references are not needed for this test
        assert_eq!(
            run_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::MemoryError(
                MemoryError::InconsistentMemory(
                    MaybeRelocatable::from((1, 6)),
                    MaybeRelocatable::from((1, 6)),
                    MaybeRelocatable::from((3, 0))
                )
            ))
        );
    }

    // tests that we are executing correctly our syscall hint processor.
    #[test]
    fn cannot_run_syscall_hints() {
        let hint_code = "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";
        let mut vm = vm!();
        //Add 3 segments to the memory
        add_segments!(vm, 3);
        vm.run_context.ap = 6;
        //Insert something into ap
        vm.memory = memory![((1, 6), (1, 6))];
        //ids and references are not needed for this test
        assert_eq!(
            run_syscall_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::NotImplemented)
        );
    }
}
