use std::any::Any;
use std::collections::HashMap;

use cairo_rs::any_box;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;


const DEPLOY_SYSCALL_CODE: &str = "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";

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
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        println!("Hello from SyscallHintProcessor");

        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;

        match &*hint_data.code {
            DEPLOY_SYSCALL_CODE => {
                println!("Running deploy syscall.");
                Err(VirtualMachineError::NotImplemented)
            },
            _ => Err(VirtualMachineError::NotImplemented)
        }
    }
}

impl<H: SyscallHandler> HintProcessor for SyscallHintProcessor<H> {
    fn execute_hint(
        &self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
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

struct OsSyscallHandler {
    tx_execution_info_iterator: Box<dyn Iterator<Item= usize>>,
    call_iterator: Box<dyn Iterator<Item= usize>>,
    //  A stack that keeps track of the state of the calls being executed now.
    // The last item is the state of the current call; the one before it, is the
    // state of the caller (the call the called the current call); and so on.
    call_stack: Vec<usize>,
    // An iterator over contract addresses that were deployed during that call.
    deployed_contracts_iterator: Box<dyn Iterator<Item= usize>>,
    // An iterator to the retdata of its internal calls.
    retdata_iterator: Box<dyn Iterator<Item= usize>>,
    // An iterator to the read_values array which is consumed when the transaction
    // code is executed.
    execute_code_read_iterator: Box<dyn Iterator<Item= usize>>,
    // StarkNet storage members.
    starknet_storage_by_address: HashMap<usize, usize>,
    // A pointer to the Cairo TxInfo struct.
    // This pointer needs to match the TxInfo pointer that is going to be used during the system
    // call validation by the StarkNet OS.
    // Set during enter_tx.
    tx_info_ptr: Option<Relocatable>,
    // The TransactionExecutionInfo for the transaction currently being executed.
    tx_execution_info: Option<usize>,
}

impl OsSyscallHandler {
    fn skip_tx(&mut self) -> Option<usize> {
        self.tx_execution_info_iterator.next()
    }

    fn _storage_read(&mut self) -> Option<usize> {
        self.execute_code_read_iterator.next()
    }

    fn _get_tx_info_ptr(self) -> Option<Relocatable> {
        self.tx_info_ptr
    }

    fn _call_contract(&mut self) -> Option<usize> {
        self.retdata_iterator.next()
    }

    fn _deploy(&mut self) -> Option<usize> {
        // let constructor_retdata = self.retdata_iterator.next();
        // assert len(constructor_retdata) == 0, "Unexpected constructor_retdata."
        self.deployed_contracts_iterator.next()
    }
}
pub struct BusinessLogicSyscallHandler;

impl SyscallHandler for BusinessLogicSyscallHandler {}

#[cfg(test)]
mod tests {
    use crate::core::syscall_handler::{SyscallHintProcessor, DEPLOY_SYSCALL_CODE};
    use crate::utils::test_utils::*;
    use cairo_rs::any_box;
    use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
    use cairo_rs::types::exec_scope::ExecutionScopes;
    use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_rs::vm::errors::memory_errors::MemoryError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
    use cairo_rs::vm::vm_core::VirtualMachine;
    use num_bigint::{BigInt, Sign};
    use std::any::Any;
    use std::collections::HashMap;

    #[test]
    fn run_alloc_hint_ap_is_not_empty() {
        let hint_code = "memory[ap] = segments.add()";
        let mut vm = vm!();
        //Add 3 segments to the memory
        add_segments!(vm, 3);
        vm.set_ap(6);
        //Insert something into ap
        let key = Relocatable::from((1, 6));
        vm.insert_value(&key, (1, 6)).unwrap();
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
        let hint_code = DEPLOY_SYSCALL_CODE;
        let mut vm = vm!();
        assert_eq!(
            run_syscall_hint!(vm, HashMap::new(), hint_code),
            Err(VirtualMachineError::NotImplemented)
        );
    }
}
