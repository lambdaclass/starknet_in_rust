use std::any::Any;
use std::collections::HashMap;

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::syscall_request::*;

use cairo_rs::any_box;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};

const DEPLOY_SYSCALL_CODE: &str =
    "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";

pub struct OrderedEvent {
    #[allow(unused)] // TODO: Remove once used.
    keys: Vec<BigInt>,
    #[allow(unused)] // TODO: Remove once used.
    data: Vec<BigInt>,
}

pub(crate) struct SyscallHintProcessor<H: SyscallHandler> {
    builtin_hint_processor: BuiltinHintProcessor,
    #[allow(unused)] // TODO: remove after using.
    syscall_handler: H,
}

impl SyscallHintProcessor<BusinessLogicSyscallHandler> {
    #[allow(unused)] // TODO: Remove once used.
    pub fn new_empty(
    ) -> Result<SyscallHintProcessor<BusinessLogicSyscallHandler>, SyscallHandlerError> {
        Ok(SyscallHintProcessor {
            builtin_hint_processor: BuiltinHintProcessor::new_empty(),
            syscall_handler: BusinessLogicSyscallHandler::new()?,
        })
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
        _vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(VirtualMachineError::WrongHintData)?;

        match &*hint_data.code {
            DEPLOY_SYSCALL_CODE => {
                println!("Running deploy syscall.");
                Err(VirtualMachineError::NotImplemented)
            }
            _ => Err(VirtualMachineError::NotImplemented),
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
            self.execute_syscall_hint(vm, exec_scopes, hint_data, constants)?;
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

pub(crate) trait SyscallHandler {
    fn emit_event(
        &self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;
    fn send_message_to_l1(&self, vm: VirtualMachine, syscall_ptr: Relocatable);
    fn _get_tx_info_ptr(&self, vm: VirtualMachine);
    fn _deploy(
        &self,
        vm: VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<i32, SyscallHandlerError>;
    fn _read_and_validate_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
    fn _call_contract(
        &self,
        syscall_name: &str,
        vm: VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Vec<i32>;
    fn _get_caller_address(&self, vm: VirtualMachine, syscall_ptr: Relocatable) -> i32;
    fn _get_contract_address(&self, vm: VirtualMachine, syscall_ptr: Relocatable) -> i32;
    fn _storage_read(&self, address: i32) -> i32;
    fn _storage_write(&self, address: i32, value: i32);
    fn _allocate_segment(&self, vm: VirtualMachine, data: Vec<MaybeRelocatable>) -> Relocatable;

    fn read_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "emit_event" => EmitEventStruct::from_ptr(vm, syscall_ptr),
            "deploy" => DeployRequestStruct::from_ptr(vm, syscall_ptr),
            _ => Err(SyscallHandlerError::UnknownSyscall),
        }
    }
}

#[allow(unused)] // TODO: remove after using.
struct OsSyscallHandler {}

pub struct BusinessLogicSyscallHandler {
    contract_address: u64,
}

impl BusinessLogicSyscallHandler {
    pub fn new() -> Result<Self, SyscallHandlerError> {
        Ok(BusinessLogicSyscallHandler {
            contract_address: 0,
        })
    }
}

pub fn bigint_to_usize(bigint: &BigInt) -> Result<usize, SyscallHandlerError> {
    bigint
        .to_usize()
        .ok_or(SyscallHandlerError::BigintToUsizeFail)
}

impl SyscallHandler for BusinessLogicSyscallHandler {
    // trait functions
    fn emit_event(
        &self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = if let SyscallRequest::EmitEvent(request) =
            self._read_and_validate_syscall_request("emit_event", vm, syscall_ptr)?
        {
            request
        } else {
            panic!()
        };
        let keys_len = bigint_to_usize(&request.keys_len)?;
        let data_len = bigint_to_usize(&request.data_len)?;

        #[allow(unused)] // TODO: Remove once used.
        let keys: Vec<BigInt> = vm
            .get_integer_range(&request.keys, keys_len)
            .map_err(|_| SyscallHandlerError::SegmentationFault)?
            .into_iter()
            .map(|c| c.into_owned())
            .collect();

        #[allow(unused)] // TODO: Remove once used.
        let data: Vec<BigInt> = vm
            .get_integer_range(&request.data, data_len)
            .map_err(|_| SyscallHandlerError::SegmentationFault)?
            .into_iter()
            .map(|c| c.into_owned())
            .collect();

        Ok(())
    }
    fn send_message_to_l1(&self, _vm: VirtualMachine, _syscall_ptr: Relocatable) {
        todo!()
    }

    fn _get_tx_info_ptr(&self, _vm: VirtualMachine) {
        todo!()
    }
    fn _deploy(
        &self,
        vm: VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<i32, SyscallHandlerError> {
        let request = if let SyscallRequest::Deploy(request) =
            self._read_and_validate_syscall_request("emit_event", &vm, syscall_ptr)?
        {
            request
        } else {
            panic!()
        };

        if !(request.deploy_from_zero.is_zero() || request.deploy_from_zero.is_one()) {
            // "The deploy_from_zero field in the deploy system call must be 0 or 1."
            panic!();
        };

        let constructor_calldata = vm.get_integer_range(
            &request.constructor_calldata,
            bigint_to_usize(&request.constructor_calldata_size)?,
        );

        let class_hash = &request.class_hash;

        let deployer_address = if request.deploy_from_zero.is_zero() {
            self.contract_address
        } else {
            0
        };

        todo!()
    }

    fn _read_and_validate_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        self.read_syscall_request(syscall_name, vm, syscall_ptr)
    }

    fn _call_contract(
        &self,
        _syscall_name: &str,
        _vm: VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Vec<i32> {
        todo!()
    }
    fn _get_caller_address(&self, _vm: VirtualMachine, _syscall_ptr: Relocatable) -> i32 {
        todo!()
    }
    fn _get_contract_address(&self, _vm: VirtualMachine, _syscall_ptr: Relocatable) -> i32 {
        todo!()
    }
    fn _storage_read(&self, _address: i32) -> i32 {
        todo!()
    }
    fn _storage_write(&self, _address: i32, _value: i32) {
        todo!()
    }
    fn _allocate_segment(&self, _vm: VirtualMachine, _data: Vec<MaybeRelocatable>) -> Relocatable {
        todo!()
    }
}

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
