use std::any::Any;
use std::collections::HashMap;

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::syscall_request::*;

use crate::business_logic::execution::objects::*;
use cairo_rs::any_box;
use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
    BuiltinHintProcessor, HintProcessorData,
};
use cairo_rs::hint_processor::builtin_hint_processor::hint_utils::get_relocatable_from_var_name;
use cairo_rs::hint_processor::hint_processor_definition::{HintProcessor, HintReference};
use cairo_rs::serde::deserialize_program::ApTracking;
use cairo_rs::types::exec_scope::ExecutionScopes;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

const DEPLOY_SYSCALL_CODE: &str =
    "syscall_handler.deploy(segments=segments, syscall_ptr=ids.syscall_ptr)";

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
        &mut self,
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
        &mut self,
        vm: &mut VirtualMachine,
        _exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        _constants: &HashMap<String, BigInt>,
    ) -> Result<(), SyscallHandlerError> {
        let hint_data = hint_data
            .downcast_ref::<HintProcessorData>()
            .ok_or(SyscallHandlerError::WrongHintData)?;

        match &*hint_data.code {
            DEPLOY_SYSCALL_CODE => {
                println!("Running deploy syscall.");
                Err(SyscallHandlerError::NotImplemented)
            }
            EMIT_EVENT_CODE => {
                let syscall_ptr = get_syscall_ptr(vm, &hint_data.ids_data, &hint_data.ap_tracking)?;
                self.syscall_handler.emit_event(&vm, syscall_ptr)
            }
            _ => Err(SyscallHandlerError::NotImplemented),
        }
    }
}

pub fn get_syscall_ptr(
    vm: &VirtualMachine,
    ids_data: &HashMap<String, HintReference>,
    ap_tracking: &ApTracking,
) -> Result<Relocatable, SyscallHandlerError> {
    let syscall_ptr = get_relocatable_from_var_name("syscall_ptr", vm, ids_data, ap_tracking).map_err(|_| SyscallHandlerError::SegmentationFault)?;
    Ok(syscall_ptr)
}

impl<H: SyscallHandler> HintProcessor for SyscallHintProcessor<H> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, BigInt>,
    ) -> Result<(), VirtualMachineError> {
        if self.should_run_syscall_hint(vm, exec_scopes, hint_data, constants)? {
            self.execute_syscall_hint(vm, exec_scopes, hint_data, constants).map_err(|_| VirtualMachineError::UnknownHint("hint data".to_string()))?;
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

//* ---------------------
//* SyscallHandler Trait
//* ---------------------

pub(crate) trait SyscallHandler {
    fn emit_event(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;

    fn send_message_to_l1(&self, vm: VirtualMachine, syscall_ptr: Relocatable);
    fn _get_tx_info_ptr(&self, vm: VirtualMachine);
    fn _deploy(&self, vm: VirtualMachine, syscall_ptr: Relocatable) -> i32;

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
            _ => Err(SyscallHandlerError::UnknownSyscall),
        }
    }
}

#[allow(unused)] // TODO: remove after using.
struct OsSyscallHandler {}

//* -----------------------------------
//* BusinessLogicHandler implementation
//* -----------------------------------

pub struct BusinessLogicSyscallHandler {
    tx_execution_context: TransactionExecutionContext,
    events: Vec<OrderedEvent>,
}

impl BusinessLogicSyscallHandler {
    pub fn new() -> Result<Self, SyscallHandlerError> {
        let events = Vec::new();
        let tx_execution_context = TransactionExecutionContext::new();
        Ok(BusinessLogicSyscallHandler {
            events,
            tx_execution_context,
        })
    }
}

impl SyscallHandler for BusinessLogicSyscallHandler {
    // trait functions
    fn emit_event(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let SyscallRequest::EmitEvent(request) =
            self._read_and_validate_syscall_request("emit_event", vm, syscall_ptr)?;

        let keys_len = bigint_to_usize(&request.keys_len)?;
        let data_len = bigint_to_usize(&request.data_len)?;

        let order = self.tx_execution_context.n_emitted_events;
        let keys: Vec<BigInt> = get_integer_range(vm, &request.keys, keys_len)?;
        let data: Vec<BigInt> = get_integer_range(vm, &request.data, data_len)?;

        self.events.push(OrderedEvent::new(order, keys, data));

        // Update events count.
        self.tx_execution_context.n_emitted_events += 1;
        Ok(())
    }

    fn send_message_to_l1(&self, _vm: VirtualMachine, _syscall_ptr: Relocatable) {
        todo!()
    }

    fn _get_tx_info_ptr(&self, _vm: VirtualMachine) {
        todo!()
    }
    fn _deploy(&self, _vm: VirtualMachine, _syscall_ptr: Relocatable) -> i32 {
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

//* -------------------
//* Helper Functions
//* -------------------

pub fn bigint_to_usize(bigint: &BigInt) -> Result<usize, SyscallHandlerError> {
    bigint
        .to_usize()
        .ok_or(SyscallHandlerError::BigintToUsizeFail)
}

fn get_integer_range(
    vm: &VirtualMachine,
    addr: &Relocatable,
    size: usize,
) -> Result<Vec<BigInt>, SyscallHandlerError> {
    Ok(vm
        .get_integer_range(addr, size)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .into_iter()
        .map(|c| c.into_owned())
        .collect::<Vec<BigInt>>())
}

#[cfg(test)]
mod tests {
    use crate::business_logic::execution::objects::OrderedEvent;
    use crate::core::syscall_handler::{SyscallHandler, SyscallHintProcessor, DEPLOY_SYSCALL_CODE};
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
    use std::str::FromStr;

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

    #[test]
    fn emit_event_test() {
        let mut syscall_handler = SyscallHintProcessor::new_empty().unwrap().syscall_handler;
        let mut vm = vm!();
        add_segments!(vm, 3);
        // insert selector of syscall
        let selector = BigInt::from_str("1280709301550335749748").unwrap();
        vm.insert_value(&Relocatable::from((1, 0)), selector)
            .unwrap();

        // keys_len
        let keys_len = BigInt::from_str("2").unwrap();
        vm.insert_value(&Relocatable::from((1, 1)), keys_len)
            .unwrap();

        // keys
        let keys = Relocatable::from((2, 0));
        vm.insert_value(&Relocatable::from((1, 2)), keys).unwrap();

        // data_len
        let data_len = BigInt::from_str("2").unwrap();
        vm.insert_value(&Relocatable::from((1, 3)), data_len)
            .unwrap();

        // data
        let data = Relocatable::from((2, 3));
        vm.insert_value(&Relocatable::from((1, 4)), data).unwrap();

        let syscall_ptr = Relocatable::from((1, 0));

        // insert keys and data to generate the event
        // keys points to (2,0)
        let key1 = BigInt::from_str("1").unwrap();
        vm.insert_value(&Relocatable::from((2, 0)), key1).unwrap();
        let key2 = BigInt::from_str("1").unwrap();
        vm.insert_value(&Relocatable::from((2, 1)), key2).unwrap();

        // data points to (2,3)
        let data1 = BigInt::from_str("1").unwrap();
        vm.insert_value(&Relocatable::from((2, 3)), data1).unwrap();
        let data2 = BigInt::from_str("1").unwrap();
        vm.insert_value(&Relocatable::from((2, 4)), data2).unwrap();

        // invoke syscall
        syscall_handler.emit_event(&vm, syscall_ptr).unwrap();

        let event = syscall_handler.events[0].clone();

        assert_eq!(
            OrderedEvent::new(
                0,
                Vec::from([
                    BigInt::from_str("1").unwrap(),
                    BigInt::from_str("1").unwrap()
                ]),
                Vec::from([
                    BigInt::from_str("1").unwrap(),
                    BigInt::from_str("1").unwrap()
                ])
            ),
            event
        );
        assert_eq!(syscall_handler.tx_execution_context.n_emitted_events, 1);
    }
}
