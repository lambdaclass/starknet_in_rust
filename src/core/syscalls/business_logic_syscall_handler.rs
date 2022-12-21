use std::cell::RefCell;
use std::rc::Rc;

use super::syscall_request::*;
use crate::business_logic::execution::objects::*;
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::core::syscalls::syscall_handler::SyscallHandler;
use crate::hash_utils::calculate_contract_address_from_hash;
use crate::utils::*;
use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;
use num_traits::{One, Zero};

//* -----------------------------------
//* BusinessLogicHandler implementation
//* -----------------------------------

pub struct BusinessLogicSyscallHandler {
    tx_execution_context: Rc<RefCell<TransactionExecutionContext>>,
    events: Rc<RefCell<Vec<OrderedEvent>>>,
    contract_address: u64,
    l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
}

impl BusinessLogicSyscallHandler {
    pub fn new() -> Self {
        let events = Rc::new(RefCell::new(Vec::new()));
        let tx_execution_context = Rc::new(RefCell::new(TransactionExecutionContext::new()));
        BusinessLogicSyscallHandler {
            events,
            tx_execution_context,
            contract_address: 0,
            l2_to_l1_messages: Vec::new(),
        }
    }
}

impl Default for BusinessLogicSyscallHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallHandler for BusinessLogicSyscallHandler {
    fn emit_event(
        &self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = match self._read_and_validate_syscall_request("emit_event", vm, syscall_ptr) {
            Ok(SyscallRequest::EmitEvent(emit_event_struct)) => emit_event_struct,
            _ => return Err(SyscallHandlerError::InvalidSyscallReadRequest),
        };

        let keys_len = request.keys_len;
        let data_len = request.data_len;

        let order = self.tx_execution_context.borrow_mut().n_emitted_events;
        let keys: Vec<BigInt> = get_integer_range(vm, &request.keys, keys_len)?;
        let data: Vec<BigInt> = get_integer_range(vm, &request.data, data_len)?;

        self.events
            .borrow_mut()
            .push(OrderedEvent::new(order, keys, data));

        // Update events count.
        self.tx_execution_context.borrow_mut().n_emitted_events += 1;
        Ok(())
    }

    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        let request = if let SyscallRequest::SendMessageToL1(request) =
            self._read_and_validate_syscall_request("send_message_to_l1", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedSendMessageToL1);
        };

        let payload = get_integer_range(vm, &request.payload_ptr, request.payload_size)?;

        self.l2_to_l1_messages.push(OrderedL2ToL1Message::new(
            self.tx_execution_context.borrow().n_sent_messages,
            request.to_address,
            payload,
        ));

        // Update messages count.
        self.tx_execution_context.borrow_mut().n_sent_messages += 1;
        Ok(())
    }
    fn library_call(
        &self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        self._call_contract_and_write_response("library_call", vm, syscall_ptr);
        Ok(())
    }

    fn _get_tx_info_ptr(&self, _vm: VirtualMachine) {
        todo!()
    }

    fn _deploy(
        &self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<i32, SyscallHandlerError> {
        let request = if let SyscallRequest::Deploy(request) =
            self._read_and_validate_syscall_request("deploy", vm, syscall_ptr)?
        {
            request
        } else {
            return Err(SyscallHandlerError::ExpectedDeployRequestStruct);
        };

        if !(request.deploy_from_zero.is_zero() || request.deploy_from_zero.is_one()) {
            return Err(SyscallHandlerError::DeployFromZero(
                request.deploy_from_zero,
            ));
        };

        let constructor_calldata = get_integer_range(
            vm,
            &request.constructor_calldata,
            bigint_to_usize(&request.constructor_calldata_size)?,
        )?;

        let class_hash = &request.class_hash;

        let deployer_address = if request.deploy_from_zero.is_zero() {
            self.contract_address
        } else {
            0
        };

        let _contract_address = calculate_contract_address_from_hash(
            &request.contract_address_salt,
            class_hash,
            &constructor_calldata,
            deployer_address,
        )?;

        // Initialize the contract.
        let (_sign, _class_hash_bytes) = request.class_hash.to_bytes_be();

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

    fn _call_contract_and_write_response(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) {
        let response_data = self._call_contract(syscall_name, vm, syscall_ptr.clone());
        // TODO: Should we build a response struct to pass to _write_syscall_response?
        self._write_syscall_response(response_data, vm, syscall_ptr);
    }

    fn _call_contract(
        &self,
        _syscall_name: &str,
        _vm: &VirtualMachine,
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
    fn _write_syscall_response(
        &self,
        _response: Vec<i32>,
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::bigint;
    use crate::business_logic::execution::objects::OrderedEvent;
    use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
    use crate::core::syscalls::business_logic_syscall_handler::BusinessLogicSyscallHandler;
    use crate::core::syscalls::hint_code::{DEPLOY_SYSCALL_CODE, EMIT_EVENT_CODE};
    use crate::core::syscalls::syscall_handler::*;
    use crate::utils::test_utils::*;
    use cairo_rs::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::{
        BuiltinHintProcessor, HintProcessorData,
    };
    use cairo_rs::hint_processor::hint_processor_definition::HintProcessor;
    use cairo_rs::relocatable;
    use cairo_rs::types::exec_scope::ExecutionScopes;
    use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
    use cairo_rs::vm::errors::memory_errors::MemoryError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError;
    use cairo_rs::vm::errors::vm_errors::VirtualMachineError::UnknownHint;
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
            Err(UnknownHint("Hint not implemented".to_string()))
        );
    }

    #[test]
    fn emit_event_test() {
        // create data and variables to execute hint

        let mut vm = vm!();
        add_segments!(vm, 4);

        // insert selector of syscall
        let selector = BigInt::from_str("1280709301550335749748").unwrap();

        // keys_len
        let keys_len = BigInt::from_str("2").unwrap();
        // data_len
        let data_len = BigInt::from_str("2").unwrap();

        // insert keys and data to generate the event
        // keys points to (2,0)
        let key1 = BigInt::from_str("1").unwrap();
        let key2 = BigInt::from_str("1").unwrap();

        // data points to (2,3)
        let data1 = BigInt::from_str("1").unwrap();
        let data2 = BigInt::from_str("1").unwrap();

        memory_insert!(
            vm,
            [
                ((1, 0), (2, 0)),
                ((2, 0), selector),
                ((2, 1), (keys_len)),
                ((2, 2), (3, 0)),
                ((2, 3), data_len),
                ((2, 4), (3, 3)),
                ((3, 0), key1),
                ((3, 1), key2),
                ((3, 3), data1),
                ((3, 4), data2)
            ]
        );
        // syscall_ptr
        let ids_data = ids_data!["syscall_ptr"];

        let hint_data = HintProcessorData::new_default(EMIT_EVENT_CODE.to_string(), ids_data);
        // invoke syscall
        let syscall_handler = SyscallHintProcessor::new_empty().unwrap();
        syscall_handler
            .execute_hint(
                &mut vm,
                &mut ExecutionScopes::new(),
                &any_box!(hint_data),
                &HashMap::new(),
            )
            .unwrap();

        let event = syscall_handler
            .syscall_handler
            .events
            .borrow()
            .get(0)
            .unwrap()
            .clone();

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
        assert_eq!(
            syscall_handler
                .syscall_handler
                .tx_execution_context
                .borrow()
                .n_emitted_events,
            1
        );
    }

    #[test]
    fn deploy_from_zero_error() {
        let syscall = BusinessLogicSyscallHandler::new();
        let mut vm = vm!();

        add_segments!(vm, 2);

        vm.insert_value(&relocatable!(1, 0), bigint!(0)).unwrap();
        vm.insert_value(&relocatable!(1, 1), bigint!(1)).unwrap();
        vm.insert_value(&relocatable!(1, 2), bigint!(2)).unwrap();
        vm.insert_value(&relocatable!(1, 3), bigint!(3)).unwrap();
        vm.insert_value(&relocatable!(1, 4), relocatable!(1, 20))
            .unwrap();
        vm.insert_value(&relocatable!(1, 5), bigint!(4)).unwrap();

        assert_eq!(
            syscall._deploy(&vm, relocatable!(1, 0)),
            Err(SyscallHandlerError::DeployFromZero(4))
        )
    }
}
