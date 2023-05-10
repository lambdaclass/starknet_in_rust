use super::business_logic_syscall_handler::BusinessLogicSyscallHandler;
use super::syscall_request::{EmitEventRequest, GetBlockTimestampRequest, StorageReadRequest};
use super::{
    syscall_request::{
        CallContractRequest, DeployRequest, FromPtr, LibraryCallRequest, SendMessageToL1Request,
        StorageWriteRequest, SyscallRequest,
    },
    syscall_response::{DeployResponse, FailureReason, ResponseBody, SyscallResponse},
};
use crate::business_logic::state::state_api::{State, StateReader};
use crate::business_logic::transaction::error::TransactionError;
use crate::core::errors::state_errors::StateError;
use crate::{
    business_logic::execution::objects::CallResult,
    core::errors::syscall_handler_errors::SyscallHandlerError, utils::Address,
};
use cairo_lang_casm::hints::Hint;
use cairo_vm::hint_processor::hint_processor_definition::HintReference;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::{
    felt::Felt252,
    hint_processor::{
        cairo_1_hint_processor::hint_processor::Cairo1HintProcessor,
        hint_processor_definition::HintProcessor,
    },
    types::{
        exec_scope::ExecutionScopes,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{errors::hint_errors::HintError, vm_core::VirtualMachine},
};
use num_traits::Zero;
use std::{any::Any, boxed::Box, collections::HashMap, ops::Add};

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
pub(crate) trait SyscallHandler {
    fn get_block_timestamp(
        &mut self,
        vm: &VirtualMachine,
        request: GetBlockTimestampRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn emit_event(
        &mut self,
        vm: &VirtualMachine,
        request: EmitEventRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn get_block_number(
        &mut self,
        vm: &mut VirtualMachine,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn storage_read(
        &mut self,
        _vm: &VirtualMachine,
        request: StorageReadRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        if request.reserved != Felt252::zero() {
            return Err(SyscallHandlerError::UnsupportedAddressDomain(
                request.reserved.to_string(),
            ));
        }

        let value = self._storage_read(request.key)?;

        Ok(SyscallResponse {
            gas: remaining_gas,
            body: Some(ResponseBody::StorageReadResponse { value: Some(value) }),
        })
    }

    fn _storage_read(&mut self, key: [u8; 32]) -> Result<Felt252, StateError>;
    fn syscall_deploy(
        &mut self,
        vm: &VirtualMachine,
        syscall_request: DeployRequest,
        remaining_gas: u64,
    ) -> Result<(Address, CallResult), SyscallHandlerError>;

    fn deploy(
        &mut self,
        vm: &mut VirtualMachine,
        syscall_request: DeployRequest,
        mut remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let (contract_address, result) = self.syscall_deploy(vm, syscall_request, remaining_gas)?;

        remaining_gas -= result.gas_consumed;

        let retdata_len = result.retdata.len();

        let retdata_start = self.allocate_segment(vm, result.retdata)?;
        let retdata_end = retdata_start.add(retdata_len)?;

        let ok = result.is_success;

        let body: ResponseBody = if ok {
            let contract_address = contract_address.0;
            ResponseBody::Deploy(DeployResponse {
                contract_address,
                retdata_start,
                retdata_end,
            })
        } else {
            ResponseBody::Failure(FailureReason {
                retdata_start,
                retdata_end,
            })
        };
        let response = SyscallResponse {
            gas: remaining_gas,
            body: Some(body),
        };

        Ok(response)
    }

    fn send_message_to_l1(
        &mut self,
        vm: &mut VirtualMachine,
        request: SendMessageToL1Request,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn call_contract(
        &mut self,
        vm: &mut VirtualMachine,
        request: CallContractRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn library_call(
        &mut self,
        vm: &mut VirtualMachine,
        library_call_request: LibraryCallRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn read_and_validate_syscall_request(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
        syscall_name: &str,
    ) -> Result<SyscallRequest, SyscallHandlerError>;

    fn storage_write(
        &mut self,
        vm: &mut VirtualMachine,
        request: StorageWriteRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn read_syscall_request(
        &self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
        syscall_name: &str,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "emit_event" => EmitEventRequest::from_ptr(vm, syscall_ptr),
            "storage_read" => StorageReadRequest::from_ptr(vm, syscall_ptr),
            "call_contract" => CallContractRequest::from_ptr(vm, syscall_ptr),
            "library_call" => LibraryCallRequest::from_ptr(vm, syscall_ptr),
            "deploy" => DeployRequest::from_ptr(vm, syscall_ptr),
            "get_block_number" => Ok(SyscallRequest::GetBlockNumber),
            "storage_write" => StorageWriteRequest::from_ptr(vm, syscall_ptr),
            "send_message_to_l1" => SendMessageToL1Request::from_ptr(vm, syscall_ptr),
            "storage_write" => StorageWriteRequest::from_ptr(vm, syscall_ptr),
            _ => Err(SyscallHandlerError::UnknownSyscall(
                syscall_name.to_string(),
            )),
        }
    }

    fn allocate_segment(
        &mut self,
        vm: &mut VirtualMachine,
        data: Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, SyscallHandlerError>;
}

//* ------------------------
//* Structs implementations
//* ------------------------

#[allow(unused)]
pub(crate) struct SyscallHintProcessor<'a, T: State + StateReader> {
    pub(crate) cairo1_hint_processor: Cairo1HintProcessor,
    pub(crate) syscall_handler: BusinessLogicSyscallHandler<'a, T>,
}

impl<'a, T: State + StateReader> SyscallHintProcessor<'a, T> {
    pub fn new(
        syscall_handler: BusinessLogicSyscallHandler<'a, T>,
        hints: &[(usize, Vec<Hint>)],
    ) -> Self {
        SyscallHintProcessor {
            cairo1_hint_processor: Cairo1HintProcessor::new(hints),
            syscall_handler,
        }
    }
}

impl<'a, T: State + StateReader> HintProcessor for SyscallHintProcessor<'a, T> {
    fn execute_hint(
        &mut self,
        vm: &mut VirtualMachine,
        exec_scopes: &mut ExecutionScopes,
        hint_data: &Box<dyn Any>,
        constants: &HashMap<String, Felt252>,
    ) -> Result<(), HintError> {
        self.cairo1_hint_processor
            .execute_hint(vm, exec_scopes, hint_data, constants)
    }

    // Ignores all data except for the code that should contain
    fn compile_hint(
        &self,
        //Block of hint code as String
        hint_code: &str,
        //Ap Tracking Data corresponding to the Hint
        ap_tracking_data: &cairo_vm::serde::deserialize_program::ApTracking,
        //Map from variable name to reference id number
        //(may contain other variables aside from those used by the hint)
        reference_ids: &HashMap<String, usize>,
        //List of all references (key corresponds to element of the previous dictionary)
        references: &HashMap<usize, HintReference>,
    ) -> Result<Box<dyn Any>, VirtualMachineError> {
        self.cairo1_hint_processor.compile_hint(
            hint_code,
            ap_tracking_data,
            reference_ids,
            references,
        )
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
