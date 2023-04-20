use std::ops::Add;

use crate::{
    business_logic::execution::objects::CallResult,
    core::errors::syscall_handler_errors::SyscallHandlerError, utils::Address,
};
use cairo_rs::{
    types::relocatable::{MaybeRelocatable, Relocatable},
    vm::vm_core::VirtualMachine,
};

use super::{
    syscall_request::{
        CallContractRequest, DeployRequest, FromPtr, LibraryCallRequest,
        SendMessageToL1SysCallRequest, StorageWriteRequest, SyscallRequest,
    },
    syscall_response::{DeployResponse, FailureReason, ResponseBody, SyscallResponse},
};

#[allow(unused)]
pub(crate) trait SyscallHandler {
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
        request: SendMessageToL1SysCallRequest,
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
            "call_contract" => CallContractRequest::from_ptr(vm, syscall_ptr),
            "library_call" => LibraryCallRequest::from_ptr(vm, syscall_ptr),
            "deploy" => DeployRequest::from_ptr(vm, syscall_ptr),
            "storage_write" => StorageWriteRequest::from_ptr(vm, syscall_ptr),
            "send_message_to_l1" => SendMessageToL1SysCallRequest::from_ptr(vm, syscall_ptr),
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
