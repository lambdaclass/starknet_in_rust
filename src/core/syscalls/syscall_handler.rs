use std::ops::Add;

use cairo_rs::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_rs::vm::vm_core::VirtualMachine;
use felt::Felt252;
use num_traits::Zero;

use super::syscall_request::StorageReadRequest;
use super::syscall_response::{DeployResponse, FailureReason, ResponseBody};
use super::{
    syscall_request::{FromPtr, StorageWriteRequest},
    syscall_response::SyscallResponse,
};
use crate::core::errors::state_errors::StateError;
use crate::{
    business_logic::execution::objects::CallResult,
    core::errors::syscall_handler_errors::SyscallHandlerError, utils::Address,
};

use super::syscall_request::{
    CallContractRequest, DeployRequest, LibraryCallRequest, SendMessageToL1SysCall, SyscallRequest,
};

#[allow(unused)]
pub(crate) trait SyscallHandler {
    fn storage_read(
        &mut self,
        _vm: &VirtualMachine,
        request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError> {
        let request = match request {
            SyscallRequest::StorageRead(storage_read_request) => storage_read_request,
            _ => return Err(SyscallHandlerError::InvalidSyscallReadRequest),
        };

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
        syscall_request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<(Address, CallResult), SyscallHandlerError>;

    fn deploy(
        &mut self,
        mut remaining_gas: u64,
        vm: &mut VirtualMachine,
        syscall_request: SyscallRequest,
        syscall_ptr: Relocatable,
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
        syscall_ptr: Relocatable,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn call_contract(
        &mut self,
        vm: &mut VirtualMachine,
        request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn library_call(
        &mut self,
        remaining_gas: u64,
        vm: &mut VirtualMachine,
        library_call_request: SyscallRequest,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;

    fn storage_write(
        &mut self,
        vm: &mut VirtualMachine,
        request: SyscallRequest,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn read_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "storage_read" => StorageReadRequest::from_ptr(vm, syscall_ptr),
            "call_contract" => CallContractRequest::from_ptr(vm, syscall_ptr),
            "library_call" => LibraryCallRequest::from_ptr(vm, syscall_ptr),
            "deploy" => DeployRequest::from_ptr(vm, syscall_ptr),
            "storage_write" => StorageWriteRequest::from_ptr(vm, syscall_ptr),
            "send_message_to_l1" => SendMessageToL1SysCall::from_ptr(vm, syscall_ptr),
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
