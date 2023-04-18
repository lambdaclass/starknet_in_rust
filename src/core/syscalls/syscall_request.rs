use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_big_int, get_relocatable, Address},
};
use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

#[derive(Debug, PartialEq)]
pub(crate) enum SyscallRequest {
    LibraryCall(LibraryCallRequest),
    CallContract(CallContractRequest),
    SendMessageToL1(SendMessageToL1SysCall),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractRequest {
    pub(crate) selector: Felt252,
    pub(crate) contract_address: Address,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LibraryCallRequest {
    pub(crate) class_hash: Felt252,
    pub(crate) selector: Felt252,
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
}

// Arguments given in the syscall documentation
// https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/starknet/common/new_syscalls.cairo#L138
// to_address
// The recipient’s L1 address.

// payload
// The array containing the message payload -> relocatable
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SendMessageToL1SysCall {
    pub(crate) to_address: Address,
    pub(crate) payload_start: Relocatable,
    pub(crate) payload_end: Relocatable,
}

impl From<CallContractRequest> for SyscallRequest {
    fn from(call_contract_request: CallContractRequest) -> SyscallRequest {
        SyscallRequest::CallContract(call_contract_request)
    }
}

impl From<LibraryCallRequest> for SyscallRequest {
    fn from(library_call_request: LibraryCallRequest) -> Self {
        SyscallRequest::LibraryCall(library_call_request)
    }
}

impl From<SendMessageToL1SysCall> for SyscallRequest {
    fn from(syscall: SendMessageToL1SysCall) -> Self {
        SyscallRequest::SendMessageToL1(syscall)
    }
}

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl FromPtr for CallContractRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let contract_address = Address(get_big_int(vm, &syscall_ptr + 1)?);
        let function_selector = get_big_int(vm, &syscall_ptr + 2)?;
        let calldata_start = get_relocatable(vm, &syscall_ptr + 3)?;
        let calldata_end = get_relocatable(vm, &syscall_ptr + 4)?;
        Ok(CallContractRequest {
            selector,
            contract_address,
            function_selector,
            calldata_start,
            calldata_end,
        }
        .into())
    }
}

impl FromPtr for LibraryCallRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let class_hash = get_big_int(vm, syscall_ptr)?;
        let selector = get_big_int(vm, &syscall_ptr + 1)?;
        let calldata_start = get_relocatable(vm, &syscall_ptr + 2)?;
        let calldata_end = get_relocatable(vm, &syscall_ptr + 3)?;

        Ok(LibraryCallRequest {
            class_hash,
            selector,
            calldata_start,
            calldata_end,
        }
        .into())
    }
}

impl FromPtr for SendMessageToL1SysCall {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let to_address = Address(get_big_int(vm, syscall_ptr)?);
        let payload_start = get_relocatable(vm, &syscall_ptr + 1)?;
        let payload_end = get_relocatable(vm, &syscall_ptr + 2)?;

        Ok(SendMessageToL1SysCall {
            to_address,
            payload_start,
            payload_end,
        }
        .into())
    }
}
