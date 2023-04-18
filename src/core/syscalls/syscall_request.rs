use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_big_int, get_relocatable, Address},
};
use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

#[derive(Debug, PartialEq)]
pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventStruct),
    SendMessageToL1(SendMessageToL1SysCall),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EmitEventStruct {
    pub(crate) keys_start: Relocatable,
    pub(crate) keys_end: Relocatable,
    pub(crate) data_start: Relocatable,
    pub(crate) data_end: Relocatable,
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

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  Into<SyscallRequest> implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~

impl From<EmitEventStruct> for SyscallRequest {
    fn from(emit_event_struct: EmitEventStruct) -> SyscallRequest {
        SyscallRequest::EmitEvent(emit_event_struct)
    }
}

impl From<SendMessageToL1SysCall> for SyscallRequest {
    fn from(syscall: SendMessageToL1SysCall) -> Self {
        SyscallRequest::SendMessageToL1(syscall)
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  FromPtr implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl FromPtr for EmitEventStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let keys_start = get_relocatable(vm, syscall_ptr)?;
        let keys_end = get_relocatable(vm, &syscall_ptr + 1)?;
        let data_start = get_relocatable(vm, &syscall_ptr + 2)?;
        let data_end = get_relocatable(vm, &syscall_ptr + 3)?;

        Ok(EmitEventStruct {
            keys_start,
            keys_end,
            data_start,
            data_end,
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
