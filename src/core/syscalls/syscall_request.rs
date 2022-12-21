use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use crate::utils::{get_big_int, get_integer, get_relocatable};
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventStruct),
    LibraryCall(LibraryCallStruct),
}

#[derive(Clone, Debug)]
pub(crate) struct EmitEventStruct {
    #[allow(unused)] // TODO: Remove once used.
    pub(crate) selector: BigInt,
    pub(crate) keys_len: usize,
    pub(crate) keys: Relocatable,
    pub(crate) data_len: usize,
    pub(crate) data: Relocatable,
}

#[allow(unused)] // TODO: Remove once used.
#[derive(Clone, Debug)]
pub(crate) struct LibraryCallStruct {
    pub(crate) selector: BigInt,
    pub(crate) class_hash: usize,
    pub(crate) function_selector: usize,
    pub(crate) calldata_size: usize,
    pub(crate) calldata: Relocatable,
}

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl From<EmitEventStruct> for SyscallRequest {
    fn from(emit_event_struct: EmitEventStruct) -> SyscallRequest {
        SyscallRequest::EmitEvent(emit_event_struct)
    }
}

impl From<LibraryCallStruct> for SyscallRequest {
    fn from(library_call_struct: LibraryCallStruct) -> SyscallRequest {
        SyscallRequest::LibraryCall(library_call_struct)
    }
}

impl FromPtr for EmitEventStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, &(syscall_ptr))?;
        let keys_len = get_integer(vm, &(&syscall_ptr + 1))?;
        let keys = get_relocatable(vm, &(&syscall_ptr + 2))?;
        let data_len = get_integer(vm, &(&syscall_ptr + 3))?;
        let data = get_relocatable(vm, &(&syscall_ptr + 4))?;

        Ok(EmitEventStruct {
            selector,
            keys_len,
            keys,
            data_len,
            data,
        }
        .into())
    }
}

impl FromPtr for LibraryCallStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, &(syscall_ptr))?;
        let class_hash = get_integer(vm, &(&syscall_ptr + 1))?;
        let function_selector = get_integer(vm, &(&syscall_ptr + 2))?;
        let calldata_size = get_integer(vm, &(&syscall_ptr + 3))?;
        let calldata = get_relocatable(vm, &(&syscall_ptr + 4))?;
        Ok(LibraryCallStruct {
            selector,
            class_hash,
            function_selector,
            calldata_size,
            calldata,
        }
        .into())
    }
}
