use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

use crate::{core::errors::syscall_handler_errors::SyscallHandlerError, utils::get_big_int};

#[allow(unused)]
pub(crate) enum SyscallRequest {
    StorageRead(StorageReadRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageReadRequest {
    pub(crate) key: [u8; 32],
    pub(crate) reserved: Felt252,
}

impl From<StorageReadRequest> for SyscallRequest {
    fn from(storage_read_request: StorageReadRequest) -> SyscallRequest {
        SyscallRequest::StorageRead(storage_read_request)
    }
}

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl FromPtr for StorageReadRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let key = get_big_int(vm, syscall_ptr)?.to_be_bytes();
        let reserved = get_big_int(vm, &syscall_ptr + 1)?;
        Ok(StorageReadRequest { key, reserved }.into())
    }
}
