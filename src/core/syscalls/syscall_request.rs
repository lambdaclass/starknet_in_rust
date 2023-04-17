use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

use crate::{core::errors::syscall_handler_errors::SyscallHandlerError, utils::get_big_int};

pub(crate) enum SyscallRequest {
    StorageWrite(StorageWriteRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageWriteRequest {
    pub(crate) reserved: Felt252,
    pub(crate) key: Felt252,
    pub(crate) value: Felt252,
}

impl From<StorageWriteRequest> for SyscallRequest {
    fn from(storage_write_request: StorageWriteRequest) -> SyscallRequest {
        SyscallRequest::StorageWrite(storage_write_request)
    }
}

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl FromPtr for StorageWriteRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let reserved = get_big_int(vm, syscall_ptr)?;
        let key = get_big_int(vm, &syscall_ptr + 1)?;
        let value = get_big_int(vm, &syscall_ptr + 2)?;

        Ok(StorageWriteRequest {
            reserved,
            key,
            value,
        }
        .into())
    }
}
