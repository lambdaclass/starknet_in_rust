use cairo_rs::{bigint, types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use num_bigint::BigInt;

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;

use super::syscall_request::{CountFields, GetCallerAddressRequest};

pub(crate) trait WriteSyscallResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetCallerAddressResponse {
    caller_address: BigInt,
}

impl WriteSyscallResponse for GetCallerAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            &(syscall_ptr + GetCallerAddressRequest::count_fields()),
            &self.caller_address,
        )?;
        Ok(())
    }
}
