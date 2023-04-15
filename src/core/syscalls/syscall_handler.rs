use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;

use super::syscall_request::{FromPtr, SendMessageToL1SysCall, SyscallRequest};

pub(crate) trait SyscallHandler {
    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;

    fn read_and_validate_syscall_request(
        &mut self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;

    fn read_syscall_request(
        &self,
        syscall_name: &str,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        match syscall_name {
            "send_message_to_l1" => SendMessageToL1SysCall::from_ptr(vm, syscall_ptr),
            _ => Err(SyscallHandlerError::UnknownSyscall(
                syscall_name.to_string(),
            )),
        }
    }
}
