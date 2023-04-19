use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

use crate::core::errors::syscall_handler_errors::SyscallHandlerError;

use super::{
    syscall_request::{EmitEventSysCall, FromPtr, SendMessageToL1SysCall, SyscallRequest},
    syscall_response::SyscallResponse,
};

pub(crate) trait SyscallHandler {
    fn emit_event(
        &mut self,
        remaining_gas: u64,
        vm: &VirtualMachine,
        request: SyscallRequest,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

    fn send_message_to_l1(
        &mut self,
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
        remaining_gas: u64,
    ) -> Result<SyscallResponse, SyscallHandlerError>;

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
            "emit_event" => EmitEventSysCall::from_ptr(vm, syscall_ptr),
            "send_message_to_l1" => SendMessageToL1SysCall::from_ptr(vm, syscall_ptr),
            _ => Err(SyscallHandlerError::UnknownSyscall(
                syscall_name.to_string(),
            )),
        }
    }
}
