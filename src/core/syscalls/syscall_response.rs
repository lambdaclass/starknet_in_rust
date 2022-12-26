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

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_rs::relocatable;

    use crate::{
        add_segments,
        core::syscalls::{
            business_logic_syscall_handler::BusinessLogicSyscallHandler,
            syscall_handler::SyscallHandler,
        },
        utils::test_utils::vm,
    };
    use num_bigint::{BigInt, Sign};

    #[test]
    fn write_get_caller_address_response() {
        let mut syscall = BusinessLogicSyscallHandler::new();
        let mut vm = vm!();

        add_segments!(vm, 2);

        let response = GetCallerAddressResponse {
            caller_address: bigint!(3),
        };

        assert!(syscall
            ._write_syscall_response(&response, &mut vm, relocatable!(1, 0))
            .is_ok());

        // Check Vm inserts
        assert!(vm.insert_value(&relocatable!(1, 1), bigint!(8)).is_err());
        assert!(vm.insert_value(&relocatable!(1, 1), bigint!(3)).is_ok())
    }
}
