use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_big_int, get_relocatable, Address},
};

#[allow(unused)]
pub(crate) enum SyscallRequest {
    CallContract(CallContractRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractRequest {
    pub(crate) selector: Felt252,
    pub(crate) contract_address: Address,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
}

impl From<CallContractRequest> for SyscallRequest {
    fn from(call_contract_request: CallContractRequest) -> SyscallRequest {
        SyscallRequest::CallContract(call_contract_request)
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
