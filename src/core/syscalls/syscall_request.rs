use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventStruct),
}

#[derive(Clone, Debug)]
pub(crate) struct EmitEventStruct {
    #[allow(unused)] // TODO: Remove once used.
    pub(crate) selector: BigInt,
    pub(crate) keys_len: BigInt,
    pub(crate) keys: Relocatable,
    pub(crate) data_len: BigInt,
    pub(crate) data: Relocatable,
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

fn get_integer(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<BigInt, SyscallHandlerError> {
    Ok(vm
        .get_integer(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .into_owned())
}

fn get_relocatable(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<Relocatable, SyscallHandlerError> {
    Ok(vm
        .get_relocatable(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .into_owned())
}

impl FromPtr for EmitEventStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_integer(vm, &(syscall_ptr))?;
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
