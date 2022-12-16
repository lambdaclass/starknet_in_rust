use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use cairo_rs::types::relocatable::Relocatable;
use cairo_rs::vm::vm_core::VirtualMachine;
use num_bigint::BigInt;

pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventStruct),
    Deploy(DeployRequestStruct),
}

pub(crate) struct EmitEventStruct {
    #[allow(unused)] // TODO: Remove once used.
    pub(crate) selector: BigInt,
    pub(crate) keys_len: BigInt,
    pub(crate) keys: Relocatable,
    pub(crate) data_len: BigInt,
    pub(crate) data: Relocatable,
}

pub(crate) struct DeployRequestStruct {
    // The system call selector (= DEPLOY_SELECTOR).
    pub(crate) _selector: BigInt,
    // The hash of the class to deploy.
    pub(crate) class_hash: BigInt,
    // A salt for the new contract address calculation.
    pub(crate) contract_address_salt: BigInt,
    // The size of the calldata for the constructor.
    pub(crate) constructor_calldata_size: BigInt,
    // The calldata for the constructor.
    pub(crate) constructor_calldata: Relocatable,
    // Used for deterministic contract address deployment.
    pub(crate) deploy_from_zero: BigInt,
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

impl From<DeployRequestStruct> for SyscallRequest {
    fn from(deploy_request_struct: DeployRequestStruct) -> SyscallRequest {
        SyscallRequest::Deploy(deploy_request_struct)
    }
}

fn get_integer(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<BigInt, SyscallHandlerError> {
    Ok(vm
        .get_integer(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .as_ref()
        .to_owned())
}

fn get_relocatable(
    vm: &VirtualMachine,
    syscall_ptr: &Relocatable,
) -> Result<Relocatable, SyscallHandlerError> {
    Ok(vm
        .get_relocatable(syscall_ptr)
        .map_err(|_| SyscallHandlerError::SegmentationFault)?
        .as_ref()
        .to_owned())
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

impl FromPtr for DeployRequestStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_integer(vm, &syscall_ptr)?;
        let class_hash = get_integer(vm, &(&syscall_ptr + 1))?;
        let contract_address_salt = get_integer(vm, &(&syscall_ptr + 2))?;
        let constructor_calldata_size = get_integer(vm, &(&syscall_ptr + 3))?;
        let constructor_calldata = get_relocatable(vm, &(&syscall_ptr + 4))?;
        let deploy_from_zero = get_integer(vm, &(&syscall_ptr + 5))?;

        Ok(SyscallRequest::Deploy(DeployRequestStruct {
            _selector,
            class_hash,
            contract_address_salt,
            constructor_calldata_size,
            constructor_calldata,
            deploy_from_zero,
        }))
    }
}
