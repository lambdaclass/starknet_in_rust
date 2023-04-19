use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_big_int, get_integer, get_relocatable, Address},
};
// TODO: maybe we could make FromPtr trait more general, making
//   it "move" the pointer received like they do in cairo-lang
// The size of the RequestHeader in VM memory
// ```
// struct RequestHeader {
//     // The syscall selector.
//     selector: Felt252,
//     // The amount of gas left before the syscall execution.
//     gas: Felt252,
// }
// ```

const HEADER_OFFSET: usize = 2;

#[allow(unused)]
pub(crate) enum SyscallRequest {
    Deploy(DeployRequest),
    StorageWrite(StorageWriteRequest),
    SendMessageToL1(SendMessageToL1SysCall),
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

// Arguments given in the syscall documentation
// https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/starknet/common/new_syscalls.cairo#L138
// to_address
// The recipient’s L1 address.

// payload
// The array containing the message payload -> relocatable
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SendMessageToL1SysCall {
    pub(crate) to_address: Address,
    pub(crate) payload_start: Relocatable,
    pub(crate) payload_end: Relocatable,
}

impl From<SendMessageToL1SysCall> for SyscallRequest {
    fn from(syscall: SendMessageToL1SysCall) -> Self {
        SyscallRequest::SendMessageToL1(syscall)
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  FromPtr trait
// ~~~~~~~~~~~~~~~~~~~~~~~~~
pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  SyscallRequest variants
// ~~~~~~~~~~~~~~~~~~~~~~~~~

#[allow(unused)]
pub(crate) struct DeployRequest {
    // The hash of the class to deploy.
    pub(crate) class_hash: Felt252,
    // A salt for the new contract address calculation.
    pub(crate) salt: Felt252,
    // The calldata for the constructor.
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
    // Used for deterministic contract address deployment.
    pub(crate) deploy_from_zero: usize,
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  FromPtr implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~

impl FromPtr for DeployRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        mut syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        syscall_ptr += HEADER_OFFSET;
        let class_hash = get_big_int(vm, syscall_ptr)?;
        let salt = get_big_int(vm, (syscall_ptr + 1)?)?;
        let calldata_start = get_relocatable(vm, (syscall_ptr + 2)?)?;
        let calldata_end = get_relocatable(vm, (syscall_ptr + 3)?)?;
        let deploy_from_zero = get_integer(vm, (syscall_ptr + 4)?)?;

        Ok(SyscallRequest::Deploy(DeployRequest {
            class_hash,
            salt,
            calldata_start,
            calldata_end,
            deploy_from_zero,
        }))
    }
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

impl FromPtr for SendMessageToL1SysCall {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let to_address = Address(get_big_int(vm, syscall_ptr)?);
        let payload_start = get_relocatable(vm, &syscall_ptr + 1)?;
        let payload_end = get_relocatable(vm, &syscall_ptr + 2)?;

        Ok(SendMessageToL1SysCall {
            to_address,
            payload_start,
            payload_end,
        }
        .into())
    }
}
