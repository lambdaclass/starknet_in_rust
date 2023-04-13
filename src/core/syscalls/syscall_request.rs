use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_big_int, get_relocatable},
};

// TODO: maybe we could make FromPtr trait more general, making
//   it "move" the pointer received like they do in cairo-lang
/// The size of the RequestHeader in VM memory
/// ```
/// struct RequestHeader {
///     // The syscall selector.
///     selector: Felt252,
///     // The amount of gas left before the syscall execution.
///     gas: Felt252,
/// }
/// ```
const HEADER_OFFSET: usize = 2;

#[allow(unused)]
pub(crate) enum SyscallRequest {
    Deploy(DeployRequest),
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  FromPtr trait
// ~~~~~~~~~~~~~~~~~~~~~~~~~

pub(crate) trait FromPtr {
    /// Reads the request from VM memory.
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
    class_hash: Felt252,
    // A salt for the new contract address calculation.
    salt: Felt252,
    // The calldata for the constructor.
    calldata_start: Relocatable,
    calldata_end: Relocatable,
    // Used for deterministic contract address deployment.
    deploy_from_zero: Felt252,
}

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
        let deploy_from_zero = get_big_int(vm, (syscall_ptr + 4)?)?;

        Ok(SyscallRequest::Deploy(DeployRequest {
            class_hash,
            salt,
            calldata_start,
            calldata_end,
            deploy_from_zero,
        }))
    }
}
