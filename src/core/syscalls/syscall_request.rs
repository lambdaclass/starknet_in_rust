use cairo_vm::felt::Felt252;
use cairo_vm::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

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
#[derive(Debug, PartialEq)]
pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventRequest),
    LibraryCall(LibraryCallRequest),
    CallContract(CallContractRequest),
    Deploy(DeployRequest),
    GetBlockNumber,
    StorageRead(StorageReadRequest),
    StorageWrite(StorageWriteRequest),
    SendMessageToL1(SendMessageToL1Request),
    GetBlockTimestamp(GetBlockTimestampRequest),
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  SyscallRequest variants
// ~~~~~~~~~~~~~~~~~~~~~~~~~

#[allow(unused)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockTimestampRequest {}

#[allow(unused)]
#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageReadRequest {
    pub(crate) key: [u8; 32],
    pub(crate) reserved: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EmitEventRequest {
    pub(crate) keys_start: Relocatable,
    pub(crate) keys_end: Relocatable,
    pub(crate) data_start: Relocatable,
    pub(crate) data_end: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractRequest {
    pub(crate) selector: Felt252,
    pub(crate) contract_address: Address,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LibraryCallRequest {
    pub(crate) class_hash: Felt252,
    pub(crate) selector: Felt252,
    pub(crate) calldata_start: Relocatable,
    pub(crate) calldata_end: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageWriteRequest {
    pub(crate) reserved: Felt252,
    pub(crate) key: Felt252,
    pub(crate) value: Felt252,
}

// Arguments given in the syscall documentation
// https://github.com/starkware-libs/cairo-lang/blob/c954f154bbab04c3fb27f7598b015a9475fc628e/src/starkware/starknet/common/new_syscalls.cairo#L138
// to_address
// The recipient’s L1 address.

// payload
// The array containing the message payload -> relocatable
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SendMessageToL1Request {
    pub(crate) to_address: Address,
    pub(crate) payload_start: Relocatable,
    pub(crate) payload_end: Relocatable,
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  Into<SyscallRequest> implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~

impl From<GetBlockTimestampRequest> for SyscallRequest {
    fn from(get_block_timestamp: GetBlockTimestampRequest) -> SyscallRequest {
        SyscallRequest::GetBlockTimestamp(get_block_timestamp)
    }
}

impl From<EmitEventRequest> for SyscallRequest {
    fn from(emit_event_struct: EmitEventRequest) -> SyscallRequest {
        SyscallRequest::EmitEvent(emit_event_struct)
    }
}

impl From<CallContractRequest> for SyscallRequest {
    fn from(call_contract_request: CallContractRequest) -> SyscallRequest {
        SyscallRequest::CallContract(call_contract_request)
    }
}

impl From<LibraryCallRequest> for SyscallRequest {
    fn from(library_call_request: LibraryCallRequest) -> Self {
        SyscallRequest::LibraryCall(library_call_request)
    }
}

impl From<SendMessageToL1Request> for SyscallRequest {
    fn from(syscall: SendMessageToL1Request) -> Self {
        SyscallRequest::SendMessageToL1(syscall)
    }
}

impl From<StorageWriteRequest> for SyscallRequest {
    fn from(storage_write_request: StorageWriteRequest) -> SyscallRequest {
        SyscallRequest::StorageWrite(storage_write_request)
    }
}
impl From<StorageReadRequest> for SyscallRequest {
    fn from(storage_read_request: StorageReadRequest) -> SyscallRequest {
        SyscallRequest::StorageRead(storage_read_request)
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

impl FromPtr for GetBlockTimestampRequest {
    fn from_ptr(
        _vm: &VirtualMachine,
        _syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        Ok(GetBlockTimestampRequest {}.into())
    }
}

impl FromPtr for EmitEventRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let keys_start = get_relocatable(vm, syscall_ptr)?;
        let keys_end = get_relocatable(vm, &syscall_ptr + 1)?;
        let data_start = get_relocatable(vm, &syscall_ptr + 2)?;
        let data_end = get_relocatable(vm, &syscall_ptr + 3)?;

        Ok(EmitEventRequest {
            keys_start,
            keys_end,
            data_start,
            data_end,
        }
        .into())
    }
}

impl FromPtr for StorageReadRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let key = get_big_int(vm, syscall_ptr)?.to_be_bytes();
        let reserved = get_big_int(vm, &syscall_ptr + 1)?;
        Ok(StorageReadRequest { key, reserved }.into())
    }
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

impl FromPtr for LibraryCallRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let class_hash = get_big_int(vm, syscall_ptr)?;
        let selector = get_big_int(vm, &syscall_ptr + 1)?;
        let calldata_start = get_relocatable(vm, &syscall_ptr + 2)?;
        let calldata_end = get_relocatable(vm, &syscall_ptr + 3)?;

        Ok(LibraryCallRequest {
            class_hash,
            selector,
            calldata_start,
            calldata_end,
        }
        .into())
    }
}

impl FromPtr for SendMessageToL1Request {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let to_address = Address(get_big_int(vm, syscall_ptr)?);
        let payload_start = get_relocatable(vm, &syscall_ptr + 1)?;
        let payload_end = get_relocatable(vm, &syscall_ptr + 2)?;

        Ok(SendMessageToL1Request {
            to_address,
            payload_start,
            payload_end,
        }
        .into())
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
