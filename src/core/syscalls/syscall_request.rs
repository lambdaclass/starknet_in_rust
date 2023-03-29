use crate::{
    core::errors::syscall_handler_errors::SyscallHandlerError,
    utils::{get_big_int, get_integer, get_relocatable, Address},
};
use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

#[derive(Debug, PartialEq)]
pub(crate) enum SyscallRequest {
    EmitEvent(EmitEventStruct),
    GetTxInfo(GetTxInfoRequest),
    Deploy(DeployRequestStruct),
    SendMessageToL1(SendMessageToL1SysCall),
    LibraryCall(LibraryCallStruct),
    GetCallerAddress(GetCallerAddressRequest),
    GetContractAddress(GetContractAddressRequest),
    GetSequencerAddress(GetSequencerAddressRequest),
    GetBlockNumber(GetBlockNumberRequest),
    GetBlockTimestamp(GetBlockTimestampRequest),
    CallContract(CallContractRequest),
    GetTxSignature(GetTxSignatureRequest),
    StorageRead(StorageReadRequest),
    StorageWrite(StorageWriteRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractRequest {
    pub(crate) selector: Felt252,
    pub(crate) contract_address: Address,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_size: usize,
    pub(crate) calldata: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetSequencerAddressRequest {
    _selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct EmitEventStruct {
    pub(crate) selector: Felt252,
    pub(crate) keys_len: usize,
    pub(crate) keys: Relocatable,
    pub(crate) data_len: usize,
    pub(crate) data: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeployRequestStruct {
    // The system call selector (= DEPLOY_SELECTOR).
    pub(crate) _selector: Felt252,
    // The hash of the class to deploy.
    pub(crate) class_hash: Felt252,
    // A salt for the new contract address calculation.
    pub(crate) contract_address_salt: Felt252,
    // The size of the calldata for the constructor.
    pub(crate) constructor_calldata_size: Felt252,
    // The calldata for the constructor.
    pub(crate) constructor_calldata: Relocatable,
    // Used for deterministic contract address deployment.
    pub(crate) deploy_from_zero: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SendMessageToL1SysCall {
    pub(crate) _selector: Felt252,
    pub(crate) to_address: Address,
    pub(crate) payload_size: usize,
    pub(crate) payload_ptr: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LibraryCallStruct {
    pub(crate) selector: Felt252,
    pub(crate) class_hash: Felt252,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_size: usize,
    pub(crate) calldata: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockTimestampRequest {
    pub(crate) selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetCallerAddressRequest {
    pub(crate) _selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetTxSignatureRequest {
    pub(crate) _selector: Felt252,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GetTxInfoRequest {
    pub(crate) selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetContractAddressRequest {
    pub(crate) _selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockNumberRequest {
    pub(crate) _selector: Felt252,
}

/// Describes the StorageRead system call format.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageReadRequest {
    pub(crate) selector: Felt252,
    pub(crate) address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageWriteRequest {
    pub(crate) selector: Felt252,
    pub(crate) address: Address,
    pub(crate) value: Felt252,
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

impl From<SendMessageToL1SysCall> for SyscallRequest {
    fn from(send_message_to_l1_sys_call: SendMessageToL1SysCall) -> SyscallRequest {
        SyscallRequest::SendMessageToL1(send_message_to_l1_sys_call)
    }
}

impl From<LibraryCallStruct> for SyscallRequest {
    fn from(library_call_struct: LibraryCallStruct) -> SyscallRequest {
        SyscallRequest::LibraryCall(library_call_struct)
    }
}

impl From<CallContractRequest> for SyscallRequest {
    fn from(call_contract_request: CallContractRequest) -> SyscallRequest {
        SyscallRequest::CallContract(call_contract_request)
    }
}

impl From<GetCallerAddressRequest> for SyscallRequest {
    fn from(get_caller_address_request: GetCallerAddressRequest) -> SyscallRequest {
        SyscallRequest::GetCallerAddress(get_caller_address_request)
    }
}

impl From<GetSequencerAddressRequest> for SyscallRequest {
    fn from(get_sequencer_address_request: GetSequencerAddressRequest) -> SyscallRequest {
        SyscallRequest::GetSequencerAddress(get_sequencer_address_request)
    }
}

impl From<GetBlockTimestampRequest> for SyscallRequest {
    fn from(get_block_timestamp_request: GetBlockTimestampRequest) -> SyscallRequest {
        SyscallRequest::GetBlockTimestamp(get_block_timestamp_request)
    }
}

impl From<GetTxSignatureRequest> for SyscallRequest {
    fn from(get_tx_signature_request: GetTxSignatureRequest) -> SyscallRequest {
        SyscallRequest::GetTxSignature(get_tx_signature_request)
    }
}

impl From<GetTxInfoRequest> for SyscallRequest {
    fn from(get_tx_info_request: GetTxInfoRequest) -> SyscallRequest {
        SyscallRequest::GetTxInfo(get_tx_info_request)
    }
}

impl From<StorageReadRequest> for SyscallRequest {
    fn from(storage_read: StorageReadRequest) -> SyscallRequest {
        SyscallRequest::StorageRead(storage_read)
    }
}

impl From<StorageWriteRequest> for SyscallRequest {
    fn from(storage_write: StorageWriteRequest) -> SyscallRequest {
        SyscallRequest::StorageWrite(storage_write)
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  FromPtr implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~

pub(crate) trait FromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError>;
}

impl FromPtr for EmitEventStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let keys_len = get_integer(vm, &syscall_ptr + 1)?;
        let keys = get_relocatable(vm, &syscall_ptr + 2)?;
        let data_len = get_integer(vm, &syscall_ptr + 3)?;
        let data = get_relocatable(vm, &syscall_ptr + 4)?;

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

impl FromPtr for GetTxInfoRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;

        Ok(GetTxInfoRequest { selector }.into())
    }
}

impl FromPtr for LibraryCallStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let class_hash = get_big_int(vm, &syscall_ptr + 1)?;
        let function_selector = get_big_int(vm, &syscall_ptr + 2)?;
        let calldata_size = get_integer(vm, &syscall_ptr + 3)?;
        let calldata = get_relocatable(vm, &syscall_ptr + 4)?;
        Ok(LibraryCallStruct {
            selector,
            class_hash,
            function_selector,
            calldata_size,
            calldata,
        }
        .into())
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
        let calldata_size = get_integer(vm, &syscall_ptr + 3)?;
        let calldata = get_relocatable(vm, &syscall_ptr + 4)?;
        Ok(CallContractRequest {
            selector,
            contract_address,
            function_selector,
            calldata_size,
            calldata,
        }
        .into())
    }
}

impl FromPtr for DeployRequestStruct {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        let class_hash = get_big_int(vm, &syscall_ptr + 1)?;
        let contract_address_salt = get_big_int(vm, &syscall_ptr + 2)?;
        let constructor_calldata_size = get_big_int(vm, &syscall_ptr + 3)?;
        let constructor_calldata = get_relocatable(vm, &syscall_ptr + 4)?;
        let deploy_from_zero = get_integer(vm, &syscall_ptr + 5)?;

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

impl FromPtr for SendMessageToL1SysCall {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        let to_address = Address(get_big_int(vm, &syscall_ptr + 1)?);
        let payload_size = get_integer(vm, &syscall_ptr + 2)?;
        let payload_ptr = get_relocatable(vm, &syscall_ptr + 3)?;

        Ok(SyscallRequest::SendMessageToL1(SendMessageToL1SysCall {
            _selector,
            to_address,
            payload_size,
            payload_ptr,
        }))
    }
}

impl FromPtr for GetCallerAddressRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;

        Ok(SyscallRequest::GetCallerAddress(GetCallerAddressRequest {
            _selector,
        }))
    }
}

impl FromPtr for GetBlockTimestampRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        Ok(SyscallRequest::GetBlockTimestamp(
            GetBlockTimestampRequest { selector },
        ))
    }
}

impl FromPtr for GetSequencerAddressRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        Ok(SyscallRequest::GetSequencerAddress(
            GetSequencerAddressRequest { _selector },
        ))
    }
}

impl FromPtr for GetTxSignatureRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        Ok(SyscallRequest::GetTxSignature(GetTxSignatureRequest {
            _selector,
        }))
    }
}

impl FromPtr for GetBlockNumberRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;

        Ok(SyscallRequest::GetBlockNumber(GetBlockNumberRequest {
            _selector,
        }))
    }
}

impl FromPtr for GetContractAddressRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;

        Ok(SyscallRequest::GetContractAddress(
            GetContractAddressRequest { _selector },
        ))
    }
}

impl FromPtr for StorageReadRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let address = Address(get_big_int(vm, (syscall_ptr + 1)?)?);

        Ok(SyscallRequest::StorageRead(StorageReadRequest {
            selector,
            address,
        }))
    }
}

impl FromPtr for StorageWriteRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<SyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let address = Address(get_big_int(vm, (syscall_ptr + 1)?)?);
        let value = get_big_int(vm, (syscall_ptr + 2)?)?;

        Ok(SyscallRequest::StorageWrite(StorageWriteRequest {
            selector,
            address,
            value,
        }))
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//  CountFields implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pub(crate) trait CountFields {
    /// Returns the amount of fields of a struct
    fn count_fields() -> usize;
}

impl CountFields for GetCallerAddressRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for GetSequencerAddressRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for GetBlockTimestampRequest {
    fn count_fields() -> usize {
        1
    }
}
impl CountFields for GetTxSignatureRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for GetBlockNumberRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for GetContractAddressRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for GetTxInfoRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for StorageReadRequest {
    fn count_fields() -> usize {
        2
    }
}

impl CountFields for CallContractRequest {
    fn count_fields() -> usize {
        5
    }
}
impl CountFields for DeployRequestStruct {
    fn count_fields() -> usize {
        6
    }
}
