use crate::errors::syscall_handler_errors::SyscallHandlerError;
use cairo_vm::felt::Felt252;
use cairo_vm::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use starknet_rs::utils::{get_big_int, get_integer, get_relocatable, Address};

#[derive(Debug, PartialEq)]
pub(crate) enum DeprecatedSyscallRequest {
    EmitEvent(DeprecatedEmitEventRequest),
    GetTxInfo(DeprecatedGetTxInfoRequest),
    Deploy(DeprecatedDeployRequest),
    SendMessageToL1(DeprecatedSendMessageToL1SysCallRequest),
    LibraryCall(DeprecatedLibraryCallRequest),
    GetCallerAddress(DeprecatedGetCallerAddressRequest),
    GetContractAddress(DeprecatedGetContractAddressRequest),
    GetSequencerAddress(DeprecatedGetSequencerAddressRequest),
    GetBlockNumber(DeprecatedGetBlockNumberRequest),
    GetBlockTimestamp(DeprecatedGetBlockTimestampRequest),
    CallContract(DeprecatedCallContractRequest),
    GetTxSignature(DeprecatedGetTxSignatureRequest),
    StorageRead(DeprecatedStorageReadRequest),
    StorageWrite(DeprecatedStorageWriteRequest),
    ReplaceClass(DeprecatedReplaceClassRequest),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedCallContractRequest {
    pub(crate) selector: Felt252,
    pub(crate) contract_address: Address,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_size: usize,
    pub(crate) calldata: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetSequencerAddressRequest {
    _selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedEmitEventRequest {
    pub(crate) selector: Felt252,
    pub(crate) keys_len: usize,
    pub(crate) keys: Relocatable,
    pub(crate) data_len: usize,
    pub(crate) data: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedDeployRequest {
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
pub(crate) struct DeprecatedSendMessageToL1SysCallRequest {
    pub(crate) _selector: Felt252,
    pub(crate) to_address: Address,
    pub(crate) payload_size: usize,
    pub(crate) payload_ptr: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedLibraryCallRequest {
    pub(crate) selector: Felt252,
    pub(crate) class_hash: Felt252,
    pub(crate) function_selector: Felt252,
    pub(crate) calldata_size: usize,
    pub(crate) calldata: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetBlockTimestampRequest {
    pub(crate) selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetCallerAddressRequest {
    pub(crate) _selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetTxSignatureRequest {
    pub(crate) _selector: Felt252,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeprecatedGetTxInfoRequest {
    pub(crate) selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetContractAddressRequest {
    pub(crate) _selector: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetBlockNumberRequest {
    pub(crate) _selector: Felt252,
}

/// Describes the StorageRead system call format.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedStorageReadRequest {
    pub(crate) selector: Felt252,
    pub(crate) address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedStorageWriteRequest {
    pub(crate) selector: Felt252,
    pub(crate) address: Address,
    pub(crate) value: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedReplaceClassRequest {
    pub(crate) class_hash: Felt252,
}

impl From<DeprecatedEmitEventRequest> for DeprecatedSyscallRequest {
    fn from(emit_event_struct: DeprecatedEmitEventRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::EmitEvent(emit_event_struct)
    }
}

impl From<DeprecatedDeployRequest> for DeprecatedSyscallRequest {
    fn from(deploy_request_struct: DeprecatedDeployRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::Deploy(deploy_request_struct)
    }
}

impl From<DeprecatedSendMessageToL1SysCallRequest> for DeprecatedSyscallRequest {
    fn from(
        send_message_to_l1_sys_call: DeprecatedSendMessageToL1SysCallRequest,
    ) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::SendMessageToL1(send_message_to_l1_sys_call)
    }
}

impl From<DeprecatedLibraryCallRequest> for DeprecatedSyscallRequest {
    fn from(library_call_struct: DeprecatedLibraryCallRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::LibraryCall(library_call_struct)
    }
}

impl From<DeprecatedCallContractRequest> for DeprecatedSyscallRequest {
    fn from(call_contract_request: DeprecatedCallContractRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::CallContract(call_contract_request)
    }
}

impl From<DeprecatedGetCallerAddressRequest> for DeprecatedSyscallRequest {
    fn from(
        get_caller_address_request: DeprecatedGetCallerAddressRequest,
    ) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::GetCallerAddress(get_caller_address_request)
    }
}

impl From<DeprecatedGetSequencerAddressRequest> for DeprecatedSyscallRequest {
    fn from(
        get_sequencer_address_request: DeprecatedGetSequencerAddressRequest,
    ) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::GetSequencerAddress(get_sequencer_address_request)
    }
}

impl From<DeprecatedGetBlockTimestampRequest> for DeprecatedSyscallRequest {
    fn from(
        get_block_timestamp_request: DeprecatedGetBlockTimestampRequest,
    ) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::GetBlockTimestamp(get_block_timestamp_request)
    }
}

impl From<DeprecatedGetTxSignatureRequest> for DeprecatedSyscallRequest {
    fn from(get_tx_signature_request: DeprecatedGetTxSignatureRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::GetTxSignature(get_tx_signature_request)
    }
}

impl From<DeprecatedGetTxInfoRequest> for DeprecatedSyscallRequest {
    fn from(get_tx_info_request: DeprecatedGetTxInfoRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::GetTxInfo(get_tx_info_request)
    }
}

impl From<DeprecatedStorageReadRequest> for DeprecatedSyscallRequest {
    fn from(storage_read: DeprecatedStorageReadRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::StorageRead(storage_read)
    }
}

impl From<DeprecatedStorageWriteRequest> for DeprecatedSyscallRequest {
    fn from(storage_write: DeprecatedStorageWriteRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::StorageWrite(storage_write)
    }
}

impl From<DeprecatedReplaceClassRequest> for DeprecatedSyscallRequest {
    fn from(replace_class: DeprecatedReplaceClassRequest) -> DeprecatedSyscallRequest {
        DeprecatedSyscallRequest::ReplaceClass(replace_class)
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~
//  FromPtr implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~

pub(crate) trait DeprecatedFromPtr {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError>;
}

impl DeprecatedFromPtr for DeprecatedEmitEventRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let keys_len = get_integer(vm, &syscall_ptr + 1)?;
        let keys = get_relocatable(vm, &syscall_ptr + 2)?;
        let data_len = get_integer(vm, &syscall_ptr + 3)?;
        let data = get_relocatable(vm, &syscall_ptr + 4)?;

        Ok(DeprecatedEmitEventRequest {
            selector,
            keys_len,
            keys,
            data_len,
            data,
        }
        .into())
    }
}

impl DeprecatedFromPtr for DeprecatedGetTxInfoRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;

        Ok(DeprecatedGetTxInfoRequest { selector }.into())
    }
}

impl DeprecatedFromPtr for DeprecatedLibraryCallRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let class_hash = get_big_int(vm, &syscall_ptr + 1)?;
        let function_selector = get_big_int(vm, &syscall_ptr + 2)?;
        let calldata_size = get_integer(vm, &syscall_ptr + 3)?;
        let calldata = get_relocatable(vm, &syscall_ptr + 4)?;
        Ok(DeprecatedLibraryCallRequest {
            selector,
            class_hash,
            function_selector,
            calldata_size,
            calldata,
        }
        .into())
    }
}

impl DeprecatedFromPtr for DeprecatedCallContractRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let contract_address = Address(get_big_int(vm, &syscall_ptr + 1)?);
        let function_selector = get_big_int(vm, &syscall_ptr + 2)?;
        let calldata_size = get_integer(vm, &syscall_ptr + 3)?;
        let calldata = get_relocatable(vm, &syscall_ptr + 4)?;
        Ok(DeprecatedCallContractRequest {
            selector,
            contract_address,
            function_selector,
            calldata_size,
            calldata,
        }
        .into())
    }
}

impl DeprecatedFromPtr for DeprecatedDeployRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        let class_hash = get_big_int(vm, &syscall_ptr + 1)?;
        let contract_address_salt = get_big_int(vm, &syscall_ptr + 2)?;
        let constructor_calldata_size = get_big_int(vm, &syscall_ptr + 3)?;
        let constructor_calldata = get_relocatable(vm, &syscall_ptr + 4)?;
        let deploy_from_zero = get_integer(vm, &syscall_ptr + 5)?;

        Ok(DeprecatedSyscallRequest::Deploy(DeprecatedDeployRequest {
            _selector,
            class_hash,
            contract_address_salt,
            constructor_calldata_size,
            constructor_calldata,
            deploy_from_zero,
        }))
    }
}

impl DeprecatedFromPtr for DeprecatedSendMessageToL1SysCallRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        let to_address = Address(get_big_int(vm, &syscall_ptr + 1)?);
        let payload_size = get_integer(vm, &syscall_ptr + 2)?;
        let payload_ptr = get_relocatable(vm, &syscall_ptr + 3)?;

        Ok(DeprecatedSyscallRequest::SendMessageToL1(
            DeprecatedSendMessageToL1SysCallRequest {
                _selector,
                to_address,
                payload_size,
                payload_ptr,
            },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedGetCallerAddressRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;

        Ok(DeprecatedSyscallRequest::GetCallerAddress(
            DeprecatedGetCallerAddressRequest { _selector },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedGetBlockTimestampRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        Ok(DeprecatedSyscallRequest::GetBlockTimestamp(
            DeprecatedGetBlockTimestampRequest { selector },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedGetSequencerAddressRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        Ok(DeprecatedSyscallRequest::GetSequencerAddress(
            DeprecatedGetSequencerAddressRequest { _selector },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedGetTxSignatureRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;
        Ok(DeprecatedSyscallRequest::GetTxSignature(
            DeprecatedGetTxSignatureRequest { _selector },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedGetBlockNumberRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;

        Ok(DeprecatedSyscallRequest::GetBlockNumber(
            DeprecatedGetBlockNumberRequest { _selector },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedGetContractAddressRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let _selector = get_big_int(vm, syscall_ptr)?;

        Ok(DeprecatedSyscallRequest::GetContractAddress(
            DeprecatedGetContractAddressRequest { _selector },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedStorageReadRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let address = Address(get_big_int(vm, (syscall_ptr + 1)?)?);

        Ok(DeprecatedSyscallRequest::StorageRead(
            DeprecatedStorageReadRequest { selector, address },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedStorageWriteRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let selector = get_big_int(vm, syscall_ptr)?;
        let address = Address(get_big_int(vm, (syscall_ptr + 1)?)?);
        let value = get_big_int(vm, (syscall_ptr + 2)?)?;

        Ok(DeprecatedSyscallRequest::StorageWrite(
            DeprecatedStorageWriteRequest {
                selector,
                address,
                value,
            },
        ))
    }
}

impl DeprecatedFromPtr for DeprecatedReplaceClassRequest {
    fn from_ptr(
        vm: &VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<DeprecatedSyscallRequest, SyscallHandlerError> {
        let class_hash = get_big_int(vm, syscall_ptr)?;

        Ok(DeprecatedSyscallRequest::ReplaceClass(
            DeprecatedReplaceClassRequest { class_hash },
        ))
    }
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//  CountFields implementations
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pub(crate) trait CountFields {
    /// Returns the amount of fields of a struct
    fn count_fields() -> usize;
}

impl CountFields for DeprecatedGetCallerAddressRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for DeprecatedGetSequencerAddressRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for DeprecatedGetBlockTimestampRequest {
    fn count_fields() -> usize {
        1
    }
}
impl CountFields for DeprecatedGetTxSignatureRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for DeprecatedGetBlockNumberRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for DeprecatedGetContractAddressRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for DeprecatedGetTxInfoRequest {
    fn count_fields() -> usize {
        1
    }
}

impl CountFields for DeprecatedStorageReadRequest {
    fn count_fields() -> usize {
        2
    }
}

impl CountFields for DeprecatedCallContractRequest {
    fn count_fields() -> usize {
        5
    }
}
impl CountFields for DeprecatedDeployRequest {
    fn count_fields() -> usize {
        6
    }
}
