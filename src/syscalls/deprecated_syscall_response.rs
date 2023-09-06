use super::deprecated_syscall_request::{
    CountFields, DeprecatedCallContractRequest, DeprecatedDeployRequest,
    DeprecatedGetBlockNumberRequest, DeprecatedGetBlockTimestampRequest,
    DeprecatedGetCallerAddressRequest, DeprecatedGetContractAddressRequest,
    DeprecatedGetSequencerAddressRequest, DeprecatedGetTxInfoRequest,
    DeprecatedGetTxSignatureRequest, DeprecatedStorageReadRequest,
};
use crate::{syscalls::syscall_handler_errors::SyscallHandlerError, utils::Address};
use cairo_vm::{felt, types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

/// Trait to write the response of a deprecated system call
/// Takes in a mutable reference to a VirtualMachine and a Relocatable pointer to the system
///## Parameters:
///- vm: mutable reference to a VirtualMachine.
///- syscall_ptr: Relocatable pointer to the system.
pub(crate) trait DeprecatedWriteSyscallResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;
}

/// Structs to hold response data for different deprecated system calls
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedCallContractResponse {
    retdata_size: usize,
    retdata: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetCallerAddressResponse {
    caller_address: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetContractAddressResponse {
    contract_address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetSequencerAddressResponse {
    sequencer_address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetBlockTimestampResponse {
    block_timestamp: u64,
}

pub(crate) struct DeprecatedGetTxSignatureResponse {
    signature_len: usize,
    signature: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetBlockNumberResponse {
    block_number: u64,
}

impl DeprecatedCallContractResponse {
    pub(crate) const fn new(retdata_size: usize, retdata: Relocatable) -> Self {
        Self {
            retdata_size,
            retdata,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedGetTxInfoResponse {
    tx_info: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedStorageReadResponse {
    value: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeprecatedDeployResponse {
    contract_address: Felt252,
    constructor_retdata_size: Felt252,
    constructor_retdata: Relocatable,
}

impl DeprecatedGetTxInfoResponse {
    pub const fn new(tx_info: Relocatable) -> Self {
        DeprecatedGetTxInfoResponse { tx_info }
    }
}

impl DeprecatedGetBlockTimestampResponse {
    pub(crate) const fn new(block_timestamp: u64) -> Self {
        DeprecatedGetBlockTimestampResponse { block_timestamp }
    }
}

impl DeprecatedGetSequencerAddressResponse {
    pub(crate) const fn new(sequencer_address: Address) -> Self {
        Self { sequencer_address }
    }
}

impl DeprecatedGetCallerAddressResponse {
    pub fn new(caller_addr: Address) -> Self {
        let caller_address = caller_addr.0;
        DeprecatedGetCallerAddressResponse { caller_address }
    }
}

impl DeprecatedGetTxSignatureResponse {
    pub const fn new(signature: Relocatable, signature_len: usize) -> Self {
        DeprecatedGetTxSignatureResponse {
            signature,
            signature_len,
        }
    }
}
impl DeprecatedGetContractAddressResponse {
    pub const fn new(contract_address: Address) -> Self {
        DeprecatedGetContractAddressResponse { contract_address }
    }
}

impl DeprecatedStorageReadResponse {
    pub const fn new(value: Felt252) -> Self {
        DeprecatedStorageReadResponse { value }
    }
}

impl DeprecatedGetBlockNumberResponse {
    pub(crate) const fn new(block_number: u64) -> Self {
        Self { block_number }
    }
}
impl DeprecatedDeployResponse {
    pub(crate) const fn new(
        contract_address: Felt252,
        constructor_retdata_size: Felt252,
        constructor_retdata: Relocatable,
    ) -> Self {
        Self {
            contract_address,
            constructor_retdata_size,
            constructor_retdata,
        }
    }
}

/// Implementation of the DeprecatedWriteSyscallResponse trait for the different structs.
/// Each struct writes the response of its corresponding system call in the VM's memory.

impl DeprecatedWriteSyscallResponse for DeprecatedCallContractResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + DeprecatedCallContractRequest::count_fields())?,
            self.retdata_size.into(),
        )?;
        vm.insert_value(
            (syscall_ptr + (DeprecatedCallContractRequest::count_fields() + 1))?,
            self.retdata,
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedGetCallerAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + DeprecatedGetCallerAddressRequest::count_fields())?,
            &self.caller_address,
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedGetBlockTimestampResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + DeprecatedGetBlockTimestampRequest::count_fields())?,
            self.block_timestamp.into(),
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedGetSequencerAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + DeprecatedGetSequencerAddressRequest::count_fields())?,
            self.sequencer_address.0.clone(),
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedGetBlockNumberResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + DeprecatedGetBlockNumberRequest::count_fields())?,
            self.block_number.into(),
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedGetContractAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + DeprecatedGetContractAddressRequest::count_fields())?,
            self.contract_address.0.clone(),
        )?;
        Ok(())
    }
}
impl DeprecatedWriteSyscallResponse for DeprecatedGetTxSignatureResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + DeprecatedGetTxSignatureRequest::count_fields())?,
            self.signature_len.into(),
        )?;
        vm.insert_value(
            (syscall_ptr + (DeprecatedGetTxSignatureRequest::count_fields() + 1))?,
            self.signature,
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedGetTxInfoResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + DeprecatedGetTxInfoRequest::count_fields())?,
            self.tx_info,
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedDeployResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + DeprecatedDeployRequest::count_fields())?,
            self.contract_address.clone(),
        )?;
        vm.insert_value(
            (syscall_ptr + (DeprecatedDeployRequest::count_fields() + 1))?,
            self.constructor_retdata_size.clone(),
        )?;
        vm.insert_value(
            (syscall_ptr + (DeprecatedDeployRequest::count_fields() + 2))?,
            self.constructor_retdata,
        )?;
        Ok(())
    }
}

impl DeprecatedWriteSyscallResponse for DeprecatedStorageReadResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + DeprecatedStorageReadRequest::count_fields())?,
            self.value.clone(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use super::*;
    use crate::{
        add_segments,
        state::cached_state::CachedState,
        state::in_memory_state_reader::InMemoryStateReader,
        utils::{get_integer, test_utils::vm},
    };
    use cairo_vm::relocatable;

    type DeprecatedBLSyscallHandler<'a> =
        crate::syscalls::deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler<
            'a,
            InMemoryStateReader,
        >;

    /// Unit test to check the write_get_caller_address_response function
    #[test]
    fn write_get_caller_address_response() {
        // Initialize a VM and syscall handler
        let mut state = CachedState::new(Arc::new(InMemoryStateReader::default()), HashMap::new());
        let syscall = DeprecatedBLSyscallHandler::default_with(&mut state);
        let mut vm = vm!();

        // Write the response of get_caller_address into the VM's memory
        add_segments!(vm, 2);

        let caller_address = 3;
        let response = DeprecatedGetCallerAddressResponse {
            caller_address: caller_address.into(),
        };

        // Check if the correct value is written in the expected memory location
        assert!(syscall
            .write_syscall_response(&response, &mut vm, relocatable!(1, 0))
            .is_ok());

        // Check Vm inserts
        // The .write_syscall_response should insert the response.caller_address in the position (1,1)

        assert_matches!(get_integer(&vm, relocatable!(1, 1)), Ok(x) if x == caller_address);
    }
}
