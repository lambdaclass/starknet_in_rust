use super::syscall_request::{
    CallContractRequest, CountFields, DeployRequestStruct, GetBlockNumberRequest,
    GetBlockTimestampRequest, GetCallerAddressRequest, GetContractAddressRequest,
    GetSequencerAddressRequest, GetTxInfoRequest, GetTxSignatureRequest, StorageReadRequest,
};
use crate::{core::errors::syscall_handler_errors::SyscallHandlerError, utils::Address};
use cairo_rs::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use felt::Felt252;

pub(crate) trait WriteSyscallResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CallContractResponse {
    retdata_size: usize,
    retdata: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetCallerAddressResponse {
    caller_address: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetContractAddressResponse {
    contract_address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetSequencerAddressResponse {
    sequencer_address: Address,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockTimestampResponse {
    block_timestamp: u64,
}

pub(crate) struct GetTxSignatureResponse {
    signature_len: usize,
    signature: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockNumberResponse {
    block_number: u64,
}

impl CallContractResponse {
    pub(crate) fn new(retdata_size: usize, retdata: Relocatable) -> Self {
        Self {
            retdata_size,
            retdata,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetTxInfoResponse {
    tx_info: Relocatable,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StorageReadResponse {
    value: Felt252,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeployResponse {
    contract_address: Felt252,
    constructor_retdata_size: Felt252,
    constructor_retdata: Relocatable,
}

impl GetTxInfoResponse {
    pub fn new(tx_info: Relocatable) -> Self {
        GetTxInfoResponse { tx_info }
    }
}

impl GetBlockTimestampResponse {
    pub(crate) fn new(block_timestamp: u64) -> Self {
        GetBlockTimestampResponse { block_timestamp }
    }
}

impl GetSequencerAddressResponse {
    pub(crate) fn new(sequencer_address: Address) -> Self {
        Self { sequencer_address }
    }
}

impl GetCallerAddressResponse {
    pub fn new(caller_addr: Address) -> Self {
        let caller_address = caller_addr.0;
        GetCallerAddressResponse { caller_address }
    }
}

impl GetTxSignatureResponse {
    pub fn new(signature: Relocatable, signature_len: usize) -> Self {
        GetTxSignatureResponse {
            signature,
            signature_len,
        }
    }
}
impl GetContractAddressResponse {
    pub fn new(contract_address: Address) -> Self {
        GetContractAddressResponse { contract_address }
    }
}

impl StorageReadResponse {
    pub fn new(value: Felt252) -> Self {
        StorageReadResponse { value }
    }
}

impl GetBlockNumberResponse {
    pub(crate) fn new(block_number: u64) -> Self {
        Self { block_number }
    }
}
impl DeployResponse {
    pub(crate) fn new(
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

impl WriteSyscallResponse for CallContractResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + CallContractRequest::count_fields())?,
            self.retdata_size.into(),
        )?;
        vm.insert_value(
            (syscall_ptr + (CallContractRequest::count_fields() + 1))?,
            self.retdata,
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for GetCallerAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + GetCallerAddressRequest::count_fields())?,
            &self.caller_address,
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for GetBlockTimestampResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + GetBlockTimestampRequest::count_fields())?,
            self.block_timestamp.into(),
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for GetSequencerAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + GetSequencerAddressRequest::count_fields())?,
            self.sequencer_address.0.clone(),
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for GetBlockNumberResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + GetBlockNumberRequest::count_fields())?,
            self.block_number.into(),
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for GetContractAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + GetContractAddressRequest::count_fields())?,
            self.contract_address.0.clone(),
        )?;
        Ok(())
    }
}
impl WriteSyscallResponse for GetTxSignatureResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value::<Felt252>(
            (syscall_ptr + GetTxSignatureRequest::count_fields())?,
            self.signature_len.into(),
        )?;
        vm.insert_value(
            (syscall_ptr + (GetTxSignatureRequest::count_fields() + 1))?,
            self.signature,
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for GetTxInfoResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + GetTxInfoRequest::count_fields())?,
            self.tx_info,
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for DeployResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + DeployRequestStruct::count_fields())?,
            self.contract_address.clone(),
        )?;
        vm.insert_value(
            (syscall_ptr + (DeployRequestStruct::count_fields() + 1))?,
            self.constructor_retdata_size.clone(),
        )?;
        vm.insert_value(
            (syscall_ptr + (DeployRequestStruct::count_fields() + 2))?,
            self.constructor_retdata,
        )?;
        Ok(())
    }
}

impl WriteSyscallResponse for StorageReadResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            (syscall_ptr + StorageReadRequest::count_fields())?,
            self.value.clone(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        add_segments,
        business_logic::{
            fact_state::in_memory_state_reader::InMemoryStateReader,
            state::cached_state::CachedState,
        },
        core::syscalls::syscall_handler::SyscallHandler,
        utils::test_utils::vm,
    };
    use cairo_rs::relocatable;

    type BusinessLogicSyscallHandler<'a> =
        crate::core::syscalls::business_logic_syscall_handler::BusinessLogicSyscallHandler<
            'a,
            CachedState<InMemoryStateReader>,
        >;

    #[test]
    fn write_get_caller_address_response() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let syscall = BusinessLogicSyscallHandler::default_with(&mut state);
        let mut vm = vm!();

        add_segments!(vm, 2);

        let response = GetCallerAddressResponse {
            caller_address: 3.into(),
        };

        assert!(syscall
            ._write_syscall_response(&response, &mut vm, relocatable!(1, 0))
            .is_ok());

        // Check Vm inserts
        // Since we can't access the vm.memory, these inserts should check the ._write_syscall_response inserts
        // The ._write_syscall_response should insert the response.caller_address in the position (1,1)
        // Because the vm memory is write once, trying to insert an 8 in that position should return an error
        assert!(vm
            .insert_value::<Felt252>(relocatable!(1, 1), 8.into())
            .is_err());
        // Inserting a 3 should be OK because is the value inserted by ._write_syscall_response
        assert!(vm
            .insert_value::<Felt252>(relocatable!(1, 1), 3.into())
            .is_ok())
    }
}
