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

pub(crate) trait DeprecatedWriteSyscallResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;
}

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
    pub(crate) fn new(retdata_size: usize, retdata: Relocatable) -> Self {
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
    pub fn new(tx_info: Relocatable) -> Self {
        DeprecatedGetTxInfoResponse { tx_info }
    }
}

impl DeprecatedGetBlockTimestampResponse {
    pub(crate) fn new(block_timestamp: u64) -> Self {
        DeprecatedGetBlockTimestampResponse { block_timestamp }
    }
}

impl DeprecatedGetSequencerAddressResponse {
    pub(crate) fn new(sequencer_address: Address) -> Self {
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
    pub fn new(signature: Relocatable, signature_len: usize) -> Self {
        DeprecatedGetTxSignatureResponse {
            signature,
            signature_len,
        }
    }
}
impl DeprecatedGetContractAddressResponse {
    pub fn new(contract_address: Address) -> Self {
        DeprecatedGetContractAddressResponse { contract_address }
    }
}

impl DeprecatedStorageReadResponse {
    pub fn new(value: Felt252) -> Self {
        DeprecatedStorageReadResponse { value }
    }
}

impl DeprecatedGetBlockNumberResponse {
    pub(crate) fn new(block_number: u64) -> Self {
        Self { block_number }
    }
}
impl DeprecatedDeployResponse {
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
    use super::*;
    use crate::{
        add_segments,
        state::in_memory_state_reader::InMemoryStateReader,
        state::cached_state::CachedState,
        utils::{get_integer, test_utils::vm},
    };
    use cairo_vm::relocatable;

    type DeprecatedBLSyscallHandler<'a> =
        crate::syscalls::deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler<
            'a,
            CachedState<InMemoryStateReader>,
        >;

    #[test]
    fn write_get_caller_address_response() {
        let mut state = CachedState::<InMemoryStateReader>::default();
        let syscall = DeprecatedBLSyscallHandler::default_with(&mut state);
        let mut vm = vm!();

        add_segments!(vm, 2);

        let caller_address = 3;
        let response = DeprecatedGetCallerAddressResponse {
            caller_address: caller_address.into(),
        };

        assert!(syscall
            .write_syscall_response(&response, &mut vm, relocatable!(1, 0))
            .is_ok());

        // Check Vm inserts
        // The .write_syscall_response should insert the response.caller_address in the position (1,1)

        assert_matches!(get_integer(&vm, relocatable!(1, 1)), Ok(x) if x == caller_address);
    }
}
