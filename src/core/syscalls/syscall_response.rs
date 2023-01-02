use super::syscall_request::GetSequencerAddressRequest;
use super::syscall_request::{
    CountFields, GetBlockNumberRequest, GetBlockTimestampRequest, GetCallerAddressRequest,
};
use crate::core::errors::syscall_handler_errors::SyscallHandlerError;
use cairo_rs::{bigint, types::relocatable::Relocatable, vm::vm_core::VirtualMachine};
use num_bigint::BigInt;

pub(crate) trait WriteSyscallResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError>;
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetCallerAddressResponse {
    caller_address: BigInt,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetContractAddressResponse {
    contract_address: BigInt,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetSequencerAddressResponse {
    sequencer_address: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockTimestampResponse {
    block_timestamp: u64,
}

impl GetBlockTimestampResponse {
    pub(crate) fn new(block_timestamp: u64) -> Self {
        GetBlockTimestampResponse { block_timestamp }
    }
}

impl GetSequencerAddressResponse {
    pub(crate) fn new(sequencer_address: u64) -> Self {
        Self { sequencer_address }
    }
}

impl GetCallerAddressResponse {
    pub fn new(caller_addr: u64) -> Self {
        let caller_address = bigint!(caller_addr);
        GetCallerAddressResponse { caller_address }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GetBlockNumberResponse {
    block_number: u64,
}

impl GetBlockNumberResponse {
    pub(crate) fn new(block_number: u64) -> Self {
        Self { block_number }
    }
}

impl WriteSyscallResponse for GetCallerAddressResponse {
    fn write_syscall_response(
        &self,
        vm: &mut VirtualMachine,
        syscall_ptr: Relocatable,
    ) -> Result<(), SyscallHandlerError> {
        vm.insert_value(
            &(syscall_ptr + GetCallerAddressRequest::count_fields()),
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
        vm.insert_value(
            &(syscall_ptr + GetBlockTimestampRequest::count_fields()),
            bigint!(self.block_timestamp),
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
        vm.insert_value(
            &(syscall_ptr + GetSequencerAddressRequest::count_fields()),
            bigint!(self.sequencer_address),
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
        vm.insert_value(
            &(syscall_ptr + GetBlockNumberRequest::count_fields()),
            bigint!(self.block_number),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairo_rs::relocatable;

    use crate::{
        add_segments,
        core::syscalls::{
            business_logic_syscall_handler::BusinessLogicSyscallHandler,
            syscall_handler::SyscallHandler,
        },
        state::state_api_objects::BlockInfo,
        utils::test_utils::vm,
    };
    use num_bigint::{BigInt, Sign};

    #[test]
    fn write_get_caller_address_response() {
        let syscall = BusinessLogicSyscallHandler::new(BlockInfo::default());
        let mut vm = vm!();

        add_segments!(vm, 2);

        let response = GetCallerAddressResponse {
            caller_address: bigint!(3),
        };

        assert!(syscall
            ._write_syscall_response(&response, &mut vm, relocatable!(1, 0))
            .is_ok());

        // Check Vm inserts
        // Since we can't access the vm.memory, these inserts should check the ._write_syscall_response inserts
        // The ._write_syscall_response should insert the response.caller_address in the position (1,1)
        // Because the vm memory is write once, trying to insert an 8 in that position should return an error
        assert!(vm.insert_value(&relocatable!(1, 1), bigint!(8)).is_err());
        // Inserting a 3 should be OK because is the value inserted by ._write_syscall_response
        assert!(vm.insert_value(&relocatable!(1, 1), bigint!(3)).is_ok())
    }
}
